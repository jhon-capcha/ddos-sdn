# Informe Técnico del Hito 10
## Validación Integral del Sistema Defensivo DDoS en SDN

---

## 1. Información general

| Campo | Detalle |
|---|---|
| **Proyecto** | Detección y mitigación de ataques DDoS en redes SDN mediante Machine Learning utilizando Entropía de Shannon |
| **Curso** | Programación Aplicada a la Ciberseguridad |
| **Programa** | Maestría en Ciberseguridad — Universidad Nacional Mayor de San Marcos |
| **Hito** | Hito 10 — Validación integral del sistema defensivo |
| **Capa** | Evaluación experimental (campaña multi-escenario) |
| **Fase metodológica asociada** | Validación de reproducibilidad, robustez y rendimiento |
| **Estado** | Completado |

---

## 2. Objetivo del Hito

Demostrar experimentalmente que el sistema SDN desarrollado detecta, identifica y mitiga ataques DDoS de manera consistente en todos los escenarios definidos, preservando la disponibilidad del tráfico legítimo y cuantificando su desempeño mediante métricas objetivas.

A diferencia de los hitos anteriores (que construyeron y validaron componentes individuales), el Hito 10 evalúa el sistema completo bajo un protocolo experimental uniforme, con repeticiones que permiten reportar resultados estadísticamente sólidos (media ± desviación estándar).

---

## 3. Arquitectura del Hito

El Hito 10 no modifica el sistema defensivo (congelado en el Hito 9). Añade una capa de instrumentación experimental, separada del controlador:

| Componente | Rol | Ubicación |
|---|---|---|
| `mark_experiment.py` | Escribe los marcadores de experimento en el log | controller/experiments/ |
| `analyze_metrics.py` | Parser: calcula métricas desde los marcadores | controller/experiments/ |
| `summary.py` | Resumen formateado de un experimento | controller/experiments/ |
| `run_experiment.sh` | Orquestador del protocolo | controller/experiments/ |

**Principio de instrumentación:** la herramienta de medición no depende del algoritmo evaluado. El controlador (monitor.py / online_detector.py / attack_identifier.py / mitigator.py) no sabe que existe el Hito 10; solo hace OpenFlow, detección y mitigación.

### 3.1 Arquitectura experimental

> 📌 *Insertar diagrama del flujo experimental (marcadores → log → parser → CSV → tablas).*

### 3.2 Flujo de un experimento

```
run_experiment.sh
      │
      ├── EXPERIMENT_START (marcador + parametros)
      │
      ├── [baseline: trafico normal 15s]
      │
      ├── ATTACK_START ──── operador lanza hping3 (VM-1)
      │        │
      │   [deteccion → identificacion → DROP]
      │        │
      │   [ataque 90s fijos]
      │
      ├── ATTACK_STOP ───── operador detiene hping3 (VM-1)
      │        │
      │   [recuperacion → FlowRemoved]
      │
      ├── EXPERIMENT_END (marcador)
      │
      └── analyze_metrics.py → CSV → summary.py
```

### 3.3 Instrumentación por marcadores

Cuatro marcadores delimitan cada fase, con formato idéntico al del controlador y un experiment_id único:

```
EXPERIMENT_START experiment_id=... scenario=... attacker=... victim=... ...
ATTACK_START     experiment_id=... scenario=...     (origen de Td y Tm)
ATTACK_STOP      experiment_id=... scenario=...      (origen de Tr)
EXPERIMENT_END   experiment_id=... scenario=... result=...
```

---

## 4. Actividades realizadas

### 4.1 Diseño del protocolo experimental (Fase 10.1)

Definición de 5 escenarios × 3 repeticiones = 15 experimentos, con orden de dificultad creciente (Normal → SYN → ICMP → UDP → Coordinado), métricas (Td, Tm, Tr, FP, FN, vida de reglas, disponibilidad), ground truth por escenario y criterios de éxito.

### 4.2 Baseline (Fase 10.2)

Verificación del estado del laboratorio antes de los experimentos: controlador activo, switch conectado, cero reglas DROP, tráfico normal sin falsos positivos. Resultado: 102 ventanas NORMAL, 0 ATAQUE, 0 mitigaciones.

### 4.3 Campaña experimental (Fase 10.3)

Ejecución de los 15 experimentos siguiendo el protocolo uniforme. Cada experimento con limpieza reforzada previa (reinicio del controlador + mn -c + verificación) para garantizar estado inicial limpio.

### 4.4 Instrumentación y métricas (Fase 10.6)

Desarrollo y validación de la instrumentación: marcadores, parser, orquestador. El parser produce un CSV con una fila por experimento.

### 4.5 Validación de componentes (Fases 10.4 y 10.5)

Análisis de la matriz de confusión del identificador y del ciclo de vida del mitigador, a partir de la evidencia de los 15 experimentos.

### 4.6 Consolidación y discusión (Fases 10.9 y 10.10)

Cuatro tablas de resultados y la discusión que relaciona cada decisión de diseño con su evidencia experimental.

---

## 5. Decisiones de diseño

| ID | Decisión | Justificación |
|---|---|---|
| Marcadores explícitos | 4 marcadores por experimento en vez de inferir del log | La herramienta de medición no depende del algoritmo evaluado; sin heurísticas frágiles. |
| experiment_id único | Timestamp por ejecución | Permite repetir escenarios sin sobrescribir; cada fila del CSV es trazable a su bloque del log. |
| Duración de ataque fija | ATTACK_DURATION=90s | Reproducibilidad: el operador no influye en la duración; las repeticiones son comparables. |
| RECOVERY_WAIT derivado | idle_timeout + monitor_interval | Ligado al sistema, no un número mágico. |
| Instrumentación separada | controller/experiments/, no en el controlador | El sistema defensivo no sabe que existe la evaluación; separación de responsabilidades. |
| 3 repeticiones por escenario | 15 experimentos totales | Permite reportar media ± DE; demuestra repetibilidad. |
| Disponibilidad con ping | RTT + packet loss (sin iperf) | Métricas clásicas de disponibilidad bajo DDoS; evita variables de TCP como ruido. |
| Comandos idénticos al dataset | Ataques exactos del Hito 5 | El ataque de validación replica el de entrenamiento. |

---

## 6. Bitácora de incidencias

### Problema 1 — Estado residual entre experimentos

- **Síntoma:** en una repetición, Td salió negativo (-65 s): el sistema clasificaba ATAQUE antes del marcador ATTACK_START.
- **Análisis:** los marcadores estaban bien ordenados, pero el detector ya venía clasificando ataque desde el arranque del experimento.
- **Causa:** el estado en memoria del controlador (flow_state, installed_rules) persistía del experimento anterior. El `mn -c` limpia el switch pero no la memoria del proceso Ryu.
- **Solución:** protocolo de limpieza reforzada — reiniciar el controlador (además de mn -c y pkill hping3) antes de cada experimento.
- **Lección:** en controladores SDN de larga ejecución, el estado en memoria debe reiniciarse explícitamente entre experimentos independientes para evitar contaminación de las mediciones.

### Problema 2 — Coordinación del ritmo experimental

- **Síntoma:** un experimento capturó 0 ventanas de ataque (el hping3 se mató a los 3 segundos de lanzarlo).
- **Análisis:** los comandos de VM-1 se ejecutaron de golpe al inicio, sin seguir las pausas del orquestador.
- **Causa:** falta de sincronización entre el script (que marca los tiempos) y la ejecución manual del tráfico.
- **Solución:** protocolo de ritmo explícito — el script guía, el operador ejecuta cada acción cuando se le indica, y el ataque corre una duración fija.
- **Lección:** al separar la orquestación (automática) del fenómeno (manual), la coordinación entre ambos debe ser explícita y guiada.

### Nota sobre el Tr del escenario coordinado

Con 3 reglas que expiran de forma independiente, el parser mide Tr desde el primer FlowRemoved, lo que produce valores menores (y en un caso, negativo por un artefacto de sincronización de marcadores). Se documenta como limitación de medición del escenario multi-regla, sin afectar la validez de la mitigación (18/18 recuperaciones correctas).

---

## 7. Evidencias

> 📌 *Insertar capturas en cada subsección.*

### 7.1 Resumen de un experimento (orquestador)

```
 RESUMEN DEL EXPERIMENTO
 Escenario ......... syn_flood
 Td (deteccion) .... 7.0 s
 Tm (mitigacion) ... 12.0 s
 Tr (recuperacion) . 14.0 s
 Ventanas ATAQUE ... 30
 DROP instalados ... 1
 FlowRemoved ....... 1
 Resultado ......... SUCCESS
```

### 7.2 Escenario coordinado (3 DROPs)

```
 Escenario ......... coordinado
 DROP instalados ... 3
 FlowRemoved ....... 3
```
```
![Coordinado 3 DROPs](docs/evidencia_coordinado.png)
```

### 7.3 CSV consolidado de los 15 experimentos

> 📌 *Adjuntar metricas_hito10_validas.csv.*

---

## 8. Versiones / configuración utilizada

| Componente | Versión / valor |
|---|---|
| Sistema (VM-2) | Python 3.8.10 (venv) |
| Ryu | 4.34 |
| Open vSwitch | 2.13.8 (OpenFlow 1.3) |
| MONITOR_INTERVAL | 5 s |
| PPS_MIN | 50 pps |
| Confirmación | 2 ventanas |
| idle_timeout | 15 s |
| ATTACK_DURATION | 90 s (fija) |
| APP_MODE | detect_mitigate |
| Escenarios | 5 (normal, syn, icmp, udp, coordinado) |
| Repeticiones | 3 por escenario |

---

## 9. Métricas de Git

| Repo | Commit | Tag | Cambios |
|---|---|---|---|
| VM-2 (control) | 19481f8 | hito-10 | 4 archivos nuevos (instrumentación) |

Tags acumulados — VM-2: `hito-2`, `hito-4`, `inicio-hito-5`, `hito-5`, `hito-6`, `hito-7`, `hito-8`, `hito-9`, `hito-10`. El sistema defensivo no se modificó (congelado en hito-9).

---

## 10. Métricas técnicas del Hito

### Tabla 1 — Detección, Identificación y Mitigación

| Escenario | Detectado | Identificado | Mitigado | DROP |
|---|---|---|---|---|
| SYN Flood | 3/3 | 3/3 | 3/3 | 1 |
| ICMP Flood | 3/3 | 3/3 | 3/3 | 1 |
| UDP Flood | 3/3 | 3/3 | 3/3 | 1 |
| Coordinado | 3/3 | 3/3 | 3/3 | 3 |
| Normal | N/A | N/A | N/A | 0 |

### Tabla 2 — Tiempos de respuesta (media ± DE, segundos)

| Escenario | Td | Tm | Tr |
|---|---|---|---|
| SYN Flood | 6.7 ± 1.5 | 11.7 ± 1.5 | 13.3 ± 0.6 |
| ICMP Flood | 2.3 ± 1.2 | 7.3 ± 1.2 | 13.7 ± 0.6 |
| UDP Flood | 5.0 ± 0.0 | 10.0 ± 0.0 | 13.7 ± 0.6 |
| Coordinado | 6.3 ± 1.5 | 11.3 ± 1.5 | 4.5 ± 0.7 † |

### Tabla 3 — Falsos Positivos / Negativos / Disponibilidad

| Escenario | FP | FN | Packet Loss |
|---|---|---|---|
| SYN Flood | 0 | 0 | 0% |
| ICMP Flood | 0 | 0 | 0% |
| UDP Flood | 0 | 0 | 0% |
| Coordinado | 0 | 0 | 0% |
| Normal | 0 | N/A | 0% |

### Tabla 4 — Identificador (matriz de confusión agregada)

| Métrica | Valor |
|---|---|
| TP / FP / FN | 18 / 0 / 0 |
| Precisión | 1.0000 |
| Recall | 1.0000 |
| F1-score | 1.0000 |

† *Tr del coordinado: ver nota en sección 6 (medición multi-regla).*

---

## 11. Estado del Hito

| Actividad | Estado |
|---|---|
| 10.1 Protocolo experimental | ✅ |
| 10.2 Baseline | ✅ |
| 10.3 Campaña (15 experimentos) | ✅ |
| 10.4 Validación del identificador | ✅ |
| 10.5 Validación del mitigador | ✅ |
| 10.6 Instrumentación y métricas | ✅ |
| 10.7 Disponibilidad | ✅ |
| 10.8 Robustez (discusión) | ✅ |
| 10.9 Consolidación (4 tablas) | ✅ |
| 10.10 Discusión técnica | ✅ |
| Commit + tag hito-10 | ✅ |
| Snapshot VMware | 📌 Pendiente |

---

## 12. Lecciones aprendidas

- La herramienta de medición debe ser independiente del algoritmo evaluado: los marcadores explícitos garantizan que las métricas no cambian aunque se modifiquen los parámetros del sistema.
- La reproducibilidad exige controlar las variables del operador: fijar la duración del ataque elimina la variabilidad humana entre repeticiones.
- El estado en memoria de un controlador SDN de larga ejecución debe reiniciarse entre experimentos independientes; limpiar solo el switch (mn -c) es insuficiente.
- Tres repeticiones por escenario transforman una demostración ("funciona") en una evaluación ("funciona de forma reproducible, con esta variabilidad").
- Separar la orquestación automática (marcadores, tiempos) del fenómeno manual (tráfico, ataques) preserva la validez del experimento sin sacrificar la estandarización del protocolo.

---

## 13. Conclusiones técnicas

La campaña experimental del Hito 10 validó cuantitativamente el sistema defensivo completo. En 15 experimentos (5 escenarios × 3 repeticiones), el sistema detectó, identificó y mitigó el 100% de los ataques (12/12), con tiempos de detección de 2 a 7 segundos y de mitigación de 7 a 12 segundos. El identificador alcanzó precisión, recall y F1 perfectos (1.0000), sin falsos positivos ni negativos, incluso en escenarios con tráfico de respuesta de la víctima. El escenario coordinado confirmó la escalabilidad: los tres atacantes simultáneos fueron identificados y bloqueados (3 reglas DROP) en las tres repeticiones. El tráfico legítimo se preservó con 0% de pérdida durante la mitigación, y el escenario normal no produjo ningún falso positivo. Todas las reglas de mitigación se recuperaron limpiamente (18/18), confirmando la robustez del mecanismo de sincronización.

Los resultados presentan baja variabilidad, evidenciando la reproducibilidad del sistema. Más allá de demostrar que el sistema funciona, la discusión técnica relacionó cada decisión de diseño con su evidencia experimental, mostrando que las decisiones arquitectónicas (identificación por dirección, ciclo de vida basado en FlowRemoved, separación de responsabilidades) son aportes metodológicos respaldados por datos.

---

## 14. Artefactos generados

| Archivo | Descripción |
|---|---|
| `controller/experiments/mark_experiment.py` | Marcadores de experimento. |
| `controller/experiments/analyze_metrics.py` | Parser de métricas. |
| `controller/experiments/summary.py` | Resumen de experimento. |
| `controller/experiments/run_experiment.sh` | Orquestador del protocolo. |
| `Protocolo_Experimental_Hito10.md` | Diseño del protocolo (Fase 10.1). |
| `Checklist_Baseline_Hito10.md` | Checklist de baseline (Fase 10.2). |
| `Resultados_Consolidados_Hito10.md` | 4 tablas de resultados (Fase 10.9). |
| `Analisis_Discusion_Hito10.md` | Validación de componentes y discusión (10.4, 10.5, 10.8, 10.10). |
| `metricas_hito10_validas.csv` | CSV de los 15 experimentos válidos. |
| `Informe_Tecnico_Hito10_Validacion.md` | Este informe. |

---

## 15. Riesgos abiertos

| ID | Riesgo | Mitigación |
|---|---|---|
| R1 | Spoofing de IP origen | El bloqueo por ipv4_src sería inútil; trabajo futuro (la entropía de origen recuperaría valor discriminante). |
| R2 | Medición de Tr en escenario multi-regla | Documentado; usar el último FlowRemoved en lugar del primero para el coordinado en trabajo futuro. |
| R3 | Escala de la topología | Validado con 7 hosts; topologías mayores requerirían evaluación adicional. |

---

## 16. Resumen del Hito (métricas)

| Indicador | Valor |
|---|---|
| Experimentos | 15 (5 escenarios × 3 rep) |
| Detección/Identificación/Mitigación | 12/12 |
| Identificador (F1) | 1.0000 |
| TP / FP / FN | 18 / 0 / 0 |
| Recuperación de reglas | 18/18 (100%) |
| Falsos positivos (Normal) | 0 |
| Packet loss legítimo | 0% |
| Coordinado (escalabilidad) | 3 DROPs × 3 rep |
| Commit / Tag | 19481f8 / hito-10 |
| Estado | Completado |

---

## 17. Próximo Hito

**Hito 11 — Informe final (formato IEEE):**

- Consolidación de todo el proyecto (Hitos 1–10) en el formato académico de publicación.
- Introducción, trabajos relacionados, metodología, arquitectura, resultados y discusión.
- Los resultados del Hito 10 (4 tablas, F1=1.0, escalabilidad) constituyen la sección de resultados experimentales.
- Trabajo futuro: extensión a IP spoofing (donde la entropía de origen recuperaría valor discriminante), evaluación de QoS con iperf, y escalado a topologías mayores.

---

*Informe Técnico del Hito 10 — Proyecto DDoS SDN — Maestría en Ciberseguridad (UNMSM)*

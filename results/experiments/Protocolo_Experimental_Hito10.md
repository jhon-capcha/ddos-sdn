# Protocolo Experimental — Hito 10
## Validación Integral del Sistema Defensivo DDoS en SDN

---

## 1. Objetivo y principio rector

**Objetivo:** demostrar experimentalmente que el sistema SDN desarrollado detecta, identifica y mitiga ataques DDoS de manera consistente en todos los escenarios definidos, preservando la disponibilidad del tráfico legítimo, y cuantificando su desempeño mediante métricas objetivas.

**Principio rector:** demostrar reproducibilidad, robustez y rendimiento mediante evidencia experimental. No basta con mostrar que el sistema "funciona" una vez; se busca evidencia estadística (repeticiones), cobertura (múltiples escenarios) y trazabilidad (cada resultado ligado a su registro en el log).

---

## 2. Configuración del sistema

| Parámetro | Valor |
|---|---|
| `MONITOR_INTERVAL` | 5 s |
| `PPS_MIN` | 50 pps |
| Confirmación | 2 ventanas consecutivas |
| `idle_timeout` (regla DROP) | 15 s |
| `hard_timeout` (regla DROP) | 0 (deshabilitado) |
| `MITIGATION_PRIORITY` | 100 |
| flags de la regla | OFPFF_SEND_FLOW_REM |
| `VICTIM_IP` | 10.0.0.1 (h1) |
| `APP_MODE` | detect_mitigate |
| Modelo operativo | model_sin_flowcount.joblib (Decision Tree, 7 features) |

**Topología:** switch s1 (OVS 2.13.8, OpenFlow 1.3) con 7 hosts. h1 = víctima (10.0.0.1). h2, h3, h4 = tráfico legítimo de fondo. h5, h6, h7 = atacantes (10.0.0.11/12/13).

---

## 3. Escenarios y orden de ejecución

Se ejecutan cinco escenarios, en un orden de dificultad creciente que además agrupa por característica técnica:

| # | Escenario | Atacante(s) | Característica clave |
|---|---|---|---|
| A | Normal | ninguno | Mide falsos positivos (especificidad). |
| B | SYN Flood | h5 | Ataque con respuesta de la víctima (SYN-ACK). |
| C | ICMP Flood | h5 | Ataque con respuesta de la víctima (echo reply). |
| D | UDP Flood | h5 | Ataque sin respuesta significativa. |
| E | Coordinado | h5, h6, h7 | Múltiples atacantes simultáneos (escalabilidad). |

**Justificación del orden:** los escenarios B y C comparten la característica de que la víctima genera tráfico de respuesta —el origen del refinamiento del criterio de identificación (`src_ip != VICTIM_IP`) en el Hito 9. Validarlos consecutivamente confirma que el criterio maneja el tráfico de retorno en sus dos casos difíciles. UDP (sin respuesta) es el caso más simple. El coordinado se deja al final por ser la prueba de mayor complejidad, donde se valida la escalabilidad del criterio de identificación a múltiples orígenes.

**Repeticiones:** cada escenario se ejecuta **3 veces** (repeticiones independientes), para un total de **15 experimentos**. Esto permite reportar media ± desviación estándar de las métricas temporales, aportando solidez estadística.

---

## 4. Definición de métricas

| Métrica | Símbolo | Definición | Fuente |
|---|---|---|---|
| Tiempo de detección | Td | Desde el inicio del ataque hasta la 1ª ventana clasificada como ATAQUE | monitor.log |
| Tiempo de mitigación | Tm | Desde el inicio del ataque hasta la instalación del DROP | monitor.log |
| Tiempo de recuperación | Tr | Desde el fin del ataque hasta el FlowRemoved | monitor.log |
| Vida de la regla | — | Duración de la regla DROP (campo `vida=Xs`) | monitor.log |
| Falsos positivos | FP | Ventanas de tráfico normal clasificadas como ataque / mitigaciones indebidas | monitor.log |
| Falsos negativos | FN | Ventanas de ataque no detectadas | monitor.log |
| RTT legítimo | — | Latencia de los pings de fondo (h2/h3/h4 → h1) durante la mitigación | ping |
| Packet loss legítimo | — | Porcentaje de pérdida del tráfico legítimo durante la mitigación | ping |

**Nota sobre la disponibilidad:** se mide con `ping` (RTT + packet loss + continuidad). No se emplea `iperf`: RTT y packet loss son las métricas clásicas de disponibilidad bajo DDoS y responden directamente al objetivo, mientras que el throughput introduciría variables de TCP (congestion control, ventana, jitter) que son ruido para la hipótesis. La evaluación de QoS con iperf queda como posible trabajo futuro.

---

## 5. Ground truth por escenario

Para calcular TP/FP/FN del identificador, se define formalmente el conjunto de atacantes reales por escenario:

| Escenario | Atacantes reales (ground truth) |
|---|---|
| Normal | ∅ (conjunto vacío) |
| SYN Flood | { 10.0.0.11 } (h5) |
| ICMP Flood | { 10.0.0.11 } (h5) |
| UDP Flood | { 10.0.0.11 } (h5) |
| Coordinado | { 10.0.0.11, 10.0.0.12, 10.0.0.13 } (h5, h6, h7) |

El identificador debe producir **exactamente** este conjunto en cada ventana de ataque. Un flujo extra marcado es un FP; un atacante real no marcado es un FN.

---

## 6. Criterios de éxito por escenario

**Escenario A (Normal):**
- Todas las ventanas clasificadas como NORMAL (o FP documentados).
- Cero mitigaciones instaladas.
- Cero reglas DROP en el switch.

**Escenarios B, C, D (ataque simple):**
- Detección: ATAQUE en ≤ ~2 ciclos desde el inicio.
- Identificación: exactamente { h5 } (la respuesta de la víctima excluida).
- Mitigación: 1 regla DROP instalada (h5 → h1).
- Corte sostenido: el contador del atacante se congela; el DROP no expira mientras el ataque siga.
- Tráfico legítimo: 0% de pérdida en los pings de fondo.
- Recuperación: FlowRemoved (motivo=idle_timeout) ~15 s tras el cese.

**Escenario E (Coordinado):**
- Identificación: exactamente { h5, h6, h7 }.
- Mitigación: 3 reglas DROP instaladas (una por atacante).
- Anti-duplicado: sin reinstalaciones espurias.
- Tráfico legítimo: 0% de pérdida.
- Recuperación: 3 FlowRemoved tras el cese.

---

## 7. Protocolo de ejecución por experimento

Cada uno de los 15 experimentos sigue esta secuencia:

```
1. BASELINE (verificación de estabilidad)
   - Controlador en detect_mitigate, switch conectado, cero reglas DROP.
   - Detector en NORMAL con tráfico de fondo.

2. MARCADOR DE INICIO
   EID=$(python mark_experiment.py start <scenario> --attacker <h> --victim h1)

3. FASE NORMAL (~20 s)
   - Tráfico de fondo: h2/h3/h4 ping -i 0.5 h1

4. INICIO DEL ATAQUE (registrar la hora)
   - <scenario>: h5 hping3 ... (continuo, sin parar)

5. OBSERVACIÓN (~40 s, ataque activo)
   - Verificar: detección → identificación → DROP → corte sostenido.
   - Medir disponibilidad: h2 ping -c 5 h1, h3 ping -c 5 h1.

6. CESE DEL ATAQUE
   - h5 kill %<n>

7. RECUPERACIÓN (~20 s)
   - Verificar FlowRemoved (motivo=idle_timeout) y vida de la regla.

8. MARCADOR DE FIN
   python mark_experiment.py end <scenario> --experiment-id $EID --result SUCCESS

9. LIMPIEZA antes del siguiente experimento
   - (en VM-1) sudo mn -c ; relevantar topología.
```

**Comandos de ataque por escenario:**

| Escenario | Comando (en mininet) |
|---|---|
| SYN Flood | `h5 hping3 -S -i u1000 -s 5353 10.0.0.1 &` |
| ICMP Flood | `h5 hping3 -1 -i u1000 10.0.0.1 &` |
| UDP Flood | `h5 hping3 -2 -i u1000 -s 1111 -k -p 80 10.0.0.1 &` |
| Coordinado | `h5 hping3 -S ... &` + `h6 hping3 -S ... &` + `h7 hping3 -S ... &` |

> Nota: los comandos exactos de cada escenario deben coincidir con los usados en la generación del dataset (Hito 5), para mantener la coherencia entre entrenamiento y validación.

---

## 8. Instrumentación

| Herramienta | Rol | Ubicación |
|---|---|---|
| `mark_experiment.py` | Escribe marcadores EXPERIMENT_START/END en monitor.log (mismo formato, experiment_id único) | controller/experiments/ |
| `analyze_metrics.py` | Parser: lee los bloques delimitados por marcadores y calcula Td/Tm/Tr + contadores → CSV | controller/experiments/ |
| `monitor.log` | Registro autosuficiente de eventos (detección, mitigación, FlowRemoved) | controller/logs/ |
| `ping` | Medición de disponibilidad (RTT + packet loss) | Mininet (VM-1) |

**Principio de instrumentación:** la herramienta de medición no depende del algoritmo que evalúa. El parser solo procesa eventos delimitados por marcadores explícitos, sin heurísticas. Si se cambiara la política de confirmación (2→3 ventanas) o cualquier umbral, el parser no cambia: solo mide lo que el log registra. La instrumentación vive en `controller/experiments/`, separada del sistema defensivo (el controlador no sabe que existe el Hito 10).

**Salida del parser (CSV):**
```
experiment_id, scenario, td, tm, tr, rule_lifetime,
normal_windows, attack_windows, drop_rules, flow_removed,
reinstalled, attackers_identified, fp, fn
```

Este CSV alimenta directamente las tablas de resultados del informe del Hito 10 (media ± DE por escenario sobre las 3 repeticiones).

---

## 9. Fases del Hito 10 (resumen de ejecución)

| Fase | Descripción |
|---|---|
| 10.1 | Diseño del protocolo experimental (este documento) |
| 10.2 | Baseline (verificación de estabilidad previa) |
| 10.3 | Validación por escenario en vivo (Normal→SYN→ICMP→UDP→Coordinado, ×3) |
| 10.4 | Validación aislada del identificador (TP/FP/FN con last_flow_deltas reales) |
| 10.5 | Validación aislada del mitigador (FlowMod→DROP→FlowRemoved→reinstalación) |
| 10.6 | Instrumentación y métricas (parser → CSV) |
| 10.7 | Disponibilidad del servicio (RTT/loss del tráfico legítimo) |
| 10.8 | Robustez (casos límite: ataques repetidos, expiración+reinstalación) |
| 10.9 | Consolidación de resultados (4 tablas, media ± DE) |
| 10.10 | Discusión técnica (decisiones de diseño ↔ evidencia) |
| 10.11 | Cierre (commit + tag + snapshot + informe) |

---

*Protocolo Experimental del Hito 10 — Proyecto DDoS SDN — Maestría en Ciberseguridad (UNMSM)*

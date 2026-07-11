# Análisis y Discusión Técnica — Hito 10
## Validación por Componente y Discusión de las Decisiones de Diseño

---

## Fase 10.4 — Validación del identificador de atacantes

Esta validación evalúa el módulo `attack_identifier` de forma aislada: dado el conjunto de flujos de una ventana de ataque, ¿identifica exactamente a los atacantes reales? Se emplea el ground truth definido por el diseño experimental (qué host ataca en cada escenario) y se contrasta con los atacantes efectivamente identificados (una regla DROP por atacante identificado).

### Ground truth por escenario

| Escenario | Atacantes reales | IP(s) |
|---|---|---|
| Normal | ∅ | — |
| SYN Flood | {h5} | 10.0.0.11 |
| ICMP Flood | {h7} | 10.0.0.13 |
| UDP Flood | {h6} | 10.0.0.12 |
| Coordinado | {h5, h6, h7} | 10.0.0.11/12/13 |

### Matriz de confusión (agregada sobre las 3 repeticiones)

| Escenario | Reales | Identificados | TP | FP | FN |
|---|---|---|---|---|---|
| Normal | {} | {} | 0 | 0 | 0 |
| SYN Flood | {h5} | {h5} | 3 | 0 | 0 |
| ICMP Flood | {h7} | {h7} | 3 | 0 | 0 |
| UDP Flood | {h6} | {h6} | 3 | 0 | 0 |
| Coordinado | {h5,h6,h7} | {h5,h6,h7} | 9 | 0 | 0 |
| **TOTAL** | | | **18** | **0** | **0** |

### Métricas de clasificación

| Métrica | Valor |
|---|---|
| Precisión | 1.0000 |
| Recall (sensibilidad) | 1.0000 |
| F1-score | 1.0000 |

**Interpretación:** el identificador alcanzó precisión y recall perfectos. No marcó ningún flujo legítimo como atacante (0 falsos positivos, incluyendo el tráfico de respuesta de la víctima en SYN, ICMP y UDP), ni omitió ningún atacante real (0 falsos negativos, incluso en el escenario coordinado con tres orígenes simultáneos). El criterio por dirección (`dst==VICTIM_IP AND src≠VICTIM_IP AND pps≥PPS_MIN`) discriminó correctamente el tráfico de ataque del tráfico de retorno en los tres protocolos.

---

## Fase 10.5 — Validación del mitigador

Esta validación evalúa el ciclo de vida completo de las reglas de mitigación: cada ataque identificado debe producir una regla FlowMod DROP, que al cesar el ataque debe expirar (FlowRemoved) y sincronizar el registro interno (clear_rule).

### Ciclo de mitigación por escenario (agregado sobre 3 repeticiones)

| Escenario | DROP instalados | FlowRemoved | clear_rule() | Ciclo completo |
|---|---|---|---|---|
| SYN Flood | 3 | 3 | 3 | ✓ |
| ICMP Flood | 3 | 3 | 3 | ✓ |
| UDP Flood | 3 | 3 | 3 | ✓ |
| Coordinado | 9 | 9 | 9 | ✓ |
| **TOTAL** | **18** | **18** | **18** | ✓ |

**Tasa de recuperación: 18/18 = 100%.**

**Interpretación:** cada regla DROP instalada tuvo su correspondiente evento FlowRemoved y su llamada a clear_rule(), sin excepción. Esto confirma que el mecanismo de sincronización basado en el flag OFPFF_SEND_FLOW_REM y el handler de eventos funciona de forma robusta: no quedaron reglas huérfanas (instaladas pero no registradas) ni registros huérfanos (registrados pero expirados en el switch). El estado del controlador se mantuvo sincronizado con el estado real del switch en los 18 ciclos de mitigación.

---

## Fase 10.8 — Robustez (evidencia del desarrollo)

Los casos límite relevantes para la robustez del sistema se manifestaron y resolvieron durante el desarrollo del Hito 9, por lo que no requirieron experimentos artificiales adicionales:

- **Expiración y reinstalación de reglas:** durante el Hito 9 se detectó que la combinación de `hard_timeout` con el registro interno producía desincronización (la regla expiraba en el switch pero el controlador la creía activa). El rediseño con `idle_timeout` + `OFPFF_SEND_FLOW_REM` resolvió el problema, y la campaña del Hito 10 confirmó su estabilidad (18/18 recuperaciones limpias).

- **Múltiples FlowRemoved simultáneos:** el escenario coordinado ejercita la gestión de múltiples reglas que expiran de forma independiente. Las 9 reglas del coordinado (3 por repetición) se instalaron y expiraron correctamente, demostrando que el handler procesa eventos FlowRemoved concurrentes sin pérdida de sincronización.

- **Estado residual entre ejecuciones:** durante la campaña se observó que el estado en memoria del controlador (flow_state, installed_rules) debía reiniciarse entre experimentos para evitar contaminación. Esto motivó el protocolo de limpieza reforzada, y es una observación relevante sobre la gestión del estado en controladores SDN de larga ejecución.

Estos comportamientos, surgidos de la validación empírica, tienen mayor valor metodológico que casos límite diseñados artificialmente, pues documentan problemas reales y sus soluciones.

---

## Fase 10.10 — Discusión técnica

Esta sección relaciona cada decisión de diseño del sistema con la evidencia experimental que la respalda. El valor de la investigación no reside únicamente en que el sistema funciona, sino en comprender por qué funciona y qué aportan sus decisiones arquitectónicas.

### Decisión 1 — Identificación por dirección (eliminación de CONTRIB_MIN)

**Decisión:** identificar al atacante por la dirección del flujo hacia la víctima (`dst==VICTIM_IP, src≠VICTIM_IP, pps≥PPS_MIN`), descartando el criterio inicial de contribución relativa (`contribution > 0.60`).

**Evidencia:** el escenario coordinado identificó a los tres atacantes simultáneos (18/18 TP, 0 FP) en todas las repeticiones. Con un umbral de contribución, tres atacantes repartiéndose el tráfico habrían quedado cada uno por debajo del umbral (aproximadamente 1/3 cada uno) y ninguno se habría bloqueado. El criterio por dirección es independiente del número de atacantes y de cómo se reparta el tráfico entre ellos.

**Aporte:** un criterio de identificación robusto ante ataques distribuidos, que no requiere recalibración según el número de orígenes.

### Decisión 2 — Criterio direccional válido para todos los protocolos

**Decisión:** el filtro `src≠VICTIM_IP` excluye el tráfico de respuesta de la víctima, independientemente del protocolo.

**Evidencia:** los tres escenarios con respuesta de la víctima (SYN con SYN-ACK, ICMP con echo reply, UDP con ICMP port unreachable) alcanzaron identificación perfecta (0 FP). La respuesta de la víctima, cuyo origen es la propia víctima, se excluye automáticamente en los tres casos.

**Aporte:** un único criterio de identificación maneja correctamente ataques con y sin tráfico de retorno, sin lógica específica por protocolo.

### Decisión 3 — Ciclo de vida idle_timeout + FlowRemoved

**Decisión:** gestionar la expiración de reglas solo con `idle_timeout` (sin `hard_timeout`) y sincronizar el registro mediante el evento `FlowRemoved`.

**Evidencia:** 18/18 reglas se recuperaron limpiamente (FlowRemoved = DROP en todos los escenarios). El tiempo de recuperación fue consistente (~13 s en ataques simples). No se observaron reglas huérfanas ni ventanas de re-exposición.

**Aporte:** un ciclo de vida donde el switch es la fuente de verdad del estado, eliminando la desincronización que producía el enfoque anterior.

### Decisión 4 — Separación de responsabilidades (detector / identificador / mitigador)

**Decisión:** arquitectura modular donde el detector clasifica, el identificador señala el origen, y el mitigador administra reglas, cada uno con una responsabilidad única.

**Evidencia:** cada componente pudo validarse de forma aislada (Fases 10.4 y 10.5) con datos reales, sin depender del sistema en vivo. El identificador se probó como función pura (last_flow_deltas → atacantes); el mitigador, como administrador de reglas.

**Aporte:** mantenibilidad y testabilidad. La separación permitió validar y refinar cada pieza independientemente, y facilita la evolución futura (por ejemplo, cambiar el algoritmo de detección sin tocar el mitigador).

### Decisión 5 — Instrumentación por marcadores independiente del algoritmo

**Decisión:** medir el rendimiento mediante marcadores explícitos (EXPERIMENT_START, ATTACK_START, ATTACK_STOP, EXPERIMENT_END) parseados por una herramienta que no depende del sistema evaluado.

**Evidencia:** las 15 ejecuciones produjeron métricas reproducibles con baja variabilidad (desviaciones de 0.0–1.5 s). La herramienta de medición mide solo entre marcadores, sin inferir nada del algoritmo de detección.

**Aporte:** resultados reproducibles y una metodología de medición que permanece válida aunque cambien los parámetros o el algoritmo del sistema evaluado.

### Síntesis

Las decisiones de diseño no fueron elecciones arbitrarias, sino refinamientos guiados por evidencia experimental. El criterio de identificación por dirección surgió al observar (con datos reales) que el ataque y su respuesta se reparten el tráfico casi por igual; el ciclo de vida basado en FlowRemoved surgió al detectar la desincronización del hard_timeout. La campaña del Hito 10 confirma cuantitativamente que estas decisiones producen un sistema que detecta, identifica y mitiga ataques DDoS de forma consistente, escalable y sin falsos positivos, preservando la disponibilidad del servicio legítimo.

---

*Análisis y Discusión Técnica del Hito 10 — Proyecto DDoS SDN — Maestría en Ciberseguridad (UNMSM)*

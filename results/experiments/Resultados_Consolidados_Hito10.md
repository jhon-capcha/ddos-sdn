# Resultados Consolidados — Hito 10
## Validación Integral del Sistema Defensivo DDoS en SDN

---

## Resumen de la campaña experimental

Se ejecutaron **15 experimentos** (5 escenarios × 3 repeticiones) siguiendo un protocolo uniforme implementado mediante el orquestador `run_experiment.sh`, que registró los marcadores experimentales y mantuvo constantes los tiempos de observación entre repeticiones. La generación de tráfico y de ataques permaneció manual para no introducir automatismos que alteraran el comportamiento del sistema evaluado.

**Parámetros del sistema (constantes en toda la campaña):**

| Parámetro | Valor |
|---|---|
| MONITOR_INTERVAL | 5 s |
| PPS_MIN | 50 pps |
| Confirmación | 2 ventanas consecutivas |
| idle_timeout | 15 s |
| VICTIM_IP | 10.0.0.1 (h1) |
| APP_MODE | detect_mitigate |
| Duración de ataque | 90 s (fija) |

**Comandos de ataque (idénticos a los del dataset de entrenamiento, Hito 5):**

| Escenario | Atacante | Comando |
|---|---|---|
| SYN Flood | h5 (10.0.0.11) | `hping3 -S -p 80 -i u1000 10.0.0.1` |
| UDP Flood | h6 (10.0.0.12) | `hping3 --udp -p 53 -s 5353 -i u1000 10.0.0.1` |
| ICMP Flood | h7 (10.0.0.13) | `hping3 --icmp -i u1000 10.0.0.1` |
| Coordinado | h5+h6+h7 | los tres simultáneos |
| Normal | ninguno | solo tráfico de fondo (h2/h3/h4) |

---

## Tabla 1 — Detección, Identificación y Mitigación

| Escenario | Detectado | Identificado | Mitigado | DROP esperado |
|---|---|---|---|---|
| SYN Flood | 3/3 | 3/3 | 3/3 | 1 |
| ICMP Flood | 3/3 | 3/3 | 3/3 | 1 |
| UDP Flood | 3/3 | 3/3 | 3/3 | 1 |
| Coordinado | 3/3 | 3/3 | 3/3 | 3 |
| Normal | N/A (sin ataque) | N/A | N/A | 0 |

**Resultado:** los 12 experimentos con ataque (SYN, ICMP, UDP, Coordinado × 3) fueron detectados, identificados y mitigados con éxito en el 100% de los casos. El escenario coordinado instaló las 3 reglas DROP esperadas (una por atacante) en las 3 repeticiones.

---

## Tabla 2 — Tiempos de respuesta (media ± desviación estándar)

| Escenario | Td (detección) | Tm (mitigación) | Tr (recuperación) |
|---|---|---|---|
| SYN Flood | 6.7 ± 1.5 s | 11.7 ± 1.5 s | 13.3 ± 0.6 s |
| ICMP Flood | 2.3 ± 1.2 s | 7.3 ± 1.2 s | 13.7 ± 0.6 s |
| UDP Flood | 5.0 ± 0.0 s | 10.0 ± 0.0 s | 13.7 ± 0.6 s |
| Coordinado | 6.3 ± 1.5 s | 11.3 ± 1.5 s | 4.5 ± 0.7 s † |
| Normal | N/A | N/A | N/A |

**Td** = tiempo de detección (desde el inicio del ataque hasta la primera ventana clasificada como ATAQUE). **Tm** = tiempo de mitigación (desde el inicio del ataque hasta la instalación del DROP). **Tr** = tiempo de recuperación (desde el cese del ataque hasta el FlowRemoved).

† *El Tr del escenario coordinado no es directamente comparable con los de ataque simple: al instalar 3 reglas que expiran en momentos ligeramente distintos, el parser mide desde el primer FlowRemoved. Se reporta el promedio de las repeticiones 2 y 3; la repetición 1 se excluyó por un artefacto de medición (el primer FlowRemoved ocurrió antes del marcador ATTACK_STOP debido a la multiplicidad de reglas).*

**Observaciones:**
- La detección más rápida corresponde a ICMP (2.3 s), por la firma clara del flood. La más lenta a SYN (6.7 s).
- La variabilidad de Td (0.0–1.5 s) proviene del punto del ciclo de monitoreo (5 s) en que arranca el ataque. UDP presentó desviación cero (detección perfectamente consistente).
- La mitigación se produce ~5 s después de la detección (las 2 ventanas de confirmación).

---

## Tabla 3 — Falsos Positivos, Falsos Negativos y Disponibilidad

| Escenario | FP | FN | Packet Loss (tráfico legítimo) |
|---|---|---|---|
| SYN Flood | 0 | 0 | 0% |
| ICMP Flood | 0 | 0 | 0% |
| UDP Flood | 0 | 0 | 0% |
| Coordinado | 0 | 0 | 0% |
| Normal | 0 | N/A | 0% (referencia) |

**Resultado:** cero falsos positivos y cero falsos negativos en toda la campaña. El escenario Normal (tráfico legítimo puro, 3 repeticiones) no produjo ninguna ventana clasificada como ataque ni ninguna regla de mitigación, confirmando la especificidad del sistema. El tráfico legítimo (h2/h3/h4 → h1) se mantuvo con 0% de pérdida durante la mitigación en todos los escenarios de ataque, confirmando la naturaleza quirúrgica de la mitigación.

---

## Tabla 4 — Ciclo de vida de las reglas de mitigación

| Escenario | DROP instalados (total 3 reps) | FlowRemoved (total) | Vida de la regla (media ± DE) |
|---|---|---|---|
| SYN Flood | 3 | 3 | 103.4 ± 1.4 s |
| ICMP Flood | 3 | 3 | 108.7 ± 6.9 s |
| UDP Flood | 3 | 3 | 101.7 ± 5.6 s |
| Coordinado | 9 | 9 | 101.2 ± 4.8 s |
| Normal | 0 | 0 | N/A |

**Resultado:** en todos los escenarios, el número de FlowRemoved igualó al de reglas DROP instaladas, confirmando que el mecanismo de sincronización (evento OFPFF_SEND_FLOW_REM + handler) funciona correctamente: cada regla instalada expiró limpiamente al cesar el ataque, sin desincronización entre el estado del switch y el del controlador. El coordinado instaló 9 reglas en total (3 por repetición) y todas se recuperaron.

---

## Interpretación global

La campaña experimental demuestra cuantitativamente que el sistema:

1. **Detecta** los cuatro tipos de ataque (SYN, ICMP, UDP, coordinado) de forma consistente, con tiempos de detección de 2 a 7 segundos.

2. **Identifica** correctamente el origen del ataque en todos los casos, incluyendo los escenarios con tráfico de respuesta de la víctima (SYN con SYN-ACK, ICMP con echo reply, UDP con ICMP port unreachable). El criterio por dirección (`dst==víctima, src≠víctima, pps≥PPS_MIN`) excluyó correctamente el tráfico de retorno en todos los protocolos.

3. **Mitiga** con precisión quirúrgica: bloquea solo el tráfico atacante→víctima, manteniendo el tráfico legítimo con 0% de pérdida.

4. **Escala** a múltiples atacantes simultáneos: el escenario coordinado identificó y bloqueó a los tres atacantes (3 reglas DROP) en las 3 repeticiones.

5. **No genera falsos positivos:** el tráfico legítimo puro nunca se clasificó como ataque (escenario Normal, 3 repeticiones).

6. **Se recupera automáticamente:** todas las reglas expiraron limpiamente tras el cese del ataque (FlowRemoved = DROP en todos los casos).

Los resultados presentan baja variabilidad (desviaciones estándar de 0.0 a 1.5 s en los tiempos de respuesta), lo que evidencia la reproducibilidad del comportamiento del sistema.

---

*Resultados Consolidados del Hito 10 — Proyecto DDoS SDN — Maestría en Ciberseguridad (UNMSM)*

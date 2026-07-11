# 06 — Reproducción de la Campaña Experimental (Hito 10)

Guía para reproducir la campaña experimental que validó el sistema: 15 experimentos (5 escenarios × 3 repeticiones), con métricas objetivas de detección, mitigación y recuperación.

---

## 1. Objetivo

Reproducir la validación integral del sistema defensivo bajo un protocolo experimental uniforme, obteniendo las métricas de tiempo (Td, Tm, Tr), la tasa de detección/identificación/mitigación, los falsos positivos y el ciclo de vida de las reglas.

---

## 2. Diseño experimental

- **5 escenarios** × **3 repeticiones** = **15 experimentos**.
- Orden de dificultad creciente: Normal → SYN → ICMP → UDP → Coordinado.
- Duración de ataque **fija** (90 s) para garantizar comparabilidad entre repeticiones.
- Generación de tráfico y ataques **manual**; el protocolo (marcadores y tiempos) lo estandariza un orquestador (`run_experiment.sh`).

**Principio metodológico:** la herramienta de medición no depende del algoritmo evaluado. El controlador no sabe que existe la campaña experimental; solo hace detección y mitigación. Los marcadores delimitan cada experimento y el parser calcula las métricas a partir de ellos.

---

## 3. Escenarios

| Escenario | Atacante(s) | IP(s) | Comando de ataque |
|---|---|---|---|
| Normal | ninguno | — | (solo tráfico de fondo) |
| SYN Flood | h5 | 10.0.0.11 | `hping3 -S -p 80 -i u1000 10.0.0.1` |
| ICMP Flood | h7 | 10.0.0.13 | `hping3 --icmp -i u1000 10.0.0.1` |
| UDP Flood | h6 | 10.0.0.12 | `hping3 --udp -p 53 -s 5353 -i u1000 10.0.0.1` |
| Coordinado | h5+h6+h7 | .11/.12/.13 | los tres simultáneos |

---

## 4. Preparación del laboratorio

Instrumentación necesaria (en `controller/experiments/`):

| Archivo | Función |
|---|---|
| `mark_experiment.py` | Escribe los marcadores del experimento en el log |
| `analyze_metrics.py` | Parser: calcula las métricas y genera el CSV |
| `summary.py` | Muestra el resumen de un experimento |
| `run_experiment.sh` | Orquestador del protocolo |

Parámetros del sistema (constantes en toda la campaña): `MONITOR_INTERVAL=5s`, `PPS_MIN=50`, confirmación=2 ventanas, `idle_timeout=15s`, `ATTACK_DURATION=90s`.

---

## 5. Procedimiento previo (limpieza reforzada)

**Antes de CADA experimento**, ejecutar la limpieza completa. Este paso es crítico: sin él, el estado residual produce métricas inválidas (por ejemplo, tiempos de detección negativos).

**Paso 1 — VM-1: limpiar el plano de datos**
```bash
exit                        # salir de mininet si se está dentro
sudo mn -c
sudo pkill -f hping3
```

**Paso 2 — VM-2: reiniciar el controlador** (Ctrl+C y relanzar)
```bash
source ~/ddos-sdn/venv/bin/activate
cd ~/ddos-sdn
APP_MODE=detect_mitigate ryu-manager --ofp-tcp-listen-port 6653 controller/apps/monitor.py
```

**Paso 3 — VM-1: levantar la topología**
```bash
cd ~/ddos-sdn
sudo python3 data-plane/topologia/topologia_ddos.py
```

**Paso 4 — VM-1: verificar que no hay reglas DROP**
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -i drop
```
→ debe estar vacío.

> **Por qué reiniciar el controlador:** `mn -c` limpia el switch, pero el estado en memoria del controlador (`flow_state`, `installed_rules`) persiste hasta que se reinicia el proceso Ryu. Omitir este paso es la causa principal de mediciones contaminadas.

---

## 6. Ejecución de un experimento

Lanzar el orquestador (VM-2, terminal de experimentos):

```bash
cd ~/ddos-sdn/controller/experiments
./run_experiment.sh <escenario> <repetición>
# Ejemplo: ./run_experiment.sh syn_flood 1
```

El script guía el procedimiento. **El script marca los tiempos; el operador ejecuta el tráfico cuando se le indica.** Ritmo de coordinación entre las dos VMs:

| Paso | El script (VM-2) | El operador (VM-1) |
|---|---|---|
| ① | Pide lanzar tráfico de fondo | `h2/h3/h4 ping -i 0.5 h1 &` → ENTER |
| ② | Pide lanzar el ataque | ENTER, luego el comando `hping3` del escenario |
| ③ | Cuenta 90 s de ataque (fijo) | No tocar; observar el DROP en VM-2 |
| ④ | Pide detener el ataque | `<host> kill %1` → ENTER |
| ⑤ | Espera 20 s (recuperación) | Observar el FlowRemoved en VM-2 |
| ⑥ | Pide detener el fondo | `h2/h3/h4 kill %1` → ENTER |
| ⑦ | Imprime el resumen | — |

Para el escenario **Normal** (sin ataque), el ritmo es más corto: fondo → observar 15 s → detener fondo → resumen.

---

## 7. Repeticiones

Cada escenario se ejecuta **3 veces**. Entre cada repetición, repetir la limpieza reforzada completa (sección 5). Nunca encadenar experimentos sin limpieza intermedia.

```
./run_experiment.sh syn_flood 1    # + limpieza antes
./run_experiment.sh syn_flood 2    # + limpieza antes
./run_experiment.sh syn_flood 3    # + limpieza antes
```

---

## 8. Obtención de métricas

El orquestador genera automáticamente el CSV acumulado en `/tmp/metricas_hito10.csv` y muestra el resumen de cada experimento. Para reanalizar el log en cualquier momento:

```bash
python analyze_metrics.py ~/ddos-sdn/controller/logs/monitor.log -o /tmp/metricas.csv
cat /tmp/metricas.csv
```

Cada fila del CSV contiene: `experiment_id`, escenario, Td, Tm, Tr, duración del ataque, vida de la regla, ventanas normal/ataque, reglas DROP, FlowRemoved y resultado.

---

## 9. Resultados esperados

Un experimento correcto debe producir estos valores:

| Escenario | Ventanas ATAQUE | DROP instalados | FlowRemoved | FP |
|---|---|---|---|---|
| Normal | 0 | 0 | 0 | 0 |
| SYN Flood | > 0 | 1 | 1 | 0 |
| ICMP Flood | > 0 | 1 | 1 | 0 |
| UDP Flood | > 0 | 1 | 1 | 0 |
| Coordinado | > 0 | 3 | 3 | 0 |

**Rangos de tiempo típicos:** Td entre 2 y 8 s, Tm entre 7 y 13 s, Tr entre 13 y 15 s (en escenarios de ataque simple).

Si un experimento produce Td negativo, 0 ventanas de ataque cuando debería haberlas, o un número de DROP distinto al esperado, **descártalo y repítelo** tras una limpieza reforzada. Este es el criterio de validez aplicado en la campaña original.

---

## 10. Lista de comprobación (Checklist)

Antes y durante cada experimento:

```
□ sudo mn -c ejecutado
□ Controlador reiniciado (estado en memoria limpio)
□ Modelo cargado (Detector listo)
□ Switch conectado (dpid=1)
□ Sin reglas DROP (dump-flows vacío)
□ Detección NORMAL confirmada
□ Tráfico de fondo iniciado (flujos=6)
□ Escenario y repetición correctos en run_experiment.sh
□ Comando de ataque correcto para el escenario
□ DROP observado durante el ataque
□ FlowRemoved observado tras el cese
□ CSV generado con métricas válidas
□ Resumen coherente con "Resultados esperados"
```

---

## 11. Limpieza final

Al terminar la campaña:

```bash
# VM-1
sudo mn -c
sudo pkill -f hping3
# VM-2
# Ctrl+C en el controlador
# Guardar el CSV y el log de resultados
cp /tmp/metricas_hito10.csv ~/resultados_campana.csv
```

---

*Documento 06 — Reproducción del Hito 10 — DDoS-SDN-Defense*

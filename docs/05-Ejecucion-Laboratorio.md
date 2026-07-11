# 05 — Ejecución del Laboratorio

Manual de operación del sistema DDoS-SDN-Defense. Describe cómo poner en marcha el laboratorio, generar tráfico, ejecutar ataques y verificar la mitigación.

---

## 1. Objetivo

Poner en funcionamiento el sistema defensivo completo (plano de control + plano de datos), generar tráfico legítimo y de ataque, y verificar que el sistema detecta, identifica y mitiga los ataques DDoS de forma automática.

---

## 2. Arquitectura utilizada

| Plano | Máquina | Software | IP de gestión |
|---|---|---|---|
| Control | VM-2 | Ryu 4.34 + Machine Learning | 10.10.10.40 |
| Datos | VM-1 | Mininet 2.3.0 + Open vSwitch 2.13.8 | 10.10.10.30 |

La topología es una estrella: un switch OpenFlow (s1) con 7 hosts (h1 víctima, h2–h4 legítimos, h5–h7 atacantes).

---

## 3. Requisitos previos

- Ambas máquinas virtuales encendidas y con conectividad entre ellas (ver [`04-Configuracion-Red.md`](04-Configuracion-Red.md)).
- El repositorio clonado en ambas VMs.
- En VM-2, el entorno virtual de Python creado e instalado (ver [`03-Instalacion-VM2.md`](03-Instalacion-VM2.md)).

---

## 4. Inicio del plano de control (VM-2)

**Regla de oro:** el controlador debe arrancar ANTES de levantar la topología.

```bash
source ~/ddos-sdn/venv/bin/activate
cd ~/ddos-sdn
APP_MODE=detect_mitigate ryu-manager --ofp-tcp-listen-port 6653 controller/apps/monitor.py
```

Espera a ver estas líneas de confirmación:

```
Mitigacion ACTIVA: victima=10.0.0.1, pps_min=50, confirmacion=2 ventanas
Detector listo: modelo='model_sin_flowcount.joblib' (7 features)
Monitor13 iniciado (OpenFlow 1.3, intervalo=5s, modo=detect_mitigate)
```

**Modos disponibles (`APP_MODE`):**

| Modo | Comportamiento |
|---|---|
| `detect` | Solo detección (no mitiga) |
| `detect_mitigate` | Detección + identificación + mitigación (modo completo) |
| `capture` | Captura de datos para el dataset |

---

## 5. Inicio del plano de datos (VM-1)

```bash
sudo mn -c
cd ~/ddos-sdn
sudo python3 data-plane/topologia/topologia_ddos.py
```

Al arrancar, en VM-2 debe aparecer:

```
Switch conectado: dpid=1
Detector: warming up (fijando linea base)...
```

Quedas en el prompt `mininet>`.

---

## 6. Verificación inicial

**En VM-1 (terminal aparte):** confirma que no hay reglas DROP residuales:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -i drop
```

La salida debe estar **vacía**.

**En VM-2:** confirma que el detector clasifica el tráfico como `NORMAL`:

```
Deteccion: NORMAL | pps=0.0 ... flujos=0 | ventanas normal=N ataque=0
```

---

## 7. Generación de tráfico legítimo

En el prompt `mininet>` de VM-1:

```
h2 ping -i 0.5 h1 &
h3 ping -i 0.5 h1 &
h4 ping -i 0.5 h1 &
```

En VM-2 verás cambiar a `flujos=6` con un `pps` de decenas, manteniéndose la clasificación `NORMAL`.

---

## 8. Ejecución de ataques

Cada tipo de ataque se lanza desde su host correspondiente. Los comandos replican exactamente los del dataset de entrenamiento:

| Ataque | Host | Comando (en `mininet>`) |
|---|---|---|
| SYN Flood | h5 | `h5 hping3 -S -p 80 -i u1000 10.0.0.1 &` |
| UDP Flood | h6 | `h6 hping3 --udp -p 53 -s 5353 -i u1000 10.0.0.1 &` |
| ICMP Flood | h7 | `h7 hping3 --icmp -i u1000 10.0.0.1 &` |
| Coordinado | h5+h6+h7 | los tres comandos anteriores simultáneos |

Tras 2 ventanas de confirmación, en VM-2 aparecerá:

```
>>> ATAQUE DDoS DETECTADO <<<
>>> MITIGACION: DROP instalado para 10.0.0.11 -> 10.0.0.1 ...
```

**Detener un ataque:** desde el host atacante, `<host> kill %1` (por ejemplo, `h5 kill %1`).

---

## 9. Verificación de la mitigación

**Durante el ataque, comprueba que el tráfico legítimo sobrevive** (en `mininet>`):

```
h2 ping -c 5 h1
```

Debe responder con 0% de pérdida.

**Comprueba la regla DROP instalada** (en VM-1, terminal aparte):

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -i drop
```

Debe aparecer una regla con `priority=100` y `actions=drop`.

**Tras detener el ataque**, en VM-2 aparecerá el evento de recuperación (~15-20 s después):

```
FlowRemoved: regla 10.0.0.11 -> 10.0.0.1 eliminada (motivo=idle_timeout)
Mitigacion: regla DROP ... expiro (vida=Xs, reglas_activas=0)
```

---

## 10. Detener el laboratorio

**VM-1:** salir de Mininet y limpiar:

```
mininet> exit
```
```bash
sudo mn -c
sudo pkill -f hping3
```

**VM-2:** detener el controlador con `Ctrl+C`.

---

## 11. Solución de problemas frecuentes

| Síntoma | Causa probable | Solución |
|---|---|---|
| El switch no conecta al controlador | El controlador no está corriendo, o el puerto/IP es incorrecto | Arrancar el controlador ANTES de la topología; verificar que escucha en el puerto 6653 |
| No aparece `FlowRemoved` tras el ataque | El ataque no se detuvo, o la regla aún no expiró | Verificar que el `hping3` se mató; esperar `idle_timeout` + intervalo (~20 s) |
| El modelo no carga | Ruta del `.joblib` incorrecta o venv no activado | Activar el venv; verificar la ruta del modelo |
| `dump-flows` muestra reglas antiguas | Estado residual de una ejecución previa | `sudo mn -c` y reiniciar el controlador |
| Td negativo o detección antes del ataque | El controlador conserva estado en memoria de una ejecución previa | Reiniciar el controlador (Ctrl+C + relanzar); `mn -c` no limpia la memoria del controlador |
| El detector clasifica ATAQUE sin ataque | Estado residual (flujos previos en memoria) | Reiniciar el controlador para vaciar `flow_state` e `installed_rules` |

> **Nota importante:** `sudo mn -c` limpia el switch (Open vSwitch), pero NO limpia el estado en memoria del controlador Ryu (`flow_state`, `installed_rules`). Para un estado completamente limpio entre ejecuciones, reinicia también el controlador.

---

*Documento 05 — Manual de ejecución — DDoS-SDN-Defense*

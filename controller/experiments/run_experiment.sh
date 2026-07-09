#!/usr/bin/env bash
# ==============================================================
# run_experiment.sh
# ==============================================================
# Orquestador del protocolo experimental del Hito 10.
#
# Estandariza el PROCEDIMIENTO (marcadores + tiempos), pero NO
# automatiza el fenomeno: el trafico de fondo y el ataque se
# lanzan MANUALMENTE en VM-1. Asi el protocolo es uniforme entre
# las 15 ejecuciones sin introducir automatismos que alteren el
# comportamiento del sistema evaluado.
#
# Reproducibilidad:
#   - ATTACK_DURATION fijo: la duracion del ataque es identica en
#     todas las repeticiones (el operador no influye en ella). El
#     DROP ocurre cuando ocurre; el parser mide Td/Tm objetivamente.
#   - RECOVERY_WAIT derivado del sistema (idle_timeout + intervalo),
#     no un numero magico.
#
# NO ejecuta: hping3, ping, ovs-ofctl, mininet.
#
# Uso:  ./run_experiment.sh <scenario> [rep]
#
# Maestria en Ciberseguridad - UNMSM
# ==============================================================

set -euo pipefail

# --- Parametros del sistema (deben coincidir con la config real) ---
IDLE_TIMEOUT=15        # idle_timeout de la regla DROP (mitigator.py)
MONITOR_INTERVAL=5     # intervalo de monitoreo (monitor.py)

# --- Configuracion de tiempos del protocolo (constantes) ---
BASELINE_WAIT=15                                   # s de trafico normal previo
ATTACK_DURATION=90                                 # s de ataque (FIJO, reproducible)
RECOVERY_WAIT=$((IDLE_TIMEOUT + MONITOR_INTERVAL)) # s para ver el FlowRemoved (=20)
CLEANUP_WAIT=5                                     # s tras detener el fondo

# --- Rutas ---
EXP_DIR="$HOME/ddos-sdn/controller/experiments"
LOG_PATH="$HOME/ddos-sdn/controller/logs/monitor.log"
MARK="python $EXP_DIR/mark_experiment.py"
MARK_ARGS="--log-path $LOG_PATH"
ANALYZE="python $EXP_DIR/analyze_metrics.py"
CSV_OUT="/tmp/metricas_hito10.csv"

# --- Argumentos ---
SCENARIO="${1:-}"
REP="${2:-1}"
if [ -z "$SCENARIO" ]; then
    echo "Uso: $0 <scenario> [rep]"
    echo "Escenarios: normal, syn_flood, icmp_flood, udp_flood, coordinado"
    exit 1
fi

case "$SCENARIO" in
    syn_flood)  ATTACKER="h5" ;;
    udp_flood)  ATTACKER="h6" ;;
    icmp_flood) ATTACKER="h7" ;;
    coordinado) ATTACKER="h5,h6,h7" ;;
    normal)     ATTACKER="ninguno" ;;
    *)          ATTACKER="h5" ;;
esac

sep() { echo "=========================================="; }

sep
echo " ${SCENARIO^^} - REPETICION ${REP}"
sep

# 1. EXPERIMENT_START
EID=$($MARK start "$SCENARIO" --attacker "$ATTACKER" --victim h1 $MARK_ARGS)
echo " Experiment ID: $EID"
sep

if [ "$SCENARIO" = "normal" ]; then
    # --- Escenario NORMAL: sin ataque, mide falsos positivos ---
    echo "[Escenario NORMAL: sin ataque]"
    echo ">>> LANCE EL TRAFICO DE FONDO EN VM-1 (h2/h3/h4 ping) <<<"
    read -p "    Pulse ENTER cuando el fondo este corriendo... "
    echo "[Observacion de trafico normal: ${BASELINE_WAIT}s]"
    sleep "$BASELINE_WAIT"
    echo ">>> DETENGA EL TRAFICO DE FONDO EN VM-1 <<<"
    read -p "    Pulse ENTER cuando lo haya detenido... "
    sleep "$CLEANUP_WAIT"
    $MARK end "$SCENARIO" --experiment-id "$EID" --result SUCCESS $MARK_ARGS 2>/dev/null
else
    # --- Escenarios de ataque ---
    echo ">>> LANCE EL TRAFICO DE FONDO EN VM-1 (h2/h3/h4 ping) <<<"
    read -p "    Pulse ENTER cuando el fondo este corriendo... "
    echo "[Baseline: ${BASELINE_WAIT}s de trafico normal]"
    sleep "$BASELINE_WAIT"

    # ATTACK_START + lanzamiento manual
    echo ""
    echo ">>> PREPARESE PARA LANZAR EL ATAQUE EN VM-1 <<<"
    if [ "$SCENARIO" = "coordinado" ]; then
        echo "    (h5, h6 y h7 hacia h1, los tres)"
    fi
    read -p "    Pulse ENTER y lance el hping3 INMEDIATAMENTE despues... "
    $MARK attack-start "$SCENARIO" --experiment-id "$EID" $MARK_ARGS 2>/dev/null
    echo "    [ATTACK_START marcado. El ataque corre ${ATTACK_DURATION}s.]"

    # Duracion FIJA del ataque (reproducibilidad: el operador no influye)
    echo "[Ataque en curso: ${ATTACK_DURATION}s fijos...]"
    sleep "$ATTACK_DURATION"

    # ATTACK_STOP + detencion manual
    echo ""
    echo ">>> DETENGA EL ATAQUE EN VM-1 AHORA (kill del hping3) <<<"
    read -p "    Pulse ENTER JUSTO DESPUES de detenerlo... "
    $MARK attack-stop "$SCENARIO" --experiment-id "$EID" $MARK_ARGS 2>/dev/null
    echo "    [ATTACK_STOP marcado.]"

    # Recuperacion (derivada del sistema)
    echo "[Recuperacion: esperando ${RECOVERY_WAIT}s (idle_timeout+intervalo)...]"
    sleep "$RECOVERY_WAIT"

    # Detener fondo
    echo ""
    echo ">>> DETENGA EL TRAFICO DE FONDO EN VM-1 <<<"
    read -p "    Pulse ENTER cuando lo haya detenido... "
    sleep "$CLEANUP_WAIT"

    $MARK end "$SCENARIO" --experiment-id "$EID" --result SUCCESS $MARK_ARGS 2>/dev/null
fi

sep
echo " EXPERIMENT_END marcado (id=$EID)"
sep

# Analisis (genera el CSV acumulado)
$ANALYZE "$LOG_PATH" -o "$CSV_OUT" >/dev/null

# Resumen del experimento recien ejecutado (extraido del CSV)

# Resumen del experimento recien ejecutado
python "$EXP_DIR/summary.py" "$CSV_OUT" "$EID"

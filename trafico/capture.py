#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
capture.py
===============================================================

Orquestador de capturas experimentales para el dataset de
deteccion de DDoS en SDN (Hito 5).

Genera, de forma reproducible y con tiempos controlados:
    - trafico de fondo normal (h2, h3, h4 -> h1)
    - trafico de ataque segun el escenario (h5/h6/h7 -> h1)

Reutiliza la topologia definida en topologia_ddos.py (fuente
unica de verdad). NO arranca el controlador: Ryu (monitor.py)
debe ejecutarse en la VM-2 con el mismo SCENARIO antes de
lanzar esta captura.

Uso:
    sudo python3 trafico/capture.py <escenario>
    escenarios: normal | syn_flood | udp_flood | icmp_flood | coordinado

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

import os
import sys
import time

# Permitir importar el paquete del proyecto desde la raiz ddos-sdn/.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from mininet.log import setLogLevel, info
from topologia.topologia_ddos import crear_topologia


# =====================================================
# CONFIGURACION DEL EXPERIMENTO
# =====================================================

# Tasa de ataque (controlada, reproducible). u1000 = 1 paquete/1000us ~ 1000 pps.
ATTACK_RATE = os.getenv("ATTACK_RATE", "-i u1000")

# Duracion de la captura (segundos) desde que arranca el ataque.
ATTACK_DURATION = int(os.getenv("ATTACK_DURATION", "300"))

# Tiempo de trafico de fondo antes de lanzar el ataque (segundos).
NORMAL_DELAY = int(os.getenv("NORMAL_DELAY", "10"))

# Tiempo de espera para que el switch se conecte a Ryu (segundos).
RYU_CONNECT_WAIT = int(os.getenv("RYU_CONNECT_WAIT", "5"))

# Trafico de fondo normal (intervalo en segundos entre paquetes).
BACKGROUND_PING = "ping -i 0.5"

# Direccion de la victima (h1).
VICTIM_IP = "10.0.0.1"

# Hosts que generan trafico de fondo normal.
NORMAL_HOSTS = ["h2", "h3", "h4"]


# =====================================================
# DEFINICION DE ESCENARIOS
# =====================================================
# Cada escenario define que ataques se lanzan (host -> comando hping3).
# El trafico de fondo normal es comun a todos los escenarios.

VALID_SCENARIOS = {"normal", "syn_flood", "udp_flood", "icmp_flood", "coordinado"}

# Comandos de ataque por tipo (se completan con ATTACK_RATE y la victima).
ATTACK_SYN = "hping3 -S -p 80 %s %s" % (ATTACK_RATE, VICTIM_IP)
ATTACK_UDP = "hping3 --udp -p 53 -s 5353 %s %s" % (ATTACK_RATE, VICTIM_IP)
ATTACK_ICMP = "hping3 --icmp %s %s" % (ATTACK_RATE, VICTIM_IP)

# Mapeo escenario -> lista de (host_atacante, comando).
SCENARIO_ATTACKS = {
    "normal": [],
    "syn_flood":  [("h5", ATTACK_SYN)],
    "udp_flood":  [("h6", ATTACK_UDP)],
    "icmp_flood": [("h7", ATTACK_ICMP)],
    "coordinado": [
        ("h5", ATTACK_SYN),
        ("h6", ATTACK_UDP),
        ("h7", ATTACK_ICMP),
    ],
}


# =====================================================
# FUNCIONES AUXILIARES
# =====================================================

def log(mensaje):
    """Imprime un mensaje con marca de tiempo relativa (mm:ss)."""
    print(mensaje, flush=True)


def start_background(net):
    """Lanza el trafico de fondo normal (h2,h3,h4 -> h1) en segundo plano."""
    procesos = []
    for nombre in NORMAL_HOSTS:
        host = net.get(nombre)
        cmd = "%s %s" % (BACKGROUND_PING, VICTIM_IP)
        p = host.popen(cmd, shell=True)
        procesos.append(p)
        log("    fondo: %s -> %s (%s)" % (nombre, VICTIM_IP, BACKGROUND_PING))
    return procesos


def start_attack(net, escenario):
    """Lanza el/los ataque(s) del escenario en segundo plano."""
    procesos = []
    for host_name, cmd in SCENARIO_ATTACKS[escenario]:
        host = net.get(host_name)
        p = host.popen(cmd, shell=True)
        procesos.append(p)
        log("    ataque: %s -> %s" % (host_name, cmd))
    return procesos


def stop_processes(procesos):
    """Detiene una lista de procesos de forma ordenada."""
    for p in procesos:
        try:
            p.terminate()
        except Exception:
            pass


# =====================================================
# ORQUESTADOR
# =====================================================

def main():
    # Leer y validar el escenario.
    if len(sys.argv) < 2:
        log("Uso: sudo python3 trafico/capture.py <escenario>")
        log("Escenarios: %s" % ", ".join(sorted(VALID_SCENARIOS)))
        sys.exit(1)

    escenario = sys.argv[1]
    if escenario not in VALID_SCENARIOS:
        log("ERROR: escenario no valido: '%s'" % escenario)
        log("Escenarios validos: %s" % ", ".join(sorted(VALID_SCENARIOS)))
        sys.exit(1)

    # Encabezado informativo.
    log("=" * 53)
    log("CAPTURA OFICIAL")
    log("=" * 53)
    log("Escenario : %s" % escenario)
    log("Duracion  : %s s" % ATTACK_DURATION)
    log("Tasa      : %s" % ATTACK_RATE)
    log("Victima   : h1 (%s)" % VICTIM_IP)
    log("Fondo     : %s -> h1 (%s)" % (", ".join(NORMAL_HOSTS), BACKGROUND_PING))
    log("=" * 53)
    log("RECORDATORIO: Ryu (monitor.py) debe estar corriendo en VM-2")
    log("con SCENARIO=%s antes de esta captura." % escenario)
    log("=" * 53)

    net = crear_topologia()
    fondo = []
    ataques = []

    try:
        log("[t=0] Construyendo e iniciando la topologia...")
        net.build()
        net.start()

        log("[t=0] Esperando conexion del switch con Ryu (%ss)..." % RYU_CONNECT_WAIT)
        time.sleep(RYU_CONNECT_WAIT)

        log("[t=0] Iniciando trafico de fondo normal...")
        fondo = start_background(net)

        log("[t=0] Fondo estabilizandose (%ss)..." % NORMAL_DELAY)
        time.sleep(NORMAL_DELAY)

        if SCENARIO_ATTACKS[escenario]:
            log("[t=%s] Iniciando ataque (%s)..." % (NORMAL_DELAY, escenario))
            ataques = start_attack(net, escenario)
        else:
            log("[t=%s] Escenario 'normal': sin ataque (solo fondo)." % NORMAL_DELAY)

        # Bucle de captura con progreso cada 30 s.
        log("[t=%s] Capturando durante %ss..." % (NORMAL_DELAY, ATTACK_DURATION))
        transcurrido = 0
        paso = 30
        while transcurrido < ATTACK_DURATION:
            restante = ATTACK_DURATION - transcurrido
            dormir = paso if restante >= paso else restante
            time.sleep(dormir)
            transcurrido += dormir
            log("    Capturando... %s/%s s" % (transcurrido, ATTACK_DURATION))

        log("[t=fin] Captura completada. Deteniendo procesos...")

    except KeyboardInterrupt:
        log("\n[INTERRUPCION] Ctrl+C detectado. Deteniendo todo limpiamente...")

    finally:
        log("    Deteniendo ataque...")
        stop_processes(ataques)
        log("    Deteniendo trafico de fondo...")
        stop_processes(fondo)
        log("    Deteniendo la red (net.stop)...")
        net.stop()
        log("Captura finalizada. Escenario: %s" % escenario)


if __name__ == "__main__":
    setLogLevel("info")
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
mark_experiment.py
===============================================================

Instrumentacion experimental para el Hito 10 (validacion integral).

Escribe cuatro marcadores en el mismo monitor.log que usa el controlador,
con el MISMO formato (via el modulo logging con un Formatter identico):

    EXPERIMENT_START  -> delimita el bloque + parametros (no mide tiempo)
    ATTACK_START      -> origen de tiempos: Td = 1a deteccion - ATTACK_START
                                            Tm = 1er DROP     - ATTACK_START
    ATTACK_STOP       -> Tr = FlowRemoved - ATTACK_STOP
                         attack_duration = ATTACK_STOP - ATTACK_START
    EXPERIMENT_END    -> cierra el bloque (no mide tiempo)

El parser analyze_metrics.py delimita cada experimento y cada fase por
estos marcadores, sin heuristicas ni dependencia del algoritmo. Este
script pertenece al ENTORNO DE EVALUACION, no al sistema defensivo.

Uso:
    python mark_experiment.py start        <scenario> [--attacker h5] [--victim h1]
    python mark_experiment.py attack-start <scenario> --experiment-id <id>
    python mark_experiment.py attack-stop  <scenario> --experiment-id <id>
    python mark_experiment.py end          <scenario> --experiment-id <id> [--result SUCCESS]

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

import argparse
import logging
import os
import sys
from datetime import datetime


# Ruta del log del controlador (la misma que usa monitor.py).
DEFAULT_LOG_PATH = os.path.expanduser(
    "~/ddos-sdn/controller/logs/monitor.log")

# Formato IDENTICO al del controlador (para que las lineas encajen).
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Parametros del experimento (para enriquecer el marcador; autosuficiencia).
MONITOR_INTERVAL = os.getenv("MONITOR_INTERVAL", "5")
PPS_MIN = os.getenv("PPS_MIN", "50")
CONFIRMATION = os.getenv("CONFIRMATION", "2")


def _build_logger(log_path):
    """Crea un logger que escribe en el mismo archivo, mismo formato."""
    logger = logging.getLogger("mark_experiment")
    logger.setLevel(logging.INFO)
    logger.handlers = []
    handler = logging.FileHandler(log_path, mode="a")
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT))
    logger.addHandler(handler)
    # El marcador va SOLO al archivo (para no contaminar stdout, que se usa
    # para comunicar el experiment_id de forma limpia al llamador).
    return logger


def mark_start(logger, scenario, attacker, victim, attack_type, experiment_id):
    sep = "=" * 58
    logger.info(sep)
    logger.info("EXPERIMENT_START experiment_id=%s scenario=%s attacker=%s "
                "victim=%s attack_type=%s monitor_interval=%s pps_min=%s "
                "confirmation=%s",
                experiment_id, scenario, attacker, victim, attack_type,
                MONITOR_INTERVAL, PPS_MIN, CONFIRMATION)
    logger.info(sep)


def mark_end(logger, scenario, experiment_id, result):
    sep = "=" * 58
    logger.info(sep)
    logger.info("EXPERIMENT_END experiment_id=%s scenario=%s result=%s",
                experiment_id, scenario, result)
    logger.info(sep)


def mark_attack_start(logger, scenario, experiment_id):
    """Marca el inicio real del ataque (origen de tiempos para Td y Tm)."""
    logger.info("ATTACK_START experiment_id=%s scenario=%s",
                experiment_id, scenario)


def mark_attack_stop(logger, scenario, experiment_id):
    """Marca el fin real del ataque (origen de tiempos para Tr)."""
    logger.info("ATTACK_STOP experiment_id=%s scenario=%s",
                experiment_id, scenario)


def main():
    parser = argparse.ArgumentParser(
        description="Marcadores de experimento para el Hito 10.")
    parser.add_argument("accion",
                        choices=["start", "attack-start",
                                 "attack-stop", "end"],
                        help="start / attack-start / attack-stop / end")
    parser.add_argument("scenario",
                        help="nombre del escenario (syn_flood, udp_flood, "
                             "icmp_flood, coordinado, normal)")
    parser.add_argument("--attacker", default="h5",
                        help="host atacante (default h5; 'h5,h6,h7' coordinado)")
    parser.add_argument("--victim", default="h1", help="host victima")
    parser.add_argument("--attack-type", default="",
                        help="tipo de ataque (SYN/UDP/ICMP/COORDINADO)")
    parser.add_argument("--result", default="SUCCESS",
                        help="resultado (solo para 'end')")
    parser.add_argument("--experiment-id", default="",
                        help="id del experimento (auto en 'start' si se omite)")
    parser.add_argument("--log-path", default=DEFAULT_LOG_PATH,
                        help="ruta del monitor.log")
    args = parser.parse_args()

    experiment_id = args.experiment_id
    if not experiment_id:
        experiment_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    logger = _build_logger(args.log_path)

    if args.accion == "start":
        atype = args.attack_type or args.scenario.split("_")[0].upper()
        mark_start(logger, args.scenario, args.attacker, args.victim,
                   atype, experiment_id)
        # Comunicar el id por stdout (limpio, unica linea) para reutilizarlo
        # en los marcadores siguientes. El marcador ya quedo en el log.
        print(experiment_id)
    elif args.accion == "attack-start":
        mark_attack_start(logger, args.scenario, experiment_id)
        sys.stderr.write("ATTACK_START escrito (id=%s)\n" % experiment_id)
    elif args.accion == "attack-stop":
        mark_attack_stop(logger, args.scenario, experiment_id)
        sys.stderr.write("ATTACK_STOP escrito (id=%s)\n" % experiment_id)
    else:
        mark_end(logger, args.scenario, experiment_id, args.result)
        sys.stderr.write("EXPERIMENT_END escrito (id=%s)\n" % experiment_id)


if __name__ == "__main__":
    main()
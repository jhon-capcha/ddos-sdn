#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
analyze_metrics.py
===============================================================

Parser de metricas experimentales para el Hito 10.

Lee monitor.log, delimita cada experimento por los marcadores
EXPERIMENT_START...EXPERIMENT_END, y dentro de cada bloque calcula las
metricas temporales a partir de ATTACK_START / ATTACK_STOP y los eventos
del sistema (Deteccion, MITIGACION, FlowRemoved).

Principio: el parser NO infiere nada del algoritmo. Solo mide tiempos
entre marcadores explicitos y cuenta eventos. Si cambia la politica de
confirmacion o cualquier umbral, el parser no cambia.

Metricas por experimento:
    Td = primera Deteccion ATAQUE - ATTACK_START   (tiempo de deteccion)
    Tm = primer DROP instalado    - ATTACK_START   (tiempo de mitigacion)
    Tr = primer FlowRemoved       - ATTACK_STOP    (tiempo de recuperacion)
    attack_duration = ATTACK_STOP - ATTACK_START
    + contadores: ventanas normal/ataque, reglas DROP, FlowRemoved,
      rule_lifetime

Salida: CSV con una fila por experimento.

Uso:
    python analyze_metrics.py monitor.log [-o metricas.csv]

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

import argparse
import csv
import re
import sys
from datetime import datetime


# Formato de timestamp del log (identico al del controlador).
TS_FMT = "%Y-%m-%d %H:%M:%S"
# Regex para el timestamp al inicio de cada linea (ignora los milisegundos).
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def parse_ts(linea):
    """Extrae el datetime del inicio de una linea de log (o None)."""
    m = TS_RE.match(linea)
    if not m:
        return None
    return datetime.strptime(m.group(1), TS_FMT)


def parse_kv(linea):
    """Extrae los pares clave=valor de una linea de marcador."""
    return dict(re.findall(r"(\w+)=(\S+)", linea))


def split_experiments(lineas):
    """
    Divide el log en bloques por experiment_id. Devuelve un dict
    {experiment_id: [lineas del bloque]}.
    Un bloque va desde EXPERIMENT_START hasta EXPERIMENT_END (inclusive).
    """
    bloques = {}
    actual_id = None
    for ln in lineas:
        if "EXPERIMENT_START" in ln:
            kv = parse_kv(ln)
            actual_id = kv.get("experiment_id")
            if actual_id:
                bloques[actual_id] = [ln]
        elif actual_id is not None:
            bloques[actual_id].append(ln)
            if "EXPERIMENT_END" in ln:
                actual_id = None
    return bloques


def analizar_bloque(exp_id, lineas):
    """Calcula las metricas de un bloque experimental."""
    m = {
        "experiment_id": exp_id, "scenario": "", "attacker": "",
        "victim": "", "attack_type": "",
        "td": "", "tm": "", "tr": "", "attack_duration": "",
        "rule_lifetime": "", "normal_windows": 0, "attack_windows": 0,
        "drop_rules": 0, "flow_removed": 0, "result": "",
    }
    t_attack_start = None
    t_attack_stop = None
    t_first_attack_det = None
    t_first_drop = None
    t_first_flowrem = None

    for ln in lineas:
        ts = parse_ts(ln)

        if "EXPERIMENT_START" in ln:
            kv = parse_kv(ln)
            m["scenario"] = kv.get("scenario", "")
            m["attacker"] = kv.get("attacker", "")
            m["victim"] = kv.get("victim", "")
            m["attack_type"] = kv.get("attack_type", "")
        elif "EXPERIMENT_END" in ln:
            kv = parse_kv(ln)
            m["result"] = kv.get("result", "")
        elif "ATTACK_START" in ln:
            t_attack_start = ts
        elif "ATTACK_STOP" in ln:
            t_attack_stop = ts
        elif "Deteccion:" in ln:
            if "NORMAL" in ln:
                m["normal_windows"] += 1
            elif "ATAQUE" in ln:
                m["attack_windows"] += 1
                if t_first_attack_det is None:
                    t_first_attack_det = ts
        elif "DROP instalado" in ln:
            m["drop_rules"] += 1
            if t_first_drop is None:
                t_first_drop = ts
        elif "FlowRemoved" in ln:
            m["flow_removed"] += 1
            if t_first_flowrem is None:
                t_first_flowrem = ts
        # Vida de la regla (del log "expiro (vida=Xs, ...)").
        mv = re.search(r"vida=([\d.]+)s", ln)
        if mv:
            m["rule_lifetime"] = mv.group(1)

    # Calculo de tiempos (solo si hay referencias).
    def delta(a, b):
        return "%.1f" % (a - b).total_seconds() if a and b else ""

    if t_attack_start:
        m["td"] = delta(t_first_attack_det, t_attack_start)
        m["tm"] = delta(t_first_drop, t_attack_start)
    if t_attack_stop:
        m["tr"] = delta(t_first_flowrem, t_attack_stop)
    if t_attack_start and t_attack_stop:
        m["attack_duration"] = delta(t_attack_stop, t_attack_start)

    return m


COLUMNS = ["experiment_id", "scenario", "attacker", "victim", "attack_type",
           "td", "tm", "tr", "attack_duration", "rule_lifetime",
           "normal_windows", "attack_windows", "drop_rules", "flow_removed",
           "result"]


def main():
    ap = argparse.ArgumentParser(description="Parser de metricas del Hito 10.")
    ap.add_argument("logfile", help="ruta del monitor.log")
    ap.add_argument("-o", "--output", default="metricas_hito10.csv",
                    help="CSV de salida")
    args = ap.parse_args()

    with open(args.logfile) as f:
        lineas = f.readlines()

    bloques = split_experiments(lineas)
    if not bloques:
        sys.stderr.write("No se encontraron bloques EXPERIMENT_START/END.\n")
        sys.exit(1)

    filas = [analizar_bloque(eid, lns) for eid, lns in bloques.items()]

    with open(args.output, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(filas)

    # Resumen por pantalla.
    print("Experimentos analizados: %d" % len(filas))
    print("%-18s %-12s %6s %6s %6s %8s %8s" %
          ("experiment_id", "scenario", "Td", "Tm", "Tr", "n_win", "a_win"))
    for r in filas:
        print("%-18s %-12s %6s %6s %6s %8s %8s" %
              (r["experiment_id"], r["scenario"], r["td"] or "-",
               r["tm"] or "-", r["tr"] or "-",
               r["normal_windows"], r["attack_windows"]))
    print("\nCSV escrito en: %s" % args.output)


if __name__ == "__main__":
    main()

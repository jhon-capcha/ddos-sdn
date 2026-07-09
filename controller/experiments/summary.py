#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Muestra el resumen de un experimento del Hito 10 desde el CSV."""
import csv
import sys

csv_path = sys.argv[1]
eid = sys.argv[2]
rows = list(csv.DictReader(open(csv_path)))
r = next((x for x in rows if x["experiment_id"] == eid), None)

sep = "=" * 42
print(sep)
print(" RESUMEN DEL EXPERIMENTO")
print(sep)
if r:
    def v(k, u=""):
        val = r.get(k, "")
        return (val + u) if val else "-"
    print(" Escenario ......... %s" % r.get("scenario", "-"))
    print(" Td (deteccion) .... %s" % v("td", " s"))
    print(" Tm (mitigacion) ... %s" % v("tm", " s"))
    print(" Tr (recuperacion) . %s" % v("tr", " s"))
    print(" Duracion ataque ... %s" % v("attack_duration", " s"))
    print(" Vida de la regla .. %s" % v("rule_lifetime", " s"))
    print(" Ventanas ATAQUE ... %s" % r.get("attack_windows", "-"))
    print(" DROP instalados ... %s" % r.get("drop_rules", "-"))
    print(" FlowRemoved ....... %s" % r.get("flow_removed", "-"))
    print(" Resultado ......... %s" % r.get("result", "-"))
else:
    print(" (no se encontro el experimento en el CSV)")
print(sep)
print(" CSV acumulado: %s" % csv_path)

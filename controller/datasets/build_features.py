#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
build_features.py
===============================================================

Ingenieria de caracteristicas (Hito 6) para la deteccion de
DDoS en SDN. Transforma el dataset crudo por flujo
(dataset_final.csv) en un dataset por ventana de monitoreo
(dataset_features.csv) apto para el entrenamiento de ML.

Metodologia:
  - La ventana es el ciclo de monitoreo del controlador
    (MONITOR_INTERVAL = 5 s): groupby(scenario, timestamp).
  - Las tasas se calculan sobre INCREMENTOS entre ventanas
    consecutivas del mismo flujo (el packet_count de OpenFlow
    es acumulativo, no incremental).
  - La entropia de Shannon se calcula sobre la distribucion de
    FLUJOS por IP (frecuencia), sin ponderar por packet_count.
  - La etiqueta de la ventana es "ataque" si existe al menos un
    flujo de ataque en ella (any), si no "normal".

REFACTOR (Hito 8): el calculo de las features (entropia, tasas,
ensamblado del vector) se delega en feature_engineering.py, el
modulo compartido con el detector en linea (monitor.py). Esto
GARANTIZA LA PARIDAD entre el entrenamiento (este batch) y la
inferencia en tiempo real. La logica de este script (carga,
diff por flujo, agregacion, auditoria, export) no cambia.

Pipeline:
    1. Cargar y validar dataset_final.csv (17 columnas).
    2. Calcular delta_packets y delta_bytes por flujo (diff+fillna).
    3. Agrupar por ventana (scenario, timestamp).
    4-5. Features de volumen, tasa y entropia (feature_engineering).
    6. Etiqueta de ventana (any ataque).
    7. Auditoria (sin NaN/Inf, distribucion de clases).
    8. Exportar dataset_features.csv + reporte.

Uso:
    python3 build_features.py

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

import os
import sys
from datetime import datetime

import numpy as np
import pandas as pd

import feature_engineering as fe


# =====================================================
# CONFIGURACION
# =====================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROCESSED_DIR = os.path.join(BASE_DIR, "processed")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

INPUT_CSV = os.path.join(PROCESSED_DIR, "dataset_final.csv")
OUTPUT_CSV = os.path.join(PROCESSED_DIR, "dataset_features.csv")
REPORT_TXT = os.path.join(REPORTS_DIR, "features_report.txt")

# Intervalo de monitoreo (definido en el modulo compartido, unica fuente).
MONITOR_INTERVAL = fe.MONITOR_INTERVAL

# Etiquetas.
LABEL_NORMAL = "normal"
LABEL_ATTACK = "ataque"

# Columnas esperadas en el dataset crudo (17).
EXPECTED_COLUMNS = [
    "timestamp", "fecha", "scenario", "dpid",
    "src_mac", "dst_mac", "src_ip", "dst_ip", "src_host", "dst_host",
    "in_port", "out_port",
    "packet_count", "byte_count", "duration_sec", "priority",
    "label",
]

# Identificador completo del flujo (match fields de OpenFlow).
# Dos flujos distintos podrian compartir origen/destino pero diferir
# en puerto o prioridad: el diff() debe operar sobre el flujo exacto.
FLOW_ID_COLS = [
    "scenario", "dpid", "src_mac", "dst_mac",
    "in_port", "out_port", "priority",
]

# Columnas del dataset de features (12: 3 metadatos + 8 features + label).
# Las 8 features vienen del modulo compartido (orden canonico).
FEATURE_COLUMNS = fe.FEATURE_COLUMNS_FULL
OUTPUT_COLUMNS = ["timestamp", "fecha", "scenario"] + FEATURE_COLUMNS + ["label"]


# =====================================================
# UTILIDADES DE REPORTE
# =====================================================

class Reporter:
    def __init__(self):
        self.lineas = []

    def add(self, texto=""):
        print(texto)
        self.lineas.append(texto)

    def save(self, ruta):
        with open(ruta, "w") as f:
            f.write("\n".join(self.lineas) + "\n")


def abortar(reporter, mensaje):
    reporter.add("")
    reporter.add("ERROR: %s" % mensaje)
    reporter.add("Ingenieria de caracteristicas ABORTADA.")
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        reporter.save(REPORT_TXT)
    except Exception:
        pass
    sys.exit(1)


# =====================================================
# PIPELINE
# =====================================================

def main():
    reporter = Reporter()
    reporter.add("=" * 60)
    reporter.add("INGENIERIA DE CARACTERISTICAS - HITO 6")
    reporter.add("=" * 60)
    reporter.add("Fecha de generacion: %s"
                 % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    reporter.add("Entrada: %s" % INPUT_CSV)
    reporter.add("Ventana: %.0f s (MONITOR_INTERVAL)" % MONITOR_INTERVAL)
    reporter.add("")

    # --- Paso 1: cargar y validar ---
    reporter.add("[1] Cargando y validando dataset crudo...")
    if not os.path.exists(INPUT_CSV):
        abortar(reporter, "no se encontro %s" % INPUT_CSV)
    try:
        df = pd.read_csv(INPUT_CSV)
    except Exception as e:
        abortar(reporter, "no se pudo leer el CSV: %s" % e)

    if list(df.columns) != EXPECTED_COLUMNS:
        abortar(reporter, "columnas inesperadas en el dataset crudo")
    reporter.add("    OK  %d filas (flujos), %d columnas"
                 % (len(df), len(df.columns)))
    reporter.add("")

    # --- Paso 2: calcular incrementos por flujo ---
    reporter.add("[2] Calculando incrementos por flujo (diff + fillna)...")
    # Ordenar por flujo y tiempo para que diff() opere en secuencia.
    df = df.sort_values(FLOW_ID_COLS + ["timestamp"]).reset_index(drop=True)

    grupos = df.groupby(FLOW_ID_COLS, sort=False)
    # diff() da NaN en la primera observacion de cada flujo; ese NaN
    # se rellena con el propio contador (el incremento desde el
    # nacimiento del flujo hasta la primera captura es el contador).
    df["delta_packets"] = grupos["packet_count"].diff()
    df["delta_packets"] = df["delta_packets"].fillna(df["packet_count"])
    df["delta_bytes"] = grupos["byte_count"].diff()
    df["delta_bytes"] = df["delta_bytes"].fillna(df["byte_count"])

    # Salvaguarda: un contador que se reinicia (poco probable en este
    # laboratorio) produciria un delta negativo. Se acota a 0.
    neg_p = int((df["delta_packets"] < 0).sum())
    neg_b = int((df["delta_bytes"] < 0).sum())
    if neg_p or neg_b:
        reporter.add("    AVISO: deltas negativos (packets=%d, bytes=%d) -> 0"
                     % (neg_p, neg_b))
        df["delta_packets"] = df["delta_packets"].clip(lower=0)
        df["delta_bytes"] = df["delta_bytes"].clip(lower=0)
    reporter.add("    OK  delta_packets y delta_bytes calculados")
    reporter.add("")

    # --- Pasos 3-6: agregar por ventana ---
    reporter.add("[3-6] Agregando por ventana (scenario, timestamp)...")
    filas = []
    # Agrupar por la ventana natural del controlador.
    for (scenario, timestamp), g in df.groupby(["scenario", "timestamp"],
                                               sort=True):
        # Metadato: fecha legible (la de cualquier flujo de la ventana).
        fecha = g["fecha"].iloc[0]

        # Features de la ventana: calculadas por el modulo COMPARTIDO
        # (misma logica que el detector en linea -> paridad garantizada).
        feature_row = fe.build_feature_row(
            flow_count=len(g),
            sum_delta_packets=float(g["delta_packets"].sum()),
            sum_delta_bytes=float(g["delta_bytes"].sum()),
            src_ips=g["src_ip"],
            dst_ips=g["dst_ip"],
        )

        # Etiqueta de la ventana: ataque si hay al menos un flujo de ataque.
        label = LABEL_ATTACK if (g["label"] == LABEL_ATTACK).any() \
            else LABEL_NORMAL

        fila = {"timestamp": timestamp, "fecha": fecha, "scenario": scenario}
        fila.update(feature_row)
        fila["label"] = label
        filas.append(fila)

    features = pd.DataFrame(filas, columns=OUTPUT_COLUMNS)
    reporter.add("    OK  %d ventanas generadas" % len(features))
    reporter.add("")

    # --- Paso 7: auditoria ---
    reporter.add("[7] Auditoria del dataset de features")
    reporter.add("-" * 60)
    total = len(features)
    reporter.add("Ventanas totales : %d" % total)
    reporter.add("Columnas         : %d" % len(features.columns))
    reporter.add("")

    reporter.add("Ventanas por escenario:")
    for esc, n in features["scenario"].value_counts().sort_index().items():
        reporter.add("    %-12s %4d" % (esc, n))
    reporter.add("")

    reporter.add("Distribucion de clases (por ventana):")
    conteo = features["label"].value_counts()
    n_normal = int(conteo.get(LABEL_NORMAL, 0))
    n_attack = int(conteo.get(LABEL_ATTACK, 0))
    pct_n = 100.0 * n_normal / total if total else 0.0
    pct_a = 100.0 * n_attack / total if total else 0.0
    reporter.add("    %-8s %4d  (%5.1f%%)" % (LABEL_NORMAL, n_normal, pct_n))
    reporter.add("    %-8s %4d  (%5.1f%%)" % (LABEL_ATTACK, n_attack, pct_a))
    reporter.add("")

    # Integridad numerica: sin NaN ni Inf en las features.
    sub = features[FEATURE_COLUMNS]
    nan_count = int(sub.isnull().sum().sum())
    inf_count = int(np.isinf(sub.to_numpy(dtype=float)).sum())
    reporter.add("Valores NaN en features : %d" % nan_count)
    reporter.add("Valores Inf en features : %d" % inf_count)
    reporter.add("")

    # Rango de cada feature (verificacion de sanidad).
    reporter.add("Rango de las features:")
    for col in FEATURE_COLUMNS:
        reporter.add("    %-20s min=%.4f  max=%.4f  media=%.4f"
                     % (col, sub[col].min(), sub[col].max(), sub[col].mean()))
    reporter.add("-" * 60)
    reporter.add("")

    if nan_count or inf_count:
        abortar(reporter, "el dataset de features contiene NaN o Inf")

    # --- Paso 8: exportar ---
    reporter.add("[8] Exportando...")
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    features.to_csv(OUTPUT_CSV, index=False, lineterminator="\n")
    reporter.add("    -> %s" % OUTPUT_CSV)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    reporter.add("    -> %s" % REPORT_TXT)
    reporter.add("")
    reporter.add("=" * 60)
    reporter.add("INGENIERIA DE CARACTERISTICAS COMPLETADA")
    reporter.add("=" * 60)

    reporter.save(REPORT_TXT)


if __name__ == "__main__":
    main()
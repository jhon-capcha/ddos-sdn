#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
build_dataset.py
===============================================================

Consolidador y auditor del dataset de deteccion de DDoS en SDN
(Hito 5). A partir de los cinco CSV crudos por escenario, genera
un unico dataset_final.csv de forma reproducible y validada.

Pipeline:
    1. Verificar que existen los cinco CSV esperados.
    2. Validar que todos tienen exactamente las 17 columnas.
    3. Comprobar que no hay filas corruptas.
    4. Cargar todos los archivos con pandas.
    5. Concatenar sin alterar el orden experimental.
    6. Reiniciar el indice interno (no se exporta al CSV).
    7. Generar estadisticas (por escenario y por clase).
    8. Guardar processed/dataset_final.csv.
    9. Generar un reporte de auditoria en reports/.

Uso:
    python3 build_dataset.py

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

import os
import sys
from datetime import datetime

import pandas as pd


# =====================================================
# CONFIGURACION
# =====================================================

# Directorio base (donde vive este script: controller/datasets/).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RAW_DIR = os.path.join(BASE_DIR, "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

# Escenarios en el ORDEN experimental de adquisicion (se preserva).
SCENARIOS = ["normal", "syn_flood", "udp_flood", "icmp_flood", "coordinado"]

# Esquema esperado: las 17 columnas exactas del dataset crudo.
EXPECTED_COLUMNS = [
    "timestamp", "fecha", "scenario", "dpid",
    "src_mac", "dst_mac", "src_ip", "dst_ip", "src_host", "dst_host",
    "in_port", "out_port",
    "packet_count", "byte_count", "duration_sec", "priority",
    "label",
]

# Etiquetas esperadas.
LABEL_NORMAL = "normal"
LABEL_ATTACK = "ataque"

OUTPUT_CSV = os.path.join(PROCESSED_DIR, "dataset_final.csv")
REPORT_TXT = os.path.join(REPORTS_DIR, "build_report.txt")


# =====================================================
# UTILIDADES DE REPORTE
# =====================================================

class Reporter:
    """Acumula lineas para imprimirlas y guardarlas en el reporte."""

    def __init__(self):
        self.lineas = []

    def add(self, texto=""):
        print(texto)
        self.lineas.append(texto)

    def save(self, ruta):
        with open(ruta, "w") as f:
            f.write("\n".join(self.lineas) + "\n")


def abortar(reporter, mensaje):
    """Registra un error y termina la ejecucion."""
    reporter.add("")
    reporter.add("ERROR: %s" % mensaje)
    reporter.add("Consolidacion ABORTADA.")
    # Intentar guardar el reporte parcial para dejar traza del fallo.
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
    reporter.add("CONSOLIDACION DEL DATASET - HITO 5")
    reporter.add("=" * 60)
    reporter.add("Fecha de generacion: %s"
                 % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    reporter.add("Directorio raw: %s" % RAW_DIR)
    reporter.add("")

    # --- Paso 1: verificar existencia de los cinco CSV ---
    reporter.add("[1] Verificando existencia de los CSV...")
    rutas = {}
    for esc in SCENARIOS:
        ruta = os.path.join(RAW_DIR, "%s.csv" % esc)
        if not os.path.exists(ruta):
            abortar(reporter, "no se encontro el archivo: %s" % ruta)
        rutas[esc] = ruta
        reporter.add("    OK  %s.csv" % esc)
    reporter.add("")

    # --- Pasos 2-4: validar estructura, filas corruptas y cargar ---
    reporter.add("[2-4] Validando estructura y cargando...")
    frames = []
    filas_por_escenario = {}
    for esc in SCENARIOS:
        try:
            df = pd.read_csv(rutas[esc])
        except Exception as e:
            abortar(reporter, "no se pudo leer %s.csv: %s" % (esc, e))

        # Validar columnas exactas (nombres y orden).
        cols = list(df.columns)
        if cols != EXPECTED_COLUMNS:
            faltantes = set(EXPECTED_COLUMNS) - set(cols)
            extra = set(cols) - set(EXPECTED_COLUMNS)
            detalle = []
            if faltantes:
                detalle.append("faltan: %s" % sorted(faltantes))
            if extra:
                detalle.append("sobran: %s" % sorted(extra))
            if not detalle:
                detalle.append("orden distinto")
            abortar(reporter, "%s.csv tiene columnas invalidas (%s)"
                    % (esc, "; ".join(detalle)))

        # Validar consistencia de la columna scenario.
        escenarios_en_col = df["scenario"].unique().tolist()
        if escenarios_en_col != [esc]:
            abortar(reporter, "%s.csv contiene scenario inconsistente: %s"
                    % (esc, escenarios_en_col))

        # Validar etiquetas dentro del conjunto esperado.
        etiquetas = set(df["label"].unique())
        validas = {LABEL_NORMAL, LABEL_ATTACK}
        if not etiquetas.issubset(validas):
            invalidas = etiquetas - validas
            abortar(reporter, "%s.csv tiene etiquetas invalidas: %s"
                    % (esc, sorted(invalidas)))

        filas_por_escenario[esc] = len(df)
        frames.append(df)
        reporter.add("    OK  %-12s %5d filas, 17 columnas" % (esc, len(df)))
    reporter.add("")

    # --- Paso 5: concatenar en el orden experimental ---
    reporter.add("[5] Concatenando en orden experimental...")
    reporter.add("    Orden: %s" % " -> ".join(SCENARIOS))
    dataset = pd.concat(frames, ignore_index=True)
    reporter.add("")

    # --- Paso 6: reiniciar indice (en memoria, no se exporta) ---
    dataset = dataset.reset_index(drop=True)

    # --- Paso 7: estadisticas ---
    reporter.add("[6-7] Estadisticas del dataset consolidado")
    reporter.add("-" * 60)
    total = len(dataset)
    reporter.add("Filas totales : %d" % total)
    reporter.add("Columnas      : %d" % len(dataset.columns))
    reporter.add("")

    reporter.add("Filas por escenario:")
    for esc in SCENARIOS:
        n = filas_por_escenario[esc]
        pct = 100.0 * n / total if total else 0.0
        reporter.add("    %-12s %5d  (%5.1f%%)" % (esc, n, pct))
    reporter.add("")

    reporter.add("Distribucion de clases:")
    conteo = dataset["label"].value_counts()
    n_normal = int(conteo.get(LABEL_NORMAL, 0))
    n_attack = int(conteo.get(LABEL_ATTACK, 0))
    pct_normal = 100.0 * n_normal / total if total else 0.0
    pct_attack = 100.0 * n_attack / total if total else 0.0
    reporter.add("    %-8s %5d  (%5.1f%%)" % (LABEL_NORMAL, n_normal, pct_normal))
    reporter.add("    %-8s %5d  (%5.1f%%)" % (LABEL_ATTACK, n_attack, pct_attack))
    reporter.add("")

    # Validacion cruzada de columnas (todas presentes).
    reporter.add("Verificacion de columnas: %s"
                 % ("OK" if list(dataset.columns) == EXPECTED_COLUMNS
                    else "FALLO"))
    # Valores nulos.
    nulos = int(dataset.isnull().sum().sum())
    reporter.add("Valores nulos totales   : %d" % nulos)
    # Duplicados exactos.
    duplicados = int(dataset.duplicated().sum())
    reporter.add("Filas duplicadas exactas: %d" % duplicados)
    reporter.add("-" * 60)
    reporter.add("")

    # --- Paso 8: guardar dataset_final.csv ---
    reporter.add("[8] Guardando dataset consolidado...")
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    # index=False: no exportar el indice de pandas (decision de diseno).
    # lineterminator="\n": coherente con los CSV crudos (LF, no CRLF).
    dataset.to_csv(OUTPUT_CSV, index=False, lineterminator="\n")
    reporter.add("    -> %s" % OUTPUT_CSV)
    reporter.add("")

    # --- Paso 9: guardar reporte ---
    reporter.add("[9] Guardando reporte de auditoria...")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    reporter.add("    -> %s" % REPORT_TXT)
    reporter.add("")
    reporter.add("=" * 60)
    reporter.add("CONSOLIDACION COMPLETADA CORRECTAMENTE")
    reporter.add("=" * 60)

    reporter.save(REPORT_TXT)


if __name__ == "__main__":
    main()

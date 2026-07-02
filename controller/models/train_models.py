#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
train_models.py
===============================================================

Entrenamiento y evaluacion de modelos de ML clasico (Hito 7)
para la deteccion de DDoS en SDN, sobre dataset_features.csv
(una muestra por ventana de monitoreo).

Modelos comparados (4 familias distintas):
    - Decision Tree (restringido: max_depth=5, min_samples_leaf=2)
    - Random Forest (200 arboles)
    - SVM (kernel RBF)
    - KNN (k=5)

Metodologia:
    - Seleccion EXPLICITA de las features (evita fuga de metadatos
      como scenario/timestamp).
    - Pipeline(StandardScaler + modelo): el escalado se ajusta solo
      con los datos de entrenamiento de cada fold (sin data leakage).
    - class_weight='balanced' en DT, RF y SVM (mitiga el desbalance).
      KNN no soporta class_weight.
    - Validacion cruzada estratificada 5-fold (metricas robustas).
    - Holdout 70/30 estratificado (matriz de confusion + tiempo de
      inferencia promediado con warm-up, en us/muestra).
    - Importancia de features (DT y RF), arbol legible (PNG + TXT),
      comparativa de F1 entre modelos.

Modos:
    python3 train_models.py
        Evaluacion PRINCIPAL (8 features). Salidas en results/ y
        reports/, modelo de produccion best_model.joblib.

    python3 train_models.py --sin-flowcount
        Evaluacion COMPLEMENTARIA (7 features, sin flow_count).
        Analisis de robustez: fuerza al modelo a usar la fisica del
        trafico en vez del numero de flujos (propio de la topologia).
        Salidas en results_sin_flowcount/ y reports_sin_flowcount/,
        SIN sobrescribir la evaluacion principal.

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")  # backend sin display (VM sin entorno grafico)
import matplotlib.pyplot as plt

import joblib
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import (StratifiedKFold, cross_validate,
                                     train_test_split)
from sklearn.inspection import permutation_importance
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             accuracy_score, confusion_matrix)
from sklearn.tree import (DecisionTreeClassifier, export_text, plot_tree)
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier


# =====================================================
# CONFIGURACION
# =====================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(os.path.dirname(BASE_DIR), "datasets")
INPUT_CSV = os.path.join(DATASETS_DIR, "processed", "dataset_features.csv")

# Las 8 features predictoras (seleccion EXPLICITA, sin metadatos).
FEATURE_COLUMNS_FULL = [
    "flow_count",
    "packet_count_total", "byte_count_total",
    "packets_per_second", "bytes_per_second", "bytes_per_packet",
    "entropy_src_ip", "entropy_dst_ip",
]

LABEL_COLUMN = "label"
POSITIVE_CLASS = "ataque"   # clase positiva para precision/recall/F1

# Abreviaturas para nombrar los archivos de figuras.
MODEL_ABBR = {
    "Decision Tree": "dt",
    "Random Forest": "rf",
    "SVM": "svm",
    "KNN": "knn",
}
SEED = 42
N_SPLITS = 5
TEST_SIZE = 0.30

# Medicion del tiempo de inferencia.
WARMUP_ITERS = 100
MEASURE_ITERS = 1000


def configurar(sin_flowcount):
    """
    Devuelve (FEATURE_COLUMNS, rutas) segun el modo.

    - Modo principal (8 features): salidas en results/ y reports/,
      modelo best_model.joblib. Es la evaluacion oficial.
    - Modo complementario (--sin-flowcount, 7 features): salidas en
      results_sin_flowcount/ y reports_sin_flowcount/, sin sobrescribir
      la evaluacion principal ni el modelo de produccion. Es el analisis
      de robustez que fuerza al modelo a usar la fisica del trafico.
    """
    if sin_flowcount:
        features = [c for c in FEATURE_COLUMNS_FULL if c != "flow_count"]
        results_dir = os.path.join(BASE_DIR, "results_sin_flowcount")
        reports_dir = os.path.join(BASE_DIR, "reports_sin_flowcount")
        # El modelo complementario NO es el de produccion: no piso
        # best_model.joblib ni feature_columns.json.
        model_path = os.path.join(results_dir, "model_sin_flowcount.joblib")
        features_json = os.path.join(results_dir,
                                     "feature_columns_sin_flowcount.json")
    else:
        features = list(FEATURE_COLUMNS_FULL)
        results_dir = os.path.join(BASE_DIR, "results")
        reports_dir = os.path.join(BASE_DIR, "reports")
        model_path = os.path.join(BASE_DIR, "best_model.joblib")
        features_json = os.path.join(BASE_DIR, "feature_columns.json")

    rutas = {
        "results_dir": results_dir,
        "reports_dir": reports_dir,
        "model_path": model_path,
        "features_json": features_json,
        "results_csv": os.path.join(results_dir, "resultados_modelos.csv"),
        "report_txt": os.path.join(reports_dir, "training_report.txt"),
    }
    return features, rutas


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


def abortar(reporter, mensaje, rutas=None):
    reporter.add("")
    reporter.add("ERROR: %s" % mensaje)
    reporter.add("Entrenamiento ABORTADO.")
    if rutas is not None:
        try:
            os.makedirs(rutas["reports_dir"], exist_ok=True)
            reporter.save(rutas["report_txt"])
        except Exception:
            pass
    sys.exit(1)


# =====================================================
# MODELOS
# =====================================================

def construir_modelos():
    """Devuelve los 4 modelos con sus hiperparametros."""
    return {
        "Decision Tree": DecisionTreeClassifier(
            max_depth=5, min_samples_leaf=2,
            class_weight="balanced", random_state=SEED),
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced", random_state=SEED),
        "SVM": SVC(
            kernel="rbf",
            class_weight="balanced", random_state=SEED),
        "KNN": KNeighborsClassifier(n_neighbors=5),
    }


def hacer_pipeline(modelo):
    """Pipeline con escalado (evita fuga: el scaler se ajusta en train)."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("model", modelo),
    ])


# =====================================================
# FIGURAS
# =====================================================

def fig_confusion(cm, nombre, ruta, clases):
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_title("Matriz de confusion - %s" % nombre)
    ax.set_xlabel("Prediccion")
    ax.set_ylabel("Real")
    ax.set_xticks(range(len(clases)))
    ax.set_yticks(range(len(clases)))
    ax.set_xticklabels(clases)
    ax.set_yticklabels(clases)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                    color="black")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(ruta, dpi=130)
    plt.close(fig)


def fig_importancia(importancias, nombre, ruta, feature_columns):
    orden = np.argsort(importancias)
    fig, ax = plt.subplots(figsize=(6.5, 4.0))
    ax.barh(np.array(feature_columns)[orden], importancias[orden],
            color="#3b6ea5")
    ax.set_title("Importancia de features - %s" % nombre)
    ax.set_xlabel("Importancia")
    fig.tight_layout()
    fig.savefig(ruta, dpi=130)
    plt.close(fig)


def fig_arbol(modelo_dt, ruta, clases, feature_columns):
    fig, ax = plt.subplots(figsize=(16, 9))
    plot_tree(modelo_dt, feature_names=feature_columns,
              class_names=clases, filled=True, rounded=True,
              fontsize=8, ax=ax)
    fig.tight_layout()
    fig.savefig(ruta, dpi=130)
    plt.close(fig)


def fig_permutation(medias, stds, ruta, feature_columns):
    orden = np.argsort(medias)
    fig, ax = plt.subplots(figsize=(6.5, 4.0))
    ax.barh(np.array(feature_columns)[orden], medias[orden],
            xerr=stds[orden], color="#a5683b", ecolor="#333333", capsize=3)
    ax.set_title("Importancia por permutacion - Random Forest")
    ax.set_xlabel("Caida media de F1 al permutar (mayor = mas importante)")
    fig.tight_layout()
    fig.savefig(ruta, dpi=130)
    plt.close(fig)


def fig_comparativa_f1(nombres, f1s, ruta):
    orden = np.argsort(f1s)[::-1]
    fig, ax = plt.subplots(figsize=(6.5, 3.8))
    ax.barh(np.array(nombres)[orden][::-1], np.array(f1s)[orden][::-1],
            color="#4c9a5a")
    ax.set_xlim(0, 1.05)
    ax.set_title("Comparativa de F1-score (validacion cruzada)")
    ax.set_xlabel("F1-score (clase ataque)")
    for i, v in enumerate(np.array(f1s)[orden][::-1]):
        ax.text(v + 0.01, i, "%.4f" % v, va="center")
    fig.tight_layout()
    fig.savefig(ruta, dpi=130)
    plt.close(fig)


# =====================================================
# PIPELINE PRINCIPAL
# =====================================================

def main():
    parser = argparse.ArgumentParser(
        description="Entrenamiento de modelos ML para deteccion DDoS (Hito 7)")
    parser.add_argument(
        "--sin-flowcount", action="store_true",
        help="Evaluacion complementaria: excluye flow_count de las features "
             "(analisis de robustez que fuerza al modelo a usar la fisica del "
             "trafico en vez del numero de flujos, propio de la topologia).")
    args = parser.parse_args()

    FEATURE_COLUMNS, rutas = configurar(args.sin_flowcount)
    modo = "COMPLEMENTARIA (sin flow_count, 7 features)" \
        if args.sin_flowcount else "PRINCIPAL (8 features)"

    reporter = Reporter()
    reporter.add("=" * 60)
    reporter.add("ENTRENAMIENTO Y EVALUACION DE MODELOS - HITO 7")
    reporter.add("Evaluacion %s" % modo)
    reporter.add("=" * 60)
    reporter.add("Fecha: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    reporter.add("Entrada: %s" % INPUT_CSV)
    reporter.add("")

    os.makedirs(rutas["results_dir"], exist_ok=True)
    os.makedirs(rutas["reports_dir"], exist_ok=True)

    # --- Carga y seleccion de features ---
    reporter.add("[1] Cargando dataset de features...")
    if not os.path.exists(INPUT_CSV):
        abortar(reporter, "no se encontro %s" % INPUT_CSV, rutas)
    df = pd.read_csv(INPUT_CSV)

    faltantes = [c for c in FEATURE_COLUMNS + [LABEL_COLUMN]
                 if c not in df.columns]
    if faltantes:
        abortar(reporter, "faltan columnas: %s" % faltantes, rutas)

    X = df[FEATURE_COLUMNS].values
    y = df[LABEL_COLUMN].values
    clases = sorted(np.unique(y).tolist())  # ['ataque','normal']
    n_pos = int((y == POSITIVE_CLASS).sum())
    n_neg = int((y != POSITIVE_CLASS).sum())
    reporter.add("    Muestras: %d | Features: %d" % (X.shape[0], X.shape[1]))
    reporter.add("    Clases: %s (%s=%d, resto=%d)"
                 % (clases, POSITIVE_CLASS, n_pos, n_neg))
    reporter.add("    Features: %s" % ", ".join(FEATURE_COLUMNS))
    reporter.add("")

    # --- Validacion cruzada estratificada ---
    reporter.add("[2] Validacion cruzada estratificada (%d folds)..." % N_SPLITS)
    skf = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=SEED)
    scoring = {
        "accuracy": "accuracy",
        "precision": "precision_macro",
        "recall": "recall_macro",
        "f1_pos": lambda est, Xv, yv: f1_score(
            yv, est.predict(Xv), pos_label=POSITIVE_CLASS),
    }

    modelos = construir_modelos()
    resultados = []
    f1_cv = {}
    for nombre, modelo in modelos.items():
        pipe = hacer_pipeline(modelo)
        cv = cross_validate(pipe, X, y, cv=skf, scoring=scoring)
        acc = cv["test_accuracy"].mean()
        prec = cv["test_precision"].mean()
        rec = cv["test_recall"].mean()
        f1 = cv["test_f1_pos"].mean()
        f1_std = cv["test_f1_pos"].std()
        f1_cv[nombre] = f1
        resultados.append({
            "modelo": nombre,
            "accuracy": round(acc, 4),
            "precision_macro": round(prec, 4),
            "recall_macro": round(rec, 4),
            "f1_ataque": round(f1, 4),
            "f1_std": round(f1_std, 4),
        })
        reporter.add("    %-14s acc=%.4f  prec=%.4f  rec=%.4f  F1=%.4f (+-%.4f)"
                     % (nombre, acc, prec, rec, f1, f1_std))
    reporter.add("")

    # --- Holdout 70/30 para matriz de confusion y tiempo de inferencia ---
    reporter.add("[3] Holdout 70/30 (matriz de confusion + tiempo)...")
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=SEED)

    tiempos = {}
    pipes_entrenados = {}
    for nombre, modelo in construir_modelos().items():
        pipe = hacer_pipeline(modelo)
        pipe.fit(X_tr, y_tr)
        pipes_entrenados[nombre] = pipe
        y_pred = pipe.predict(X_te)

        cm = confusion_matrix(y_te, y_pred, labels=clases)
        fig_confusion(cm, nombre,
                      os.path.join(rutas["results_dir"],
                                   "confusion_matrix_%s.png"
                                   % MODEL_ABBR[nombre]),
                      clases)

        # Tiempo de inferencia: warm-up + promedio (us/muestra).
        for _ in range(WARMUP_ITERS):
            pipe.predict(X_te)
        t0 = time.perf_counter()
        for _ in range(MEASURE_ITERS):
            pipe.predict(X_te)
        t1 = time.perf_counter()
        us = (t1 - t0) / (MEASURE_ITERS * len(X_te)) * 1e6
        tiempos[nombre] = us

        # Anexar tiempo al resultado correspondiente.
        for r in resultados:
            if r["modelo"] == nombre:
                r["tiempo_us_muestra"] = round(us, 4)
                # cm ordenada por 'clases'; localizar ataque/normal
                idx_at = clases.index(POSITIVE_CLASS)
                idx_no = 1 - idx_at
                r["holdout_TP"] = int(cm[idx_at, idx_at])
                r["holdout_FN"] = int(cm[idx_at, idx_no])
                r["holdout_FP"] = int(cm[idx_no, idx_at])
                r["holdout_TN"] = int(cm[idx_no, idx_no])
        reporter.add("    %-14s tiempo=%.4f us/muestra  cm=%s"
                     % (nombre, us, cm.tolist()))
    reporter.add("")

    # --- Importancia de features (DT y RF) ---
    reporter.add("[4] Importancia de features (DT y RF)...")
    for nombre, fname in [("Decision Tree", "dt"), ("Random Forest", "rf")]:
        imp = pipes_entrenados[nombre].named_steps["model"].feature_importances_
        fig_importancia(imp, nombre,
                        os.path.join(rutas["results_dir"],
                                     "feature_importance_%s.png" % fname),
                        FEATURE_COLUMNS)
        top = sorted(zip(FEATURE_COLUMNS, imp), key=lambda x: -x[1])[:3]
        reporter.add("    %-14s top-3: %s"
                     % (nombre,
                        ", ".join("%s=%.3f" % (f, v) for f, v in top)))
    reporter.add("")

    # --- Importancia por permutacion (independiente del algoritmo) ---
    reporter.add("[5] Importancia por permutacion (Random Forest, holdout)...")
    # Medida independiente del modelo: mide la caida de F1 al permutar
    # cada feature. NOTA: con features redundantes (varias separan por
    # si solas), una importancia baja indica SUSTITUIBILIDAD, no
    # irrelevancia (permutar una no daña si otra la reemplaza).
    rf_pipe = pipes_entrenados["Random Forest"]
    scorer_f1 = lambda est, Xv, yv: f1_score(
        yv, est.predict(Xv), pos_label=POSITIVE_CLASS)
    perm = permutation_importance(
        rf_pipe, X_te, y_te, scoring=scorer_f1,
        n_repeats=30, random_state=SEED)
    fig_permutation(perm.importances_mean, perm.importances_std,
                    os.path.join(rutas["results_dir"],
                                 "permutation_importance_rf.png"),
                    FEATURE_COLUMNS)
    perm_top = sorted(zip(FEATURE_COLUMNS, perm.importances_mean),
                      key=lambda x: -x[1])[:3]
    reporter.add("    top-3: %s"
                 % ", ".join("%s=%.4f" % (f, v) for f, v in perm_top))
    reporter.add("    (nota: importancia baja = sustituibilidad por "
                 "redundancia, no irrelevancia)")
    reporter.add("")

    # --- Arbol de decision legible (PNG + TXT) ---
    reporter.add("[6] Exportando arbol de decision (PNG + TXT)...")
    dt_model = pipes_entrenados["Decision Tree"].named_steps["model"]
    fig_arbol(dt_model, os.path.join(rutas["results_dir"], "decision_tree.png"),
              clases, FEATURE_COLUMNS)
    texto_arbol = export_text(dt_model, feature_names=FEATURE_COLUMNS)
    with open(os.path.join(rutas["results_dir"], "decision_tree.txt"), "w") as f:
        f.write(texto_arbol)
    reporter.add("    -> decision_tree.png / decision_tree.txt")
    reporter.add("")

    # --- Comparativa de F1 ---
    reporter.add("[7] Comparativa de F1 entre modelos...")
    fig_comparativa_f1(list(f1_cv.keys()), list(f1_cv.values()),
                       os.path.join(rutas["results_dir"],
                                    "model_comparison_f1.png"))
    reporter.add("    -> model_comparison_f1.png")
    reporter.add("")

    # --- Seleccion del mejor modelo (F1, desempate por tiempo) ---
    reporter.add("[8] Seleccion del mejor modelo...")
    mejor = max(resultados,
                key=lambda r: (r["f1_ataque"], -r["tiempo_us_muestra"]))
    nombre_mejor = mejor["modelo"]
    reporter.add("    Mejor modelo: %s (F1=%.4f, %.4f us/muestra)"
                 % (nombre_mejor, mejor["f1_ataque"],
                    mejor["tiempo_us_muestra"]))

    # Reentrenar el mejor con TODOS los datos y serializar.
    pipe_final = hacer_pipeline(construir_modelos()[nombre_mejor])
    pipe_final.fit(X, y)
    joblib.dump(pipe_final, rutas["model_path"])
    with open(rutas["features_json"], "w") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)
    reporter.add("    -> %s (reentrenado con todo el dataset)"
                 % os.path.basename(rutas["model_path"]))
    reporter.add("    -> %s" % os.path.basename(rutas["features_json"]))
    reporter.add("")

    # --- Guardar CSV de resultados ---
    cols = ["modelo", "accuracy", "precision_macro", "recall_macro",
            "f1_ataque", "f1_std", "tiempo_us_muestra",
            "holdout_TP", "holdout_FP", "holdout_FN", "holdout_TN"]
    pd.DataFrame(resultados)[cols].to_csv(rutas["results_csv"], index=False,
                                          lineterminator="\n")
    reporter.add("    -> resultados_modelos.csv")
    reporter.add("")

    reporter.add("=" * 60)
    reporter.add("ENTRENAMIENTO COMPLETADO")
    reporter.add("=" * 60)
    reporter.save(rutas["report_txt"])


if __name__ == "__main__":
    main()
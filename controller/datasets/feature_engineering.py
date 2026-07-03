#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
feature_engineering.py
===============================================================

Logica PURA de ingenieria de caracteristicas, COMPARTIDA entre:

  - build_features.py  (batch, Hito 6): procesa el dataset crudo
    completo y genera dataset_features.csv.
  - monitor.py         (online, Hito 8): calcula las mismas
    features en tiempo real, ventana a ventana.

El objetivo de este modulo es GARANTIZAR LA PARIDAD: ambos
contextos calculan las features con exactamente la misma logica,
las mismas constantes y el mismo redondeo. Cualquier divergencia
entre entrenamiento (batch) e inferencia (online) produciria
predicciones erroneas silenciosas.

Este modulo NO tiene estado ni hace I/O: solo funciones puras.
El calculo del incremento (delta) es distinto en cada contexto
(batch usa pandas .diff(); online resta contra el estado guardado),
pero AMBOS alimentan estas funciones con los mismos numeros.

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

from collections import Counter

import numpy as np


# =====================================================
# CONSTANTES DE PARIDAD
# =====================================================

# Intervalo de monitoreo del controlador (segundos). Define la ventana.
# DEBE ser identico en batch y online.
MONITOR_INTERVAL = 5.0

# Redondeos aplicados a cada feature (criticos para la paridad por hash:
# batch y online deben redondear exactamente igual).
ROUND_RATE = 4      # pps, bps, bpp
ROUND_ENTROPY = 6   # entropias

# Las 8 features en su orden canonico (evaluacion cientifica, Hito 7).
FEATURE_COLUMNS_FULL = [
    "flow_count",
    "packet_count_total", "byte_count_total",
    "packets_per_second", "bytes_per_second", "bytes_per_packet",
    "entropy_src_ip", "entropy_dst_ip",
]

# Las 7 features del detector operativo (sin flow_count, Hito 8).
# flow_count codifica la topologia del laboratorio, no la fisica del
# ataque; el detector de produccion no debe depender de ella.
FEATURE_COLUMNS_OPERATIONAL = [
    "packet_count_total", "byte_count_total",
    "packets_per_second", "bytes_per_second", "bytes_per_packet",
    "entropy_src_ip", "entropy_dst_ip",
]


# =====================================================
# ENTROPIA DE SHANNON (pura, acepta Series o lista)
# =====================================================

def shannon_entropy(valores):
    """
    Entropia de Shannon (base 2) sobre la distribucion de FRECUENCIAS
    de los valores (p. ej. IPs de una ventana).

        H = - sum_i  p_i * log2(p_i)

    donde p_i es la proporcion de flujos con la IP i en la ventana.
    NO se pondera por packet_count: se mide la dispersion de fuentes.

    - Una sola IP  -> H = 0 (concentracion total).
    - IPs uniformes -> H maxima (log2 del numero de IPs distintas).

    Acepta cualquier iterable (pd.Series en batch, lista en online).
    El resultado es invariante al orden de los valores, verificado
    para dar resultado identico bit a bit tras redondeo entre ambos
    contextos.
    """
    conteos = Counter(valores)
    total = sum(conteos.values())
    if total == 0:
        return 0.0
    ps = np.array([c / total for c in conteos.values()], dtype=float)
    # Solo p > 0 contribuyen (0*log0 = 0 por convencion); Counter no
    # genera claves con conteo 0, asi que todas las p son > 0.
    h = float(-(ps * np.log2(ps)).sum())
    # Normalizar el cero negativo (-0.0) que surge cuando hay una sola
    # clase (p=1 -> -1*log2(1) = -0.0). Evita '-0.0' en CSV/logs.
    return h + 0.0 if h == 0.0 else h

# =====================================================
# TASAS DE VENTANA (puras)
# =====================================================

def window_rates(sum_delta_packets, sum_delta_bytes,
                 interval=MONITOR_INTERVAL):
    """
    Calcula las tres tasas de la ventana a partir de los incrementos
    (delta) agregados. Identico en batch y online.

        packets_per_second = sum_delta_packets / interval
        bytes_per_second   = sum_delta_bytes   / interval
        bytes_per_packet   = sum_delta_bytes   / max(sum_delta_packets, 1)

    El max(..., 1) protege la division cuando no hay trafico nuevo.
    Devuelve (pps, bps, bpp) SIN redondear (el redondeo se aplica al
    ensamblar el vector, para un unico punto de control).
    """
    pps = sum_delta_packets / interval
    bps = sum_delta_bytes / interval
    bpp = sum_delta_bytes / max(sum_delta_packets, 1.0)
    return pps, bps, bpp


# =====================================================
# ENSAMBLADO DEL VECTOR DE FEATURES (puro)
# =====================================================

def build_feature_row(flow_count, sum_delta_packets, sum_delta_bytes,
                      src_ips, dst_ips):
    """
    Construye el diccionario de las 8 features de una ventana, con el
    redondeo canonico. Es el UNICO lugar donde se calcula una feature,
    de modo que batch y online producen exactamente los mismos valores.

    Parametros:
        flow_count        : numero de flujos en la ventana (int)
        sum_delta_packets : suma de incrementos de paquetes (float)
        sum_delta_bytes   : suma de incrementos de bytes (float)
        src_ips           : iterable de IPs origen (una por flujo)
        dst_ips           : iterable de IPs destino (una por flujo)

    Devuelve un dict {feature: valor} con las 8 claves de
    FEATURE_COLUMNS_FULL, en los tipos y redondeos correctos.
    """
    pps, bps, bpp = window_rates(sum_delta_packets, sum_delta_bytes)
    h_src = shannon_entropy(src_ips)
    h_dst = shannon_entropy(dst_ips)
    return {
        "flow_count": int(flow_count),
        "packet_count_total": int(sum_delta_packets),
        "byte_count_total": int(sum_delta_bytes),
        "packets_per_second": round(pps, ROUND_RATE),
        "bytes_per_second": round(bps, ROUND_RATE),
        "bytes_per_packet": round(bpp, ROUND_RATE),
        "entropy_src_ip": round(h_src, ROUND_ENTROPY),
        "entropy_dst_ip": round(h_dst, ROUND_ENTROPY),
    }


def feature_row_to_vector(feature_row, feature_columns):
    """
    Extrae del dict de features un vector ordenado segun feature_columns
    (el contrato cargado de feature_columns.json). Valida la longitud
    para evitar errores silenciosos de orden/numero de features.

    Devuelve una lista de valores en el orden exacto de feature_columns.
    """
    faltantes = [c for c in feature_columns if c not in feature_row]
    if faltantes:
        raise RuntimeError(
            "Features ausentes en la fila: %s" % faltantes)
    vector = [feature_row[c] for c in feature_columns]
    if len(vector) != len(feature_columns):
        raise RuntimeError(
            "Longitud del vector (%d) != contrato (%d)"
            % (len(vector), len(feature_columns)))
    return vector

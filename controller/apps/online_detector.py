#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
online_detector.py
===============================================================

Inteligencia del detector DDoS en tiempo real.

Clases:
  - OnlineFeatureBuilder: convierte las estadisticas de flujo
    (FlowStats) de cada ciclo en un vector de features, manteniendo
    el estado incremental para calcular los Delta. DETERMINISTA.
    Ademas expone last_flow_deltas (estado publico de solo lectura
    de la ultima ventana) para el identificador de atacantes (Hito 9).
  - OnlineDetector: carga el modelo y su contrato de features, y
    clasifica un feature_row en NORMAL / ATAQUE.

Paridad: el calculo de features se delega en feature_engineering.py,
el mismo modulo que usa build_features.py (batch). El Delta se calcula
aqui (contra el estado guardado), pero las features finales las produce
el modulo compartido. last_flow_deltas NO interviene en el feature_row
(paridad verificada: anadir el estado publico no altera el calculo).

Linea base (baseline): el detector clasifica desde el SEGUNDO ciclo.
El primer ciclo solo fija la linea base de los contadores, porque en
el primer poll los flujos pueden llevar tiempo activos y su contador
acumulado no representa el intervalo de 5 s.

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

import json
import os
import sys

import joblib

# Importar el modulo compartido de features. Se anade la carpeta
# datasets/ al path para poder importarlo desde apps/.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_DATASETS_DIR = os.path.join(os.path.dirname(_THIS_DIR), "datasets")
if _DATASETS_DIR not in sys.path:
    sys.path.insert(0, _DATASETS_DIR)

import feature_engineering as fe


# =====================================================
# CONFIGURACION
# =====================================================

# Tiempo (segundos) sin actividad tras el cual se purga un flujo del
# estado. Con MONITOR_INTERVAL=5s, 30s equivalen a ~6 ciclos.
FLOW_TIMEOUT = 30.0


# =====================================================
# CONSTRUCTOR DE FEATURES EN LINEA (estado incremental)
# =====================================================

class OnlineFeatureBuilder:
    """
    Mantiene el estado de los contadores por flujo entre ciclos y
    produce, en cada ciclo, el vector de las 8 features de la ventana.

    Contrato:
        feature_row = builder.update(flows, now)
        - SIEMPRE devuelve un feature_row (nunca None).
        - builder.ready indica si ya existe linea base valida.
        - builder.last_flow_deltas expone los flujos de la ultima
          ventana con su Delta y contribucion (para el Hito 9).
        - No conoce el modelo ML ni toma decisiones operacionales.

    flow_id = (dpid, src_mac, dst_mac, in_port, out_port, priority)
    """

    def __init__(self, flow_timeout=FLOW_TIMEOUT):
        # Estado por flujo: contadores de la ultima fotografia + last_seen.
        self.flow_state = {}
        self.flow_timeout = flow_timeout
        # Cuenta de ciclos procesados (para la logica de 'ready').
        self._cycles = 0
        # Estado publico de solo lectura: los flujos de la ULTIMA ventana
        # con su Delta y contribucion. Lo consume attack_identifier.py
        # (Hito 9). NO afecta al calculo del feature_row (paridad intacta).
        self.last_flow_deltas = []

    @property
    def ready(self):
        """
        True desde el SEGUNDO ciclo: hace falta una fotografia previa
        contra la cual calcular Delta.
        """
        return self._cycles >= 2

    def update(self, flows, now):
        """
        Procesa las estadisticas de flujo de un ciclo.

        Parametros:
            flows : lista de dicts con las claves flow_id, packet_count,
                    byte_count, src_ip, dst_ip (y opcionalmente src_mac,
                    dst_mac).
            now   : marca de tiempo del ciclo (segundos).

        Devuelve el feature_row (dict de 8 features) de la ventana.
        Efecto lateral: actualiza self.last_flow_deltas.
        """
        sum_dp = 0.0
        sum_db = 0.0
        src_ips = []
        dst_ips = []
        deltas_ventana = []

        for f in flows:
            fid = f["flow_id"]
            pc = f["packet_count"]
            bc = f["byte_count"]

            prev = self.flow_state.get(fid)
            if prev is None:
                # Flujo sin linea base: Delta = 0 en este ciclo (el
                # acumulado no representa el intervalo). Desde el proximo
                # ciclo tendra base y su Delta sera real.
                dp = 0.0
                db = 0.0
            else:
                # Delta real entre dos fotografias consecutivas.
                dp = pc - prev["packet_count"]
                db = bc - prev["byte_count"]
                # Salvaguarda ante reinicio de contador.
                if dp < 0:
                    dp = 0.0
                if db < 0:
                    db = 0.0

            sum_dp += dp
            sum_db += db
            # Cada flujo contribuye una vez a la distribucion de IPs.
            src_ips.append(f["src_ip"])
            dst_ips.append(f["dst_ip"])

            # Registrar el Delta de este flujo (para el identificador del
            # Hito 9). La contribucion se completa tras el bucle, cuando
            # ya se conoce el total. Esto NO interviene en el feature_row.
            deltas_ventana.append({
                "flow_id": fid,
                "src_mac": f.get("src_mac", ""),
                "dst_mac": f.get("dst_mac", ""),
                "src_ip": f["src_ip"],
                "dst_ip": f["dst_ip"],
                "delta_packets": dp,
                "delta_bytes": db,
                "pps": dp / fe.MONITOR_INTERVAL,
                "bps": db / fe.MONITOR_INTERVAL,
                "contribution": 0.0,
            })

            # Actualizar el estado del flujo.
            self.flow_state[fid] = {
                "packet_count": pc,
                "byte_count": bc,
                "last_seen": now,
            }

        # Completar la contribucion de cada flujo reutilizando el MISMO
        # sum_dp del feature_row (cero duplicacion del total).
        for d in deltas_ventana:
            d["contribution"] = (d["delta_packets"] / sum_dp
                                 if sum_dp > 0 else 0.0)
        # Publicar el estado de la ventana (solo lectura para el Hito 9).
        self.last_flow_deltas = deltas_ventana

        flow_count = len(flows)
        # Features de la ventana: calculadas por el modulo COMPARTIDO
        # (paridad con build_features.py garantizada).
        feature_row = fe.build_feature_row(
            flow_count=flow_count,
            sum_delta_packets=sum_dp,
            sum_delta_bytes=sum_db,
            src_ips=src_ips,
            dst_ips=dst_ips,
        )

        # Purga de flujos inactivos (higiene de memoria).
        self._cleanup(now)
        # Registrar que se proceso un ciclo.
        self._cycles += 1

        return feature_row

    def _cleanup(self, now):
        """Elimina del estado los flujos inactivos (last_seen viejo)."""
        muertos = [fid for fid, st in self.flow_state.items()
                   if now - st["last_seen"] > self.flow_timeout]
        for fid in muertos:
            del self.flow_state[fid]


# =====================================================
# DETECTOR (modelo ML + contrato de features)
# =====================================================

class OnlineDetector:
    """
    Carga el modelo serializado y su contrato de features, y clasifica
    un feature_row en NORMAL / ATAQUE. El modelo es un Pipeline completo
    (StandardScaler + clasificador); el escalado se aplica en predict().
    """

    def __init__(self, model_path, feature_columns_path):
        if not os.path.exists(model_path):
            raise RuntimeError("no se encontro el modelo: %s" % model_path)
        if not os.path.exists(feature_columns_path):
            raise RuntimeError("no se encontro el contrato: %s"
                               % feature_columns_path)
        self.model = joblib.load(model_path)
        with open(feature_columns_path) as f:
            self.feature_columns = json.load(f)

    def predict(self, feature_row):
        """
        Clasifica un feature_row. Devuelve "normal" / "ataque".
        Construye el vector en el orden EXACTO del contrato.
        """
        vector = fe.feature_row_to_vector(feature_row, self.feature_columns)
        pred = self.model.predict([vector])
        return pred[0]

    def predict_proba(self, feature_row):
        """Probabilidad de la clase predicha, si el modelo la soporta."""
        if not hasattr(self.model, "predict_proba"):
            return None
        vector = fe.feature_row_to_vector(feature_row, self.feature_columns)
        proba = self.model.predict_proba([vector])
        return float(proba.max())
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
online_detector.py
===============================================================

Inteligencia del detector DDoS en tiempo real (Hito 8).

Contiene dos clases con responsabilidad unica cada una:

  - OnlineFeatureBuilder: convierte las estadisticas de flujo
    (FlowStats) de cada ciclo de monitoreo en un vector de
    features, manteniendo el estado incremental (los contadores
    de la ventana anterior) para calcular los Delta. Es
    DETERMINISTA: mismas fotografias -> mismo feature_row.

  - OnlineDetector: carga el modelo serializado y su contrato de
    features (feature_columns.json), y clasifica un feature_row
    en NORMAL / ATAQUE.

Paridad: el calculo de las features se delega en
feature_engineering.py, el MISMO modulo que usa build_features.py
(batch). Asi las features online son identicas a las de
entrenamiento. El Delta se calcula aqui (contra el estado
guardado), pero las features finales las produce el modulo
compartido.

Linea base (baseline): el detector empieza a clasificar desde el
SEGUNDO ciclo. El primer ciclo solo fija la linea base de los
contadores OpenFlow, porque en el primer poll los flujos pueden
llevar tiempo activos y su contador acumulado no representa el
intervalo de 5 s. Solo el incremento entre dos fotografias
consecutivas es comparable con las features de entrenamiento.

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
    Mantiene el estado de los contadores por flujo entre ciclos de
    monitoreo y produce, en cada ciclo, el vector de las 8 features
    de la ventana actual.

    Contrato:
        feature_row = builder.update(flows, now)
        - SIEMPRE devuelve un feature_row (nunca None).
        - builder.ready indica si ya existe una linea base valida
          (es decir, si el feature_row es utilizable para clasificar).
        - No conoce el modelo ML ni toma decisiones operacionales.

    flow_id = (dpid, src_mac, dst_mac, in_port, out_port, priority)
    (los mismos campos que el batch, sin 'scenario' que no existe en
    una sesion continua del controlador).
    """

    def __init__(self, flow_timeout=FLOW_TIMEOUT):
        # Estado por flujo: contadores de la ultima fotografia + last_seen.
        self.flow_state = {}
        self.flow_timeout = flow_timeout
        # Cuenta cuantos ciclos se han procesado. La linea base existe
        # cuando ya hubo AL MENOS un ciclo previo (el actual puede
        # calcular Delta contra la fotografia anterior).
        self._cycles = 0

    @property
    def ready(self):
        """
        True si ya existe una linea base valida: hace falta haber
        procesado al menos un ciclo previo, de modo que el ciclo actual
        pueda calcular Delta contra una fotografia anterior. Es decir,
        ready es True a partir del SEGUNDO ciclo.
        """
        return self._cycles >= 2

    def update(self, flows, now):
        """
        Procesa las estadisticas de flujo de un ciclo.

        Parametros:
            flows : lista de dicts, cada uno con las claves:
                    flow_id (tupla), packet_count, byte_count,
                    src_ip, dst_ip
            now   : marca de tiempo del ciclo (segundos)

        Devuelve el feature_row (dict de 8 features) de la ventana.
        """
        sum_dp = 0.0
        sum_db = 0.0
        src_ips = []
        dst_ips = []

        for f in flows:
            fid = f["flow_id"]
            pc = f["packet_count"]
            bc = f["byte_count"]

            prev = self.flow_state.get(fid)
            if prev is None:
                # Flujo sin linea base: no inventamos su tasa desde el
                # nacimiento (el acumulado no representa el intervalo).
                # Delta = 0 en este ciclo; desde el proximo tendra base.
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
            # Cada flujo contribuye una vez a la distribucion de IPs
            # (frecuencia de flujos por IP, igual que el batch).
            src_ips.append(f["src_ip"])
            dst_ips.append(f["dst_ip"])

            # Actualizar el estado del flujo.
            self.flow_state[fid] = {
                "packet_count": pc,
                "byte_count": bc,
                "last_seen": now,
            }

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

        # Purga de flujos inactivos (higiene de memoria; uso intensivo
        # en el Hito 9 para identificar atacantes activos).
        self._cleanup(now)

        # Registrar que se proceso un ciclo (para la logica de 'ready').
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
    un feature_row en NORMAL / ATAQUE.

    El modelo es un Pipeline completo (StandardScaler + clasificador),
    asi que el escalado se aplica automaticamente en predict().
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
        Clasifica un feature_row. Devuelve la etiqueta predicha
        ("normal" / "ataque").

        Construye el vector en el orden EXACTO del contrato y valida
        la longitud (evita errores silenciosos de orden/numero).
        """
        vector = fe.feature_row_to_vector(feature_row, self.feature_columns)
        pred = self.model.predict([vector])
        return pred[0]

    def predict_proba(self, feature_row):
        """
        Devuelve la probabilidad de la clase predicha, si el modelo la
        soporta; en caso contrario None. (Un arbol sobre datos
        separables suele dar 1.0, poco informativo.)
        """
        if not hasattr(self.model, "predict_proba"):
            return None
        vector = fe.feature_row_to_vector(feature_row, self.feature_columns)
        proba = self.model.predict_proba([vector])
        return float(proba.max())

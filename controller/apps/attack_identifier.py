#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
attack_identifier.py
===============================================================

Identificacion del origen de un ataque DDoS (Hito 9).

Modulo PURO: recibe la lista de flujos de la ultima ventana
(builder.last_flow_deltas) y devuelve los flujos identificados como
atacantes. No conoce Ryu, ni el modelo ML, ni instala reglas: solo
identifica. Su unica responsabilidad es responder a la pregunta:
"que flujos estan enviando trafico anomalo hacia el servidor
protegido?".

Criterio de identificacion (cerrado con datos reales):
    Un flujo es atacante si y solo si:
        dst_ip == VICTIM_IP     (dirigido a la victima protegida)
        src_ip != VICTIM_IP     (NO es la respuesta de la victima)
        pps    >= PPS_MIN       (tasa anormalmente alta)

    Se descarto el criterio de "contribucion > umbral" porque en un
    SYN flood el ataque (h5->h1) y su respuesta (h1->h5) tienen
    volumenes casi identicos (~49.5% cada uno en los datos reales),
    de modo que ninguno superaba un umbral del 60%. El filtro por
    DIRECCION (dst==victima, src!=victima) separa limpiamente el
    ataque de su reflejo, y ademas escala a multiples atacantes
    simultaneos (coordinado) sin recalibrar porcentajes.

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

import os


# =====================================================
# CONFIGURACION (parametrizable por variable de entorno)
# =====================================================

# IP de la victima protegida. En el experimento controlado es h1.
# En produccion seria el servidor a proteger (un parametro natural).
VICTIM_IP = os.getenv("VICTIM_IP", "10.0.0.1")

# Tasa minima (paquetes/segundo) para considerar un flujo como ataque.
# Guarda holgado: el fondo real ~2 pps, el ataque ~600 pps; 50 esta
# 25x sobre el fondo y 12x bajo el ataque (margen amplio en ambos lados).
PPS_MIN = float(os.getenv("PPS_MIN", "50"))


class AttackIdentifier:
    """
    Identifica flujos atacantes dentro de una ventana ya clasificada
    como ATAQUE por el detector. Modulo puro y determinista.
    """

    def __init__(self, victim_ip=VICTIM_IP, pps_min=PPS_MIN):
        self.victim_ip = victim_ip
        self.pps_min = pps_min

    def identify(self, last_flow_deltas):
        """
        Devuelve la lista de flujos identificados como atacantes.

        Parametro:
            last_flow_deltas : lista de dicts (builder.last_flow_deltas),
                               cada uno con src_ip, dst_ip, pps, etc.

        Devuelve una lista (posiblemente vacia) de los mismos dicts que
        cumplen el criterio de atacante. Cada elemento conserva toda la
        informacion (flow_id, MACs, IPs, pps...) que el mitigador
        necesitara para construir el match del FlowMod DROP.
        """
        atacantes = []
        for flujo in last_flow_deltas:
            if (flujo["dst_ip"] == self.victim_ip
                    and flujo["src_ip"] != self.victim_ip
                    and flujo["pps"] >= self.pps_min):
                atacantes.append(flujo)
        return atacantes

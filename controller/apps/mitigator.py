#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
mitigator.py
===============================================================

Mitigacion de ataques DDoS mediante reglas OpenFlow (Hito 9).

Instala reglas FlowMod DROP sobre los flujos atacantes: el trafico
atacante->victima se descarta en el plano de datos.

Match (quirurgico, validado experimentalmente):
    eth_type = 0x0800   (IPv4; OpenFlow lo exige para match sobre IP)
    ipv4_src = atacante
    ipv4_dst = victima
Verificado en OVS: la regla priority=100 prevalece sobre la del
learning switch (priority=1) y el contador n_packets del DROP crece,
mientras el del flujo atacante se congela.

Ciclo de vida (refinado tras validacion experimental):
    priority     = 100  (gana al learning switch)
    idle_timeout = 15 s (la regla vive mientras haya trafico de ataque;
                         se elimina 15 s despues de que el ataque cese)
    hard_timeout = 0    (SIN hard_timeout: se observo que combinarlo con
                         el registro installed_rules producia una
                         desincronizacion entre el estado del controlador
                         y el del switch. Con solo idle_timeout la regla
                         persiste mientras el ataque este activo.)
    flags = OFPFF_SEND_FLOW_REM  (OVS notifica al controlador cuando la
                         regla expira -> el switch es la fuente de verdad
                         para sincronizar installed_rules.)

Anti-duplicado: installed_rules (dict) registra las reglas activas por
(src_ip, dst_ip). El controlador (monitor.py) llama a clear_rule() al
recibir el evento FlowRemoved, manteniendo el registro sincronizado.

Maestria en Ciberseguridad - UNMSM
===============================================================
"""

import os
import time


# =====================================================
# CONFIGURACION (parametrizable por variable de entorno)
# =====================================================

MITIGATION_PRIORITY = int(os.getenv("MITIGATION_PRIORITY", "100"))
MITIGATION_IDLE_TIMEOUT = int(os.getenv("MITIGATION_IDLE_TIMEOUT", "15"))

# EtherType de IPv4 (OpenFlow exige este match para filtrar por IP).
ETH_TYPE_IPV4 = 0x0800


class Mitigator:
    """
    Instala reglas FlowMod DROP sobre los flujos atacantes y mantiene un
    registro de las reglas activas. No escucha eventos OpenFlow (eso es
    responsabilidad de monitor.py): solo administra reglas.
    """

    def __init__(self, logger=None,
                 priority=MITIGATION_PRIORITY,
                 idle_timeout=MITIGATION_IDLE_TIMEOUT):
        self.logger = logger
        self.priority = priority
        self.idle_timeout = idle_timeout
        # Reglas activas: {(src_ip, dst_ip): metadatos}. El dict (en vez
        # de un set) prepara metricas para el Hito 10 (tiempo de vida,
        # numero de mitigaciones, etc.) sin romper la API.
        self.installed_rules = {}

    def mitigate(self, datapath, attackers):
        """
        Instala una regla DROP por cada atacante nuevo.

        Devuelve la lista de (src_ip, dst_ip) bloqueados en esta llamada
        (los nuevos; los ya activos se omiten por anti-duplicado).
        """
        nuevos = []
        for atk in attackers:
            src_ip = atk["src_ip"]
            dst_ip = atk["dst_ip"]
            clave = (src_ip, dst_ip)

            # Anti-duplicado: no reinstalar una regla ya activa.
            if clave in self.installed_rules:
                continue

            self._install_drop(datapath, src_ip, dst_ip)
            # Registrar SOLO tras enviar el FlowMod (si _install_drop
            # lanzara, no se registraria un estado inconsistente).
            self.installed_rules[clave] = {
                "installed_at": time.time(),
                "priority": self.priority,
                "idle_timeout": self.idle_timeout,
            }
            nuevos.append(clave)

            if self.logger is not None:
                self.logger.warning(
                    ">>> MITIGACION: DROP instalado para %s -> %s "
                    "(priority=%d, idle=%ds, flow_rem=on, reglas_activas=%d)",
                    src_ip, dst_ip, self.priority, self.idle_timeout,
                    len(self.installed_rules))

        return nuevos

    def _install_drop(self, datapath, src_ip, dst_ip):
        """
        Construye e instala el FlowMod DROP para un par (src_ip, dst_ip).
        DROP = instruccion APPLY_ACTIONS con lista de acciones vacia.
        Sin hard_timeout; con OFPFF_SEND_FLOW_REM para sincronizacion.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=ETH_TYPE_IPV4,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
        )

        # DROP: APPLY_ACTIONS con acciones vacias (sin OUTPUT -> descarta).
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, [])]

        # hard_timeout=0: la regla permanece mientras exista trafico de
        # ataque; es idle_timeout quien controla su eliminacion (15 s tras
        # cesar el ataque). flags=OFPFF_SEND_FLOW_REM: OVS notifica al
        # controlador cuando la regla expira, para sincronizar el registro.
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=self.priority,
            match=match,
            instructions=inst,
            idle_timeout=self.idle_timeout,
            hard_timeout=0,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
        )

        datapath.send_msg(mod)

    def clear_rule(self, src_ip, dst_ip):
        """
        Elimina una regla del registro cuando el switch notifica su
        expiracion (via FlowRemoved). Lo invoca monitor.py al recibir el
        evento. Permite reinstalar la regla si el ataque reaparece.
        Registra el tiempo de vida real de la regla (util para las
        metricas del Hito 10). Devuelve True si la regla estaba registrada.
        """
        clave = (src_ip, dst_ip)
        info = self.installed_rules.get(clave)
        if info is None:
            return False
        lifetime = time.time() - info["installed_at"]
        del self.installed_rules[clave]
        if self.logger is not None:
            self.logger.info(
                "Mitigacion: regla DROP %s -> %s expiro (vida=%.1fs, "
                "reglas_activas=%d).",
                src_ip, dst_ip, lifetime, len(self.installed_rules))
        return True
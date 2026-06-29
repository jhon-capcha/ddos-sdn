#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
monitor.py
===============================================================

Aplicacion Ryu (controlador SDN propio) para el laboratorio de
deteccion y mitigacion de ataques DDoS mediante Machine Learning
utilizando Entropia de Shannon.

Funcionalidad del Hito 4:
    - Switch de aprendizaje OpenFlow 1.3 (learning switch).
    - Monitoreo periodico de estadisticas de flujo.
    - Registro de estadisticas en consola y archivo.

Proyecto:
Deteccion y mitigacion de ataques DDoS en redes SDN mediante
Machine Learning utilizando Entropia de Shannon.

Maestria en Ciberseguridad
Universidad Nacional Mayor de San Marcos
===============================================================
"""

import logging
import os
import time
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub

# =====================================================
# RUTAS DEL PROYECTO
# =====================================================
# Se calculan respecto al propio archivo para que el log
# siempre se escriba en controller/logs/, sin importar desde
# que directorio se ejecute ryu-manager.
#   monitor.py -> controller/apps/monitor.py
#   BASE_DIR   -> controller/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# =====================================================
# CONFIGURACION DEL MONITOR
# =====================================================

# Intervalo de consulta de estadisticas (segundos).
# Parametrizado: en el Hito 6 se experimentara con distintos
# tamanos de ventana para el calculo de la entropia de Shannon.
MONITOR_INTERVAL = 5

# Registro (logging)
LOG_DIRECTORY = os.path.join(BASE_DIR, "logs")
LOG_FILENAME = "monitor.log"
LOG_LEVEL = logging.INFO

# Logger del modulo (sus handlers se configuran en el bloque de registro)
LOGGER = logging.getLogger(__name__)


# =====================================================
# CLASE PRINCIPAL DEL CONTROLADOR
# =====================================================

class Monitor13(app_manager.RyuApp):
    """
    Controlador SDN propio (OpenFlow 1.3):
    learning switch + monitoreo periodico de estadisticas de flujo.
    """

    # Esta aplicacion habla exclusivamente OpenFlow 1.3.
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Monitor13, self).__init__(*args, **kwargs)

        # Tabla de aprendizaje del switch: {dpid: {mac: puerto}}
        self.mac_to_port = {}

        # Switches conectados: {dpid: datapath}
        self.datapaths = {}

        # Configurar el registro (consola + archivo)
        self._setup_logging()

        # Lanzar el hilo de monitoreo en paralelo
        self.monitor_thread = hub.spawn(self._monitor)

        LOGGER.info("Monitor13 iniciado (OpenFlow 1.3, intervalo=%ss)",
                    MONITOR_INTERVAL)

    # =================================================
    # SECCION: SWITCH OPENFLOW 1.3 (learning switch)
    # =================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Se ejecuta cuando un switch se conecta (handshake)."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Registrar el switch (para el monitoreo posterior)
        self.datapaths[datapath.id] = datapath
        LOGGER.info("Switch conectado: dpid=%s", datapath.id)

        # Instalar la regla table-miss:
        # lo que no coincida con ninguna regla -> enviar al controlador.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        """
        Construye e instala una regla (FlowMod) en el switch.

        Metodo reutilizable. Se empleara posteriormente para:
            - learning switch (Hito 4)
            - reglas de mitigacion / Drop de ataques DDoS (Hito 9)
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Las acciones se envuelven en una instruccion APPLY_ACTIONS.
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Learning switch: aprende MACs e instala reglas de reenvio."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Parsear el paquete para leer las cabeceras Ethernet.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignorar paquetes LLDP (descubrimiento de topologia).
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Aprender: la MAC origen esta en el puerto de entrada.
        self.mac_to_port[dpid][src] = in_port

        # Decidir el puerto de salida.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Si conocemos el destino, instalar una regla para este flujo
        # (asi el switch lo maneja solo, sin volver a preguntar).
        if out_port != ofproto.OFPP_FLOOD:
            # En los hitos posteriores (deteccion/mitigacion) el match
            # se ampliara para incluir informacion IP y de transporte
            # (ipv4_src, ipv4_dst, ip_proto, tcp_dst, udp_dst).
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        # Enviar el paquete actual (PacketOut).
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)

    # =================================================
    # SECCION: MONITOREO DE ESTADISTICAS DE FLUJO
    # =================================================

    def _monitor(self):
        """Bucle que solicita estadisticas a cada switch periodicamente."""
        while True:
            # Si aun no hay switches conectados, esperar sin iterar.
            if not self.datapaths:
                hub.sleep(MONITOR_INTERVAL)
                continue

            for datapath in list(self.datapaths.values()):
                self._request_stats(datapath)
            hub.sleep(MONITOR_INTERVAL)

    def _request_stats(self, datapath):
        """Envia una peticion de estadisticas de flujo al switch."""
        # Solicita al switch las estadisticas de todos los flujos
        # instalados (corazon del monitoreo del Hito 4).
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Recibe las estadisticas de flujo y extrae los campos utiles."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        timestamp = time.time()
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Ordenar los flujos para que el log sea determinista
        # (mismo orden en cada ejecucion -> comparaciones mas faciles).
        flujos = sorted(
            body,
            key=lambda flow: (
                flow.match.get("in_port", 0),
                flow.match.get("eth_src", ""),
                flow.match.get("eth_dst", "")
            )
        )

        for stat in flujos:
            # Ignorar la regla table-miss (priority 0, sin match de MACs).
            if stat.priority == 0:
                continue

            # Extraer los campos del match (pueden no estar todos presentes).
            match = stat.match
            src_mac = match.get("eth_src", "")
            dst_mac = match.get("eth_dst", "")
            in_port = match.get("in_port", "")

            # Buscar la primera accion OUTPUT del flujo.
            out_port = ""
            for inst in stat.instructions:
                for action in getattr(inst, "actions", []):
                    if action.__class__.__name__ == "OFPActionOutput":
                        out_port = action.port
                        break

            LOGGER.info(
                "stats fecha=%s dpid=%s src=%s dst=%s in_port=%s out_port=%s "
                "packets=%s bytes=%s duration=%ss priority=%s ts=%.0f",
                fecha, dpid, src_mac, dst_mac, in_port, out_port,
                stat.packet_count, stat.byte_count,
                stat.duration_sec, stat.priority, timestamp
            )

    # =================================================
    # SECCION: REGISTRO (logging)
    # =================================================

    def _setup_logging(self):
        """
        Configura el logging del modulo con dos destinos:
            - FileHandler   -> controller/logs/monitor.log (evidencia permanente)
            - StreamHandler -> consola (observacion en tiempo real)
        propagate=False evita que los mensajes suban al logger raiz de Ryu
        (lo que provocaria lineas duplicadas).
        """
        # Crear la carpeta de logs si no existe.
        os.makedirs(LOG_DIRECTORY, exist_ok=True)

        LOGGER.setLevel(LOG_LEVEL)
        LOGGER.propagate = False

        # Formato comun para ambos destinos (consola y archivo identicos).
        formato = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

        # Handler de archivo: escribe en controller/logs/monitor.log
        log_path = os.path.join(LOG_DIRECTORY, LOG_FILENAME)
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(LOG_LEVEL)
        file_handler.setFormatter(formato)

        # Handler de consola: muestra los mensajes en tiempo real.
        console_handler = logging.StreamHandler()
        console_handler.setLevel(LOG_LEVEL)
        console_handler.setFormatter(formato)

        # Garantizar exactamente 1 FileHandler + 1 StreamHandler:
        # limpiar handlers previos (recargas, imports, pruebas) y anadir.
        if LOGGER.hasHandlers():
            LOGGER.handlers.clear()

        LOGGER.addHandler(file_handler)
        LOGGER.addHandler(console_handler)
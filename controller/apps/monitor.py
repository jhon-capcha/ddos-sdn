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

import csv
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
import sys

# Importar el detector online (Hito 8). Se anade apps/ al path por si
# ryu-manager se ejecuta desde otro directorio.
_APPS_DIR = os.path.dirname(os.path.abspath(__file__))
if _APPS_DIR not in sys.path:
    sys.path.insert(0, _APPS_DIR)
from online_detector import OnlineFeatureBuilder, OnlineDetector

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
# CONFIGURACION DEL DATASET (Hito 5)
# =====================================================

# Escenario experimental (parametrizado por variable de entorno).
# El controlador NO cambia entre escenarios: solo cambia esta variable.
VALID_SCENARIOS = {"normal", "syn_flood", "udp_flood", "icmp_flood", "coordinado"}
SCENARIO = os.getenv("SCENARIO", "normal")

# Fecha de captura opcional (para repetir experimentos sin sobrescribir).
# Si se define, el CSV sera "<scenario>_<fecha>.csv"; si no, "<scenario>.csv".
CAPTURE_DATE = os.getenv("CAPTURE_DATE", "")

# Directorio del dataset crudo.
DATASET_DIRECTORY = os.path.join(BASE_DIR, "datasets", "raw")

# Etiquetas del dataset (constantes, evitan cadenas repetidas).
LABEL_NORMAL = "normal"
LABEL_ATTACK = "ataque"

# Cabecera del CSV (17 columnas: crudo enriquecido + scenario + label).
CSV_HEADER = [
    "timestamp", "fecha", "scenario", "dpid",
    "src_mac", "dst_mac", "src_ip", "dst_ip", "src_host", "dst_host",
    "in_port", "out_port",
    "packet_count", "byte_count", "duration_sec", "priority",
    "label",
]

# =====================================================
# CONFIGURACION DEL DETECTOR (Hito 8)
# =====================================================

# Modo de operacion del controlador (parametrizado por variable de entorno):
#   capture         -> solo captura dataset (comportamiento del Hito 5)
#   detect          -> solo detecta en tiempo real (Hito 8)
#   capture_detect  -> captura y detecta simultaneamente
# Default 'capture': retrocompatible con el Hito 5 (nada se rompe).
VALID_APP_MODES = {"capture", "detect", "capture_detect"}
APP_MODE = os.getenv("APP_MODE", "capture")

# Modelo operativo del detector: se usa el modelo SIN flow_count, porque
# flow_count codifica la topologia del laboratorio (6/8/12 flujos), no la
# fisica del ataque. El detector de produccion debe generalizar.
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "results_sin_flowcount",
                          "model_sin_flowcount.joblib")
FEATURE_COLUMNS_PATH = os.path.join(MODELS_DIR, "results_sin_flowcount",
                                    "feature_columns_sin_flowcount.json")

# =====================================================
# INVENTARIO DE LA TOPOLOGIA (fuente unica de verdad)
# =====================================================
# Mapea cada MAC a su host, IP y rol. La MAC sigue el numero de host
# (h5 -> ...05), pero la IP de los atacantes "salta" a .11/.12/.13
# (diseno del Hito 1 para distinguir el rol por IP).
HOST_INVENTORY = {
    "00:00:00:00:00:01": {"host": "h1", "ip": "10.0.0.1",  "rol": "victima"},
    "00:00:00:00:00:02": {"host": "h2", "ip": "10.0.0.2",  "rol": "normal"},
    "00:00:00:00:00:03": {"host": "h3", "ip": "10.0.0.3",  "rol": "normal"},
    "00:00:00:00:00:04": {"host": "h4", "ip": "10.0.0.4",  "rol": "normal"},
    "00:00:00:00:00:05": {"host": "h5", "ip": "10.0.0.11", "rol": "atacante"},
    "00:00:00:00:00:06": {"host": "h6", "ip": "10.0.0.12", "rol": "atacante"},
    "00:00:00:00:00:07": {"host": "h7", "ip": "10.0.0.13", "rol": "atacante"},
}


def get_host_info(mac):
    """Devuelve la info de inventario de una MAC, o None si no esta registrada."""
    return HOST_INVENTORY.get(mac)


def get_label(src_mac):
    """
    Etiqueta el flujo segun el ROL del host origen (Enfoque A).
    La etiqueta pertenece al flujo, no al instante:
        - origen con rol 'atacante' -> ataque
        - origen 'normal' o 'victima' -> normal
    """
    info = get_host_info(src_mac)
    if info is None:
        # No deberia ocurrir: los flujos desconocidos se filtran antes
        # de llegar aqui. Se devuelve normal por seguridad.
        return LABEL_NORMAL
    if info["rol"] == "atacante":
        return LABEL_ATTACK
    return LABEL_NORMAL


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

        # Validar el modo de operacion (falla rapido ante un typo).
        if APP_MODE not in VALID_APP_MODES:
            LOGGER.error("APP_MODE no valido: '%s'. Validos: %s",
                         APP_MODE, sorted(VALID_APP_MODES))
            raise ValueError("APP_MODE no valido: %s" % APP_MODE)

        # Banderas de subsistema segun el modo.
        self.do_capture = APP_MODE in {"capture", "capture_detect"}
        self.do_detect = APP_MODE in {"detect", "capture_detect"}

        # Subsistema de captura (Hito 5): solo si el modo lo requiere.
        # En modo 'detect' puro NO se valida SCENARIO ni se crea CSV.
        if self.do_capture:
            self._setup_dataset()

        # Subsistema de deteccion (Hito 8): solo si el modo lo requiere.
        if self.do_detect:
            self._setup_detector()

        # Lanzar el hilo de monitoreo en paralelo
        self.monitor_thread = hub.spawn(self._monitor)

        LOGGER.info("Monitor13 iniciado (OpenFlow 1.3, intervalo=%ss, modo=%s)",
                    MONITOR_INTERVAL, APP_MODE)


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
        """
        Recibe las estadisticas de flujo, las registra en el log y
        escribe en el CSV los flujos pertenecientes a la topologia.
        Los flujos con MAC desconocida se excluyen del dataset y se
        cuentan para evaluar la calidad de la captura.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        timestamp = time.time()
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Acumulador de flujos de la ventana para el detector (Hito 8).
        # Se llena durante el bucle y se procesa al final si do_detect.
        flows_online = []

        # Ordenar los flujos para que el registro sea determinista
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

            # Extraer los campos del match.
            match = stat.match
            src_mac = match.get("eth_src", "")
            dst_mac = match.get("eth_dst", "")
            in_port = match.get("in_port", "")

            # Buscar la primera accion OUTPUT del flujo.
            # Se utiliza una bandera para finalizar ambos bucles sin
            # depender del valor del puerto de salida (por ejemplo, si
            # en otra implementacion el puerto pudiera ser 0).
            out_port = ""
            encontrado = False
            for inst in stat.instructions:
                for action in getattr(inst, "actions", []):
                    if action.__class__.__name__ == "OFPActionOutput":
                        out_port = action.port
                        encontrado = True
                        break
                if encontrado:
                    break

            # Registro en el log (evidencia experimental, se mantiene).
            LOGGER.info(
                "stats fecha=%s dpid=%s src=%s dst=%s in_port=%s out_port=%s "
                "packets=%s bytes=%s duration=%ss priority=%s ts=%.0f",
                fecha, dpid, src_mac, dst_mac, in_port, out_port,
                stat.packet_count, stat.byte_count,
                stat.duration_sec, stat.priority, timestamp
            )

            # Resolver el inventario para ambos extremos del flujo.
            src_info = get_host_info(src_mac)
            dst_info = get_host_info(dst_mac)

            # Filtrar flujos con MAC desconocida: no entran al dataset
            # ni al detector (mismo criterio que el batch del Hito 5/6).
            if src_info is None or dst_info is None:
                LOGGER.debug("Flujo ignorado (MAC desconocida): src=%s dst=%s",
                             src_mac, dst_mac)
                if self.do_capture:
                    self.ignored_flows += 1
                continue

            # Acumular el flujo para el detector (Hito 8). El flow_id usa
            # los mismos campos que el batch (sin 'scenario'): la paridad
            # de features esta garantizada por feature_engineering.
            if self.do_detect:
                flows_online.append({
                    "flow_id": (dpid, src_mac, dst_mac,
                                in_port, out_port, stat.priority),
                    "packet_count": stat.packet_count,
                    "byte_count": stat.byte_count,
                    "src_ip": src_info["ip"],
                    "dst_ip": dst_info["ip"],
                })

            # Construir y escribir la fila del dataset (17 columnas).
            label = get_label(src_mac)
            fila = [
                "%.0f" % timestamp, fecha, SCENARIO, dpid,
                src_mac, dst_mac,
                src_info["ip"], dst_info["ip"],
                src_info["host"], dst_info["host"],
                in_port, out_port,
                stat.packet_count, stat.byte_count,
                stat.duration_sec, stat.priority,
                label,
            ]
            if self.do_capture:
                self.csv_writer.writerow(fila)
                self.registered_flows += 1
                if label == LABEL_ATTACK:
                    self.count_attack += 1
                else:
                    self.count_normal += 1

        # --- Captura (Hito 5): escribir a disco y resumir ---
        if self.do_capture:
            # Asegurar que las filas se escriban a disco en cada ciclo.
            self.csv_file.flush()

            # Resumen de calidad de la captura (acumulado, con porcentajes).
            total = self.registered_flows
            if total > 0:
                pct_normal = 100.0 * self.count_normal / total
                pct_attack = 100.0 * self.count_attack / total
            else:
                pct_normal = 0.0
                pct_attack = 0.0
            LOGGER.info(
                "Dataset[%s]: registrados=%s normales=%s (%.1f%%) "
                "ataque=%s (%.1f%%) ignorados=%s",
                SCENARIO, total,
                self.count_normal, pct_normal,
                self.count_attack, pct_attack,
                self.ignored_flows
            )

        # --- Deteccion (Hito 8): clasificar la ventana ---
        if self.do_detect:
            self._classify_window(flows_online, timestamp)

    # =================================================
    # SECCION: DETECTOR EN TIEMPO REAL (Hito 8)
    # =================================================

    def _setup_detector(self):
        """
        Inicializa el detector en tiempo real (Hito 8): el constructor
        de features incremental y el modelo de clasificacion.
        """
        self.feature_builder = OnlineFeatureBuilder()
        self.detector = OnlineDetector(MODEL_PATH, FEATURE_COLUMNS_PATH)

        # Contadores de deteccion (ventanas clasificadas).
        self.win_normal = 0
        self.win_attack = 0

        LOGGER.info("Detector listo: modelo='%s' (%d features)",
                    os.path.basename(MODEL_PATH),
                    len(self.detector.feature_columns))

    def _classify_window(self, flows_online, now):
        """
        Construye las features de la ventana actual y, si ya hay linea
        base, clasifica y registra el resultado. 'flows_online' es la
        lista de flujos de la ventana (dicts con flow_id, contadores, IPs).
        """
        feature_row = self.feature_builder.update(flows_online, now)

        # Primer ciclo: solo se fija la linea base, no se clasifica.
        if not self.feature_builder.ready:
            LOGGER.info("Detector: warming up (fijando linea base)...")
            return

        pred = self.detector.predict(feature_row)
        if pred == LABEL_ATTACK:
            self.win_attack += 1
        else:
            self.win_normal += 1

        # Log estructurado de la deteccion.
        LOGGER.info(
            "Deteccion: %s | pps=%.1f bps=%.1f entropy_src=%.4f "
            "entropy_dst=%.4f flujos=%d | ventanas normal=%d ataque=%d",
            pred.upper(),
            feature_row["packets_per_second"],
            feature_row["bytes_per_second"],
            feature_row["entropy_src_ip"],
            feature_row["entropy_dst_ip"],
            feature_row["flow_count"],
            self.win_normal, self.win_attack,
        )
        if pred == LABEL_ATTACK:
            LOGGER.warning(
                ">>> ATAQUE DDoS DETECTADO <<< pps=%.1f (ventana con %d flujos)",
                feature_row["packets_per_second"], feature_row["flow_count"])
    
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

    def _setup_dataset(self):
        """
        Prepara el CSV del dataset para el escenario actual (Hito 5).
        Valida SCENARIO, crea el directorio, abre el CSV y escribe la
        cabecera una sola vez (si el archivo es nuevo).
        """
        # Validar el escenario (falla rapido y claro ante un typo).
        if SCENARIO not in VALID_SCENARIOS:
            LOGGER.error("Escenario no valido: '%s'. Validos: %s",
                         SCENARIO, sorted(VALID_SCENARIOS))
            raise ValueError("Escenario no valido: %s" % SCENARIO)

        # Crear el directorio del dataset si no existe.
        os.makedirs(DATASET_DIRECTORY, exist_ok=True)

        # Nombre del CSV: "<scenario>.csv" o "<scenario>_<fecha>.csv".
        if CAPTURE_DATE:
            nombre = "%s_%s.csv" % (SCENARIO, CAPTURE_DATE)
        else:
            nombre = "%s.csv" % SCENARIO
        self.csv_path = os.path.join(DATASET_DIRECTORY, nombre)

        # Abrir el CSV en modo "append" y escribir la cabecera solo si es nuevo.
        archivo_nuevo = not os.path.exists(self.csv_path)
        self.csv_file = open(self.csv_path, "a", newline="")
        
        # lineterminator="\n" fuerza finales de linea Unix (LF), evitando
        # el CRLF por defecto del modulo csv (que dificulta grep y otras
        # herramientas de texto en Linux).
        self.csv_writer = csv.writer(self.csv_file, lineterminator="\n")

        if archivo_nuevo:
            self.csv_writer.writerow(CSV_HEADER)
            self.csv_file.flush()

        # Contadores de calidad de captura.
        self.registered_flows = 0
        self.ignored_flows = 0
        self.count_normal = 0
        self.count_attack = 0

        LOGGER.info("Dataset listo: escenario='%s', archivo='%s'",
                    SCENARIO, self.csv_path)
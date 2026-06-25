#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
topologia_ddos.py
===============================================================

Topologia SDN utilizada en el laboratorio experimental para la
deteccion y mitigacion de ataques DDoS mediante Machine Learning
utilizando Entropia de Shannon.

Arquitectura:
    - 1 Switch Open vSwitch (OpenFlow 1.3)
    - 1 Host victima
    - 3 Hosts legitimos
    - 3 Hosts atacantes

Proyecto:
Deteccion y mitigacion de ataques DDoS en redes SDN mediante
Machine Learning utilizando Entropia de Shannon.

Maestria en Ciberseguridad
Universidad Nacional Mayor de San Marcos
===============================================================
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info, error

# =====================================================
# CONFIGURACION DEL LABORATORIO
# =====================================================

# Seleccion de controlador:
#   False -> controlador local de Mininet (validacion, Hito 1)
#   True  -> controlador remoto Ryu en VM-2 (laboratorio, Hito 4)
USE_REMOTE_CONTROLLER = False

# Controlador remoto (Ryu en VM-2), usado cuando USE_REMOTE_CONTROLLER = True
REMOTE_CONTROLLER_IP = "10.10.10.40"

# Puerto del protocolo OpenFlow (estandar IANA, no el historico 6633)
OPENFLOW_PORT = 6653

# Protocolo OpenFlow utilizado por el switch Open vSwitch
OPENFLOW_VERSION = "OpenFlow13"

# Roles de los hosts (constantes para evitar errores tipograficos)
ROLE_VICTIM     = "victim"
ROLE_LEGITIMATE = "legitimate"
ROLE_ATTACKER   = "attacker"

# Definicion logica de la topologia (unica fuente de verdad).
# Cada host queda definido por su IP, MAC y rol.
# Direccionamiento: victima .1 | legitimos .2-.4 | atacantes .11-.13
# (el salto en los atacantes permite distinguir el rol por la IP)
HOSTS = {
    "h1": {"ip": "10.0.0.1",  "mac": "00:00:00:00:00:01", "role": ROLE_VICTIM},
    "h2": {"ip": "10.0.0.2",  "mac": "00:00:00:00:00:02", "role": ROLE_LEGITIMATE},
    "h3": {"ip": "10.0.0.3",  "mac": "00:00:00:00:00:03", "role": ROLE_LEGITIMATE},
    "h4": {"ip": "10.0.0.4",  "mac": "00:00:00:00:00:04", "role": ROLE_LEGITIMATE},
    "h5": {"ip": "10.0.0.11", "mac": "00:00:00:00:00:05", "role": ROLE_ATTACKER},
    "h6": {"ip": "10.0.0.12", "mac": "00:00:00:00:00:06", "role": ROLE_ATTACKER},
    "h7": {"ip": "10.0.0.13", "mac": "00:00:00:00:00:07", "role": ROLE_ATTACKER},
}


# =====================================================
# DEFINICION DE LA TOPOLOGIA
# =====================================================

def crear_topologia() -> Mininet:
    """
    Construye la topologia en estrella:
    un switch OpenFlow 1.3 (s1) con 7 hosts conectados.
    Devuelve el objeto Mininet ya construido (sin arrancar).
    """

    # Comprobacion de coherencia: la topologia define exactamente 7 hosts.
    if len(HOSTS) != 7:
        error("*** Error: la topologia debe contener exactamente 7 hosts.\n")
        raise ValueError("Numero de hosts incorrecto en HOSTS.")

    # 1) Crear la red. Usamos OVSSwitch (Open vSwitch) y TCLink (enlaces TC).
    #    build=False: construimos manualmente paso a paso.
    net = Mininet(
        switch=OVSSwitch,
        link=TCLink,
        build=False
    )

    # 2) Seleccionar y anadir el controlador segun el modo configurado.
    info("*** Anadiendo controlador\n")
    if USE_REMOTE_CONTROLLER:
        info("    Modo: REMOTO -> Ryu en %s:%s\n"
             % (REMOTE_CONTROLLER_IP, OPENFLOW_PORT))
        net.addController(
            "c0",
            controller=RemoteController,
            ip=REMOTE_CONTROLLER_IP,
            port=OPENFLOW_PORT
        )
    else:
        info("    Modo: LOCAL -> OVSController\n")
        net.addController("c0", controller=OVSController)

    # 3) Anadir el switch s1 (forzamos OpenFlow 1.3).
    info("*** Anadiendo switch s1 (OpenFlow 1.3)\n")
    s1 = net.addSwitch("s1", protocols=OPENFLOW_VERSION)

    # 4) Anadir los hosts iterando sobre la definicion centralizada.
    info("*** Anadiendo hosts\n")
    hosts = {}
    for nombre, datos in HOSTS.items():
        hosts[nombre] = net.addHost(
            nombre,
            ip=datos["ip"],
            mac=datos["mac"]
        )

    # 5) Crear los enlaces iterando sobre HOSTS.
    #    Python 3.7+ preserva el orden de insercion de los diccionarios.
    #    Esto garantiza la asignacion determinista de puertos:
    #    s1-eth1->h1, s1-eth2->h2, ..., s1-eth7->h7.
    #    (clave para depurar dump-flows y para la defensa)
    info("*** Creando enlaces host <-> s1 (en orden)\n")
    for nombre in HOSTS:
        net.addLink(hosts[nombre], s1)

    return net


# =====================================================
# EJECUCION DEL LABORATORIO
# =====================================================

def main() -> None:
    """
    Ciclo de vida del laboratorio:
    construir -> arrancar -> validar (pingAll) -> CLI -> detener.
    El net.stop() va en finally para garantizar limpieza ante cualquier fallo.
    """
    net = crear_topologia()

    try:
        info("*** Construyendo la red\n")
        net.build()

        info("*** Iniciando la red\n")
        net.start()

        info("*** Validando conectividad (pingAll)\n")
        net.pingAll()

        info("*** Abriendo CLI de Mininet (escribe 'exit' para salir)\n")
        CLI(net)

    except Exception as e:
        error("*** Error durante la ejecucion: %s\n" % e)

    finally:
        info("*** Deteniendo la red\n")
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()

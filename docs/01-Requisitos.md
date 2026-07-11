# 01 — Requisitos

Requisitos de hardware y software para desplegar el laboratorio DDoS-SDN-Defense.

---

## 1. Arquitectura de despliegue

El sistema se despliega sobre **dos máquinas virtuales** independientes, siguiendo la separación de planos característica de SDN:

| Máquina | Plano | Rol |
|---|---|---|
| VM-1 | Datos | Mininet + Open vSwitch (emulación de la red) |
| VM-2 | Control | Ryu + Machine Learning (controlador SDN) |

Ambas se ejecutaron sobre **VMware Workstation Pro** en un host Windows.

---

## 2. Requisitos de hardware (por VM)

| Recurso | Mínimo recomendado |
|---|---|
| CPU | 2 vCPU |
| RAM | 2 GB (VM-1), 4 GB (VM-2) |
| Disco | 20 GB |
| Red | 2 adaptadores: NAT (internet) + red interna (10.10.10.0/24) |

> El host debe tener virtualización habilitada (VT-x/AMD-V) y suficiente RAM para ejecutar ambas VMs simultáneamente (mínimo 8 GB de RAM en el host).

---

## 3. Software base

| Componente | Versión | VM |
|---|---|---|
| Sistema operativo | Ubuntu 20.04 LTS | VM-1 y VM-2 |
| Python | 3.8.10 | VM-1 y VM-2 |
| Mininet | 2.3.0 | VM-1 |
| Open vSwitch | 2.13.8 | VM-1 |
| Ryu | 4.34 | VM-2 |
| scikit-learn | 1.3.2 | VM-2 |

---

## 4. Dependencias de Python (VM-2)

Las dependencias exactas están pinneadas en [`requirements.txt`](../requirements.txt). Las principales:

| Paquete | Versión | Uso |
|---|---|---|
| ryu | 4.34 | Controlador SDN |
| eventlet | 0.30.2 | Concurrencia de Ryu (versión crítica) |
| scikit-learn | 1.3.2 | Modelo de Machine Learning |
| pandas | 2.0.3 | Procesamiento de datos |
| numpy | 1.24.4 | Cálculo numérico |
| joblib | 1.4.2 | Persistencia del modelo |
| matplotlib | 3.7.5 | Figuras de evaluación |

> **Advertencia sobre eventlet:** Ryu 4.34 requiere `eventlet==0.30.2`. Versiones más recientes de eventlet son incompatibles y provocan errores al arrancar el controlador. Respetar la versión pinneada.

---

## 5. Herramientas adicionales

| Herramienta | Uso | VM |
|---|---|---|
| hping3 | Generación de tráfico de ataque | VM-1 |
| git | Clonado del repositorio | ambas |
| tcpdump (opcional) | Inspección de tráfico | VM-1 |

---

## 6. Requisitos de red

Las dos VMs se comunican a través de una **red interna** dedicada:

| VM | IP de gestión |
|---|---|
| VM-1 (datos) | 10.10.10.30 |
| VM-2 (control) | 10.10.10.40 |

El controlador escucha en el puerto **6653** (OpenFlow 1.3). Detalles en [`04-Configuracion-Red.md`](04-Configuracion-Red.md).

---

## 7. Orden de instalación recomendado

```
1. Crear las dos VMs (Ubuntu 20.04)
2. Configurar la red (02, 03, 04)
3. Instalar VM-1: Mininet + Open vSwitch  →  02-Instalacion-VM1.md
4. Instalar VM-2: Ryu + entorno Python    →  03-Instalacion-VM2.md
5. Configurar la red entre VMs            →  04-Configuracion-Red.md
6. Ejecutar el laboratorio                →  05-Ejecucion-Laboratorio.md
```

---

*Documento 01 — Requisitos — DDoS-SDN-Defense*

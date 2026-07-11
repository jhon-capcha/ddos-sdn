# 03 — Instalación de VM-2 (Plano de Control)

Instalación del controlador Ryu 4.34 y el entorno de Machine Learning sobre Ubuntu 20.04. Esta VM ejecuta la lógica de detección, identificación y mitigación.

---

## 1. Preparación del sistema

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y git python3 python3-pip python3-venv
```

---

## 2. Clonado del repositorio

```bash
cd ~
git clone https://github.com/jhon-capcha/ddos-sdn-defense.git
cd ddos-sdn-defense
```

En esta VM se utiliza principalmente la carpeta `controller/` (controlador, detector, identificador, mitigador).

---

## 3. Creación del entorno virtual

El entorno virtual aísla las dependencias del proyecto del Python del sistema:

```bash
python3 -m venv venv
source venv/bin/activate
```

> **Importante:** cada nueva sesión de terminal requiere activar el entorno con `source venv/bin/activate` antes de ejecutar el controlador.

---

## 4. Instalación de dependencias

Con el entorno activado, instalar todas las dependencias pinneadas:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Esto instala Ryu 4.34, scikit-learn 1.3.2, pandas, numpy y todas las dependencias con sus versiones exactas.

> **Advertencia sobre eventlet:** el `requirements.txt` fija `eventlet==0.30.2`, versión requerida por Ryu 4.34. No actualizar eventlet: versiones más recientes rompen el arranque del controlador.

> **Nota sobre `pkg_resources==0.0.0`:** si `pip install` falla por esta línea (artefacto de Ubuntu), elimínala del `requirements.txt` antes de instalar; no afecta al funcionamiento.

---

## 5. Verificación de la instalación

**Ryu:**
```bash
ryu-manager --version
# Debe mostrar: ryu-manager 4.34
```

**Paquetes clave:**
```bash
pip freeze | grep -iE "ryu|scikit-learn|pandas|numpy"
```
Debe mostrar:
```
numpy==1.24.4
pandas==2.0.3
ryu==4.34
scikit-learn==1.3.2
```

**Carga del modelo:**
```bash
python3 -c "import joblib; m = joblib.load('controller/models/results_sin_flowcount/model_sin_flowcount.joblib'); print(type(m).__name__)"
# Debe mostrar: Pipeline
```

---

## 6. Prueba de arranque del controlador

```bash
source venv/bin/activate
APP_MODE=detect_mitigate ryu-manager --ofp-tcp-listen-port 6653 controller/apps/monitor.py
```

Debe mostrar:
```
Mitigacion ACTIVA: victima=10.0.0.1, pps_min=50, confirmacion=2 ventanas
Detector listo: modelo='model_sin_flowcount.joblib' (7 features)
Monitor13 iniciado (OpenFlow 1.3, intervalo=5s, modo=detect_mitigate)
```

Detener con `Ctrl+C`.

---

## 7. Solución de problemas

| Síntoma | Solución |
|---|---|
| `ryu-manager: command not found` | Activar el venv: `source venv/bin/activate` |
| Error de eventlet al arrancar Ryu | Verificar `eventlet==0.30.2` (`pip install eventlet==0.30.2`) |
| El modelo no carga | Verificar la ruta del `.joblib`; confirmar que el venv está activado |
| `pip install` falla en `pkg_resources==0.0.0` | Eliminar esa línea del `requirements.txt` |
| El controlador no recibe conexiones | Verificar el firewall y que el puerto 6653 esté libre |

---

*Documento 03 — Instalación VM-2 — DDoS-SDN-Defense*

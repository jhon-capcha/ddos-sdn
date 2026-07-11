# 02 — Instalación de VM-1 (Plano de Datos)

Instalación de Mininet 2.3.0 y Open vSwitch 2.13.8 sobre Ubuntu 20.04. Esta VM emula la red SDN.

---

## 1. Preparación del sistema

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y git python3 python3-pip
```

---

## 2. Instalación de Mininet (desde el repositorio oficial)

Mininet se instaló desde el código fuente (no por `apt`), para disponer de la versión 2.3.0 con todas sus herramientas.

```bash
cd ~
git clone https://github.com/mininet/mininet.git
cd mininet
git checkout 2.3.0
```

Instalar Mininet junto con Open vSwitch:

```bash
cd ~/mininet
sudo ./util/install.sh -nfv
```

**Opciones del instalador:**
- `-n` : instala el núcleo de Mininet
- `-f` : instala OpenFlow
- `-v` : instala Open vSwitch

---

## 3. Verificación de la instalación

**Mininet:**
```bash
mn --version
# Debe mostrar: 2.3.0
```

**Open vSwitch:**
```bash
ovs-vsctl --version
# Debe mostrar: ovs-vsctl (Open vSwitch) 2.13.8
```

**Prueba de conectividad básica:**
```bash
sudo mn --test pingall
```
Debe mostrar `Results: 0% dropped`.

---

## 4. Instalación de hping3 (generación de ataques)

```bash
sudo apt install -y hping3
```

Verificar:
```bash
which hping3
```

---

## 5. Clonado del repositorio del proyecto

```bash
cd ~
git clone https://github.com/jhon-capcha/ddos-sdn-defense.git
```

En esta VM se utiliza únicamente la carpeta `data-plane/` (topología y generación de tráfico).

---

## 6. Verificación final

```bash
cd ~/ddos-sdn-defense
sudo python3 data-plane/topologia/topologia_ddos.py
```

Si el controlador (VM-2) aún no está corriendo, la topología arrancará pero el switch quedará esperando conexión. Esto es normal: el controlador debe arrancar primero (ver [`05-Ejecucion-Laboratorio.md`](05-Ejecucion-Laboratorio.md)).

Salir con:
```
mininet> exit
```
```bash
sudo mn -c
```

---

## 7. Solución de problemas

| Síntoma | Solución |
|---|---|
| `mn: command not found` | Reabrir la terminal o `source ~/.bashrc`; verificar que `install.sh` terminó sin errores |
| Error de permisos al ejecutar Mininet | Mininet requiere `sudo` |
| OVS no arranca | `sudo systemctl start openvswitch-switch` |
| Reglas residuales entre pruebas | `sudo mn -c` |

---

*Documento 02 — Instalación VM-1 — DDoS-SDN-Defense*

# 04 — Configuración de Red

Configuración de la conectividad entre VM-1 (plano de datos) y VM-2 (plano de control).

---

## 1. Esquema de red

Las dos VMs se comunican por una **red interna dedicada** (aislada del tráfico externo), además de un adaptador NAT para acceso a internet:

```
        ┌─────────────┐         Red interna          ┌─────────────┐
        │    VM-1     │      10.10.10.0/24            │    VM-2     │
        │ Plano datos │◀───────────────────────────▶│ Plano ctrl. │
        │ 10.10.10.30 │   OpenFlow 1.3 (6653)        │ 10.10.10.40 │
        └─────────────┘                              └─────────────┘
              │                                             │
           NAT (internet)                              NAT (internet)
```

---

## 2. Adaptadores de red (VMware)

Cada VM se configuró con **dos adaptadores**:

| Adaptador | Tipo | Propósito |
|---|---|---|
| 1 | NAT | Acceso a internet (instalación de paquetes, git) |
| 2 | Red interna (Host-only o LAN Segment) | Comunicación VM-1 ↔ VM-2 |

En VMware, el segundo adaptador debe estar en el **mismo segmento de red** en ambas VMs para que se vean entre sí.

---

## 3. Configuración de IPs estáticas

Sobre el adaptador de red interna, asignar IPs estáticas.

**VM-1 (plano de datos): 10.10.10.30**

Editar la configuración de red (Netplan en Ubuntu 20.04):
```bash
sudo nano /etc/netplan/01-netcfg.yaml
```

Ejemplo de configuración (ajustar el nombre de la interfaz, p. ej. `ens37`):
```yaml
network:
  version: 2
  ethernets:
    ens37:
      addresses:
        - 10.10.10.30/24
      dhcp4: no
```

Aplicar:
```bash
sudo netplan apply
```

**VM-2 (plano de control): 10.10.10.40** — igual, cambiando la dirección a `10.10.10.40/24`.

---

## 4. Verificación de conectividad

**Desde VM-1, hacer ping a VM-2:**
```bash
ping -c 3 10.10.10.40
```

**Desde VM-2, hacer ping a VM-1:**
```bash
ping -c 3 10.10.10.30
```

Ambos deben responder sin pérdida.

---

## 5. Configuración del controlador en la topología

La topología de VM-1 debe apuntar al controlador remoto en VM-2. En el script de topología (`data-plane/topologia/topologia_ddos.py`), el controlador se define como remoto:

```python
RemoteController('c0', ip='10.10.10.40', port=6653)
```

Verificar que la IP coincide con la de VM-2 (10.10.10.40) y el puerto con el que usa el controlador (6653).

---

## 6. Verificación del canal OpenFlow

Con el controlador corriendo en VM-2 y la topología levantada en VM-1, verificar la conexión:

**En VM-2**, debe aparecer en el log:
```
Switch conectado: dpid=1
```

**En VM-1**, verificar el controlador configurado:
```bash
sudo ovs-vsctl show
```
Debe mostrar el `Controller "tcp:10.10.10.40:6653"` con `is_connected: true`.

---

## 7. Solución de problemas

| Síntoma | Solución |
|---|---|
| Las VMs no se hacen ping | Verificar que ambos adaptadores 2 están en el mismo segmento de red interna |
| El nombre de la interfaz no es `ens37` | Identificarla con `ip a`; usar el nombre real en Netplan |
| El switch no conecta al controlador | Verificar la IP (10.10.10.40) y el puerto (6653) en el script de topología; confirmar que el controlador está corriendo |
| `is_connected: false` en `ovs-vsctl show` | El controlador no está activo o hay bloqueo de firewall en el puerto 6653 |

---

*Documento 04 — Configuración de Red — DDoS-SDN-Defense*

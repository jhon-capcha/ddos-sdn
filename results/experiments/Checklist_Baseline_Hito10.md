# Fase 10.2 — Checklist de Baseline
## Verificación del estado del laboratorio antes de cada experimento

---

## Objetivo

Demostrar que el laboratorio está en un **estado conocido y estable** antes de iniciar los experimentos. No es "probar que funciona", sino garantizar que ningún estado residual (reglas viejas, flujos congelados, procesos zombis) contamine las mediciones. Un baseline fallido **detiene** el inicio del experimento.

---

## Checklist de verificación

### 1. Estado del controlador
Al arrancar `APP_MODE=detect_mitigate`, el log debe mostrar:
```
Mitigacion ACTIVA: victima=10.0.0.1, pps_min=50, confirmacion=2 ventanas
Detector listo: modelo='model_sin_flowcount.joblib' (7 features)
Monitor13 iniciado (OpenFlow 1.3, intervalo=5s, modo=detect_mitigate)
Switch conectado: dpid=1
Detector: warming up (fijando linea base)...
```
- [ ] Detector listo
- [ ] Mitigación ACTIVA
- [ ] Switch conectado
- [ ] Warming up completado (1er ciclo)

### 2. Estado del switch (reglas)
```
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```
Debe contener únicamente:
- [ ] Regla `priority=0` (table-miss → CONTROLLER)
- [ ] Reglas del learning switch (`priority=1`) conforme aparece tráfico
- [ ] **NO** debe existir ninguna regla `priority=100 actions=drop`

### 3. Estado del tráfico normal
Generar solo tráfico de fondo durante ~1 minuto:
```
mininet> h2 ping -i 0.5 h1 &
mininet> h3 ping -i 0.5 h1 &
mininet> h4 ping -i 0.5 h1 &
```

### 4. Estado del detector (durante el minuto)
- [ ] Todas las ventanas clasificadas como **NORMAL**
- [ ] **NUNCA** aparece ATAQUE

### 5. Estado del identificador
- [ ] 0 atacantes identificados durante toda la prueba

### 6. Estado del mitigador
- [ ] **NUNCA** aparece "DROP instalado"
- [ ] **NUNCA** aparece "FlowRemoved"

### 7. Disponibilidad
```
mininet> h2 ping -c 5 h1
```
- [ ] packet loss = 0%
- [ ] RTT estable (< 1 ms tras el primer paquete)

---

## Criterio de aceptación del Baseline

El baseline se considera **exitoso** solo si TODOS se cumplen:

| Condición | Estado |
|---|---|
| Detector inicializado correctamente | ☐ |
| Builder estabilizado (warming up completado) | ☐ |
| Switch conectado | ☐ |
| Cero reglas DROP instaladas | ☐ |
| Cero eventos FlowRemoved | ☐ |
| Cero ventanas clasificadas como ATAQUE | ☐ |
| Cero mitigaciones | ☐ |
| Tráfico legítimo operativo | ☐ |
| Packet loss = 0% | ☐ |

**Si cualquier condición falla, el experimento NO comienza.** Se investiga la causa (estado residual, proceso previo, regla vieja) y se reinicia el laboratorio antes de proceder.

---

*Checklist de Baseline — Fase 10.2 — Proyecto DDoS SDN — Maestría en Ciberseguridad (UNMSM)*

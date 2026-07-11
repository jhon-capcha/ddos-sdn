# 07 — Arquitectura del Sistema

Descripción técnica de la arquitectura del sistema DDoS-SDN-Defense: componentes, flujos de información y decisiones de diseño.

---

## 1. Visión general

El sistema implementa una defensa en tiempo real contra ataques DDoS sobre una red definida por software (SDN). Aprovecha la centralización del control característica de SDN para observar el estado global de la red mediante estadísticas OpenFlow, clasificar el tráfico con un modelo de Machine Learning, identificar el origen de los ataques e instalar contramedidas dinámicas.

![Arquitectura del sistema](img/arquitectura.png)

La arquitectura se organiza en dos planos:

- **Plano de control (VM-2):** ejecuta el controlador Ryu con toda la lógica de defensa.
- **Plano de datos (VM-1):** emula la red con Mininet y un switch Open vSwitch.

Ambos planos se comunican mediante OpenFlow 1.3 sobre el puerto 6653.

---

## 2. Topología

![Topología SDN](img/topologia.png)

La topología es una estrella con un switch central (s1) y 7 hosts:

| Host | Rol | IP | Función en los experimentos |
|---|---|---|---|
| h1 | Víctima | 10.0.0.1 | Objetivo de todos los ataques |
| h2–h4 | Legítimos | 10.0.0.2–4 | Tráfico normal de fondo |
| h5 | Atacante | 10.0.0.11 | SYN Flood |
| h6 | Atacante | 10.0.0.12 | UDP Flood |
| h7 | Atacante | 10.0.0.13 | ICMP Flood |

La agregación de flujos se realiza por triplete (IP origen, IP destino, protocolo), sin incluir los puertos de capa 4, para evitar la explosión de la tabla de flujos durante un ataque DDoS.

---

## 3. Componentes del plano de control

El controlador se compone de cuatro módulos con responsabilidades bien delimitadas:

### 3.1 monitor.py (orquestación)

Punto de entrada del controlador. Gestiona la conexión OpenFlow con el switch, solicita las estadísticas de flujo de forma periódica (cada 5 segundos), y coordina el flujo entre los demás módulos. Implementa la máquina de estados que exige 2 ventanas de ataque consecutivas antes de mitigar (para reducir falsos positivos) y el handler del evento `FlowRemoved`.

### 3.2 online_detector.py (detección)

Construye las características del tráfico en tiempo real a partir de las estadísticas de flujo y ejecuta la inferencia del modelo. La lógica de cálculo de características es compartida con el entrenamiento por lotes, garantizando la paridad entre entrenamiento e inferencia. Expone además el estado de la última ventana (deltas por flujo) para el módulo de identificación.

### 3.3 attack_identifier.py (identificación del origen)

Determina qué hosts son los atacantes. Aplica un criterio basado en la dirección del flujo: un flujo se considera atacante si su destino es la víctima, su origen no es la víctima, y supera un umbral de paquetes por segundo. Este criterio es independiente del número de atacantes y escala a ataques coordinados.

### 3.4 mitigator.py (mitigación)

Instala reglas FlowMod DROP dirigidas al tráfico atacante→víctima, con prioridad alta (100) para prevalecer sobre las reglas del switch de aprendizaje. Gestiona el ciclo de vida de las reglas mediante `idle_timeout` y el flag `OFPFF_SEND_FLOW_REM`, manteniendo un registro interno sincronizado con el estado real del switch.

---

## 4. Pipeline de Machine Learning

![Pipeline de Machine Learning](img/pipeline_ml.png)

El modelo se entrenó siguiendo un pipeline reproducible:

1. **Generación de tráfico:** tráfico normal (pings entre hosts) y de ataque (SYN, UDP, ICMP con hping3).
2. **Captura:** recolección de estadísticas de flujo vía OpenFlow.
3. **Feature engineering:** cálculo de características por ventana, incluyendo la entropía de Shannon de la distribución de IPs.
4. **Entrenamiento:** ajuste de un `DecisionTreeClassifier` dentro de un `Pipeline` de scikit-learn.
5. **Modelo:** serialización del pipeline entrenado (`.joblib`).

**Modelo operativo:**

```python
Pipeline([
    ('scaler', StandardScaler()),
    ('model', DecisionTreeClassifier(class_weight='balanced',
                                     max_depth=5,
                                     min_samples_leaf=2,
                                     random_state=42))
])
```

El `StandardScaler` no es requerido por el árbol de decisión (que es invariante a la escala), pero se incluye para garantizar la consistencia del procesamiento entre entrenamiento e inferencia y para permitir la sustitución del clasificador por otros modelos sensibles a la escala.

**Características:** el modelo opera sobre 7 características estadísticas por ventana. La de mayor importancia es `packets_per_second` (~89% de la importancia del modelo), seguida de otras métricas de volumen y la entropía de Shannon de las IPs de origen y destino.

---

## 5. Flujo de defensa

![Flujo de defensa](img/flujo_mitigacion.png)

El ciclo defensivo opera de forma continua:

1. **Recolección:** el monitor solicita estadísticas de flujo cada 5 segundos.
2. **Detección:** el detector construye las características y clasifica la ventana como NORMAL o ATAQUE.
3. **Confirmación:** se exigen 2 ventanas de ATAQUE consecutivas antes de actuar (reduce falsos positivos).
4. **Identificación:** el identificador determina los hosts atacantes según el criterio de dirección.
5. **Mitigación:** el mitigador instala una regla DROP por cada atacante identificado.
6. **Recuperación:** al cesar el ataque, las reglas expiran por `idle_timeout`, generan un evento `FlowRemoved` y el registro interno se sincroniza.

---

## 6. Decisiones de diseño

Las decisiones arquitectónicas clave fueron refinadas con base en evidencia experimental durante el desarrollo:

### 6.1 Identificación por dirección (no por contribución)

El criterio inicial basado en la contribución relativa de cada flujo (`contribution > umbral`) falló en el escenario coordinado: con tres atacantes repartiéndose el tráfico, cada uno quedaba por debajo del umbral. El criterio final, basado en la dirección del flujo (`dst==víctima, src≠víctima, pps≥umbral`), es independiente del número de atacantes y del reparto del tráfico entre ellos.

### 6.2 Ciclo de vida basado en FlowRemoved

El uso inicial de `hard_timeout` producía desincronización: la regla expiraba en el switch mientras el registro del controlador la creía activa. El diseño final usa solo `idle_timeout` combinado con el flag `OFPFF_SEND_FLOW_REM` y un handler del evento `FlowRemoved`, de modo que el switch es la fuente de verdad del estado de las reglas.

### 6.3 Separación de responsabilidades

Detección, identificación y mitigación se implementan como módulos independientes. Esto permite validar cada uno de forma aislada, facilita el mantenimiento y permite evolucionar un componente (por ejemplo, el algoritmo de detección) sin afectar a los demás.

### 6.4 Paridad entre entrenamiento e inferencia

La lógica de cálculo de características es compartida entre el procesamiento por lotes (entrenamiento) y el procesamiento en línea (producción), garantizando que el modelo recibe en producción el mismo tipo de datos con los que fue entrenado.

### 6.5 Agregación de flujos sin puertos L4

La agregación por triplete (origen, destino, protocolo) sin incluir los puertos de capa 4 previene la explosión de la tabla de flujos: bajo un ataque DDoS con puertos aleatorios, incluir los puertos multiplicaría el número de flujos rastreados.

---

## 7. Parámetros del sistema

| Parámetro | Valor | Descripción |
|---|---|---|
| MONITOR_INTERVAL | 5 s | Frecuencia de recolección de estadísticas |
| PPS_MIN | 50 pps | Umbral mínimo de paquetes por segundo para identificar un atacante |
| Confirmación | 2 ventanas | Ventanas de ataque consecutivas antes de mitigar |
| idle_timeout | 15 s | Tiempo de inactividad antes de expirar una regla DROP |
| priority (DROP) | 100 | Prioridad de las reglas de mitigación |
| VICTIM_IP | 10.0.0.1 | IP de la víctima protegida |

---

## 8. Limitaciones y trabajo futuro

- **IP spoofing:** el bloqueo por IP de origen sería ineficaz ante atacantes que falsifican su IP. En ese escenario, la entropía de la IP de origen (actualmente poco discriminante con IPs fijas) recuperaría valor. Es la principal línea de trabajo futuro.
- **Escala de la topología:** el sistema se validó con 7 hosts; topologías mayores requerirían evaluación adicional.
- **Medición del tiempo de recuperación en ataques coordinados:** con múltiples reglas simultáneas, la métrica de recuperación requiere una consideración especial (ver documentación de resultados).

---

*Documento 07 — Arquitectura del Sistema — DDoS-SDN-Defense*

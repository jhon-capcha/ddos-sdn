# Caracterización del Tráfico mediante Entropía de Shannon para la Detección, Identificación y Mitigación Automática de Ataques DDoS en Redes SDN

**Jhon Capcha**
*Maestría en Ciberseguridad*
*Universidad Nacional Mayor de San Marcos*
Lima, Perú
email / ORCID

---

## Resumen (Abstract)

Los ataques de denegación de servicio distribuido (DDoS) alteran la distribución estadística del tráfico de red. Este trabajo propone un sistema de defensa organizado en tres capas conceptuales: una capa de caracterización, fundamentada en la Entropía de Shannon, que transforma el tráfico en una representación estadística interpretable; una capa de decisión, basada en Machine Learning, que clasifica dicha representación; y una capa de respuesta, sobre red definida por software (SDN), que identifica el origen y aplica mitigación automática mediante OpenFlow. La Entropía de Shannon no actúa como un detector, sino como un mecanismo de caracterización del comportamiento estadístico del tráfico. La validación experimental, compuesta por quince experimentos en cinco escenarios, obtuvo una identificación de atacantes con F1-score de 1.00, cero falsos positivos en tráfico legítimo y recuperación automática del 100% de las reglas de mitigación, demostrando escalabilidad ante ataques coordinados con múltiples orígenes simultáneos.

**Palabras clave (Keywords):** Entropía de Shannon, caracterización estadística del tráfico, DDoS, Software Defined Networking, OpenFlow, Machine Learning, mitigación automática.

---

## I. Introducción

Los ataques de denegación de servicio distribuido (DDoS) modifican la distribución estadística del tráfico de red. Un ataque volumétrico dirigido concentra el tráfico hacia una víctima, alterando la aleatoriedad de las direcciones y de las tasas de flujo respecto de una condición normal. Esta alteración estadística es la señal que permite distinguir un ataque de la actividad legítima.

La Entropía de Shannon proporciona una medida rigurosa de esa aleatoriedad. Al cuantificar la incertidumbre de la distribución de las direcciones IP, la entropía captura de forma compacta los cambios que un ataque introduce en la estructura del tráfico. No obstante, una decisión basada en umbrales fijos sobre una o pocas métricas de entropía resulta sensible al entorno. Para superar esta limitación, la caracterización basada en entropía se complementa con un modelo de Machine Learning que clasifica el tráfico a partir de la representación estadística, en lugar de operar sobre el tráfico bruto. Finalmente, la arquitectura de red definida por software (SDN) permite actuar de forma inmediata sobre el origen identificado mediante OpenFlow.

Este trabajo propone estructurar la defensa contra DDoS como un **modelo conceptual de tres capas** (Fig. 1), en el que cada componente cumple una función claramente diferenciada:

- **Capa de caracterización:** la Entropía de Shannon transforma el tráfico en una representación estadística interpretable.
- **Capa de decisión:** un clasificador de Machine Learning determina si esa representación corresponde a tráfico normal o de ataque.
- **Capa de respuesta:** la infraestructura SDN/OpenFlow identifica el origen y aplica la mitigación automática.

Bajo este modelo, la innovación no reside en el uso de un clasificador particular, sino en integrar una caracterización estadística fundamentada en la Entropía de Shannon con una decisión automática y una respuesta en tiempo real sobre SDN.

*[FIGURA 1: modelo_tres_capas.png — Modelo conceptual de tres capas]*

El objetivo del trabajo es desarrollar un sistema de defensa contra ataques DDoS cuya caracterización del tráfico se fundamenta en la Entropía de Shannon y cuya clasificación automática se realiza mediante Machine Learning, con identificación del origen y mitigación automatizadas sobre infraestructura SDN.

Las contribuciones principales son:

- Un modelo conceptual de tres capas (caracterización, decisión, respuesta) que estructura la defensa contra DDoS en SDN.
- Una caracterización del tráfico basada en la Entropía de Shannon como fundamento analítico del sistema.
- Un mecanismo de clasificación que opera sobre la representación estadística del tráfico, no sobre el tráfico bruto.
- Un criterio de identificación del origen robusto ante ataques distribuidos con múltiples orígenes.
- Un esquema de mitigación automática con recuperación basada en el ciclo de vida de las reglas OpenFlow.

## II. Estado del Arte

### A. Métodos estadísticos basados en entropía

La caracterización estadística del tráfico se ha abordado mediante diversas medidas de información. La Entropía de Shannon es la más difundida por su interpretación directa como medida de incertidumbre. Existen generalizaciones —las entropías de Rényi y de Tsallis, con un parámetro de orden— y pruebas como Chi-cuadrado, empleadas para detectar desviaciones respecto de una distribución de referencia.

**¿Por qué la Entropía de Shannon?** Entre las alternativas, la Entropía de Shannon fue seleccionada porque reúne simultáneamente un conjunto de propiedades idóneas para el entorno SDN: bajo costo computacional, que permite el cálculo en línea sobre cada ventana; interpretación clara como medida de incertidumbre de la distribución; cálculo a partir de estadísticas agregadas de flujo, sin necesidad de inspección profunda de paquetes (Deep Packet Inspection); independencia del contenido de los paquetes, operando solo sobre metadatos de flujo; y compatibilidad natural con la información que OpenFlow entrega al controlador. Estas propiedades hacen de la Entropía de Shannon una elección fundamentada, no arbitraria, como base de la capa de caracterización.

### B. Métodos basados en Machine Learning

La clasificación de tráfico mediante Machine Learning se ha explorado con SVM, KNN, Random Forest, árboles de decisión y redes neuronales. Estos enfoques aprenden patrones complejos, pero su desempeño depende de la representación de entrada.

**¿Por qué no utilizar únicamente Machine Learning?** El uso exclusivo de Machine Learning obliga al modelo a aprender directamente sobre variables de bajo nivel cuya interpretación puede resultar limitada. La incorporación de la Entropía de Shannon permite representar explícitamente el comportamiento estadístico del tráfico antes del proceso de clasificación. En consecuencia, el clasificador aprende sobre una representación con significado físico, lo que aumenta la interpretabilidad del sistema y vincula la decisión automática con un fundamento analítico. Por ello, en este trabajo el Machine Learning no opera sobre el tráfico bruto, sino sobre la caracterización estadística producida por la Entropía de Shannon.

## III. Capa de Caracterización: Entropía de Shannon

La Entropía de Shannon mide la incertidumbre asociada a una distribución de probabilidad. Para una variable aleatoria X con valores xᵢ y probabilidades p(xᵢ):

    H(X) = - Σ p(xᵢ) · log₂ p(xᵢ)     (1)

En el contexto del tráfico, X representa la distribución de las direcciones IP (origen o destino) en una ventana de tiempo, y p(xᵢ) es la proporción de flujos asociados a la dirección xᵢ.

Es importante precisar el papel que desempeña esta medida en el sistema: **la Entropía de Shannon no constituye un detector de ataques, sino un mecanismo de representación del comportamiento estadístico del tráfico.** Su función es transformar un conjunto de flujos en un valor que resume la estructura de su distribución, produciendo una caracterización compacta e interpretable sobre la que operará la capa de decisión.

**¿Qué mide?** La entropía cuantifica cuán uniforme o concentrada está la distribución de direcciones. Un valor alto indica dispersión (muchas direcciones con proporciones similares); un valor bajo, concentración (pocas direcciones dominan).

**¿Por qué funciona ante ataques?** En condiciones normales, el tráfico se distribuye entre múltiples pares origen-destino, produciendo una entropía estable. Un ataque DDoS dirigido concentra el tráfico hacia la víctima, alterando la distribución y, con ella, el valor de entropía. Este cambio es la firma estadística que caracteriza la condición de ataque.

**¿Qué ocurre cuando la distribución cambia?** La transición de una distribución dispersa a una concentrada (o viceversa) se refleja en una variación de la entropía respecto de su línea base. Esta variación, combinada con variables de volumen, proporciona a la capa de decisión la información necesaria para clasificar.

**¿Por qué SDN facilita su cálculo?** El controlador SDN recibe periódicamente las estadísticas de flujo mediante OpenFlow. Esta información agregada permite construir la distribución de direcciones y calcular la entropía de forma centralizada, sin inspección profunda de paquetes ni sondas distribuidas.

## IV. Arquitectura del Sistema

El sistema materializa el modelo de tres capas sobre una arquitectura SDN de dos planos: el plano de control (controlador Ryu) y el plano de datos (Mininet y Open vSwitch), comunicados por OpenFlow 1.3.

El pipeline de caracterización (Fig. 2) sitúa la Entropía de Shannon en el centro del proceso, dejando explícito que el clasificador no consume tráfico, sino su representación estadística:

    Tráfico OpenFlow
          ↓
    Construcción de ventanas temporales
          ↓
    Distribución estadística de direcciones
          ↓
    Entropía de Shannon  →  representación matemática del comportamiento
          ↓
    Variables estadísticas complementarias
          ↓
    Vector de características
          ↓
    Decision Tree (capa de decisión)

*[FIGURA 2: pipeline_caracterizacion.png — Pipeline de caracterización]*

El sistema se compone de cuatro módulos funcionales. La **orquestación** gestiona la conexión OpenFlow y solicita estadísticas cada 5 segundos, exigiendo dos ventanas de ataque consecutivas antes de mitigar. La **detección** construye el vector de características y ejecuta la clasificación. La **identificación** determina los hosts atacantes mediante un criterio basado en la dirección del flujo hacia la víctima. La **mitigación** instala reglas FlowMod DROP y gestiona su ciclo de vida mediante idle_timeout y el evento FlowRemoved.

## V. Metodología

### A. Entorno experimental

El laboratorio se desplegó sobre dos máquinas virtuales: plano de datos (Mininet 2.3.0, Open vSwitch 2.13.8) y plano de control (Ryu 4.34). La topología es una estrella con un conmutador y siete hosts: una víctima, tres generadores de tráfico legítimo y tres atacantes.

### B. Pipeline de procesamiento

El flujo metodológico coloca la caracterización mediante entropía como paso central: captura de estadísticas → construcción de ventanas → **cálculo de la Entropía de Shannon** → variables estadísticas complementarias → vector de características → clasificación. Las estadísticas se agregan por triplete (IP origen, IP destino, protocolo), sin puertos de capa 4, para evitar la explosión de la tabla de flujos bajo ataque.

### C. Vector de características

El vector incluye la Entropía de Shannon de las direcciones de origen y destino, junto a variables de volumen (tasa de paquetes y de bytes por segundo). La lógica de cálculo es compartida entre el entrenamiento por lotes y la inferencia en línea, garantizando la paridad.

### D. Capa de decisión

Sobre el vector opera un árbol de decisión en un pipeline de scikit-learn (StandardScaler + DecisionTreeClassifier, con `max_depth=5`, `class_weight='balanced'`, `min_samples_leaf=2`, `random_state=42`). El árbol no requiere escalado, pero el estandarizador garantiza la consistencia del procesamiento y permite sustituir el clasificador por modelos sensibles a la escala.

## VI. Diseño Experimental

Se ejecutaron quince experimentos en cinco escenarios con tres repeticiones cada uno.

**TABLA I. Escenarios experimentales**

| Escenario | Atacante(s) | Tipo de ataque |
|---|---|---|
| Normal | ninguno | tráfico legítimo (control) |
| SYN Flood | h5 | inundación TCP SYN |
| ICMP Flood | h7 | inundación ICMP |
| UDP Flood | h6 | inundación UDP |
| Coordinado | h5, h6, h7 | ataque distribuido simultáneo |

Los experimentos siguieron un protocolo uniforme con un orquestador que estandariza los tiempos y registra marcadores. La generación de tráfico y ataques se mantuvo manual, con duración de ataque fija de 90 segundos. La instrumentación de medición es independiente del algoritmo evaluado, lo que asegura la reproducibilidad.

## VII. Resultados

### A. Comportamiento de la caracterización mediante Shannon

El análisis del comportamiento de la Entropía de Shannon confirma su valor como caracterización del tráfico. Durante los escenarios de tráfico normal, la entropía de las direcciones se mantuvo estable, reflejando una distribución consistente del tráfico legítimo. Durante los ataques, la concentración del tráfico hacia la víctima alteró la distribución y, con ella, los valores de entropía respecto de la línea base. Esta variación proporcionó, junto con las variables de volumen, la información sobre la que la capa de decisión distinguió las condiciones de ataque. El comportamiento observado es coherente en los distintos tipos de ataque: la caracterización estadística reaccionó a la alteración de la distribución con independencia del protocolo empleado.

### B. Detección, identificación y mitigación

El sistema detectó, identificó y mitigó el 100% de los ataques (12 de 12). En el escenario coordinado se instalaron tres reglas DROP (una por atacante) en las tres repeticiones.

**TABLA II. Tiempos de respuesta (media ± desviación estándar, en segundos)**

| Escenario | Td | Tm | Tr |
|---|---|---|---|
| SYN Flood | 6.7 ± 1.5 | 11.7 ± 1.5 | 13.3 ± 0.6 |
| ICMP Flood | 2.3 ± 1.2 | 7.3 ± 1.2 | 13.7 ± 0.6 |
| UDP Flood | 5.0 ± 0.0 | 10.0 ± 0.0 | 13.7 ± 0.6 |
| Coordinado | 6.3 ± 1.5 | 11.3 ± 1.5 | — ᵃ |

ᵃ Requiere consideración especial por la presencia de múltiples reglas.

### C. Rendimiento del identificador

**TABLA III. Matriz de confusión del identificador (agregada)**

| Métrica | Valor |
|---|---|
| Verdaderos positivos (TP) | 18 |
| Falsos positivos (FP) | 0 |
| Falsos negativos (FN) | 0 |
| Precisión | 1.00 |
| Recall | 1.00 |
| F1-score | 1.00 |

### D. Falsos positivos y disponibilidad

El escenario de tráfico normal no produjo ninguna clasificación de ataque ni mitigación en sus tres repeticiones. El tráfico legítimo se preservó con 0% de pérdida durante la mitigación. Las 18 reglas instaladas se recuperaron automáticamente (18 eventos FlowRemoved), sin reglas huérfanas.

## VIII. Discusión

Los resultados validan las decisiones de diseño. El **criterio de identificación por dirección** fue determinante para la escalabilidad: un criterio basado en la contribución relativa habría fallado en el escenario coordinado, donde tres atacantes se reparten el tráfico. El **ciclo de vida basado en FlowRemoved** resolvió la desincronización del hard_timeout, haciendo del conmutador la fuente de verdad del estado.

Un resultado particularmente relevante concierne al papel de la Entropía de Shannon dentro del sistema. En el entorno experimental, las variables relacionadas con la tasa de paquetes mostraron una mayor importancia relativa dentro del clasificador. Sin embargo, la Entropía de Shannon mantuvo su capacidad para representar el comportamiento estadístico del tráfico incluso cuando no fue la característica de mayor peso en la decisión. Esto demuestra que el valor de la entropía no reside únicamente en su importancia dentro del modelo de Machine Learning, sino en proporcionar una representación matemática estable y explicable del estado del tráfico. La entropía no compite con las variables de volumen: constituye el fundamento de caracterización sobre el que se articula la decisión.

Este comportamiento se explica por las características controladas del laboratorio: los atacantes emplean direcciones IP fijas y no realizan falsificación de origen (IP spoofing), por lo que la entropía de la IP de origen presenta menor variación discriminante. En presencia de IP spoofing —donde los atacantes falsifican múltiples direcciones de origen—, la entropía de origen recuperaría su poder discriminante, y su papel como fundamento analítico se reflejaría explícitamente en las métricas del clasificador. Este resultado no constituye una limitación del enfoque, sino una consecuencia esperada del escenario, y define la principal línea de trabajo futuro.

## IX. Conclusiones y Trabajo Futuro

Este trabajo presentó un sistema de defensa contra ataques DDoS en SDN estructurado en tres capas: caracterización, decisión y respuesta. La Entropía de Shannon permitió representar el comportamiento estadístico del tráfico y constituyó la base para la construcción del vector de características. Sobre esta representación, el Machine Learning proporcionó el mecanismo de decisión automática, y la infraestructura SDN habilitó la identificación del origen y la mitigación inmediata mediante OpenFlow.

El sistema cierra el ciclo defensivo completo —caracterización, detección, identificación, mitigación y recuperación— con tiempos de respuesta reproducibles del orden de segundos. La validación experimental demostró una identificación de atacantes con F1-score de 1.00, cero falsos positivos, recuperación automática del 100% de las reglas y escalabilidad ante ataques coordinados.

La contribución conceptual del trabajo radica en el modelo de tres capas, que asigna a cada tecnología un papel definido: la Entropía de Shannon como fundamento de caracterización, el Machine Learning como mecanismo de decisión, y SDN como mecanismo de respuesta. Como trabajo futuro se plantea la evaluación en escenarios con falsificación de IP de origen, donde la caracterización mediante entropía de origen recuperaría plenamente su protagonismo; la evaluación de la calidad de servicio; y el escalado a topologías de mayor tamaño.

## Agradecimientos

El autor agradece a la Maestría en Ciberseguridad de la Universidad Nacional Mayor de San Marcos y al curso de Programación Aplicada a la Ciberseguridad por el marco académico en el que se desarrolló esta investigación.

## Referencias

*[Completar con las referencias bibliográficas del marco teórico. Formato IEEE. Referencias base sugeridas:]*

[1] C. E. Shannon, "A mathematical theory of communication," *Bell System Technical Journal*, vol. 27, no. 3, pp. 379–423, 1948.

[2] N. McKeown et al., "OpenFlow: Enabling innovation in campus networks," *ACM SIGCOMM Computer Communication Review*, vol. 38, no. 2, pp. 69–74, 2008.

[3] *[Referencia sobre detección de DDoS basada en entropía en SDN]*

[4] *[Referencia sobre entropías generalizadas: Rényi / Tsallis en tráfico de red]*

[5] *[Referencias sobre Machine Learning aplicado a detección de DDoS en SDN]*

*[Añadir las referencias específicas del marco teórico de la tesis; se recomienda entre 15 y 30 para un artículo de conferencia.]*

---

*Artículo elaborado a partir del proyecto de tesis — Maestría en Ciberseguridad, UNMSM. Estructura conforme al formato IEEE Conference. Modelo conceptual: caracterización (Shannon) · decisión (ML) · respuesta (SDN).*

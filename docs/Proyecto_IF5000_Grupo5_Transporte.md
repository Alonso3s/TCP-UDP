# Proyecto de Curso — Análisis de la Pila TCP/IP

**Universidad de Costa Rica · Sede del Sur · Bach. en Informática Empresarial**
**IF5000 — Redes y Comunicación de Datos · Prof. Mainor Cruz**

> **Grupo 5 — Capa de Transporte: TCP y UDP**

---

## 1. Objetivo general

Desarrollar en cada grupo de estudiantes un dominio profundo de una capa específica de la pila TCP/IP, mediante el diseño e implementación de un sistema propio que:

- capture tráfico real,
- opere a bajo nivel sobre los campos del protocolo asignado, y
- analice al menos una condición anómala característica de esa capa,

evidenciando así la comprensión del funcionamiento interno de las redes y la comunicación de datos.

## 2. Objetivos específicos

- Estudiar el o los **RFC** relevantes y la literatura técnica del protocolo asignado, hasta dominar la estructura de sus mensajes y su comportamiento esperado.
- Diseñar y proponer la **arquitectura** de un sistema que evidencie el funcionamiento de la capa asignada, justificando decisiones técnicas, herramientas y alcance.
- Implementar al menos un componente que opere **directamente sobre los campos del protocolo**, sin depender exclusivamente de librerías de alto nivel que oculten la estructura.
- Capturar y analizar **tráfico real** del protocolo en una red controlada por el equipo, validando los resultados contra herramientas estándar como Wireshark.
- Identificar, reproducir y analizar al menos una **anomalía, ataque o comportamiento atípico** característico de la capa, reportando métricas honestas de la detección.
- Comunicar los resultados de manera profesional mediante una **presentación oral con demostración en vivo** y un **póster científico**.

---

## 3. Organización del proyecto

El curso se organiza en **seis grupos de tres estudiantes** cada uno. A cada grupo se le asignará por sorteo una de las seis capas o segmentos de la pila TCP/IP. La distribución busca cubrir, entre todos los grupos, la pila completa, de modo que al cierre de las presentaciones el curso tenga una visión integral del funcionamiento de las redes desde el medio físico hasta los protocolos de aplicación.

Cada equipo organiza su propio plan de trabajo interno: la asignación de roles, la distribución de tareas y el cronograma de avances forman parte de la propuesta de solución (**Entregable E1**) y son evaluables. El docente acompañará los avances mediante consultas en clase y revisiones puntuales según se solicite.

---

## 4. Consigna específica del Grupo 5 — Capa de Transporte (TCP y UDP)

Demostrar el funcionamiento de la **capa de transporte**. El sistema debe evidenciar:

- el establecimiento, mantenimiento y cierre de sesiones **TCP**,
- sus mecanismos de **control de flujo** y **retransmisión**, y
- la comparación con el modelo **sin conexión de UDP**.

El grupo seleccionará y justificará al menos **un ataque o comportamiento anómalo** característico de la capa de transporte (por ejemplo, escaneo de puertos o inundaciones) para análisis y detección.

---

## 5. Componentes mínimos del sistema

Independientemente de la capa asignada, todo sistema propuesto debe cumplir con los tres componentes siguientes. La forma específica de cumplirlos es decisión del grupo y debe quedar plenamente justificada en la propuesta de solución.

### Componente 1 — Captura y observación de tráfico real
El sistema debe permitir capturar tráfico real del protocolo asignado en una red controlada por el equipo (laboratorio doméstico, máquina virtual, topología simulada en **Cisco Packet Tracer** o **GNS3**). Debe documentarse la metodología de captura, las herramientas empleadas y la forma de garantizar que el tráfico observado es representativo.

### Componente 2 — Implementación a bajo nivel
El sistema debe incluir al menos un componente programado por el grupo que opere directamente sobre los campos del protocolo, **sin que toda la lógica delegue en librerías de alto nivel** que oculten la estructura del mensaje. El grupo decidirá qué porciones implementará (parser, constructor de mensajes, cliente, servidor, analizador), con qué alcance y por qué.

### Componente 3 — Análisis de una condición anómala
El sistema debe analizar y, cuando aplique, detectar al menos una anomalía, ataque o comportamiento atípico característico de la capa. El grupo seleccionará el caso, justificará la elección y propondrá métricas claras para evaluar la efectividad (por ejemplo: tasa de verdaderos positivos, falsos positivos, latencia de detección, cobertura).

---

## 6. Restricciones, herramientas y recursos

- **Stack tecnológico recomendado:** Python 3 con `scapy` y *sockets*. Otros lenguajes son admisibles si el grupo justifica la elección en su propuesta.
- **Validación obligatoria:** las capturas y los *parsers* propios deben compararse contra **Wireshark** o **tshark** para evidenciar correctitud.
- **Infraestructura:** los grupos trabajan con equipos propios y su red local. Se recomienda usar **Cisco Packet Tracer** o **GNS3** para topologías aisladas y controladas.
- **Versionamiento:** es obligatorio un **repositorio Git público** (GitHub, GitLab o similar) con historia de commits. *No se aceptarán repositorios con un único commit final.*
- **Pruebas reproducibles:** el repositorio debe incluir capturas `.pcap` de muestra y un guion de pruebas para que el docente pueda reproducir los resultados.
- **Integridad académica:** todo código de terceros debe citarse explícitamente. Todo uso de IA generativa debe declararse en una sección titulada **"Asistencia de IA"**, indicando qué se solicitó y cómo se incorporó.
- **Pruebas controladas:** los ataques o anomalías deben reproducirse **exclusivamente en redes y equipos propios**, nunca sobre infraestructura de terceros sin autorización.

---

## 7. Entregables

### E1 — Propuesta de solución
Documento escrito de **máximo cuatro páginas**, entregable en la primera semana posterior a la asignación del tema. Debe contener:

- comprensión del problema y del protocolo asignado (síntesis del RFC relevante);
- arquitectura propuesta con diagrama de componentes;
- metodología (cómo se capturará tráfico, qué se implementará, qué anomalía se analizará);
- plan de trabajo interno con asignación de roles y cronograma propio;
- métricas con las que se evaluará el éxito de la solución;
- riesgos previstos con su plan de mitigación.

> Este documento es la base sobre la que se evaluarán los avances posteriores.

### E2 — Sistema funcional y código fuente
Repositorio Git público con: código fuente, `README` con instrucciones de instalación y uso, lista explícita de dependencias, capturas `.pcap` de muestra e instrucciones para reproducir los experimentos. El sistema debe ejecutarse ante el docente y los compañeros sin más ajustes que los descritos en el `README`.

### E3 — Presentación oral y demostración en vivo
**Martes 23 de junio.** Cada grupo dispone de **30 minutos**:

- **15 min** — exposición teórica del protocolo y la arquitectura del sistema;
- **10 min** — demostración en vivo del sistema funcionando;
- **5 min** — preguntas del docente y de los compañeros.

El orden de exposición seguirá la pila desde el nivel más bajo (Enlace) hasta el más alto (Aplicación).

### E4 — Póster científico
Póster en formato **A1** con estructura de conferencia académica: motivación, marco teórico, arquitectura del sistema, metodología, resultados experimentales con gráficos, conclusión y referencias. Se exhibe el día de la presentación; los integrantes deben estar disponibles junto a él durante el receso.

---

## 8. Rúbrica de evaluación (100 pts)

Cada criterio se evalúa en escala: **Inexistente (0 pts) · Regular · Bueno · Excelente**.

| Criterio | Inexistente (0) | Regular | Bueno | Excelente |
|---|---|---|---|---|
| **Profundidad técnica** (20) | No se demuestra conocimiento del protocolo ni de su RFC. | Conocimiento superficial; decisiones sin justificación sólida. **(8)** | Buen dominio; la mayoría de las decisiones justificadas. **(14)** | Dominio profundo del RFC; todas las decisiones justificadas con precisión. **(20)** |
| **Sistema funcional y calidad de código** (20) | El sistema no corre o no existe repositorio. | Fallos importantes; código poco legible; commits escasos. **(8)** | Funciona con pequeños problemas; código razonablemente documentado. **(14)** | Completamente funcional; código limpio, documentado y repositorio con historia clara. **(20)** |
| **Resultados experimentales** (15) | No se presentan resultados ni capturas. | Resultados incompletos o no reproducibles; sin comparación con Wireshark. **(5)** | Datos reales y comparación parcial con Wireshark. **(10)** | Completos, reproducibles, con gráficos y comparación sistemática con Wireshark. **(15)** |
| **Análisis de anomalías** (15) | No se analiza ninguna anomalía. | Se menciona pero el análisis es superficial o sin métricas. **(5)** | Análisis sólido con métricas parciales; elección justificada. **(10)** | Análisis riguroso con métricas completas, selección justificada y resultados reproducibles. **(15)** |
| **Presentación oral y demo** (15) | No se presenta o la demo no funciona. | Exposición confusa o demo fallida; dificultad para responder. **(5)** | Exposición clara con demo funcional; respuestas aceptables. **(10)** | Exposición fluida, demo impecable, respuestas precisas y excelente manejo del tiempo. **(15)** |
| **Póster científico** (15) | No se presenta o no tiene relación con el trabajo. | Incompleto o sin estructura académica; comunicación deficiente. **(5)** | Estructura correcta y contenido técnico; comunicación aceptable. **(10)** | Completo, visualmente riguroso, con gráficos y resultados; excelente comunicación. **(15)** |
| **Total** | | | | **100** |

---

## 9. Recursos sugeridos

*Base de partida, no exhaustiva. Cada grupo debe ampliar con los RFC específicos de su protocolo.*

### Material bibliográfico de referencia
- Kurose, J. y Ross, K. — *Computer Networking: A Top-Down Approach* (8.ª ed.).
- Tanenbaum, A. y Wetherall, D. — *Computer Networks* (5.ª ed.).
- Stallings, W. — *Data and Computer Communications*.
- Documentos **RFC del IETF** correspondientes al protocolo asignado — <https://www.rfc-editor.org>

### Herramientas técnicas
- **Wireshark / tshark** — análisis y validación de capturas — <https://www.wireshark.org>
- **scapy** — biblioteca de Python para manipulación de paquetes — <https://scapy.net>
- **Cisco Packet Tracer** y **GNS3** — simulación de topologías de red.
- **Mininet** — emulación de redes en una sola máquina — <https://mininet.org>

### Capturas de tráfico de muestra
- Repositorio de muestras de Wireshark — <https://wiki.wireshark.org/SampleCaptures>
- Conjuntos de datos del *Canadian Institute for Cybersecurity*, **CIC-IDS**.
- **MAWI** Working Group Traffic Archive.

---

## 10. Observaciones finales

Este enunciado es deliberadamente abierto: la propuesta de solución de cada grupo es parte esencial del aprendizaje y de la evaluación. Se valorará la **originalidad** del enfoque, la **profundidad técnica**, el **rigor experimental** y la **calidad de la comunicación final**.

Ante dudas sobre alcance, herramientas o viabilidad, los grupos pueden consultar al docente en clase o en horas de atención. El acompañamiento del proceso es deseable; **lo que no es aceptable es esperar al final del periodo para reportar avances.**

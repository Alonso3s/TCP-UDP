# Proyecto IF5000 — Grupo 5: Capa de Transporte (TCP / UDP)

> **Guía maestra del proyecto.** Este archivo es la fuente de verdad: define qué construimos,
> qué **no** construimos, cómo se organiza el repositorio y cómo trabajar con Claude Code.
> Si una tarea no aparece aquí, no se hace sin acordarlo antes con el equipo.

- **Curso:** IF5000 — Redes y Comunicación de Datos · Prof. Mainor Cruz · UCR Sede del Sur
- **Capa asignada:** Transporte (TCP y UDP)
- **Anomalía a analizar:** Escaneo de puertos (extensión opcional: inundación SYN)
- **Stack:** Python 3 + scapy + sockets · validación con Wireshark / tshark
- **Entrega de la demo (E3):** martes 23 de junio
- **Integrantes:** [Integrante 1] · [Integrante 2] · [Integrante 3]
- **Repositorio:** [URL del repo Git público]

---

## 1. Objetivo en una frase

Construir y demostrar un sistema **propio** en Python que capture tráfico **TCP/UDP real** en
una red controlada, **parsee los campos del protocolo a bajo nivel** (sin delegar todo en
librerías de alto nivel), **detecte un escaneo de puertos** con métricas honestas, y valide
todo contra Wireshark.

---

## 2. Alcance — qué SÍ hacemos

El sistema debe cumplir **tres componentes mínimos**. Esto es lo único que se evalúa; todo lo
demás es accesorio.

### Componente 1 — Captura de tráfico real
- Montar una red controlada propia (VMs en red aislada y/o topología en **GNS3**).
- Generar tráfico representativo: sesiones TCP completas, datagramas UDP y los escaneos.
- Capturar con scapy/tcpdump y guardar archivos `.pcap` reproducibles.
- Documentar la metodología de captura.

### Componente 2 — Implementación a bajo nivel (el corazón del proyecto)
- **Parser propio** que decodifica las cabeceras **TCP (20 bytes + opciones)** y **UDP (8 bytes)**
  a partir de los **bytes crudos** (módulo `struct`). No usar el disector automático de scapy
  para interpretar los campos.
- **Reconstructor de estados TCP**: acuerdo de tres vías, evolución de la ventana,
  retransmisiones y cierre (FIN/RST).
- **Validación**: comparar campo a campo la salida del parser propio contra `tshark`/`pyshark`
  sobre el mismo `.pcap`.

### Componente 3 — Análisis de la anomalía
- Reproducir escaneos de puertos en **nuestra propia red** (nmap y/o escáner propio en scapy).
- Detectar el escaneo con heurísticas (muchos puertos en ventana corta, proporción RST/SYN-ACK,
  conexiones semiabiertas).
- Reportar métricas: precisión, recall, F1, falsos positivos/hora, latencia de detección,
  cobertura de tipos de escaneo.

---

## 3. Fuera de alcance — qué NO hacemos

> Esta sección existe para no perder tiempo. Si alguien quiere hacer algo de aquí, primero se
> consulta con el equipo y se justifica.

- ❌ **No** implementamos otras capas (enlace, red, aplicación). Cada una es de otro grupo.
- ❌ **No** reimplementamos toda la pila TCP/IP desde cero. Solo el parser de cabeceras + la
  reconstrucción de estados de transporte.
- ❌ **No** usamos el disector automático de scapy como "implementación de bajo nivel". Scapy se
  usa para **capturar** y **generar** tráfico, no para parsear los campos por nosotros.
- ❌ **No** construimos una topología de routers compleja (RIP, OSPF, VLANs…). La capa de
  transporte no lo necesita; basta con dos hosts y un punto de captura.
- ❌ **No** atacamos infraestructura de terceros. Todo ataque/escaneo es en **nuestras** VMs.
- ❌ **No** hacemos un IDS general ni metemos machine learning. Un tipo de anomalía bien hecho
  (escaneo de puertos) vale más que muchos a medias.
- ❌ **No** construimos una interfaz gráfica elaborada. CLI + reportes/gráficos es suficiente.
- ❌ **No** dejamos un único commit final. Commits frecuentes y descriptivos (lo exige la rúbrica).
- ❌ **No** hardcodeamos valores que deberían ser parámetros (umbrales, rutas, puertos).

---

## 4. Estructura del repositorio

```
g5-transporte/
├── README.md                 # instalación, uso y cómo reproducir
├── requirements.txt          # dependencias explícitas
├── docs/
│   ├── E1_Propuesta.pdf       # propuesta entregada
│   └── poster/                # póster A1 (E4)
├── captures/                 # .pcap de muestra (TCP, UDP, escaneos)
├── src/
│   ├── generator/            # genera tráfico TCP/UDP + escáner propio
│   ├── capture/              # sniffer -> .pcap
│   ├── parser/               # ⭐ parser de bajo nivel (struct) TCP/UDP
│   ├── states/               # reconstructor de estados TCP
│   ├── detector/             # detección de escaneo + cálculo de métricas
│   └── validation/           # comparación contra tshark/pyshark
├── tests/                    # pruebas unitarias del parser y el detector
├── scripts/                  # guion de pruebas reproducible (un comando)
└── results/                  # métricas y gráficos generados
```

**Convención de ramas:** una rama por componente (`feat/parser`, `feat/detector`,
`feat/capture`…), integración temprana a `main`. Nadie trabaja directo sobre `main`.

---

## 5. Reparto por rol

| Rol | Responsable | Carpetas | Tareas |
|-----|-------------|----------|--------|
| Infraestructura y captura | [Integrante 1] | `generator/`, `capture/`, `captures/` | Red/VMs o GNS3, generador de tráfico, capturas `.pcap`, gestión del repo |
| Implementación de bajo nivel | [Integrante 2] | `parser/`, `states/`, `validation/` | Parser TCP/UDP desde bytes, reconstructor de estados, validación vs tshark |
| Análisis y detección | [Integrante 3] | `detector/`, `results/`, `docs/poster/` | Detector de escaneo, métricas, gráficos, póster |

Compartido entre los tres: informe, README, presentación y commits.

---

## 6. Cronograma

| Fase | Tarea | Fechas |
|------|-------|--------|
| 1. Base | Estudio de RFC, montaje de red, generador de tráfico, repo inicial | 13–15 jun |
| 2. Núcleo | Parser de bajo nivel TCP/UDP, reconstructor de estados, validación vs tshark | 16–18 jun |
| 3. Detección | Detector de escaneo, métricas, `.pcap` definitivos, README y guion de pruebas | 19–21 jun |
| 4. Cierre | Póster A1, ensayo de la demostración en vivo | 22 jun |
| **E3** | **Presentación oral y demostración** | **23 jun** |

---

## 7. Definición de "terminado" (criterios de aceptación)

Un componente está listo solo cuando cumple esto:

- **Captura:** existen `.pcap` reproducibles con TCP normal, UDP y al menos un escaneo; la
  metodología está documentada en el README.
- **Parser:** decodifica todos los campos de cabecera TCP y UDP desde bytes; coincide ≥ 99 % con
  `tshark` en los campos clave; tiene pruebas unitarias.
- **Estados:** identifica correctamente handshake, cierre, retransmisiones y ventana en los flujos
  de muestra.
- **Detección:** detecta ≥ 3 tipos de escaneo; reporta precisión, recall, F1, FP/hora, latencia y
  cobertura, con verdad de referencia conocida.
- **Reproducibilidad:** `scripts/` permite reproducir los resultados con un comando, tal como lo
  hará el docente.

---

## 8. Tareas (checklist)

### Fase 1 — Base
- [ ] Crear el repositorio Git público e invitar a los integrantes
- [ ] `README.md`, `requirements.txt` y estructura de carpetas inicial
- [ ] Montar la red controlada (VMs aisladas o topología GNS3)
- [ ] Generador de tráfico TCP (cliente/servidor con sockets)
- [ ] Generador de tráfico UDP
- [ ] Escáner de puertos propio (scapy) y/o uso de nmap documentado

### Fase 2 — Núcleo
- [ ] Sniffer que guarda `.pcap`
- [ ] Parser de cabecera **UDP** (8 bytes) desde bytes crudos
- [ ] Parser de cabecera **TCP** (puertos, seq, ack, offset, flags, ventana, checksum, opciones)
- [ ] Reconstructor de estados TCP (handshake, ventana, retransmisión, cierre)
- [ ] Validación campo a campo contra `tshark`/`pyshark`
- [ ] Pruebas unitarias del parser

### Fase 3 — Detección
- [ ] Detector de escaneo (heurísticas + umbrales parametrizables)
- [ ] Cálculo de métricas (precisión, recall, F1, FP/hora, latencia, cobertura)
- [ ] Gráficos de resultados
- [ ] `.pcap` de muestra definitivos en `captures/`
- [ ] Guion de pruebas reproducible en `scripts/`
- [ ] README final con instalación, uso y reproducción

### Fase 4 — Cierre
- [ ] Póster A1 (motivación, marco teórico, arquitectura, metodología, resultados, conclusión, referencias)
- [ ] Ensayo de la demo en vivo (cronometrado: 15 teoría / 10 demo / 5 preguntas)

### Extensión (solo si sobra tiempo)
- [ ] Detección de inundación SYN (RFC 4987)
- [ ] Escaneo UDP y escaneos FIN/NULL/Xmas

---

## 9. Cómo trabajar con Claude Code

- Trabajen **una tarea acotada a la vez**, tomada del checklist de arriba. Eviten pedir "haz todo
  el proyecto"; pidan, por ejemplo, "implementa el parser de la cabecera TCP en `src/parser/`
  según la sección 2 de este documento".
- Pásenle este archivo como contexto al inicio de cada sesión para que respete el **alcance** y el
  **fuera de alcance**.
- Recordatorio para el agente y para nosotros: **el parser debe leer bytes crudos con `struct`**,
  no usar el disector automático de scapy.
- Todo código tomado de terceros se **cita** explícitamente en el archivo donde se use.
- Commits pequeños y frecuentes, con mensaje claro. Una rama por componente.

---

## 10. Referencia técnica rápida

**Cabecera TCP** (mínimo 20 bytes): puertos origen/destino · número de secuencia · número de
acuse (ACK) · offset de datos · flags (URG, ACK, PSH, RST, SYN, FIN) · ventana · checksum ·
puntero urgente · opciones.

**Cabecera UDP** (8 bytes): puerto origen · puerto destino · longitud · checksum.

**Comportamiento de los escaneos:**
- *SYN scan (half-open):* puerto abierto → `SYN-ACK`; cerrado → `RST`; no completa el handshake.
- *Connect scan:* completa el handshake de tres vías.
- *FIN/NULL/Xmas:* puerto cerrado → `RST`; abierto → descarta el segmento.
- *UDP scan:* sin respuesta → abierto|filtrado; ICMP "port unreachable" → cerrado.

**RFC de referencia:** RFC 9293 (TCP) · RFC 768 (UDP) · RFC 5681 (control de congestión TCP) ·
RFC 4987 (inundación SYN).

---

## 11. Entregables (recordatorio)

| Entregable | Qué es | Estado |
|------------|--------|--------|
| **E1** | Propuesta de solución (máx. 4 páginas) | ✅ Lista |
| **E2** | Repo Git público: código, README, dependencias, `.pcap`, guion de pruebas | ⏳ |
| **E3** | Presentación oral + demo en vivo (23 jun, 30 min) | ⏳ |
| **E4** | Póster científico A1 | ⏳ |

**Reglas que no se negocian:** repositorio con historial real de commits · sección "Asistencia de
IA" en el informe · ataques solo en red propia · código de terceros citado.

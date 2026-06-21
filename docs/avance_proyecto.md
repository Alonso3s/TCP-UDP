# Avance del proyecto - Grupo 5 Transporte

## Estado general

Segun el checklist de `PROYECTO_Grupo5_Transporte.md`, el proyecto cerro por completo la
**Fase 1**, la **Fase 2 - Nucleo** y la **Fase 3 - Deteccion** con evidencia real (no solo
pruebas unitarias sinteticas). Solo queda pendiente la **Fase 4 - Cierre**.

Avance global estimado: **95%**.

## Fase 1 - Base

Avance estimado: **100%**.

| Tarea | Estado |
|---|---|
| Crear repo Git publico e invitar integrantes | Cumplido |
| `README.md`, `requirements.txt` y estructura inicial | Cumplido |
| Montar red controlada | Cumplido (loopback local, ver `docs/network_setup.md`) |
| Generador de trafico TCP | Cumplido |
| Generador de trafico UDP | Cumplido |
| Escaner de puertos propio | Cumplido y verificado (ver bug de latencia abajo) |
| Capturas reales versionadas en `captures/` | Cumplido: `sesion_tcp_udp.pcap`, `escaneo_tcp_connect.pcap` |

## Fase 2 - Nucleo

Avance estimado: **100%**.

| Tarea | Estado |
|---|---|
| Sniffer que guarda `.pcap` | Cumplido |
| Parser UDP desde bytes crudos | Cumplido |
| Parser TCP desde bytes crudos | Cumplido |
| Reconstructor de estados TCP | Cumplido y verificado con captura real |
| Validacion contra `tshark` | Cumplido: 100% de coincidencia en ambas capturas reales |
| Pruebas unitarias del parser | Cumplido (23/23 pruebas) |

El reconstructor identifica desde capturas reales: inicio y final del handshake, cambios de
ventana, retransmisiones, FIN y RST. Verificado sobre `sesion_tcp_udp.pcap` con dos flujos TCP
completos (handshake + datos + cierre).

## Fase 3 - Deteccion

Avance estimado: **100%**.

| Tarea | Estado |
|---|---|
| Detector de escaneo | Cumplido y corregido (ver bugs abajo) |
| Metricas: precision, recall, F1, FP/hora, latencia y cobertura | Cumplido con datos reales: 100% en los tres |
| Graficos de resultados | Cumplido: SVG en `results/detections_by_source.svg` |
| `.pcap` de muestra definitivos | Cumplido |
| `results/truth_labels.json` con verdad de referencia real | Cumplido |
| 0 falsos positivos en trafico normal (`sesion_tcp_udp.pcap`) | Cumplido: 0 detecciones en 36 paquetes |
| Guion reproducible en `scripts/` | Cumplido: `demo.py`, `analyze_pcap.py`, `validate_captures.py` |
| README final | Cumplido |

## Fase 4 - Cierre

Avance estimado: **0%**.

| Tarea | Estado |
|---|---|
| Seccion "Asistencia de IA" (regla no negociable del enunciado) | Pendiente |
| Poster A1 | Pendiente |
| Ensayo de la demo en vivo | Pendiente |

## Bugs reales encontrados y corregidos

Al revisar el codigo con datos reales (no solo los tests unitarios sinteticos) se encontraron
y corrigieron tres bugs:

1. **Escaner de puertos lento en Windows** (`src/generator/port_scanner.py`): en esta red
   controlada, un puerto cerrado en loopback tarda ~2s en devolver el rechazo (el adaptador de
   loopback de Npcap intercepta el trafico). `connect_ex()` bloqueante no lo manejaba bien.
   Corregido con `select()` no bloqueante + escaneo en paralelo (`ThreadPoolExecutor`): el
   rango documentado (101 puertos) bajo de una proyeccion de ~50s a **4.1s reales**.

2. **Falso positivo direccional en el detector** (`src/detector/port_scan.py`): el detector
   marcaba tanto al atacante real como al servidor que respondia (porque las respuestas usan
   muchos puertos efimeros distintos). Corregido contando solo paquetes `SYN` sin `ACK`
   (intentos de conexion reales) para medir diversidad de puertos.

3. **Validacion contra tshark desalineada** (`src/validation/tshark_compare.py`,
   `src/capture/pcap_reader.py`): la comparacion emparejaba paquetes por posicion (`packets[i]`
   vs `rows[i]`); un solo paquete que tshark ve y el parser propio no (p. ej. IPv6, no
   soportado) desalineaba todo lo que seguia, bajando el match a 38% en una captura real.
   Corregido emparejando por `frame.number` (identificador estable del mismo paquete fisico
   para ambas herramientas). Resultado real: **100% de coincidencia** en ambas capturas.

Tambien se corrigio el filtro BPF de captura (`scripts/demo.py`): estaba muy abierto
(`"tcp or udp"`) y capturaba trafico de otros procesos en la maquina; ahora se restringe a
`"(tcp or udp) and host 127.0.0.1"`.

## Cumplido hasta ahora

- Parser UDP y TCP desde bytes crudos con `struct`, incluyendo flags y opciones.
- Lector de `.pcap` que soporta Ethernet (DLT_EN10MB) y loopback Windows/BSD (DLT_NULL), con
  numero de frame para emparejar contra tshark.
- Sniffer para guardar capturas TCP/UDP en `.pcap`, restringido a la red controlada.
- Generador de trafico TCP/UDP con sockets.
- Escaner TCP connect propio, paralelo y con manejo correcto de latencia de red.
- Reconstructor de estados TCP (handshake, ventana, retransmision, cierre).
- Validador contra `tshark` por numero de frame, sin falsos mismatches en cascada.
- Detector de escaneo de puertos sin falsos positivos direccionales, con metricas reales.
- `scripts/demo.py`: un solo comando que corre las 8 fases completas (sniffer, sesion TCP/UDP,
  reconstructor, validacion tshark, escaneo, deteccion) y genera ambas capturas definitivas.
- `scripts/validate_captures.py`: valida ambas capturas definitivas contra tshark y guarda el
  reporte en `results/tshark_validation.txt`.
- `results/`: `truth_labels.json` (verdad de referencia real), `detections.json/csv`,
  `detections_by_source.svg`, `metrics.json` (precision/recall/F1 = 100% con datos reales),
  `tshark_validation.txt`.
- 23/23 pruebas unitarias pasando.

## Pendiente principal

1. Escribir la seccion "Asistencia de IA" (regla no negociable del enunciado; no existe todavia
   en ningun documento).
2. Commitear los cambios de esta revision (bugs corregidos, `demo.py` integrado, capturas y
   `results/` reales).
3. Poster A1.
4. Ensayo cronometrado de la demo en vivo (15 teoria / 10 demo / 5 preguntas).

## Siguiente paso recomendado

El nucleo tecnico y la evidencia experimental ya estan completos y verificados con datos
reales. Lo que falta es exclusivamente Fase 4: documentar la asistencia de IA, cerrar el
poster y ensayar la demo cronometrada antes del 23 de junio.

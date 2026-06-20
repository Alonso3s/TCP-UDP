# Avance del proyecto - Grupo 5 Transporte

## Estado general

Segun el checklist de `PROYECTO_Grupo5_Transporte.md`, el proyecto ya cerro la base funcional
de la **Fase 1**, completo la implementacion principal de la **Fase 2 - Nucleo** y dejo lista
la implementacion base de la **Fase 3 - Deteccion**.

Avance global estimado: **70-78%**.

## Fase 1 - Base

Avance estimado: **95-100%**.

| Tarea | Estado |
|---|---|
| Crear repo Git publico e invitar integrantes | Cumplido |
| `README.md`, `requirements.txt` y estructura inicial | Cumplido |
| Montar red controlada | Cumplido (loopback local, ver `docs/network_setup.md`) |
| Generador de trafico TCP | Cumplido |
| Generador de trafico UDP | Cumplido |
| Escaner de puertos propio o nmap documentado | Cumplido inicial: `src/generator/port_scanner.py` |

Pendiente menor de Fase 1: generar y versionar capturas reales definitivas en `captures/`.

## Fase 2 - Nucleo

Avance estimado: **85-90%**.

| Tarea | Estado |
|---|---|
| Sniffer que guarda `.pcap` | Cumplido inicial |
| Parser UDP desde bytes crudos | Cumplido |
| Parser TCP desde bytes crudos | Cumplido |
| Reconstructor de estados TCP | Cumplido inicial |
| Validacion contra `tshark`/`pyshark` | Cumplido a nivel de modulo/CLI; falta correrlo con capturas definitivas |
| Pruebas unitarias del parser | Cumplido |

El reconstructor actual identifica eventos observables desde capturas: inicio y final del
handshake, cambios de ventana, retransmisiones basicas, FIN y RST.

## Fase 3 - Deteccion

Avance estimado: **70-80%**.

| Tarea | Estado |
|---|---|
| Detector de escaneo | Cumplido inicial |
| Metricas: precision, recall, F1, FP/hora, latencia y cobertura | Cumplido inicial |
| Graficos de resultados | Cumplido inicial: SVG generado por `scripts/analyze_pcap.py` |
| `.pcap` de muestra definitivos | Pendiente operativo |
| Guion reproducible en `scripts/` | Cumplido inicial: `scripts/analyze_pcap.py` |
| README final | Cumplido inicial |

## Fase 4 - Cierre

Avance estimado: **0%**.

| Tarea | Estado |
|---|---|
| Poster A1 | Pendiente |
| Ensayo de la demo en vivo | Pendiente |

## Cumplido hasta ahora

- Parser UDP desde bytes crudos con `struct`.
- Parser TCP desde bytes crudos con `struct`, incluyendo flags y opciones.
- Pruebas unitarias del parser.
- Lector de `.pcap` que extrae Ethernet/IPv4 y entrega cabeceras TCP/UDP al parser propio.
- Sniffer basico para guardar capturas TCP/UDP en `.pcap`.
- Generador de trafico TCP con sockets.
- Generador de trafico UDP con sockets.
- Escaner TCP connect propio con sockets.
- Reconstructor inicial de estados TCP.
- Validador contra `tshark` para comparar campos TCP/UDP.
- Detector de escaneo de puertos por diversidad de puertos destino en ventana temporal.
- Calculo de metricas: precision, recall, F1, falsos positivos por hora, latencia y cobertura.
- Generacion de reportes `json`, `csv` y grafico `svg` en `results/`.
- README actualizado con uso de captura, generadores, escaner y reconstructor.
- Red controlada documentada en `docs/network_setup.md`.
- Pruebas automatizadas: parser, lector pcap, generador, escaner y reconstructor.

## Pendiente principal

1. Generar capturas reales reproducibles en `captures/`:
   - `sesion_tcp_udp.pcap`
   - `escaneo_tcp_connect.pcap`
2. Correr `python -m src.validation.tshark_compare captures\sesion_tcp_udp.pcap` con `tshark` instalado.
3. Correr `python scripts/analyze_pcap.py captures\escaneo_tcp_connect.pcap --output-dir results`.
4. Crear `results/truth_labels.json` con la verdad de referencia del escaneo real y recalcular metricas.
5. Completar poster A1 y ensayo de demo.

## Siguiente paso recomendado

El siguiente paso en orden natural ya no es programar mas nucleo, sino producir evidencia:
capturas definitivas, salida de validacion contra `tshark`, archivos en `results/` y graficos para
el poster/demo.

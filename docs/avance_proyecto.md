# Avance del proyecto - Grupo 5 Transporte

## Estado general

Segun el checklist de `PROYECTO_Grupo5_Transporte.md`, el proyecto ya cerro la base funcional
de la **Fase 1** y avanzo en la **Fase 2 - Nucleo**.

Avance global estimado: **42-48%**.

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

Avance estimado: **55-65%**.

| Tarea | Estado |
|---|---|
| Sniffer que guarda `.pcap` | Cumplido inicial |
| Parser UDP desde bytes crudos | Cumplido |
| Parser TCP desde bytes crudos | Cumplido |
| Reconstructor de estados TCP | Cumplido inicial |
| Validacion contra `tshark`/`pyshark` | Pendiente |
| Pruebas unitarias del parser | Cumplido |

El reconstructor actual identifica eventos observables desde capturas: inicio y final del
handshake, cambios de ventana, retransmisiones basicas, FIN y RST.

## Fase 3 - Deteccion

Avance estimado: **5-10%**.

| Tarea | Estado |
|---|---|
| Detector de escaneo | Pendiente |
| Metricas: precision, recall, F1, FP/hora, latencia y cobertura | Pendiente |
| Graficos de resultados | Pendiente |
| `.pcap` de muestra definitivos | Pendiente |
| Guion reproducible en `scripts/` | Parcial: existe `scripts/demo.py`, falta integrar escaneo/detector/metricas |
| README final | Parcial |

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
- README actualizado con uso de captura, generadores, escaner y reconstructor.
- Red controlada documentada en `docs/network_setup.md`.
- Pruebas automatizadas: parser, lector pcap, generador, escaner y reconstructor.

## Pendiente principal

1. Generar capturas reales reproducibles en `captures/`:
   - `sesion_tcp_udp.pcap`
   - `escaneo_tcp_connect.pcap`
2. Implementar validacion campo a campo contra `tshark` o `pyshark`.
3. Implementar detector de escaneo de puertos sobre los paquetes parseados.
4. Calcular metricas de deteccion: precision, recall, F1, FP/hora, latencia y cobertura.
5. Generar salidas en `results/`, incluyendo tablas y graficos.
6. Integrar escaneo, detector y metricas en `scripts/demo.py` o en un nuevo guion reproducible.
7. Completar poster A1 y ensayo de demo.

## Siguiente paso recomendado

El siguiente paso en orden natural es implementar la **validacion contra tshark**, porque permite
defender la correctitud del parser de bajo nivel. Despues conviene implementar el **detector de
escaneo**, aprovechando el escaner propio y las capturas `escaneo_tcp_connect.pcap`.

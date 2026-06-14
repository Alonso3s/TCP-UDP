# Avance del proyecto - Grupo 5 Transporte

## Estado general

Según el checklist de `PROYECTO_Grupo5_Transporte.md`, el proyecto está entre la
**Fase 1 - Base** y el inicio de la **Fase 2 - Núcleo**.

Avance global estimado: **22%**.

## Fase 1 - Base

Avance estimado: **45-55%**.

| Tarea | Estado |
|---|---|
| Crear repo Git público e invitar integrantes | Cumplido |
| `README.md`, `requirements.txt` y estructura inicial | Cumplido parcialmente |
| Montar red controlada | Pendiente |
| Generador de tráfico TCP | Cumplido |
| Generador de tráfico UDP | Cumplido |
| Escáner de puertos propio o nmap documentado | Pendiente |

## Fase 2 - Núcleo

Avance estimado: **35-45%**.

| Tarea | Estado |
|---|---|
| Sniffer que guarda `.pcap` | Cumplido inicial |
| Parser UDP desde bytes crudos | Cumplido inicial |
| Parser TCP desde bytes crudos | Cumplido inicial |
| Reconstructor de estados TCP | Pendiente |
| Validación contra `tshark`/`pyshark` | Pendiente |
| Pruebas unitarias del parser | Cumplido inicial |

## Fase 3 - Detección

Avance estimado: **0-5%**.

| Tarea | Estado |
|---|---|
| Detector de escaneo | Pendiente |
| Métricas: precisión, recall, F1, FP/hora, latencia y cobertura | Pendiente |
| Gráficos de resultados | Pendiente |
| `.pcap` de muestra definitivos | Pendiente |
| Guion reproducible en `scripts/` | Pendiente |
| README final | Pendiente |

## Fase 4 - Cierre

Avance estimado: **0%**.

| Tarea | Estado |
|---|---|
| Póster A1 | Pendiente |
| Ensayo de la demo en vivo | Pendiente |

## Cumplido hasta ahora

- Parser UDP desde bytes crudos con `struct`.
- Parser TCP desde bytes crudos con `struct`, incluyendo flags y opciones.
- Pruebas unitarias iniciales del parser.
- Lector de `.pcap` que extrae Ethernet/IPv4 y entrega cabeceras TCP/UDP al parser propio.
- Sniffer básico para guardar capturas TCP/UDP en `.pcap`.
- Generador de tráfico TCP con sockets.
- Generador de tráfico UDP con sockets.
- README inicial con instalación, pruebas, captura y generación de tráfico.

## Pendiente principal

- Montar y documentar la red controlada.
- Generar capturas reales reproducibles en `captures/`.
- Implementar escáner de puertos propio o documentar uso de nmap.
- Implementar reconstructor de estados TCP.
- Validar el parser contra `tshark` o `pyshark`.
- Implementar detector de escaneo de puertos.
- Calcular métricas de detección.
- Generar gráficos/resultados.
- Crear guion reproducible en `scripts/`.
- Completar README final, póster y ensayo de demo.

## Siguiente paso recomendado

El siguiente paso más conveniente para subir en la rúbrica es implementar el
**reconstructor de estados TCP**, porque conecta directamente con el núcleo técnico del proyecto:
handshake, cierre, retransmisiones y evolución de ventana.

Como alternativa, si se quiere cerrar primero la Fase 1, el siguiente paso sería implementar un
**escáner de puertos propio básico** y documentar cómo generar capturas controladas.

# Proyecto Grupo 5 - Capa de Transporte

Sistema en Python para capturar, parsear y analizar tráfico TCP/UDP en una red controlada.

## Estado actual

- Parser UDP desde bytes crudos con `struct`.
- Parser TCP desde bytes crudos con `struct`, incluyendo flags y opciones.
- Lector de `.pcap` que extrae tramas Ethernet/IPv4 y entrega cabeceras TCP/UDP al parser propio.
- Sniffer CLI para guardar capturas TCP/UDP en `.pcap`.
- Generador TCP/UDP con sockets para producir trafico normal reproducible.
- Pruebas unitarias iniciales del parser.

## Instalación

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Pruebas

```powershell
python -m pytest
```

## Captura de trafico

El sniffer usa Scapy para capturar y guardar paquetes, no para interpretar los campos TCP/UDP:

```powershell
python -m src.capture.sniffer captures\muestra_tcp_udp.pcap --count 100 --timeout 30
```

## Generacion de trafico

Terminal 1, servidor TCP:

```powershell
python -m src.generator.traffic tcp-server --host 127.0.0.1 --port 5000 --count 1
```

Terminal 2, cliente TCP:

```powershell
python -m src.generator.traffic tcp-client --host 127.0.0.1 --port 5000 "hola tcp" "grupo 5"
```

Para UDP:

```powershell
python -m src.generator.traffic udp-server --host 127.0.0.1 --port 5001 --count 2
python -m src.generator.traffic udp-client --host 127.0.0.1 --port 5001 "hola udp" "grupo 5"
```

## Alcance

Este repositorio sigue la guía de `PROYECTO_Grupo5_Transporte.md`: scapy se puede usar para
capturar o generar tráfico, pero el parser de transporte debe interpretar las cabeceras desde
bytes crudos.

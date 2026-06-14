# Proyecto Grupo 5 - Capa de Transporte

Sistema en Python para capturar, parsear y analizar tráfico TCP/UDP en una red controlada.

**Curso:** IF5000 — Redes y Comunicación de Datos · UCR Sede del Sur  
**Integrantes:** Darnell Alonso Estrada Quesada, Rick Daniel Rodriguez  
**Demo E3:** 23 de junio de 2026

## Estado actual

- Parser UDP desde bytes crudos con `struct`.
- Parser TCP desde bytes crudos con `struct`, incluyendo flags y opciones.
- Lector de `.pcap` que extrae tramas Ethernet/IPv4 y entrega cabeceras TCP/UDP al parser propio.
- Sniffer CLI para guardar capturas TCP/UDP en `.pcap`.
- Generador TCP/UDP con sockets para producir tráfico normal reproducible.
- Red controlada local documentada en `docs/network_setup.md`.
- Pruebas unitarias iniciales del parser.

## Instalación

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> **Windows:** Se requiere [Npcap](https://npcap.com/) con modo WinPcap habilitado para que
> Scapy pueda capturar paquetes. Ejecutar el sniffer como administrador.

## Pruebas

```powershell
python -m pytest
```

## Red controlada

La red controlada usa la interfaz **loopback** (`127.0.0.1`) de la máquina de desarrollo.
Servidor, cliente y sniffer corren como procesos separados en la misma máquina.
Ver procedimiento completo en [`docs/network_setup.md`](docs/network_setup.md).

### Descubrir la interfaz loopback (Windows)

```powershell
python -c "from scapy.all import conf; conf.ifaces.show()"
```

Usar el nombre que aparece junto a `127.0.0.1` (p. ej. `\Device\NPF_Loopback`).

## Captura de tráfico

El sniffer usa Scapy para capturar y guardar paquetes, no para interpretar los campos TCP/UDP.
Iniciarlo **antes** de lanzar los generadores:

```powershell
# Windows
python -m src.capture.sniffer captures\sesion_tcp_udp.pcap ^
    --iface "\Device\NPF_Loopback" --count 300 --timeout 60

# Linux / macOS
python -m src.capture.sniffer captures/sesion_tcp_udp.pcap \
    --iface lo --count 300 --timeout 60
```

## Generación de tráfico

**TCP** (dos terminales):

```powershell
# Terminal 2 — servidor
python -m src.generator.traffic tcp-server --host 127.0.0.1 --port 5000 --count 1

# Terminal 3 — cliente
python -m src.generator.traffic tcp-client --host 127.0.0.1 --port 5000 "hola tcp" "grupo 5"
```

**UDP** (dos terminales):

```powershell
# Terminal 2 — servidor
python -m src.generator.traffic udp-server --host 127.0.0.1 --port 5001 --count 2

# Terminal 3 — cliente
python -m src.generator.traffic udp-client --host 127.0.0.1 --port 5001 "hola udp" "grupo 5"
```

## Verificar una captura

```powershell
python -c "
from src.capture.pcap_reader import iter_pcap_transport_headers
for pkt in iter_pcap_transport_headers('captures/sesion_tcp_udp.pcap'):
    print(pkt.protocol, pkt.source_ip, '->', pkt.destination_ip)
"
```

## Demo en un comando

Ejecutar sniffer + generadores TCP/UDP + parser en secuencia automática (en CMD como administrador):

```powershell
cd "C:Donte este guardado el proyecto\TCP-UDP"
python scripts/demo.py
```

Requiere Npcap instalado en Windows y ejecutar como administrador. El script detecta la
interfaz loopback automáticamente y guarda la captura en `captures/demo_captura.pcap`.

## Alcance

Este repositorio sigue la guía de `PROYECTO_Grupo5_Transporte.md`: Scapy se usa para
capturar y generar tráfico, pero el parser de transporte interpreta las cabeceras desde
bytes crudos con `struct`, sin delegar en el disector automático de Scapy.

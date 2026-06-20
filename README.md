# Proyecto Grupo 5 - Capa de Transporte

Sistema en Python para capturar, parsear y analizar trafico TCP/UDP en una red controlada.

**Curso:** IF5000 - Redes y Comunicacion de Datos, UCR Sede del Sur  
**Integrantes:** Darnell Alonso Estrada Quesada, Rick Daniel Rodriguez  
**Demo E3:** 23 de junio de 2026

## Estado actual

- Parser UDP desde bytes crudos con `struct`.
- Parser TCP desde bytes crudos con `struct`, incluyendo flags y opciones.
- Lector de `.pcap` que extrae tramas Ethernet/IPv4 y entrega cabeceras TCP/UDP al parser propio.
- Sniffer CLI para guardar capturas TCP/UDP en `.pcap`.
- Generador TCP/UDP con sockets para producir trafico normal reproducible.
- Escaner TCP connect propio para generar trafico de escaneo controlado.
- Reconstructor inicial de estados TCP: handshake, ventana, retransmision y cierre.
- Red controlada local documentada en `docs/network_setup.md`.
- Pruebas unitarias iniciales del parser, generador, lector, escaner y reconstructor.

## Instalacion

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Windows: se requiere Npcap con modo WinPcap habilitado para que Scapy pueda capturar paquetes.
> Ejecutar el sniffer como administrador.

## Pruebas

```powershell
python -m pytest
```

## Red controlada

La red controlada usa la interfaz loopback (`127.0.0.1`) de la maquina de desarrollo.
Servidor, cliente, escaner y sniffer corren como procesos separados en la misma maquina.
Ver procedimiento completo en `docs/network_setup.md`.

### Descubrir la interfaz loopback en Windows

```powershell
python -c "from scapy.all import conf; conf.ifaces.show()"
```

Usar el nombre que aparece junto a `127.0.0.1`, por ejemplo `\Device\NPF_Loopback`.

## Captura de trafico

El sniffer usa Scapy para capturar y guardar paquetes, no para interpretar los campos TCP/UDP.
Iniciarlo antes de lanzar los generadores o el escaner:

```powershell
# Windows
python -m src.capture.sniffer captures\sesion_tcp_udp.pcap ^
    --iface "\Device\NPF_Loopback" --count 300 --timeout 60

# Linux / macOS
python -m src.capture.sniffer captures/sesion_tcp_udp.pcap \
    --iface lo --count 300 --timeout 60
```

## Generacion de trafico

TCP:

```powershell
# Terminal 2 - servidor
python -m src.generator.traffic tcp-server --host 127.0.0.1 --port 5000 --count 1

# Terminal 3 - cliente
python -m src.generator.traffic tcp-client --host 127.0.0.1 --port 5000 "hola tcp" "grupo 5"
```

UDP:

```powershell
# Terminal 2 - servidor
python -m src.generator.traffic udp-server --host 127.0.0.1 --port 5001 --count 2

# Terminal 3 - cliente
python -m src.generator.traffic udp-client --host 127.0.0.1 --port 5001 "hola udp" "grupo 5"
```

## Escaneo de puertos controlado

El proyecto incluye un escaner TCP connect propio con sockets. Ejecutarlo solo contra la red
controlada del proyecto:

```powershell
python -m src.generator.port_scanner --host 127.0.0.1 --ports 5000-5100 --timeout 0.5
```

Para capturar el escaneo, iniciar primero el sniffer y guardar un `.pcap` separado:

```powershell
python -m src.capture.sniffer captures\escaneo_tcp_connect.pcap ^
    --iface "\Device\NPF_Loopback" --count 500 --timeout 60
python -m src.generator.port_scanner --host 127.0.0.1 --ports 5000-5100
```

## Verificar una captura

```powershell
python -c "
from src.capture import iter_pcap_transport_headers
for pkt in iter_pcap_transport_headers('captures/sesion_tcp_udp.pcap'):
    print(pkt.protocol, pkt.source_ip, '->', pkt.destination_ip)
"
```

## Reconstruir estados TCP

```powershell
python -c "
from src.capture import iter_pcap_transport_headers
from src.states import reconstruct_tcp_flows
flows = reconstruct_tcp_flows(iter_pcap_transport_headers('captures/demo_captura.pcap'))
for flow in flows.values():
    print(flow.key, flow.handshake_completed, flow.closed, flow.retransmissions, flow.window_updates)
"
```

## Demo en un comando

Ejecutar sniffer, generadores TCP/UDP y parser en secuencia automatica:

```powershell
python scripts/demo.py
```

Requiere Npcap instalado en Windows y ejecutar como administrador. El script detecta la
interfaz loopback automaticamente y guarda la captura en `captures/demo_captura.pcap`.

## Alcance

Este repositorio sigue la guia de `PROYECTO_Grupo5_Transporte.md`: Scapy se usa para capturar y
generar trafico, pero el parser de transporte interpreta las cabeceras desde bytes crudos con
`struct`, sin delegar en el disector automatico de Scapy.

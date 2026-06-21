# Proyecto Grupo 5 - Capa de Transporte

Sistema en Python para capturar, parsear y analizar trafico TCP/UDP en una red controlada.

**Curso:** IF5000 - Redes y Comunicacion de Datos, UCR Sede del Sur  
**Integrantes:** Darnell Alonso Estrada Quesada, Rick Daniel Rodriguez  
**Demo E3:** 23 de junio de 2026

## Estado actual

- Parser TCP/UDP propio desde bytes crudos con `struct` (sin usar el disector de Scapy).
- Lector de `.pcap` (Ethernet y loopback Windows/BSD) + sniffer CLI para capturar trafico real.
- Generador de trafico TCP/UDP y escaner de puertos propio, ambos con sockets.
- Reconstructor de estados TCP, detector de escaneo de puertos con metricas, y validacion
  campo a campo contra `tshark`.
- `scripts/demo.py` corre todo el flujo (captura, sesion, escaneo, deteccion, validacion) con
  un solo comando.
- 23 pruebas unitarias.

## Arquitectura del proyecto

Cada carpeta de `src/` resuelve una parte especifica de lo que pide el enunciado. Esta seccion
explica que hace cada una y por que existe.

### `src/parser/` - Parser de bajo nivel TCP/UDP

Decodifica las cabeceras TCP (20+ bytes, incluye opciones como MSS) y UDP (8 bytes)
directamente desde bytes crudos con `struct`: puertos, numero de secuencia/ACK, flags, ventana,
checksum, etc. Es el nucleo del proyecto - el enunciado exige una implementacion propia a bajo
nivel, no delegar el parseo en una libreria.

### `src/capture/` - Captura y lectura de `.pcap`

- `pcap_reader.py`: lee un archivo `.pcap` byte por byte, extrae los paquetes IPv4 (soporta
  tramas Ethernet estandar y el formato de loopback de Windows/BSD) y entrega cada segmento
  TCP/UDP al parser propio. Sin esto, una captura guardada en disco no se puede convertir en
  algo que el parser entienda.
- `sniffer.py`: usa Scapy **solo** para escuchar la interfaz de red y guardar los paquetes en un
  `.pcap` - no interpreta los campos, eso lo hace el parser propio despues. Hace falta para
  generar la evidencia de trafico real que exige el enunciado.

### `src/generator/` - Trafico controlado y reproducible

- `traffic.py`: cliente/servidor TCP y UDP con sockets puros. Genera una sesion TCP completa
  (handshake, datos, cierre) y datagramas UDP, de forma repetible. Hace falta para tener
  trafico controlado que se pueda capturar y analizar, en vez de depender de trafico externo
  impredecible.
- `port_scanner.py`: escaner TCP connect propio (no nmap), corre los puertos en paralelo con
  `ThreadPoolExecutor` para no tardar minutos por la latencia de rechazo en loopback. Genera la
  anomalia (escaneo de puertos) que el resto del sistema debe detectar.

### `src/states/` - Reconstructor de estados TCP

A partir de paquetes ya parseados, reconstruye el comportamiento observable de cada conexion
TCP: inicio y fin del handshake de tres vias, cambios de ventana, retransmisiones (mismo
origen + SEQ + longitud + flags ya visto) y cierre por FIN o RST. Hace falta porque el
enunciado pide demostrar explicitamente el establecimiento, mantenimiento y cierre de sesiones
TCP, no solo capturarlas.

### `src/detector/` - Deteccion de escaneo de puertos

Detecta un escaneo cuando un mismo origen contacta muchos puertos destino distintos de un mismo
objetivo en una ventana de tiempo corta. Solo cuenta intentos de conexion reales (`SYN` sin
`ACK`) para no confundir las respuestas normales de un servidor con un escaneo. Tambien calcula
las metricas de la rubrica: precision, recall, F1, falsos positivos por hora, latencia de
deteccion y cobertura, comparando contra una verdad de referencia conocida.

### `src/validation/` - Validacion contra tshark

Compara, campo por campo, lo que extrae el parser propio contra lo que reporta `tshark` sobre
el mismo `.pcap` (IPs, puertos, secuencia, ACK, flags, ventana, checksums). Empareja los
paquetes por numero de frame (no por posicion), para que un solo paquete no soportado (p. ej.
IPv6) no desalinee el resto de la comparacion. Hace falta porque el enunciado exige validar el
parser propio contra una herramienta de referencia (Wireshark/tshark).

### `scripts/` - Automatizacion

- `demo.py`: corre todo el sistema de punta a punta con un solo comando, pensado para la
  presentacion en vivo.
- `analyze_pcap.py`: toma una captura de escaneo, corre el detector y genera los reportes
  (`results/detections.json/csv`, grafico SVG, y metricas si hay verdad de referencia).
- `validate_captures.py`: corre la validacion contra tshark sobre las dos capturas definitivas
  y guarda el reporte en `results/tshark_validation.txt`.

### Carpetas de datos

- `captures/`: capturas `.pcap` versionadas en el repo (el enunciado exige capturas reales, no
  solo codigo).
- `results/`: metricas, reportes y graficos generados por `scripts/analyze_pcap.py` y
  `scripts/validate_captures.py`.
- `tests/`: pruebas unitarias de cada modulo de `src/`.
- `docs/`: guia interna del proyecto, enunciado original y procedimiento detallado de la red
  controlada (`docs/network_setup.md`).

## Instalacion

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Windows: se requiere [Npcap](https://npcap.com/) con modo WinPcap habilitado para que Scapy
> pueda capturar paquetes. Ejecutar el sniffer (y `scripts/demo.py`) como administrador.
> Para la validacion contra tshark se requiere Wireshark instalado; si `tshark` no esta en el
> `PATH`, usar la ruta completa: `C:\Program Files\Wireshark\tshark.exe`.

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

## Demo en un solo comando

Corre las 8 fases completas (sniffer de la sesion, trafico TCP, trafico UDP, parser +
reconstructor de estados, validacion contra tshark, sniffer del escaneo, escaneo de puertos y
deteccion de la anomalia) en una sola corrida:

```powershell
python scripts/demo.py
```

Requiere Npcap instalado en Windows y ejecutar **como administrador**. El script detecta la
interfaz loopback automaticamente y genera las dos capturas definitivas:

- `captures/sesion_tcp_udp.pcap` - trafico normal (sesion TCP completa + datagramas UDP).
- `captures/escaneo_tcp_connect.pcap` - la anomalia (escaneo de puertos).

## Ejecucion manual, paso a paso

Esta es la secuencia completa que `scripts/demo.py` automatiza, para quien prefiera correr cada
pieza por separado (para entender el flujo o depurar algo puntual). Requiere varias terminales
abiertas en la raiz del proyecto; en Windows, el sniffer necesita una terminal **como
administrador**.

### 1. Capturar la sesion TCP/UDP normal

**Terminal 1 - sniffer** (iniciarlo antes que los demas procesos):

```powershell
python -m src.capture.sniffer captures\sesion_tcp_udp.pcap ^
    --iface "\Device\NPF_Loopback" --count 500 --timeout 12 ^
    --filter "(tcp or udp) and host 127.0.0.1"
```

**Terminal 2 - servidor TCP, luego servidor UDP:**

```powershell
python -m src.generator.traffic tcp-server --host 127.0.0.1 --port 5000 --count 1
python -m src.generator.traffic udp-server --host 127.0.0.1 --port 5001 --count 3
```

**Terminal 3 - cliente TCP, luego cliente UDP:**

```powershell
python -m src.generator.traffic tcp-client --host 127.0.0.1 --port 5000 "hola tcp" "grupo 5"
python -m src.generator.traffic udp-client --host 127.0.0.1 --port 5001 "hola udp" "grupo 5"
```

El sniffer termina solo al alcanzar `--count` o `--timeout` y escribe el `.pcap`.

### 2. Ver los paquetes parseados

```powershell
python -c "
from src.capture import iter_pcap_transport_headers
for pkt in iter_pcap_transport_headers('captures/sesion_tcp_udp.pcap'):
    print(pkt.protocol, pkt.source_ip, '->', pkt.destination_ip)
"
```

### 3. Reconstruir los estados TCP

```powershell
python -c "
from src.capture import iter_pcap_transport_headers
from src.states import reconstruct_tcp_flows
packets = list(iter_pcap_transport_headers('captures/sesion_tcp_udp.pcap'))
for flow in reconstruct_tcp_flows(packets).values():
    print(flow.key, 'handshake=', flow.handshake_completed, 'cerrado=', flow.closed,
          'retransmisiones=', flow.retransmissions, 'cambios_ventana=', flow.window_updates)
"
```

### 4. Validar el parser propio contra tshark

```powershell
python -m src.validation.tshark_compare captures\sesion_tcp_udp.pcap ^
    --tshark "C:\Program Files\Wireshark\tshark.exe"
```

Compara campo a campo: IP origen/destino, protocolo, puertos, secuencia, ACK, longitud de
cabecera, flags, ventana, longitud UDP y checksums.

### 5. Capturar y correr el escaneo de puertos

**Terminal 1 - sniffer para el escaneo:**

```powershell
python -m src.capture.sniffer captures\escaneo_tcp_connect.pcap ^
    --iface "\Device\NPF_Loopback" --count 500 --timeout 10 ^
    --filter "(tcp or udp) and host 127.0.0.1"
```

**Terminal 2 - escaner propio:**

```powershell
python -m src.generator.port_scanner --host 127.0.0.1 --ports 6000-6050
```

### 6. Detectar el escaneo y generar resultados

```powershell
python scripts/analyze_pcap.py captures\escaneo_tcp_connect.pcap ^
    --output-dir results --window 5 --min-ports 10
```

Genera `results/detections.json`, `results/detections.csv` y `results/detections_by_source.svg`.

Con verdad de referencia (usar los timestamps reales del `.pcap`, no segundos relativos como
`0.0`/`60.0`) se calculan ademas precision, recall, F1, FP/hora, latencia y cobertura:

```json
{
  "labels": [
    {
      "source_ip": "127.0.0.1",
      "target_ip": "127.0.0.1",
      "protocol": "TCP",
      "start_time": 1782002082.324981,
      "end_time": 1782002084.363494
    }
  ]
}
```

```powershell
python scripts/analyze_pcap.py captures\escaneo_tcp_connect.pcap ^
    --truth results\truth_labels.json
```

### 7. Validar ambas capturas definitivas de una sola vez

```powershell
python scripts/validate_captures.py
```

Corre la validacion contra tshark sobre `sesion_tcp_udp.pcap` y `escaneo_tcp_connect.pcap`, y
guarda el reporte en `results/tshark_validation.txt`.

## Alcance

Este repositorio sigue la guia de `docs/PROYECTO_Grupo5_Transporte.md`: Scapy se usa para
capturar y generar trafico, pero el parser de transporte interpreta las cabeceras desde bytes
crudos con `struct`, sin delegar en el disector automatico de Scapy.

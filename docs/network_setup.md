# Red controlada — Topología local (localhost)

## Descripción

La red controlada del proyecto usa la interfaz **loopback** (`127.0.0.1`) de la máquina de
desarrollo. Los distintos procesos (servidor, cliente, sniffer) corren en terminales separadas
sobre la misma máquina, comunicándose a través del adaptador de bucle invertido del sistema
operativo.

Esta topología cubre los tres componentes requeridos por el proyecto:

- Generar sesiones TCP completas y datagramas UDP reproducibles.
- Capturar el tráfico con Scapy a nivel de bytes crudos y guardar `.pcap`.
- Reproducir escaneos de puertos (`nmap 127.0.0.1` o escáner propio) sin afectar infraestructura ajena.

---

## Diagrama

```
┌──────────────────────────────────────────────────────────────┐
│                     Máquina de desarrollo                    │
│                                                              │
│   ┌───────────────────┐  loopback   ┌──────────────────────┐ │
│   │  Servidor         │◄────────────►│  Cliente / Escáner  │ │
│   │  TCP  :5000       │  127.0.0.1  │  (generador o nmap) │ │
│   │  UDP  :5001       │             └──────────────────────┘ │
│   └───────────────────┘                                      │
│                                                              │
│   ┌──────────────────────────────────────────────────────┐   │
│   │  Sniffer (Scapy)                                     │   │
│   │  captura en interfaz loopback → captures/*.pcap      │   │
│   └──────────────────────────────────────────────────────┘   │
│                                                              │
│   Interfaz loopback:                                         │
│     Linux / macOS : lo                                       │
│     Windows+Npcap : \Device\NPF_Loopback                     │
└──────────────────────────────────────────────────────────────┘
```

---

## Requisitos del entorno

| Herramienta | Versión mín. | Propósito |
|-------------|-------------|-----------|
| Python | 3.10 | Runtime del proyecto |
| scapy | 2.5 | Captura + lectura de `.pcap` |
| pytest | 7.0 | Pruebas unitarias |
| nmap | 7.x | Escaneos de puertos (Fase 3) |
| **Npcap** *(solo Windows)* | 1.70 | Driver de captura en Windows |

> **Windows:** Instalar [Npcap](https://npcap.com/) con la opción
> *"WinPcap API-compatible mode"* habilitada. Sin Npcap, Scapy no puede
> capturar paquetes, incluyendo el loopback. Requiere ejecutar el sniffer
> con permisos de administrador.

---

## Descubrir el nombre de la interfaz loopback

### Windows

```powershell
python -c "from scapy.all import conf; conf.ifaces.show()"
```

Buscar la fila con dirección `127.0.0.1`. El nombre a pasar con `--iface` suele ser
`\Device\NPF_Loopback`.

### Linux / macOS

```bash
python -c "from scapy.all import get_if_list; print(get_if_list())"
# La interfaz loopback es 'lo'
```

---

## Procedimiento de captura reproducible

Abrir **tres terminales** en la raíz del proyecto con el entorno virtual activo
(`.venv\Scripts\Activate.ps1` en Windows o `source .venv/bin/activate` en Linux).

### Paso 1 — Iniciar el sniffer (Terminal 1)

```powershell
# Windows (ajustar --iface si el nombre difiere)
python -m src.capture.sniffer captures\sesion_tcp_udp.pcap ^
    --iface "\Device\NPF_Loopback" --count 300 --timeout 60
```

```bash
# Linux / macOS
python -m src.capture.sniffer captures/sesion_tcp_udp.pcap \
    --iface lo --count 300 --timeout 60
```

### Paso 2 — Servidor TCP (Terminal 2)

```powershell
python -m src.generator.traffic tcp-server --host 127.0.0.1 --port 5000 --count 1
```

### Paso 3 — Cliente TCP (Terminal 3)

```powershell
python -m src.generator.traffic tcp-client --host 127.0.0.1 --port 5000 "hola tcp" "grupo 5"
```

### Paso 4 — Servidor UDP (Terminal 2, tras terminar el TCP)

```powershell
python -m src.generator.traffic udp-server --host 127.0.0.1 --port 5001 --count 2
```

### Paso 5 — Cliente UDP (Terminal 3)

```powershell
python -m src.generator.traffic udp-client --host 127.0.0.1 --port 5001 "hola udp" "grupo 5"
```

El sniffer termina automáticamente al alcanzar el `--count` o el `--timeout` y escribe el `.pcap`.

---

## Verificar la captura

```powershell
python -c "
from src.capture.pcap_reader import iter_pcap_transport_headers
for pkt in iter_pcap_transport_headers('captures/sesion_tcp_udp.pcap'):
    proto = pkt.protocol
    src   = pkt.source_ip
    dst   = pkt.destination_ip
    hdr   = pkt.header
    print(f'{proto}  {src} -> {dst}  {hdr}')
"
```

---

## Puertos utilizados

| Puerto | Protocolo | Uso |
|--------|-----------|-----|
| 5000 | TCP | Servidor de eco TCP (generador) |
| 5001 | UDP | Servidor de eco UDP (generador) |
| 5002–5100 | TCP/UDP | Rango reservado para escaneos (Fase 3) |

---

## Escaneo de puertos propio

El proyecto incluye un escáner TCP connect propio basado en sockets. Este escáner genera intentos
de conexión TCP contra un rango de puertos de la red controlada, suficiente para producir tráfico
de escaneo reproducible sin tocar infraestructura externa.

```powershell
python -m src.generator.port_scanner --host 127.0.0.1 --ports 5000-5100 --timeout 0.5
```

Para generar una captura específica del escaneo:

```powershell
python -m src.capture.sniffer captures\escaneo_tcp_connect.pcap ^
    --iface "\Device\NPF_Loopback" --count 500 --timeout 60
python -m src.generator.port_scanner --host 127.0.0.1 --ports 5000-5100
```

Opcionalmente, si el entorno tiene `nmap`, se puede comparar contra:

```powershell
nmap 127.0.0.1 -sT -p 5000-5100
```

---

## Metodología de captura

1. El sniffer se inicia **antes** que cualquier otro proceso para no perder paquetes.
2. El filtro BPF `tcp or udp` descarta tráfico de fondo irrelevante.
3. El generador crea sesiones TCP completas (SYN → SYN-ACK → ACK → datos → FIN) y datagramas UDP.
4. El sniffer escribe el `.pcap` al finalizar; este archivo es la entrada del parser, el
   reconstructor de estados y el validador.
5. Para los escaneos (Fase 3), se lanza `nmap 127.0.0.1 -sS -p 5000-5100` (o el escáner propio)
   mientras el sniffer está activo, y se guarda en un `.pcap` separado.

---

## Limitaciones conocidas

- La captura en loopback en Windows puede requerir privilegios de administrador.
- En algunos sistemas Windows, Scapy no ve el loopback sin Npcap ≥ 1.70.
- El filtro BPF `tcp or udp` no captura paquetes ICMP (irrelevante para este proyecto).

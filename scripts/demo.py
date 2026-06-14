#!/usr/bin/env python3
"""
Demo del sistema — Grupo 5 Capa de Transporte
IF5000 — Redes y Comunicación de Datos, UCR Sede del Sur

Uso (desde la raíz del proyecto con el entorno virtual activo):

    python scripts/demo.py

Requisitos en Windows: Npcap instalado + ejecutar como administrador.
"""
from __future__ import annotations

import platform
import subprocess
import sys
import time
from pathlib import Path

# Forzar UTF-8 en stdout para que los caracteres especiales funcionen en Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))   # permite "import src.*" desde scripts/

CAPTURES = ROOT / "captures"
CAPTURES.mkdir(exist_ok=True)

PYTHON = sys.executable
PCAP_FILE = CAPTURES / "demo_captura.pcap"

TCP_PORT = 5000
UDP_PORT = 5001
SNIFFER_TIMEOUT = 15   # segundos; los generadores terminan antes


def _detect_loopback() -> str:
    """Detecta el nombre de la interfaz loopback según el SO."""
    if platform.system() != "Windows":
        return "lo"
    try:
        from scapy.all import conf  # type: ignore[import-untyped]
        for iface in conf.ifaces.values():
            ip = getattr(iface, "ip", None)
            if ip == "127.0.0.1":
                return iface.name
    except Exception:
        pass
    return r"\Device\NPF_Loopback"


def _section(step: str, title: str) -> None:
    print(f"\n{'─' * 62}")
    print(f"  {step}  {title}")
    print("─" * 62)


def _run(*args: str) -> None:
    subprocess.run([PYTHON, *args], cwd=ROOT, check=True)


def _popen(*args: str) -> subprocess.Popen:
    return subprocess.Popen([PYTHON, *args], cwd=ROOT)


def main() -> None:
    iface = _detect_loopback()

    print("\n" + "=" * 62)
    print("  DEMO — Grupo 5 | Capa de Transporte | IF5000 UCR")
    print("  Integrantes: Darnell Estrada · Rick Rodriguez · Jorge Murillo")
    print("=" * 62)

    # ── 1. Sniffer ──────────────────────────────────────────────
    _section("[1/4]", "Iniciando sniffer en interfaz loopback")
    print(f"  Interfaz : {iface}")
    print(f"  Salida   : captures/demo_captura.pcap")
    sniffer = _popen(
        "-m", "src.capture.sniffer",
        str(PCAP_FILE),
        "--iface", iface,
        "--count", "500",
        "--timeout", str(SNIFFER_TIMEOUT),
        "--filter", "tcp or udp",
    )
    time.sleep(2)  # dar tiempo al sniffer para abrir la interfaz
    if sniffer.poll() is not None:
        print("\n  [ERROR] El sniffer terminó de inmediato.")
        print("  Verifique que Npcap esté instalado y que corre como administrador.")
        sys.exit(1)
    print(f"  Sniffer activo (PID {sniffer.pid}).")

    # ── 2. Sesión TCP ────────────────────────────────────────────
    _section("[2/4]", f"Sesión TCP completa  →  127.0.0.1:{TCP_PORT}")
    tcp_server = _popen(
        "-m", "src.generator.traffic",
        "tcp-server",
        "--host", "127.0.0.1",
        "--port", str(TCP_PORT),
        "--count", "1",
    )
    time.sleep(1.5)
    _run(
        "-m", "src.generator.traffic",
        "tcp-client",
        "--host", "127.0.0.1",
        "--port", str(TCP_PORT),
        "hola tcp", "grupo 5", "IF5000 UCR",
    )
    tcp_server.wait(timeout=5)
    print("  Completada (SYN → SYN-ACK → ACK → datos → FIN-ACK).")

    # ── 3. Datagramas UDP ────────────────────────────────────────
    _section("[3/4]", f"Datagramas UDP  →  127.0.0.1:{UDP_PORT}")
    udp_server = _popen(
        "-m", "src.generator.traffic",
        "udp-server",
        "--host", "127.0.0.1",
        "--port", str(UDP_PORT),
        "--count", "3",
    )
    time.sleep(1.5)
    _run(
        "-m", "src.generator.traffic",
        "udp-client",
        "--host", "127.0.0.1",
        "--port", str(UDP_PORT),
        "hola udp", "grupo 5", "IF5000 UCR",
    )
    udp_server.wait(timeout=5)
    print("  3 datagramas enviados y recibidos.")

    # ── 4. Esperar sniffer y parsear ─────────────────────────────
    _section("[4/4]", "Analizando captura")
    remaining = SNIFFER_TIMEOUT - 7  # ~7 s consumidos por generadores + sleeps
    print(f"  Esperando fin del sniffer ({max(remaining, 1)} s)...")
    try:
        sniffer.wait(timeout=SNIFFER_TIMEOUT + 5)
    except subprocess.TimeoutExpired:
        sniffer.kill()
        sniffer.wait()

    if not PCAP_FILE.exists():
        print(f"\n  [ERROR] No se generó {PCAP_FILE.name}")
        print("  El sniffer necesita Npcap y permisos de administrador.")
        sys.exit(1)

    from src.capture.pcap_reader import iter_pcap_transport_headers  # noqa: PLC0415

    packets = list(iter_pcap_transport_headers(PCAP_FILE))
    tcp_pkts = [p for p in packets if p.protocol == "TCP"]
    udp_pkts = [p for p in packets if p.protocol == "UDP"]

    print(f"\n  Paquetes capturados : {len(packets)}")
    print(f"    TCP               : {len(tcp_pkts)}")
    print(f"    UDP               : {len(udp_pkts)}")

    # Tabla de cabeceras
    print()
    col = f"  {'Proto':<5}  {'Origen IP:Puerto':<25}  {'Destino IP:Puerto':<25}  Flags / Info"
    print(col)
    print("  " + "─" * (len(col) - 2))
    for pkt in packets[:25]:
        hdr = pkt.header
        src = f"{pkt.source_ip}:{hdr.source_port}"
        dst = f"{pkt.destination_ip}:{hdr.destination_port}"
        if pkt.protocol == "TCP":
            active = [f for f, on in hdr.flags.items() if on]
            info = " ".join(active) if active else "—"
        else:
            info = f"len={hdr.length}"
        print(f"  {pkt.protocol:<5}  {src:<25}  {dst:<25}  {info}")
    if len(packets) > 25:
        print(f"  ... y {len(packets) - 25} paquetes más (ver {PCAP_FILE.name})")

    # Resumen final
    print("\n" + "=" * 62)
    print("  RESUMEN")
    print(f"    Captura  : {PCAP_FILE.name}")
    print(f"    Paquetes : {len(packets)}  (TCP {len(tcp_pkts)}, UDP {len(udp_pkts)})")
    print()
    print("  PRÓXIMAS FASES:")
    print("    [ ] src/states/     — estados TCP (handshake, ventana, retransmisión)")
    print("    [ ] src/detector/   — detección de port scan + métricas")
    print("    [ ] src/validation/ — comparación campo a campo vs tshark")
    print("=" * 62 + "\n")


if __name__ == "__main__":
    main()

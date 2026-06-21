#!/usr/bin/env python3
"""
Demo del sistema — Grupo 5 Capa de Transporte
IF5000 — Redes y Comunicación de Datos, UCR Sede del Sur

Uso (desde la raíz del proyecto, en una terminal con permisos de administrador):

    python scripts/demo.py

Requisitos en Windows: Npcap instalado + ejecutar como administrador.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Forzar UTF-8 en stdout para que los caracteres especiales funcionen en Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))   # permite "import src.*" desde scripts/

from src.capture import iter_pcap_transport_headers  # noqa: E402
from src.detector import detect_port_scans  # noqa: E402
from src.states import reconstruct_tcp_flows  # noqa: E402
from src.validation import validate_pcap_with_tshark  # noqa: E402

CAPTURES = ROOT / "captures"
CAPTURES.mkdir(exist_ok=True)

PYTHON = sys.executable
SESSION_PCAP = CAPTURES / "sesion_tcp_udp.pcap"
SCAN_PCAP = CAPTURES / "escaneo_tcp_connect.pcap"

TCP_PORT = 5000
UDP_PORT = 5001
SCAN_PORTS = "6000-6050"
SESSION_SNIFFER_TIMEOUT = 12   # segundos; TCP+UDP terminan antes
SCAN_SNIFFER_TIMEOUT = 10      # segundos; el escaneo termina antes

# Wireshark no siempre agrega tshark.exe al PATH en Windows.
TSHARK_CANDIDATES = ("tshark", r"C:\Program Files\Wireshark\tshark.exe")


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


def _find_tshark() -> str | None:
    for candidate in TSHARK_CANDIDATES:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _section(step: str, title: str) -> None:
    print(f"\n{'─' * 62}")
    print(f"  {step}  {title}")
    print("─" * 62)


def _run(*args: str) -> None:
    subprocess.run([PYTHON, *args], cwd=ROOT, check=True)


def _popen(*args: str) -> subprocess.Popen:
    return subprocess.Popen([PYTHON, *args], cwd=ROOT)


def _start_sniffer(pcap_path: Path, timeout: int, iface: str) -> subprocess.Popen:
    sniffer = _popen(
        "-m", "src.capture.sniffer",
        str(pcap_path),
        "--iface", iface,
        "--count", "500",
        "--timeout", str(timeout),
        "--filter", "(tcp or udp) and host 127.0.0.1",
    )
    time.sleep(2)  # dar tiempo al sniffer para abrir la interfaz
    if sniffer.poll() is not None:
        print("\n  [ERROR] El sniffer terminó de inmediato.")
        print("  Verifique que Npcap esté instalado y que corre como administrador.")
        sys.exit(1)
    return sniffer


def _wait_sniffer(sniffer: subprocess.Popen, timeout: int) -> None:
    try:
        sniffer.wait(timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        sniffer.kill()
        sniffer.wait()


def main() -> None:
    iface = _detect_loopback()

    print("\n" + "=" * 62)
    print("  DEMO — Grupo 5 | Capa de Transporte | IF5000 UCR")
    print("  Integrantes: Darnell Estrada · Rick Rodriguez · Jorge Murillo")
    print("=" * 62)

    # ── PARTE 1: sesión TCP/UDP normal ──────────────────────────────
    _section("[1/8]", "Iniciando sniffer — sesión TCP/UDP")
    print(f"  Interfaz : {iface}")
    print(f"  Salida   : captures/{SESSION_PCAP.name}")
    session_sniffer = _start_sniffer(SESSION_PCAP, SESSION_SNIFFER_TIMEOUT, iface)
    print(f"  Sniffer activo (PID {session_sniffer.pid}).")

    _section("[2/8]", f"Sesión TCP completa  →  127.0.0.1:{TCP_PORT}")
    tcp_server = _popen(
        "-m", "src.generator.traffic",
        "tcp-server", "--host", "127.0.0.1", "--port", str(TCP_PORT), "--count", "1",
    )
    time.sleep(1.5)
    _run(
        "-m", "src.generator.traffic",
        "tcp-client", "--host", "127.0.0.1", "--port", str(TCP_PORT),
        "hola tcp", "grupo 5", "IF5000 UCR",
    )
    tcp_server.wait(timeout=5)
    print("  Completada (SYN → SYN-ACK → ACK → datos → FIN-ACK).")

    _section("[3/8]", f"Datagramas UDP  →  127.0.0.1:{UDP_PORT}")
    udp_server = _popen(
        "-m", "src.generator.traffic",
        "udp-server", "--host", "127.0.0.1", "--port", str(UDP_PORT), "--count", "3",
    )
    time.sleep(1.5)
    _run(
        "-m", "src.generator.traffic",
        "udp-client", "--host", "127.0.0.1", "--port", str(UDP_PORT),
        "hola udp", "grupo 5", "IF5000 UCR",
    )
    udp_server.wait(timeout=5)
    print("  3 datagramas enviados y recibidos.")

    _section("[4/8]", "Analizando sesión: parser + reconstructor de estados")
    _wait_sniffer(session_sniffer, SESSION_SNIFFER_TIMEOUT)
    if not SESSION_PCAP.exists():
        print(f"\n  [ERROR] No se generó {SESSION_PCAP.name}")
        print("  El sniffer necesita Npcap y permisos de administrador.")
        sys.exit(1)

    session_packets = list(iter_pcap_transport_headers(SESSION_PCAP))
    tcp_pkts = [p for p in session_packets if p.protocol == "TCP"]
    udp_pkts = [p for p in session_packets if p.protocol == "UDP"]
    print(f"  Paquetes capturados : {len(session_packets)}  (TCP {len(tcp_pkts)}, UDP {len(udp_pkts)})")

    _print_packet_table(session_packets)

    flows = reconstruct_tcp_flows(session_packets)
    print("\n  Reconstrucción de estados TCP:")
    for key, flow in flows.items():
        print(f"    Flujo {key[0]} <-> {key[1]}")
        print(
            f"      handshake completo={flow.handshake_completed}  cerrado={flow.closed}  "
            f"retransmisiones={flow.retransmissions}  cambios de ventana={flow.window_updates}"
        )
        for event in flow.events:
            ts = f"{event.timestamp:.2f}s" if event.timestamp is not None else "?"
            print(f"        [{ts}] {event.event_type}: {event.detail}")

    _section("[5/8]", "Validando parser propio contra tshark")
    tshark_path = _find_tshark()
    if tshark_path is None:
        print("  [OMITIDO] No se encontró tshark instalado ni en el PATH.")
    else:
        try:
            summary = validate_pcap_with_tshark(SESSION_PCAP, tshark_path=tshark_path)
            print(f"  Paquetes comparados : {summary.compared_packets}")
            print(f"  Campos comparados   : {summary.compared_fields}")
            print(f"  Coincidencia        : {summary.match_ratio:.2%}")
            if summary.unmatched_own_packets or summary.unmatched_tshark_rows:
                print(
                    f"  Sin pareja          : {summary.unmatched_own_packets} del parser propio, "
                    f"{summary.unmatched_tshark_rows} de tshark (p. ej. IPv6, no soportado)"
                )
            if summary.mismatches:
                print("  Diferencias:")
                for mismatch in summary.mismatches[:10]:
                    print(
                        f"    pkt={mismatch.packet_index} field={mismatch.field} "
                        f"propio={mismatch.own_value} tshark={mismatch.tshark_value}"
                    )
        except Exception as exc:  # noqa: BLE001 - reporte best-effort en la demo
            print(f"  [ERROR] {exc}")

    # ── PARTE 2: escaneo de puertos ──────────────────────────────────
    _section("[6/8]", "Iniciando sniffer — escaneo de puertos")
    print(f"  Salida   : captures/{SCAN_PCAP.name}")
    scan_sniffer = _start_sniffer(SCAN_PCAP, SCAN_SNIFFER_TIMEOUT, iface)
    print(f"  Sniffer activo (PID {scan_sniffer.pid}).")

    _section("[7/8]", f"Escaneo TCP connect propio  →  127.0.0.1:{SCAN_PORTS}")
    _run("-m", "src.generator.port_scanner", "--host", "127.0.0.1", "--ports", SCAN_PORTS)

    _section("[8/8]", "Analizando escaneo: detector de anomalías")
    _wait_sniffer(scan_sniffer, SCAN_SNIFFER_TIMEOUT)
    if not SCAN_PCAP.exists():
        print(f"\n  [ERROR] No se generó {SCAN_PCAP.name}")
        sys.exit(1)

    scan_packets = list(iter_pcap_transport_headers(SCAN_PCAP))
    print(f"  Paquetes capturados : {len(scan_packets)}")

    detections = detect_port_scans(scan_packets)
    if detections:
        for detection in detections:
            print(
                f"    [ALERTA] {detection.protocol} {detection.source_ip} -> "
                f"{detection.target_ip}: {detection.distinct_ports} puertos "
                f"({detection.reason})"
            )
    else:
        print("    No se detectaron escaneos (revisar umbrales/min_distinct_ports).")

    # ── Resumen final ──────────────────────────────────────────────
    print("\n" + "=" * 62)
    print("  RESUMEN")
    print(f"    Sesión TCP/UDP : {SESSION_PCAP.name}  ({len(session_packets)} paquetes)")
    print(
        f"    Escaneo        : {SCAN_PCAP.name}  "
        f"({len(scan_packets)} paquetes, {len(detections)} detección(es))"
    )
    print("=" * 62 + "\n")


def _print_packet_table(packets) -> None:
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
        print(f"  ... y {len(packets) - 25} paquetes más")


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import sniff, wrpcap


def capture_to_pcap(
    output_path: str | Path,
    *,
    interface: str | None = None,
    count: int = 0,
    timeout: int | None = None,
    bpf_filter: str = "tcp or udp",
) -> int:
    """Captura trafico TCP/UDP real y lo guarda en un archivo pcap."""
    packets = sniff(
        iface=interface,
        count=count,
        timeout=timeout,
        filter=bpf_filter,
        store=True,
    )
    wrpcap(str(output_path), packets)
    return len(packets)


def main() -> None:
    parser = argparse.ArgumentParser(description="Captura trafico TCP/UDP a un pcap")
    parser.add_argument("output", help="Ruta del archivo .pcap de salida")
    parser.add_argument("--iface", help="Interfaz de red a capturar")
    parser.add_argument("--count", type=int, default=0, help="Cantidad de paquetes")
    parser.add_argument("--timeout", type=int, help="Tiempo maximo de captura en segundos")
    parser.add_argument(
        "--filter",
        default="tcp or udp",
        help="Filtro BPF para la captura",
    )
    args = parser.parse_args()

    total = capture_to_pcap(
        args.output,
        interface=args.iface,
        count=args.count,
        timeout=args.timeout,
        bpf_filter=args.filter,
    )
    print(f"Paquetes capturados: {total}")


if __name__ == "__main__":
    main()

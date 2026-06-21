#!/usr/bin/env python3
"""Valida las capturas definitivas contra tshark y guarda el reporte en results/."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.validation import validate_pcap_with_tshark  # noqa: E402

CAPTURES = ROOT / "captures"
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

PCAPS = (
    CAPTURES / "sesion_tcp_udp.pcap",
    CAPTURES / "escaneo_tcp_connect.pcap",
)

# Wireshark no siempre agrega tshark.exe al PATH en Windows.
TSHARK_CANDIDATES = ("tshark", r"C:\Program Files\Wireshark\tshark.exe")


def _find_tshark() -> str | None:
    for candidate in TSHARK_CANDIDATES:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def main() -> None:
    tshark_path = _find_tshark()
    if tshark_path is None:
        print("[ERROR] No se encontro tshark instalado ni en el PATH.")
        sys.exit(1)

    lines = ["VALIDACION DEL PARSER PROPIO CONTRA TSHARK", "=" * 60, ""]

    for pcap_path in PCAPS:
        lines.append(f"Captura: {pcap_path.name}")
        if not pcap_path.exists():
            lines.append("  [OMITIDO] no existe, corra scripts/demo.py primero.")
            lines.append("")
            continue

        summary = validate_pcap_with_tshark(pcap_path, tshark_path=tshark_path)
        lines.append(f"  Paquetes comparados : {summary.compared_packets}")
        lines.append(f"  Campos comparados   : {summary.compared_fields}")
        lines.append(f"  Coincidencia        : {summary.match_ratio:.2%}")
        if summary.unmatched_own_packets or summary.unmatched_tshark_rows:
            lines.append(
                f"  Sin pareja          : {summary.unmatched_own_packets} del parser propio, "
                f"{summary.unmatched_tshark_rows} de tshark"
            )
        if summary.mismatches:
            lines.append(f"  Diferencias ({len(summary.mismatches)}):")
            for mismatch in summary.mismatches[:25]:
                lines.append(
                    f"    pkt={mismatch.packet_index} field={mismatch.field} "
                    f"propio={mismatch.own_value} tshark={mismatch.tshark_value}"
                )
        lines.append("")

    report = "\n".join(lines)
    output_path = RESULTS / "tshark_validation.txt"
    output_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"Guardado en {output_path}")


if __name__ == "__main__":
    main()

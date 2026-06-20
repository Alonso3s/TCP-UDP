#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.capture import iter_pcap_transport_headers  # noqa: E402
from src.detector import (  # noqa: E402
    PortScanDetection,
    detect_port_scans,
    evaluate_detections,
    load_truth_labels,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analiza un pcap, detecta escaneos y genera resultados"
    )
    parser.add_argument("pcap", help="Ruta del archivo .pcap")
    parser.add_argument("--output-dir", default="results", help="Directorio de salida")
    parser.add_argument("--window", type=float, default=5.0, help="Ventana en segundos")
    parser.add_argument(
        "--min-ports",
        type=int,
        default=10,
        help="Minimo de puertos destino distintos para alertar",
    )
    parser.add_argument(
        "--truth",
        help="JSON opcional con labels de verdad de referencia para metricas",
    )
    args = parser.parse_args()

    packets = list(iter_pcap_transport_headers(args.pcap))
    detections = detect_port_scans(
        packets,
        window_seconds=args.window,
        min_distinct_ports=args.min_ports,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    detections_json = output_dir / "detections.json"
    detections_csv = output_dir / "detections.csv"
    chart_svg = output_dir / "detections_by_source.svg"
    metrics_json = output_dir / "metrics.json"

    _write_detections_json(detections, detections_json)
    _write_detections_csv(detections, detections_csv)
    _write_detection_chart(detections, chart_svg)

    print(f"Paquetes analizados : {len(packets)}")
    print(f"Detecciones         : {len(detections)}")
    print(f"JSON                : {detections_json}")
    print(f"CSV                 : {detections_csv}")
    print(f"Grafico SVG         : {chart_svg}")

    if args.truth:
        labels = load_truth_labels(args.truth)
        metrics = evaluate_detections(
            detections,
            labels,
            observation_seconds=_observation_seconds(packets),
        )
        metrics_json.write_text(
            json.dumps(asdict(metrics), indent=2),
            encoding="utf-8",
        )
        print(f"Metricas            : {metrics_json}")
        print(f"Precision           : {metrics.precision:.2%}")
        print(f"Recall              : {metrics.recall:.2%}")
        print(f"F1                  : {metrics.f1:.2%}")


def _write_detections_json(
    detections: list[PortScanDetection],
    output_path: Path,
) -> None:
    output_path.write_text(
        json.dumps([asdict(detection) for detection in detections], indent=2),
        encoding="utf-8",
    )


def _write_detections_csv(
    detections: list[PortScanDetection],
    output_path: Path,
) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(
            [
                "source_ip",
                "target_ip",
                "protocol",
                "start_time",
                "end_time",
                "distinct_ports",
                "packet_count",
                "ports",
                "reason",
            ]
        )
        for detection in detections:
            writer.writerow(
                [
                    detection.source_ip,
                    detection.target_ip,
                    detection.protocol,
                    detection.start_time,
                    detection.end_time,
                    detection.distinct_ports,
                    detection.packet_count,
                    " ".join(str(port) for port in detection.ports),
                    detection.reason,
                ]
            )


def _write_detection_chart(
    detections: list[PortScanDetection],
    output_path: Path,
) -> None:
    counts: dict[str, int] = {}
    for detection in detections:
        counts[detection.source_ip] = counts.get(detection.source_ip, 0) + 1

    labels = sorted(counts)
    width = 760
    row_height = 34
    height = max(120, 70 + row_height * max(1, len(labels)))
    max_count = max(counts.values(), default=1)

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 760 {height}">',
        '<rect width="760" height="100%" fill="#ffffff"/>',
        '<text x="24" y="32" font-family="Arial" font-size="20" font-weight="700">'
        "Detecciones por origen</text>",
    ]

    if not labels:
        lines.append(
            '<text x="24" y="76" font-family="Arial" font-size="14">'
            "No se detectaron escaneos</text>"
        )
    else:
        for index, label in enumerate(labels):
            y = 70 + index * row_height
            bar_width = int((counts[label] / max_count) * 520)
            lines.extend(
                [
                    f'<text x="24" y="{y + 18}" font-family="Arial" font-size="13">{label}</text>',
                    f'<rect x="170" y="{y}" width="{bar_width}" height="22" fill="#2563eb"/>',
                    f'<text x="{180 + bar_width}" y="{y + 16}" font-family="Arial" '
                    f'font-size="13">{counts[label]}</text>',
                ]
            )

    lines.append("</svg>")
    output_path.write_text("\n".join(lines), encoding="utf-8")


def _observation_seconds(packets: list[object]) -> float:
    timestamps = [
        packet.timestamp
        for packet in packets
        if getattr(packet, "timestamp", None) is not None
    ]
    if len(timestamps) < 2:
        return 0.0
    return max(timestamps) - min(timestamps)


if __name__ == "__main__":
    main()

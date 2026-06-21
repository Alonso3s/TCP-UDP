from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from src.capture import TransportPacket, iter_pcap_transport_headers
from src.parser import TCPHeader, UDPHeader


@dataclass(frozen=True)
class PortScanDetection:
    source_ip: str
    target_ip: str
    protocol: str
    start_time: float | None
    end_time: float | None
    distinct_ports: int
    packet_count: int
    ports: tuple[int, ...]
    reason: str


@dataclass(frozen=True)
class ScanTruthLabel:
    source_ip: str
    target_ip: str
    protocol: str = "TCP"
    start_time: float | None = None
    end_time: float | None = None


@dataclass(frozen=True)
class DetectionMetrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    false_positives_per_hour: float
    average_latency_seconds: float | None
    coverage: float


def detect_port_scans(
    packets: Iterable[TransportPacket],
    *,
    window_seconds: float = 5.0,
    min_distinct_ports: int = 10,
    protocols: set[str] | None = None,
) -> list[PortScanDetection]:
    """Detecta escaneos por muchos puertos destino en una ventana temporal corta."""
    protocols = protocols or {"TCP", "UDP"}
    windows: dict[tuple[str, str, str], deque[TransportPacket]] = defaultdict(deque)
    detections: list[PortScanDetection] = []
    emitted: set[tuple[str, str, str, int]] = set()

    ordered_packets = sorted(
        (
            packet
            for packet in packets
            if packet.protocol in protocols and _is_scan_probe(packet)
        ),
        key=lambda packet: packet.timestamp if packet.timestamp is not None else 0.0,
    )

    for packet in ordered_packets:
        destination_port = _destination_port(packet)
        if destination_port is None:
            continue

        key = (packet.source_ip, packet.destination_ip, packet.protocol)
        window = windows[key]
        window.append(packet)
        _trim_window(window, window_seconds)

        ports = sorted(
            {
                port
                for port in (_destination_port(candidate) for candidate in window)
                if port is not None
            }
        )
        if len(ports) < min_distinct_ports:
            continue

        bucket = _time_bucket(packet.timestamp, window_seconds)
        emitted_key = (*key, bucket)
        if emitted_key in emitted:
            continue

        emitted.add(emitted_key)
        detections.append(
            PortScanDetection(
                source_ip=packet.source_ip,
                target_ip=packet.destination_ip,
                protocol=packet.protocol,
                start_time=window[0].timestamp,
                end_time=packet.timestamp,
                distinct_ports=len(ports),
                packet_count=len(window),
                ports=tuple(ports),
                reason=(
                    f"{len(ports)} puertos destino distintos en "
                    f"{window_seconds:.1f} segundos"
                ),
            )
        )

    return detections


def evaluate_detections(
    detections: Sequence[PortScanDetection],
    truth_labels: Sequence[ScanTruthLabel],
    *,
    observation_seconds: float,
) -> DetectionMetrics:
    matched_truth: set[int] = set()
    true_positives = 0
    false_positives = 0
    latencies: list[float] = []

    for detection in detections:
        match_index = _find_matching_truth(detection, truth_labels, matched_truth)
        if match_index is None:
            false_positives += 1
            continue

        true_positives += 1
        matched_truth.add(match_index)
        label = truth_labels[match_index]
        if detection.start_time is not None and label.start_time is not None:
            latencies.append(max(0.0, detection.start_time - label.start_time))

    false_negatives = len(truth_labels) - true_positives
    precision = _safe_div(true_positives, true_positives + false_positives)
    recall = _safe_div(true_positives, true_positives + false_negatives)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    hours = observation_seconds / 3600 if observation_seconds > 0 else 0.0

    return DetectionMetrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positives_per_hour=_safe_div(false_positives, hours),
        average_latency_seconds=(
            sum(latencies) / len(latencies) if latencies else None
        ),
        coverage=recall,
    )


def load_truth_labels(path: str | Path) -> list[ScanTruthLabel]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    labels = data["labels"] if isinstance(data, dict) else data
    return [ScanTruthLabel(**label) for label in labels]


def save_detections_json(
    detections: Sequence[PortScanDetection],
    output_path: str | Path,
) -> None:
    Path(output_path).write_text(
        json.dumps([asdict(detection) for detection in detections], indent=2),
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Detecta escaneos de puertos en un pcap")
    parser.add_argument("pcap", help="Ruta del archivo .pcap")
    parser.add_argument("--window", type=float, default=5.0, help="Ventana en segundos")
    parser.add_argument(
        "--min-ports",
        type=int,
        default=10,
        help="Minimo de puertos destino distintos",
    )
    args = parser.parse_args(argv)

    detections = detect_port_scans(
        iter_pcap_transport_headers(args.pcap),
        window_seconds=args.window,
        min_distinct_ports=args.min_ports,
    )
    for detection in detections:
        print(
            f"{detection.protocol} {detection.source_ip} -> {detection.target_ip}: "
            f"{detection.distinct_ports} puertos ({detection.reason})"
        )


def _destination_port(packet: TransportPacket) -> int | None:
    if isinstance(packet.header, TCPHeader | UDPHeader):
        return packet.header.destination_port
    return None


def _is_scan_probe(packet: TransportPacket) -> bool:
    """Distingue intentos de conexion de simples respuestas.

    Un SYN sin ACK es quien inicia la conexion contra un puerto nuevo. Sin este
    filtro, las respuestas de un servidor (que regresan a los distintos puertos
    efimeros que usa cada conexion del escaner) tambien acumulan "muchos puertos
    destino distintos" y el servidor terminaba marcado como si escaneara al
    atacante.
    """
    if packet.protocol == "TCP" and isinstance(packet.header, TCPHeader):
        return packet.header.flags["SYN"] and not packet.header.flags["ACK"]
    return packet.protocol == "UDP"


def _trim_window(window: deque[TransportPacket], window_seconds: float) -> None:
    latest = window[-1].timestamp
    if latest is None:
        return

    while len(window) > 1:
        oldest = window[0].timestamp
        if oldest is None or latest - oldest <= window_seconds:
            break
        window.popleft()


def _time_bucket(timestamp: float | None, window_seconds: float) -> int:
    if timestamp is None or window_seconds <= 0:
        return 0
    return int(timestamp // window_seconds)


def _find_matching_truth(
    detection: PortScanDetection,
    truth_labels: Sequence[ScanTruthLabel],
    matched_truth: set[int],
) -> int | None:
    for index, label in enumerate(truth_labels):
        if index in matched_truth:
            continue
        if detection.source_ip != label.source_ip:
            continue
        if detection.target_ip != label.target_ip:
            continue
        if detection.protocol != label.protocol:
            continue
        if not _overlaps(detection.start_time, detection.end_time, label.start_time, label.end_time):
            continue
        return index
    return None


def _overlaps(
    left_start: float | None,
    left_end: float | None,
    right_start: float | None,
    right_end: float | None,
) -> bool:
    if None in (left_start, left_end, right_start, right_end):
        return True
    return left_start <= right_end and right_start <= left_end


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


if __name__ == "__main__":
    main()

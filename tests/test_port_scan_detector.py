from __future__ import annotations

from src.capture import TransportPacket
from src.detector import ScanTruthLabel, detect_port_scans, evaluate_detections
from src.parser import TCPHeader


def test_detect_port_scans_alerts_on_many_ports_in_window():
    packets = [
        _tcp_packet(
            timestamp=float(index),
            source_ip="10.0.0.10",
            destination_ip="10.0.0.20",
            source_port=40000 + index,
            destination_port=5000 + index,
        )
        for index in range(10)
    ]

    detections = detect_port_scans(
        packets,
        window_seconds=10,
        min_distinct_ports=10,
    )

    assert len(detections) == 1
    assert detections[0].source_ip == "10.0.0.10"
    assert detections[0].target_ip == "10.0.0.20"
    assert detections[0].distinct_ports == 10


def test_detect_port_scans_ignores_low_port_diversity():
    packets = [
        _tcp_packet(
            timestamp=float(index),
            source_ip="10.0.0.10",
            destination_ip="10.0.0.20",
            source_port=40000 + index,
            destination_port=5000,
        )
        for index in range(10)
    ]

    assert detect_port_scans(packets, window_seconds=10, min_distinct_ports=3) == []


def test_evaluate_detections_calculates_metrics():
    detections = detect_port_scans(
        [
            _tcp_packet(
                timestamp=float(index),
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                source_port=40000 + index,
                destination_port=5000 + index,
            )
            for index in range(10)
        ],
        window_seconds=10,
        min_distinct_ports=10,
    )
    labels = [
        ScanTruthLabel(
            source_ip="10.0.0.10",
            target_ip="10.0.0.20",
            protocol="TCP",
            start_time=0.0,
            end_time=10.0,
        )
    ]

    metrics = evaluate_detections(detections, labels, observation_seconds=60)

    assert metrics.true_positives == 1
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1 == 1.0


def _tcp_packet(
    *,
    timestamp: float,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
) -> TransportPacket:
    return TransportPacket(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="TCP",
        header=TCPHeader(
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=100,
            acknowledgment_number=0,
            data_offset=5,
            reserved=0,
            flags_value=0x002,
            flags={
                "FIN": False,
                "SYN": True,
                "RST": False,
                "PSH": False,
                "ACK": False,
                "URG": False,
                "ECE": False,
                "CWR": False,
                "NS": False,
            },
            window_size=8192,
            checksum=0,
            urgent_pointer=0,
            options=(),
        ),
        payload_length=0,
    )

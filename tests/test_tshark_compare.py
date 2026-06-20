from __future__ import annotations

from src.capture import TransportPacket
from src.parser import TCPHeader, UDPHeader
from src.validation import TsharkRow, compare_packets_to_tshark_rows, parse_tshark_csv


def test_compare_tcp_packet_to_tshark_row_matches_fields():
    packet = TransportPacket(
        timestamp=1.0,
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="TCP",
        header=TCPHeader(
            source_port=12345,
            destination_port=80,
            sequence_number=100,
            acknowledgment_number=200,
            data_offset=5,
            reserved=0,
            flags_value=0x018,
            flags={name: name in {"ACK", "PSH"} for name in _flag_names()},
            window_size=8192,
            checksum=0x1A2B,
            urgent_pointer=0,
            options=(),
        ),
        payload_length=5,
    )
    row = TsharkRow(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="TCP",
        fields={
            "tcp.srcport": "12345",
            "tcp.dstport": "80",
            "tcp.seq_raw": "100",
            "tcp.ack_raw": "200",
            "tcp.hdr_len": "20",
            "tcp.flags": "0x18",
            "tcp.window_size_value": "8192",
            "tcp.checksum": "0x1a2b",
        },
    )

    summary = compare_packets_to_tshark_rows([packet], [row])

    assert summary.compared_packets == 1
    assert summary.match_ratio == 1.0
    assert summary.mismatches == ()


def test_compare_udp_packet_to_tshark_row_reports_mismatch():
    packet = TransportPacket(
        timestamp=1.0,
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="UDP",
        header=UDPHeader(
            source_port=5001,
            destination_port=53,
            length=12,
            checksum=0x1111,
        ),
        payload_length=4,
    )
    row = TsharkRow(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="UDP",
        fields={
            "udp.srcport": "5001",
            "udp.dstport": "54",
            "udp.length": "12",
            "udp.checksum": "0x1111",
        },
    )

    summary = compare_packets_to_tshark_rows([packet], [row])

    assert len(summary.mismatches) == 1
    assert summary.mismatches[0].field == "destination_port"


def test_parse_tshark_csv_detects_protocol_from_fields():
    rows = parse_tshark_csv(
        [
            '"10.0.0.1","10.0.0.2","TCP","1234","80","1","0","20","0x002","8192","0x0000","","","",""',
            '"10.0.0.1","10.0.0.2","UDP","","","","","","","","","5001","53","8","0x0000"',
        ]
    )

    assert rows[0].protocol == "TCP"
    assert rows[1].protocol == "UDP"


def _flag_names() -> tuple[str, ...]:
    return ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS")

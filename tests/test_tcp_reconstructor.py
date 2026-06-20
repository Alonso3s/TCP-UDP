from __future__ import annotations

from src.capture import TransportPacket
from src.parser import TCPHeader
from src.states import (
    TCP_EVENT_FIN,
    TCP_EVENT_HANDSHAKE_COMPLETED,
    TCP_EVENT_HANDSHAKE_STARTED,
    TCP_EVENT_RETRANSMISSION,
    TCP_EVENT_WINDOW_UPDATE,
    reconstruct_tcp_flows,
)


def test_reconstruct_tcp_flow_detects_handshake_and_fin():
    packets = [
        _packet(1.0, "10.0.0.1", 40000, "10.0.0.2", 80, seq=100, flags=["SYN"]),
        _packet(
            1.1,
            "10.0.0.2",
            80,
            "10.0.0.1",
            40000,
            seq=200,
            ack=101,
            flags=["SYN", "ACK"],
        ),
        _packet(
            1.2,
            "10.0.0.1",
            40000,
            "10.0.0.2",
            80,
            seq=101,
            ack=201,
            flags=["ACK"],
        ),
        _packet(
            1.3,
            "10.0.0.1",
            40000,
            "10.0.0.2",
            80,
            seq=101,
            ack=201,
            flags=["FIN", "ACK"],
        ),
    ]

    flows = reconstruct_tcp_flows(packets)
    flow = next(iter(flows.values()))

    assert flow.handshake_started is True
    assert flow.handshake_completed is True
    assert flow.closed is True
    assert [event.event_type for event in flow.events] == [
        TCP_EVENT_HANDSHAKE_STARTED,
        TCP_EVENT_HANDSHAKE_COMPLETED,
        TCP_EVENT_FIN,
    ]


def test_reconstruct_tcp_flow_detects_window_update_and_retransmission():
    packets = [
        _packet(
            1.0,
            "10.0.0.1",
            40000,
            "10.0.0.2",
            80,
            seq=100,
            ack=1,
            flags=["ACK"],
            window=8192,
            payload_length=10,
        ),
        _packet(
            1.1,
            "10.0.0.1",
            40000,
            "10.0.0.2",
            80,
            seq=100,
            ack=1,
            flags=["ACK"],
            window=4096,
            payload_length=10,
        ),
    ]

    flow = next(iter(reconstruct_tcp_flows(packets).values()))
    event_types = [event.event_type for event in flow.events]

    assert flow.window_updates == 1
    assert flow.retransmissions == 1
    assert TCP_EVENT_WINDOW_UPDATE in event_types
    assert TCP_EVENT_RETRANSMISSION in event_types


def _packet(
    timestamp: float,
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
    *,
    seq: int,
    ack: int = 0,
    flags: list[str],
    window: int = 8192,
    payload_length: int = 0,
) -> TransportPacket:
    return TransportPacket(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="TCP",
        header=TCPHeader(
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=seq,
            acknowledgment_number=ack,
            data_offset=5,
            reserved=0,
            flags_value=0,
            flags={
                "FIN": "FIN" in flags,
                "SYN": "SYN" in flags,
                "RST": "RST" in flags,
                "PSH": "PSH" in flags,
                "ACK": "ACK" in flags,
                "URG": "URG" in flags,
                "ECE": "ECE" in flags,
                "CWR": "CWR" in flags,
                "NS": "NS" in flags,
            },
            window_size=window,
            checksum=0,
            urgent_pointer=0,
            options=(),
        ),
        payload_length=payload_length,
    )

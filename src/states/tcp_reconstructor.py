from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from src.capture import TransportPacket
from src.parser import TCPHeader


TCP_EVENT_HANDSHAKE_STARTED = "HANDSHAKE_STARTED"
TCP_EVENT_HANDSHAKE_COMPLETED = "HANDSHAKE_COMPLETED"
TCP_EVENT_WINDOW_UPDATE = "WINDOW_UPDATE"
TCP_EVENT_RETRANSMISSION = "RETRANSMISSION"
TCP_EVENT_FIN = "FIN"
TCP_EVENT_RST = "RST"


Endpoint = tuple[str, int]
FlowKey = tuple[Endpoint, Endpoint]


@dataclass(frozen=True)
class TCPEvent:
    event_type: str
    timestamp: float | None
    source: Endpoint
    destination: Endpoint
    sequence_number: int
    acknowledgment_number: int
    detail: str


@dataclass
class TCPFlowState:
    key: FlowKey
    client: Endpoint | None = None
    server: Endpoint | None = None
    handshake_started: bool = False
    handshake_completed: bool = False
    closed: bool = False
    reset: bool = False
    packet_count: int = 0
    retransmissions: int = 0
    window_updates: int = 0
    last_window_by_endpoint: dict[Endpoint, int] = field(default_factory=dict)
    seen_segments: set[tuple[Endpoint, int, int, bool, bool]] = field(default_factory=set)
    events: list[TCPEvent] = field(default_factory=list)


def reconstruct_tcp_flows(packets: Iterable[TransportPacket]) -> dict[FlowKey, TCPFlowState]:
    """Reconstruye estado TCP observable desde paquetes ya parseados."""
    flows: dict[FlowKey, TCPFlowState] = {}

    for packet in packets:
        if packet.protocol != "TCP" or not isinstance(packet.header, TCPHeader):
            continue

        header = packet.header
        source = (packet.source_ip, header.source_port)
        destination = (packet.destination_ip, header.destination_port)
        key = normalize_flow_key(source, destination)
        flow = flows.setdefault(key, TCPFlowState(key=key))
        flow.packet_count += 1

        _observe_handshake(flow, packet, source, destination)
        _observe_window(flow, packet, source, destination)
        _observe_retransmission(flow, packet, source, destination)
        _observe_close(flow, packet, source, destination)

    return flows


def normalize_flow_key(source: Endpoint, destination: Endpoint) -> FlowKey:
    return tuple(sorted((source, destination)))  # type: ignore[return-value]


def _observe_handshake(
    flow: TCPFlowState,
    packet: TransportPacket,
    source: Endpoint,
    destination: Endpoint,
) -> None:
    header = packet.header
    flags = header.flags

    if flags["SYN"] and not flags["ACK"] and not flow.handshake_started:
        flow.client = source
        flow.server = destination
        flow.handshake_started = True
        _add_event(
            flow,
            TCP_EVENT_HANDSHAKE_STARTED,
            packet,
            source,
            destination,
            "SYN inicial observado",
        )
        return

    if (
        flags["ACK"]
        and not flags["SYN"]
        and flow.handshake_started
        and not flow.handshake_completed
        and flow.client == source
        and flow.server == destination
    ):
        flow.handshake_completed = True
        _add_event(
            flow,
            TCP_EVENT_HANDSHAKE_COMPLETED,
            packet,
            source,
            destination,
            "ACK final del three-way handshake observado",
        )


def _observe_window(
    flow: TCPFlowState,
    packet: TransportPacket,
    source: Endpoint,
    destination: Endpoint,
) -> None:
    header = packet.header
    previous_window = flow.last_window_by_endpoint.get(source)
    flow.last_window_by_endpoint[source] = header.window_size

    if previous_window is None or previous_window == header.window_size:
        return

    flow.window_updates += 1
    _add_event(
        flow,
        TCP_EVENT_WINDOW_UPDATE,
        packet,
        source,
        destination,
        f"ventana {previous_window} -> {header.window_size}",
    )


def _observe_retransmission(
    flow: TCPFlowState,
    packet: TransportPacket,
    source: Endpoint,
    destination: Endpoint,
) -> None:
    header = packet.header
    flags = header.flags
    consumes_sequence = packet.payload_length > 0 or flags["SYN"] or flags["FIN"]
    signature = (
        source,
        header.sequence_number,
        packet.payload_length,
        flags["SYN"],
        flags["FIN"],
    )

    if consumes_sequence and signature in flow.seen_segments:
        flow.retransmissions += 1
        _add_event(
            flow,
            TCP_EVENT_RETRANSMISSION,
            packet,
            source,
            destination,
            "segmento con mismo origen, SEQ, longitud y flags",
        )

    if consumes_sequence:
        flow.seen_segments.add(signature)


def _observe_close(
    flow: TCPFlowState,
    packet: TransportPacket,
    source: Endpoint,
    destination: Endpoint,
) -> None:
    header = packet.header
    flags = header.flags

    if flags["RST"]:
        flow.reset = True
        flow.closed = True
        _add_event(flow, TCP_EVENT_RST, packet, source, destination, "RST observado")
    elif flags["FIN"]:
        flow.closed = True
        _add_event(flow, TCP_EVENT_FIN, packet, source, destination, "FIN observado")


def _add_event(
    flow: TCPFlowState,
    event_type: str,
    packet: TransportPacket,
    source: Endpoint,
    destination: Endpoint,
    detail: str,
) -> None:
    header = packet.header
    flow.events.append(
        TCPEvent(
            event_type=event_type,
            timestamp=packet.timestamp,
            source=source,
            destination=destination,
            sequence_number=header.sequence_number,
            acknowledgment_number=header.acknowledgment_number,
            detail=detail,
        )
    )

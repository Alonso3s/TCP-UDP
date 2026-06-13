from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
import struct
from pathlib import Path
from typing import Iterator

from src.parser import TCPHeader, UDPHeader, parse_tcp_header, parse_udp_header


ETHERNET_MIN_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
IPV4_MIN_HEADER_LEN = 20
PROTO_TCP = 6
PROTO_UDP = 17


@dataclass(frozen=True)
class IPv4Packet:
    source_ip: str
    destination_ip: str
    protocol: int
    header_length: int
    total_length: int
    payload: bytes


@dataclass(frozen=True)
class TransportPacket:
    timestamp: float | None
    source_ip: str
    destination_ip: str
    protocol: str
    header: TCPHeader | UDPHeader
    payload_length: int


def parse_ethernet_ipv4_frame(frame_bytes: bytes) -> IPv4Packet:
    """Extrae un paquete IPv4 desde una trama Ethernet cruda."""
    if len(frame_bytes) < ETHERNET_MIN_LEN:
        raise ValueError("La trama Ethernet requiere al menos 14 bytes")

    ethertype = struct.unpack("!H", frame_bytes[12:14])[0]
    payload_offset = ETHERNET_MIN_LEN

    if ethertype == ETHERTYPE_VLAN:
        if len(frame_bytes) < ETHERNET_MIN_LEN + 4:
            raise ValueError("La trama VLAN esta incompleta")
        ethertype = struct.unpack("!H", frame_bytes[16:18])[0]
        payload_offset += 4

    if ethertype != ETHERTYPE_IPV4:
        raise ValueError(f"Ethertype no soportado: 0x{ethertype:04x}")

    return parse_ipv4_packet(frame_bytes[payload_offset:])


def parse_ipv4_packet(packet_bytes: bytes) -> IPv4Packet:
    """Parsea lo minimo de IPv4 para ubicar el segmento TCP o datagrama UDP."""
    if len(packet_bytes) < IPV4_MIN_HEADER_LEN:
        raise ValueError("La cabecera IPv4 requiere al menos 20 bytes")

    version_ihl = packet_bytes[0]
    version = version_ihl >> 4
    if version != 4:
        raise ValueError(f"Version IP no soportada: {version}")

    header_length = (version_ihl & 0x0F) * 4
    if header_length < IPV4_MIN_HEADER_LEN:
        raise ValueError(f"Longitud de cabecera IPv4 invalida: {header_length}")

    if len(packet_bytes) < header_length:
        raise ValueError("El paquete IPv4 esta truncado antes del payload")

    total_length = struct.unpack("!H", packet_bytes[2:4])[0]
    if total_length < header_length:
        raise ValueError("La longitud total IPv4 es menor que su cabecera")

    if len(packet_bytes) < total_length:
        raise ValueError("El paquete IPv4 esta truncado segun su longitud total")

    protocol = packet_bytes[9]
    source_ip = str(IPv4Address(packet_bytes[12:16]))
    destination_ip = str(IPv4Address(packet_bytes[16:20]))
    payload = packet_bytes[header_length:total_length]

    return IPv4Packet(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        header_length=header_length,
        total_length=total_length,
        payload=payload,
    )


def iter_pcap_transport_headers(
    pcap_path: str | Path,
    *,
    strict: bool = False,
) -> Iterator[TransportPacket]:
    """Itera cabeceras TCP/UDP de un pcap usando bytes crudos como entrada."""
    from scapy.utils import RawPcapReader

    for packet_bytes, metadata in RawPcapReader(str(pcap_path)):
        timestamp = _metadata_timestamp(metadata)

        try:
            ipv4 = parse_ethernet_ipv4_frame(bytes(packet_bytes))
            transport = _parse_transport_packet(ipv4, timestamp)
        except ValueError:
            if strict:
                raise
            continue

        if transport is not None:
            yield transport


def _parse_transport_packet(
    ipv4: IPv4Packet,
    timestamp: float | None,
) -> TransportPacket | None:
    if ipv4.protocol == PROTO_TCP:
        header = parse_tcp_header(ipv4.payload)
        payload_length = len(ipv4.payload) - header.header_length
        protocol = "TCP"
    elif ipv4.protocol == PROTO_UDP:
        header = parse_udp_header(ipv4.payload)
        payload_length = max(0, header.length - 8)
        protocol = "UDP"
    else:
        return None

    return TransportPacket(
        timestamp=timestamp,
        source_ip=ipv4.source_ip,
        destination_ip=ipv4.destination_ip,
        protocol=protocol,
        header=header,
        payload_length=payload_length,
    )


def _metadata_timestamp(metadata: object) -> float | None:
    seconds = getattr(metadata, "sec", None)
    microseconds = getattr(metadata, "usec", None)

    if seconds is None:
        return None
    if microseconds is None:
        microseconds = 0

    return float(seconds) + (float(microseconds) / 1_000_000)

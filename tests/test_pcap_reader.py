import pytest

from src.capture import parse_ethernet_ipv4_frame, parse_ipv4_packet
from src.capture.pcap_reader import PROTO_TCP, PROTO_UDP


def test_parse_ipv4_packet_with_tcp_payload():
    tcp_header = bytes.fromhex(
        "c0010050"
        "0000007b"
        "000001c8"
        "5018"
        "2000"
        "1f2e"
        "0000"
    )
    packet = _ipv4_packet(PROTO_TCP, tcp_header)

    ipv4 = parse_ipv4_packet(packet)

    assert ipv4.source_ip == "192.168.1.10"
    assert ipv4.destination_ip == "192.168.1.20"
    assert ipv4.protocol == PROTO_TCP
    assert ipv4.header_length == 20
    assert ipv4.total_length == 40
    assert ipv4.payload == tcp_header


def test_parse_ethernet_ipv4_frame_with_udp_payload():
    udp_header = bytes.fromhex("3039003500101a2b")
    frame = _ethernet_frame(_ipv4_packet(PROTO_UDP, udp_header))

    ipv4 = parse_ethernet_ipv4_frame(frame)

    assert ipv4.source_ip == "192.168.1.10"
    assert ipv4.destination_ip == "192.168.1.20"
    assert ipv4.protocol == PROTO_UDP
    assert ipv4.payload == udp_header


def test_parse_ethernet_rejects_non_ipv4_frame():
    frame = (
        bytes.fromhex("001122334455")
        + bytes.fromhex("66778899aabb")
        + bytes.fromhex("86dd")
        + b"\x00" * 20
    )

    with pytest.raises(ValueError, match="Ethertype no soportado"):
        parse_ethernet_ipv4_frame(frame)


def test_parse_ipv4_rejects_truncated_packet():
    with pytest.raises(ValueError, match="al menos 20 bytes"):
        parse_ipv4_packet(b"\x45" + b"\x00" * 18)


def _ethernet_frame(payload: bytes) -> bytes:
    destination_mac = bytes.fromhex("001122334455")
    source_mac = bytes.fromhex("66778899aabb")
    ethertype_ipv4 = bytes.fromhex("0800")
    return destination_mac + source_mac + ethertype_ipv4 + payload


def _ipv4_packet(protocol: int, payload: bytes) -> bytes:
    version_ihl = 0x45
    dscp_ecn = 0
    total_length = 20 + len(payload)
    identification = 1
    flags_fragment = 0
    ttl = 64
    checksum = 0
    source_ip = bytes([192, 168, 1, 10])
    destination_ip = bytes([192, 168, 1, 20])

    return (
        bytes([version_ihl, dscp_ecn])
        + total_length.to_bytes(2, "big")
        + identification.to_bytes(2, "big")
        + flags_fragment.to_bytes(2, "big")
        + bytes([ttl, protocol])
        + checksum.to_bytes(2, "big")
        + source_ip
        + destination_ip
        + payload
    )

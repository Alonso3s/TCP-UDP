import pytest

from src.parser import parse_tcp_header, parse_udp_header


def test_parse_udp_header_from_raw_bytes():
    raw = bytes.fromhex("3039003500101a2b")

    header = parse_udp_header(raw)

    assert header.source_port == 12345
    assert header.destination_port == 53
    assert header.length == 16
    assert header.checksum == 0x1A2B


def test_parse_udp_rejects_short_header():
    with pytest.raises(ValueError, match="al menos 8 bytes"):
        parse_udp_header(b"\x00" * 7)


def test_parse_tcp_header_without_options():
    raw = bytes.fromhex(
        "c0010050"
        "0000007b"
        "000001c8"
        "5018"
        "2000"
        "1f2e"
        "0000"
    )

    header = parse_tcp_header(raw)

    assert header.source_port == 49153
    assert header.destination_port == 80
    assert header.sequence_number == 123
    assert header.acknowledgment_number == 456
    assert header.data_offset == 5
    assert header.header_length == 20
    assert header.flags["ACK"] is True
    assert header.flags["PSH"] is True
    assert header.flags["SYN"] is False
    assert header.window_size == 8192
    assert header.checksum == 0x1F2E
    assert header.urgent_pointer == 0
    assert header.options == ()


def test_parse_tcp_header_with_mss_option_and_padding():
    raw = bytes.fromhex(
        "c0010050"
        "00000001"
        "00000000"
        "6002"
        "faf0"
        "0000"
        "0000"
        "020405b4"
    )

    header = parse_tcp_header(raw)

    assert header.data_offset == 6
    assert header.header_length == 24
    assert header.flags["SYN"] is True
    assert len(header.options) == 1
    assert header.options[0].kind == 2
    assert header.options[0].length == 4
    assert header.options[0].data == bytes.fromhex("05b4")


def test_parse_tcp_rejects_short_header():
    with pytest.raises(ValueError, match="al menos 20 bytes"):
        parse_tcp_header(b"\x00" * 19)


def test_parse_tcp_rejects_impossible_data_offset():
    raw = bytes.fromhex(
        "c0010050"
        "00000001"
        "00000000"
        "4002"
        "faf0"
        "0000"
        "0000"
    )

    with pytest.raises(ValueError, match="Offset de datos TCP invalido"):
        parse_tcp_header(raw)

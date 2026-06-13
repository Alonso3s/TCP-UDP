from __future__ import annotations

from dataclasses import dataclass
import struct


TCP_MIN_HEADER_LEN = 20
UDP_HEADER_LEN = 8

TCP_FLAG_BITS = {
    "FIN": 0x001,
    "SYN": 0x002,
    "RST": 0x004,
    "PSH": 0x008,
    "ACK": 0x010,
    "URG": 0x020,
    "ECE": 0x040,
    "CWR": 0x080,
    "NS": 0x100,
}


@dataclass(frozen=True)
class UDPHeader:
    source_port: int
    destination_port: int
    length: int
    checksum: int


@dataclass(frozen=True)
class TCPOption:
    kind: int
    length: int
    data: bytes


@dataclass(frozen=True)
class TCPHeader:
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    data_offset: int
    reserved: int
    flags_value: int
    flags: dict[str, bool]
    window_size: int
    checksum: int
    urgent_pointer: int
    options: tuple[TCPOption, ...]

    @property
    def header_length(self) -> int:
        return self.data_offset * 4


def parse_udp_header(packet_bytes: bytes) -> UDPHeader:
    """Parsea una cabecera UDP desde bytes crudos, sin usar un disector."""
    if len(packet_bytes) < UDP_HEADER_LEN:
        raise ValueError("La cabecera UDP requiere al menos 8 bytes")

    source_port, destination_port, length, checksum = struct.unpack(
        "!HHHH", packet_bytes[:UDP_HEADER_LEN]
    )
    return UDPHeader(
        source_port=source_port,
        destination_port=destination_port,
        length=length,
        checksum=checksum,
    )


def parse_tcp_header(segment_bytes: bytes) -> TCPHeader:
    """Parsea una cabecera TCP desde bytes crudos, incluyendo opciones."""
    if len(segment_bytes) < TCP_MIN_HEADER_LEN:
        raise ValueError("La cabecera TCP requiere al menos 20 bytes")

    (
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        offset_reserved_flags,
        window_size,
        checksum,
        urgent_pointer,
    ) = struct.unpack("!HHIIHHHH", segment_bytes[:TCP_MIN_HEADER_LEN])

    data_offset = (offset_reserved_flags >> 12) & 0xF
    if data_offset < 5:
        raise ValueError(f"Offset de datos TCP invalido: {data_offset}")

    header_length = data_offset * 4
    if len(segment_bytes) < header_length:
        raise ValueError(
            f"La cabecera TCP declara {header_length} bytes, "
            f"pero se recibieron {len(segment_bytes)}"
        )

    reserved = (offset_reserved_flags >> 9) & 0x7
    flags_value = offset_reserved_flags & 0x1FF
    flags = {name: bool(flags_value & mask) for name, mask in TCP_FLAG_BITS.items()}
    options = _parse_tcp_options(segment_bytes[TCP_MIN_HEADER_LEN:header_length])

    return TCPHeader(
        source_port=source_port,
        destination_port=destination_port,
        sequence_number=sequence_number,
        acknowledgment_number=acknowledgment_number,
        data_offset=data_offset,
        reserved=reserved,
        flags_value=flags_value,
        flags=flags,
        window_size=window_size,
        checksum=checksum,
        urgent_pointer=urgent_pointer,
        options=options,
    )


def _parse_tcp_options(options_bytes: bytes) -> tuple[TCPOption, ...]:
    options: list[TCPOption] = []
    index = 0

    while index < len(options_bytes):
        kind = options_bytes[index]

        if kind == 0:
            options.append(TCPOption(kind=kind, length=1, data=b""))
            break

        if kind == 1:
            options.append(TCPOption(kind=kind, length=1, data=b""))
            index += 1
            continue

        if index + 1 >= len(options_bytes):
            raise ValueError("Opcion TCP malformada sin byte de longitud")

        length = options_bytes[index + 1]
        if length < 2:
            raise ValueError(f"Longitud de opcion TCP invalida: {length}")

        option_end = index + length
        if option_end > len(options_bytes):
            raise ValueError("La opcion TCP excede la longitud declarada de cabecera")

        options.append(
            TCPOption(
                kind=kind,
                length=length,
                data=options_bytes[index + 2 : option_end],
            )
        )
        index = option_end

    return tuple(options)

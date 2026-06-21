from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from src.capture import TransportPacket, iter_pcap_transport_headers
from src.parser import TCPHeader, UDPHeader


TSHARK_FIELDS = (
    "ip.src",
    "ip.dst",
    "_ws.col.Protocol",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.hdr_len",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.checksum",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "udp.checksum",
    # Al final para no romper el orden de columnas de capturas/pruebas previas.
    "frame.number",
)


@dataclass(frozen=True)
class TsharkRow:
    source_ip: str
    destination_ip: str
    protocol: str
    fields: dict[str, str]
    frame_number: int | None = None


@dataclass(frozen=True)
class FieldMismatch:
    packet_index: int
    field: str
    own_value: str
    tshark_value: str


@dataclass(frozen=True)
class ValidationSummary:
    compared_packets: int
    compared_fields: int
    mismatches: tuple[FieldMismatch, ...]
    unmatched_own_packets: int = 0
    unmatched_tshark_rows: int = 0

    @property
    def matched_fields(self) -> int:
        return self.compared_fields - len(self.mismatches)

    @property
    def match_ratio(self) -> float:
        if self.compared_fields == 0:
            return 0.0
        return self.matched_fields / self.compared_fields


def validate_pcap_with_tshark(
    pcap_path: str | Path,
    *,
    tshark_path: str = "tshark",
) -> ValidationSummary:
    """Compara el parser propio contra campos extraidos por tshark."""
    if shutil.which(tshark_path) is None:
        raise RuntimeError(
            f"No se encontro '{tshark_path}'. Instale Wireshark/tshark o agreguelo al PATH."
        )

    packets = list(iter_pcap_transport_headers(pcap_path))
    rows = read_tshark_rows(pcap_path, tshark_path=tshark_path)
    return compare_packets_to_tshark_rows(packets, rows)


def read_tshark_rows(
    pcap_path: str | Path,
    *,
    tshark_path: str = "tshark",
) -> list[TsharkRow]:
    command = [
        tshark_path,
        "-r",
        str(pcap_path),
        "-Y",
        "tcp or udp",
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
    ]
    for field in TSHARK_FIELDS:
        command.extend(["-e", field])

    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return parse_tshark_csv(completed.stdout.splitlines())


def parse_tshark_csv(lines: Iterable[str]) -> list[TsharkRow]:
    rows: list[TsharkRow] = []
    reader = csv.reader(lines)

    for raw_row in reader:
        if not raw_row:
            continue

        padded = raw_row + [""] * (len(TSHARK_FIELDS) - len(raw_row))
        fields = dict(zip(TSHARK_FIELDS, padded, strict=False))
        protocol = "TCP" if fields["tcp.srcport"] else "UDP"
        frame_number_text = fields.get("frame.number", "")
        rows.append(
            TsharkRow(
                source_ip=fields["ip.src"],
                destination_ip=fields["ip.dst"],
                protocol=protocol,
                fields=fields,
                frame_number=int(frame_number_text) if frame_number_text else None,
            )
        )

    return rows


def compare_packets_to_tshark_rows(
    packets: Sequence[TransportPacket],
    rows: Sequence[TsharkRow],
) -> ValidationSummary:
    pairs, unmatched_own, unmatched_tshark = _pair_packets_with_rows(packets, rows)
    mismatches: list[FieldMismatch] = []
    compared_fields = 0

    for index, (packet, row) in enumerate(pairs):
        own_fields = _packet_fields(packet)
        tshark_fields = _row_fields(row)

        for field, own_value in own_fields.items():
            compared_fields += 1
            tshark_value = tshark_fields.get(field, "")
            if own_value != tshark_value:
                mismatches.append(
                    FieldMismatch(
                        packet_index=index,
                        field=field,
                        own_value=own_value,
                        tshark_value=tshark_value,
                    )
                )

    return ValidationSummary(
        compared_packets=len(pairs),
        compared_fields=compared_fields,
        mismatches=tuple(mismatches),
        unmatched_own_packets=unmatched_own,
        unmatched_tshark_rows=unmatched_tshark,
    )


def _pair_packets_with_rows(
    packets: Sequence[TransportPacket],
    rows: Sequence[TsharkRow],
) -> tuple[list[tuple[TransportPacket, TsharkRow]], int, int]:
    """Empareja paquetes propios con filas de tshark por `frame.number`.

    Emparejar por posicion se rompe si tshark incluye algun frame que el
    parser propio no soporta (p. ej. IPv6): todo lo que sigue queda
    desalineado y el "mismatch" se propaga en cascada. El numero de frame es
    un identificador estable del mismo paquete fisico en el .pcap para ambas
    herramientas, sin importar que cada una filtre un subconjunto distinto.
    """
    has_frame_numbers = bool(packets) and bool(rows) and all(
        packet.frame_number is not None for packet in packets
    ) and all(row.frame_number is not None for row in rows)

    if not has_frame_numbers:
        # Sin numero de frame (p. ej. en pruebas unitarias con datos sintéticos),
        # se cae de vuelta al emparejado posicional original.
        size = min(len(packets), len(rows))
        pairs = list(zip(packets[:size], rows[:size], strict=False))
        return pairs, len(packets) - size, len(rows) - size

    rows_by_frame = {row.frame_number: row for row in rows}
    matched_frames: set[int] = set()
    pairs = []
    for packet in packets:
        row = rows_by_frame.get(packet.frame_number)
        if row is not None:
            pairs.append((packet, row))
            matched_frames.add(packet.frame_number)

    unmatched_own = len(packets) - len(pairs)
    unmatched_tshark = len(rows) - len(matched_frames)
    return pairs, unmatched_own, unmatched_tshark


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Valida parser propio contra tshark")
    parser.add_argument("pcap", help="Ruta del archivo .pcap")
    parser.add_argument("--tshark", default="tshark", help="Ruta o nombre del binario tshark")
    args = parser.parse_args(argv)

    summary = validate_pcap_with_tshark(args.pcap, tshark_path=args.tshark)
    print(f"Paquetes comparados: {summary.compared_packets}")
    print(f"Campos comparados  : {summary.compared_fields}")
    print(f"Coincidencia       : {summary.match_ratio:.2%}")
    if summary.unmatched_own_packets or summary.unmatched_tshark_rows:
        print(
            f"Sin pareja         : {summary.unmatched_own_packets} del parser propio, "
            f"{summary.unmatched_tshark_rows} de tshark (p. ej. IPv6, no soportado)"
        )

    if summary.mismatches:
        print("\nDiferencias:")
        for mismatch in summary.mismatches[:25]:
            print(
                f"  pkt={mismatch.packet_index} field={mismatch.field} "
                f"own={mismatch.own_value} tshark={mismatch.tshark_value}"
            )


def _packet_fields(packet: TransportPacket) -> dict[str, str]:
    header = packet.header
    base = {
        "source_ip": packet.source_ip,
        "destination_ip": packet.destination_ip,
        "protocol": packet.protocol,
    }

    if isinstance(header, TCPHeader):
        base.update(
            {
                "source_port": str(header.source_port),
                "destination_port": str(header.destination_port),
                "sequence_number": str(header.sequence_number),
                "acknowledgment_number": str(header.acknowledgment_number),
                "header_length": str(header.header_length),
                "flags_value": f"0x{header.flags_value:03x}",
                "window_size": str(header.window_size),
                "checksum": f"0x{header.checksum:04x}",
            }
        )
    elif isinstance(header, UDPHeader):
        base.update(
            {
                "source_port": str(header.source_port),
                "destination_port": str(header.destination_port),
                "length": str(header.length),
                "checksum": f"0x{header.checksum:04x}",
            }
        )

    return base


def _row_fields(row: TsharkRow) -> dict[str, str]:
    fields = row.fields
    base = {
        "source_ip": row.source_ip,
        "destination_ip": row.destination_ip,
        "protocol": row.protocol,
    }

    if row.protocol == "TCP":
        base.update(
            {
                "source_port": fields["tcp.srcport"],
                "destination_port": fields["tcp.dstport"],
                "sequence_number": fields["tcp.seq_raw"],
                "acknowledgment_number": fields["tcp.ack_raw"],
                "header_length": fields["tcp.hdr_len"],
                "flags_value": _normalize_hex(fields["tcp.flags"], width=3),
                "window_size": fields["tcp.window_size_value"],
                "checksum": _normalize_hex(fields["tcp.checksum"], width=4),
            }
        )
    else:
        base.update(
            {
                "source_port": fields["udp.srcport"],
                "destination_port": fields["udp.dstport"],
                "length": fields["udp.length"],
                "checksum": _normalize_hex(fields["udp.checksum"], width=4),
            }
        )

    return base


def _normalize_hex(value: str, *, width: int) -> str:
    if not value:
        return ""
    return f"0x{int(value, 0):0{width}x}"


if __name__ == "__main__":
    main()

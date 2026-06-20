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
)


@dataclass(frozen=True)
class TsharkRow:
    source_ip: str
    destination_ip: str
    protocol: str
    fields: dict[str, str]


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
        rows.append(
            TsharkRow(
                source_ip=fields["ip.src"],
                destination_ip=fields["ip.dst"],
                protocol=protocol,
                fields=fields,
            )
        )

    return rows


def compare_packets_to_tshark_rows(
    packets: Sequence[TransportPacket],
    rows: Sequence[TsharkRow],
) -> ValidationSummary:
    compared_packets = min(len(packets), len(rows))
    mismatches: list[FieldMismatch] = []
    compared_fields = 0

    for index in range(compared_packets):
        packet = packets[index]
        row = rows[index]
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

    if len(packets) != len(rows):
        mismatches.append(
            FieldMismatch(
                packet_index=compared_packets,
                field="packet_count",
                own_value=str(len(packets)),
                tshark_value=str(len(rows)),
            )
        )

    return ValidationSummary(
        compared_packets=compared_packets,
        compared_fields=compared_fields,
        mismatches=tuple(mismatches),
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Valida parser propio contra tshark")
    parser.add_argument("pcap", help="Ruta del archivo .pcap")
    parser.add_argument("--tshark", default="tshark", help="Ruta o nombre del binario tshark")
    args = parser.parse_args(argv)

    summary = validate_pcap_with_tshark(args.pcap, tshark_path=args.tshark)
    print(f"Paquetes comparados: {summary.compared_packets}")
    print(f"Campos comparados  : {summary.compared_fields}")
    print(f"Coincidencia       : {summary.match_ratio:.2%}")

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

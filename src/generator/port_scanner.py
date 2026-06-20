from __future__ import annotations

import argparse
import socket
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass


DEFAULT_SCAN_TIMEOUT = 0.5


@dataclass(frozen=True)
class PortScanResult:
    host: str
    port: int
    status: str
    latency_ms: float | None
    error: str | None = None


def scan_tcp_ports(
    host: str,
    ports: Iterable[int],
    *,
    timeout: float = DEFAULT_SCAN_TIMEOUT,
) -> list[PortScanResult]:
    """Escaner TCP connect propio para generar trafico de escaneo controlado."""
    results: list[PortScanResult] = []

    for port in ports:
        started = time.perf_counter()
        status = "closed"
        latency_ms: float | None = None
        error: str | None = None

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                code = sock.connect_ex((host, port))
                latency_ms = (time.perf_counter() - started) * 1000
                status = "open" if code == 0 else "closed"
                if code not in (0,):
                    error = _socket_error_name(code)
            except socket.timeout:
                latency_ms = (time.perf_counter() - started) * 1000
                status = "filtered"
                error = "timeout"
            except OSError as exc:
                latency_ms = (time.perf_counter() - started) * 1000
                status = "error"
                error = exc.strerror or str(exc)

        results.append(
            PortScanResult(
                host=host,
                port=port,
                status=status,
                latency_ms=latency_ms,
                error=error,
            )
        )

    return results


def parse_port_range(port_range: str) -> list[int]:
    """Convierte '80,443,5000-5010' en una lista ordenada de puertos unicos."""
    ports: set[int] = set()

    for chunk in port_range.split(","):
        part = chunk.strip()
        if not part:
            continue

        if "-" in part:
            start_text, end_text = part.split("-", maxsplit=1)
            start = _parse_port(start_text)
            end = _parse_port(end_text)
            if start > end:
                raise ValueError("El rango de puertos debe ir de menor a mayor")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(part))

    if not ports:
        raise ValueError("Debe indicar al menos un puerto")

    return sorted(ports)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Escaner TCP connect propio para la red controlada"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host destino")
    parser.add_argument(
        "--ports",
        default="5000-5100",
        help="Puertos a escanear, por ejemplo: 22,80,5000-5100",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_SCAN_TIMEOUT,
        help="Timeout por puerto en segundos",
    )
    args = parser.parse_args(argv)

    results = scan_tcp_ports(
        args.host,
        parse_port_range(args.ports),
        timeout=args.timeout,
    )

    for result in results:
        latency = "-" if result.latency_ms is None else f"{result.latency_ms:.2f} ms"
        print(f"{result.host}:{result.port:<5} {result.status:<8} {latency}")


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"Puerto invalido: {value}") from exc

    if not 1 <= port <= 65535:
        raise ValueError(f"Puerto fuera de rango: {port}")
    return port


def _socket_error_name(code: int) -> str:
    try:
        return socket.errorTab.get(code, f"errno {code}")  # type: ignore[attr-defined]
    except AttributeError:
        return f"errno {code}"


if __name__ == "__main__":
    main()

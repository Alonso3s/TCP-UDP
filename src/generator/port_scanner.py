from __future__ import annotations

import argparse
import os
import select
import socket
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


# En esta red controlada, un puerto cerrado en loopback tarda ~2s en devolver el
# rechazo (el adaptador de loopback de Npcap intercepta el trafico antes de que
# el sistema genere el RST). Un timeout corto clasificaria todo como "filtered"
# en vez de "closed". Escanear en paralelo evita pagar ese costo por puerto.
DEFAULT_SCAN_TIMEOUT = 2.5
DEFAULT_MAX_WORKERS = 50


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
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> list[PortScanResult]:
    """Escaner TCP connect propio para generar trafico de escaneo controlado.

    Escanea en paralelo: el costo de un puerto que no responde se paga una sola
    vez para todo el lote, no una vez por puerto.
    """
    port_list = list(ports)
    if not port_list:
        return []

    workers = max(1, min(max_workers, len(port_list)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda port: _scan_one_port(host, port, timeout), port_list))


def _scan_one_port(host: str, port: int, timeout: float) -> PortScanResult:
    """Conecta sin bloquear y espera con select() en vez de connect_ex() bloqueante.

    En Windows, connect_ex() con socket bloqueante+timeout solo revisa
    writefds; un puerto cerrado (RST) se reporta en exceptfds y por eso
    connect_ex() se queda esperando el timeout completo en vez de fallar al
    instante. Vigilando tambien exceptfds, los puertos cerrados responden en
    milisegundos como en cualquier otro sistema.
    """
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)

    try:
        try:
            sock.connect((host, port))
        except BlockingIOError:
            pass
        except OSError as exc:
            return PortScanResult(
                host=host,
                port=port,
                status="error",
                latency_ms=_elapsed_ms(started),
                error=exc.strerror or str(exc),
            )

        _, writable, exceptional = select.select([], [sock], [sock], timeout)

        if not writable and not exceptional:
            return PortScanResult(
                host=host,
                port=port,
                status="filtered",
                latency_ms=_elapsed_ms(started),
                error="timeout",
            )

        error_code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        latency_ms = _elapsed_ms(started)
        if error_code == 0:
            return PortScanResult(host=host, port=port, status="open", latency_ms=latency_ms)

        return PortScanResult(
            host=host,
            port=port,
            status="closed",
            latency_ms=latency_ms,
            error=_socket_error_name(error_code),
        )
    finally:
        sock.close()


def _elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


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
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="Cantidad de conexiones en paralelo",
    )
    args = parser.parse_args(argv)

    results = scan_tcp_ports(
        args.host,
        parse_port_range(args.ports),
        timeout=args.timeout,
        max_workers=args.workers,
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
    # En Windows, los codigos de socket son de WinSock (p. ej. 10061), no los
    # errno de la librería C que entiende os.strerror; socket.errorTab los
    # traduce correctamente. En POSIX no existe esa tabla y os.strerror basta.
    error_tab = getattr(socket, "errorTab", None)
    if error_tab and code in error_tab:
        return error_tab[code]
    try:
        return os.strerror(code)
    except ValueError:
        return f"errno {code}"


if __name__ == "__main__":
    main()

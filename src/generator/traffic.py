from __future__ import annotations

import argparse
import socket
from collections.abc import Iterable, Sequence


DEFAULT_HOST = "127.0.0.1"
DEFAULT_TCP_PORT = 5000
DEFAULT_UDP_PORT = 5001
DEFAULT_MESSAGES = (
    "grupo5 tcp udp",
    "mensaje de prueba",
    "fin de transmision",
)


def send_tcp_messages(
    host: str,
    port: int,
    messages: Iterable[str | bytes],
    *,
    timeout: float = 3.0,
    encoding: str = "utf-8",
) -> list[bytes]:
    """Envia mensajes por TCP y retorna las respuestas del servidor."""
    responses: list[bytes] = []

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        for message in messages:
            data = _to_bytes(message, encoding)
            sock.sendall(data)
            responses.append(sock.recv(4096))

    return responses


def send_udp_messages(
    host: str,
    port: int,
    messages: Iterable[str | bytes],
    *,
    timeout: float = 3.0,
    wait_response: bool = True,
    encoding: str = "utf-8",
) -> list[bytes]:
    """Envia datagramas UDP y, si se pide, retorna las respuestas recibidas."""
    responses: list[bytes] = []

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for message in messages:
            data = _to_bytes(message, encoding)
            sock.sendto(data, (host, port))

            if wait_response:
                response, _address = sock.recvfrom(4096)
                responses.append(response)

    return responses


def run_tcp_echo_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_TCP_PORT,
    *,
    max_connections: int = 1,
    timeout: float | None = None,
) -> int:
    """Servidor TCP echo bloqueante para generar sesiones TCP completas."""
    handled_connections = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
        server.settimeout(timeout)

        while handled_connections < max_connections:
            connection, _address = server.accept()
            handled_connections += 1

            with connection:
                connection.settimeout(timeout)
                while True:
                    data = connection.recv(4096)
                    if not data:
                        break
                    connection.sendall(data)

    return handled_connections


def run_udp_echo_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_UDP_PORT,
    *,
    max_datagrams: int = 3,
    timeout: float | None = None,
) -> int:
    """Servidor UDP echo bloqueante para generar datagramas UDP."""
    handled_datagrams = 0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((host, port))
        server.settimeout(timeout)

        while handled_datagrams < max_datagrams:
            data, address = server.recvfrom(4096)
            handled_datagrams += 1
            server.sendto(data, address)

    return handled_datagrams


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Generador reproducible de trafico TCP/UDP con sockets"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_server_args(subparsers.add_parser("tcp-server", help="Servidor TCP echo"))
    _add_client_args(subparsers.add_parser("tcp-client", help="Cliente TCP"))
    _add_server_args(
        subparsers.add_parser("udp-server", help="Servidor UDP echo"),
        default_port=DEFAULT_UDP_PORT,
        counter_name="datagrams",
    )
    _add_client_args(
        subparsers.add_parser("udp-client", help="Cliente UDP"),
        default_port=DEFAULT_UDP_PORT,
    )

    args = parser.parse_args(argv)
    messages = getattr(args, "messages", None) or list(DEFAULT_MESSAGES)

    if args.command == "tcp-server":
        total = run_tcp_echo_server(
            args.host,
            args.port,
            max_connections=args.count,
            timeout=args.timeout,
        )
        print(f"Conexiones TCP atendidas: {total}")
    elif args.command == "tcp-client":
        responses = send_tcp_messages(args.host, args.port, messages, timeout=args.timeout)
        _print_responses(responses)
    elif args.command == "udp-server":
        total = run_udp_echo_server(
            args.host,
            args.port,
            max_datagrams=args.count,
            timeout=args.timeout,
        )
        print(f"Datagramas UDP atendidos: {total}")
    elif args.command == "udp-client":
        responses = send_udp_messages(args.host, args.port, messages, timeout=args.timeout)
        _print_responses(responses)


def _add_server_args(
    parser: argparse.ArgumentParser,
    *,
    default_port: int = DEFAULT_TCP_PORT,
    counter_name: str = "connections",
) -> None:
    parser.add_argument("--host", default=DEFAULT_HOST, help="IP local donde escuchar")
    parser.add_argument("--port", type=int, default=default_port, help="Puerto local")
    parser.add_argument(
        "--count",
        type=int,
        default=1 if counter_name == "connections" else len(DEFAULT_MESSAGES),
        help="Cantidad maxima de conexiones o datagramas",
    )
    parser.add_argument("--timeout", type=float, help="Tiempo maximo de espera")


def _add_client_args(
    parser: argparse.ArgumentParser,
    *,
    default_port: int = DEFAULT_TCP_PORT,
) -> None:
    parser.add_argument("--host", default=DEFAULT_HOST, help="IP destino")
    parser.add_argument("--port", type=int, default=default_port, help="Puerto destino")
    parser.add_argument("--timeout", type=float, default=3.0, help="Tiempo maximo de espera")
    parser.add_argument("messages", nargs="*", help="Mensajes a enviar")


def _print_responses(responses: Iterable[bytes]) -> None:
    for index, response in enumerate(responses, start=1):
        print(f"Respuesta {index}: {response.decode('utf-8', errors='replace')}")


def _to_bytes(message: str | bytes, encoding: str) -> bytes:
    if isinstance(message, bytes):
        return message
    return message.encode(encoding)


if __name__ == "__main__":
    main()

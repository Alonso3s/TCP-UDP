from __future__ import annotations

import socket
import threading

from src.generator import send_tcp_messages, send_udp_messages


def test_send_tcp_messages_to_echo_server():
    ready = threading.Event()
    port_holder: list[int] = []
    server_thread = threading.Thread(
        target=_tcp_echo_server_once,
        args=(ready, port_holder),
        daemon=True,
    )
    server_thread.start()
    ready.wait(timeout=2)

    responses = send_tcp_messages(
        "127.0.0.1",
        port_holder[0],
        ["hola", "tcp"],
    )

    server_thread.join(timeout=2)
    assert responses == [b"hola", b"tcp"]


def test_send_udp_messages_to_echo_server():
    ready = threading.Event()
    port_holder: list[int] = []
    server_thread = threading.Thread(
        target=_udp_echo_server,
        args=(ready, port_holder, 2),
        daemon=True,
    )
    server_thread.start()
    ready.wait(timeout=2)

    responses = send_udp_messages(
        "127.0.0.1",
        port_holder[0],
        ["hola", "udp"],
    )

    server_thread.join(timeout=2)
    assert responses == [b"hola", b"udp"]


def _tcp_echo_server_once(ready: threading.Event, port_holder: list[int]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port_holder.append(server.getsockname()[1])
        ready.set()

        connection, _address = server.accept()
        with connection:
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                connection.sendall(data)


def _udp_echo_server(
    ready: threading.Event,
    port_holder: list[int],
    max_datagrams: int,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        port_holder.append(server.getsockname()[1])
        ready.set()

        for _ in range(max_datagrams):
            data, address = server.recvfrom(4096)
            server.sendto(data, address)

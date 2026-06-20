from __future__ import annotations

import socket
import threading

import pytest

from src.generator import parse_port_range, scan_tcp_ports


def test_parse_port_range_accepts_single_ports_and_ranges():
    assert parse_port_range("5002,5000-5001,5001") == [5000, 5001, 5002]


def test_parse_port_range_rejects_invalid_values():
    with pytest.raises(ValueError, match="fuera de rango"):
        parse_port_range("0")

    with pytest.raises(ValueError, match="menor a mayor"):
        parse_port_range("5002-5000")


def test_scan_tcp_ports_marks_open_local_port():
    ready = threading.Event()
    port_holder: list[int] = []
    server_thread = threading.Thread(
        target=_tcp_server_once,
        args=(ready, port_holder),
        daemon=True,
    )
    server_thread.start()
    ready.wait(timeout=2)

    results = scan_tcp_ports("127.0.0.1", [port_holder[0]], timeout=1.0)

    server_thread.join(timeout=2)
    assert len(results) == 1
    assert results[0].status == "open"
    assert results[0].latency_ms is not None


def _tcp_server_once(ready: threading.Event, port_holder: list[int]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port_holder.append(server.getsockname()[1])
        ready.set()

        connection, _address = server.accept()
        connection.close()

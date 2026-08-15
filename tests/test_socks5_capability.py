from __future__ import annotations

import importlib.util
import json
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "roles" / "operations" / "files" / "ru-proxy-capability.py"
SPEC = importlib.util.spec_from_file_location("ru_proxy_capability", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def receive_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        result.extend(connection.recv(size - len(result)))
    return bytes(result)


class Socks5CapabilityTests(unittest.TestCase):
    def assert_udp_associate(self, username: str = "", password: str = "") -> None:
        errors: list[BaseException] = []
        ready = threading.Event()
        udp_done = threading.Event()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay, socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        ) as server:
            relay.bind(("127.0.0.1", 0))
            relay.settimeout(3)
            relay_port = relay.getsockname()[1]
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            server_port = server.getsockname()[1]

            def serve_tcp() -> None:
                try:
                    ready.set()
                    connection, _ = server.accept()
                    with connection:
                        version, count = receive_exact(connection, 2)
                        self.assertEqual(version, 5)
                        methods = receive_exact(connection, count)
                        selected_method = 2 if username else 0
                        self.assertIn(selected_method, methods)
                        connection.sendall(bytes([5, selected_method]))
                        if username:
                            auth_version, user_length = receive_exact(connection, 2)
                            self.assertEqual(auth_version, 1)
                            self.assertEqual(receive_exact(connection, user_length).decode(), username)
                            password_length = receive_exact(connection, 1)[0]
                            self.assertEqual(receive_exact(connection, password_length).decode(), password)
                            connection.sendall(b"\x01\x00")
                        self.assertEqual(receive_exact(connection, 10), b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                        connection.sendall(
                            b"\x05\x00\x00\x01\x7f\x00\x00\x01"
                            + relay_port.to_bytes(2, "big")
                        )
                        udp_done.wait(3)
                except BaseException as error:  # Передаём ошибку основному потоку теста.
                    errors.append(error)

            def serve_udp() -> None:
                try:
                    packet, address = relay.recvfrom(4096)
                    self.assertGreaterEqual(len(packet), 22)
                    transaction = packet[10:12]
                    dns_response = transaction + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
                    relay.sendto(packet[:10] + dns_response, address)
                except BaseException as error:  # Передаём ошибку основному потоку теста.
                    errors.append(error)
                finally:
                    udp_done.set()

            tcp_thread = threading.Thread(target=serve_tcp)
            udp_thread = threading.Thread(target=serve_udp)
            tcp_thread.start()
            udp_thread.start()
            ready.wait(1)
            with tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "config.json"
                outbound = {
                    "tag": "ru-socks",
                    "server": "127.0.0.1",
                    "server_port": server_port,
                }
                if username:
                    outbound.update({"username": username, "password": password})
                config.write_text(json.dumps({"outbounds": [outbound]}), encoding="utf-8")
                self.assertTrue(MODULE.udp_supported(config, timeout=2))
            tcp_thread.join(3)
            udp_thread.join(3)
        if errors:
            raise errors[0]

    def test_udp_associate_without_authentication(self) -> None:
        self.assert_udp_associate()

    def test_udp_associate_with_authentication(self) -> None:
        self.assert_udp_associate("proxy-user", "proxy-password")

    def test_save_mode_replaces_only_changed_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "proxy-udp.mode"
            MODULE.save_mode(state, "direct")
            first_mtime = state.stat().st_mtime_ns
            MODULE.save_mode(state, "direct")
            self.assertEqual(state.stat().st_mtime_ns, first_mtime)
            MODULE.save_mode(state, "proxy")
            self.assertEqual(state.read_text(encoding="ascii"), "proxy\n")

    def test_authentication_failure_never_becomes_direct_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "proxy-udp.mode"
            config = Path(directory) / "config.json"
            config.write_text('{"outbounds": []}', encoding="utf-8")
            with (
                mock.patch.object(
                    MODULE, "udp_supported", side_effect=PermissionError("denied")
                ),
                mock.patch.object(
                    sys,
                    "argv",
                    ["ru-proxy-capability", "--config", str(config),
                     "--state", str(state), "--update-state"],
                ),
            ):
                self.assertEqual(MODULE.main(), MODULE.EXIT_NO_PERMISSION)
            self.assertFalse(state.exists())

    def test_operations_role_accepts_only_transient_proxy_errors(self) -> None:
        tasks = (
            ROOT / "roles" / "operations" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "operations_ru_proxy_capability.rc not in [0, 68, 69]",
            tasks,
        )
        self.assertIn("content: \"direct\\n\"", tasks)
        self.assertNotIn("operations_ru_proxy_capability.rc not in [0, 2]", tasks)

    def test_explicit_udp_rejection_selects_direct_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "proxy-udp.mode"
            config = Path(directory) / "config.json"
            config.write_text('{"outbounds": []}', encoding="utf-8")
            with (
                mock.patch.object(MODULE, "udp_supported", return_value=False),
                mock.patch.object(
                    sys,
                    "argv",
                    ["ru-proxy-capability", "--config", str(config),
                     "--state", str(state), "--update-state"],
                ),
            ):
                self.assertEqual(MODULE.main(), 0)
            self.assertEqual(state.read_text(encoding="ascii"), "direct\n")

    def test_tcp_probe_failure_is_not_reported_as_available_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "proxy-udp.mode"
            config = Path(directory) / "config.json"
            config.write_text('{"outbounds": []}', encoding="utf-8")
            with (
                mock.patch.object(MODULE, "udp_supported", return_value=True),
                mock.patch.object(
                    MODULE,
                    "tcp_https_probe",
                    side_effect=RuntimeError("TCP CONNECT timeout"),
                ),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "ru-proxy-capability",
                        "--config",
                        str(config),
                        "--state",
                        str(state),
                        "--update-state",
                        "--tcp-probe-url",
                        "https://api.ipify.org",
                    ],
                ),
            ):
                self.assertEqual(MODULE.main(), MODULE.EXIT_UNAVAILABLE)
            self.assertFalse(state.exists())

    def test_name_resolution_failure_has_a_distinct_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text('{"outbounds": []}', encoding="utf-8")
            with (
                mock.patch.object(
                    MODULE,
                    "udp_supported",
                    side_effect=socket.gaierror(-3, "Temporary failure in name resolution"),
                ),
                mock.patch.object(
                    sys,
                    "argv",
                    ["ru-proxy-capability", "--config", str(config)],
                ),
            ):
                self.assertEqual(MODULE.main(), MODULE.EXIT_NO_HOST)

    def test_tcp_probe_uses_ipv4_destination_like_tun_traffic(self) -> None:
        request_parts: list[bytes] = []

        class FakeSocket:
            def __init__(self) -> None:
                self.responses = bytearray(
                    b"\x05\x00"
                    b"\x05\x00\x00\x01"
                    b"\x7f\x00\x00\x01"
                    b"\x00\x50"
                )

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout: int) -> None:
                return None

            def sendall(self, value: bytes) -> None:
                request_parts.append(value)

            def recv(self, size: int) -> bytes:
                value = bytes(self.responses[:size])
                del self.responses[:size]
                return value

        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(
                json.dumps(
                    {"outbounds": [{"tag": "ru-socks", "server": "proxy.test", "server_port": 1080}]}
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(MODULE.socket, "create_connection", return_value=FakeSocket()),
                mock.patch.object(
                    MODULE.socket,
                    "getaddrinfo",
                    return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 443))],
                ),
                mock.patch.object(MODULE.ssl, "create_default_context", side_effect=RuntimeError("stop after CONNECT")),
            ):
                with self.assertRaisesRegex(RuntimeError, "stop after CONNECT"):
                    MODULE.tcp_https_probe(config, "https://api.ipify.org", timeout=2)

        connect_request = request_parts[-1]
        self.assertEqual(connect_request[:4], b"\x05\x01\x00\x01")
        self.assertEqual(connect_request[4:8], socket.inet_aton("203.0.113.10"))


if __name__ == "__main__":
    unittest.main()

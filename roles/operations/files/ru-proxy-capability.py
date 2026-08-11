#!/usr/bin/env python3
"""Безопасно проверить SOCKS5 UDP ASSOCIATE и сохранить выбранный режим UDP."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import sys
from pathlib import Path
from urllib.parse import urlsplit


TIMEOUT = 7


def receive_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise RuntimeError("SOCKS5 закрыл соединение")
        result.extend(part)
    return bytes(result)


def receive_address(connection: socket.socket, address_type: int) -> str:
    if address_type == 1:
        return socket.inet_ntop(socket.AF_INET, receive_exact(connection, 4))
    if address_type == 4:
        return socket.inet_ntop(socket.AF_INET6, receive_exact(connection, 16))
    if address_type == 3:
        length = receive_exact(connection, 1)[0]
        return receive_exact(connection, length).decode("ascii")
    raise RuntimeError("SOCKS5 вернул неизвестный тип адреса")


def skip_udp_address(packet: bytes, offset: int, address_type: int) -> int:
    if address_type == 1:
        return offset + 4
    if address_type == 4:
        return offset + 16
    if address_type == 3:
        return offset + 1 + packet[offset]
    raise RuntimeError("SOCKS5 UDP вернул неизвестный тип адреса")


def dns_query(transaction: bytes) -> bytes:
    labels = b"".join(bytes([len(label)]) + label for label in b"example.com".split(b"."))
    return transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x00\x01\x00\x01"


def load_proxy(config: Path) -> tuple[str, int, str, str]:
    document = json.loads(config.read_text(encoding="utf-8"))
    outbound = next(item for item in document["outbounds"] if item.get("tag") == "ru-socks")
    return (
        str(outbound["server"]),
        int(outbound["server_port"]),
        str(outbound.get("username", "")),
        str(outbound.get("password", "")),
    )


def authenticate_socks5(
    connection: socket.socket, username: str, password: str
) -> None:
    methods = [0, 2] if username else [0]
    connection.sendall(bytes([5, len(methods), *methods]))
    version, method = receive_exact(connection, 2)
    if version != 5 or method == 255:
        raise RuntimeError("SOCKS5 отклонил доступные методы аутентификации")
    if method == 2:
        user = username.encode("utf-8")
        secret = password.encode("utf-8")
        if not (1 <= len(user) <= 255 and 1 <= len(secret) <= 255):
            raise RuntimeError("Учётные данные SOCKS5 имеют недопустимую длину")
        connection.sendall(bytes([1, len(user)]) + user + bytes([len(secret)]) + secret)
        if receive_exact(connection, 2) != b"\x01\x00":
            raise PermissionError("SOCKS5 отклонил имя пользователя или пароль")
    elif method != 0:
        raise RuntimeError("SOCKS5 выбрал неподдерживаемый метод аутентификации")


def udp_supported(config: Path, timeout: int = TIMEOUT) -> bool:
    host, port, username, password = load_proxy(config)
    with socket.create_connection((host, port), timeout=timeout) as control:
        control.settimeout(timeout)
        authenticate_socks5(control, username, password)

        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        version, reply, reserved, address_type = receive_exact(control, 4)
        if version != 5 or reserved != 0:
            raise RuntimeError("SOCKS5 вернул повреждённый ответ UDP ASSOCIATE")
        if reply == 7:
            return False
        if reply != 0:
            raise RuntimeError(f"SOCKS5 не выполнил UDP ASSOCIATE, код {reply}")
        relay_host = receive_address(control, address_type)
        relay_port = struct.unpack("!H", receive_exact(control, 2))[0]
        try:
            relay_ip = ipaddress.ip_address(relay_host)
            if relay_ip.is_unspecified:
                relay_host = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[0][4][0]
        except ValueError:
            pass

        relay = socket.getaddrinfo(relay_host, relay_port, 0, socket.SOCK_DGRAM)[0]
        transaction = secrets.token_bytes(2)
        payload = dns_query(transaction)
        request = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53) + payload
        with socket.socket(relay[0], socket.SOCK_DGRAM) as udp:
            udp.settimeout(timeout)
            udp.sendto(request, relay[4])
            response, _ = udp.recvfrom(4096)
        if len(response) < 10 or response[:3] != b"\x00\x00\x00":
            return False
        offset = skip_udp_address(response, 4, response[3]) + 2
        dns_response = response[offset:]
        return len(dns_response) >= 12 and dns_response[:2] == transaction and bool(dns_response[2] & 0x80)


def tcp_https_probe(
    config: Path, probe_url: str, expected_ip: str = "", timeout: int = TIMEOUT
) -> str:
    """Проверить SOCKS5 CONNECT, TLS и HTTPS напрямую, не раскрывая учётные данные."""
    target = urlsplit(probe_url)
    if target.scheme != "https" or not target.hostname:
        raise ValueError("для TCP-проверки требуется корректный HTTPS URL")
    target_host = target.hostname
    target_port = target.port or 443
    target_addresses = socket.getaddrinfo(
        target_host, target_port, socket.AF_INET, socket.SOCK_STREAM
    )
    if not target_addresses:
        raise OSError("не удалось определить IPv4 узла TCP-проверки")
    target_ipv4 = target_addresses[0][4][0]

    proxy_host, proxy_port, username, password = load_proxy(config)
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as control:
        control.settimeout(timeout)
        authenticate_socks5(control, username, password)
        control.sendall(
            b"\x05\x01\x00\x01"
            + socket.inet_aton(target_ipv4)
            + struct.pack("!H", target_port)
        )
        version, reply, reserved, address_type = receive_exact(control, 4)
        if version != 5 or reserved != 0:
            raise RuntimeError("SOCKS5 вернул повреждённый ответ TCP CONNECT")
        if reply != 0:
            raise RuntimeError(f"SOCKS5 не выполнил TCP CONNECT, код {reply}")
        receive_address(control, address_type)
        receive_exact(control, 2)

        context = ssl.create_default_context()
        with context.wrap_socket(control, server_hostname=target_host) as secure:
            secure.settimeout(timeout)
            path = target.path or "/"
            if target.query:
                path += "?" + target.query
            secure.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                "Accept: text/plain\r\nConnection: close\r\n\r\n".encode("ascii")
            )
            response = bytearray()
            while len(response) < 65536:
                part = secure.recv(4096)
                if not part:
                    break
                response.extend(part)

    headers, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator or not headers.startswith(b"HTTP/"):
        raise RuntimeError("HTTPS-проверка вернула повреждённый ответ")
    try:
        status = int(headers.split(b"\r\n", 1)[0].split()[1])
    except (IndexError, ValueError) as error:
        raise RuntimeError("HTTPS-проверка не вернула код состояния") from error
    if not 200 <= status < 300:
        raise RuntimeError(f"HTTPS-проверка вернула код {status}")
    public_ip = body.decode("ascii").strip()
    try:
        parsed_ip = ipaddress.ip_address(public_ip)
    except ValueError as error:
        raise RuntimeError("HTTPS-проверка не вернула IP-адрес") from error
    if parsed_ip.version != 4:
        raise RuntimeError("HTTPS-проверка не вернула IPv4")
    if expected_ip and public_ip != expected_ip:
        raise RuntimeError("внешний IP SOCKS5 не совпадает с ожидаемым")
    return public_ip


def save_mode(state: Path, mode: str) -> bool:
    state.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    current = state.read_text(encoding="ascii").strip() if state.exists() else ""
    if current == mode:
        return False
    temporary = state.with_name(f".{state.name}.{os.getpid()}")
    temporary.write_text(mode + "\n", encoding="ascii")
    temporary.chmod(0o644)
    os.replace(temporary, state)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка UDP через настроенный SOCKS5")
    parser.add_argument("--config", type=Path, default=Path("/etc/sing-box/config.json"))
    parser.add_argument("--state", type=Path, default=Path("/var/lib/awg-routing/proxy-udp.mode"))
    parser.add_argument("--update-state", action="store_true", help="сохранить proxy или direct")
    parser.add_argument("--tcp-probe-url", help="дополнительно проверить SOCKS5 TCP/TLS/HTTPS")
    parser.add_argument("--expected-ip", default="", help="ожидаемый внешний IPv4")
    arguments = parser.parse_args()
    try:
        supported = udp_supported(arguments.config)
        if arguments.tcp_probe_url:
            tcp_https_probe(
                arguments.config,
                arguments.tcp_probe_url,
                arguments.expected_ip,
            )
    except (OSError, RuntimeError, ValueError, KeyError, StopIteration, json.JSONDecodeError) as error:
        print(f"Проверка SOCKS5 не выполнена: {error}", file=sys.stderr)
        return 2
    mode = "proxy" if supported else "direct"
    if arguments.update_state:
        if save_mode(arguments.state, mode):
            print("Режим UDP изменён")
    if supported:
        print("UDP через SOCKS5: поддерживается")
    else:
        print("UDP через SOCKS5: не поддерживается; RU UDP пойдёт напрямую через ENTRY")
    if arguments.tcp_probe_url:
        print("TCP/HTTPS через SOCKS5: поддерживается")
    if supported:
        return 0
    return 0 if arguments.update_state else 1


if __name__ == "__main__":
    raise SystemExit(main())

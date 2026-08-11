#!/usr/bin/env python3
"""Проверить расшифрованный Vault YAML из stdin без вывода чувствительных данных."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import sys

import yaml


def fail(message: str) -> None:
    print(f"Проверка Vault не пройдена: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_peers(document: dict, key: str, *, allow_empty: bool = False) -> int:
    peers = document.get(key)
    if not isinstance(peers, list) or (not peers and not allow_empty):
        suffix = "списком" if allow_empty else "непустым списком"
        fail(f"{key} должен быть {suffix}")
    names: set[str] = set()
    networks: set[str] = set()
    for peer in peers:
        if not isinstance(peer, dict):
            fail(f"{key} содержит элемент, который не является словарём")
        name = peer.get("name")
        public_key = peer.get("public_key")
        allowed = peer.get("allowed_ips")
        if not isinstance(name, str) or not name.strip() or name in names:
            fail(f"{key} содержит пустое или повторяющееся имя")
        names.add(name)
        if not isinstance(public_key, str) or len(public_key) < 40:
            fail(f"{key} содержит некорректное поле публичного ключа")
        if not isinstance(allowed, list) or not allowed:
            fail(f"{key} не содержит разрешённых IP-сетей")
        for value in allowed:
            try:
                network = str(ipaddress.ip_network(value, strict=True))
            except (TypeError, ValueError):
                fail(f"{key} содержит некорректную разрешённую IP-сеть")
            if network in networks:
                fail(f"{key} содержит повторяющиеся разрешённые IP-сети")
            networks.add(network)
    return len(peers)


def validate_key(document: dict, key: str) -> None:
    value = document.get(key)
    if not isinstance(value, str):
        fail(f"{key} отсутствует или имеет неверный тип")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        fail(f"{key} не является корректным Base64")
    if len(decoded) != 32:
        fail(f"{key} должен содержать 32 байта")


def main() -> None:
    try:
        document = yaml.safe_load(sys.stdin.read())
    except yaml.YAMLError:
        fail("некорректный YAML")
    if not isinstance(document, dict):
        fail("Верхний уровень YAML должен быть словарём")
    modern = validate_peers(document, "vault_entry_client_peers", allow_empty=True)
    legacy = validate_peers(
        document, "vault_entry_legacy_client_peers", allow_empty=True
    )
    mobile = (
        validate_peers(document, "vault_entry_mobile_client_peers", allow_empty=True)
        if "vault_entry_mobile_client_peers" in document
        else 0
    )
    if modern + legacy + mobile == 0:
        fail("требуется хотя бы один основной, совместимый либо мобильный клиент ENTRY")
    validate_peers(document, "vault_exit_peers")
    for key in (
        "vault_awg_entry_private_key",
        "vault_awg_entry_legacy_private_key",
        "vault_awg_entry_exit_private_key",
        "vault_awg_entry_exit_peer_public_key",
        "vault_awg_entry_exit_entry_public_key",
        "vault_awg_exit_private_key",
        "vault_awg_entry_exit_psk",
        "vault_awg3_header_protection_key",
    ):
        validate_key(document, key)
    if "vault_entry_mobile_client_peers" in document:
        validate_key(document, "vault_awg_entry_mobile_private_key")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Создать целиком зашифрованный тестовый Vault без вывода секретов."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import re
import stat
import subprocess
import shutil
from pathlib import Path

import yaml
from ansible.parsing.vault import VaultLib, VaultSecret


KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
KEY_TOOL = shutil.which("awg") or shutil.which("wg")


def fail(message: str) -> None:
    raise SystemExit(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--vault-password-file", required=True, type=Path)
    parser.add_argument("--client-secrets-file", required=True, type=Path)
    return parser.parse_args()


def command(name: str, stdin: str | None = None) -> str:
    if KEY_TOOL is None:
        fail("Установите amneziawg-tools или wireguard-tools на управляющем узле")
    try:
        result = subprocess.run(
            [KEY_TOOL, name],
            input=stdin,
            text=True,
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        fail("Локальная AWG-совместимая утилита завершилась с ошибкой без вывода ключей")
    value = result.stdout.strip()
    if not KEY_RE.fullmatch(value):
        fail("Локальная утилита awg вернула некорректный ключ, не выводя его")
    return value


def public_key(private_key: str) -> str:
    return command("pubkey", f"{private_key}\n")


def load_mapping(path: Path) -> dict:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        fail(f"Не удалось прочитать безопасную структуру inventory: {path}")
    if not isinstance(value, dict):
        fail(f"Ожидался словарь YAML: {path}")
    return value


def require_external(path: Path, repo_root: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return resolved
    fail(f"{label} должен находиться за пределами репозитория")


def exclusive_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    test_root = repo_root / "inventory" / "test"
    vault_path = test_root / "group_vars" / "all" / "vault.yml"
    if vault_path.exists():
        fail(f"Отказ от перезаписи существующего зашифрованного Vault: {vault_path}")
    if not (test_root / "hosts.yml").is_file():
        fail("Перед созданием Vault подготовьте и проверьте исключённый inventory/test")

    password_path = require_external(
        args.vault_password_file, repo_root, "Файл пароля Vault"
    )
    client_path = require_external(
        args.client_secrets_file, repo_root, "Файл секретов клиента"
    )
    if client_path.exists():
        fail(f"Отказ от перезаписи существующего файла секретов клиента: {client_path}")
    if not password_path.is_file():
        fail("Файл пароля Vault отсутствует")
    if stat.S_IMODE(password_path.stat().st_mode) & 0o077:
        fail("Файл пароля Vault не должен быть доступен группе или другим пользователям")
    vault_password = password_path.read_bytes().rstrip(b"\r\n")
    if not vault_password:
        fail("Файл пароля Vault пуст")

    all_vars = load_mapping(test_root / "group_vars" / "all" / "main.yml")
    entry_vars = load_mapping(test_root / "group_vars" / "entry.yml")
    interserver_address = all_vars.get("awg_interserver_entry_address")
    client_subnet = entry_vars.get("entry_client_subnet")
    try:
        client_network = ipaddress.ip_network(client_subnet, strict=True)
        client_hosts = client_network.hosts()
        next(client_hosts)
        client_address = str(next(client_hosts)) + "/32"
        ipaddress.ip_interface(interserver_address)
    except (TypeError, ValueError, StopIteration):
        fail("В тестовом inventory некорректна адресация клиента или межсерверного соединения")

    soax_username = getpass.getpass("Имя пользователя SOAX (ввод скрыт): ").strip()
    soax_password = getpass.getpass("Пароль SOAX (ввод скрыт): ").strip()
    if not soax_username or not soax_password:
        fail("Учётные данные SOAX не могут быть пустыми")

    entry_private = command("genkey")
    legacy_entry_private = command("genkey")
    mobile_entry_private = command("genkey")
    interserver_private = command("genkey")
    exit_private = command("genkey")
    interserver_psk = command("genpsk")
    client_private = command("genkey")
    client_psk = command("genpsk")

    document = {
        "vault_awg_entry_private_key": entry_private,
        "vault_awg_entry_legacy_private_key": legacy_entry_private,
        "vault_awg_entry_mobile_private_key": mobile_entry_private,
        "vault_awg_entry_exit_private_key": interserver_private,
        "vault_awg_entry_exit_peer_public_key": public_key(exit_private),
        "vault_awg_entry_exit_entry_public_key": public_key(interserver_private),
        "vault_awg_exit_private_key": exit_private,
        "vault_awg_entry_exit_psk": interserver_psk,
        "vault_awg3_header_protection_key": command("genkey"),
        "vault_proxy_username": soax_username,
        "vault_proxy_password": soax_password,
        "vault_entry_client_peers": [
            {
                "name": "acceptance-client",
                "public_key": public_key(client_private),
                "allowed_ips": [client_address],
                "preshared_key": client_psk,
            }
        ],
        "vault_entry_legacy_client_peers": [],
        "vault_entry_mobile_client_peers": [],
        "vault_exit_peers": [
            {
                "name": "entry",
                "public_key": public_key(interserver_private),
                "allowed_ips": [interserver_address],
                "preshared_key": interserver_psk,
            }
        ],
    }
    plaintext = yaml.safe_dump(document, sort_keys=False).encode("utf-8")
    encrypted = VaultLib([("default", VaultSecret(vault_password))]).encrypt(plaintext)
    decrypted = VaultLib([("default", VaultSecret(vault_password))]).decrypt(encrypted)
    if decrypted != plaintext:
        fail("Проверка шифрования Vault в памяти не пройдена")

    client_content = (
        f"AWG_CLIENT_PRIVATE_KEY={client_private}\n"
        f"AWG_CLIENT_PRESHARED_KEY={client_psk}\n"
        f"AWG_CLIENT_ADDRESS={client_address}\n"
    ).encode("utf-8")
    exclusive_write(client_path, client_content)
    try:
        exclusive_write(vault_path, encrypted)
    except BaseException:
        client_path.unlink(missing_ok=True)
        raise

    print(f"Создан зашифрованный тестовый Vault: {vault_path}")
    print(f"Секретные данные клиента созданы вне репозитория: {client_path}")
    print("Закрытые ключи, PSK, учётные данные и полная конфигурация клиента не выводились.")


if __name__ == "__main__":
    main()

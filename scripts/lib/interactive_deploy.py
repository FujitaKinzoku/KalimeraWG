#!/usr/bin/env python3
"""Интерактивный production-оркестратор ENTRY, EXIT и необязательного FRONT."""

from __future__ import annotations

import argparse
import atexit
import base64
import binascii
import getpass
import hashlib
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import textwrap
import urllib.request
from pathlib import Path

import yaml
from ansible.parsing.vault import VaultLib, VaultSecret
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def fail(message: str) -> None:
    raise SystemExit(message)


def telegram_credentials_valid(token: str, chat_id: str) -> bool:
    """Проверить структуру токена BotFather и числового Telegram chat ID."""
    return bool(
        re.fullmatch(r"[0-9]{6,20}:[A-Za-z0-9_-]{20,}", token)
        and re.fullmatch(r"-?[1-9][0-9]{0,19}", chat_id)
    )


def telegram_api_result(token: str, method: str) -> object | None:
    """Вызвать безопасный метод Bot API, не включая токен в сообщения ошибок."""
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        headers={"User-Agent": "KalimeraWG-Installer/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.load(response)
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        return None
    return payload.get("result")


def telegram_latest_chat_from_updates(updates: object) -> tuple[str, str] | None:
    """Извлечь последний доступный chat ID и безопасную подпись из updates."""
    if not isinstance(updates, list):
        return None
    for update in reversed(updates):
        if not isinstance(update, dict):
            continue
        candidates = [
            update.get("message"),
            update.get("edited_message"),
            update.get("channel_post"),
            update.get("my_chat_member"),
            update.get("chat_member"),
        ]
        callback = update.get("callback_query")
        if isinstance(callback, dict):
            candidates.append(callback.get("message"))
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            chat = candidate.get("chat")
            if not isinstance(chat, dict) or not isinstance(chat.get("id"), int):
                continue
            label = str(
                chat.get("title")
                or chat.get("username")
                or chat.get("first_name")
                or chat.get("type")
                or "Telegram chat"
            )
            return str(chat["id"]), label
    return None


def configure_line_editing() -> None:
    """Включить предсказуемое редактирование ввода в SSH, WSL и терминале."""
    try:
        import readline
    except ImportError:
        return

    # Терминалы передают Backspace как Ctrl-H либо DEL. Обрабатываем оба
    # варианта, чтобы пользователь мог исправить ввод и не видел символ ``^H``.
    readline.parse_and_bind('"\\C-h": backward-delete-char')
    readline.parse_and_bind('"\\C-?": backward-delete-char')


_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[1;31m",
    "green": "\033[1;32m",
    "yellow": "\033[1;33m",
    "blue": "\033[1;34m",
    "magenta": "\033[1;35m",
    "cyan": "\033[1;36m",
    "white": "\033[1;37m",
}

AWG3_COMPONENT_KEYS = (
    "awg3_go_version",
    "awg3_go_archives",
    "awg3_go_source_version",
    "awg3_go_source_commit",
    "awg3_tools_source_version",
    "awg3_tools_source_commit",
)

AWG3_MOBILE_COMPONENT_KEYS = (
    "awg3_mobile_go_version",
    "awg3_mobile_go_archives",
    "awg3_mobile_go_source_version",
    "awg3_mobile_go_source_commit",
    "awg3_mobile_tools_source_version",
    "awg3_mobile_tools_source_commit",
)


def color_output_enabled() -> bool:
    """Использовать цвет только в настоящем совместимом терминале."""
    return (
        sys.stdout.isatty()
        and os.environ.get("TERM", "dumb") != "dumb"
        and "NO_COLOR" not in os.environ
    )


def styled(value: object, tone: str) -> str:
    text = str(value)
    if not color_output_enabled():
        return text
    return f"{_ANSI[tone]}{text}{_ANSI['reset']}"


def ui_width() -> int:
    columns = shutil.get_terminal_size((88, 24)).columns
    return max(44, min(96, columns - 2))


def ui_panel(title: str, lines: list[str], tone: str = "blue") -> None:
    """Показать компактную панель с переносом длинных строк."""
    width = ui_width()
    inner = width - 2
    title_text = f" {title} "
    top_fill = max(0, inner - len(title_text))
    print(styled(f"┌{title_text}{'─' * top_fill}┐", tone))
    for raw_line in lines or [""]:
        wrapped = textwrap.wrap(
            str(raw_line),
            width=max(10, inner - 2),
            replace_whitespace=False,
            drop_whitespace=False,
        ) or [""]
        for line in wrapped:
            print(f"{styled('│', tone)} {line:<{inner - 2}} {styled('│', tone)}")
    print(styled(f"└{'─' * inner}┘", tone))


def ui_rows(title: str, rows: list[tuple[str, object]], tone: str = "blue") -> None:
    """Показать выровненный набор параметров без раскрытия секретов."""
    if not rows:
        ui_panel(title, ["Нет данных"], tone)
        return
    label_width = min(28, max(len(label) for label, _ in rows))
    available = max(12, ui_width() - label_width - 7)
    lines: list[str] = []
    for label, value in rows:
        chunks = textwrap.wrap(
            str(value), width=available, replace_whitespace=False
        ) or [""]
        lines.append(f"{label:<{label_width}} │ {chunks[0]}")
        lines.extend(f"{'':<{label_width}} │ {chunk}" for chunk in chunks[1:])
    ui_panel(title, lines, tone)


def ui_section(number: int, title: str, description: str = "") -> None:
    print()
    heading = f"[{number}/6] {title}"
    print(styled(f"┌── {heading} {'─' * max(0, ui_width() - len(heading) - 5)}", "cyan"))
    if description:
        print(styled(f"└─ {description}", "dim"))


def ui_step(title: str, description: str) -> None:
    print()
    print(styled(f"[▶] {title}", "cyan"))
    print(styled(f"    {description}", "dim"))


def ui_success(message: str) -> None:
    ui_panel("ГОТОВО", [f"✓ {message}"], "green")


def show_installer_banner() -> None:
    ui_panel(
        "KALIMERAWG · ИНТЕРАКТИВНАЯ УСТАНОВКА",
        [
            "ENTRY сервер  →  AWG 3+  →  EXIT сервер",
            "Управляемый DNS · маршрутизация RU · SOAX/SOCKS5 · защита SSH",
            "Значение в [квадратных скобках] принимается клавишей Enter.",
            "Секреты вводятся без отображения и сохраняются в Ansible Vault.",
        ],
        "magenta",
    )


def migrate_production_inventory(production: Path) -> bool:
    """Безопасно обновить известные устаревшие несекретные параметры inventory."""
    entry_path = production / "group_vars" / "entry.yml"
    exit_path = production / "group_vars" / "exit.yml"
    all_path = production / "group_vars" / "all" / "main.yml"
    if not entry_path.is_file():
        return False
    entry_vars = load_yaml(entry_path)
    exit_vars = load_yaml(exit_path) if exit_path.is_file() else {}
    all_vars = load_yaml(all_path) if all_path.is_file() else {}
    changed = False
    all_changed = False

    hosts_path = production / "hosts.yml"
    front_path = production / "group_vars" / "front.yml"
    hosts_document = load_yaml(hosts_path) if hosts_path.is_file() else {}
    front_hosts = (
        hosts_document.get("all", {})
        .get("children", {})
        .get("front", {})
        .get("hosts", {})
    )
    front_present = isinstance(front_hosts, dict) and bool(front_hosts)
    legacy_front = bool(entry_vars.get("front_relay_enabled", False)) or front_present
    if legacy_front:
        front_vars = load_yaml(front_path) if front_path.is_file() else {}
        origin_domain = str(front_vars.get("front_origin_domain", "")).strip()
        client_domain = str(front_vars.get("front_client_domain", "")).strip()
        cdn_ready = bool(
            front_vars.get("front_cdn_state") == "ready"
            or (client_domain and client_domain != origin_domain)
        )
        access_modes = front_vars.get("front_access_modes")
        if not isinstance(access_modes, list) or not access_modes:
            access_modes = ["direct", "cdn"] if cdn_ready else ["direct"]
        front_defaults: dict[str, object] = {
            "front_enabled": True,
            "front_relay_enabled": True,
            "front_active_id": str(front_vars.get("front_active_id", "front-1")),
            "front_replacement_state": "active",
            "front_access_modes": access_modes,
            "front_cdn_state": "ready" if cdn_ready else "not_configured",
            "front_direct_domain": str(
                front_vars.get("front_direct_domain", origin_domain)
            ),
            "front_cdn_domain": str(
                front_vars.get("front_cdn_domain", client_domain if cdn_ready else "")
            ),
            "front_subscription_enabled": False,
            "front_vless_encryption_enabled": True,
            "front_xhttp_disguise_enabled": True,
            "awg3_transit_enabled": False,
        }
        front_changed = False
        for key, value in front_defaults.items():
            if key not in front_vars:
                front_vars[key] = value
                front_changed = True
        for key, value in {
            "front_enabled": True,
            "front_relay_enabled": True,
            "front_subscription_enabled": False,
            "front_vless_encryption_enabled": True,
            "front_xhttp_disguise_enabled": True,
            "awg3_transit_enabled": False,
        }.items():
            if front_vars.get(key) != value:
                front_vars[key] = value
                front_changed = True
        entry_front_defaults: dict[str, object] = {
            "front_enabled": True,
            "front_relay_enabled": True,
            "front_backend_enabled": True,
            "reality_fallback_enabled": True,
            "reality_fallback_direct_client_enabled": False,
        }
        for key, value in entry_front_defaults.items():
            if entry_vars.get(key) != value:
                entry_vars[key] = value
                changed = True
        if front_changed:
            yaml_write(front_path, front_vars)
            changed = True
        if front_changed or changed:
            print(
                "Production inventory обновлён: FRONT переведён на модель "
                "front_enabled/access_modes/cdn_state с отдельным backend ENTRY."
            )

    awg3_defaults_path = (
        production.parents[1] / "roles" / "awg3_transit" / "defaults" / "main.yml"
    )
    if all_path.is_file() and awg3_defaults_path.is_file():
        awg3_defaults = load_yaml(awg3_defaults_path)
        for key in AWG3_COMPONENT_KEYS:
            if key not in all_vars and key in awg3_defaults:
                all_vars[key] = awg3_defaults[key]
                all_changed = True
        if all_changed:
            print(
                "Production inventory обновлён: текущая проверенная сборка AWG3 "
                "закреплена для воспроизводимых повторных deploy."
            )
    awg3_mobile_defaults_path = (
        production.parents[1] / "roles" / "awg3_mobile" / "defaults" / "main.yml"
    )
    if all_path.is_file() and awg3_mobile_defaults_path.is_file():
        awg3_mobile_defaults = load_yaml(awg3_mobile_defaults_path)
        mobile_components_changed = False
        for key in AWG3_MOBILE_COMPONENT_KEYS:
            if key not in all_vars and key in awg3_mobile_defaults:
                all_vars[key] = awg3_mobile_defaults[key]
                all_changed = True
                mobile_components_changed = True
        if mobile_components_changed:
            print(
                "Production inventory обновлён: отдельная сборка mobile AWG 3.1 "
                "закреплена без изменения межсерверного AWG 3.0."
            )
    if (
        entry_vars.get("entry_ru_tun_stack") == "mixed"
        and entry_vars.get("entry_ru_endpoint_independent_nat") is False
    ):
        entry_vars["entry_ru_tun_stack"] = "gvisor"
        entry_vars["entry_ru_endpoint_independent_nat"] = True
        changed = True
        print("Production inventory обновлён: RU TUN переведён на стабильный стек gvisor.")

    old_mobile_public_port = entry_vars.pop("entry_mobile_client_public_port", None)
    old_mobile_internal_port = entry_vars.pop("entry_mobile_client_internal_port", None)
    old_mobile_i1_mode = entry_vars.pop("entry_mobile_i1_mode", None)
    if old_mobile_i1_mode is not None:
        changed = True
    if old_mobile_public_port is not None or old_mobile_internal_port is not None:
        entry_vars["entry_mobile_legacy_public_port"] = int(
            old_mobile_public_port if old_mobile_public_port is not None else 53
        )
        entry_vars["entry_mobile_legacy_internal_port"] = int(
            old_mobile_internal_port if old_mobile_internal_port is not None else 39746
        )
        entry_vars["entry_mobile_client_listen_port"] = 8443
        changed = True
        print(
            "Production inventory обновлён: mobile AWG переведён с внешнего "
            "UDP/53 и перенаправления на прямой UDP/8443."
        )
    elif (
        entry_vars.get("entry_mobile_client_available", False)
        and "entry_mobile_client_listen_port" not in entry_vars
    ):
        entry_vars["entry_mobile_client_listen_port"] = 8443
        changed = True

    if (
        entry_vars.get("entry_mobile_client_available", False)
        and (
            entry_vars.get("entry_mobile_profile_generation") != "awg3.1"
            or entry_vars.get("entry_mobile_service_name") != "awg3-mobile.service"
            or not awg_mobile_awg3_profile_is_complete(
                entry_vars.get("entry_mobile_awg_obfuscation")
            )
        )
    ):
        entry_vars.update(
            {
                "entry_mobile_profile_generation": "awg3.1",
                "entry_mobile_service_name": "awg3-mobile.service",
                "entry_mobile_awg_obfuscation": awg_mobile_awg3_obfuscation(),
            }
        )
        changed = True
        print(
            "Production inventory обновлён: профиль mobile заменён на mobile/AWG3+. "
            "Ранее выданные mobile-конфиги нужно выпустить заново."
        )

    cps_changed = False
    for document, profile_names in (
        (
            entry_vars,
            (
                "entry_awg0_obfuscation",
                "entry_awg1_obfuscation",
                "entry_mobile_awg_obfuscation",
                "awg3_transit_obfuscation",
            ),
        ),
        (exit_vars, ("exit_awg_obfuscation", "awg3_transit_obfuscation")),
    ):
        for profile_name in profile_names:
            profile = document.get(profile_name)
            if not isinstance(profile, dict):
                continue
            for index in range(1, 6):
                key = f"i{index}"
                value = profile.get(key)
                if not isinstance(value, str):
                    continue
                normalized = normalize_awg_cps_signature(value)
                if normalized != value:
                    profile[key] = normalized
                    cps_changed = True

    if cps_changed:
        changed = True
        print(
            "Production inventory обновлён: CPS-теги I1–I5 приведены к "
            "документированному пределу 1000 байт."
        )
    if changed:
        yaml_write(entry_path, entry_vars)
        if exit_path.is_file():
            yaml_write(exit_path, exit_vars)
    if all_changed:
        yaml_write(all_path, all_vars)
    return changed or all_changed


def enable_mobile_profile(production: Path, vault_password: Path) -> bool:
    """Добавить отсутствующий mobile/AWG3+-профиль в production inventory."""
    entry_path = production / "group_vars" / "entry.yml"
    vault_path = production / "group_vars" / "all" / "vault.yml"
    if not entry_path.is_file() or not vault_path.is_file() or not vault_password.is_file():
        fail("Для включения mobile-профиля нужны production inventory и пароль Vault")

    entry_vars = load_yaml(entry_path)
    known_networks: list[ipaddress.IPv4Network] = []
    for key in (
        "entry_client_subnet",
        "entry_legacy_client_subnet",
        "awg3_transit_address",
        "entry_exit_tunnel_address",
    ):
        value = entry_vars.get(key)
        if not isinstance(value, str) or "{{" in value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            known_networks.append(network)

    mobile_network: ipaddress.IPv4Network | None = None
    configured_mobile_network_usable = False
    configured_mobile_subnet = entry_vars.get("entry_mobile_client_subnet")
    if isinstance(configured_mobile_subnet, str):
        try:
            candidate = ipaddress.ip_network(configured_mobile_subnet, strict=True)
        except ValueError:
            candidate = None
        if (
            isinstance(candidate, ipaddress.IPv4Network)
            and candidate.num_addresses >= 2
            and not any(candidate.overlaps(network) for network in known_networks)
        ):
            mobile_network = candidate
            configured_mobile_network_usable = True

    if mobile_network is None:
        for candidate in ipaddress.ip_network("10.68.0.0/16").subnets(new_prefix=24):
            if not any(candidate.overlaps(network) for network in known_networks):
                mobile_network = candidate
                break
    if mobile_network is None:
        fail("Не удалось автоматически выбрать отдельную IPv4-подсеть mobile AWG")

    mobile_hosts = mobile_network.hosts()
    try:
        mobile_server_address = next(mobile_hosts)
        next(mobile_hosts)
    except StopIteration:
        fail("Подсеть mobile AWG должна содержать адреса сервера и клиента")

    entry_changed = not bool(entry_vars.get("entry_mobile_client_available", False))
    mobile_defaults: dict[str, object] = {
        "entry_mobile_client_available": True,
        "entry_mobile_client_enabled": False,
        "entry_mobile_client_interface": "awg-mobile",
        "entry_mobile_client_address": (
            f"{mobile_server_address}/{mobile_network.prefixlen}"
        ),
        "entry_mobile_client_listen_address": str(mobile_server_address),
        "entry_mobile_client_subnet": str(mobile_network),
        "entry_mobile_client_listen_port": 8443,
        "entry_mobile_legacy_public_port": 53,
        "entry_mobile_legacy_internal_port": 39746,
        "entry_mobile_client_mtu": 1380,
        "entry_mobile_service_name": "awg3-mobile.service",
        "entry_mobile_profile_generation": "awg3.1",
    }
    mobile_network_keys = {
        "entry_mobile_client_address",
        "entry_mobile_client_listen_address",
        "entry_mobile_client_subnet",
    }
    for key, value in mobile_defaults.items():
        if (
            key == "entry_mobile_client_available"
            or key not in entry_vars
            or (not configured_mobile_network_usable and key in mobile_network_keys)
        ):
            if entry_vars.get(key) != value:
                entry_vars[key] = value
                entry_changed = True
    if not isinstance(entry_vars.get("entry_mobile_awg_obfuscation"), dict):
        entry_vars["entry_mobile_awg_obfuscation"] = awg_mobile_awg3_obfuscation()
        entry_changed = True

    vault_secret = vault_password.read_bytes().rstrip(b"\r\n")
    if not vault_secret:
        fail("Файл пароля Ansible Vault пуст")
    vault_lib = VaultLib([("default", VaultSecret(vault_secret))])
    try:
        vault_document = yaml.safe_load(vault_lib.decrypt(vault_path.read_bytes()))
    except Exception as error:
        fail(f"Не удалось расшифровать production Vault: {type(error).__name__}")
    if not isinstance(vault_document, dict):
        fail("Production Vault должен содержать словарь переменных")

    vault_changed = False
    if not vault_document.get("vault_awg_entry_mobile_private_key"):
        vault_document["vault_awg_entry_mobile_private_key"] = awg_private_key()
        vault_changed = True
    if not vault_document.get("vault_awg_entry_mobile_header_protection_key"):
        vault_document["vault_awg_entry_mobile_header_protection_key"] = awg_private_key()
        vault_changed = True
    if not isinstance(vault_document.get("vault_entry_mobile_client_peers"), list):
        vault_document["vault_entry_mobile_client_peers"] = []
        vault_changed = True

    if vault_changed:
        encrypted = vault_lib.encrypt(
            yaml.safe_dump(vault_document, sort_keys=False).encode()
        )
        temporary = vault_path.with_name(
            f".{vault_path.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            secure_write(temporary, encrypted)
            os.replace(temporary, vault_path)
            vault_path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)
    if entry_changed:
        yaml_write(entry_path, entry_vars)

    if entry_changed or vault_changed:
        print(
            "Production inventory обновлён: добавлен отдельный mobile/AWG3+ "
            f"{mobile_network} на UDP/8443; интерфейс пока выключен."
        )
    return entry_changed or vault_changed


def ensure_mobile_awg3_vault_material(
    production: Path, vault_password: Path
) -> bool:
    """Добавить отдельный HeaderProtectionKey при переходе на mobile/AWG3+."""
    entry_path = production / "group_vars" / "entry.yml"
    vault_path = production / "group_vars" / "all" / "vault.yml"
    if not entry_path.is_file() or not vault_path.is_file():
        return False
    entry_vars = load_yaml(entry_path)
    if not entry_vars.get("entry_mobile_client_available", False):
        return False
    vault_secret = vault_password.read_bytes().rstrip(b"\r\n")
    if not vault_secret:
        fail("Файл пароля Ansible Vault пуст")
    vault_lib = VaultLib([("default", VaultSecret(vault_secret))])
    try:
        document = yaml.safe_load(vault_lib.decrypt(vault_path.read_bytes()))
    except Exception as error:
        fail(f"Не удалось расшифровать production Vault: {type(error).__name__}")
    if not isinstance(document, dict):
        fail("Production Vault должен содержать словарь переменных")
    if document.get("vault_awg_entry_mobile_header_protection_key"):
        return False
    document["vault_awg_entry_mobile_header_protection_key"] = awg_private_key()
    encrypted = vault_lib.encrypt(yaml.safe_dump(document, sort_keys=False).encode())
    temporary = vault_path.with_name(f".{vault_path.name}.{secrets.token_hex(8)}.tmp")
    try:
        secure_write(temporary, encrypted)
        os.replace(temporary, vault_path)
        vault_path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    print("Production Vault обновлён: создан отдельный HeaderProtectionKey mobile/AWG3+.")
    return True


_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def enable_front_profile(production: Path, vault_password: Path) -> bool:
    """Добавить FRONT-релей (CDN-фронтированный VLESS+XHTTP) к production inventory.

    В отличие от enable_mobile_profile это добавляет НОВЫЙ хост, а не просто
    флаги существующему - требует интерактивных данных подключения. См.
    docs/front-relay.md для ручных шагов (DNS/CDN), которые нужны отдельно.
    """
    hosts_path = production / "hosts.yml"
    entry_path = production / "group_vars" / "entry.yml"
    front_path = production / "group_vars" / "front.yml"
    if not hosts_path.is_file() or not entry_path.is_file() or not vault_password.is_file():
        fail("Для включения FRONT-релея нужны production inventory и пароль Vault")

    hosts_document = load_yaml(hosts_path)
    children = hosts_document.setdefault("all", {}).setdefault("children", {})
    if "front" in children and children["front"].get("hosts"):
        print("FRONT-релей уже подключён к production inventory; повторное включение не требуется.")
        return False

    ui_panel(
        "FRONT-РЕЛЕЙ: CDN-ФРОНТИРОВАННЫЙ VLESS ДЛЯ РЕЖИМА БЕЛЫХ СПИСКОВ",
        [
            "Отдельная VPS с Nginx+Xray-core и служебным каналом до ENTRY.",
            "Прямой режим работает без CDN. CDN-режим включается только после",
            "подтверждения готового внешнего CDN-ресурса.",
        ],
        "cyan",
    )
    front_host = prompt("IP-адрес или DNS-имя FRONT сервера")
    if not front_host:
        fail("Необходимо указать адрес FRONT сервера")
    require_public_endpoint(front_host, "Адрес FRONT сервера")
    # Постоянный публичный IPv4, а не front_host как есть (может быть
    # DNS-именем) - нужен для изолированного UFW-правила на ENTRY, тем же
    # способом, что security_interserver_peer_ipv4 для пары ENTRY/EXIT.
    front_public_ipv4 = resolve_single_public_ipv4(front_host, "Адрес FRONT сервера")
    front_user = prompt("Пользователь SSH FRONT сервера", "root")
    front_port = prompt_port("Текущий SSH-порт FRONT сервера", 22)
    front_new_port = prompt_port("Новый управляемый SSH-порт FRONT сервера", 56777)
    if front_new_port < 1024:
        fail("Управляемый SSH-порт FRONT должен находиться в диапазоне 1024–65535")
    front_password = getpass.getpass("Пароль SSH FRONT сервера (ввод скрыт): ")
    if not front_password:
        fail("Начальный пароль SSH FRONT не может быть пустым")

    front_origin_domain = prompt("Origin-домен FRONT (A-запись уже указывает на этот сервер)")
    if not _DOMAIN_RE.match(front_origin_domain or ""):
        fail("Origin-домен FRONT должен быть корректным DNS-именем")
    front_certbot_email = prompt("E-mail для уведомлений Let's Encrypt/Certbot")
    if not _EMAIL_RE.match(front_certbot_email or ""):
        fail("Некорректный e-mail для Certbot")

    ui_panel(
        "РЕЖИМ ДОСТУПА FRONT",
        [
            "1 · прямой TLS+XHTTP через FRONT без CDN",
            "2 · TLS+XHTTP только через уже готовый CDN",
            "3 · оба варианта одновременно",
        ],
        "cyan",
    )
    access_choice = prompt("Выберите режим FRONT", "1")
    access_modes_by_choice = {
        "1": ["direct"],
        "2": ["cdn"],
        "3": ["direct", "cdn"],
    }
    if access_choice not in access_modes_by_choice:
        fail("Выбран неподдерживаемый режим FRONT")
    front_access_modes = access_modes_by_choice[access_choice]
    front_direct_domain = front_origin_domain
    front_cdn_domain = ""
    front_cdn_state = "not_configured"
    if "direct" in front_access_modes:
        print(f"Домен прямого доступа FRONT: {front_origin_domain}")
    if "cdn" in front_access_modes:
        if not prompt_bool("CDN-ресурс уже создан и готов к проверке", False):
            fail(
                "CDN-режим нельзя включить до готовности ресурса. "
                "Выберите прямой режим и добавьте CDN следующим deploy."
            )
        front_cdn_domain = prompt("Публичный домен готового CDN-ресурса")
        if not _DOMAIN_RE.match(front_cdn_domain or ""):
            fail("Публичный домен CDN должен быть корректным DNS-именем")
        front_cdn_state = "ready"

    entry_vars = load_yaml(entry_path)
    entry_changed = False
    for key, value in {
        "front_enabled": True,
        "front_relay_enabled": True,
        "front_backend_enabled": True,
        "reality_fallback_enabled": True,
        "reality_fallback_direct_client_enabled": False,
        "front_public_ipv4": front_public_ipv4,
    }.items():
        if entry_vars.get(key) != value:
            entry_vars[key] = value
            entry_changed = True
    if entry_changed:
        yaml_write(entry_path, entry_vars)

    front_vars = {
        "awg_node_role": "front",
        "front_enabled": True,
        "front_relay_enabled": True,
        "front_active_id": "front-1",
        "front_replacement_state": "active",
        "front_access_modes": front_access_modes,
        "front_cdn_state": front_cdn_state,
        "front_direct_domain": front_direct_domain,
        "front_cdn_domain": front_cdn_domain,
        "front_client_domain": (
            front_cdn_domain if front_access_modes == ["cdn"] else front_direct_domain
        ),
        "front_subscription_enabled": False,
        "front_vless_encryption_enabled": True,
        "front_xhttp_disguise_enabled": True,
        "awg3_transit_enabled": False,
        # Дефолт роли ("/api/stream") - общеизвестный путь и лёгкий
        # fingerprint; путь генерируется здесь, потому что он должен быть
        # постоянным (входит в клиентские ссылки и правила кэширования CDN),
        # а не пересчитываться при каждом deploy.
        "front_xhttp_path": "/" + secrets.token_urlsafe(9),
        "front_origin_domain": front_origin_domain,
        "front_certbot_email": front_certbot_email,
    }
    yaml_write(front_path, front_vars)

    ssh_private = Path.home() / ".ssh" / "awg-iac-production"
    ssh_public = Path(str(ssh_private) + ".pub")
    if not ssh_private.is_file() or not ssh_public.is_file():
        fail("Не найден управляющий SSH-ключ awg-iac-production")
    front_password = bootstrap_key(
        front_host,
        front_user,
        front_port,
        front_password,
        ssh_public,
        "FRONT сервер",
    )
    front_automation_source_ipv4 = remote_observed_ssh_source_ipv4(
        front_host,
        front_user,
        front_port,
        ssh_private,
    )
    if not front_automation_source_ipv4:
        fail("FRONT не подтвердил исходный IPv4 управляющего SSH-сеанса")
    if front_user != "root":
        vault_path = production / "group_vars" / "all" / "vault.yml"
        vault_secret = vault_password.read_bytes().rstrip(b"\r\n")
        vault_lib = VaultLib([("default", VaultSecret(vault_secret))])
        try:
            vault_document = yaml.safe_load(vault_lib.decrypt(vault_path.read_bytes()))
        except Exception as error:
            fail(f"Не удалось открыть Vault для FRONT: {type(error).__name__}")
        if not isinstance(vault_document, dict):
            fail("Production Vault должен содержать словарь переменных")
        vault_document["vault_front_become_password"] = front_password
        encrypted = vault_lib.encrypt(
            yaml.safe_dump(vault_document, sort_keys=False).encode("utf-8")
        )
        temporary = vault_path.with_name(
            f".{vault_path.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            secure_write(temporary, encrypted)
            os.replace(temporary, vault_path)
            vault_path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)
    front_host_vars: dict[str, object] = {
        "ansible_host": front_host,
        "ansible_user": front_user,
        "ansible_port": front_port,
        "ansible_become": True,
        "ansible_ssh_private_key_file": str(ssh_private),
        "ssh_listen_port": front_new_port,
        "security_allow_ssh_port_change": front_port != front_new_port,
        "security_automation_source_ipv4": front_automation_source_ipv4,
    }
    if front_user != "root":
        front_host_vars["ansible_become_password"] = "{{ vault_front_become_password }}"
    children["front"] = {"hosts": {"front-managed": front_host_vars}}
    yaml_write(hosts_path, hosts_document)

    print(
        "Production inventory обновлён: добавлен FRONT-релей "
        f"({front_origin_domain}); он будет применён текущим deploy."
    )
    return True


def _front_replacement_state_root() -> Path:
    return Path.home() / ".local" / "share" / "awg-iac" / "production" / "front-replacement"


def _read_front_users_over_ssh(host_vars: dict[str, object]) -> dict[str, object]:
    host = str(host_vars.get("ansible_host", ""))
    user = str(host_vars.get("ansible_user", "kalimera"))
    port = int(host_vars.get("ansible_port", 22))
    identity = str(
        host_vars.get(
            "ansible_ssh_private_key_file",
            Path.home() / ".ssh" / "awg-iac-production",
        )
    )
    result = subprocess.run(
        [
            require_command("ssh"),
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15",
            "-o", "ConnectionAttempts=1",
            "-o", "StrictHostKeyChecking=yes",
            "-i", identity,
            "-p", str(port),
            f"{user}@{host}",
            "sudo -n /usr/local/libexec/kalimera-admin-command vless-user backup",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        fail(
            "Не удалось получить зашифрованный реестр пользователей со старого "
            "FRONT. Замена остановлена до изменения inventory."
        )
    try:
        state = json.loads(result.stdout)
    except ValueError:
        fail("Старый FRONT вернул некорректный реестр VLESS-пользователей")
    if (
        not isinstance(state, dict)
        or state.get("schema") != 1
        or not isinstance(state.get("users"), list)
        or not state["users"]
    ):
        fail("Реестр VLESS-пользователей старого FRONT не прошёл проверку")
    return state


def prepare_front_replacement(production: Path, vault_password: Path) -> bool:
    """Подготовить новый FRONT, сохранив рабочий CDN-путь до commit."""
    hosts_path = production / "hosts.yml"
    entry_path = production / "group_vars" / "entry.yml"
    front_path = production / "group_vars" / "front.yml"
    vault_path = production / "group_vars" / "all" / "vault.yml"
    if not all(path.is_file() for path in (hosts_path, entry_path, front_path, vault_path)):
        fail("Для замены FRONT нужен полный production inventory")

    hosts_document = load_yaml(hosts_path)
    front_hosts = (
        hosts_document.get("all", {})
        .get("children", {})
        .get("front", {})
        .get("hosts", {})
    )
    if not isinstance(front_hosts, dict) or len(front_hosts) != 1:
        fail("Безопасная замена требует ровно один действующий FRONT")
    front_vars = load_yaml(front_path)
    if front_vars.get("front_replacement_state", "active") != "active":
        fail("Замена FRONT уже подготовлена; используйте commit или rollback")

    old_name, old_host_vars = next(iter(front_hosts.items()))
    if not isinstance(old_host_vars, dict):
        fail("Некорректные параметры действующего FRONT")
    old_public_ipv4 = resolve_single_public_ipv4(
        str(old_host_vars.get("ansible_host", "")), "Адрес действующего FRONT"
    )
    users_state = _read_front_users_over_ssh(old_host_vars)

    ui_panel(
        "БЕЗОПАСНАЯ ЗАМЕНА FRONT",
        [
            "Старый FRONT и его UFW-доступ сохраняются до отдельного commit.",
            "Домен CDN, XHTTP path, UUID пользователей и backend ENTRY не меняются.",
            "Для нового FRONT нужен новый origin-домен с готовой A-записью.",
        ],
        "cyan",
    )
    new_host = prompt("IP-адрес или DNS-имя нового FRONT")
    require_public_endpoint(new_host, "Адрес нового FRONT")
    new_public_ipv4 = resolve_single_public_ipv4(new_host, "Адрес нового FRONT")
    if new_public_ipv4 == old_public_ipv4:
        fail("Новый FRONT должен иметь другой публичный IPv4")
    new_user = prompt("Пользователь SSH нового FRONT", "root")
    new_port = prompt_port("Текущий SSH-порт нового FRONT", 22)
    managed_port = prompt_port(
        "Новый управляемый SSH-порт нового FRONT",
        int(old_host_vars.get("ssh_listen_port", 56777)),
    )
    if managed_port < 1024:
        fail("Управляемый SSH-порт FRONT должен быть не ниже 1024")
    password = getpass.getpass("Пароль SSH нового FRONT (ввод скрыт): ")
    if not password:
        fail("Начальный пароль нового FRONT не может быть пустым")
    new_origin = prompt("Новый origin-домен (A-запись уже указывает на новый FRONT)")
    if not _DOMAIN_RE.match(new_origin or ""):
        fail("Origin-домен нового FRONT должен быть корректным DNS-именем")
    certbot_email = prompt(
        "E-mail Certbot",
        str(front_vars.get("front_certbot_email", "")),
    )
    if not _EMAIL_RE.match(certbot_email or ""):
        fail("Некорректный e-mail для Certbot")

    ssh_private = Path.home() / ".ssh" / "awg-iac-production"
    ssh_public = Path(str(ssh_private) + ".pub")
    if not ssh_private.is_file() or not ssh_public.is_file():
        fail("Не найден управляющий SSH-ключ awg-iac-production")
    password = bootstrap_key(
        new_host, new_user, new_port, password, ssh_public, "Новый FRONT сервер"
    )
    source_ipv4 = remote_observed_ssh_source_ipv4(
        new_host, new_user, new_port, ssh_private
    )
    if not source_ipv4:
        fail("Новый FRONT не подтвердил исходный IPv4 управляющего SSH-сеанса")

    backup_root = _front_replacement_state_root()
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup_dir = backup_root / secrets.token_hex(8)
    backup_dir.mkdir(mode=0o700)
    for source in (hosts_path, entry_path, front_path, vault_path):
        target = backup_dir / source.name
        secure_write(target, source.read_bytes())
    secure_write(
        backup_root / "current.json",
        json.dumps({"backup": str(backup_dir)}, ensure_ascii=False).encode("utf-8"),
    )

    vault_secret = vault_password.read_bytes().rstrip(b"\r\n")
    vault_lib = VaultLib([("default", VaultSecret(vault_secret))])
    try:
        vault_document = yaml.safe_load(vault_lib.decrypt(vault_path.read_bytes()))
    except Exception as error:
        fail(f"Не удалось открыть Vault для замены FRONT: {type(error).__name__}")
    if not isinstance(vault_document, dict):
        fail("Production Vault должен содержать словарь переменных")
    vault_document["vault_front_vless_users"] = users_state
    if new_user != "root":
        vault_document["vault_front_become_password"] = password
    encrypted = vault_lib.encrypt(
        yaml.safe_dump(vault_document, sort_keys=False).encode("utf-8")
    )
    temporary_vault = vault_path.with_name(
        f".{vault_path.name}.{secrets.token_hex(8)}.tmp"
    )
    try:
        secure_write(temporary_vault, encrypted)
        os.replace(temporary_vault, vault_path)
        vault_path.chmod(0o600)
    finally:
        temporary_vault.unlink(missing_ok=True)

    entry_vars = load_yaml(entry_path)
    entry_vars.update(
        {
            "front_public_ipv4": new_public_ipv4,
            "front_previous_public_ipv4": old_public_ipv4,
            "front_replacement_state": "prepared",
        }
    )
    yaml_write(entry_path, entry_vars)

    modes = front_vars.get("front_access_modes", ["direct"])
    front_vars.update(
        {
            "front_active_id": f"front-{secrets.token_hex(3)}",
            "front_replacement_state": "prepared",
            "front_previous_public_ipv4": old_public_ipv4,
            "front_previous_origin_domain": front_vars.get("front_origin_domain", ""),
            "front_origin_domain": new_origin,
            "front_direct_domain": new_origin,
            "front_client_domain": (
                str(front_vars.get("front_cdn_domain", ""))
                if modes == ["cdn"]
                else new_origin
            ),
            "front_certbot_email": certbot_email,
        }
    )
    yaml_write(front_path, front_vars)

    replacement_host_vars: dict[str, object] = {
        "ansible_host": new_host,
        "ansible_user": new_user,
        "ansible_port": new_port,
        "ansible_become": True,
        "ansible_ssh_private_key_file": str(ssh_private),
        "ssh_listen_port": managed_port,
        "security_allow_ssh_port_change": new_port != managed_port,
        "security_automation_source_ipv4": source_ipv4,
    }
    if new_user != "root":
        replacement_host_vars["ansible_become_password"] = "{{ vault_front_become_password }}"
    hosts_document["all"]["children"]["front"]["hosts"] = {
        old_name: replacement_host_vars
    }
    yaml_write(hosts_path, hosts_document)
    print(
        "Новый FRONT подготовлен в inventory. Старый FRONT останется разрешён "
        "на ENTRY до --commit-front-replacement."
    )
    return True


def rollback_front_replacement(production: Path) -> bool:
    marker = _front_replacement_state_root() / "current.json"
    if not marker.is_file():
        fail("Резервная копия незавершённой замены FRONT не найдена")
    try:
        backup_dir = Path(json.loads(marker.read_text(encoding="utf-8"))["backup"])
    except (OSError, ValueError, KeyError):
        fail("Повреждён маркер резервной копии FRONT")
    mapping = {
        "hosts.yml": production / "hosts.yml",
        "entry.yml": production / "group_vars" / "entry.yml",
        "front.yml": production / "group_vars" / "front.yml",
        "vault.yml": production / "group_vars" / "all" / "vault.yml",
    }
    for name, target in mapping.items():
        source = backup_dir / name
        if not source.is_file():
            fail("Резервная копия FRONT неполна")
        secure_write(target, source.read_bytes())
    print(
        "Inventory прежнего FRONT восстановлен; deploy повторно применит его "
        "состояние. Маркер отката будет удалён только после успешной проверки."
    )
    return True


def commit_front_replacement(production: Path) -> None:
    entry_path = production / "group_vars" / "entry.yml"
    front_path = production / "group_vars" / "front.yml"
    entry_vars = load_yaml(entry_path)
    front_vars = load_yaml(front_path)
    if front_vars.get("front_replacement_state") != "prepared":
        fail("Подготовленная замена FRONT не найдена")
    if not prompt_bool(
        "Новая VLESS-сессия через новый FRONT успешно проверена",
        False,
    ):
        fail("Commit отменён; старый FRONT остаётся разрешён на ENTRY")
    if "cdn" in front_vars.get("front_access_modes", []):
        if not prompt_bool(
            "CDN origin переключён на новый FRONT и клиентская сессия проверена",
            False,
        ):
            fail("Commit отменён; старый FRONT остаётся разрешён на ENTRY")
    previous = str(entry_vars.get("front_previous_public_ipv4", ""))
    entry_vars["front_replacement_state"] = "active"
    front_vars["front_replacement_state"] = "active"
    yaml_write(entry_path, entry_vars)
    yaml_write(front_path, front_vars)
    # Старый адрес пока сохраняется в inventory, чтобы роль security могла
    # удалить точное временное правило UFW. После успешного deploy поля будут
    # удалены окончательно.
    if not previous:
        fail("В inventory отсутствует IPv4 прежнего FRONT")


def finish_front_replacement(production: Path) -> None:
    entry_path = production / "group_vars" / "entry.yml"
    front_path = production / "group_vars" / "front.yml"
    entry_vars = load_yaml(entry_path)
    front_vars = load_yaml(front_path)
    previous_ipv4 = str(entry_vars.get("front_previous_public_ipv4", "")).strip()
    previous_origin = str(front_vars.get("front_previous_origin_domain", "")).strip()
    for document in (entry_vars, front_vars):
        document.pop("front_previous_public_ipv4", None)
        document.pop("front_previous_origin_domain", None)
    yaml_write(entry_path, entry_vars)
    yaml_write(front_path, front_vars)
    marker = _front_replacement_state_root() / "current.json"
    marker.unlink(missing_ok=True)
    print("Замена FRONT подтверждена; временный доступ прежнего FRONT удалён.")
    if previous_ipv4:
        previous_label = previous_ipv4
        if previous_origin:
            previous_label = f"{previous_origin} ({previous_ipv4})"
        print(
            f"Старый FRONT {previous_label} больше не входит в каскад. "
            "Выключите или переустановите его после контрольной проверки нового FRONT."
        )


def prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    marker = styled("◆", "cyan")
    value = input(f"{marker} {label}{styled(suffix, 'dim')}: ").strip()
    return value or (default or "")


def prompt_bool(label: str, default: bool = True) -> bool:
    marker = "Y/n" if default else "y/N"
    while True:
        value = input(
            f"{styled('◆', 'cyan')} {label}{styled(f' [{marker}]', 'dim')}: "
        ).strip().lower()
        if not value:
            return default
        if value in {"y", "yes", "д", "да"}:
            return True
        if value in {"n", "no", "н", "нет"}:
            return False


def prompt_port(label: str, default: int) -> int:
    while True:
        value = prompt(label, str(default))
        try:
            port = int(value)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            return port


def prompt_admin_public_key() -> str:
    allowed_prefixes = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-")
    while True:
        value = input("Административный публичный SSH-ключ (одна строка): ").strip()
        fields = value.split()
        if len(fields) < 2 or not fields[0].startswith(allowed_prefixes):
            print("Введите публичный ключ OpenSSH, например ssh-ed25519 AAAA...")
            continue
        try:
            decoded = base64.b64decode(fields[1], validate=True)
        except (ValueError, binascii.Error):
            print("Данные публичного SSH-ключа не являются корректным base64.")
            continue
        if len(decoded) < 16:
            print("Данные публичного SSH-ключа слишком короткие.")
            continue
        return value


def generate_account_password(length: int = 30) -> str:
    """Создать пароль без неоднозначных символов, гарантируя все классы знаков."""
    if length < 25:
        raise ValueError("Пароль учётной записи должен содержать не менее 25 символов")
    lower = "abcdefghijkmnopqrstuvwxyz"
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    digits = "23456789"
    special = "!@#$%^&*_-+="
    chooser = secrets.SystemRandom()
    characters = [
        chooser.choice(lower),
        chooser.choice(upper),
        chooser.choice(digits),
        chooser.choice(special),
    ]
    alphabet = lower + upper + digits + special
    characters.extend(chooser.choice(alphabet) for _ in range(length - len(characters)))
    chooser.shuffle(characters)
    return "".join(characters)


def hash_account_password(password: str) -> str:
    """Получить совместимый SHA-512 crypt-хеш, не передавая пароль в argv."""
    result = subprocess.run(
        [require_command("openssl"), "passwd", "-6", "-stdin"],
        input=password + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    password_hash = result.stdout.strip()
    if result.returncode != 0 or not password_hash.startswith("$6$"):
        fail("Не удалось безопасно сформировать хеш пароля учётной записи")
    return password_hash


def show_generated_account_passwords(passwords: dict[str, str]) -> None:
    ui_panel(
        "ПАРОЛИ УЧЁТНЫХ ЗАПИСЕЙ · ПОКАЗЫВАЮТСЯ ОДИН РАЗ",
        [
            "Сохраните значения сейчас в менеджере паролей.",
            "SSH использует ключи; эти пароли предназначены для sudo и аварийной консоли.",
            "",
            *[f"{label}: {value}" for label, value in passwords.items()],
            "",
            "В inventory сохраняются только необратимые хеши; повторный показ невозможен.",
        ],
        "yellow",
    )


def require_public_endpoint(value: str, label: str) -> None:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(value, None, socket.AF_INET)}
    except socket.gaierror as error:
        fail(f"Не удалось разрешить {label} в IPv4: {error}")
    if not addresses or not all(ipaddress.ip_address(address).is_global for address in addresses):
        fail(f"{label} должен разрешаться только в публичные IPv4-адреса")


def resolve_single_public_ipv4(value: str, label: str) -> str:
    """Получить единственный постоянный публичный IPv4 для правила межсерверного UFW."""
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(value, None, socket.AF_INET)}
    except socket.gaierror as error:
        fail(f"Не удалось разрешить {label} в IPv4: {error}")
    if len(addresses) != 1:
        fail(f"{label} должен разрешаться ровно в один постоянный публичный IPv4-адрес")
    address = addresses.pop()
    if not ipaddress.ip_address(address).is_global:
        fail(f"{label} должен быть публичным IPv4-адресом")
    return address


def probe_reality_dest(host: str, port: int = 443, attempts: int = 3) -> bool:
    """Проверить, что dest-сайт REALITY стабильно отвечает TLS 1.3 одним
    и тем же сертификатом - та же логика (три пробы), что применяется
    сервером при deploy и в reality-dest-switch."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    fingerprints: set[str] = set()
    for _ in range(attempts):
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    if tls_sock.version() != "TLSv1.3":
                        return False
                    der = tls_sock.getpeercert(binary_form=True)
                    if not der:
                        return False
                    fingerprints.add(hashlib.sha256(der).hexdigest())
        except (OSError, ssl.SSLError):
            return False
    return len(fingerprints) == 1


def detect_local_public_ipv4(route_target: str) -> str:
    """Определить публичный IPv4 локального интерфейса по реальному маршруту.

    Для локальной установки Ansible должен продолжать использовать loopback,
    однако клиентам и EXIT нужен внешний адрес ENTRY. Источник маршрута до EXIT
    точнее имени интерфейса и работает с любым его названием. Если VPS находится
    за NAT и на интерфейсе нет публичного адреса, автоматическое значение не
    подставляется: установщик попросит указать опубликованный адрес явно.
    """
    targets: list[str] = []
    try:
        targets.extend(
            sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(
                        route_target, None, socket.AF_INET, socket.SOCK_DGRAM
                    )
                }
            )
        )
    except socket.gaierror:
        pass
    targets.append("1.1.1.1")

    for target in targets:
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            connection.connect((target, 443))
            candidate = str(connection.getsockname()[0])
        except OSError:
            continue
        finally:
            connection.close()
        try:
            if ipaddress.ip_address(candidate).is_global:
                return candidate
        except ValueError:
            continue
    return ""


def detect_local_ssh_port() -> int:
    sshd = shutil.which("sshd")
    if not sshd:
        return 22
    result = subprocess.run(
        [sshd, "-T"], text=True, capture_output=True, check=False
    )
    for line in result.stdout.splitlines():
        if line.startswith("port "):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                break
    return 22


def require_command(name: str) -> str:
    path = shutil.which(name)
    if not path:
        fail(f"Отсутствует обязательная команда управляющего окружения: {name}")
    return path


def run(argv: list[str], *, env: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(argv, check=True, env=env)
    except subprocess.CalledProcessError:
        fail(f"Команда завершилась с ошибкой; секретные данные не показаны: {argv[0]}")


def cleanup_deployment(repo: Path, hosts: Path, vault_password: Path) -> None:
    """Вернуть APT timers и UFW даже после ошибки или Ctrl+C."""
    ansible_playbook = shutil.which("ansible-playbook")
    if not ansible_playbook or not hosts.is_file() or not vault_password.is_file():
        return
    try:
        hosts_document = load_yaml(hosts)
        all_vars_path = hosts.parent / "group_vars" / "all" / "main.yml"
        all_vars = load_yaml(all_vars_path) if all_vars_path.is_file() else {}
        recover_saved_admin_access(
            hosts_document,
            hosts,
            str(all_vars.get("security_admin_user", "kalimera")),
            bool(all_vars.get("security_finalize_admin_access", False)),
        )
    except (KeyError, OSError, TypeError, ValueError, yaml.YAMLError):
        # Cleanup остаётся best-effort даже для частично записанного inventory.
        pass
    try:
        subprocess.run(
            [
            ansible_playbook,
            "-i",
            str(hosts),
            str(repo / "playbooks" / "cleanup.yml"),
            "--vault-password-file",
            str(vault_password),
            ],
            check=False,
        )
    except OSError:
        # Аварийная очистка не должна скрывать исходную ошибку установки.
        return


def awg_private_key() -> str:
    raw = bytearray(os.urandom(32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return base64.b64encode(bytes(raw)).decode("ascii")


def awg_public_key(private_value: str) -> str:
    private = X25519PrivateKey.from_private_bytes(base64.b64decode(private_value))
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(public).decode("ascii")


def awg_psk() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


def ssh_exchange_keypair() -> tuple[str, str]:
    """Создать отдельную Ed25519 identity только для обмена долями."""
    private = Ed25519PrivateKey.generate()
    private_value = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_value = private.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    return private_value, f"{public_value} kalimerawg-share-exchange"


def split_runtime_secret(
    secret_hex: str, *, threshold: int = 2, total: int = 5
) -> list[str]:
    """Разделить 256-битный KEK штатной Ubuntu-реализацией Shamir SSS."""
    if not re.fullmatch(r"[0-9a-f]{64}", secret_hex):
        fail("Ключ runtime-пакета должен быть 256-битным hex-значением")
    if not (2 <= threshold <= total <= 16):
        fail("Допустимо от 2 до 16 долей, threshold не может превышать total")
    command = require_command("ssss-split")
    result = subprocess.run(
        [
            command,
            "-t",
            str(threshold),
            "-n",
            str(total),
            "-s",
            "256",
            "-x",
            "-Q",
            "-w",
            "kalimerawgruntimev1",
        ],
        input=secret_hex + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    shares = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0 or len(shares) != total:
        fail("Не удалось создать пороговые доли; секретные данные не показаны")
    if len(set(shares)) != total or any(
        not re.fullmatch(r"kalimerawgruntimev1-[1-9][0-9]*-[0-9a-f]+", share)
        for share in shares
    ):
        fail("ssss-split вернул неожиданный формат долей")
    return shares


def ensure_runtime_secret_material(production: Path, vault_password: Path) -> bool:
    """Добавить 2-of-5 материал существующему inventory без вывода секретов."""
    vault_path = production / "group_vars" / "all" / "vault.yml"
    all_path = production / "group_vars" / "all" / "main.yml"
    entry_path = production / "group_vars" / "entry.yml"
    exit_path = production / "group_vars" / "exit.yml"
    front_path = production / "group_vars" / "front.yml"
    hosts_path = production / "hosts.yml"
    if not all(
        path.is_file()
        for path in (vault_path, all_path, entry_path, exit_path, hosts_path)
    ):
        fail("Production inventory неполон для включения runtime-защиты")

    vault_secret = vault_password.read_bytes().rstrip(b"\r\n")
    vault_lib = VaultLib([("default", VaultSecret(vault_secret))])
    try:
        document = yaml.safe_load(vault_lib.decrypt(vault_path.read_bytes()))
    except Exception as error:
        fail(f"Не удалось расшифровать production Vault: {type(error).__name__}")
    if not isinstance(document, dict):
        fail("Production Vault должен содержать словарь переменных")

    hosts_document = load_yaml(hosts_path)
    children = hosts_document.get("all", {}).get("children", {})
    entry_hosts = children.get("entry", {}).get("hosts", {})
    exit_hosts = children.get("exit", {}).get("hosts", {})
    front_hosts = children.get("front", {}).get("hosts", {})
    if not isinstance(entry_hosts, dict) or len(entry_hosts) != 1:
        fail("Пороговое хранилище требует ровно один ENTRY сервер")
    if not isinstance(exit_hosts, dict) or not exit_hosts:
        fail("Пороговое хранилище требует хотя бы один EXIT сервер")
    if not isinstance(front_hosts, dict):
        front_hosts = {}
    active_hosts = list(entry_hosts) + list(exit_hosts) + list(front_hosts)

    changed = False
    shares = document.get("vault_runtime_secret_shares")
    if not isinstance(shares, list) or len(shares) < 3:
        total_shares = max(5, len(active_hosts) + 2)
        if total_shares > 16:
            fail("Слишком много держателей для поддерживаемого набора Shamir-долей")
        data_key = secrets.token_hex(32)
        shares = split_runtime_secret(
            data_key, threshold=2, total=total_shares
        )
        document["vault_runtime_secret_key_sha256"] = hashlib.sha256(
            bytes.fromhex(data_key)
        ).hexdigest()
        document["vault_runtime_secret_shares"] = shares
        changed = True
    if len(active_hosts) > len(shares) - 2:
        fail(
            "Для серверов не хватает уникальных Shamir-долей с сохранением "
            "двух резервных долей"
        )

    exchange_private = document.get("vault_runtime_exchange_private_keys")
    exchange_public = document.get("vault_runtime_exchange_public_keys")
    if not isinstance(exchange_private, dict) or not isinstance(exchange_public, dict):
        exchange_private = {}
        exchange_public = {}
    for host in active_hosts:
        if not exchange_private.get(host) or not exchange_public.get(host):
            private_value, public_value = ssh_exchange_keypair()
            exchange_private[host] = private_value
            exchange_public[host] = public_value
            changed = True
    stale_hosts = (set(exchange_private) | set(exchange_public)) - set(active_hosts)
    for stale_host in stale_hosts:
        exchange_private.pop(stale_host, None)
        exchange_public.pop(stale_host, None)
        changed = True
    document["vault_runtime_exchange_private_keys"] = exchange_private
    document["vault_runtime_exchange_public_keys"] = exchange_public

    all_vars = load_yaml(all_path)
    expected_all = {
        "runtime_secrets_enabled": True,
        "runtime_secrets_threshold": 2,
        "runtime_secrets_total_shares": len(shares),
        "runtime_secrets_runtime_root": "/run/kalimera-secrets",
        "runtime_secrets_state_root": "/var/lib/kalimera-secrets",
        "runtime_secrets_config_root": "/etc/kalimera-secrets",
        "runtime_secrets_peer_timeout_seconds": 7,
        "runtime_secrets_unlock_timeout_seconds": 180,
        "runtime_secrets_service_name": "kalimera-secrets-unlock.service",
        "runtime_secrets_ctl_path": "/usr/local/sbin/kalimera-secretctl",
    }
    if not all_vars.get("runtime_secrets_cluster_id"):
        expected_all["runtime_secrets_cluster_id"] = secrets.token_hex(16)
    for key, value in expected_all.items():
        if all_vars.get(key) != value:
            all_vars[key] = value
            changed = True

    local_controller = any(
        isinstance(values, dict)
        and values.get("ansible_connection") == "local"
        for values in entry_hosts.values()
    )

    for share_index, host in enumerate(active_hosts, start=1):
        host_group = (
            entry_hosts
            if host in entry_hosts
            else exit_hosts
            if host in exit_hosts
            else front_hosts
        )
        host_values = host_group[host]
        if not isinstance(host_values, dict):
            host_values = {}
            host_group[host] = host_values
        if host_values.get("runtime_secrets_share_index") != share_index:
            host_values["runtime_secrets_share_index"] = share_index
            changed = True
        if host in exit_hosts or host in front_hosts:
            advertise_ipv4 = host_values.get("ansible_host", host)
            if host_values.get("runtime_secrets_advertise_ipv4") != advertise_ipv4:
                host_values["runtime_secrets_advertise_ipv4"] = advertise_ipv4
                changed = True

    existing_entry_vars = load_yaml(entry_path)
    existing_exit_vars = load_yaml(exit_path)
    all_runtime_peers = (
        "{{ ((groups['entry'] | default([])) + "
        "(groups['exit'] | default([])) + (groups['front'] | default([]))) "
        "| reject('equalto', inventory_hostname) | list }}"
    )
    group_runtime_values: list[tuple[Path, int, str]] = [
        (entry_path, 1, all_runtime_peers),
        (
            exit_path,
            2,
            all_runtime_peers,
        ),
    ]
    if front_hosts:
        group_runtime_values.append((front_path, 3, all_runtime_peers))
    for path, index, peers in group_runtime_values:
        values = load_yaml(path)
        if values.get("runtime_secrets_share_index") != index:
            values["runtime_secrets_share_index"] = index
            changed = True
        if values.get("runtime_secrets_peer_inventory_hosts") != peers:
            values["runtime_secrets_peer_inventory_hosts"] = peers
            changed = True
        advertise = None
        if index == 1:
            advertise = existing_exit_vars.get("security_interserver_peer_ipv4")
        elif index == 2:
            advertise = existing_entry_vars.get("security_interserver_peer_ipv4")
        if not advertise:
            advertise = (
                "{{ entry_public_endpoint | default(ansible_host) }}"
                if index == 1
                else "{{ ansible_host }}"
            )
        if values.get("runtime_secrets_advertise_ipv4") != advertise:
            values["runtime_secrets_advertise_ipv4"] = advertise
            changed = True
        if index == 1 and local_controller:
            controller_values = {
                "runtime_secrets_controller_vault_password_path": str(vault_password),
                "runtime_secrets_controller_ssh_private_key_path": str(
                    Path.home() / ".ssh" / "awg-iac-production"
                ),
                "runtime_secrets_controller_client_state_path": str(
                    Path.home()
                    / ".local"
                    / "share"
                    / "awg-iac"
                    / "production"
                    / "clients"
                ),
            }
            for key, value in controller_values.items():
                if values.get(key) != value:
                    values[key] = value
                    changed = True
        yaml_write(path, values)

    if changed:
        yaml_write(hosts_path, hosts_document)
        yaml_write(all_path, all_vars)
        plaintext = yaml.safe_dump(document, sort_keys=False).encode("utf-8")
        temporary = vault_path.with_name(
            f".{vault_path.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            secure_write(temporary, vault_lib.encrypt(plaintext))
            os.replace(temporary, vault_path)
            vault_path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)
        print(
            "Production inventory обновлён: включено пороговое хранение "
            "runtime-секретов 2-of-5."
        )
    return changed


def ensure_admin_account_material(
    production: Path,
    vault_password: Path,
    repo: Path,
    *,
    pending_passwords: dict[str, str] | None = None,
    regenerate_undelivered: bool = False,
) -> bool:
    """Подготовить рабочие учётные записи без рассинхронизации sudo на resume."""
    vault_path = production / "group_vars" / "all" / "vault.yml"
    all_path = production / "group_vars" / "all" / "main.yml"
    hosts_path = production / "hosts.yml"
    if not all(path.is_file() for path in (vault_path, all_path, hosts_path)):
        fail("Production inventory неполон для создания рабочего администратора")

    vault_secret = vault_password.read_bytes().rstrip(b"\r\n")
    vault_lib = VaultLib([("default", VaultSecret(vault_secret))])
    try:
        vault_document = yaml.safe_load(vault_lib.decrypt(vault_path.read_bytes()))
    except Exception as error:
        fail(f"Не удалось расшифровать production Vault: {type(error).__name__}")
    if not isinstance(vault_document, dict):
        fail("Production Vault должен содержать словарь переменных")

    all_vars = load_yaml(all_path)
    hosts_document = load_yaml(hosts_path)
    children = hosts_document.get("all", {}).get("children", {})
    front_hosts = children.get("front", {}).get("hosts", {})
    has_front = isinstance(front_hosts, dict) and bool(front_hosts)
    passwords_delivered = all_vars.get("security_account_passwords_delivered")
    redeliver_undelivered = bool(
        regenerate_undelivered and passwords_delivered is False
    )
    required: list[tuple[str, str | None, str]] = [
        (
            "vault_entry_kalimera_password_hash",
            "vault_entry_kalimera_password",
            "ENTRY · kalimera",
        ),
        ("vault_entry_root_password_hash", None, "ENTRY · root"),
        (
            "vault_exit_kalimera_password_hash",
            "vault_exit_kalimera_password",
            "EXIT · kalimera",
        ),
        ("vault_exit_root_password_hash", None, "EXIT · root"),
    ]
    if has_front:
        required.extend(
            [
                (
                    "vault_front_kalimera_password_hash",
                    "vault_front_kalimera_password",
                    "FRONT · kalimera",
                ),
                ("vault_front_root_password_hash", None, "FRONT · root"),
            ]
        )
    passwords_for_delivery: dict[str, str] = {}
    vault_changed = False
    admin_material_changed = False
    for hash_key, automation_password_key, label in required:
        missing_hash = not str(vault_document.get(hash_key, "")).startswith("$6$")
        automation_password = (
            str(vault_document.get(automation_password_key, ""))
            if automation_password_key
            else ""
        )
        if automation_password_key and automation_password:
            if missing_hash:
                vault_document[hash_key] = hash_account_password(
                    automation_password
                )
                vault_changed = True
            if redeliver_undelivered:
                passwords_for_delivery[label] = automation_password
            continue

        needs_password = bool(
            missing_hash
            or (automation_password_key and not automation_password)
            or (redeliver_undelivered and automation_password_key is None)
        )
        if needs_password:
            password = generate_account_password()
            passwords_for_delivery[label] = password
            vault_document[hash_key] = hash_account_password(password)
            vault_changed = True
            if automation_password_key:
                vault_document[automation_password_key] = password
                admin_material_changed = True

    changed = vault_changed
    transition_required = admin_material_changed or not bool(
        all_vars.get("security_manage_admin_account", False)
    )
    admin_keys = all_vars.get("security_admin_authorized_keys", [])
    if not isinstance(admin_keys, list) or not any(
        isinstance(key, str) and key.strip() for key in admin_keys
    ):
        all_vars["security_admin_authorized_keys"] = [prompt_admin_public_key()]
        transition_required = True
        changed = True
    expected_all = {
        "security_manage_admin_account": True,
        "security_admin_user": "kalimera",
        "security_controller_repo_path": str(repo),
        "security_require_admin_authorized_key": True,
    }
    if passwords_for_delivery and passwords_delivered is not False:
        expected_all["security_account_passwords_delivered"] = False
    if transition_required:
        expected_all["security_finalize_admin_access"] = False
    for key, value in expected_all.items():
        if all_vars.get(key) != value:
            all_vars[key] = value
            changed = True

    host_mappings: list[tuple[object, str, str]] = [
        (
            children.get("entry", {}).get("hosts", {}),
            "{{ vault_entry_kalimera_password_hash }}",
            "{{ vault_entry_root_password_hash }}",
        ),
        (
            children.get("exit", {}).get("hosts", {}),
            "{{ vault_exit_kalimera_password_hash }}",
            "{{ vault_exit_root_password_hash }}",
        ),
    ]
    if has_front:
        host_mappings.append(
            (
                front_hosts,
                "{{ vault_front_kalimera_password_hash }}",
                "{{ vault_front_root_password_hash }}",
            )
        )
    for hosts, admin_hash, root_hash in host_mappings:
        if not isinstance(hosts, dict) or len(hosts) != 1:
            fail("Для миграции учётных записей требуется по одному хосту каждой активной роли")
        values = next(iter(hosts.values()))
        if not isinstance(values, dict):
            fail("Некорректные host variables production inventory")
        for key, value in (
            ("security_admin_password_hash", admin_hash),
            ("security_root_password_hash", root_hash),
        ):
            if values.get(key) != value:
                values[key] = value
                changed = True

    if changed:
        yaml_write(all_path, all_vars)
        yaml_write(hosts_path, hosts_document)
        plaintext = yaml.safe_dump(vault_document, sort_keys=False).encode("utf-8")
        temporary = vault_path.with_name(
            f".{vault_path.name}.{secrets.token_hex(8)}.tmp"
        )
        try:
            secure_write(temporary, vault_lib.encrypt(plaintext))
            os.replace(temporary, vault_path)
            vault_path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)
    if passwords_for_delivery:
        if pending_passwords is None:
            show_generated_account_passwords(passwords_for_delivery)
        else:
            pending_passwords.update(passwords_for_delivery)
        passwords_for_delivery.clear()
    return changed


def mark_account_passwords_delivered(production: Path) -> None:
    """Запомнить только факт одноразового показа, не сохраняя сами пароли."""
    all_path = production / "group_vars" / "all" / "main.yml"
    values = load_yaml(all_path)
    if values.get("security_account_passwords_delivered") is not True:
        values["security_account_passwords_delivered"] = True
        yaml_write(all_path, values)


def remove_bootstrap_become_passwords(
    production: Path, vault_password: Path
) -> bool:
    """Удалить только пароли первоначальных SSH-пользователей.

    Пароли ``kalimera`` остаются исключительно внутри Ansible Vault: они нужны
    для ``sudo`` при повторном deploy, но не выводятся после первого показа.
    """
    vault_path = production / "group_vars" / "all" / "vault.yml"
    if not vault_path.is_file() or not vault_password.is_file():
        fail("Production Vault недоступен для удаления bootstrap-паролей")
    vault_secret = vault_password.read_bytes().rstrip(b"\r\n")
    vault_lib = VaultLib([("default", VaultSecret(vault_secret))])
    try:
        document = yaml.safe_load(vault_lib.decrypt(vault_path.read_bytes()))
    except Exception as error:
        fail(f"Не удалось расшифровать production Vault: {type(error).__name__}")
    if not isinstance(document, dict):
        fail("Production Vault должен содержать словарь переменных")
    changed = False
    for key in (
        "vault_entry_become_password",
        "vault_exit_become_password",
        "vault_front_become_password",
    ):
        if key in document:
            del document[key]
            changed = True
    if not changed:
        return False
    plaintext = yaml.safe_dump(document, sort_keys=False).encode("utf-8")
    temporary = vault_path.with_name(f".{vault_path.name}.{secrets.token_hex(8)}.tmp")
    try:
        secure_write(temporary, vault_lib.encrypt(plaintext))
        os.replace(temporary, vault_path)
        vault_path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return True


AWG_CLIENT_PROFILES = {
    "performance": {
        "jc": (4, 4), "jmin": (64, 64), "jmax": (80, 96),
    },
    "balanced": {
        "jc": (5, 7), "jmin": (64, 96), "jmax": (128, 384),
    },
    "masking": {
        "jc": (8, 10), "jmin": (96, 192), "jmax": (384, 1024),
    },
    "mobile": {
        "jc": (5, 5), "jmin": (10, 10), "jmax": (50, 50),
    },
    "old": {
        "jc": (4, 6), "jmin": (64, 64), "jmax": (80, 96),
    },
}

AWG3_MOBILE_FEATURE_DEFAULTS = {
    "content_padding_addition": "8-32",
    "rekey_after_time": "120-180",
    "rekey_timeout": "5-8",
    "reject_after_time": "180-240",
    "keepalive_timeout": "10-15",
    "max_handshake_attempts": "18-24",
    "persistent_keepalive": "22-30",
    "random_trailers": True,
    "disable_cookies": False,
}

AWG_QUIC_INITIAL_SIZE = 1200
AWG_CPS_RANDOM_TAG_MAX = 1000
AWG_MINIMUM_OUTER_PMTU = 1280


def random_between(bounds: tuple[int, int]) -> int:
    lower, upper = bounds
    return lower + secrets.randbelow(upper - lower + 1)


def awg_random_bytes_tags(size: int) -> str:
    """Описать случайные байты тегами CPS, каждый не длиннее 1000 байт."""
    if size < 1:
        fail("Размер случайного поля CPS должен быть положительным")
    tags = []
    remaining = size
    while remaining:
        chunk = min(remaining, AWG_CPS_RANDOM_TAG_MAX)
        tags.append(f"<r {chunk}>")
        remaining -= chunk
    return "".join(tags)


def normalize_awg_cps_signature(signature: str) -> str:
    """Разбить устаревшие теги <r N> с N > 1000 без изменения длины пакета."""

    def replace(match: re.Match[str]) -> str:
        size = int(match.group(1))
        if size <= AWG_CPS_RANDOM_TAG_MAX:
            return match.group(0)
        return awg_random_bytes_tags(size)

    return re.sub(r"<r ([0-9]+)>", replace, signature)


def awg_cps_signature_size(signature: str) -> int:
    """Проверить CPS-синтаксис и вернуть точный размер сформированного пакета."""
    if not signature:
        return 0
    tags = re.findall(r"<(r [0-9]+|b 0x[0-9A-Fa-f]+)>", signature)
    if "".join(f"<{tag}>" for tag in tags) != signature:
        fail("AWG-профиль содержит неподдерживаемый CPS-тег")
    size = 0
    for tag in tags:
        kind, value = tag.split(maxsplit=1)
        if kind == "r":
            random_size = int(value)
            if not 1 <= random_size <= AWG_CPS_RANDOM_TAG_MAX:
                fail("Размер случайного CPS-тега AWG должен быть от 1 до 1000")
            size += random_size
        else:
            hexadecimal = value[2:]
            if len(hexadecimal) == 0 or len(hexadecimal) % 2:
                fail("Hex-значение CPS-тега AWG должно содержать целые байты")
            size += len(hexadecimal) // 2
    return size


def validate_awg_obfuscation(
    profile: dict[str, object], outer_pmtu: int = AWG_MINIMUM_OUTER_PMTU
) -> None:
    """Отклонить профиль, который нарушает инварианты AWG или безопасный PMTU."""
    required = {
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
    }
    if set(profile) != required:
        fail("AWG-профиль содержит неполный или неизвестный набор параметров")

    jc, jmin, jmax = (int(profile[name]) for name in ("jc", "jmin", "jmax"))
    if not (1 <= jc <= 128 and 0 <= jmin <= jmax and jmax + 28 <= outer_pmtu):
        fail("Jc/Jmin/Jmax AWG не согласованы с безопасным PMTU")

    s1, s2, s3, s4 = (int(profile[name]) for name in ("s1", "s2", "s3", "s4"))
    if any(value < 0 or value > 65535 for value in (s1, s2, s3, s4)):
        fail("S1-S4 AWG выходят за допустимый диапазон")
    if s1 + 56 == s2 or (s3 > 0 and s2 + 28 == s3):
        fail("S-параметры AWG создают коллизию размеров служебных сообщений")

    header_intervals: list[tuple[int, int]] = []
    for name in ("h1", "h2", "h3", "h4"):
        raw = str(profile[name])
        match = re.fullmatch(r"([0-9]+)(?:-([0-9]+))?", raw)
        if match is None:
            fail(f"{name.upper()} AWG имеет неверный формат")
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not 1 <= start <= end <= 2_147_483_647:
            fail(f"{name.upper()} AWG выходит за допустимый диапазон")
        if any(start <= previous_end and previous_start <= end
               for previous_start, previous_end in header_intervals):
            fail("H1-H4 AWG пересекаются")
        header_intervals.append((start, end))

    for name in ("i1", "i2", "i3", "i4", "i5"):
        packet_size = awg_cps_signature_size(str(profile[name]))
        if packet_size and packet_size + 28 > outer_pmtu:
            fail(f"{name.upper()} AWG превышает минимальный внешний PMTU")


def awg_quic_initial_signature(target_size: int = AWG_QUIC_INITIAL_SIZE) -> str:
    """Создать индивидуальный QUIC Initial-подобный I1 заданного размера.

    Размер по умолчанию (1200 байт) используется общим профилем
    (`awg_server_obfuscation`, KeeneticOS/mobile/transit до переопределения).
    Явный `target_size` позволяет профилям с большим запасом MTU (например,
    межсерверному AWG3+) использовать более крупный I1 без изменения этого
    общего значения для остальных профилей.

    Доступные upstream-теги AWG не умеют вычислять QUIC AEAD, поэтому пакет не
    выдаётся за полноценное QUIC-соединение. При этом его открытая структура
    соответствует длинному заголовку QUIC v1: версия, случайные DCID/SCID,
    token length, корректная QUIC varint-длина и packet number выбранной длины.
    Случайные поля и заполнение создаются заново при каждой отправке.
    """
    packet_number_size = random_between((1, 4))
    first_byte = 0xC0 | (packet_number_size - 1)
    dcid_size = random_between((8, 20))
    scid_size = random_between((8, 20))
    fixed_size = 10 + dcid_size + scid_size
    protected_size = target_size - fixed_size
    if not 64 <= protected_size < 16384:
        fail("Не удалось сформировать безопасный размер QUIC-подобной AWG-сигнатуры")
    encoded_length = 0x4000 | protected_size
    return (
        f"<b 0x{first_byte:02x}00000001{dcid_size:02x}>"
        f"{awg_random_bytes_tags(dcid_size)}"
        f"<b 0x{scid_size:02x}>"
        f"{awg_random_bytes_tags(scid_size)}"
        f"<b 0x00{encoded_length:04x}>"
        f"{awg_random_bytes_tags(protected_size)}"
    )


def awg_quic_short_signature(size_bounds: tuple[int, int]) -> str:
    """Создать дополнительный пакет с формой короткого заголовка QUIC."""
    packet_size = random_between(size_bounds)
    first_byte = 0x40 | secrets.randbelow(0x20)
    return f"<b 0x{first_byte:02x}><r {packet_size - 1}>"


def awg_message_padding() -> tuple[int, int, int]:
    """Создать S1-S3 без совпадения размеров служебных сообщений AWG."""
    s1 = random_between((16, 64))
    s2 = random_between((16, 64))
    while s1 + 56 == s2:
        s2 = random_between((16, 64))
    s3 = random_between((16, 64))
    while s2 + 28 == s3:
        s3 = random_between((16, 64))
    return s1, s2, s3


def awg_server_obfuscation() -> dict[str, object]:
    """Создать постоянный профиль AWG2 для KeeneticOS 5.1.x."""
    header_ranges = []
    for bucket in range(4):
        bucket_start = 1 + bucket * 500_000_000
        start = bucket_start + secrets.randbelow(200_000_001)
        end = start + random_between((50_000_000, 200_000_000))
        header_ranges.append(f"{start}-{end}")
    secrets.SystemRandom().shuffle(header_ranges)
    s1, s2, s3 = awg_message_padding()
    result = {
        "jc": 6,
        "jmin": 64,
        "jmax": 192,
        "s1": s1,
        "s2": s2,
        "s3": s3,
        # HeaderProtectionKey в AWG 3+ требует S1-S4 не меньше 12.
        # Единый нижний предел позволяет безопасно использовать профиль и
        # для клиентского AWG2, и как основу межсерверного AWG3.
        "s4": random_between((12, 32)),
        "h1": header_ranges[0],
        "h2": header_ranges[1],
        "h3": header_ranges[2],
        "h4": header_ranges[3],
        "i1": awg_quic_initial_signature(),
        "i2": awg_quic_short_signature((96, 192)),
        "i3": awg_quic_short_signature((64, 160)),
        "i4": awg_quic_short_signature((48, 128)),
        "i5": awg_quic_short_signature((32, 96)),
    }
    validate_awg_obfuscation(result)
    return result


def awg_legacy_server_obfuscation() -> dict[str, object]:
    """Создать базовый ASC-профиль с одиночными H для KeeneticOS до 5.1."""
    headers = secrets.SystemRandom().sample(range(5, 2_147_483_648), 4)
    s1, s2, _ = awg_message_padding()
    result = {
        "jc": 4,
        "jmin": 64,
        "jmax": 96,
        "s1": s1,
        "s2": s2,
        "s3": 0,
        "s4": 0,
        "h1": headers[0],
        "h2": headers[1],
        "h3": headers[2],
        "h4": headers[3],
        "i1": "",
        "i2": "",
        "i3": "",
        "i4": "",
        "i5": "",
    }
    validate_awg_obfuscation(result)
    return result


def awg_mobile_awg3_obfuscation() -> dict[str, object]:
    """Создать полный профиль маскировки mobile/AWG3+ для AWG 3.1."""
    result = awg_server_obfuscation()
    result.update({"jc": 5, "jmin": 10, "jmax": 50})
    validate_awg_obfuscation(result)
    if any(int(result[key]) < 12 for key in ("s1", "s2", "s3", "s4")):
        fail("Mobile/AWG3+ требует S1-S4 не меньше 12")
    if any(not str(result[f"i{index}"]) for index in range(1, 6)):
        fail("Mobile/AWG3+ требует полный набор I1-I5")
    return result


def awg_mobile_awg3_profile_is_complete(value: object) -> bool:
    """Проверить полноту сохранённого профиля без вывода его значений."""
    if not isinstance(value, dict):
        return False
    required = (
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
    )
    if any(key not in value for key in required):
        return False
    try:
        if any(int(value[key]) < 12 for key in ("s1", "s2", "s3", "s4")):
            return False
    except (TypeError, ValueError):
        return False
    return all(str(value[f"i{index}"]).strip() for index in range(1, 6))


def awg3_transit_obfuscation() -> dict[str, object]:
    """Создать профиль обфускации межсерверного AWG3+ (ENTRY-EXIT).

    Jc/Jmin/Jmax и I1-I5 переопределены относительно общего
    `awg_server_obfuscation()` в сторону большей энтропии/размера: это
    длинный высоконагруженный туннель без клиентского MTU-ограничения
    (в отличие от KeeneticOS/mobile), а сами эти поля - junk и
    handshake-смежные пакеты, а не поле, применяемое к каждому
    транспортному пакету, поэтому увеличение почти не стоит пропускной
    способности (см. docs/awg3.md). Значения оставлены с явным запасом
    от защитного предела `+28 <= 1280` в `validate_awg_obfuscation`
    (используется её MTU-независимый дефолт, а не фактический
    согласованный MTU канала - профиль должен оставаться безопасным даже
    при самом низком допустимом MTU).
    """
    result = awg_server_obfuscation()
    result.update({
        "jc": 12,
        "jmin": 64,
        "jmax": 512,
        "i1": awg_quic_initial_signature(1240),
        "i2": awg_quic_short_signature((96, 384)),
        "i3": awg_quic_short_signature((64, 320)),
        "i4": awg_quic_short_signature((48, 256)),
        "i5": awg_quic_short_signature((32, 192)),
    })
    validate_awg_obfuscation(result)
    return result


def awg_client_obfuscation(
    profile_name: str, server_profile: dict[str, object]
) -> dict[str, object]:
    profile = AWG_CLIENT_PROFILES[profile_name]
    result = {
        "jc": random_between(profile["jc"]),
        "jmin": random_between(profile["jmin"]),
        "jmax": random_between(profile["jmax"]),
    }
    for key in (
        "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
        "i1", "i2", "i3", "i4", "i5",
    ):
        result[key] = server_profile[key]
    validate_awg_obfuscation(result)
    return result


def secure_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def yaml_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"Ожидалась структура YAML mapping: {path}")
    return value


def update_client_config_mtu(
    config: Path, result: Path, client_mode: str | bool
) -> None:
    """Атомарно записать согласованный MTU в готовый клиентский конфиг."""
    values = load_yaml(result)
    if client_mode is True or client_mode == "legacy":
        key = "legacy_client_mtu"
    elif client_mode == "mobile":
        key = "mobile_client_mtu"
    else:
        key = "client_mtu"
    mtu = int(values[key])
    if not 576 <= mtu <= 1420:
        fail("Получен недопустимый результат автоматического согласования MTU")
    lines = config.read_text(encoding="utf-8").splitlines()
    replaced = False
    for index, line in enumerate(lines):
        if line.startswith("MTU = "):
            lines[index] = f"MTU = {mtu}"
            replaced = True
            break
    if not replaced:
        fail("В клиентской конфигурации не найден параметр MTU")
    temporary = config.with_name(f".{config.name}.{secrets.token_hex(8)}.tmp")
    secure_write(temporary, ("\n".join(lines) + "\n").encode())
    os.replace(temporary, config)
    config.chmod(0o600)


def update_saved_client_configs_mtu(clients_dir: Path, result: Path) -> None:
    """Согласовать MTU всех локально сохранённых конфигов после resume."""
    if not clients_dir.is_dir() or not result.is_file():
        return
    for config in clients_dir.glob("*.conf"):
        text = config.read_text(encoding="utf-8")
        update_client_config_mtu(config, result, "S3 = " not in text)


def update_saved_client_configs_cps(clients_dir: Path) -> None:
    """Атомарно исправить превышающие 1000 байт CPS-теги сохранённых клиентов."""
    if not clients_dir.is_dir():
        return
    for config in clients_dir.glob("*.conf"):
        lines = config.read_text(encoding="utf-8").splitlines()
        changed = False
        for index, line in enumerate(lines):
            match = re.match(r"^(I[1-5]\s*=\s*)(.*)$", line)
            if match is None:
                continue
            normalized = normalize_awg_cps_signature(match.group(2))
            if normalized != match.group(2):
                lines[index] = f"{match.group(1)}{normalized}"
                changed = True
        if not changed:
            continue
        temporary = config.with_name(f".{config.name}.{secrets.token_hex(8)}.tmp")
        secure_write(temporary, ("\n".join(lines) + "\n").encode())
        os.replace(temporary, config)
        config.chmod(0o600)


def pin_resolved_awg_packages(all_vars_path: Path, lock_path: Path) -> None:
    """Сохранить первый разрешённый набор PPA-пакетов для повторных запусков."""
    mapping = {
        "amneziawg": "amneziawg",
        "amneziawg-dkms": "amneziawg_dkms",
        "amneziawg-tools": "amneziawg_tools",
    }
    resolved: dict[str, str] = {}
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        package, separator, version = line.partition("=")
        if separator and package in mapping and version:
            resolved[mapping[package]] = version
    if set(resolved) != set(mapping.values()):
        fail("Получен неполный список закреплённых версий AmneziaWG")
    variables = load_yaml(all_vars_path)
    variables["awg_package_version_mode"] = "pinned"
    variables["awg_package_versions"] = resolved
    yaml_write(all_vars_path, variables)


def prepare_component_update(repo: Path, production: Path) -> None:
    """Выбрать новые AWG-пакеты и проверенный manifest остальных компонентов."""
    all_vars_path = production / "group_vars" / "all" / "main.yml"
    entry_vars_path = production / "group_vars" / "entry.yml"
    exit_vars_path = production / "group_vars" / "exit.yml"
    stable_entry_path = repo / "inventory" / "example" / "group_vars" / "entry.yml"
    awg3_defaults_path = repo / "roles" / "awg3_transit" / "defaults" / "main.yml"
    awg3_mobile_defaults_path = repo / "roles" / "awg3_mobile" / "defaults" / "main.yml"
    variables = load_yaml(all_vars_path)
    entry_variables = load_yaml(entry_vars_path)
    exit_variables = load_yaml(exit_vars_path)
    stable_entry = load_yaml(stable_entry_path)
    awg3_defaults = load_yaml(awg3_defaults_path)
    awg3_mobile_defaults = load_yaml(awg3_mobile_defaults_path)

    variables["awg_package_version_mode"] = "candidate"
    variables.pop("awg_package_versions", None)
    for key in ("entry_sing_box_version", "entry_sing_box_packages"):
        if key not in stable_entry:
            fail(f"Проверенный manifest компонентов не содержит {key}")
        entry_variables[key] = stable_entry[key]
    for key in AWG3_COMPONENT_KEYS:
        if key not in awg3_defaults:
            fail(f"Проверенный manifest AWG3 не содержит {key}")
        variables[key] = awg3_defaults[key]
    for key in AWG3_MOBILE_COMPONENT_KEYS:
        if key not in awg3_mobile_defaults:
            fail(f"Проверенный manifest mobile AWG 3.1 не содержит {key}")
        variables[key] = awg3_mobile_defaults[key]
    # Профиль обфускации межсерверного канала - как и версии пакетов выше,
    # часть проверенного manifest этого выпуска репозитория, а не только
    # первичной установки. Пересоздаётся заново (свежие Jc/Jmin/Jmax/S1-S4/
    # H1-H4/I1-I5 - см. awg3_transit_obfuscation()) и записывается
    # одинаково на ENTRY и EXIT, иначе стороны разойдутся и handshake
    # перестанет собираться.
    transit_obfuscation = awg3_transit_obfuscation()
    entry_variables["awg3_transit_obfuscation"] = transit_obfuscation
    exit_variables["awg3_transit_obfuscation"] = transit_obfuscation
    yaml_write(all_vars_path, variables)
    yaml_write(entry_vars_path, entry_variables)
    yaml_write(exit_vars_path, exit_variables)


def restore_file(path: Path, content: bytes | None) -> None:
    """Атомарно восстановить файл транзакции либо удалить созданный файл."""
    if content is None:
        path.unlink(missing_ok=True)
        return
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.rollback")
    secure_write(temporary, content)
    os.replace(temporary, path)


def bootstrap_key(
    host: str,
    user: str,
    port: int,
    password: str,
    public_key: Path,
    server_label: str,
) -> str:
    candidate = password
    argv = [
        require_command("sshpass"),
        "-e",
        require_command("ssh-copy-id"),
        "-i",
        str(public_key),
        "-p",
        str(port),
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
        f"{user}@{host}",
    ]
    for attempt in range(1, 4):
        print(f"{server_label}: установка ключа для {user}@{host}:{port} (попытка {attempt}/3)...")
        environment = os.environ.copy()
        environment["SSHPASS"] = candidate
        try:
            result = subprocess.run(argv, check=False, env=environment, timeout=45)
        except subprocess.TimeoutExpired:
            print(
                f"{server_label} не ответил за 45 секунд. Проверьте доступность "
                f"TCP/{port} с управляющего сервера, UFW, Fail2Ban и firewall хостинга."
            )
            if attempt < 3:
                print(f"{server_label}: повтор подключения без повторного запроса пароля.")
                continue
            break
        if result.returncode == 0:
            print(f"{server_label}: вход по установленному ключу подготовлен.")
            return candidate
        if attempt < 3:
            print(
                f"{server_label} отклонил подключение. Проверьте текущий SSH-порт, "
                "пользователя и разрешение входа по паролю."
            )
            candidate = getpass.getpass(
                f"Повторите пароль SSH {server_label} (ввод скрыт): "
            )
            if not candidate:
                fail(f"Пароль SSH {server_label} не может быть пустым")
    fail(
        f"Не удалось установить SSH-ключ на {server_label} ({user}@{host}:{port}). "
        "Проверьте доступ обычной командой ssh и настройку PasswordAuthentication на сервере."
    )


def install_local_key(user: str, public_key: Path) -> None:
    if os.geteuid() != 0:
        fail("Локальную установку ENTRY сервера необходимо запускать от root")
    account = pwd.getpwnam(user)
    ssh_dir = Path(account.pw_dir) / ".ssh"
    ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    ssh_dir.chmod(0o700)
    authorized = ssh_dir / "authorized_keys"
    line = public_key.read_text(encoding="utf-8").strip()
    existing = authorized.read_text(encoding="utf-8") if authorized.exists() else ""
    if line not in existing.splitlines():
        with authorized.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    os.chown(ssh_dir, account.pw_uid, account.pw_gid)
    os.chown(authorized, account.pw_uid, account.pw_gid)
    authorized.chmod(0o600)


def check_ssh(host: str, user: str, port: int, private_key: Path) -> None:
    run(
        [
            require_command("ssh"),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
            "-i",
            str(private_key),
            "-p",
            str(port),
            f"{user}@{host}",
            "true",
        ]
    )


def ssh_connection_works(host: str, user: str, port: int, private_key: Path) -> bool:
    """Проверить управляющий SSH без вывода диагностики и изменения сервера."""
    result = subprocess.run(
        [
            require_command("ssh"),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ConnectionAttempts=1",
            "-i",
            str(private_key),
            "-p",
            str(port),
            f"{user}@{host}",
            "true",
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def remote_observed_ssh_source_ipv4(
    host: str,
    user: str,
    port: int,
    private_key: Path,
) -> str:
    """Получить реальный source IPv4 так, как его видит удалённый sshd.

    Значение интерфейса управляющей VPS может отличаться от адреса после SNAT.
    Ограничивать ключ ``from=`` безопасно только фактически наблюдаемым адресом.
    """
    result = subprocess.run(
        [
            require_command("ssh"),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ConnectionAttempts=1",
            "-i",
            str(private_key),
            "-p",
            str(port),
            f"{user}@{host}",
            "printf '%s\\n' \"$SSH_CONNECTION\"",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return ""
    fields = result.stdout.strip().split()
    if len(fields) != 4:
        return ""
    candidate = fields[0]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return ""
    return candidate if isinstance(address, ipaddress.IPv4Address) and address.is_global else ""


def verify_saved_inventory_access(hosts_document: dict) -> None:
    """Не запускать resume и cleanup через уже недоступную учётную запись."""
    inaccessible: list[str] = []
    children = hosts_document["all"]["children"]
    for group in ("entry", "exit", "front"):
        for name, variables in children.get(group, {}).get("hosts", {}).items():
            if variables.get("ansible_connection") == "local":
                continue
            private_key = Path(str(variables["ansible_ssh_private_key_file"]))
            if not ssh_connection_works(
                str(variables["ansible_host"]),
                str(variables["ansible_user"]),
                int(variables["ansible_port"]),
                private_key,
            ):
                inaccessible.append(
                    f"{name}: {variables['ansible_user']}@{variables['ansible_host']}:"
                    f"{variables['ansible_port']}"
                )
    if inaccessible:
        fail(
            "Сохранённый управляющий SSH-канал недоступен:\n  - "
            + "\n  - ".join(inaccessible)
            + "\nAnsible и аварийная очистка не запускались. "
            "Восстановите служебный ключ через консоль хостинга либо "
            "административный вход kalimera, затем повторите './deploy --resume'."
        )


def recover_saved_admin_access(
    hosts_document: dict,
    hosts_path: Path,
    admin_user: str = "kalimera",
    root_login_finalized: bool = False,
) -> list[str]:
    """Исправить inventory, если root уже закрыт, а kalimera доступен.

    Финальная SSH-политика может успеть примениться непосредственно перед
    прерыванием deploy. Тогда новый сеанс root уже запрещён, хотя inventory
    ещё содержит промежуточного пользователя root. Менять канал можно только
    после отдельной успешной проверки того же ключа как ``kalimera``.
    """
    recovered: list[str] = []
    children = hosts_document["all"]["children"]
    for group in ("entry", "exit", "front"):
        for name, variables in children.get(group, {}).get("hosts", {}).items():
            if variables.get("ansible_connection") == "local":
                continue
            private_key_value = variables.get("ansible_ssh_private_key_file")
            host_value = variables.get("ansible_host")
            port_value = variables.get("ansible_port")
            if not private_key_value or not host_value or port_value is None:
                continue
            private_key = Path(str(private_key_value))
            host = str(host_value)
            current_user = str(variables.get("ansible_user", admin_user))
            current_port = int(port_value)
            current_login_expected = not (
                root_login_finalized and current_user == "root"
            )
            if current_login_expected and ssh_connection_works(
                host, current_user, current_port, private_key
            ):
                continue

            candidate_ports = [current_port]
            managed_port = int(variables.get("ssh_listen_port", current_port))
            if managed_port not in candidate_ports:
                candidate_ports.append(managed_port)
            recovered_port = next(
                (
                    port
                    for port in candidate_ports
                    if ssh_connection_works(host, admin_user, port, private_key)
                ),
                None,
            )
            if recovered_port is None:
                continue

            variables["ansible_user"] = admin_user
            variables["ansible_port"] = recovered_port
            variables["ansible_become"] = True
            variables["ansible_become_method"] = "sudo"
            variables["ansible_become_password"] = (
                "{{ vault_" + group + "_kalimera_password }}"
            )
            if recovered_port != current_port:
                variables["security_previous_ssh_port"] = current_port
                variables["security_allow_ssh_port_change"] = False
            recovered.append(name)

    if recovered:
        yaml_write(hosts_path, hosts_document)
        print(
            "Production inventory восстановлен через подтверждённый SSH-доступ "
            f"{admin_user}: " + ", ".join(recovered) + "."
        )
    return recovered


def refresh_saved_automation_sources(hosts_document: dict, hosts_path: Path) -> bool:
    """Актуализировать ``from=`` по уже проверенному управляющему SSH-сеансу."""
    changed = False
    observed_values: set[str] = set()
    children = hosts_document["all"]["children"]
    for group in ("entry", "exit", "front"):
        for name, variables in children.get(group, {}).get("hosts", {}).items():
            if variables.get("ansible_connection") == "local":
                continue
            observed = remote_observed_ssh_source_ipv4(
                str(variables["ansible_host"]),
                str(variables["ansible_user"]),
                int(variables["ansible_port"]),
                Path(str(variables["ansible_ssh_private_key_file"])),
            )
            if not observed:
                fail(
                    f"{name} не подтвердил исходный IPv4 проверенного SSH-сеанса. "
                    "Конфигурация не изменялась."
                )
            observed_values.add(observed)
            if variables.get("security_automation_source_ipv4") != observed:
                variables["security_automation_source_ipv4"] = observed
                changed = True
    if changed:
        yaml_write(hosts_path, hosts_document)
        print(
            "Production inventory обновлён: фактический IPv4 служебного SSH - "
            + ", ".join(sorted(observed_values))
            + "."
        )
    return changed


def require_operator_ssh_confirmation() -> None:
    print("\nПеред удалением старого SSH-порта откройте отдельный терминал на своём компьютере.")
    print("Проверьте вход пользователем kalimera по вашему закрытому ключу на всех активных серверах через новые SSH-порты.")
    print("Не подтверждайте этап, пока все независимые SSH-сеансы не открылись.")
    if not prompt_bool("Вход kalimera по административному ключу проверен на всех серверах", False):
        fail("Установка безопасно остановлена: старые SSH-порты сохранены, Fail2Ban не включён")


def show_front_deploy_state(production: Path) -> None:
    """Показать оператору выбранную топологию FRONT до изменения серверов."""
    hosts_path = production / "hosts.yml"
    front_path = production / "group_vars" / "front.yml"
    if not hosts_path.is_file():
        return
    hosts = load_yaml(hosts_path)
    front_hosts = (
        hosts.get("all", {})
        .get("children", {})
        .get("front", {})
        .get("hosts", {})
    )
    if not isinstance(front_hosts, dict) or not front_hosts:
        ui_panel(
            "FRONT И CDN",
            [
                "FRONT: не включён",
                "CDN: не используется",
                "Пользовательский VLESS: отсутствует",
            ],
            "yellow",
        )
        return
    front_vars = load_yaml(front_path) if front_path.is_file() else {}
    modes = front_vars.get("front_access_modes", ["direct"])
    mode_text = ", ".join(str(mode) for mode in modes)
    cdn_state = str(front_vars.get("front_cdn_state", "not_configured"))
    ui_panel(
        "FRONT И CDN",
        [
            f"FRONT: включён ({front_vars.get('front_active_id', 'front-1')})",
            f"Режимы доступа: {mode_text}",
            f"CDN: {cdn_state}",
            "VLESS: только через FRONT; прямой inbound ENTRY отключён",
        ],
        "cyan",
    )


def show_deployment_summary(production: Path) -> None:
    hosts = load_yaml(production / "hosts.yml")
    all_vars = load_yaml(production / "group_vars" / "all" / "main.yml")
    entry_vars = load_yaml(production / "group_vars" / "entry.yml")
    exit_vars = load_yaml(production / "group_vars" / "exit.yml")
    front_path = production / "group_vars" / "front.yml"
    front_vars = load_yaml(front_path) if front_path.is_file() else {}
    children = hosts["all"]["children"]
    entry = children["entry"]["hosts"]["entry-managed"]
    exit_node = children["exit"]["hosts"]["exit-managed"]
    front_nodes = children.get("front", {}).get("hosts", {})
    entry_public = str(entry_vars.get("entry_public_endpoint", entry["ansible_host"]))
    exit_public = str(exit_node["ansible_host"])
    proxy_enabled = bool(entry_vars.get("entry_ru_proxy_enabled", False))
    dot_items = entry_vars.get("entry_dot_upstreams", [])
    dot_summary = ", ".join(
        f"{item['address']} (TLS: {item['tls_name']})" for item in dot_items
    )
    doh_summary = (
        f"{entry_vars.get('entry_dns_doh_server')}"
        f"{entry_vars.get('entry_dns_doh_path')} "
        f"(TLS: {entry_vars.get('entry_dns_doh_tls_name')})"
    )
    clients_dir = Path.home() / ".local" / "share" / "awg-iac" / "production" / "clients"
    mtu_file = clients_dir.parent / "mtu.yml"
    client_files = sorted(clients_dir.glob("*.conf")) if clients_dir.is_dir() else []
    admin_user = str(all_vars.get("security_admin_user", "kalimera"))

    access_rows: list[tuple[str, object]] = [
        (
            "SSH ENTRY",
            f"{admin_user}@{entry_public}:{entry['ansible_port']}",
        ),
        (
            "SSH EXIT",
            f"{admin_user}@{exit_public}:{exit_node['ansible_port']}",
        ),
        (
            "VPN-клиенты",
            f"{entry_public}:{entry_vars.get('entry_awg0_listen_port')}/UDP",
        ),
    ]
    if front_nodes:
        front_name, front_node = next(iter(front_nodes.items()))
        access_rows.append(
            (
                "SSH FRONT",
                f"{admin_user}@{front_node['ansible_host']}:{front_node['ansible_port']}",
            )
        )
        front_modes = ", ".join(front_vars.get("front_access_modes", ["direct"]))
        access_rows.append(
            (
                "VLESS FRONT",
                f"{front_modes}; CDN: {front_vars.get('front_cdn_state', 'not_configured')}",
            )
        )
    if entry_vars.get("entry_legacy_client_available", False):
        legacy_state = (
            "включён" if entry_vars.get("entry_legacy_client_enabled", False)
            else "выключен до создания old-клиента"
        )
        access_rows.append(
            (
                "Старые клиенты",
                f"{entry_public}:{entry_vars.get('entry_legacy_client_listen_port')}/UDP; "
                f"{legacy_state}",
            )
        )
    if entry_vars.get("entry_mobile_client_available", False):
        mobile_state = (
            "включён" if entry_vars.get("entry_mobile_client_enabled", False)
            else "выключен до создания mobile-клиента"
        )
        access_rows.append(
            (
                "Мобильные клиенты",
                f"{entry_public}:{entry_vars.get('entry_mobile_client_listen_port')}/UDP; "
                f"AWG 3.1, полный профиль; {mobile_state}",
            )
        )

    transit_label = (
        "AWG 3+ userspace"
        if entry_vars.get("awg3_transit_enabled", False)
        else "AmneziaWG"
    )
    access_rows.append(
        (
            "Канал ENTRY–EXIT",
            f"{entry_vars.get('entry_exit_endpoint')} · {transit_label}",
        )
    )

    architecture_rows: list[tuple[str, object]] = [
        ("Основной маршрут", "VPN-клиент → ENTRY → EXIT → Интернет"),
    ]
    if front_nodes:
        architecture_rows.append(
            (
                "VLESS-маршрут",
                "клиент → FRONT → отдельный REALITY backend ENTRY → EXIT/RU",
            )
        )
    if proxy_enabled:
        architecture_rows.extend(
            [
                ("RU-трафик", "VPN-клиент → ENTRY → SOCKS5/TUN → Интернет"),
                ("RU DNS", f"DoH через прокси: {doh_summary}"),
            ]
        )
    else:
        architecture_rows.extend(
            [
                ("RU-трафик", "VPN-клиент → WAN ENTRY → Интернет"),
                ("RU DNS", "основной резолвер ENTRY по DoT"),
            ]
        )
    architecture_rows.append(
        ("Основной DNS", f"Unbound DoT: {dot_summary or 'не настроен'}")
    )

    security_rows = [
        (
            "UFW ENTRY",
            f"TCP/{entry['ansible_port']} SSH; "
            f"UDP/{entry_vars.get('entry_awg0_listen_port')} клиенты; "
            f"UDP/{entry_vars.get('entry_mobile_client_listen_port')} mobile/AWG3+ при включении; "
            f"UDP/{entry_vars.get('security_interserver_listen_port')} только от "
            f"{entry_vars.get('security_interserver_peer_ipv4')}",
        ),
        (
            "UFW EXIT",
            f"TCP/{exit_node['ansible_port']} SSH; "
            f"UDP/{exit_vars.get('security_interserver_listen_port')} только от "
            f"{exit_vars.get('security_interserver_peer_ipv4')}",
        ),
        (
            "Доступ SSH",
            f"только {admin_user}; root SSH отключён; автоматизация через sudo + Vault",
        ),
        ("Fail2Ban", "включён после подтверждения нового SSH-доступа"),
    ]
    if front_nodes:
        front_node = next(iter(front_nodes.values()))
        security_rows.append(
            (
                "UFW FRONT",
                f"TCP/{front_node['ansible_port']} SSH; TCP/80 ACME; TCP/443 VLESS",
            )
        )

    mtu_rows: list[tuple[str, object]] = []
    if entry_vars.get("awg3_transit_enabled", False):
        if mtu_file.is_file():
            mtu = load_yaml(mtu_file)
            mtu_rows.extend(
                [
                    ("Внешний PMTU", mtu.get("shared_outer_pmtu")),
                    ("MTU AWG 3+", mtu.get("transit_mtu")),
                    ("MTU клиентов", mtu.get("client_mtu")),
                    ("MTU old-клиентов", mtu.get("legacy_client_mtu")),
                    ("MTU mobile-клиентов", mtu.get("mobile_client_mtu")),
                ]
            )
        else:
            mtu_rows.append(
                ("MTU", "будет автоматически измерен в обоих направлениях")
            )

    file_rows: list[tuple[str, object]] = [
        ("Inventory", production),
        (
            "Пароль Vault",
            Path.home() / ".config" / "awg-iac" / "production-vault.pass",
        ),
    ]
    if client_files:
        for path in client_files:
            file_rows.append(
                (
                    f"Клиент {path.stem}",
                    f"{path} · права {stat.S_IMODE(path.stat().st_mode):04o}",
                )
            )
    else:
        file_rows.append(("Каталог клиентов", clients_dir))

    print()
    ui_panel(
        "KALIMERAWG · ИТОГОВАЯ КОНФИГУРАЦИЯ",
        [
            "Установка завершена. Ниже показаны только безопасные данные.",
            "Закрытые ключи, PSK и содержимое клиентских конфигураций не выводятся.",
            "Одноразовые пароли следуют отдельным блоком после этой сводки.",
        ],
        "green",
    )
    ui_rows("ПОДКЛЮЧЕНИЯ", access_rows, "cyan")
    ui_rows("СХЕМА РАБОТЫ И DNS", architecture_rows, "magenta")
    if mtu_rows:
        ui_rows("АВТОМАТИЧЕСКИ СОГЛАСОВАННЫЙ MTU", mtu_rows, "blue")
    ui_rows("ЗАЩИТА ВНЕШНИХ ИНТЕРФЕЙСОВ", security_rows, "yellow")
    ui_rows("ГОТОВЫЕ ФАЙЛЫ", file_rows, "green")
    ui_panel(
        "КОМАНДЫ ENTRY СЕРВЕРА",
        [
            "Состояние:  awg-health · server-audit · dns-status",
            "Клиенты:    vpn-user list/create/delete · awg-old · awg-mobile",
            "Маршруты:   ru-domain · se-domain · entry-domain · ru-direct-ports",
            "Прокси/DNS: ru-proxy · ru-proxy-set · dot-switch · doh-switch",
            "Система:    maintenance · update-all · kalimera-deploy --resume --update-components · f2b-reset",
        ],
        "blue",
    )
    ui_panel(
        "КОМАНДЫ EXIT СЕРВЕРА",
        [
            "awg-health · server-audit · maintenance · update-all · обновление компонентов с управляющей машины · f2b-reset",
        ],
        "blue",
    )
    ui_panel(
        "СЛЕДУЮЩИЕ ШАГИ",
        [
            "1. Откройте новое SSH-соединение ко всем серверам из блока «ПОДКЛЮЧЕНИЯ».",
            "2. Безопасно перенесите первый файл клиента и импортируйте его в AmneziaWG.",
            "3. Проверьте handshake клиента и выполните awg-health --strict.",
            "Подсказки: kalimera-help · точный синтаксис: <команда> --help.",
        ],
        "green",
    )


def ansible(
    repo: Path,
    inventory: Path,
    vault_password: Path,
    playbook: str,
    extra_vars: dict[str, object] | None = None,
) -> None:
    argv = [
            require_command("ansible-playbook"),
            "-i",
            str(inventory),
            str(repo / playbook),
            "--vault-password-file",
            str(vault_password),
            "-e",
            "awg_adoption_mode=apply",
        ]
    for key, value in (extra_vars or {}).items():
        rendered = str(value).lower() if isinstance(value, bool) else str(value)
        argv.extend(["-e", f"{key}={rendered}"])
    run(argv)


def complete_ssh_transition(
    repo: Path,
    hosts_path: Path,
    vault_password: Path,
    hosts_document: dict,
    mtu_result: Path,
    awg_package_lock: Path,
) -> bool:
    children = hosts_document["all"]["children"]
    managed_hosts = tuple(
        (group, name)
        for group in ("entry", "exit", "front")
        for name in children.get(group, {}).get("hosts", {})
    )
    transitioning = []
    for group, name in managed_hosts:
        variables = children[group]["hosts"][name]
        if variables.get("security_allow_ssh_port_change", False):
            transitioning.append((group, name, variables))

    all_vars_path = hosts_path.parent / "group_vars" / "all" / "main.yml"
    all_vars = load_yaml(all_vars_path)
    admin_transition_pending = bool(
        all_vars.get("security_manage_admin_account", False)
        and not all_vars.get("security_finalize_admin_access", False)
    )

    if not transitioning and not admin_transition_pending:
        return False

    print("Продолжается переход SSH: временно работают старый и новый порты...")
    ansible(
        repo,
        hosts_path,
        vault_password,
        "playbooks/site.yml",
        {
            "awg_enable_fail2ban": False,
            "awg_health_run_during_deploy": False,
            "awg_telegram_monitor_start_immediately": False,
            "awg_prepare_apt": True,
            "awg_restore_apt": False,
            "awg_mtu_controller_result_path": str(mtu_result),
            "awg_package_controller_lock_path": str(awg_package_lock),
        },
    )

    transitioning_names = {name for _group, name, _variables in transitioning}
    admin_user = str(all_vars.get("security_admin_user", "kalimera"))
    for group, name in managed_hosts:
        variables = children[group]["hosts"][name]
        local_connection = variables.get("ansible_connection") == "local"
        if (admin_transition_pending or name in transitioning_names) and not local_connection:
            check_ssh(
                str(variables["ansible_host"]),
                admin_user,
                int(variables["ssh_listen_port"]),
                Path(str(variables["ansible_ssh_private_key_file"])),
            )
        elif (admin_transition_pending or name in transitioning_names) and local_connection:
            print(
                f"{name}: локальный Ansible-канал уже проверен; "
                "SSH root через loopback не используется."
            )
        if name in transitioning_names:
            current = int(variables["ansible_port"])
            variables["ansible_port"] = int(variables["ssh_listen_port"])
            variables["security_allow_ssh_port_change"] = False
            variables["security_previous_ssh_port"] = current
        if all_vars.get("security_manage_admin_account", False):
            variables["ansible_user"] = admin_user
            variables["ansible_become"] = True
            variables["ansible_become_method"] = "sudo"
            variables["ansible_become_password"] = (
                "{{ vault_" + group + "_kalimera_password }}"
            )

    require_operator_ssh_confirmation()
    all_vars["security_finalize_admin_access"] = True
    yaml_write(all_vars_path, all_vars)
    yaml_write(hosts_path, hosts_document)
    if all_vars.get("security_manage_admin_account", False):
        remove_bootstrap_become_passwords(hosts_path.parent, vault_password)
    return True


def main() -> None:
    configure_line_editing()
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument(
        "--resume", action="store_true", help="продолжить или повторить существующую установку"
    )
    parser.add_argument(
        "--summary", action="store_true", help="показать безопасную итоговую конфигурацию"
    )
    parser.add_argument(
        "--terminal-only",
        action="store_true",
        help="обновить только оформление терминала и справку без изменения каскада",
    )
    parser.add_argument(
        "--enable-mobile",
        action="store_true",
        help="при --resume безопасно добавить отсутствующий mobile AWG UDP/8443",
    )
    parser.add_argument(
        "--enable-front",
        action="store_true",
        help=(
            "при --resume добавить FRONT-релей (CDN-фронтированный VLESS+XHTTP) "
            "как отдельный хост - интерактивно запросит данные подключения"
        ),
    )
    parser.add_argument(
        "--replace-front",
        action="store_true",
        help="при --resume подготовить новый FRONT без отключения прежнего",
    )
    parser.add_argument(
        "--commit-front-replacement",
        action="store_true",
        help="подтвердить проверенный новый FRONT и удалить доступ прежнего",
    )
    parser.add_argument(
        "--rollback-front-replacement",
        action="store_true",
        help="восстановить inventory прежнего FRONT из защищённой копии",
    )
    parser.add_argument(
        "--update-components",
        action="store_true",
        help=(
            "при --resume транзакционно обновить пакеты AmneziaWG и применить "
            "проверенные версии sing-box/AWG3 из текущего выпуска KalimeraWG"
        ),
    )
    args = parser.parse_args()
    if args.enable_mobile and not args.resume:
        parser.error("--enable-mobile используется только вместе с --resume")
    if args.enable_front and not args.resume:
        parser.error("--enable-front используется только вместе с --resume")
    if (args.replace_front or args.commit_front_replacement or args.rollback_front_replacement) and not args.resume:
        parser.error("операции замены FRONT используются только вместе с --resume")
    if sum(
        bool(value)
        for value in (
            args.enable_front,
            args.replace_front,
            args.commit_front_replacement,
            args.rollback_front_replacement,
        )
    ) > 1:
        parser.error("выберите только одну операцию FRONT")
    if args.update_components and not args.resume:
        parser.error("--update-components используется только вместе с --resume")
    if args.update_components and any(
        (
            args.enable_front,
            args.replace_front,
            args.commit_front_replacement,
            args.rollback_front_replacement,
        )
    ):
        parser.error("--update-components нельзя объединять с операциями FRONT")
    if args.terminal_only and (
        args.resume
        or args.summary
        or args.enable_mobile
        or args.enable_front
        or args.replace_front
        or args.commit_front_replacement
        or args.rollback_front_replacement
        or args.update_components
    ):
        parser.error("--terminal-only нельзя объединять с другими режимами deploy")
    repo = args.repo_root.resolve()
    production = repo / "inventory" / "production"
    state_root = Path.home() / ".local" / "share" / "awg-iac" / "production"
    mtu_result = state_root / "mtu.yml"
    awg_package_lock = state_root / "amneziawg-package-lock.txt"
    vault_password = Path.home() / ".config" / "awg-iac" / "production-vault.pass"
    if args.summary:
        if not (production / "hosts.yml").is_file() or not (
            production / "group_vars" / "entry.yml"
        ).is_file():
            fail("Сформированный production inventory не найден")
        show_deployment_summary(production)
        return
    if args.terminal_only:
        hosts_path = production / "hosts.yml"
        vault_path = production / "group_vars" / "all" / "vault.yml"
        if not hosts_path.is_file() or not vault_path.is_file() or not vault_password.is_file():
            fail("Не найден production inventory или внешний пароль Ansible Vault")
        ansible(repo, hosts_path, vault_password, "playbooks/terminal.yml")
        print(
            "Терминальный интерфейс всех активных серверов обновлён без изменения SSH, "
            "AWG, UFW, DNS и маршрутизации."
        )
        return
    if args.resume:
        hosts_path = production / "hosts.yml"
        vault_path = production / "group_vars" / "all" / "vault.yml"
        all_vars_path = production / "group_vars" / "all" / "main.yml"
        if not hosts_path.is_file() or not vault_path.is_file() or not vault_password.is_file():
            fail("Не найден production inventory или внешний пароль Ansible Vault")
        if not all_vars_path.is_file():
            fail("Не найдены групповые переменные production inventory")
        migrate_production_inventory(production)
        ensure_mobile_awg3_vault_material(production, vault_password)
        if args.rollback_front_replacement:
            rollback_front_replacement(production)
        if args.enable_front:
            enable_front_profile(production, vault_password)
        if args.replace_front:
            prepare_front_replacement(production, vault_password)
        show_front_deploy_state(production)
        ensure_runtime_secret_material(production, vault_password)
        pending_account_passwords: dict[str, str] = {}
        ensure_admin_account_material(
            production,
            vault_password,
            repo,
            pending_passwords=pending_account_passwords,
            regenerate_undelivered=True,
        )
        if args.enable_mobile:
            enable_mobile_profile(production, vault_password)
        update_saved_client_configs_cps(state_root / "clients")
        all_vars = load_yaml(all_vars_path)
        if (
            all_vars.get("awg_package_version_mode") == "candidate"
            and awg_package_lock.is_file()
            and not args.update_components
        ):
            pin_resolved_awg_packages(all_vars_path, awg_package_lock)
            all_vars = load_yaml(all_vars_path)
        if not all_vars.get("security_admin_authorized_keys"):
            print("Перед отключением входа по паролю требуется административный публичный SSH-ключ.")
            all_vars["security_admin_authorized_keys"] = [prompt_admin_public_key()]
            yaml_write(all_vars_path, all_vars)
        if not all_vars.get("security_require_admin_authorized_key"):
            all_vars["security_require_admin_authorized_key"] = True
            yaml_write(all_vars_path, all_vars)
        hosts_document = load_yaml(hosts_path)
        recover_saved_admin_access(
            hosts_document,
            hosts_path,
            str(all_vars.get("security_admin_user", "kalimera")),
            bool(all_vars.get("security_finalize_admin_access", False)),
        )
        verify_saved_inventory_access(hosts_document)
        refresh_saved_automation_sources(hosts_document, hosts_path)
        if args.update_components:
            transitioning = [
                variables
                for group in ("entry", "exit", "front")
                if group in hosts_document["all"]["children"]
                for variables in hosts_document["all"]["children"][group]["hosts"].values()
                if variables.get("security_allow_ssh_port_change", False)
            ]
            if transitioning:
                fail(
                    "Сначала завершите обычный './deploy --resume' для перехода SSH, "
                    "затем отдельно запустите обновление компонентов"
                )
        cleanup_callback = lambda: cleanup_deployment(repo, hosts_path, vault_password)
        atexit.register(cleanup_callback)
        transition_completed = complete_ssh_transition(
            repo,
            hosts_path,
            vault_password,
            hosts_document,
            mtu_result,
            awg_package_lock,
        )
        if awg_package_lock.is_file() and not args.update_components:
            pin_resolved_awg_packages(all_vars_path, awg_package_lock)
        component_backup: dict[Path, bytes | None] = {}
        if args.update_components:
            entry_vars_path = production / "group_vars" / "entry.yml"
            exit_vars_path = production / "group_vars" / "exit.yml"
            for path in (all_vars_path, entry_vars_path, exit_vars_path, awg_package_lock):
                component_backup[path] = path.read_bytes() if path.is_file() else None
            prepare_component_update(repo, production)
        final_variables = {
            "awg_enable_fail2ban": True,
            "awg_health_run_during_deploy": False,
            "awg_telegram_monitor_start_immediately": False,
            "awg_mtu_controller_result_path": str(mtu_result),
            "awg_package_controller_lock_path": str(awg_package_lock),
        }
        if args.update_components:
            final_variables["awg_package_refresh"] = True
            final_variables["awg_package_transaction_id"] = secrets.token_hex(12)
        if transition_completed:
            final_variables.update({"awg_prepare_apt": False, "awg_restore_apt": True})
        try:
            try:
                ansible(
                    repo, hosts_path, vault_password, "playbooks/site.yml", final_variables
                )
            except SystemExit:
                # Финальный прогон site.yml включает и отключение root
                # (security_finalize_admin_access), и более поздние задачи,
                # которым снова нужен SSH (например, Shamir-play). Если один
                # из хостов успел перейти на kalimera именно в этом прогоне,
                # а inventory на диске ещё содержит устаревший root, задача
                # падает с "Permission denied (publickey)" даже при полностью
                # исправном состоянии серверов. Проверяем это по-настоящему
                # (реальное SSH-подключение внутри recover_saved_admin_access),
                # а не считаем совпадением - и повторяем прогон один раз, если
                # восстановление действительно что-то исправило.
                hosts_document = load_yaml(hosts_path)
                all_vars_current = load_yaml(all_vars_path)
                recovered = recover_saved_admin_access(
                    hosts_document,
                    hosts_path,
                    str(all_vars_current.get("security_admin_user", "kalimera")),
                    bool(all_vars_current.get("security_finalize_admin_access", False)),
                )
                if not recovered:
                    raise
                print(
                    "SSH-доступ подтверждён по kalimera после перехода: "
                    + ", ".join(recovered)
                    + ". Повторяю финальный прогон без вмешательства оператора."
                )
                ansible(
                    repo, hosts_path, vault_password, "playbooks/site.yml", final_variables
                )
            if awg_package_lock.is_file():
                pin_resolved_awg_packages(all_vars_path, awg_package_lock)
            ansible(repo, hosts_path, vault_password, "playbooks/verify.yml")
            ansible(repo, hosts_path, vault_password, "playbooks/finalize-monitoring.yml")
            ansible(repo, hosts_path, vault_password, "playbooks/verify.yml")
            if args.commit_front_replacement:
                commit_front_replacement(production)
                try:
                    ansible(
                        repo,
                        hosts_path,
                        vault_password,
                        "playbooks/entry.yml",
                        final_variables,
                    )
                    ansible(repo, hosts_path, vault_password, "playbooks/verify.yml")
                except SystemExit:
                    entry_vars = load_yaml(production / "group_vars" / "entry.yml")
                    front_vars = load_yaml(production / "group_vars" / "front.yml")
                    entry_vars["front_replacement_state"] = "prepared"
                    front_vars["front_replacement_state"] = "prepared"
                    yaml_write(production / "group_vars" / "entry.yml", entry_vars)
                    yaml_write(production / "group_vars" / "front.yml", front_vars)
                    try:
                        ansible(
                            repo,
                            hosts_path,
                            vault_password,
                            "playbooks/entry.yml",
                            final_variables,
                        )
                    except SystemExit:
                        pass
                    fail(
                        "Commit замены FRONT не прошёл проверку; прежний FRONT "
                        "повторно разрешён на ENTRY"
                    )
                finish_front_replacement(production)
        except SystemExit as update_error:
            if not args.update_components:
                raise
            print(
                "Обновление компонентов не прошло проверку. "
                "Выполняется автоматический откат ENTRY и EXIT..."
            )
            for path, content in component_backup.items():
                restore_file(path, content)
            rollback_variables = dict(final_variables)
            rollback_variables["awg_package_refresh"] = False
            rollback_variables["awg_package_rollback"] = True
            try:
                ansible(
                    repo,
                    hosts_path,
                    vault_password,
                    "playbooks/site.yml",
                    rollback_variables,
                )
                ansible(repo, hosts_path, vault_password, "playbooks/verify.yml")
            except SystemExit:
                fail(
                    "Обновление и автоматический откат завершились ошибкой. "
                    "Не перезагружайте серверы; используйте сохранённые пакеты в "
                    "/var/cache/awg-iac/component-rollback и повторите deploy с "
                    "закреплённым inventory"
                )
            for path, content in component_backup.items():
                restore_file(path, content)
            cleanup_deployment(repo, hosts_path, vault_password)
            atexit.unregister(cleanup_callback)
            fail(f"{update_error}\nПредыдущая рабочая версия компонентов восстановлена.")
        update_saved_client_configs_mtu(state_root / "clients", mtu_result)
        cleanup_deployment(repo, hosts_path, vault_password)
        atexit.unregister(cleanup_callback)
        if args.rollback_front_replacement:
            (_front_replacement_state_root() / "current.json").unlink(missing_ok=True)
            print("Откат FRONT применён и проверен; маркер восстановления удалён.")
        if args.update_components:
            print("Компоненты каскада обновлены транзакционно и успешно проверены.")
        elif args.replace_front:
            print(
                "Новый FRONT применён. Для каждого direct-пользователя повторно "
                "выполните 'vless-user export ИМЯ' на новом FRONT и импортируйте "
                "JSON с новым origin-доменом. Затем проверьте direct/CDN VLESS-сессию, "
                "переключите CDN origin и выполните "
                "'kalimera-deploy --resume --commit-front-replacement'."
            )
        else:
            print("Существующая конфигурация повторно применена и успешно проверена.")
        show_deployment_summary(production)
        if pending_account_passwords:
            show_generated_account_passwords(pending_account_passwords)
            mark_account_passwords_delivered(production)
            pending_account_passwords.clear()
        return
    if production.exists():
        fail(
            "inventory/production уже существует; используйте './deploy --resume' "
            "для продолжения существующей установки"
        )

    for command in (
        "ansible-playbook",
        "ansible-inventory",
        "ssh",
        "ssh-copy-id",
        "ssh-keygen",
        "sshpass",
        "openssl",
        "ssss-split",
        "ssss-combine",
    ):
        require_command(command)

    show_installer_banner()

    ui_section(
        1,
        "СЕРВЕРЫ",
        "Укажите, где находятся ENTRY и EXIT и как подключаться к ним сейчас.",
    )
    local_entry = prompt_bool("Установить ENTRY сервер на этой машине", False)
    entry_host = "127.0.0.1" if local_entry else prompt("IP-адрес или DNS-имя ENTRY сервера")
    exit_host = prompt("IP-адрес или DNS-имя EXIT сервера")
    if not entry_host or not exit_host:
        fail("Необходимо указать адреса ENTRY сервера и EXIT сервера")
    if not local_entry:
        require_public_endpoint(entry_host, "Адрес удалённого ENTRY сервера")
    require_public_endpoint(exit_host, "Адрес EXIT сервера")

    front_enabled = prompt_bool(
        "Добавить отдельный FRONT для VLESS-доступа", False
    )
    front_host = ""
    if front_enabled:
        front_host = prompt("IP-адрес или DNS-имя FRONT сервера")
        require_public_endpoint(front_host, "Адрес FRONT сервера")

    entry_user = prompt("Пользователь SSH ENTRY сервера", "root")
    exit_user = prompt("Пользователь SSH EXIT сервера", "root")
    front_user = prompt("Пользователь SSH FRONT сервера", "root") if front_enabled else ""
    if local_entry and entry_user != "root":
        fail("Локальная установка ENTRY сервера должна выполняться от root")
    entry_current_port = prompt_port(
        "Текущий SSH-порт ENTRY сервера", detect_local_ssh_port() if local_entry else 22
    )
    exit_current_port = prompt_port("Текущий SSH-порт EXIT сервера", 22)
    front_current_port = (
        prompt_port("Текущий SSH-порт FRONT сервера", 22) if front_enabled else 22
    )

    ui_section(
        2,
        "ПОРТЫ",
        "Новые SSH-порты проверяются до закрытия старых; AWG использует UDP.",
    )
    entry_new_port = prompt_port("Новый управляемый SSH-порт ENTRY сервера", 56777)
    exit_new_port = prompt_port("Новый управляемый SSH-порт EXIT сервера", 56777)
    front_new_port = (
        prompt_port("Новый управляемый SSH-порт FRONT сервера", 56777)
        if front_enabled
        else 56777
    )
    if min(entry_new_port, exit_new_port, front_new_port) < 1024:
        fail("Управляемые SSH-порты должны находиться в диапазоне 1024–65535")
    client_awg_port = prompt_port("UDP-порт AWG для VPN-клиентов ENTRY сервера", 443)
    transit_awg_port = prompt_port(
        "Публичный UDP-порт межсерверного AWG на EXIT сервере",
        443,
    )
    legacy_awg_port = prompt_port(
        "UDP-порт для старых клиентов KeeneticOS 4.3.x",
        39744,
    )
    mobile_awg_port = prompt_port(
        "UDP-порт мобильного AWG 3.1",
        8443,
    )
    if client_awg_port == legacy_awg_port:
        fail("Основной и совместимый клиентские UDP-порты AWG на ENTRY должны различаться")
    # На ENTRY клиентский kernel-интерфейс и userspace AWG3 не могут надёжно
    # делить один сокет. Публичным портом каскада остаётся UDP/443 на EXIT, а
    # локальный порт AWG3 на ENTRY выбирается отдельно и фильтруется по IP EXIT.
    entry_transit_listen_port = 39745
    while entry_transit_listen_port in {client_awg_port, legacy_awg_port}:
        entry_transit_listen_port += 1
    if entry_transit_listen_port > 65535:
        fail("Не удалось автоматически выбрать локальный UDP-порт AWG3 на ENTRY")
    if mobile_awg_port in {
        client_awg_port, legacy_awg_port, entry_transit_listen_port,
    }:
        fail("UDP-порт мобильного AWG должен отличаться от других портов AWG на ENTRY")

    ui_section(
        3,
        "БЕЗОПАСНЫЙ ДОСТУП",
        "Пароли нужны только для bootstrap; постоянный вход останется по вашему ключу.",
    )
    entry_password = ""
    if not local_entry:
        entry_password = getpass.getpass("Пароль SSH ENTRY сервера (ввод скрыт): ")
    exit_password = getpass.getpass("Пароль SSH EXIT сервера (ввод скрыт): ")
    front_password = (
        getpass.getpass("Пароль SSH FRONT сервера (ввод скрыт): ")
        if front_enabled
        else ""
    )
    if (
        (not local_entry and not entry_password)
        or not exit_password
        or (front_enabled and not front_password)
    ):
        fail("Начальные пароли SSH удалённых серверов не могут быть пустыми")

    print("Вставьте ПУБЛИЧНЫЙ ключ с вашего компьютера. Никогда не вставляйте закрытый ключ.")
    admin_public_key = prompt_admin_public_key()

    entry_sudo = entry_user != "root" and prompt_bool(
        "Для sudo на ENTRY сервере используется тот же пароль", True
    )
    exit_sudo = exit_user != "root" and prompt_bool(
        "Для sudo на EXIT сервере используется тот же пароль", True
    )
    front_sudo = front_enabled and front_user != "root" and prompt_bool(
        "Для sudo на FRONT сервере используется тот же пароль", True
    )

    ui_section(
        4,
        "МАРШРУТИЗАЦИЯ RU-ТРАФИКА",
        "Прямой маршрут работает без прокси; SOAX и SOCKS5 получают TUN и fail-open.",
    )
    ui_panel(
        "ВЫБОР МАРШРУТА",
        [
            "1 · напрямую через ENTRY сервер",
            "2 · через SOAX SOCKS5",
            "3 · через другой SOCKS5-прокси",
        ],
        "cyan",
    )
    proxy_choice = prompt("Выберите режим", "1")
    if proxy_choice not in {"1", "2", "3"}:
        fail("Выбран неподдерживаемый режим RU-трафика")
    proxy_enabled = proxy_choice != "1"
    proxy_host = ""
    proxy_port = 0
    proxy_username = ""
    proxy_password = ""
    expected_proxy_ip = ""
    if proxy_enabled:
        proxy_host = prompt(
            "Адрес SOCKS5-прокси", "proxy.soax.com" if proxy_choice == "2" else None
        )
        proxy_port = prompt_port("Порт SOCKS5-прокси", 1337 if proxy_choice == "2" else 1080)
        proxy_username = getpass.getpass("Имя пользователя SOCKS5, если требуется (ввод скрыт): ")
        proxy_password = getpass.getpass("Пароль SOCKS5, если требуется (ввод скрыт): ")
        if bool(proxy_username) != bool(proxy_password):
            fail("Имя пользователя и пароль SOCKS5 должны быть указаны вместе либо оба оставлены пустыми")
        expected_proxy_ip = prompt("Ожидаемый внешний IPv4 прокси; пусто - определить автоматически", "")

    reality_fallback_enabled = front_enabled
    reality_fallback_dest = "yandex.ru"
    # yandex.ru первым - RU-правдоподобный, собственная инфраструктура
    # Yandex (не CDN), стабильно проходит preflight-проверку сертификата на
    # живом каскаде. www.microsoft.com исключён - отдаётся через Akamai
    # (сторонний CDN), что на практике повышало долю сорванных
    # REALITY-хендшейков. www.debian.org сюда намеренно не включён -
    # резолвится в несколько IP (DNS round-robin) и не проходит
    # preflight-проверку стабильности сертификата.
    reality_candidates = [
        "yandex.ru", "vk.ru", "vk.com", "kinopoisk.ru",
        "market.yandex.ru", "maps.yandex.ru", "music.yandex.ru",
        "dzen.ru", "tinkoff.ru",
    ]
    front_origin_domain = ""
    front_certbot_email = ""
    front_access_modes: list[str] = []
    front_cdn_state = "not_configured"
    front_direct_domain = ""
    front_cdn_domain = ""
    if front_enabled:
        ui_panel(
            "FRONT И СЛУЖЕБНЫЙ REALITY BACKEND",
            [
                "VLESS доступен только через отдельный FRONT.",
                "Прямого пользовательского VLESS-inbound на ENTRY не будет.",
                "RU-прокси и backend FRONT работают разными службами.",
            ],
            "cyan",
        )
        front_origin_domain = prompt(
            "Origin-домен FRONT (A-запись указывает на FRONT)"
        )
        if not _DOMAIN_RE.match(front_origin_domain or ""):
            fail("Origin-домен FRONT должен быть корректным DNS-именем")
        front_certbot_email = prompt("E-mail для Let's Encrypt/Certbot")
        if not _EMAIL_RE.match(front_certbot_email or ""):
            fail("Некорректный e-mail для Certbot")
        ui_panel(
            "РЕЖИМ ДОСТУПА FRONT",
            [
                "1 · прямой TLS+XHTTP через FRONT без CDN",
                "2 · TLS+XHTTP только через готовый CDN",
                "3 · прямой доступ и готовый CDN одновременно",
            ],
            "cyan",
        )
        front_choice = prompt("Выберите режим FRONT", "1")
        front_mode_map = {
            "1": ["direct"],
            "2": ["cdn"],
            "3": ["direct", "cdn"],
        }
        if front_choice not in front_mode_map:
            fail("Выбран неподдерживаемый режим FRONT")
        front_access_modes = front_mode_map[front_choice]
        if "direct" in front_access_modes:
            front_direct_domain = front_origin_domain
            print(f"Домен прямого доступа FRONT: {front_origin_domain}")
        if "cdn" in front_access_modes:
            if not prompt_bool("CDN-ресурс уже создан и готов", False):
                fail(
                    "Для чистой установки выберите direct, если CDN ещё не готов. "
                    "CDN можно подключить отдельным обновлением inventory."
                )
            front_cdn_domain = prompt("Публичный домен готового CDN-ресурса")
            if not _DOMAIN_RE.match(front_cdn_domain or ""):
                fail("Публичный домен CDN должен быть корректным")
            front_cdn_state = "ready"

        print("Проверка кандидатов маскировочного dest-сайта (TLS 1.3, три пробы)...")
        results = {host: probe_reality_dest(host) for host in reality_candidates}
        ui_panel(
            "КАНДИДАТЫ DEST-САЙТА REALITY",
            [
                f"{index} · {host} [{'OK' if results[host] else 'FAIL'}]"
                for index, host in enumerate(reality_candidates, start=1)
            ] + ["0 · указать свой домен"],
            "cyan",
        )
        dest_choice = prompt("Номер кандидата или 0 для своего домена", "1")
        if dest_choice == "0":
            reality_fallback_dest = prompt("Домен маскировочного сайта")
        elif dest_choice.isdigit() and 1 <= int(dest_choice) <= len(reality_candidates):
            reality_fallback_dest = reality_candidates[int(dest_choice) - 1]
        else:
            fail("Выбран неподдерживаемый вариант dest-сайта REALITY")
        if not results.get(reality_fallback_dest, probe_reality_dest(reality_fallback_dest)):
            fail(
                f"dest-сайт {reality_fallback_dest} не прошёл проверку TLS 1.3 - "
                "выберите другой"
            )
        print(f"dest-сайт {reality_fallback_dest} проверен.")

    ui_section(
        5,
        "DNS И МОНИТОРИНГ",
        "По умолчанию: Mullvad DoT и Yandex DoH для RU-доменов через прокси.",
    )
    telegram_enabled = prompt_bool("Включить мониторинг через Telegram", False)
    telegram_token = ""
    telegram_chat = ""
    if telegram_enabled:
        ui_panel(
            "ЛИЧНЫЙ TELEGRAM-БОТ",
            [
                "1 · у меня уже есть токен собственного бота",
                "2 · нужно создать нового бота через официальный @BotFather",
                "KalimeraWG не предоставляет общего бота и не получает ваши данные.",
            ],
            "cyan",
        )
        telegram_setup = prompt("Выберите вариант", "1")
        if telegram_setup not in {"1", "2"}:
            fail("Выберите 1 для готового бота или 2 для создания нового")
        if telegram_setup == "2":
            ui_panel(
                "СОЗДАНИЕ БОТА ЧЕРЕЗ @BOTFATHER",
                [
                    "1. Откройте в Telegram официальный @BotFather с отметкой проверки.",
                    "2. Отправьте команду /newbot.",
                    "3. Укажите отображаемое имя бота.",
                    "4. Укажите уникальное имя пользователя, оканчивающееся на bot.",
                    "5. Скопируйте выданный токен целиком вместе с двоеточием.",
                ],
                "magenta",
            )
            input("Нажмите Enter после получения токена от @BotFather: ")
        telegram_token = getpass.getpass(
            "Полный токен Telegram-бота с двоеточием (ввод скрыт): "
        ).strip()
        if not re.fullmatch(r"[0-9]{6,20}:[A-Za-z0-9_-]{20,}", telegram_token):
            fail(
                "Некорректный токен Telegram: введите всю строку BotFather "
                "целиком вместе с двоеточием"
            )
        bot = telegram_api_result(telegram_token, "getMe")
        if not isinstance(bot, dict) or not bot.get("username"):
            fail("Telegram не подтвердил токен бота. Проверьте токен и доступ в Интернет")
        print(f"Telegram-бот подтверждён: @{bot['username']}")

        telegram_chat = prompt(
            "Числовой Telegram chat ID; Enter - определить автоматически"
        )
        if not telegram_chat:
            ui_panel(
                "ОПРЕДЕЛЕНИЕ TELEGRAM CHAT ID",
                [
                    f"Откройте @{bot['username']} в Telegram.",
                    "Нажмите Start и отправьте боту любое сообщение.",
                    "После отправки вернитесь сюда и нажмите Enter.",
                ],
                "cyan",
            )
            input("Нажмите Enter после отправки сообщения боту: ")
            discovered = telegram_latest_chat_from_updates(
                telegram_api_result(telegram_token, "getUpdates?timeout=10")
            )
            if discovered is None:
                fail(
                    "Chat ID не найден. Отправьте сообщение непосредственно боту "
                    "или введите ранее сохранённый числовой Chat ID"
                )
            telegram_chat, chat_label = discovered
            print(f"Telegram chat найден: {chat_label} (ID {telegram_chat})")
        if not telegram_credentials_valid(telegram_token, telegram_chat):
            fail("Telegram chat ID должен быть отдельным положительным или отрицательным числом")

    dot_upstreams = [
        {"address": "194.242.2.2", "tls_name": "dns.mullvad.net"},
    ]
    if not prompt_bool("Использовать Mullvad DNS-over-TLS по умолчанию", True):
        dot_addresses = [item.strip() for item in prompt("IPv4-адреса DoT через запятую").split(",") if item.strip()]
        dot_tls_name = prompt("TLS-имя сервера DoT")
        if not dot_addresses or not dot_tls_name:
            fail("Для собственного DoT нужны адреса серверов и TLS-имя")
        try:
            for address in dot_addresses:
                ipaddress.IPv4Address(address)
        except ValueError:
            fail("Каждый адрес собственного DoT должен быть IPv4-адресом")
        dot_upstreams = [{"address": address, "tls_name": dot_tls_name} for address in dot_addresses]

    doh_server = "77.88.8.8"
    doh_tls_name = "common.dot.dns.yandex.net"
    doh_path = "/dns-query"
    if not prompt_bool("Использовать Yandex DNS-over-HTTPS для RU-доменов", True):
        doh_server = prompt("IPv4-адрес DoH-сервера")
        doh_tls_name = prompt("TLS-имя DoH-сервера")
        doh_path = prompt("HTTP-путь DoH", "/dns-query")
        try:
            ipaddress.IPv4Address(doh_server)
        except ValueError:
            fail("Собственный DoH-сервер должен иметь IPv4-адрес")
        if not doh_tls_name or not doh_path.startswith("/"):
            fail("Для собственного DoH нужны TLS-имя и абсолютный HTTP-путь")

    exit_endpoint = prompt("Публичный адрес AWG EXIT сервера", exit_host)
    require_public_endpoint(exit_endpoint, "AWG endpoint EXIT сервера")
    exit_public_ipv4 = resolve_single_public_ipv4(exit_endpoint, "AWG endpoint EXIT сервера")
    entry_public_default = (
        detect_local_public_ipv4(exit_host) if local_entry else entry_host
    )
    if local_entry and entry_public_default:
        print(
            "Автоматически определён внешний IPv4 интерфейса ENTRY: "
            f"{entry_public_default}"
        )
    entry_public_endpoint = prompt(
        "Публичный адрес AWG ENTRY сервера", entry_public_default
    )
    require_public_endpoint(entry_public_endpoint, "AWG endpoint ENTRY сервера")
    entry_public_ipv4 = resolve_single_public_ipv4(
        entry_public_endpoint, "AWG endpoint ENTRY сервера"
    )
    front_public_ipv4 = (
        resolve_single_public_ipv4(front_host, "Адрес FRONT сервера")
        if front_enabled
        else ""
    )
    ui_section(
        6,
        "ПЕРВЫЙ VPN-КЛИЕНТ",
        "Конфигурация будет создана автоматически и сохранена с правами 0600.",
    )
    client_name = prompt("Имя первого VPN-пользователя", "vpn-user")
    if not client_name or not all(character.isalnum() or character in "-_" for character in client_name):
        fail("Имя VPN-пользователя может содержать только буквы, цифры, дефис и подчёркивание")
    ui_panel(
        "ПРОФИЛЬ МАСКИРОВКИ",
        [
            "1 · максимальная производительность",
            "2 · сбалансированный",
            "3 · максимальная маскировка",
            "4 · mobile/AWG3+: полный профиль AWG 3.1 и отдельный UDP/8443",
            "5 · KeeneticOS 4.3.x: базовый ASC и отдельный интерфейс",
        ],
        "magenta",
    )
    profile_choice = prompt("Выберите профиль", "2")
    profile_names = {
        "1": "performance", "2": "balanced", "3": "masking",
        "4": "mobile", "5": "old",
    }
    if profile_choice not in profile_names:
        fail("Выбран неподдерживаемый профиль маскировки")
    client_profile_name = profile_names[profile_choice]
    client_subnet_text = prompt("Подсеть AWG-клиентов", "10.66.0.0/24")
    legacy_client_subnet_text = prompt(
        "Подсеть старых AWG-клиентов KeeneticOS 4.3.x", "10.67.0.0/24"
    )
    mobile_client_subnet_text = prompt(
        "Подсеть клиентов mobile/AWG3+", "10.68.0.0/24"
    )
    transit_subnet_text = prompt("Подсеть AWG между ENTRY сервером и EXIT сервером", "10.77.0.0/24")
    try:
        client_subnet = ipaddress.ip_network(client_subnet_text, strict=True)
        legacy_client_subnet = ipaddress.ip_network(legacy_client_subnet_text, strict=True)
        mobile_client_subnet = ipaddress.ip_network(mobile_client_subnet_text, strict=True)
        transit_subnet = ipaddress.ip_network(transit_subnet_text, strict=True)
        networks = (
            client_subnet, legacy_client_subnet, mobile_client_subnet,
            transit_subnet,
        )
        if any(
            networks[left].overlaps(networks[right])
            for left in range(len(networks))
            for right in range(left + 1, len(networks))
        ):
            fail("Подсети основных, старых, мобильных клиентов и ENTRY–EXIT не должны пересекаться")
        client_hosts = client_subnet.hosts()
        entry_client_ip = next(client_hosts)
        modern_initial_client_ip = next(client_hosts)
        legacy_hosts = legacy_client_subnet.hosts()
        entry_legacy_client_ip = next(legacy_hosts)
        legacy_initial_client_ip = next(legacy_hosts)
        mobile_hosts = mobile_client_subnet.hosts()
        entry_mobile_client_ip = next(mobile_hosts)
        mobile_initial_client_ip = next(mobile_hosts)
        transit_hosts = transit_subnet.hosts()
        exit_transit_ip = next(transit_hosts)
        entry_transit_ip = next(transit_hosts)
    except (ValueError, StopIteration):
        fail("Подсети AWG должны быть корректными IPv4-сетями минимум с двумя доступными адресами")

    config_root = Path.home() / ".config" / "awg-iac"
    ssh_private = Path.home() / ".ssh" / "awg-iac-production"
    ssh_public = Path(str(ssh_private) + ".pub")
    vault_password = config_root / "production-vault.pass"
    client_config = state_root / "clients" / f"{client_name}.conf"

    if client_config.exists():
        fail("Отказ от перезаписи существующих защищённых данных VPN-клиента")
    staging = repo / "work" / f"production-{secrets.token_hex(8)}"
    config_staging = state_root / f".{client_name}-{secrets.token_hex(8)}.conf.tmp"

    def cleanup_staging() -> None:
        if staging.exists():
            shutil.rmtree(staging)
        if not production.exists():
            config_staging.unlink(missing_ok=True)

    atexit.register(cleanup_staging)

    if not ssh_private.exists():
        ssh_private.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        run(
            [
                require_command("ssh-keygen"),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(ssh_private),
                "-C",
                "awg-iac-production",
            ]
        )
    ssh_private.chmod(0o600)

    if not vault_password.exists():
        secure_write(vault_password, (secrets.token_urlsafe(48) + "\n").encode())
    if stat.S_IMODE(vault_password.stat().st_mode) & 0o077:
        fail("Права файла пароля Vault недостаточно строгие")

    print("Установка автоматически созданного публичного SSH-ключа...")
    if local_entry:
        print("ENTRY сервер: локальная установка ключа без парольного SSH-подключения...")
        install_local_key(entry_user, ssh_public)
    else:
        entry_password = bootstrap_key(
            entry_host,
            entry_user,
            entry_current_port,
            entry_password,
            ssh_public,
            "ENTRY сервер",
        )
    exit_password = bootstrap_key(
        exit_host,
        exit_user,
        exit_current_port,
        exit_password,
        ssh_public,
        "EXIT сервер",
    )
    if front_enabled:
        front_password = bootstrap_key(
            front_host,
            front_user,
            front_current_port,
            front_password,
            ssh_public,
            "FRONT сервер",
        )

    # Не полагаться на адрес локального интерфейса: при SNAT, floating IP или
    # сложной сети хостинга удалённый sshd может видеть другой source IPv4.
    exit_observed_source_ipv4 = remote_observed_ssh_source_ipv4(
        exit_host,
        exit_user,
        exit_current_port,
        ssh_private,
    )
    if not exit_observed_source_ipv4:
        fail(
            "EXIT сервер не подтвердил исходный IPv4 управляющего SSH-сеанса. "
            "Ограничение служебного ключа не применяется, чтобы не потерять доступ."
        )
    exit_automation_source_ipv4 = exit_observed_source_ipv4
    front_automation_source_ipv4 = ""
    if front_enabled:
        front_automation_source_ipv4 = remote_observed_ssh_source_ipv4(
            front_host,
            front_user,
            front_current_port,
            ssh_private,
        )
        if not front_automation_source_ipv4:
            fail(
                "FRONT сервер не подтвердил исходный IPv4 управляющего SSH-сеанса. "
                "Конфигурация не изменялась."
            )
    if local_entry:
        entry_automation_source_ipv4 = entry_public_ipv4
    else:
        entry_observed_source_ipv4 = remote_observed_ssh_source_ipv4(
            entry_host,
            entry_user,
            entry_current_port,
            ssh_private,
        )
        if not entry_observed_source_ipv4:
            fail(
                "ENTRY сервер не подтвердил исходный IPv4 управляющего SSH-сеанса. "
                "Ограничение служебного ключа не применяется, чтобы не потерять доступ."
            )
        entry_automation_source_ipv4 = entry_observed_source_ipv4
    observed_sources = {entry_automation_source_ipv4, exit_automation_source_ipv4}
    if front_automation_source_ipv4:
        observed_sources.add(front_automation_source_ipv4)
    print(
        "Фактический IPv4 управляющего SSH подтверждён серверами: "
        + ", ".join(sorted(observed_sources))
    )

    staging.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(repo / "inventory" / "example", staging)
    all_vars_path = staging / "group_vars" / "all" / "main.yml"
    entry_vars_path = staging / "group_vars" / "entry.yml"
    exit_vars_path = staging / "group_vars" / "exit.yml"
    front_vars_path = staging / "group_vars" / "front.yml"
    all_vars = load_yaml(all_vars_path)
    entry_vars = load_yaml(entry_vars_path)
    exit_vars = load_yaml(exit_vars_path)
    front_vars: dict[str, object] = {}
    client_mode = (
        "legacy" if client_profile_name == "old"
        else "mobile" if client_profile_name == "mobile"
        else "modern"
    )
    client_server_obfuscation = awg_server_obfuscation()
    legacy_server_obfuscation = awg_legacy_server_obfuscation()
    mobile_server_obfuscation = awg_mobile_awg3_obfuscation()
    initial_server_obfuscation = (
        legacy_server_obfuscation if client_mode == "legacy"
        else mobile_server_obfuscation if client_mode == "mobile"
        else client_server_obfuscation
    )
    initial_client_ip = (
        legacy_initial_client_ip if client_mode == "legacy"
        else mobile_initial_client_ip if client_mode == "mobile"
        else modern_initial_client_ip
    )
    transit_obfuscation = awg3_transit_obfuscation()
    initial_client_obfuscation = awg_client_obfuscation(
        client_profile_name, initial_server_obfuscation
    )

    account_passwords = {
        "ENTRY · kalimera": generate_account_password(),
        "ENTRY · root": generate_account_password(),
        "EXIT · kalimera": generate_account_password(),
        "EXIT · root": generate_account_password(),
    }
    if front_enabled:
        account_passwords.update(
            {
                "FRONT · kalimera": generate_account_password(),
                "FRONT · root": generate_account_password(),
            }
        )
    account_password_hashes = {
        label: hash_account_password(password)
        for label, password in account_passwords.items()
    }

    for key in ("ansible_user", "ansible_port", "ssh_listen_port"):
        all_vars.pop(key, None)
    all_vars.update(
        {
            "awg_adoption_mode": "apply",
            "awg_package_version_mode": "candidate",
            "security_manage_ssh": True,
            "security_manage_admin_account": True,
            "security_admin_user": "kalimera",
            "security_finalize_admin_access": False,
            "security_controller_repo_path": str(repo),
            "security_admin_authorized_keys": [admin_public_key],
            "security_require_admin_authorized_key": True,
            "security_account_passwords_delivered": False,
            "awg_interserver_entry_address": f"{entry_transit_ip}/32",
            "awg_telegram_monitor_enabled": telegram_enabled,
            "runtime_secrets_enabled": True,
            "runtime_secrets_threshold": 2,
            "runtime_secrets_total_shares": 5,
            "runtime_secrets_cluster_id": secrets.token_hex(16),
            "runtime_secrets_unlock_timeout_seconds": 180,
        }
    )
    entry_vars.update(
        {
            "entry_wan_interface": "auto",
            "entry_client_address": f"{entry_client_ip}/{client_subnet.prefixlen}",
            "entry_client_listen_address": str(entry_client_ip),
            "entry_client_subnet": str(client_subnet),
            "entry_exit_tunnel_address": f"{entry_transit_ip}/32",
            "entry_exit_endpoint": f"{exit_endpoint}:{transit_awg_port}",
            "entry_exit_interface": "awg3",
            "entry_public_endpoint": entry_public_endpoint,
            "entry_awg0_listen_port": client_awg_port,
            "security_interserver_peer_ipv4": exit_public_ipv4,
            "security_interserver_listen_port": entry_transit_listen_port,
            "entry_awg0_mtu": 1380,
            "entry_awg_client_mtu": 1380,
            "entry_awg0_obfuscation": client_server_obfuscation,
            "entry_manage_awg_configs": True,
            "entry_awg1_obfuscation": transit_obfuscation,
            "entry_awg_client_default_profile": client_profile_name,
            "entry_awg_client_mode": "modern",
            "entry_legacy_client_available": True,
            "entry_legacy_client_enabled": client_mode == "legacy",
            "entry_legacy_client_interface": "awg-old",
            "entry_legacy_client_address": f"{entry_legacy_client_ip}/{legacy_client_subnet.prefixlen}",
            "entry_legacy_client_listen_address": str(entry_legacy_client_ip),
            "entry_legacy_client_subnet": str(legacy_client_subnet),
            "entry_legacy_client_listen_port": legacy_awg_port,
            "entry_legacy_awg_obfuscation": legacy_server_obfuscation,
            "entry_mobile_client_available": True,
            "entry_mobile_client_enabled": client_mode == "mobile",
            "entry_mobile_client_interface": "awg-mobile",
            "entry_mobile_client_address": f"{entry_mobile_client_ip}/{mobile_client_subnet.prefixlen}",
            "entry_mobile_client_listen_address": str(entry_mobile_client_ip),
            "entry_mobile_client_subnet": str(mobile_client_subnet),
            "entry_mobile_client_listen_port": mobile_awg_port,
            "entry_mobile_legacy_public_port": 53,
            "entry_mobile_legacy_internal_port": 39746,
            "entry_mobile_client_mtu": 1380,
            "entry_mobile_awg_obfuscation": mobile_server_obfuscation,
            "entry_mobile_service_name": "awg3-mobile.service",
            "entry_mobile_profile_generation": "awg3.1",
            "awg3_mobile_content_padding_addition": AWG3_MOBILE_FEATURE_DEFAULTS["content_padding_addition"],
            "awg3_mobile_rekey_after_time": AWG3_MOBILE_FEATURE_DEFAULTS["rekey_after_time"],
            "awg3_mobile_rekey_timeout": AWG3_MOBILE_FEATURE_DEFAULTS["rekey_timeout"],
            "awg3_mobile_reject_after_time": AWG3_MOBILE_FEATURE_DEFAULTS["reject_after_time"],
            "awg3_mobile_keepalive_timeout": AWG3_MOBILE_FEATURE_DEFAULTS["keepalive_timeout"],
            "awg3_mobile_max_handshake_attempts": AWG3_MOBILE_FEATURE_DEFAULTS["max_handshake_attempts"],
            "awg3_mobile_persistent_keepalive": AWG3_MOBILE_FEATURE_DEFAULTS["persistent_keepalive"],
            "awg3_mobile_random_trailers": AWG3_MOBILE_FEATURE_DEFAULTS["random_trailers"],
            "awg3_mobile_disable_cookies": AWG3_MOBILE_FEATURE_DEFAULTS["disable_cookies"],
            "awg3_transit_enabled": True,
            "awg3_transit_interface": "awg3",
            "awg3_transit_listen_port": entry_transit_listen_port,
            "awg3_transit_address": f"{entry_transit_ip}/32",
            "awg3_peer_endpoint_host": exit_endpoint,
            "awg3_peer_endpoint_port": transit_awg_port,
            "awg3_peer_tunnel_address": str(exit_transit_ip),
            "awg3_transit_private_key": "{{ vault_awg_entry_exit_private_key }}",
            "awg3_transit_peer_public_key": "{{ vault_awg_entry_exit_peer_public_key }}",
            "awg3_transit_allowed_ips": ["0.0.0.0/0"],
            "awg3_transit_obfuscation": transit_obfuscation,
            "entry_ru_proxy_enabled": proxy_enabled,
            "entry_proxy_server": proxy_host or "127.0.0.1",
            "entry_proxy_port": proxy_port or 1080,
            "entry_ru_proxy_expected_ip": expected_proxy_ip,
            "reality_fallback_enabled": reality_fallback_enabled,
            "reality_fallback_dest": reality_fallback_dest,
            "front_enabled": front_enabled,
            "front_relay_enabled": front_enabled,
            "front_backend_enabled": front_enabled,
            "reality_fallback_direct_client_enabled": False,
            "front_public_ipv4": front_public_ipv4,
            "entry_dot_upstreams": dot_upstreams,
            "entry_dns_doh_server": doh_server,
            "entry_dns_doh_tls_name": doh_tls_name,
            "entry_dns_doh_path": doh_path,
            "runtime_secrets_share_index": 1,
            "runtime_secrets_peer_inventory_hosts": (
                "{{ ((groups['exit'] | default([])) + "
                "(groups['front'] | default([]))) | list }}"
            ),
            "runtime_secrets_advertise_ipv4": entry_public_ipv4,
        }
    )
    if local_entry:
        entry_vars["runtime_secrets_controller_vault_password_path"] = str(
            vault_password
        )
        entry_vars["runtime_secrets_controller_ssh_private_key_path"] = str(
            ssh_private
        )
        entry_vars["runtime_secrets_controller_client_state_path"] = str(
            state_root / "clients"
        )
    exit_vars.update(
        {
            "exit_wan_interface": "auto",
            "exit_awg_interface": "awg3",
            "exit_awg_listen_port": transit_awg_port,
            "security_interserver_peer_ipv4": entry_public_ipv4,
            "security_interserver_listen_port": transit_awg_port,
            "exit_awg_address": f"{exit_transit_ip}/{transit_subnet.prefixlen}",
            "exit_awg_subnet": str(transit_subnet),
            "exit_awg_obfuscation": transit_obfuscation,
            "exit_manage_awg_config": False,
            "exit_peer_migration_policy": "explicit",
            "awg3_transit_enabled": True,
            "awg3_transit_interface": "awg3",
            "awg3_transit_listen_port": transit_awg_port,
            "awg3_transit_address": f"{exit_transit_ip}/{transit_subnet.prefixlen}",
            "awg3_peer_endpoint_host": entry_public_endpoint,
            "awg3_peer_endpoint_port": entry_transit_listen_port,
            "awg3_peer_tunnel_address": str(entry_transit_ip),
            "awg3_transit_private_key": "{{ vault_awg_exit_private_key }}",
            "awg3_transit_peer_public_key": "{{ vault_awg_entry_exit_entry_public_key }}",
            "awg3_transit_allowed_ips": [f"{entry_transit_ip}/32"],
            "awg3_transit_obfuscation": transit_obfuscation,
            "runtime_secrets_share_index": 2,
            "runtime_secrets_peer_inventory_hosts": (
                "{{ (groups['entry'] | default([])) + "
                "(groups['exit'] | default([]) | reject('equalto', inventory_hostname) | list) + "
                "(groups['front'] | default([])) }}"
            ),
            "runtime_secrets_advertise_ipv4": exit_public_ipv4,
        }
    )
    yaml_write(all_vars_path, all_vars)
    yaml_write(entry_vars_path, entry_vars)
    yaml_write(exit_vars_path, exit_vars)
    if front_enabled:
        front_vars.update(
            {
                "awg_node_role": "front",
                "front_enabled": True,
                "front_relay_enabled": True,
                "front_active_id": "front-1",
                "front_replacement_state": "active",
                "front_access_modes": front_access_modes,
                "front_cdn_state": front_cdn_state,
                "front_origin_domain": front_origin_domain,
                "front_direct_domain": front_direct_domain,
                "front_cdn_domain": front_cdn_domain,
                "front_client_domain": (
                    front_cdn_domain
                    if front_access_modes == ["cdn"]
                    else front_direct_domain
                ),
                "front_certbot_email": front_certbot_email,
                "front_xhttp_path": "/" + secrets.token_urlsafe(9),
                "front_subscription_enabled": False,
                "front_vless_encryption_enabled": True,
                "front_xhttp_disguise_enabled": True,
                "awg3_transit_enabled": False,
                "runtime_secrets_share_index": 3,
                "runtime_secrets_peer_inventory_hosts": (
                    "{{ (groups['entry'] | default([])) + "
                    "(groups['exit'] | default([])) }}"
                ),
                "runtime_secrets_advertise_ipv4": front_public_ipv4,
            }
        )
        yaml_write(front_vars_path, front_vars)

    host_vars = {
        "entry-managed": {
            "ansible_host": entry_host,
            "ansible_user": entry_user,
            "ansible_port": entry_current_port,
            "ansible_become": True,
            "ansible_ssh_private_key_file": str(ssh_private),
            "ssh_listen_port": entry_new_port,
            "security_allow_ssh_port_change": entry_current_port != entry_new_port,
            "security_automation_source_ipv4": entry_automation_source_ipv4,
            "security_admin_password_hash": "{{ vault_entry_kalimera_password_hash }}",
            "security_root_password_hash": "{{ vault_entry_root_password_hash }}",
            "runtime_secrets_share_index": 1,
        },
        "exit-managed": {
            "ansible_host": exit_host,
            "ansible_user": exit_user,
            "ansible_port": exit_current_port,
            "ansible_become": True,
            "ansible_ssh_private_key_file": str(ssh_private),
            "ssh_listen_port": exit_new_port,
            "security_allow_ssh_port_change": exit_current_port != exit_new_port,
            "security_automation_source_ipv4": exit_automation_source_ipv4,
            "security_admin_password_hash": "{{ vault_exit_kalimera_password_hash }}",
            "security_root_password_hash": "{{ vault_exit_root_password_hash }}",
            "runtime_secrets_share_index": 2,
        },
    }
    if front_enabled:
        host_vars["front-managed"] = {
            "ansible_host": front_host,
            "ansible_user": front_user,
            "ansible_port": front_current_port,
            "ansible_become": True,
            "ansible_ssh_private_key_file": str(ssh_private),
            "ssh_listen_port": front_new_port,
            "security_allow_ssh_port_change": front_current_port != front_new_port,
            "security_automation_source_ipv4": front_automation_source_ipv4,
            "security_admin_password_hash": "{{ vault_front_kalimera_password_hash }}",
            "security_root_password_hash": "{{ vault_front_root_password_hash }}",
            "runtime_secrets_share_index": 3,
        }
    if local_entry:
        host_vars["entry-managed"]["ansible_connection"] = "local"
        host_vars["entry-managed"]["ansible_python_interpreter"] = "/usr/bin/python3"
    if entry_sudo:
        host_vars["entry-managed"]["ansible_become_password"] = "{{ vault_entry_become_password }}"
    if exit_sudo:
        host_vars["exit-managed"]["ansible_become_password"] = "{{ vault_exit_become_password }}"
    if front_sudo:
        host_vars["front-managed"]["ansible_become_password"] = "{{ vault_front_become_password }}"

    hosts_document = {
        "all": {
            "children": {
                "entry": {"hosts": {"entry-managed": host_vars["entry-managed"]}},
                "exit": {"hosts": {"exit-managed": host_vars["exit-managed"]}},
            }
        }
    }
    if front_enabled:
        hosts_document["all"]["children"]["front"] = {
            "hosts": {"front-managed": host_vars["front-managed"]}
        }
    hosts_path = staging / "hosts.yml"
    yaml_write(hosts_path, hosts_document)

    entry_private = awg_private_key()
    legacy_entry_private = awg_private_key()
    mobile_entry_private = awg_private_key()
    mobile_header_protection_key = awg_private_key()
    transit_private = awg_private_key()
    exit_private = awg_private_key()
    transit_psk = awg_psk()
    client_private = awg_private_key()
    client_psk = awg_psk()
    runtime_secret_key = secrets.token_hex(32)
    runtime_secret_shares = split_runtime_secret(
        runtime_secret_key, threshold=2, total=5
    )
    entry_exchange_private, entry_exchange_public = ssh_exchange_keypair()
    exit_exchange_private, exit_exchange_public = ssh_exchange_keypair()
    if front_enabled:
        front_exchange_private, front_exchange_public = ssh_exchange_keypair()
    vault_document: dict[str, object] = {
        "vault_entry_kalimera_password": account_passwords["ENTRY · kalimera"],
        "vault_entry_kalimera_password_hash": account_password_hashes["ENTRY · kalimera"],
        "vault_entry_root_password_hash": account_password_hashes["ENTRY · root"],
        "vault_exit_kalimera_password": account_passwords["EXIT · kalimera"],
        "vault_exit_kalimera_password_hash": account_password_hashes["EXIT · kalimera"],
        "vault_exit_root_password_hash": account_password_hashes["EXIT · root"],
        "vault_awg_entry_private_key": entry_private,
        "vault_awg_entry_legacy_private_key": legacy_entry_private,
        "vault_awg_entry_mobile_private_key": mobile_entry_private,
        "vault_awg_entry_mobile_header_protection_key": mobile_header_protection_key,
        "vault_awg_entry_exit_private_key": transit_private,
        "vault_awg_entry_exit_peer_public_key": awg_public_key(exit_private),
        "vault_awg_exit_private_key": exit_private,
        "vault_awg_entry_exit_psk": transit_psk,
        "vault_awg3_header_protection_key": awg_private_key(),
        "vault_awg_entry_exit_entry_public_key": awg_public_key(transit_private),
        "vault_proxy_username": proxy_username,
        "vault_proxy_password": proxy_password,
        "vault_entry_client_peers": ([] if client_mode in {"legacy", "mobile"} else [
            {
                "name": client_name,
                "public_key": awg_public_key(client_private),
                "allowed_ips": [f"{initial_client_ip}/32"],
                "preshared_key": client_psk,
            }
        ]),
        "vault_entry_legacy_client_peers": ([
            {
                "name": client_name,
                "public_key": awg_public_key(client_private),
                "allowed_ips": [f"{initial_client_ip}/32"],
                "preshared_key": client_psk,
            }
        ] if client_mode == "legacy" else []),
        "vault_entry_mobile_client_peers": ([
            {
                "name": client_name,
                "public_key": awg_public_key(client_private),
                "allowed_ips": [f"{initial_client_ip}/32"],
                "preshared_key": client_psk,
            }
        ] if client_mode == "mobile" else []),
        "vault_exit_peers": [
            {
                "name": "entry",
                "public_key": awg_public_key(transit_private),
                "allowed_ips": [f"{entry_transit_ip}/32"],
                "preshared_key": transit_psk,
            }
        ],
        "vault_runtime_secret_key_sha256": hashlib.sha256(
            bytes.fromhex(runtime_secret_key)
        ).hexdigest(),
        "vault_runtime_secret_shares": runtime_secret_shares,
        "vault_runtime_exchange_private_keys": {
            "entry-managed": entry_exchange_private,
            "exit-managed": exit_exchange_private,
        },
        "vault_runtime_exchange_public_keys": {
            "entry-managed": entry_exchange_public,
            "exit-managed": exit_exchange_public,
        },
    }
    if front_enabled:
        vault_document.update(
            {
                "vault_front_kalimera_password": account_passwords["FRONT · kalimera"],
                "vault_front_kalimera_password_hash": account_password_hashes["FRONT · kalimera"],
                "vault_front_root_password_hash": account_password_hashes["FRONT · root"],
            }
        )
        vault_document["vault_runtime_exchange_private_keys"][
            "front-managed"
        ] = front_exchange_private
        vault_document["vault_runtime_exchange_public_keys"][
            "front-managed"
        ] = front_exchange_public
    if entry_sudo:
        vault_document["vault_entry_become_password"] = entry_password
    if exit_sudo:
        vault_document["vault_exit_become_password"] = exit_password
    if front_sudo:
        vault_document["vault_front_become_password"] = front_password
    if telegram_enabled:
        vault_document["vault_telegram_bot_token"] = telegram_token
        vault_document["vault_telegram_chat_id"] = telegram_chat

    vault_secret = vault_password.read_bytes().rstrip(b"\r\n")
    plaintext = yaml.safe_dump(vault_document, sort_keys=False).encode()
    encrypted = VaultLib([("default", VaultSecret(vault_secret))]).encrypt(plaintext)
    secure_write(staging / "group_vars" / "all" / "vault.yml", encrypted)
    del account_password_hashes
    obfuscation = initial_client_obfuscation
    client_server_private = (
        legacy_entry_private if client_mode == "legacy" else entry_private
    )
    if client_mode == "mobile":
        client_server_private = mobile_entry_private
    client_dns_address = (
        entry_legacy_client_ip if client_mode == "legacy" else entry_client_ip
    )
    if client_mode == "mobile":
        client_dns_address = entry_mobile_client_ip
    client_address_prefix = (
        legacy_client_subnet.prefixlen
        if client_mode == "legacy"
        else mobile_client_subnet.prefixlen
        if client_mode == "mobile"
        else client_subnet.prefixlen
    )
    client_endpoint_port = (
        legacy_awg_port if client_mode == "legacy"
        else mobile_awg_port if client_mode == "mobile"
        else client_awg_port
    )
    modern_padding = ""
    modern_signatures = ""
    if client_mode in {"modern", "mobile"}:
        modern_padding = f"S3 = {obfuscation['s3']}\nS4 = {obfuscation['s4']}\n"
    if client_mode == "modern":
        modern_signatures = (
            f"I1 = {obfuscation['i1']}\nI2 = {obfuscation['i2']}\n"
            f"I3 = {obfuscation['i3']}\nI4 = {obfuscation['i4']}\n"
            f"I5 = {obfuscation['i5']}\n"
        )
    elif client_mode == "mobile":
        modern_signatures = (
            f"I1 = {obfuscation['i1']}\nI2 = {obfuscation['i2']}\n"
            f"I3 = {obfuscation['i3']}\nI4 = {obfuscation['i4']}\n"
            f"I5 = {obfuscation['i5']}\n"
        )
    mobile_awg3_fields = ""
    persistent_keepalive = "25"
    if client_mode == "mobile":
        mobile_awg3_fields = (
            f"HeaderProtectionKey = {mobile_header_protection_key}\n"
            f"ContentPaddingAddition = {AWG3_MOBILE_FEATURE_DEFAULTS['content_padding_addition']}\n"
            f"RekeyAfterTime = {AWG3_MOBILE_FEATURE_DEFAULTS['rekey_after_time']}\n"
            f"RekeyTimeout = {AWG3_MOBILE_FEATURE_DEFAULTS['rekey_timeout']}\n"
            f"RejectAfterTime = {AWG3_MOBILE_FEATURE_DEFAULTS['reject_after_time']}\n"
            f"KeepaliveTimeout = {AWG3_MOBILE_FEATURE_DEFAULTS['keepalive_timeout']}\n"
            f"MaxHandshakeAttempts = {AWG3_MOBILE_FEATURE_DEFAULTS['max_handshake_attempts']}\n"
            "RandomTrailers = "
            f"{'on' if AWG3_MOBILE_FEATURE_DEFAULTS['random_trailers'] else 'off'}\n"
            "DisableCookies = "
            f"{'on' if AWG3_MOBILE_FEATURE_DEFAULTS['disable_cookies'] else 'off'}\n"
        )
        persistent_keepalive = str(
            AWG3_MOBILE_FEATURE_DEFAULTS["persistent_keepalive"]
        )
    client_config_text = (
        "[Interface]\n"
        f"PrivateKey = {client_private}\n"
        f"Address = {initial_client_ip}/{client_address_prefix}\n"
        f"DNS = {client_dns_address}\n"
        f"MTU = {1280 if client_mode == 'legacy' else 1380}\n"
        f"Jc = {obfuscation['jc']}\nJmin = {obfuscation['jmin']}\nJmax = {obfuscation['jmax']}\n"
        f"S1 = {obfuscation['s1']}\nS2 = {obfuscation['s2']}\n"
        f"{modern_padding}"
        f"H1 = {obfuscation['h1']}\nH2 = {obfuscation['h2']}\nH3 = {obfuscation['h3']}\nH4 = {obfuscation['h4']}\n"
        f"{modern_signatures}"
        f"{mobile_awg3_fields}\n"
        "[Peer]\n"
        f"PublicKey = {awg_public_key(client_server_private)}\n"
        f"PresharedKey = {client_psk}\n"
        f"Endpoint = {entry_public_endpoint}:{client_endpoint_port}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"PersistentKeepalive = {persistent_keepalive}\n"
    )
    secure_write(config_staging, client_config_text.encode())

    production.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging, production)
    client_config.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.replace(config_staging, client_config)
    hosts_path = production / "hosts.yml"
    atexit.unregister(cleanup_staging)
    cleanup_callback = lambda: cleanup_deployment(repo, hosts_path, vault_password)
    atexit.register(cleanup_callback)

    show_front_deploy_state(production)

    ui_step(
        "ПРЕДВАРИТЕЛЬНЫЙ АУДИТ",
        "Проверяем Ubuntu, сеть и доступ без изменения конфигурации серверов.",
    )
    run(
        [
            require_command("ansible-playbook"),
            "-i",
            str(hosts_path),
            str(repo / "playbooks" / "audit.yml"),
            "--vault-password-file",
            str(vault_password),
        ]
    )
    ui_step(
        "ЭТАП 1 · БЕЗОПАСНЫЙ ПЕРЕХОД SSH",
        "Старый и новый SSH-порты временно работают одновременно; Fail2Ban остановлен.",
    )
    ansible(
        repo,
        hosts_path,
        vault_password,
        "playbooks/site.yml",
        {
            "awg_enable_fail2ban": False,
            "awg_health_run_during_deploy": False,
            "awg_telegram_monitor_start_immediately": False,
            "awg_prepare_apt": True,
            "awg_restore_apt": False,
            "awg_mtu_controller_result_path": str(mtu_result),
            "awg_package_controller_lock_path": str(awg_package_lock),
        },
    )
    pin_resolved_awg_packages(
        production / "group_vars" / "all" / "main.yml", awg_package_lock
    )

    if not local_entry:
        check_ssh(entry_host, "kalimera", entry_new_port, ssh_private)
    else:
        print(
            "ENTRY сервер: локальный Ansible-канал проверен; "
            "SSH root через 127.0.0.1 не используется."
        )
    check_ssh(exit_host, "kalimera", exit_new_port, ssh_private)
    if front_enabled:
        check_ssh(front_host, "kalimera", front_new_port, ssh_private)
    require_operator_ssh_confirmation()

    all_vars = load_yaml(production / "group_vars" / "all" / "main.yml")
    all_vars["security_finalize_admin_access"] = True
    yaml_write(production / "group_vars" / "all" / "main.yml", all_vars)

    transition_hosts = [
        ("entry-managed", "entry", entry_current_port, entry_new_port),
        ("exit-managed", "exit", exit_current_port, exit_new_port),
    ]
    if front_enabled:
        transition_hosts.append(
            ("front-managed", "front", front_current_port, front_new_port)
        )
    for name, group, current, desired in transition_hosts:
        host_vars[name]["ansible_user"] = "kalimera"
        host_vars[name]["ansible_become"] = True
        host_vars[name]["ansible_become_method"] = "sudo"
        host_vars[name]["ansible_become_password"] = (
            "{{ vault_" + group + "_kalimera_password }}"
        )
        host_vars[name]["ansible_port"] = desired
        host_vars[name]["security_allow_ssh_port_change"] = False
        host_vars[name]["security_previous_ssh_port"] = current
    hosts_document["all"]["children"]["entry"]["hosts"]["entry-managed"] = host_vars["entry-managed"]
    hosts_document["all"]["children"]["exit"]["hosts"]["exit-managed"] = host_vars["exit-managed"]
    if front_enabled:
        hosts_document["all"]["children"]["front"]["hosts"]["front-managed"] = host_vars["front-managed"]
    yaml_write(hosts_path, hosts_document)
    remove_bootstrap_become_passwords(production, vault_password)

    ui_step(
        "ЭТАП 2 · ФИНАЛЬНАЯ ПОЛИТИКА",
        "Закрываем старые порты, включаем Fail2Ban и запускаем строгую проверку.",
    )
    ansible(
        repo,
        hosts_path,
        vault_password,
        "playbooks/site.yml",
        {
            "awg_enable_fail2ban": True,
            "awg_health_run_during_deploy": False,
            "awg_telegram_monitor_start_immediately": False,
            "awg_prepare_apt": False,
            "awg_restore_apt": True,
            "awg_mtu_controller_result_path": str(mtu_result),
            "awg_package_controller_lock_path": str(awg_package_lock),
        },
    )
    ansible(repo, hosts_path, vault_password, "playbooks/verify.yml")
    ansible(repo, hosts_path, vault_password, "playbooks/finalize-monitoring.yml")
    ansible(repo, hosts_path, vault_password, "playbooks/verify.yml")
    update_client_config_mtu(client_config, mtu_result, client_mode)
    cleanup_deployment(repo, hosts_path, vault_password)
    atexit.unregister(cleanup_callback)

    ui_success("Все активные серверы настроены, проверены и готовы к работе.")
    show_deployment_summary(production)
    show_generated_account_passwords(account_passwords)
    mark_account_passwords_delivered(production)
    account_passwords.clear()


if __name__ == "__main__":
    main()

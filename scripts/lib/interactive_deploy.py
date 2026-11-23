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
import tempfile
import textwrap
import time
import urllib.request
import zoneinfo
from pathlib import Path
from typing import NamedTuple

import yaml
from ansible.parsing.vault import VaultLib, VaultSecret
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Соседний модуль: программа запускается как файл, а тесты загружают её по пути,
# поэтому каталог добавляется в путь поиска явно.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import controller_backup  # noqa: E402


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
    # Отдельной сборки mobile AWG 3.1 больше нет - интерфейс поднимает
    # kernel-модуль, поэтому и закреплять для него нечего. Оставшиеся в
    # inventory ключи прежней сборки безвредны и просто перестают читаться.
    mobile_build_keys = (
        "awg3_mobile_go_version",
        "awg3_mobile_go_archives",
        "awg3_mobile_go_source_version",
        "awg3_mobile_go_source_commit",
        "awg3_mobile_tools_source_version",
        "awg3_mobile_tools_source_commit",
    )
    if all_path.is_file() and any(key in all_vars for key in mobile_build_keys):
        for key in mobile_build_keys:
            all_vars.pop(key, None)
        all_changed = True
        print(
            "Production inventory обновлён: mobile/AWG3+ переведён на kernel-модуль, "
            "закрепление отдельной сборки убрано."
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
            or not awg_mobile_awg3_profile_is_complete(
                entry_vars.get("entry_mobile_awg_obfuscation")
            )
        )
    ):
        entry_vars.update(
            {
                "entry_mobile_profile_generation": "awg3.1",
                "entry_mobile_awg_obfuscation": awg_mobile_awg3_obfuscation(),
            }
        )
        changed = True
        print(
            "Production inventory обновлён: профиль mobile заменён на mobile/AWG3+. "
            "Ранее выданные mobile-конфиги нужно выпустить заново."
        )

    # Переход mobile/AWG3+ с отдельного userspace-движка на kernel-модуль.
    # Отдельно от блока выше: имя службы меняется без смены профиля, поэтому
    # переиздавать клиентские конфиги не требуется.
    if (
        entry_vars.get("entry_mobile_client_available", False)
        and entry_vars.get("entry_mobile_service_name") != MOBILE_SERVICE_NAME
    ):
        entry_vars["entry_mobile_service_name"] = MOBILE_SERVICE_NAME
        changed = True
        print(
            "Production inventory обновлён: mobile/AWG3+ переведён на kernel-модуль "
            "AmneziaWG; ранее выданные конфиги остаются действительными."
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
        "entry_mobile_service_name": MOBILE_SERVICE_NAME,
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


def update_production_vault(
    production: Path,
    vault_password: Path,
    updates: dict[str, object] | None = None,
    remove: tuple[str, ...] = (),
) -> bool:
    """Записать или удалить значения в production Vault.

    Возвращает True, если содержимое изменилось. Файл заменяется атомарно, значения
    на экран не выводятся.
    """
    vault_path = production / "group_vars" / "all" / "vault.yml"
    if not vault_path.is_file() or not vault_password.is_file():
        fail("Не найден production Vault или внешний пароль Ansible Vault")
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
    changed = False
    for key, value in (updates or {}).items():
        if document.get(key) != value or key not in document:
            document[key] = value
            changed = True
    for key in remove:
        if key in document:
            del document[key]
            changed = True
    if not changed:
        return False
    encrypted = vault_lib.encrypt(yaml.safe_dump(document, sort_keys=False).encode())
    temporary = vault_path.with_name(f".{vault_path.name}.{secrets.token_hex(8)}.tmp")
    try:
        secure_write(temporary, encrypted)
        os.replace(temporary, vault_path)
        vault_path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return True


PROXY_SCOPES = ("all", "selected")
_PROXY_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def prompt_proxy_scope(default: str = "all") -> str:
    """Спросить, что направлять через RU-прокси: всё российское или только списки."""
    ui_panel(
        "ЧТО НАПРАВЛЯТЬ ЧЕРЕЗ ПРОКСИ",
        [
            "1 · только выбранные домены и адреса (списки proxy-domain и proxy-address)",
            "2 · весь российский трафик",
            "Списки proxy-domain и proxy-address идут через прокси в обоих вариантах.",
        ],
        "cyan",
    )
    choice = prompt("Выберите вариант", "1" if default == "selected" else "2")
    if choice not in {"1", "2"}:
        fail("Выберите 1 для выбранных адресов или 2 для всего российского трафика")
    return "selected" if choice == "1" else "all"


def probe_socks5_proxy(host: str, port: int, username: str, password: str) -> str | None:
    """Вернуть внешний IPv4 прокси или None, если запрос через него не прошёл.

    Учётные данные передаются curl через stdin, а не аргументами командной строки:
    аргументы видны другим пользователям системы.
    """
    curl = shutil.which("curl")
    if curl is None:
        return None
    lines = [
        "silent",
        "ipv4",
        "max-time = 15",
        f'proxy = "socks5h://{host}:{port}"',
        'url = "https://api.ipify.org"',
    ]
    if username:
        escaped = f"{username}:{password}".replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'proxy-user = "{escaped}"')
    try:
        result = subprocess.run(
            [curl, "--config", "-"],
            input="\n".join(lines) + "\n",
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    answer = result.stdout.strip()
    try:
        return str(ipaddress.IPv4Address(answer))
    except ValueError:
        return None


def enable_ru_proxy(production: Path, vault_password: Path) -> bool:
    """Включить RU-прокси на установленном каскаде или заменить его параметры.

    Меняются только inventory и Vault. Клиентские конфиги и ключи AWG не
    затрагиваются; серверы настраивает последующий обычный deploy.
    """
    entry_path = production / "group_vars" / "entry.yml"
    if not entry_path.is_file():
        fail("Для включения RU-прокси нужен production inventory")
    entry_vars = load_yaml(entry_path)
    already_enabled = bool(entry_vars.get("entry_ru_proxy_enabled", False))
    ui_section(
        1,
        "RU-ПРОКСИ",
        "SOCKS5 с российским адресом. Клиентские конфиги не меняются.",
    )
    if already_enabled:
        print("RU-прокси уже включён: введённые значения заменят текущие.")
    current_host = str(entry_vars.get("entry_proxy_server") or "")
    host = prompt(
        "Адрес SOCKS5-прокси",
        current_host if current_host not in {"", "127.0.0.1"} else None,
    ).strip()
    if not _PROXY_HOST_RE.fullmatch(host):
        fail("Адрес SOCKS5-прокси должен быть доменным именем или IPv4-адресом")
    current_port = entry_vars.get("entry_proxy_port")
    port = prompt_port(
        "Порт SOCKS5-прокси", current_port if isinstance(current_port, int) else 1080
    )
    username = getpass.getpass("Имя пользователя SOCKS5, если требуется (ввод скрыт): ")
    password = getpass.getpass("Пароль SOCKS5, если требуется (ввод скрыт): ")
    if bool(username) != bool(password):
        fail("Имя пользователя и пароль SOCKS5 должны быть указаны вместе либо оба оставлены пустыми")

    external_ip = probe_socks5_proxy(host, port, username, password)
    if external_ip is None:
        print("Проверочный запрос через прокси не прошёл: адрес, порт или учётные данные неверны либо прокси недоступен с этого сервера.")
        if not prompt_bool("Сохранить параметры без проверки", False):
            fail("RU-прокси не включён: параметры не сохранены")
    else:
        print(f"Прокси отвечает, внешний адрес: {external_ip}")

    expected_ip = prompt(
        "Ожидаемый внешний IPv4 прокси; пусто - не проверять (нужно для прокси со сменой адреса)",
        "",
    ).strip()
    if expected_ip:
        try:
            expected_ip = str(ipaddress.IPv4Address(expected_ip))
        except ValueError:
            fail("Ожидаемый внешний адрес должен быть IPv4-адресом")
    current_scope = str(entry_vars.get("entry_ru_proxy_scope", "selected"))
    scope = prompt_proxy_scope(
        current_scope if already_enabled and current_scope in PROXY_SCOPES else "selected"
    )

    updates: dict[str, object] = {
        "entry_ru_proxy_enabled": True,
        "entry_proxy_server": host,
        "entry_proxy_port": port,
        "entry_ru_proxy_expected_ip": expected_ip,
        "entry_ru_proxy_scope": scope,
    }
    entry_changed = any(entry_vars.get(key) != value for key, value in updates.items())
    vault_changed = update_production_vault(
        production,
        vault_password,
        {"vault_proxy_username": username, "vault_proxy_password": password},
    )
    if entry_changed:
        entry_vars.update(updates)
        yaml_write(entry_path, entry_vars)
    if scope == "selected":
        print(
            "Production inventory обновлён: RU-прокси включён для выбранных адресов. "
            "После deploy добавьте их на ENTRY: proxy-domain add ДОМЕН, proxy-address add АДРЕС."
        )
    else:
        print("Production inventory обновлён: RU-прокси включён для всего российского трафика.")
    return entry_changed or vault_changed


def disable_ru_proxy(production: Path) -> bool:
    """Выключить RU-прокси: российский трафик снова выходит напрямую с ENTRY."""
    entry_path = production / "group_vars" / "entry.yml"
    if not entry_path.is_file():
        fail("Для выключения RU-прокси нужен production inventory")
    entry_vars = load_yaml(entry_path)
    if not entry_vars.get("entry_ru_proxy_enabled", False):
        print("RU-прокси уже выключен.")
        return False
    entry_vars["entry_ru_proxy_enabled"] = False
    yaml_write(entry_path, entry_vars)
    print(
        "Production inventory обновлён: RU-прокси выключен. Списки proxy-domain и "
        "proxy-address сохраняются на ENTRY и снова начнут действовать после включения."
    )
    return True


def prompt_telegram_credentials() -> tuple[str, str]:
    """Запросить и проверить токен собственного бота и chat ID."""
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
    return telegram_token, telegram_chat


def enable_telegram_monitor(production: Path, vault_password: Path) -> bool:
    """Включить Telegram-уведомления на установленном каскаде или заменить бота."""
    all_vars_path = production / "group_vars" / "all" / "main.yml"
    if not all_vars_path.is_file():
        fail("Для включения Telegram нужен production inventory")
    all_vars = load_yaml(all_vars_path)
    ui_section(
        1,
        "TELEGRAM-УВЕДОМЛЕНИЯ",
        "Собственный бот сообщает о сбоях и восстановлении серверов каскада.",
    )
    if all_vars.get("awg_telegram_monitor_enabled", False):
        print("Telegram-уведомления уже включены: введённые значения заменят текущие.")
    token, chat = prompt_telegram_credentials()
    vault_changed = update_production_vault(
        production,
        vault_password,
        {"vault_telegram_bot_token": token, "vault_telegram_chat_id": chat},
    )
    vars_changed = not bool(all_vars.get("awg_telegram_monitor_enabled", False))
    if vars_changed:
        all_vars["awg_telegram_monitor_enabled"] = True
        yaml_write(all_vars_path, all_vars)
    print(
        "Production inventory обновлён: Telegram-уведомления включены. "
        "После deploy проверьте отправку командой telegram-test."
    )
    return vars_changed or vault_changed


def disable_telegram_monitor(production: Path, vault_password: Path) -> bool:
    """Выключить Telegram-уведомления и удалить токен бота из Vault."""
    all_vars_path = production / "group_vars" / "all" / "main.yml"
    if not all_vars_path.is_file():
        fail("Для выключения Telegram нужен production inventory")
    all_vars = load_yaml(all_vars_path)
    vars_changed = bool(all_vars.get("awg_telegram_monitor_enabled", False))
    if vars_changed:
        all_vars["awg_telegram_monitor_enabled"] = False
        yaml_write(all_vars_path, all_vars)
    vault_changed = update_production_vault(
        production,
        vault_password,
        remove=("vault_telegram_bot_token", "vault_telegram_chat_id"),
    )
    if vars_changed or vault_changed:
        print("Production inventory обновлён: Telegram-уведомления выключены, токен бота удалён из Vault.")
    else:
        print("Telegram-уведомления уже выключены.")
    return vars_changed or vault_changed


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
        # Свой набор имён маскировки XHTTP вместо общих значений роли.
        **new_front_disguise(),
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


STANDBY_EXIT_HOST = "exit-standby-managed"
STANDBY_EXIT_INTERFACE = "awg4"


def standby_transit_network(used: list[object]) -> ipaddress.IPv4Network:
    """Свободная служебная подсеть туннеля ENTRY - резервный EXIT."""
    occupied: list[ipaddress.IPv4Network] = []
    for value in used:
        if not value:
            continue
        try:
            occupied.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            continue
    for third_octet in range(78, 100):
        candidate = ipaddress.ip_network(f"10.{third_octet}.0.0/24")
        if not any(candidate.overlaps(network) for network in occupied):
            return candidate
    fail("Не найдена свободная подсеть 10.78.0.0/24-10.99.0.0/24 для туннеля резервного EXIT")


def standby_transit_profile(primary: object) -> dict[str, object]:
    """Профиль обфускации туннеля до резервного EXIT.

    Профиль свой, но S4 совпадает с основным туннелем: S4 добавляется к каждому
    пакету данных и входит в расчёт MTU, а MTU каскада один на оба пути.
    """
    profile = awg3_transit_obfuscation()
    if isinstance(primary, dict) and primary.get("s4") is not None:
        profile["s4"] = int(primary["s4"])
    validate_awg_obfuscation(profile)
    return profile


def standby_exit_configured(hosts_document: dict) -> bool:
    exit_hosts = (
        hosts_document.get("all", {}).get("children", {}).get("exit", {}).get("hosts", {})
    )
    return isinstance(exit_hosts, dict) and STANDBY_EXIT_HOST in exit_hosts


def repair_standby_exit_inventory(production: Path) -> bool:
    """Дополнить хост резервного EXIT значениями, которые выводятся из настроек ENTRY.

    Установщик записывает хост один раз и при повторном запуске его не трогает.
    Значение, добавленное в установщик позже, без этого шага не попало бы в уже
    созданный inventory, и deploy останавливался бы на проверке роли exit.
    """
    hosts_path = production / "hosts.yml"
    entry_path = production / "group_vars" / "entry.yml"
    if not hosts_path.is_file() or not entry_path.is_file():
        return False
    hosts_document = load_yaml(hosts_path)
    if not standby_exit_configured(hosts_document):
        return False
    standby = hosts_document["all"]["children"]["exit"]["hosts"][STANDBY_EXIT_HOST]
    if not isinstance(standby, dict):
        return False
    entry_tunnel_address = load_yaml(entry_path).get("entry_standby_exit_tunnel_address")
    expected: dict[str, object] = {}
    if entry_tunnel_address:
        expected["awg_interserver_entry_address"] = str(entry_tunnel_address)
    changed = False
    for key, value in expected.items():
        if standby.get(key) != value:
            standby[key] = value
            changed = True
    if changed:
        yaml_write(hosts_path, hosts_document)
        print("Production inventory дополнен: недостающие значения резервного EXIT.")
    return changed


STANDBY_ROUTE_PROBES = 100
# Доля подключений с потерей, начиная с которой маршрут считается плохим.
STANDBY_ROUTE_LOSS_PERCENT = 2
# Первый пакет TCP-соединения ядро повторяет через секунду: подключение, занявшее
# столько, прошло со второй попытки - пакет или ответ на него потерялся.
ROUTE_RETRANSMIT_SECONDS = 0.9


def probe_tcp_route(
    host: str,
    port: int,
    count: int = STANDBY_ROUTE_PROBES,
    pause: float = 0.1,
    timeout: float = 5.0,
) -> dict[str, int | None]:
    """Серия TCP-подключений к серверу: сколько из них прошло с первой попытки.

    Данные не передаются, соединение сразу закрывается. Потери пакетов на маршруте
    видны как подключения, занявшие секунду и больше либо оставшиеся без ответа.
    """
    clean: list[float] = []
    slow = failed = done = 0
    for index in range(count):
        started = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except OSError:
            failed += 1
        else:
            elapsed = time.monotonic() - started
            if elapsed >= ROUTE_RETRANSMIT_SECONDS:
                slow += 1
            else:
                clean.append(elapsed)
        done = index + 1
        # Порт закрыт или адрес неверен: ждать всю серию незачем.
        if failed == done and done >= 5:
            break
        if done < count:
            time.sleep(pause)
    clean.sort()
    return {
        "count": done,
        "clean": len(clean),
        "slow": slow,
        "failed": failed,
        "rtt_ms": int(clean[len(clean) // 2] * 1000) if clean else None,
    }


def confirm_standby_route(host: str, port: int) -> None:
    """Проверить маршрут от ENTRY до нового сервера, пока ничего не изменено.

    Найдено на рабочем каскаде: сервер был исправен и доступен, а маршрут между
    хостингами терял 3-5% пакетов - скорость через готовый туннель оказалась в
    сорок раз ниже, чем через основной EXIT.
    """
    print(
        f"Проверка маршрута до {host}: {STANDBY_ROUTE_PROBES} TCP-подключений к порту "
        f"{port}, около 20 секунд..."
    )
    result = probe_tcp_route(host, port)
    count = int(result["count"] or 0)
    lost = int(result["slow"] or 0) + int(result["failed"] or 0)
    if int(result["failed"] or 0) == count:
        fail(
            f"Сервер {host} не отвечает на TCP-порту {port}: проверьте адрес, SSH-порт и "
            "сетевые правила хостера"
        )
    if lost * 100 < STANDBY_ROUTE_LOSS_PERCENT * count:
        verdict = (
            "все с первой попытки"
            if lost == 0
            else f"со второй попытки или без ответа {lost} (в пределах нормы)"
        )
        print(
            f"Маршрут до нового сервера: подключений {count}, {verdict}, "
            f"задержка {result['rtt_ms']} мс."
        )
        return
    ui_panel(
        "МАРШРУТ ДО НОВОГО СЕРВЕРА ТЕРЯЕТ ПАКЕТЫ",
        [
            f"Из {count} подключений к {host}:{port} с первой попытки прошли "
            f"{result['clean']}, со второй - {result['slow']}, без ответа - {result['failed']}.",
            "При таких потерях скорость через резервный EXIT будет в десятки раз ниже",
            "обычной. Причина в маршруте между хостингами: настройками каскада она не",
            "устраняется. Надёжнее взять сервер у другого хостера или повторить",
            "проверку в другое время суток.",
        ],
        "yellow",
    )
    if not prompt_bool("Всё равно подключить этот сервер", False):
        print("Резервный EXIT не подключён: inventory и сервер не изменены.")
        raise SystemExit(0)


def enable_standby_exit(production: Path, vault_password: Path) -> bool:
    """Добавить резервный EXIT к production inventory (docs/standby-exit.md).

    Новый сервер входит в группу exit вторым хостом. ENTRY получает второй туннель
    и переключатель путей; основной EXIT, клиентские ключи и конфиги не меняются.
    """
    hosts_path = production / "hosts.yml"
    all_path = production / "group_vars" / "all" / "main.yml"
    entry_path = production / "group_vars" / "entry.yml"
    exit_path = production / "group_vars" / "exit.yml"
    if not all(path.is_file() for path in (hosts_path, all_path, entry_path, exit_path)):
        fail("Для подключения резервного EXIT нужен установленный production inventory")
    if not vault_password.is_file():
        fail("Для подключения резервного EXIT нужен пароль Ansible Vault")

    hosts_document = load_yaml(hosts_path)
    children = hosts_document.setdefault("all", {}).setdefault("children", {})
    exit_hosts = children.get("exit", {}).get("hosts", {})
    if standby_exit_configured(hosts_document):
        print("Резервный EXIT уже подключён к production inventory; повторное включение не требуется.")
        return False
    if not isinstance(exit_hosts, dict) or list(exit_hosts) != ["exit-managed"]:
        fail("Резервный EXIT подключается к каскаду с одним основным EXIT (exit-managed)")

    entry_vars = load_yaml(entry_path)
    exit_vars = load_yaml(exit_path)
    if entry_vars.get("awg3_transit_enabled", False) or exit_vars.get("awg3_transit_enabled", False):
        fail(
            "Резервный EXIT работает только с kernel-модулем AmneziaWG. Межсерверный канал "
            "этого каскада на userspace-движке: переключите его scripts/toggle-transit-engine.py."
        )
    if not entry_vars.get("entry_manage_awg_configs", False):
        fail("Резервный EXIT требует, чтобы конфигурации AWG на ENTRY вёл установщик")

    ui_panel(
        "РЕЗЕРВНЫЙ EXIT: ВТОРОЙ ЗАРУБЕЖНЫЙ СЕРВЕР",
        [
            "ENTRY держит туннель до обоих серверов и сам переводит зарубежный",
            "трафик на резервный, когда основной перестаёт отвечать. Клиентские",
            "конфиги не меняются. Сервер должен быть у другого хостера и в другой",
            "сети, чем основной EXIT, с чистой Ubuntu 24.04.",
        ],
        "cyan",
    )
    standby_host = prompt("IP-адрес или DNS-имя резервного EXIT")
    if not standby_host:
        fail("Необходимо указать адрес резервного EXIT")
    require_public_endpoint(standby_host, "Адрес резервного EXIT")
    standby_ipv4 = resolve_single_public_ipv4(standby_host, "Адрес резервного EXIT")
    taken_addresses = {
        str(entry_vars.get("security_interserver_peer_ipv4", "")),
        str(exit_vars.get("security_interserver_peer_ipv4", "")),
        str(entry_vars.get("front_public_ipv4", "")),
    }
    if standby_ipv4 in taken_addresses:
        fail("Этот адрес уже занят другим сервером каскада: резервному EXIT нужен отдельный сервер")
    standby_user = prompt("Пользователь SSH резервного EXIT", "root")
    standby_port = prompt_port("Текущий SSH-порт резервного EXIT", 22)
    primary_ssh_port = int(exit_hosts["exit-managed"].get("ssh_listen_port", 56777))
    standby_new_port = prompt_port("Новый управляемый SSH-порт резервного EXIT", primary_ssh_port)
    if standby_new_port < 1024:
        fail("Управляемый SSH-порт резервного EXIT должен находиться в диапазоне 1024–65535")
    standby_password = getpass.getpass("Пароль SSH резервного EXIT (ввод скрыт): ")
    if not standby_password:
        fail("Начальный пароль SSH резервного EXIT не может быть пустым")

    network = standby_transit_network(
        [
            exit_vars.get("exit_awg_subnet"),
            entry_vars.get("entry_client_subnet"),
            entry_vars.get("entry_legacy_client_subnet"),
            entry_vars.get("entry_mobile_client_subnet"),
            entry_vars.get("entry_ru_tun_address"),
        ]
    )
    exit_tunnel_ip, entry_tunnel_ip = list(network.hosts())[:2]
    exit_listen_port = int(exit_vars.get("exit_awg_listen_port", 443))
    used_ports = {
        int(entry_vars.get(key) or 0)
        for key in (
            "awg3_transit_listen_port",
            "security_interserver_listen_port",
            "entry_awg0_listen_port",
            "entry_legacy_client_listen_port",
            "entry_mobile_client_listen_port",
            "entry_mobile_legacy_internal_port",
        )
    }
    entry_listen_port = int(entry_vars.get("awg3_transit_listen_port") or 39745) + 1
    while entry_listen_port in used_ports:
        entry_listen_port += 1
    if entry_listen_port > 65535:
        fail("Не найден свободный UDP-порт ENTRY для туннеля резервного EXIT")
    profile = standby_transit_profile(entry_vars.get("entry_awg1_obfuscation"))

    ssh_private = Path.home() / ".ssh" / "awg-iac-production"
    ssh_public = Path(str(ssh_private) + ".pub")
    if not ssh_private.is_file() or not ssh_public.is_file():
        fail("Не найден управляющий SSH-ключ awg-iac-production")
    # Маршрут проверяется с этой машины, поэтому проверка имеет смысл, только
    # когда установщик работает на самом ENTRY (обычная схема).
    entry_hosts = children.get("entry", {}).get("hosts", {})
    if isinstance(entry_hosts, dict) and any(
        isinstance(values, dict) and values.get("ansible_connection") == "local"
        for values in entry_hosts.values()
    ):
        confirm_standby_route(standby_ipv4, standby_port)
    else:
        print("Маршрут от ENTRY до нового сервера не проверен: установщик запущен не на ENTRY.")
    standby_password = bootstrap_key(
        standby_host,
        standby_user,
        standby_port,
        standby_password,
        ssh_public,
        "резервный EXIT",
    )
    automation_source_ipv4 = remote_observed_ssh_source_ipv4(
        standby_host,
        standby_user,
        standby_port,
        ssh_private,
    )
    if not automation_source_ipv4:
        fail("Резервный EXIT не подтвердил исходный IPv4 управляющего SSH-сеанса")

    entry_private = awg_private_key()
    exit_private = awg_private_key()
    transit_psk = awg_psk()
    vault_updates: dict[str, object] = {
        "vault_awg_entry_standby_exit_private_key": entry_private,
        "vault_awg_entry_standby_exit_peer_public_key": awg_public_key(exit_private),
        "vault_awg_entry_standby_exit_psk": transit_psk,
        "vault_awg_entry_standby_exit_entry_public_key": awg_public_key(entry_private),
        "vault_awg_standby_header_protection_key": awg_private_key(),
        "vault_awg_standby_exit_private_key": exit_private,
        "vault_standby_exit_peers": [
            {
                "name": "entry",
                "public_key": awg_public_key(entry_private),
                "allowed_ips": [f"{entry_tunnel_ip}/32"],
                "preshared_key": transit_psk,
            }
        ],
    }
    if standby_user != "root":
        vault_updates["vault_exit_standby_become_password"] = standby_password
    update_production_vault(production, vault_password, vault_updates)

    entry_vars.update(
        {
            "entry_standby_exit_enabled": True,
            "entry_standby_exit_interface": STANDBY_EXIT_INTERFACE,
            "entry_standby_exit_host": STANDBY_EXIT_HOST,
            "entry_standby_exit_public_ipv4": standby_ipv4,
            "entry_standby_exit_endpoint": f"{standby_ipv4}:{exit_listen_port}",
            "entry_standby_exit_listen_port": entry_listen_port,
            "entry_standby_exit_tunnel_address": f"{entry_tunnel_ip}/32",
            "entry_standby_exit_peer_tunnel_address": str(exit_tunnel_ip),
            "entry_standby_exit_subnet": str(network),
            "entry_standby_exit_obfuscation": profile,
        }
    )
    yaml_write(entry_path, entry_vars)

    standby_vars: dict[str, object] = {
        # Адрес, а не имя: по нему же остальные серверы ограничивают выдачу своей
        # доли ключа (from= в authorized_keys), а sshd сверяет там адрес соединения.
        "ansible_host": standby_ipv4,
        "ansible_user": standby_user,
        "ansible_port": standby_port,
        "ansible_become": True,
        "ansible_ssh_private_key_file": str(ssh_private),
        "ssh_listen_port": standby_new_port,
        "security_allow_ssh_port_change": standby_port != standby_new_port,
        "security_automation_source_ipv4": automation_source_ipv4,
        "exit_standby": True,
        # Адрес ENTRY в туннеле этого сервера. Общее значение каскада относится к
        # туннелю основного EXIT, а роль exit сверяет с ним список peers.
        "awg_interserver_entry_address": f"{entry_tunnel_ip}/32",
        "exit_awg_address": f"{exit_tunnel_ip}/{network.prefixlen}",
        "exit_awg_subnet": str(network),
        "exit_awg_obfuscation": profile,
        "awg3_transit_address": f"{exit_tunnel_ip}/{network.prefixlen}",
        "awg3_peer_endpoint_port": entry_listen_port,
        "awg3_peer_tunnel_address": str(entry_tunnel_ip),
        "awg3_transit_allowed_ips": [f"{entry_tunnel_ip}/32"],
        "awg3_transit_obfuscation": profile,
        "awg3_transit_private_key": "{{ vault_awg_standby_exit_private_key }}",
        "awg3_transit_peer_public_key": "{{ vault_awg_entry_standby_exit_entry_public_key }}",
        # Имена секретов те же, что читает роль exit: у резервного сервера они
        # указывают на его собственные ключи.
        "vault_awg_exit_private_key": "{{ vault_awg_standby_exit_private_key }}",
        "vault_exit_peers": "{{ vault_standby_exit_peers }}",
        "vault_awg3_header_protection_key": "{{ vault_awg_standby_header_protection_key }}",
        "runtime_secrets_advertise_ipv4": standby_ipv4,
    }
    if standby_user != "root":
        standby_vars["ansible_become_password"] = "{{ vault_exit_standby_become_password }}"
    children["exit"]["hosts"][STANDBY_EXIT_HOST] = standby_vars
    yaml_write(hosts_path, hosts_document)

    # Новый сервер проходит тот же двухшаговый переход SSH, что и при установке:
    # сначала работают оба порта и root, затем вход остаётся только у kalimera.
    all_vars = load_yaml(all_path)
    if all_vars.get("security_finalize_admin_access") is not False:
        all_vars["security_finalize_admin_access"] = False
        yaml_write(all_path, all_vars)

    print(
        "Production inventory обновлён: добавлен резервный EXIT "
        f"({standby_ipv4}); он будет установлен текущим deploy."
    )
    return True


STANDBY_EXIT_VAULT_KEYS = (
    "vault_awg_entry_standby_exit_private_key",
    "vault_awg_entry_standby_exit_peer_public_key",
    "vault_awg_entry_standby_exit_psk",
    "vault_awg_entry_standby_exit_entry_public_key",
    "vault_awg_standby_header_protection_key",
    "vault_awg_standby_exit_private_key",
    "vault_standby_exit_peers",
    "vault_exit_standby_become_password",
)


def standby_exit_carries_traffic(entry_vars: dict) -> bool:
    """Идёт ли зарубежный трафик через резервный EXIT прямо сейчас.

    Читается файл переключателя путей на этой машине; если установщик запущен не
    на ENTRY, файла нет и ответ отрицательный.
    """
    state_dir = Path(str(entry_vars.get("entry_exit_path_state_dir") or "/run/kalimera-exit-path"))
    interface = str(entry_vars.get("entry_standby_exit_interface") or STANDBY_EXIT_INTERFACE)
    try:
        return (state_dir / "active").read_text(encoding="utf-8").strip() == interface
    except OSError:
        return False


def forget_ssh_host(host: str, ports: set[int]) -> None:
    """Убрать записи сервера из known_hosts этой машины.

    Иначе сервер, переустановленный на том же адресе, не прошёл бы проверку ключа
    узла при повторном подключении.
    """
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    ssh_keygen = shutil.which("ssh-keygen")
    if not host or ssh_keygen is None or not known_hosts.is_file():
        return
    for name in [host] + [f"[{host}]:{port}" for port in sorted(ports) if port != 22]:
        subprocess.run(
            [ssh_keygen, "-R", name, "-f", str(known_hosts)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def disable_standby_exit(production: Path, vault_password: Path) -> bool:
    """Отключить резервный EXIT: каскад возвращается к одному зарубежному серверу.

    Меняются только inventory и Vault. Второй туннель и переключатель путей на
    ENTRY снимает обычный deploy, который идёт следом. Сам отключённый сервер не
    изменяется: к этому моменту он может быть уже недоступен.
    """
    hosts_path = production / "hosts.yml"
    entry_path = production / "group_vars" / "entry.yml"
    if not hosts_path.is_file() or not entry_path.is_file() or not vault_password.is_file():
        fail("Для отключения резервного EXIT нужны production inventory и пароль Vault")
    hosts_document = load_yaml(hosts_path)
    entry_vars = load_yaml(entry_path)
    host_present = standby_exit_configured(hosts_document)
    entry_keys = [key for key in entry_vars if key.startswith("entry_standby_exit_")]
    # Прерванное отключение могло успеть убрать только хост: настройки ENTRY тогда
    # убираются этим же запуском.
    if not host_present and not entry_keys:
        print("Резервный EXIT не подключён: отключать нечего.")
        return False
    if standby_exit_carries_traffic(entry_vars):
        fail(
            "Зарубежный трафик сейчас идёт через резервный EXIT, отключение оборвало бы "
            "его. Сначала верните трафик на основной сервер: состояние - exit-path status, "
            "закрепить основной путь - exit-path use primary"
        )
    standby: dict = {}
    if host_present:
        candidate = hosts_document["all"]["children"]["exit"]["hosts"][STANDBY_EXIT_HOST]
        standby = candidate if isinstance(candidate, dict) else {}
    address = str(standby.get("ansible_host") or entry_vars.get("entry_standby_exit_public_ipv4") or "")
    ui_panel(
        "ОТКЛЮЧЕНИЕ РЕЗЕРВНОГО EXIT",
        [
            f"Сервер {address} выводится из каскада. ENTRY снимает второй туннель и",
            "переключатель путей, зарубежный трафик идёт только через основной EXIT.",
            "Клиентские конфиги не меняются.",
            "Сам сервер не изменяется: на нём остаются ключи его туннеля, его доля",
            "ключа хранилища и зашифрованная копия состояния контроллера. После",
            "отключения удалите сервер у хостера или переустановите на нём систему.",
        ],
        "yellow",
    )
    if not prompt_bool("Отключить резервный EXIT", False):
        print("Резервный EXIT оставлен подключённым.")
        raise SystemExit(0)

    if host_present:
        del hosts_document["all"]["children"]["exit"]["hosts"][STANDBY_EXIT_HOST]
        yaml_write(hosts_path, hosts_document)
    if entry_keys:
        for key in entry_keys:
            del entry_vars[key]
        yaml_write(entry_path, entry_vars)
    update_production_vault(production, vault_password, remove=STANDBY_EXIT_VAULT_KEYS)
    ports = {
        int(standby.get(key) or 22) for key in ("ansible_port", "ssh_listen_port")
    }
    forget_ssh_host(address, ports)
    print(
        f"Production inventory обновлён: резервный EXIT ({address}) отключён; второй "
        "туннель и переключатель путей на ENTRY снимет текущий deploy."
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
    # Маркер мог остаться от попытки, прерванной до изменения inventory: он
    # заменяется, иначе повторный запуск падал бы на существующем файле.
    restore_file(
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
    # Сначала проверяется вся копия: частично восстановленный inventory описывал бы
    # два разных FRONT сразу.
    for name in mapping:
        if not (backup_dir / name).is_file():
            fail("Резервная копия FRONT неполна")
    # Файлы нового FRONT уже лежат на месте. secure_write перезапись запрещает, и
    # откат падал на первом же файле; restore_file заменяет файл атомарно.
    for name, target in mapping.items():
        restore_file(target, (backup_dir / name).read_bytes())
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
    # Последняя доля - внешняя аварийная копия владельца и серверу не выдаётся.
    # Остальные раздаются серверам: с резервным EXIT их четыре из пяти.
    if len(active_hosts) > len(shares) - 1:
        fail(
            "Для серверов не хватает уникальных Shamir-долей с сохранением "
            "аварийной доли владельца"
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

    # Доля сервера не меняется при добавлении нового: сервер, подключённый позже
    # (резервный EXIT), получает первую свободную, а не сдвигает остальные.
    def host_values_of(host: str) -> dict:
        host_group = (
            entry_hosts
            if host in entry_hosts
            else exit_hosts
            if host in exit_hosts
            else front_hosts
        )
        values = host_group[host]
        if not isinstance(values, dict):
            values = {}
            host_group[host] = values
        return values

    assigned_indices: dict[str, int] = {}
    for host in active_hosts:
        current_index = host_values_of(host).get("runtime_secrets_share_index")
        if (
            isinstance(current_index, int)
            and 1 <= current_index < len(shares)
            and current_index not in assigned_indices.values()
        ):
            assigned_indices[host] = current_index
    free_indices = [
        index for index in range(1, len(shares)) if index not in assigned_indices.values()
    ]
    for host in active_hosts:
        if host not in assigned_indices:
            assigned_indices[host] = free_indices.pop(0)

    for host in active_hosts:
        share_index = assigned_indices[host]
        host_values = host_values_of(host)
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
    exit_group_hosts = children.get("exit", {}).get("hosts", {})
    for hosts, admin_hash, root_hash in host_mappings:
        # Роль exit допускает второй сервер - резервный EXIT. Учётные записи у него
        # те же, что у основного: рабочий вход и там и там только по ключу.
        allowed_count = (1, 2) if hosts is exit_group_hosts else (1,)
        if not isinstance(hosts, dict) or len(hosts) not in allowed_count:
            fail("Для миграции учётных записей требуется по одному хосту каждой активной роли")
        for values in hosts.values():
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

# Mobile/AWG3+ поднимается kernel-модулем через awg-quick, как и остальные
# клиентские интерфейсы; имя интерфейса задано ролью entry (awg-mobile).
MOBILE_SERVICE_NAME = "awg-quick@awg-mobile.service"

# Рандомизация размера выключена: с ней mobile терял 5% пакетов, без неё 0%
# (подробно - roles/awg3_mobile/defaults/main.yml).
AWG3_MOBILE_FEATURE_DEFAULTS = {
    "content_padding_addition": "0",
    "rekey_after_time": "120-180",
    "rekey_timeout": "5-8",
    "reject_after_time": "180-240",
    "keepalive_timeout": "10-15",
    "max_handshake_attempts": "18-24",
    "persistent_keepalive": "22-30",
    "random_trailers": False,
    "disable_cookies": False,
}

AWG_QUIC_INITIAL_SIZE = 1200
AWG_CPS_RANDOM_TAG_MAX = 1000
AWG_MINIMUM_OUTER_PMTU = 1280

# Границы размера коротких CPS-подписей I2-I5 общего профиля: пара диапазонов
# на ключ, из которых на каждый вызов разыгрываются нижняя и верхняя граница.
# Сами границы тоже случайны намеренно - репозиторий публичный, и постоянные
# литералы делали бы структуру профиля одинаковой во всех установках.
# Единственный источник правды: тесты читают эту же таблицу. Закреплённый в
# тесте отдельной копией предел уже успел устареть молча и отбраковывал 7%
# честных профилей, роняя CI на пустом месте.
AWG_SHORT_SIGNATURE_BOUNDS: dict[str, tuple[tuple[int, int], tuple[int, int]]] = {
    "i2": ((80, 110), (170, 220)),
    "i3": ((50, 75), (140, 180)),
    "i4": ((35, 55), (110, 145)),
    "i5": ((22, 40), (80, 110)),
}


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


def awg_random_header_ranges() -> list[str]:
    """Создать 4 непересекающихся диапазона H1-H4 со случайной шириной сетки.

    Раньше сетка была всегда одна и та же: ровно 4 диапазона по ровно
    500 000 000 каждый, с одних и тех же стартовых смещений при абсолютно
    любом вызове - сама эта структура (не только числа внутри неё)
    одинакова для любой установки этого (публичного) репозитория. Здесь
    ширина каждого слота выбирается заново при каждом вызове. Непересечение
    гарантируется тем, что курсор продвигается на всю зарезервированную
    ширину слота, а не только на использованную его часть - поэтому не
    может нарушиться независимо от того, какая ширина выпала. Худший случай
    (стартовый отступ 100 000 000 + 4 слота по 400 000 000) даёт максимум
    около 1.7 млрд - с явным запасом внутри допустимых для H1-H4
    [1, 2 147 483 647].
    """
    cursor = 1 + secrets.randbelow(100_000_000)
    ranges = []
    for _ in range(4):
        width = random_between((150_000_000, 400_000_000))
        offset = secrets.randbelow(int(width * 0.4) + 1)
        span = random_between((max(1, int(width * 0.1)), int(width * 0.4)))
        start = cursor + offset
        end = start + span
        ranges.append(f"{start}-{end}")
        cursor += width
    secrets.SystemRandom().shuffle(ranges)
    return ranges


def awg_short_signature_size_bounds(key: str) -> tuple[int, int]:
    """Разыграть границы размера короткой CPS-подписи I2-I5."""
    low, high = AWG_SHORT_SIGNATURE_BOUNDS[key]
    return random_between(low), random_between(high)


def awg_server_obfuscation() -> dict[str, object]:
    """Создать постоянный профиль AWG2 для KeeneticOS 5.1.x."""
    header_ranges = awg_random_header_ranges()
    s1, s2, s3 = awg_message_padding()
    result = {
        "jc": random_between((4, 8)),
        "jmin": random_between((48, 80)),
        "jmax": random_between((150, 230)),
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
        "i1": awg_quic_initial_signature(random_between((1200, 1252))),
        "i2": awg_quic_short_signature(awg_short_signature_size_bounds("i2")),
        "i3": awg_quic_short_signature(awg_short_signature_size_bounds("i3")),
        "i4": awg_quic_short_signature(awg_short_signature_size_bounds("i4")),
        "i5": awg_quic_short_signature(awg_short_signature_size_bounds("i5")),
    }
    validate_awg_obfuscation(result)
    return result


def awg_legacy_server_obfuscation() -> dict[str, object]:
    """Создать базовый ASC-профиль с одиночными H для KeeneticOS до 5.1."""
    headers = secrets.SystemRandom().sample(range(5, 2_147_483_648), 4)
    s1, s2, _ = awg_message_padding()
    result = {
        "jc": random_between((3, 6)),
        "jmin": random_between((48, 80)),
        "jmax": random_between((90, 130)),
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
    result.update({
        "jc": random_between((3, 7)),
        "jmin": random_between((6, 14)),
        "jmax": random_between((35, 70)),
    })
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

    Jc/Jmin/Jmax и границы I2-I5 переопределены относительно общего
    `awg_server_obfuscation()` в сторону большей энтропии/размера: это
    длинный высоконагруженный туннель без клиентского MTU-ограничения
    (в отличие от KeeneticOS/mobile), а сами эти поля - junk и
    handshake-смежные пакеты, а не поле, применяемое к каждому
    транспортному пакету, поэтому увеличение почти не стоит пропускной
    способности (см. docs/awg3.md). I1 не переопределяется - у него уже
    нет своего "потолка на профиль", он и так тянется к общему защитному
    пределу `+28 <= 1280` в `validate_awg_obfuscation` (используется её
    MTU-независимый дефолт, а не фактический согласованный MTU канала -
    профиль должен оставаться безопасным даже при самом низком допустимом
    MTU), поэтому отдельное значение для transit не добавило бы запаса.
    """
    result = awg_server_obfuscation()
    result.update({
        "jc": random_between((8, 16)),
        "jmin": random_between((48, 80)),
        "jmax": random_between((384, 640)),
        "i2": awg_quic_short_signature(
            (random_between((80, 112)), random_between((340, 430)))
        ),
        "i3": awg_quic_short_signature(
            (random_between((50, 78)), random_between((280, 360)))
        ),
        "i4": awg_quic_short_signature(
            (random_between((38, 58)), random_between((220, 290)))
        ),
        "i5": awg_quic_short_signature(
            (random_between((25, 40)), random_between((160, 220)))
        ),
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


def seal_local_controller_state(production: Path) -> None:
    """Сохранить в зашифрованный runtime-пакет правки после последнего seal.

    На локальном ENTRY каталог клиентов управляющего компьютера лежит в tmpfs
    runtime-секретов. Согласованный MTU записывается в него уже после playbook,
    который делает последний seal, поэтому без повторного seal перезагрузка
    ENTRY вернула бы в сохранённый конфиг прежний MTU.
    """
    entry_path = production / "group_vars" / "entry.yml"
    if not entry_path.is_file():
        return
    entry_vars = load_yaml(entry_path)
    if not entry_vars.get("runtime_secrets_controller_client_state_path"):
        return
    all_path = production / "group_vars" / "all" / "main.yml"
    all_vars = load_yaml(all_path) if all_path.is_file() else {}
    secretctl = str(
        all_vars.get("runtime_secrets_ctl_path") or "/usr/local/sbin/kalimera-secretctl"
    )
    try:
        subprocess.run([secretctl, "seal"], check=True, stdout=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        fail(
            "Не удалось сохранить согласованный MTU клиентских конфигов в "
            "зашифрованный пакет; выполните на ENTRY 'sudo kalimera-secretctl seal'"
        )


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
    variables = load_yaml(all_vars_path)
    entry_variables = load_yaml(entry_vars_path)
    exit_variables = load_yaml(exit_vars_path)
    stable_entry = load_yaml(stable_entry_path)
    awg3_defaults = load_yaml(awg3_defaults_path)

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
    # Профиль обфускации межсерверного канала - как и версии пакетов выше,
    # часть проверенного manifest этого выпуска репозитория, а не только
    # первичной установки. Пересоздаётся заново (свежие Jc/Jmin/Jmax/S1-S4/
    # H1-H4/I1-I5 - см. awg3_transit_obfuscation()) и записывается
    # одинаково на ENTRY и EXIT, иначе стороны разойдутся и handshake
    # перестанет собираться.
    transit_obfuscation = awg3_transit_obfuscation()
    entry_variables["awg3_transit_obfuscation"] = transit_obfuscation
    exit_variables["awg3_transit_obfuscation"] = transit_obfuscation
    # Остальные четыре профиля обфускации (общий/Keenetic 5.1.x, запасной
    # awg1 - тот же transit_obfuscation, что и выше, используется только
    # когда userspace AWG3+ выключен, легаси-Keenetic до 5.1, mobile/AWG3+)
    # живут только на ENTRY и тоже никогда не обновлялись после первой
    # установки - тот же класс проблемы, что уже был у transit до этой
    # сессии, чинится тем же способом.
    entry_variables["entry_awg0_obfuscation"] = awg_server_obfuscation()
    entry_variables["entry_awg1_obfuscation"] = transit_obfuscation
    entry_variables["entry_legacy_awg_obfuscation"] = awg_legacy_server_obfuscation()
    entry_variables["entry_mobile_awg_obfuscation"] = awg_mobile_awg3_obfuscation()
    yaml_write(all_vars_path, variables)
    yaml_write(entry_vars_path, entry_variables)
    yaml_write(exit_vars_path, exit_variables)


def require_amneziawg_ppa(repo: Path) -> None:
    """Не начинать обновление пакетов AmneziaWG, пока Launchpad недоступен.

    Без PPA транзакция упала бы уже на скачивании пакетов, а откат и
    сообщения об ошибке выглядели бы так, будто серверы пострадали. Проверка
    до любых изменений даёт понятный ответ: повторить позже.
    """
    defaults = load_yaml(repo / "roles" / "amneziawg" / "defaults" / "main.yml")
    url = f"{str(defaults['amneziawg_ppa_uri']).rstrip('/')}/dists/noble/InRelease"
    try:
        _http_get(url)
    except OSError as error:
        fail(
            "PPA AmneziaWG на Launchpad (ppa.launchpadcontent.net) сейчас "
            f"недоступен ({error}). Серверы не изменены; повторите обновление позже."
        )


def prepare_amneziawg_update(production: Path) -> None:
    """Разрешить новые пакеты AmneziaWG, не трогая профили обфускации.

    В отличие от --update-components здесь не перевыпускаются профили
    клиентов и межсерверного канала и не меняются sing-box/AWG3: обновляются
    только пакеты AmneziaWG, поэтому клиентские конфиги продолжают работать.
    """
    all_vars_path = production / "group_vars" / "all" / "main.yml"
    variables = load_yaml(all_vars_path)
    variables["awg_package_version_mode"] = "candidate"
    variables.pop("awg_package_versions", None)
    yaml_write(all_vars_path, variables)


XRAY_RELEASES_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
XRAY_DOWNLOAD_PREFIX = "https://github.com/XTLS/Xray-core/releases/download/"
XRAY_ASSETS = {"x86_64": "Xray-linux-64.zip", "aarch64": "Xray-linux-arm64-v8a.zip"}
XRAY_OVERRIDE_KEYS = ("front_xray_version", "front_xray_packages")
_XRAY_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _version_key(tag: str) -> tuple[int, ...]:
    return tuple(int(part) for part in tag.lstrip("v").split("."))


def _http_get(url: str, *, accept: str = "application/octet-stream") -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "KalimeraWG", "Accept": accept}
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return response.read()


def latest_xray_release() -> dict[str, object]:
    """Последний стабильный выпуск Xray-core и SHA256 архивов для FRONT.

    Контрольная сумма берётся из поля digest, которое GitHub вычисляет сам,
    а если его нет - из опубликованного рядом файла .dgst. Архив затем
    скачивает Ansible на FRONT и сверяет с этой суммой.
    """
    try:
        release = json.loads(
            _http_get(XRAY_RELEASES_API, accept="application/vnd.github+json")
        )
    except (OSError, ValueError) as error:
        fail(f"Не удалось получить сведения о выпуске Xray-core с GitHub: {error}")
    tag = str(release.get("tag_name", ""))
    if not _XRAY_TAG_RE.match(tag) or release.get("prerelease") or release.get("draft"):
        fail(f"GitHub вернул неподходящий выпуск Xray-core: {tag or 'без тега'}")
    assets = {
        str(asset.get("name")): asset
        for asset in release.get("assets", [])
        if isinstance(asset, dict)
    }
    packages: dict[str, dict[str, str]] = {}
    for architecture, name in XRAY_ASSETS.items():
        asset = assets.get(name)
        url = str(asset.get("browser_download_url", "")) if asset else ""
        if not url.startswith(XRAY_DOWNLOAD_PREFIX + tag + "/"):
            fail(f"В выпуске Xray-core {tag} нет архива {name}")
        digest = str(asset.get("digest") or "")
        checksum = digest.removeprefix("sha256:")
        if not _SHA256_RE.match(checksum):
            try:
                text = _http_get(url + ".dgst").decode("utf-8", "replace")
            except OSError as error:
                fail(f"Не удалось получить контрольную сумму {name}: {error}")
            found = re.search(r"SHA2-256=\s*([0-9a-f]{64})", text)
            checksum = found.group(1) if found else ""
        if not _SHA256_RE.match(checksum):
            fail(f"Для {name} в выпуске {tag} не найдена SHA256")
        packages[architecture] = {"url": url, "checksum": f"sha256:{checksum}"}
    return {"front_xray_version": tag, "front_xray_packages": packages}


def default_xray_version(repo: Path) -> str:
    defaults = load_yaml(repo / "roles" / "front" / "defaults" / "main.yml")
    return str(defaults["front_xray_version"])


def drop_stale_xray_override(repo: Path, production: Path) -> None:
    """Убрать версию Xray, закреплённую --update-xray, когда выпуск её догнал.

    Иначе однажды записанная в inventory версия навсегда перекрыла бы более
    новую, проверенную в следующем выпуске KalimeraWG.
    """
    front_path = production / "group_vars" / "front.yml"
    if not front_path.is_file():
        return
    front_vars = load_yaml(front_path)
    override = front_vars.get("front_xray_version")
    if not isinstance(override, str) or not _XRAY_TAG_RE.match(override):
        return
    if _version_key(default_xray_version(repo)) >= _version_key(override):
        for key in XRAY_OVERRIDE_KEYS:
            front_vars.pop(key, None)
        yaml_write(front_path, front_vars)


def newer_xray_release(repo: Path, production: Path) -> dict[str, object] | None:
    """Выпуск Xray новее применённого на FRONT либо None, если обновлять нечего."""
    front_path = production / "group_vars" / "front.yml"
    if not front_path.is_file():
        fail("FRONT не установлен: обновлять Xray-core негде")
    current = load_yaml(front_path).get("front_xray_version") or default_xray_version(repo)
    release = latest_xray_release()
    if _version_key(str(release["front_xray_version"])) <= _version_key(str(current)):
        return None
    release["previous_version"] = current
    return release


def apply_xray_release(production: Path, release: dict[str, object]) -> None:
    front_path = production / "group_vars" / "front.yml"
    front_vars = load_yaml(front_path)
    for key in XRAY_OVERRIDE_KEYS:
        front_vars[key] = release[key]
    yaml_write(front_path, front_vars)


# Легенды маскировки XHTTP: имя cookie сессии и формат её значения взяты из
# настроек по умолчанию настоящих фреймворков, чтобы id выглядел так же, как
# у реального приложения (у одного cookie на сайте длина id постоянна):
#   PHP:     PHPSESSID, 32 hex (session.sid_length 32, sid_bits_per_character 4);
#   Tomcat:  JSESSIONID, 32 HEX (sessionIdLength 16 байт, верхний регистр);
#   Django:  sessionid, 32 символа [a-z0-9] (get_random_string(32, ...)).
# Ключ паддинга - cookie CSRF-токена, обычный для того же фреймворка.
# Таблицы - предопределённые имена Xray-core (splithttp.PredefinedTable).
FRONT_DISGUISE_LEGENDS: tuple[dict[str, object], ...] = (
    {"cookie": "PHPSESSID", "table": "hex", "length": 32,
     "padding": ("csrf_token", "XSRF-TOKEN")},
    {"cookie": "JSESSIONID", "table": "HEX", "length": 32,
     "padding": ("XSRF-TOKEN", "_csrf")},
    {"cookie": "sessionid", "table": "base36", "length": 32,
     "padding": ("csrftoken",)},
)
# Имена заголовков аплинка (Xray добавляет к имени -0, -1, ...): только
# латиница, цифры и дефис - nginx молча выбрасывает имена с подчёркиванием,
# CDN передаёт произвольные X-...; длина как у прежнего X-Client-State, чтобы
# не менялся проверенный бюджет заголовков CDN.
FRONT_UPLINK_HEADER_NAMES: tuple[str, ...] = (
    "X-Client-State",
    "X-Request-State",
    "X-Session-State",
    "X-Sync-State",
    "X-App-State",
    "X-Client-Context",
    "X-Request-Context",
    "X-Page-State",
)
FRONT_DISGUISE_KEYS = (
    "front_xhttp_disguise_session_cookie",
    "front_xhttp_disguise_session_table",
    "front_xhttp_disguise_session_length",
    "front_xhttp_disguise_padding_key",
    "front_xhttp_uplink_data_key",
)


def new_front_disguise(current: dict[str, object] | None = None) -> dict[str, object]:
    """Собственный набор имён маскировки XHTTP для установки FRONT.

    Общие для многих установок имена (прежние PHPESSID/mc_token/X-Client-State)
    становятся приметой, по которой CDN или WAF может выделить такой трафик.
    current - действующий набор: новый обязан отличаться от него хотя бы
    именем cookie сессии или заголовка аплинка.
    """
    while True:
        legend = FRONT_DISGUISE_LEGENDS[secrets.randbelow(len(FRONT_DISGUISE_LEGENDS))]
        padding = legend["padding"]
        assert isinstance(padding, tuple)
        disguise: dict[str, object] = {
            "front_xhttp_disguise_session_cookie": legend["cookie"],
            "front_xhttp_disguise_session_table": legend["table"],
            "front_xhttp_disguise_session_length": legend["length"],
            "front_xhttp_disguise_padding_key": padding[secrets.randbelow(len(padding))],
            "front_xhttp_uplink_data_key": FRONT_UPLINK_HEADER_NAMES[
                secrets.randbelow(len(FRONT_UPLINK_HEADER_NAMES))
            ],
        }
        if not current or any(
            disguise[key] != current.get(key)
            for key in ("front_xhttp_disguise_session_cookie", "front_xhttp_uplink_data_key")
        ):
            return disguise


def current_front_disguise(repo: Path, front_vars: dict[str, object]) -> dict[str, object]:
    """Действующий набор: значения inventory поверх значений роли по умолчанию."""
    defaults = load_yaml(repo / "roles" / "front" / "defaults" / "main.yml")
    return {key: front_vars.get(key, defaults.get(key)) for key in FRONT_DISGUISE_KEYS}


def prepare_front_disguise_rotation(repo: Path, production: Path) -> dict[str, object]:
    """Записать в front.yml новый набор имён маскировки; вернуть прежний."""
    front_path = production / "group_vars" / "front.yml"
    if not front_path.is_file():
        fail("FRONT не установлен: менять маскировку XHTTP негде")
    front_vars = load_yaml(front_path)
    if not front_vars.get("front_xhttp_disguise_enabled", True):
        fail("Маскировка XHTTP на FRONT выключена: менять нечего")
    previous = current_front_disguise(repo, front_vars)
    front_vars.update(new_front_disguise(previous))
    yaml_write(front_path, front_vars)
    return previous


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
        else "AmneziaWG kernel"
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
    proxy_selected = proxy_enabled and entry_vars.get("entry_ru_proxy_scope", "all") == "selected"
    if proxy_selected:
        # Область selected: через прокси идут только списки proxy-domain и
        # proxy-address, российские сети выходят напрямую с ENTRY.
        architecture_rows.extend(
            [
                ("RU-трафик", "VPN-клиент → WAN ENTRY → Интернет"),
                ("Через RU-прокси", "только списки proxy-domain и proxy-address → SOCKS5/TUN"),
                (
                    "RU DNS",
                    "российский DoT напрямую с ENTRY, включая имена proxy-domain",
                ),
            ]
        )
    elif proxy_enabled:
        architecture_rows.extend(
            [
                ("RU-трафик", "VPN-клиент → ENTRY → SOCKS5/TUN → Интернет"),
                ("RU DNS", f"DoH через прокси: {doh_summary}"),
            ]
        )
    else:
        # Без RU-прокси российские имена разрешает российский DoT прямо с ENTRY
        # (roles/entry_dns, entry_dns_ru_dot_enabled включён по умолчанию).
        ru_dot_items = entry_vars.get("entry_dns_ru_dot_upstreams") or []
        if not entry_vars.get("entry_dns_ru_dot_enabled", True):
            ru_dns_summary = "основной резолвер ENTRY по DoT"
        elif ru_dot_items:
            ru_dns_summary = "DoT напрямую с ENTRY: " + ", ".join(
                f"{item['address']} (TLS: {item['tls_name']})" for item in ru_dot_items
            )
        else:
            ru_dns_summary = "Yandex DoT напрямую с ENTRY"
        architecture_rows.extend(
            [
                ("RU-трафик", "VPN-клиент → WAN ENTRY → Интернет"),
                ("RU DNS", ru_dns_summary),
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
            "Прокси/DNS: ru-proxy · ru-proxy-set · proxy-domain · proxy-address · dot-switch · doh-switch",
            "Система:    maintenance · update-all · f2b-reset",
            "Обновления: kalimera-updates · --update-amneziawg · --update-xray",
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


CASCADE_CHECK_PATH = Path("/usr/local/sbin/cascade-check")
CASCADE_VERIFY_UNIT = "kalimera-cascade-verify"
CASCADE_VERIFY_SCRIPT = Path("/usr/local/libexec/kalimera-cascade-verify")
CASCADE_VERIFY_DIR = Path("/var/lib/kalimera/cascade-reboot")
DEFAULT_MAINTENANCE_CALENDAR = "*-*-* 05:20:00"
MAINTENANCE_TIME_RE = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]")


def maintenance_calendar(time_value: str, zone: str) -> str:
    """Календарное выражение systemd для ночного обслуживания в часовом поясе zone."""
    if not MAINTENANCE_TIME_RE.fullmatch(time_value):
        fail(f"Время указывается как ЧЧ:ММ, например 02:20; получено: {time_value!r}")
    try:
        zoneinfo.ZoneInfo(zone)
    except (KeyError, ValueError):
        fail(f"Неизвестный часовой пояс: {zone!r}; например Asia/Manila или Europe/Moscow")
    return f"*-*-* {time_value}:00 {zone}"


def maintenance_show(production: Path) -> str:
    all_vars_path = production / "group_vars" / "all" / "main.yml"
    if not all_vars_path.is_file():
        fail("Не найдены групповые переменные production inventory")
    value = load_yaml(all_vars_path).get("awg_maintenance_calendar", DEFAULT_MAINTENANCE_CALENDAR)
    return str(value)


def set_maintenance_calendar(production: Path, calendar: str) -> str:
    """Записать время обслуживания в групповые переменные и вернуть прежнее значение."""
    all_vars_path = production / "group_vars" / "all" / "main.yml"
    if not all_vars_path.is_file():
        fail("Не найдены групповые переменные production inventory")
    all_vars = load_yaml(all_vars_path)
    previous = str(all_vars.get("awg_maintenance_calendar", DEFAULT_MAINTENANCE_CALENDAR))
    all_vars["awg_maintenance_calendar"] = calendar
    yaml_write(all_vars_path, all_vars)
    return previous


def cascade_reboot_plan(hosts_document: dict) -> list[str]:
    """Порядок перезагрузки: FRONT, затем EXIT, затем ENTRY.

    ENTRY идёт последним: его перезагрузка обрывает этот процесс, поэтому после
    неё проверку выполняет отдельный юнит systemd.
    """
    children = hosts_document["all"]["children"]
    order: list[str] = []
    if (children.get("front") or {}).get("hosts"):
        order.append("front")
    exit_hosts = (children.get("exit") or {}).get("hosts") or {}
    if len(exit_hosts) > 1:
        # С резервным EXIT серверы группы перезагружаются по одному: сначала
        # резервный, затем основной. Пока один из них загружается, зарубежный
        # трафик идёт через другой.
        standby = [
            name for name, values in exit_hosts.items()
            if isinstance(values, dict) and values.get("exit_standby")
        ]
        order.extend(standby + [name for name in exit_hosts if name not in standby])
    elif exit_hosts:
        order.append("exit")
    return [*order, "entry"]


def run_cascade_check() -> subprocess.CompletedProcess[str]:
    if not CASCADE_CHECK_PATH.is_file():
        fail("cascade-check не установлен на ENTRY; сначала выполните kalimera-deploy --resume")
    return subprocess.run(
        [str(CASCADE_CHECK_PATH)], capture_output=True, text=True, check=False
    )


def cascade_check_ok(result: subprocess.CompletedProcess[str]) -> bool:
    """Код 0 - OK, 3 - WARN (каскад работает). Код 1 - FAIL."""
    return result.returncode in (0, 3)


def cascade_problems(output: str) -> list[str]:
    """Строки FAIL и WARN из отчёта cascade-check."""
    return [line.strip() for line in output.splitlines() if re.match(r"\s*(FAIL|WARN)\s", line)]


def wait_for_cascade(attempts: int = 12, delay_seconds: int = 30) -> bool:
    """Дождаться, пока каскад полностью отвечает: туннели после загрузки поднимаются не сразу.

    При неудаче выводит строки FAIL и WARN, чтобы ошибки были видны в терминале.
    """
    result = None
    for attempt in range(1, attempts + 1):
        result = run_cascade_check()
        if cascade_check_ok(result):
            print(f"cascade-check после перезагрузки: код {result.returncode} (попытка {attempt})")
            return True
        if attempt < attempts:
            time.sleep(delay_seconds)
    problems = cascade_problems(result.stdout) if result is not None else []
    print("cascade-check после перезагрузки нашёл ошибки:")
    for line in problems or ["FAIL отчёт cascade-check не прочитан"]:
        print(f"  {line}")
    return False


def cascade_verify_script() -> str:
    return textwrap.dedent(
        f"""\
        #!/bin/sh
        # Создано cascade-reboot: проверка каскада после перезагрузки ENTRY.
        set -u
        sleep 120
        mkdir -p {CASCADE_VERIFY_DIR}
        # Туннели и хранилище секретов поднимаются не сразу: проверка повторяется,
        # пока не пройдёт, но не дольше десяти минут.
        deadline=$(( $(date +%s) + 600 ))
        while :; do
            {CASCADE_CHECK_PATH} > {CASCADE_VERIFY_DIR}/last-verify.tmp 2>&1
            rc=$?
            if [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || [ "$(date +%s)" -ge "$deadline" ]; then
                break
            fi
            sleep 30
        done
        {{
            cat {CASCADE_VERIFY_DIR}/last-verify.tmp
            echo "rc=$rc"
        }} > {CASCADE_VERIFY_DIR}/last-verify.txt
        rm -f {CASCADE_VERIFY_DIR}/last-verify.tmp
        # Перезагрузку начала автоматика: она сообщает итог, а после неудачи
        # останавливается до команды cascade-reboot auto on.
        if [ -e {AUTO_PENDING_FILE} ]; then
            rm -f {AUTO_PENDING_FILE}
            now="$(date -u '+%Y-%m-%d %H:%M UTC')"
            if [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ]; then
                printf '%s\\n' "$now: выполнена, каскад исправен" > {AUTO_STATUS_FILE}
                {TELEGRAM_NOTIFIER_PATH} --notify "AWG ENTRY: автоматическая перезагрузка каскада завершена; каскад исправен" >/dev/null 2>&1 || true
            else
                reason="после перезагрузки ENTRY каскад не прошёл проверку: cascade-check"
                printf '%s\\n' "$now: $reason" > {AUTO_BLOCK_FILE}
                printf '%s\\n' "$now: остановлена - $reason" > {AUTO_STATUS_FILE}
                {TELEGRAM_NOTIFIER_PATH} --notify "AWG ENTRY: автоматическая перезагрузка каскада остановлена
        $reason
        Возобновить после устранения причины: cascade-reboot auto on" >/dev/null 2>&1 || true
            fi
        fi
        systemctl disable {CASCADE_VERIFY_UNIT}.service >/dev/null 2>&1 || true
        exit 0
        """
    )


def cascade_verify_unit() -> str:
    return textwrap.dedent(
        f"""\
        [Unit]
        Description=Проверка каскада KalimeraWG после перезагрузки ENTRY
        Wants=network-online.target
        After=network-online.target

        [Service]
        Type=oneshot
        # По умолчанию systemd снимает oneshot через 90 с, а проверка после загрузки
        # ждёт 120 с и повторяется до десяти минут: без этого она всегда обрывалась
        # до записи результата.
        TimeoutStartSec=1800
        ExecStart={CASCADE_VERIFY_SCRIPT}

        [Install]
        WantedBy=multi-user.target
        """
    )


def schedule_entry_reboot() -> None:
    """Запланировать перезагрузку ENTRY; при загрузке он сам проверит каскад."""
    CASCADE_VERIFY_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
    CASCADE_VERIFY_SCRIPT.write_text(cascade_verify_script(), encoding="utf-8")
    CASCADE_VERIFY_SCRIPT.chmod(0o755)
    unit_path = Path("/etc/systemd/system") / f"{CASCADE_VERIFY_UNIT}.service"
    unit_path.write_text(cascade_verify_unit(), encoding="utf-8")
    unit_path.chmod(0o644)
    (CASCADE_VERIFY_DIR / "last-verify.txt").unlink(missing_ok=True)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", f"{CASCADE_VERIFY_UNIT}.service"])
    run(
        [
            "systemd-run",
            "--on-active=15",
            f"--unit=kalimera-cascade-reboot-{int(time.time())}",
            "/bin/systemctl",
            "reboot",
        ]
    )


BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
ADHOC_TIMEOUT_SECONDS = 60


def ansible_adhoc(
    repo: Path,
    hosts_path: Path,
    vault_password: Path,
    group: str,
    module: str,
    module_args: str,
    *,
    become: bool = False,
    oneline: bool = True,
    timeout: int = ADHOC_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str] | None:
    """Короткая команда Ansible на группе с ограничением по времени.

    Модуль reboot ждёт сервер внутри Ansible и мог зависнуть без сообщения. Здесь
    каждый вызов ограничен по времени: при отсутствии ответа возвращается None.
    oneline=False оставляет вывод команды построчным, с табуляциями как есть.
    """
    argv = [
        require_command("ansible"),
        "-i",
        str(hosts_path),
        group,
        "-m",
        module,
        "-a",
        module_args,
        "--vault-password-file",
        str(vault_password),
    ]
    if oneline:
        argv.insert(4, "-o")
    if become:
        argv.append("-b")
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            cwd=str(repo),
        )
    except subprocess.TimeoutExpired:
        return None


def read_boot_id(repo: Path, hosts_path: Path, vault_password: Path, group: str) -> str | None:
    """Идентификатор текущей загрузки сервера; он меняется после каждой перезагрузки."""
    result = ansible_adhoc(
        repo, hosts_path, vault_password, group, "command", "cat /proc/sys/kernel/random/boot_id"
    )
    if result is None:
        return None
    output = result.stdout + result.stderr
    if "Permission denied" in output:
        # Повторять неверный ключ нельзя: каждая неудачная попытка идёт в Fail2Ban,
        # и сервер блокирует ENTRY сам.
        fail(
            f"{group} отклонил ключ ENTRY (Permission denied). Остановлено, чтобы не получить "
            "бан Fail2Ban. Проверьте адрес ENTRY в правилах доступа этого сервера."
        )
    if result.returncode != 0:
        return None
    match = BOOT_ID_RE.search(result.stdout)
    return match.group(0) if match else None


def schedule_host_reboot(repo: Path, hosts_path: Path, vault_password: Path, group: str) -> bool:
    if group == "entry":
        fail("ENTRY перезагружается отдельным шагом, а не через Ansible")
    result = ansible_adhoc(
        repo,
        hosts_path,
        vault_password,
        group,
        "command",
        "systemd-run --on-active=3 /bin/systemctl reboot",
        become=True,
    )
    return result is not None and result.returncode == 0


def wait_for_host_reboot(
    repo: Path,
    hosts_path: Path,
    vault_password: Path,
    group: str,
    previous_boot_id: str,
    *,
    attempts: int = 20,
    delay_seconds: int = 20,
) -> bool:
    """Дождаться новой загрузки: сервер должен сменить boot_id, а не просто ответить."""
    time.sleep(30)
    for attempt in range(1, attempts + 1):
        current = read_boot_id(repo, hosts_path, vault_password, group)
        if current is not None and current != previous_boot_id:
            print(f"{group}: сервер загрузился заново (попытка {attempt})")
            return True
        time.sleep(delay_seconds)
    return False


LIST_SEAL_PENDING = Path("/run/kalimera-lists.seal-pending")


def save_pending_list_changes(production: Path) -> bool:
    """Сохранить в зашифрованный пакет изменения списков, которые в него не попали.

    Команды ru-domain, proxy-domain, proxy-address и ru-direct-ports оставляют
    отметку, если не смогли обновить пакет. Списки лежат в tmpfs, и после
    перезагрузки ENTRY такие изменения пропали бы.
    """
    if not LIST_SEAL_PENDING.exists():
        return True
    all_path = production / "group_vars" / "all" / "main.yml"
    all_vars = load_yaml(all_path) if all_path.is_file() else {}
    secretctl = str(
        all_vars.get("runtime_secrets_ctl_path") or "/usr/local/sbin/kalimera-secretctl"
    )
    try:
        result = subprocess.run(
            [secretctl, "seal"], check=False, stdout=subprocess.DEVNULL
        )
    except OSError:
        return False
    return result.returncode == 0


def status_line(level: str, text: str) -> None:
    """Строка проверки: OK зелёным, FAIL красным (цвет только в терминале)."""
    colours = {"OK": "\033[1;32m", "FAIL": "\033[1;31m"}
    prefix = f"{level:<4} "
    if sys.stdout.isatty() and level in colours:
        prefix = f"{colours[level]}{level:<4}\033[0m "
    print(prefix + text)


REBOOT_GUARD_PATH = Path("/usr/local/sbin/kalimera-reboot-guard")
TELEGRAM_NOTIFIER_PATH = Path("/usr/local/sbin/awg-telegram-monitor")
# Подготовка к перезагрузке может собирать модуль AmneziaWG под новое ядро.
GUARD_TIMEOUT_SECONDS = 900
GUARD_ROW_RE = re.compile(r"^(NEED|OK|FAIL|WAIT|HOLD)\t([^\t]*)(?:\t(.*))?$")
# Состояние автоматической перезагрузки. Каталог постоянный: отметки должны
# пережить перезагрузку ENTRY, которой автоматика и управляет.
AUTO_BLOCK_FILE = CASCADE_VERIFY_DIR / "auto-blocked"
AUTO_OFF_FILE = CASCADE_VERIFY_DIR / "auto-off"
AUTO_LAST_FILE = CASCADE_VERIFY_DIR / "auto-last"
AUTO_PENDING_FILE = CASCADE_VERIFY_DIR / "auto-pending"
AUTO_STATUS_FILE = CASCADE_VERIFY_DIR / "auto-status"
WEEKLY_TIMER = "kalimera-weekly.timer"
DEFAULT_AUTO_REBOOT_INTERVAL_DAYS = 6
GUARD_WAIT_ATTEMPTS = 20
GUARD_WAIT_SECONDS = 120
SERVER_NAMES = {
    "entry": "ENTRY",
    "exit": "EXIT",
    "front": "FRONT",
    # С резервным EXIT серверы группы exit перезагружаются по именам хостов.
    "exit-managed": "EXIT",
    "exit-standby-managed": "EXIT резервный",
}


class GuardReport(NamedTuple):
    """Ответ kalimera-reboot-guard одного сервера.

    rows - строки (статус, проверка, подробности): FAIL - сервер может не
    подняться, WAIT - идёт установка пакетов или deploy, HOLD - правило только
    для автоматической перезагрузки.
    """

    group: str
    answered: bool
    need: bool = False
    need_reason: str = ""
    rows: tuple[tuple[str, str, str], ...] = ()

    def problems(self, *statuses: str) -> list[str]:
        return [
            f"{label}: {detail}" if detail else label
            for status, label, detail in self.rows
            if status in statuses
        ]


def parse_guard_output(group: str, output: str) -> GuardReport:
    """Разобрать вывод kalimera-reboot-guard; посторонние строки Ansible пропускаются."""
    rows: list[tuple[str, str, str]] = []
    need: bool | None = None
    need_reason = ""
    for line in output.splitlines():
        match = GUARD_ROW_RE.match(line)
        if not match:
            continue
        status, label, detail = match.group(1), match.group(2), match.group(3) or ""
        if status == "NEED":
            need = label == "yes"
            need_reason = detail
        else:
            rows.append((status, label, detail))
    if need is None:
        # Без строки NEED это не ответ предохранителей: программа не установлена
        # или сервер не выполнил команду.
        return GuardReport(group, answered=False)
    return GuardReport(group, True, need, need_reason, tuple(rows))


def run_reboot_guard(
    repo: Path, hosts_path: Path, vault_password: Path, group: str, mode: str
) -> GuardReport:
    """Предохранители перезагрузки на сервере group: check или prepare."""
    if group == "entry":
        if not REBOOT_GUARD_PATH.is_file():
            return GuardReport(group, answered=False)
        try:
            result = subprocess.run(
                [str(REBOOT_GUARD_PATH), mode],
                capture_output=True,
                text=True,
                check=False,
                timeout=GUARD_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            return GuardReport(group, answered=False)
        return parse_guard_output(group, result.stdout)
    result = ansible_adhoc(
        repo,
        hosts_path,
        vault_password,
        group,
        "command",
        f"{REBOOT_GUARD_PATH} {mode}",
        become=True,
        oneline=False,
        timeout=GUARD_TIMEOUT_SECONDS,
    )
    if result is None:
        return GuardReport(group, answered=False)
    return parse_guard_output(group, result.stdout)


def guard_blockers(report: GuardReport, *, automatic: bool) -> list[str]:
    """Причины, по которым сервер нельзя перезагружать.

    Правила HOLD (свежее ядро, недавняя загрузка) относятся только к
    автоматической перезагрузке: человек, запустивший её сам, уже принял решение.
    """
    if not report.answered:
        return ["предохранители перезагрузки не ответили; на ENTRY: kalimera-deploy --resume"]
    if automatic:
        return report.problems("FAIL", "WAIT", "HOLD")
    return report.problems("FAIL", "WAIT")


def utc_now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())


def telegram_notify(text: str) -> bool:
    """Отправить готовое сообщение через Telegram-монитор сервера; False - не доставлено."""
    if not TELEGRAM_NOTIFIER_PATH.is_file():
        return False
    try:
        result = subprocess.run(
            [str(TELEGRAM_NOTIFIER_PATH), "--notify", text],
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def run_cascade_reboot(
    repo: Path, production: Path, vault_password: Path, *, confirmed: bool, force: bool = False
) -> None:
    hosts_path = production / "hosts.yml"
    vault_path = production / "group_vars" / "all" / "vault.yml"
    if not hosts_path.is_file() or not vault_path.is_file() or not vault_password.is_file():
        fail("Не найден production inventory или внешний пароль Ansible Vault")
    plan = cascade_reboot_plan(load_yaml(hosts_path))
    print("Порядок перезагрузки: " + " → ".join(plan))
    # Полная проверка каскада здесь не нужна: ошибка может быть как раз той
    # причиной, по которой перезагрузка нужна. До первого шага проверяется только,
    # что каждый перезагружаемый сервер отвечает по SSH: иначе его не перезагрузить
    # и не дождаться возврата.
    boot_ids: dict[str, str] = {}
    unreachable: list[str] = []
    for group in plan[:-1]:
        boot_id = read_boot_id(repo, hosts_path, vault_password, group)
        if boot_id is None:
            status_line("FAIL", f"{group}: SSH не отвечает")
            unreachable.append(group)
        else:
            status_line("OK", f"{group}: SSH отвечает, загрузка {boot_id[:8]}")
            boot_ids[group] = boot_id
    status_line("OK", "entry: локальный узел, перезагрузится последним")
    maintenance = subprocess.run(
        ["systemctl", "is-active", "--quiet", "awg-maintenance.service"], check=False
    )
    if maintenance.returncode == 0:
        status_line("FAIL", "ночное обслуживание выполняется сейчас")
        fail("Повторите позже, когда обслуживание завершится.")
    status_line("OK", "ночное обслуживание не выполняется")
    if LIST_SEAL_PENDING.exists():
        if not save_pending_list_changes(production):
            status_line("FAIL", "изменения списков не сохранены в зашифрованном пакете")
            fail(
                "Перезагрузка не начата: после неё списки доменов, адресов и портов на ENTRY "
                "вернулись бы к прежнему состоянию. Проверьте связь с EXIT и FRONT "
                "(cascade-check) и выполните: sudo kalimera-secretctl seal"
            )
        status_line("OK", "изменения списков сохранены в зашифрованном пакете")
    if unreachable:
        fail(
            f"Перезагрузка не начата: не отвечают {', '.join(unreachable)}. Ничего не перезагружено. "
            "Возможные причины: Fail2Ban или ограничение частоты UFW блокируют ENTRY, либо устарел "
            "адрес ENTRY в правилах доступа. На этом сервере проверьте: "
            "sudo fail2ban-client status sshd; sudo ufw status numbered"
        )
    # Предохранители: сервер не перезагружается, если может не подняться после
    # этого (ядро установлено не целиком, нет модуля AmneziaWG, не откроется
    # хранилище секретов) или если на нём идёт установка пакетов.
    unsafe: list[str] = []
    for group in plan:
        report = run_reboot_guard(repo, hosts_path, vault_password, group, "check")
        problems = guard_blockers(report, automatic=False)
        for problem in problems:
            status_line("FAIL", f"{group}: {problem}")
        if problems:
            unsafe.append(group)
            continue
        need = "перезагрузка требуется" if report.need else "перезагрузка не требуется"
        status_line("OK", f"{group}: предохранители пройдены, {need}")
        for note in report.problems("HOLD"):
            print(f"     {group}: автоматическая перезагрузка отложена - {note}")
    if unsafe and not force:
        fail(
            f"Перезагрузка не начата: {', '.join(unsafe)} может не подняться после неё "
            "(причины выше). Ничего не перезагружено. Перезагрузить несмотря на это: "
            "cascade-reboot --yes --force"
        )
    if not confirmed:
        status_line("OK", "перезагрузка возможна: все серверы отвечают")
        print("Перезагрузка не выполнена. Для запуска выполните: cascade-reboot --yes")
        return
    for group in plan[:-1]:
        print(f"Перезагрузка: {group}")
        boot_before = boot_ids[group]
        # Перед самой перезагрузкой: модуль AmneziaWG собирается под новое ядро,
        # секреты сохраняются в зашифрованный пакет, проверка повторяется.
        problems = guard_blockers(
            run_reboot_guard(repo, hosts_path, vault_password, group, "prepare"), automatic=False
        )
        if problems and not force:
            fail(
                f"{group} не перезагружен: подготовка не пройдена ({'; '.join(problems)}). "
                "Остальные серверы не перезагружались."
            )
        if not schedule_host_reboot(repo, hosts_path, vault_password, group):
            fail(
                f"Не удалось запланировать перезагрузку {group}. Остальные серверы не перезагружались."
            )
        if not wait_for_host_reboot(repo, hosts_path, vault_password, group, boot_before):
            fail(
                f"{group} не вернулся после перезагрузки за отведённое время. Остальные "
                "серверы не перезагружались. Проверьте сервер"
            )
        print(f"{group}: проверяю каскад после перезагрузки...")
        if wait_for_cascade():
            continue
        if not force:
            fail(
                f"После перезагрузки {group} каскад не прошёл проверку (ошибки выше). Остальные "
                "серверы не перезагружались. Чтобы продолжить несмотря на ошибки: cascade-reboot --yes --force"
            )
        print(f"ВНИМАНИЕ: после {group} остались ошибки (выше). Продолжаю, потому что указан --force")
    problems = guard_blockers(
        run_reboot_guard(repo, hosts_path, vault_password, "entry", "prepare"), automatic=False
    )
    if problems and not force:
        fail(f"ENTRY не перезагружен: подготовка не пройдена ({'; '.join(problems)}).")
    print("ENTRY перезагрузится через 15 секунд. Результат проверки после загрузки: cascade-reboot status")
    schedule_entry_reboot()


class AutoRebootSettings(NamedTuple):
    enabled: bool = True
    min_interval_days: int = DEFAULT_AUTO_REBOOT_INTERVAL_DAYS


def auto_reboot_settings(production: Path) -> AutoRebootSettings:
    all_path = production / "group_vars" / "all" / "main.yml"
    all_vars = load_yaml(all_path) if all_path.is_file() else {}
    try:
        interval = int(all_vars.get("awg_auto_reboot_min_interval_days", DEFAULT_AUTO_REBOOT_INTERVAL_DAYS))
    except (TypeError, ValueError):
        interval = DEFAULT_AUTO_REBOOT_INTERVAL_DAYS
    return AutoRebootSettings(
        enabled=bool(all_vars.get("awg_auto_reboot_enabled", True)), min_interval_days=max(interval, 0)
    )


class AutoRebootDecision(NamedTuple):
    """Решение автоматики: reboot, none (не требуется), deferred, blocked или disabled."""

    action: str
    reason: str = ""
    groups: tuple[str, ...] = ()

    def line(self) -> str:
        names = ", ".join(SERVER_NAMES.get(group, group) for group in self.groups)
        if self.action == "reboot":
            return f"выполняется сейчас: {names}" + (f" ({self.reason})" if self.reason else "")
        if self.action == "none":
            return "не требуется"
        if self.action == "blocked":
            return f"остановлена после неудачи - {self.reason}; возобновить: cascade-reboot auto on"
        if self.action == "disabled":
            return self.reason
        return f"требуется, отложена - {self.reason}"


def read_cascade_rows() -> tuple[int, list[tuple[str, ...]]]:
    """Строки cascade-check --tsv: (сегмент, статус, проверка, значение, рекомендация, мс)."""
    if not CASCADE_CHECK_PATH.is_file():
        return 1, []
    try:
        result = subprocess.run(
            [str(CASCADE_CHECK_PATH), "--tsv"], capture_output=True, text=True, check=False, timeout=900
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1, []
    rows = [tuple(line.split("\t")) for line in result.stdout.splitlines() if line.count("\t") == 5]
    return result.returncode, rows


def cascade_failures(rows: list[tuple[str, ...]]) -> list[str]:
    return [
        f"{seg}: {label}" + (f": {value}" if value else "")
        for seg, status, label, value, _hint, _ms in rows
        if status == "FAIL"
    ]


CASCADE_CONFIRM_ATTEMPTS = 3
CASCADE_CONFIRM_SECONDS = 90


def read_confirmed_cascade_rows() -> tuple[int, list[tuple[str, ...]]]:
    """Отчёт cascade-check, в котором ошибка подтверждена повторными запусками.

    Одна проверка может не пройти разово (потерянный ответ DNS через прокси). По
    единственному запуску автоматика отложила бы перезагрузку на неделю, а
    сводка сообщила бы «работа каскада нарушена» при исправном каскаде.
    """
    code, rows = read_cascade_rows()
    for _ in range(CASCADE_CONFIRM_ATTEMPTS - 1):
        if rows and not cascade_failures(rows):
            break
        time.sleep(CASCADE_CONFIRM_SECONDS)
        code, rows = read_cascade_rows()
    return code, rows


def write_auto_state(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip("\n") + "\n", encoding="utf-8")
    path.chmod(0o600)


def decide_auto_reboot(
    repo: Path,
    hosts_path: Path,
    vault_password: Path,
    plan: list[str],
    settings: AutoRebootSettings,
    cascade_rows: list[tuple[str, ...]],
    *,
    now: float | None = None,
) -> AutoRebootDecision:
    """Нужна ли автоматическая перезагрузка и можно ли выполнить её сейчас.

    Перезагрузка начинается, только если на каждом перезагружаемом сервере
    пройдены все предохранители и в отчёте cascade-check нет ошибок: исправный
    каскад не должен стать неисправным из-за планового обновления.
    """
    now = time.time() if now is None else now
    if not settings.enabled:
        return AutoRebootDecision("disabled", "автоматическая перезагрузка выключена в настройках каскада")
    if AUTO_OFF_FILE.exists():
        return AutoRebootDecision("disabled", "автоматическая перезагрузка выключена командой cascade-reboot auto off")
    if AUTO_BLOCK_FILE.exists():
        reason = AUTO_BLOCK_FILE.read_text(encoding="utf-8").strip().splitlines()
        return AutoRebootDecision("blocked", reason[0] if reason else "причина не записана")

    reports: dict[str, GuardReport] = {}
    for attempt in range(1, GUARD_WAIT_ATTEMPTS + 1):
        reports = {
            group: run_reboot_guard(repo, hosts_path, vault_password, group, "check") for group in plan
        }
        waiting = any(report.problems("WAIT") for report in reports.values())
        if not waiting or attempt == GUARD_WAIT_ATTEMPTS:
            break
        # Идёт ночное обслуживание или обновление списков пакетов: это минуты.
        time.sleep(GUARD_WAIT_SECONDS)

    silent = [SERVER_NAMES.get(group, group) for group in plan if not reports[group].answered]
    if silent:
        return AutoRebootDecision("deferred", f"предохранители не ответили: {', '.join(silent)}")
    needed = tuple(group for group in plan if reports[group].need)
    if not needed:
        return AutoRebootDecision("none")
    try:
        last = float(AUTO_LAST_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        last = 0.0
    days_since = (now - last) / 86400
    if last > 0 and 0 <= days_since < settings.min_interval_days:
        return AutoRebootDecision(
            "deferred",
            f"предыдущая автоматическая перезагрузка была {int(days_since)} дн. назад, "
            f"интервал {settings.min_interval_days} дн.",
            needed,
        )
    blockers = [
        f"{SERVER_NAMES.get(group, group)}: {problem}"
        for group in needed
        for problem in guard_blockers(reports[group], automatic=True)
    ]
    if blockers:
        return AutoRebootDecision("deferred", "; ".join(blockers), needed)
    failures = cascade_failures(cascade_rows)
    if failures:
        return AutoRebootDecision(
            "deferred", "в отчёте cascade-check есть ошибки: " + "; ".join(failures[:4]), needed
        )
    reasons = sorted({reports[group].need_reason for group in needed if reports[group].need_reason})
    return AutoRebootDecision("reboot", "; ".join(reasons)[:200], needed)


def weekly_digest(rows: list[tuple[str, ...]], reboot_line: str) -> str:
    """Еженедельная сводка для Telegram по строкам cascade-check.

    Сводка приходит и тогда, когда всё исправно: молчание исправного каскада
    иначе не отличить от сломанной доставки уведомлений.
    """
    counts = {"OK": 0, "WARN": 0, "FAIL": 0}
    problems: list[str] = []
    healing: list[str] = []
    updates: list[str] = []
    for seg, status, label, value, _hint, _ms in rows:
        if status in counts:
            counts[status] += 1
        if label.startswith("самовосстановление: "):
            text = label.removeprefix("самовосстановление: ")
            if status != "OK" and value:
                text += f" - {value}"
            healing.append(f"  {seg}: {text}")
        elif label.startswith("обновление компонента: "):
            text = label.removeprefix("обновление компонента: ") + (f" → {value}" if value else "")
            if text not in updates:
                updates.append(text)
        elif status in ("WARN", "FAIL"):
            problems.append(f"  {status} {seg}: {label}" + (f": {value}" if value else ""))
    if not rows:
        verdict = "отчёт cascade-check не получен"
    elif counts["FAIL"]:
        verdict = "работа каскада нарушена"
    elif counts["WARN"]:
        verdict = "каскад работает, есть замечания"
    else:
        verdict = "все проверки пройдены"
    lines = [
        "AWG ENTRY: еженедельная сводка каскада",
        f"Состояние: {verdict} (OK {counts['OK']} · WARN {counts['WARN']} · FAIL {counts['FAIL']})",
    ]
    lines += problems[:8]
    if len(problems) > 8:
        lines.append(f"  … и ещё замечаний: {len(problems) - 8}; подробности: cascade-check")
    lines.append("Самовосстановление:")
    lines += healing or ["  сведений нет"]
    lines.append("Обновления компонентов: " + ("нет" if not updates else ""))
    lines += [f"  {text}" for text in updates]
    lines.append(f"Перезагрузка: {reboot_line}")
    return "\n".join(lines)


def block_auto_reboot(reason: str) -> None:
    """Остановить автоматическую перезагрузку до команды cascade-reboot auto on.

    После неудачи автоматика не повторяет попытку сама: сервер, не вернувшийся
    после перезагрузки, требует человека, а повтор мог бы вывести из строя и
    остальные серверы.
    """
    write_auto_state(AUTO_BLOCK_FILE, f"{utc_now_text()}: {reason}")
    write_auto_state(AUTO_STATUS_FILE, f"{utc_now_text()}: остановлена - {reason}")
    telegram_notify(
        "AWG ENTRY: автоматическая перезагрузка каскада остановлена\n"
        f"{reason}\n"
        "Остальные серверы не перезагружались. Возобновить после устранения причины: "
        "cascade-reboot auto on"
    )
    print(f"Автоматическая перезагрузка остановлена: {reason}")


def execute_auto_reboot(
    repo: Path, hosts_path: Path, vault_password: Path, groups: tuple[str, ...]
) -> None:
    """Перезагрузить серверы по одному; остановиться на первой неудаче."""
    write_auto_state(AUTO_LAST_FILE, str(int(time.time())))
    done: list[str] = []
    for group in groups:
        name = SERVER_NAMES.get(group, group)
        problems = guard_blockers(
            run_reboot_guard(repo, hosts_path, vault_password, group, "prepare"), automatic=True
        )
        if problems:
            # Сервер ещё не тронут: это отсрочка, а не неудача перезагрузки.
            reason = f"{name}: подготовка не пройдена - {'; '.join(problems)}"
            write_auto_state(AUTO_STATUS_FILE, f"{utc_now_text()}: отложена - {reason}")
            telegram_notify(
                "AWG ENTRY: автоматическая перезагрузка каскада отложена\n"
                f"{reason}\n"
                + (f"Перезагружены: {', '.join(done)}." if done else "Ни один сервер не перезагружался.")
            )
            print(f"Автоматическая перезагрузка отложена: {reason}")
            return
        if group == "entry":
            write_auto_state(AUTO_PENDING_FILE, utc_now_text())
            print("ENTRY перезагрузится через 15 секунд; итог придёт после проверки каскада.")
            schedule_entry_reboot()
            return
        boot_before = read_boot_id(repo, hosts_path, vault_password, group)
        if boot_before is None:
            block_auto_reboot(f"{name} перестал отвечать перед перезагрузкой")
            return
        if not schedule_host_reboot(repo, hosts_path, vault_password, group):
            block_auto_reboot(f"не удалось запланировать перезагрузку {name}")
            return
        if not wait_for_host_reboot(repo, hosts_path, vault_password, group, boot_before):
            block_auto_reboot(f"{name} не вернулся после перезагрузки")
            return
        if not wait_for_cascade():
            block_auto_reboot(f"после перезагрузки {name} каскад не прошёл проверку: cascade-check")
            return
        done.append(name)
    write_auto_state(AUTO_STATUS_FILE, f"{utc_now_text()}: выполнена ({', '.join(done)}), каскад исправен")
    telegram_notify(
        f"AWG ENTRY: автоматическая перезагрузка каскада завершена ({', '.join(done)}); каскад исправен"
    )


def run_cascade_weekly(repo: Path, production: Path, vault_password: Path) -> None:
    """Еженедельное окно ENTRY: сводка в Telegram и перезагрузка, если она нужна."""
    hosts_path = production / "hosts.yml"
    vault_path = production / "group_vars" / "all" / "vault.yml"
    if not hosts_path.is_file() or not vault_path.is_file() or not vault_password.is_file():
        fail("Не найден production inventory или внешний пароль Ansible Vault")
    plan = cascade_reboot_plan(load_yaml(hosts_path))
    settings = auto_reboot_settings(production)
    _code, rows = read_confirmed_cascade_rows()
    try:
        decision = decide_auto_reboot(repo, hosts_path, vault_password, plan, settings, rows)
    except SystemExit as error:
        decision = AutoRebootDecision("deferred", f"проверка серверов прервана: {error}")
    print(f"Перезагрузка: {decision.line()}")
    if decision.action != "blocked":
        write_auto_state(AUTO_STATUS_FILE, f"{utc_now_text()}: {decision.line()}")
    telegram_notify(weekly_digest(rows, decision.line()))
    if decision.action != "reboot":
        return
    try:
        execute_auto_reboot(repo, hosts_path, vault_password, decision.groups)
    except SystemExit as error:
        # Прервано посреди перезагрузки: состояние неизвестно, повторять нельзя.
        block_auto_reboot(f"перезагрузка прервана: {error}")


def set_auto_reboot(enabled: bool) -> None:
    """cascade-reboot auto on|off: включить автоматику (и снять остановку) или выключить."""
    CASCADE_VERIFY_DIR.mkdir(parents=True, exist_ok=True)
    if enabled:
        AUTO_OFF_FILE.unlink(missing_ok=True)
        AUTO_BLOCK_FILE.unlink(missing_ok=True)
        write_auto_state(AUTO_STATUS_FILE, f"{utc_now_text()}: включена командой cascade-reboot auto on")
        print("Автоматическая перезагрузка каскада включена. Состояние: cascade-reboot status")
    else:
        write_auto_state(AUTO_OFF_FILE, utc_now_text())
        print("Автоматическая перезагрузка каскада выключена. Включить: cascade-reboot auto on")


def auto_reboot_status_lines(production: Path) -> list[str]:
    settings = auto_reboot_settings(production)
    if not settings.enabled:
        state = "выключена в настройках каскада (awg_auto_reboot_enabled: false)"
    elif AUTO_OFF_FILE.exists():
        state = "выключена командой cascade-reboot auto off; включить: cascade-reboot auto on"
    elif AUTO_BLOCK_FILE.exists():
        reason = AUTO_BLOCK_FILE.read_text(encoding="utf-8").strip()
        state = f"остановлена после неудачи - {reason}; возобновить: cascade-reboot auto on"
    else:
        state = "включена"
    lines = [f"Автоматическая перезагрузка: {state}"]
    if AUTO_STATUS_FILE.is_file():
        lines.append(f"Последнее решение: {AUTO_STATUS_FILE.read_text(encoding='utf-8').strip()}")
    window = timer_property("NextElapseUSecRealtime")
    if window:
        # Время показано в часовом поясе сервера, расписание - в поясе ночного
        # обслуживания: «воскресенье 03:50 Asia/Manila» - это ещё суббота по UTC.
        schedule = re.search(r"OnCalendar=(.*?)\s*;", timer_property("TimersCalendar"))
        lines.append(
            f"Следующее еженедельное окно: {window}"
            + (f" (расписание: {schedule.group(1)})" if schedule else "")
        )
    return lines


def timer_property(name: str) -> str:
    try:
        return subprocess.run(
            ["systemctl", "show", WEEKLY_TIMER, "-p", name, "--value"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
    except OSError:
        return ""


def last_verify_lines(report: Path) -> list[str]:
    """Итог проверки после последней перезагрузки ENTRY в несколько строк.

    Раньше команда печатала отчёт cascade-check целиком: сотни строк, за которыми
    не было видно состояния автоматики.
    """
    text = report.read_text(encoding="utf-8")
    when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(report.stat().st_mtime))
    code = re.search(r"^rc=(\d+)\s*$", text, flags=re.MULTILINE)
    if code is None:
        verdict = "итог не записан"
    elif code.group(1) == "0":
        verdict = "каскад исправен"
    elif code.group(1) == "3":
        verdict = "каскад работает, есть замечания"
    else:
        verdict = "каскад не прошёл проверку"
    lines = [f"Проверка после последней перезагрузки ENTRY ({when}): {verdict}"]
    lines += [f"  {problem}" for problem in cascade_problems(text)[:12]]
    lines.append(f"Полный отчёт: sudo cat {report}")
    return lines


def cascade_reboot_status(production: Path | None = None) -> None:
    if production is not None:
        for line in auto_reboot_status_lines(production):
            print(line)
    report = CASCADE_VERIFY_DIR / "last-verify.txt"
    if not report.is_file():
        # Модуль проверки включён от перезагрузки ENTRY до записи результата.
        pending = subprocess.run(
            ["systemctl", "is-enabled", "--quiet", f"{CASCADE_VERIFY_UNIT}.service"], check=False
        )
        if pending.returncode == 0:
            print("Проверка после перезагрузки ENTRY ещё идёт: повторите cascade-reboot status через несколько минут.")
        else:
            print("Проверки после перезагрузки ENTRY нет: каскад ещё не перезагружался командой cascade-reboot.")
        return
    for line in last_verify_lines(report):
        print(line)


# Резервная копия контроллера. ENTRY - единственное место, где лежат inventory,
# пароль Vault, ключ оркестратора и состояние клиентов: после потери сервера
# каскад пришлось бы ставить заново и перевыпускать всех клиентов. Зашифрованная
# копия хранится на EXIT и FRONT; ключ восстановления знают ENTRY и владелец.
CONTROLLER_BACKUP_DIR = Path("/var/lib/kalimera/controller-backup")
CONTROLLER_BACKUP_NAME = "controller.kbk"
CONTROLLER_BACKUP_STATUS = CONTROLLER_BACKUP_DIR / "status"
# Ключ лежит в каталоге, который целиком входит в зашифрованное хранилище
# секретов ENTRY: на диске в открытом виде его нет.
CONTROLLER_BACKUP_KEY = Path("/etc/awg/controller-backup.key")
CONTROLLER_BACKUP_PEERS = ("exit", "front")
# Неизменившаяся копия отправляется заново раз в столько секунд: так обнаруживается
# сервер, на котором файл пропал.
CONTROLLER_BACKUP_REFRESH_SECONDS = 6 * 86400
# Файл для отправки на серверы собирается в tmpfs и удаляется сразу после отправки.
CONTROLLER_BACKUP_STAGING_DIR = Path("/run")
CONTROLLER_BACKUP_PUSH_TIMEOUT_SECONDS = 300
RUNTIME_SECRETS_CONFIG = Path("/etc/kalimera-secrets/config.json")
SECRETCTL_PATH = Path("/usr/local/sbin/kalimera-secretctl")


def local_controller(hosts_document: dict) -> bool:
    """ENTRY сам управляет каскадом: установщик работает на нём."""
    hosts = hosts_document.get("all", {}).get("children", {}).get("entry", {}).get("hosts", {})
    return any(
        isinstance(values, dict) and values.get("ansible_connection") == "local"
        for values in hosts.values()
    )


def read_runtime_secrets_config() -> dict | None:
    try:
        config = json.loads(RUNTIME_SECRETS_CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return config if isinstance(config, dict) else None


def controller_recovery_key(*, create: bool) -> bytes | None:
    """Ключ восстановления из хранилища секретов ENTRY; create - создать, если его нет."""
    try:
        return controller_backup.parse_recovery_key(CONTROLLER_BACKUP_KEY.read_text(encoding="ascii"))
    except controller_backup.BackupError:
        fail(
            f"Ключ восстановления в {CONTROLLER_BACKUP_KEY} повреждён. Удалите файл: "
            "следующая копия создаст новый ключ, и его нужно будет сохранить заново"
        )
    except (OSError, UnicodeError):
        pass
    if not create:
        return None
    if not CONTROLLER_BACKUP_KEY.parent.is_dir():
        fail(f"Каталог {CONTROLLER_BACKUP_KEY.parent} отсутствует: сначала выполните kalimera-deploy --resume")
    key = controller_backup.new_recovery_key()
    secure_write(CONTROLLER_BACKUP_KEY, (controller_backup.format_recovery_key(key) + "\n").encode("ascii"))
    # Каталог лежит в tmpfs. Без сохранения пакета ключ пропал бы при перезагрузке
    # ENTRY, а копии, зашифрованные им, стало бы нечем открыть.
    sealed = subprocess.run([str(SECRETCTL_PATH), "seal"], check=False, capture_output=True, text=True)
    if sealed.returncode != 0:
        CONTROLLER_BACKUP_KEY.unlink(missing_ok=True)
        fail(
            "Новый ключ восстановления не сохранён в зашифрованный пакет: второй сервер "
            "не отдал долю ключа. Повторите, когда каскад будет на связи"
        )
    print(
        "Создан ключ восстановления контроллера. Покажите его командой "
        "'controller-backup key' и сохраните вне серверов каскада: без него копию не открыть."
    )
    return key


def controller_backup_sources(
    production: Path, state_root: Path, runtime_root: Path, ssh_private_key: Path
) -> list[controller_backup.Source]:
    sources = [controller_backup.Source(production, controller_backup.INVENTORY_DIR)]
    for child in sorted(runtime_root.iterdir()):
        if child.name != ".unlocked":
            sources.append(
                controller_backup.Source(child, f"{controller_backup.RUNTIME_DIR}/{child.name}")
            )
    if state_root.is_dir():
        for child in sorted(state_root.iterdir()):
            # Каталог клиентов на управляющем ENTRY - ссылка в хранилище секретов:
            # он уже вошёл в копию оттуда.
            if child.is_symlink() or child.name.startswith("."):
                continue
            sources.append(
                controller_backup.Source(child, f"{controller_backup.STATE_DIR}/{child.name}")
            )
    public_key = ssh_private_key.with_name(ssh_private_key.name + ".pub")
    if public_key.is_file() and not public_key.is_symlink():
        sources.append(
            controller_backup.Source(public_key, f"{controller_backup.SSH_DIR}/{public_key.name}")
        )
    return sources


CONTROLLER_BACKUP_STATUS_FIELDS = ("epoch", "time", "digest", "stored", "failed", "pushed")


def read_controller_backup_status() -> dict[str, str]:
    """Итог последней копии: когда проверена, что в ней, где сохранена."""
    try:
        fields = CONTROLLER_BACKUP_STATUS.read_text(encoding="utf-8").splitlines()[0].split("\t")
    except (OSError, IndexError):
        return {}
    if len(fields) != len(CONTROLLER_BACKUP_STATUS_FIELDS):
        return {}
    return dict(zip(CONTROLLER_BACKUP_STATUS_FIELDS, fields))


def write_controller_backup_status(
    digest: str, stored: list[str], failed: list[str], pushed: int
) -> None:
    CONTROLLER_BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    line = "\t".join(
        (str(int(time.time())), utc_now_text(), digest, ",".join(stored), ",".join(failed), str(pushed))
    )
    temporary = CONTROLLER_BACKUP_STATUS.with_name(f".{CONTROLLER_BACKUP_STATUS.name}.tmp")
    temporary.write_text(line + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, CONTROLLER_BACKUP_STATUS)


def push_controller_backup(
    repo: Path, hosts_path: Path, vault_password: Path, document: bytes, groups: list[str]
) -> tuple[list[str], list[str]]:
    """Сохранить файл копии на серверах; возвращает (где сохранён, где нет)."""
    stored: list[str] = []
    failed: list[str] = []
    staging = CONTROLLER_BACKUP_STAGING_DIR / f"kalimera-controller-backup.{secrets.token_hex(6)}"
    secure_write(staging, document)
    try:
        for group in groups:
            result = ansible_adhoc(
                repo,
                hosts_path,
                vault_password,
                group,
                "ansible.builtin.copy",
                f"src={staging} dest={CONTROLLER_BACKUP_DIR / CONTROLLER_BACKUP_NAME} "
                "owner=root group=root mode=0600",
                become=True,
                # Файл в несколько мегабайт по каналу за границу идёт дольше команды.
                timeout=CONTROLLER_BACKUP_PUSH_TIMEOUT_SECONDS,
            )
            if result is not None and result.returncode == 0:
                stored.append(group)
            else:
                failed.append(group)
    finally:
        staging.unlink(missing_ok=True)
    return stored, failed


def run_controller_backup(
    repo: Path, production: Path, vault_password: Path, *, force: bool = False
) -> bool:
    """Создать копию состояния контроллера и сохранить её на EXIT и FRONT."""
    hosts_path = production / "hosts.yml"
    hosts_document = load_yaml(hosts_path)
    if not local_controller(hosts_document):
        print(
            "Резервная копия контроллера создаётся, когда ENTRY сам управляет каскадом. "
            "Здесь управляющий компьютер отдельный: сохраните каталог inventory/production "
            "и пароль Ansible Vault сами."
        )
        return False
    config = read_runtime_secrets_config()
    if config is None:
        print("Хранилище секретов на ENTRY не настроено: резервная копия контроллера не создаётся.")
        return False
    runtime_root = Path(str(config.get("runtime_root", "")))
    cluster_id = str(config.get("cluster_id", ""))
    if not (runtime_root / ".unlocked").is_file():
        fail(
            "Хранилище секретов ENTRY закрыто: копировать нечего. "
            "Состояние: sudo kalimera-secretctl status"
        )
    children = hosts_document["all"]["children"]
    groups = [group for group in CONTROLLER_BACKUP_PEERS if children.get(group, {}).get("hosts")]
    key = controller_recovery_key(create=True)
    assert key is not None
    state_root = Path.home() / ".local" / "share" / "awg-iac" / "production"
    ssh_private_key = Path.home() / ".ssh" / "awg-iac-production"
    release = (repo / "VERSION").read_text(encoding="utf-8").strip()
    created = utc_now_text()
    manifest = {
        "created": created,
        "created_epoch": int(time.time()),
        "release": release,
        "cluster_id": cluster_id,
        "hostname": socket.gethostname(),
        "mappings": [
            {"source": str(mapping["source"]), "target": str(mapping["target"])}
            for mapping in config.get("mappings", [])
            if isinstance(mapping, dict) and mapping.get("source") and mapping.get("target")
        ],
    }
    try:
        plaintext, digest = controller_backup.build_archive(
            manifest,
            controller_backup_sources(production, state_root, runtime_root, ssh_private_key),
        )
    except (controller_backup.BackupError, OSError) as error:
        fail(f"Резервная копия контроллера не собрана: {error}")
    previous = read_controller_backup_status()
    now = int(time.time())
    unchanged = (
        previous.get("digest") == digest
        and not previous.get("failed")
        and set(filter(None, previous.get("stored", "").split(","))) == set(groups)
        and previous.get("pushed", "").isdigit()
        and now - int(previous["pushed"]) < CONTROLLER_BACKUP_REFRESH_SECONDS
    )
    if unchanged and not force:
        write_controller_backup_status(digest, groups, [], int(previous["pushed"]))
        print("Резервная копия контроллера актуальна: состояние не менялось.")
        return True
    document = controller_backup.encrypt(plaintext, key, cluster_id, created, release)
    stored, failed = push_controller_backup(repo, hosts_path, vault_password, document, groups)
    write_controller_backup_status(digest, stored, failed, now if stored else 0)
    names = lambda items: ", ".join(item.upper() for item in items)  # noqa: E731
    if stored:
        print(f"Резервная копия контроллера сохранена: {names(stored)}.")
    if failed:
        print(
            f"Резервная копия контроллера не сохранена: {names(failed)}. "
            "Проверьте связь с сервером и повторите: controller-backup"
        )
    return bool(stored) and not failed


def show_controller_backup_key() -> None:
    """Показать ключ восстановления владельцу: без него копия бесполезна."""
    key = controller_recovery_key(create=True)
    assert key is not None
    print("Ключ восстановления контроллера:")
    print()
    print(f"  {controller_backup.format_recovery_key(key)}")
    print()
    print(
        "Сохраните его вне серверов каскада, например в менеджере паролей. Копия "
        "состояния контроллера лежит на EXIT и FRONT зашифрованной этим ключом; после "
        "потери ENTRY каскад восстанавливается командой ./deploy --restore-entry ФАЙЛ "
        "на новом сервере, и она спросит этот ключ. Без ключа копию не открыть никому."
    )


def restore_entry(
    repo: Path, production: Path, vault_password: Path, capsule: Path, key_file: Path | None
) -> None:
    """Разложить состояние контроллера из копии на новом ENTRY."""
    if os.geteuid() != 0:
        fail("Восстановление ENTRY выполняется от root на новом сервере")
    if production.exists():
        fail(
            "inventory/production уже существует: восстановление выполняется на чистом "
            "сервере. Если состояние уже восстановлено, продолжайте './deploy --resume'"
        )
    try:
        document = capsule.read_bytes()
    except OSError as error:
        fail(f"Файл копии не читается: {error}")
    state_root = Path.home() / ".local" / "share" / "awg-iac" / "production"
    ssh_private_key = Path.home() / ".ssh" / "awg-iac-production"
    # Распаковка идёт в tmpfs: на диск попадает только уже разложенное состояние.
    work = Path(tempfile.mkdtemp(prefix="kalimera-restore.", dir=str(CONTROLLER_BACKUP_STAGING_DIR)))
    try:
        header = controller_backup.read_header(document)
        print(
            f"Копия контроллера от {header.get('created', '?')}, "
            f"выпуск KalimeraWG {header.get('release', '?')}."
        )
        if key_file is not None:
            key_text = key_file.read_text(encoding="utf-8")
        else:
            key_text = getpass.getpass("Ключ восстановления (ввод не отображается): ")
        plaintext = controller_backup.decrypt(document, controller_backup.parse_recovery_key(key_text))
        manifest = controller_backup.extract(plaintext, work / "content")
        release = (repo / "VERSION").read_text(encoding="utf-8").strip()
        if str(manifest.get("release", "")) != release:
            print(
                f"Копия создана выпуском {manifest.get('release', '?')}, а здесь выпуск {release}. "
                "Надёжнее восстанавливать тем же выпуском: git switch --detach vВЕРСИЯ."
            )
            if not prompt_bool("Продолжить этим выпуском", False):
                fail("Восстановление остановлено: состояние сервера не менялось")
        restored = controller_backup.restore_layout(
            work / "content",
            manifest,
            controller_backup.RestorePaths(production, vault_password, ssh_private_key, state_root),
        )
    except (controller_backup.BackupError, OSError) as error:
        fail(f"Восстановление не выполнено: {error}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("Восстановлено из копии: " + ", ".join(restored) + ".")


def require_restored_access(hosts_document: dict) -> None:
    """После восстановления: EXIT и FRONT должны принимать ключ оркестратора отсюда."""
    refused: list[str] = []
    children = hosts_document["all"]["children"]
    for group in ("exit", "front"):
        for name, variables in children.get(group, {}).get("hosts", {}).items():
            if not ssh_connection_works(
                str(variables["ansible_host"]),
                str(variables["ansible_user"]),
                int(variables["ansible_port"]),
                Path(str(variables["ansible_ssh_private_key_file"])),
            ):
                refused.append(f"{name} ({variables['ansible_host']})")
    if refused:
        fail(
            "Серверы не принимают ключ оркестратора с этого сервера: "
            + ", ".join(refused)
            + ".\nEXIT и FRONT разрешают его только с прежнего публичного адреса ENTRY. "
            "Назначьте новому серверу прежний адрес (зарезервированный IP в панели "
            "облака) и выполните './deploy --resume'. Состояние контроллера уже "
            "восстановлено: повторять --restore-entry не нужно."
        )


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
        "--enable-standby-exit",
        action="store_true",
        help=(
            "при --resume подключить резервный EXIT: второй зарубежный сервер, на который "
            "ENTRY сам переводит трафик при отказе основного; интерактивно запросит "
            "данные подключения, клиентские конфиги не меняются"
        ),
    )
    parser.add_argument(
        "--disable-standby-exit",
        action="store_true",
        help=(
            "при --resume отключить резервный EXIT: каскад возвращается к одному "
            "зарубежному серверу; сам отключённый сервер не изменяется"
        ),
    )
    parser.add_argument(
        "--enable-ru-proxy",
        action="store_true",
        help=(
            "при --resume включить RU-прокси (SOCKS5) на установленном каскаде или "
            "заменить его параметры; клиентские конфиги не меняются"
        ),
    )
    parser.add_argument(
        "--disable-ru-proxy",
        action="store_true",
        help="при --resume выключить RU-прокси: российский трафик выходит напрямую с ENTRY",
    )
    parser.add_argument(
        "--enable-telegram",
        action="store_true",
        help="при --resume включить Telegram-уведомления или заменить бота",
    )
    parser.add_argument(
        "--disable-telegram",
        action="store_true",
        help="при --resume выключить Telegram-уведомления и удалить токен из Vault",
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
    parser.add_argument(
        "--update-amneziawg",
        action="store_true",
        help=(
            "при --resume транзакционно обновить только пакеты AmneziaWG на "
            "ENTRY и EXIT; клиентские конфиги не меняются"
        ),
    )
    parser.add_argument(
        "--update-xray",
        action="store_true",
        help=(
            "при --resume установить на FRONT последний стабильный выпуск "
            "Xray-core с проверкой через CDN и автоматическим откатом"
        ),
    )
    parser.add_argument(
        "--rotate-front-disguise",
        action="store_true",
        help=(
            "при --resume заменить имена маскировки XHTTP на FRONT собственным "
            "случайным набором; все VLESS-профили нужно выпустить заново"
        ),
    )
    parser.add_argument(
        "--maintenance-time",
        metavar="ЧЧ:ММ",
        help="время ночного обслуживания в часовом поясе --maintenance-zone; применяется обычным --resume",
    )
    parser.add_argument(
        "--maintenance-zone", metavar="ЗОНА", help="часовой пояс, например Asia/Manila"
    )
    parser.add_argument(
        "--maintenance-show", action="store_true", help="показать время ночного обслуживания"
    )
    parser.add_argument(
        "--cascade-reboot",
        action="store_true",
        help="перезагрузить FRONT, EXIT и ENTRY по очереди с проверкой каскада",
    )
    parser.add_argument(
        "--cascade-reboot-status",
        action="store_true",
        help="показать результат проверки после перезагрузки ENTRY",
    )
    parser.add_argument(
        "--cascade-reboot-auto",
        choices=("on", "off"),
        help="включить автоматическую перезагрузку каскада (и снять остановку после неудачи) или выключить",
    )
    parser.add_argument(
        "--cascade-weekly",
        action="store_true",
        help="еженедельное окно: сводка в Telegram и автоматическая перезагрузка, если она нужна",
    )
    parser.add_argument(
        "--yes", action="store_true", help="подтвердить перезагрузку для --cascade-reboot"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="продолжать перезагрузку, даже если проверка после шага нашла ошибки (ошибки выводятся)",
    )
    parser.add_argument(
        "--controller-backup",
        action="store_true",
        help="создать зашифрованную копию состояния контроллера и сохранить её на EXIT и FRONT",
    )
    parser.add_argument(
        "--controller-backup-key",
        action="store_true",
        help="показать ключ восстановления контроллера",
    )
    parser.add_argument(
        "--restore-entry",
        metavar="ФАЙЛ",
        type=Path,
        help="на новом сервере: восстановить ENTRY из копии состояния контроллера",
    )
    parser.add_argument(
        "--recovery-key-file",
        metavar="ФАЙЛ",
        type=Path,
        help="файл с ключом восстановления для --restore-entry; без него ключ запрашивается",
    )
    args = parser.parse_args()
    update_flags = [
        name
        for name, value in (
            ("--update-components", args.update_components),
            ("--update-amneziawg", args.update_amneziawg),
            ("--update-xray", args.update_xray),
            ("--rotate-front-disguise", args.rotate_front_disguise),
        )
        if value
    ]
    if update_flags and not args.resume:
        parser.error(f"{update_flags[0]} используется только вместе с --resume")
    if len(update_flags) > 1:
        parser.error("выберите только одно обновление за запуск")
    if (args.update_amneziawg or args.update_xray or args.rotate_front_disguise) and any(
        (
            args.enable_front,
            args.replace_front,
            args.commit_front_replacement,
            args.rollback_front_replacement,
        )
    ):
        parser.error(f"{update_flags[0]} нельзя объединять с операциями FRONT")
    feature_flags = [
        name
        for name, value in (
            ("--enable-ru-proxy", args.enable_ru_proxy),
            ("--disable-ru-proxy", args.disable_ru_proxy),
            ("--enable-telegram", args.enable_telegram),
            ("--disable-telegram", args.disable_telegram),
        )
        if value
    ]
    if feature_flags and not args.resume:
        parser.error(f"{feature_flags[0]} используется только вместе с --resume")
    if args.enable_ru_proxy and args.disable_ru_proxy:
        parser.error("--enable-ru-proxy и --disable-ru-proxy нельзя указывать вместе")
    if args.enable_telegram and args.disable_telegram:
        parser.error("--enable-telegram и --disable-telegram нельзя указывать вместе")
    if feature_flags and (
        update_flags
        or args.enable_front
        or args.replace_front
        or args.commit_front_replacement
        or args.rollback_front_replacement
    ):
        parser.error(
            f"{feature_flags[0]} нельзя объединять с обновлениями компонентов и операциями FRONT"
        )
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
        or update_flags
        or feature_flags
    ):
        parser.error("--terminal-only нельзя объединять с другими режимами deploy")
    repo = args.repo_root.resolve()
    production = repo / "inventory" / "production"
    state_root = Path.home() / ".local" / "share" / "awg-iac" / "production"
    mtu_result = state_root / "mtu.yml"
    awg_package_lock = state_root / "amneziawg-package-lock.txt"
    vault_password = Path.home() / ".config" / "awg-iac" / "production-vault.pass"
    maintenance_requested = bool(args.maintenance_time or args.maintenance_zone)
    reboot_requested = bool(args.cascade_reboot or args.cascade_reboot_status)
    service_commands = [
        maintenance_requested,
        args.maintenance_show,
        args.cascade_reboot,
        args.cascade_reboot_status,
        args.cascade_reboot_auto,
        args.cascade_weekly,
        args.controller_backup,
        args.controller_backup_key,
    ]
    if args.recovery_key_file and not args.restore_entry:
        parser.error("--recovery-key-file используется только вместе с --restore-entry")
    if args.restore_entry and (
        any(service_commands)
        or args.resume
        or args.summary
        or args.terminal_only
        or update_flags
        or feature_flags
        or args.enable_mobile
        or args.enable_front
        or args.replace_front
        or args.commit_front_replacement
        or args.rollback_front_replacement
    ):
        parser.error("--restore-entry выполняется отдельно, на новом сервере")
    if args.yes and not args.cascade_reboot:
        parser.error("--yes используется только вместе с --cascade-reboot")
    if args.force and not (args.cascade_reboot and args.yes):
        parser.error("--force используется только вместе с --cascade-reboot --yes")
    if maintenance_requested and not (args.maintenance_time and args.maintenance_zone):
        parser.error("--maintenance-time и --maintenance-zone указываются вместе")
    if sum(bool(value) for value in service_commands) > 1:
        parser.error("выберите одну команду обслуживания за запуск")
    if any(service_commands) and (
        args.resume
        or args.summary
        or args.terminal_only
        or update_flags
        or feature_flags
        or args.enable_mobile
        or args.enable_front
        or args.replace_front
        or args.commit_front_replacement
        or args.rollback_front_replacement
    ):
        parser.error("команды обслуживания нельзя объединять с другими режимами deploy")
    if (args.enable_standby_exit or args.disable_standby_exit) and (
        not args.resume
        or (args.enable_standby_exit and args.disable_standby_exit)
        or any(service_commands)
        or args.summary
        or args.terminal_only
        or args.restore_entry
        or update_flags
        or feature_flags
        or args.enable_mobile
        or args.enable_front
        or args.replace_front
        or args.commit_front_replacement
        or args.rollback_front_replacement
    ):
        parser.error(
            "--enable-standby-exit и --disable-standby-exit выполняются отдельным запуском: "
            "kalimera-deploy --resume --enable-standby-exit"
        )
    if any(service_commands) and not (production / "hosts.yml").is_file():
        fail("Не найден production inventory; сначала выполните установку")
    if args.maintenance_show:
        print(f"Время ночного обслуживания: {maintenance_show(production)}")
        return
    if maintenance_requested:
        calendar = maintenance_calendar(args.maintenance_time, args.maintenance_zone)
        previous = set_maintenance_calendar(production, calendar)
        print(f"Время ночного обслуживания: {previous} → {calendar}")
        print("Применяю обычный деплой, чтобы таймер получил новое время...")
        args.resume = True
    if args.cascade_reboot:
        run_cascade_reboot(
            repo, production, vault_password, confirmed=args.yes, force=args.force
        )
        return
    if args.cascade_reboot_status:
        cascade_reboot_status(production)
        return
    if args.cascade_reboot_auto:
        set_auto_reboot(args.cascade_reboot_auto == "on")
        return
    if args.cascade_weekly:
        run_cascade_weekly(repo, production, vault_password)
        return
    if args.controller_backup:
        if not run_controller_backup(repo, production, vault_password):
            raise SystemExit(1)
        return
    if args.controller_backup_key:
        show_controller_backup_key()
        return
    restoring = False
    if args.restore_entry:
        restore_entry(repo, production, vault_password, args.restore_entry, args.recovery_key_file)
        print("Применяю восстановленную конфигурацию к новому ENTRY...")
        args.resume = True
        restoring = True
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
        repair_standby_exit_inventory(production)
        drop_stale_xray_override(repo, production)
        if args.update_components or args.update_amneziawg:
            require_amneziawg_ppa(repo)
        xray_release: dict[str, object] | None = None
        if args.update_xray:
            xray_release = newer_xray_release(repo, production)
            if xray_release is None:
                print(
                    "Xray-core на FRONT уже последней стабильной версии; "
                    "обновлять нечего."
                )
                return
            print(
                f"Будет установлен Xray-core {xray_release['front_xray_version']} "
                f"вместо {xray_release['previous_version']}."
            )
        if args.rotate_front_disguise:
            if not (production / "group_vars" / "front.yml").is_file():
                fail("FRONT не установлен: менять маскировку XHTTP негде")
            print(
                "Имена маскировки XHTTP на FRONT будут заменены. Все выданные "
                "VLESS-профили этого каскада перестанут подключаться, пока их не "
                "выпустят заново командой 'vless-user export ИМЯ' (и 'vless-user "
                "auto' для профилей с резервом)."
            )
            if not prompt_bool("Продолжить", False):
                print("Маскировка не изменена.")
                return
        ensure_mobile_awg3_vault_material(production, vault_password)
        if args.rollback_front_replacement:
            rollback_front_replacement(production)
        if args.enable_front:
            enable_front_profile(production, vault_password)
        if args.enable_standby_exit:
            enable_standby_exit(production, vault_password)
        if args.disable_standby_exit:
            disable_standby_exit(production, vault_password)
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
        # Дополнительные функции включаются на работающем каскаде: меняются только
        # inventory и Vault, а серверы настраивает обычный прогон ниже. Ключи и
        # клиентские конфиги при этом не пересоздаются.
        if args.enable_ru_proxy:
            enable_ru_proxy(production, vault_password)
        if args.disable_ru_proxy:
            disable_ru_proxy(production)
        if args.enable_telegram:
            enable_telegram_monitor(production, vault_password)
        if args.disable_telegram:
            disable_telegram_monitor(production, vault_password)
        update_saved_client_configs_cps(state_root / "clients")
        # Обновление пакетов AmneziaWG: полный набор компонентов или только сами
        # пакеты. В обоих случаях нужна транзакция пакетов с откатом.
        package_update = args.update_components or args.update_amneziawg
        transactional = package_update or args.update_xray or args.rotate_front_disguise
        all_vars = load_yaml(all_vars_path)
        if (
            all_vars.get("awg_package_version_mode") == "candidate"
            and awg_package_lock.is_file()
            and not package_update
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
        if restoring:
            require_restored_access(hosts_document)
        recover_saved_admin_access(
            hosts_document,
            hosts_path,
            str(all_vars.get("security_admin_user", "kalimera")),
            bool(all_vars.get("security_finalize_admin_access", False)),
        )
        verify_saved_inventory_access(hosts_document)
        refresh_saved_automation_sources(hosts_document, hosts_path)
        if transactional:
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
        if awg_package_lock.is_file() and not package_update:
            pin_resolved_awg_packages(all_vars_path, awg_package_lock)
        component_backup: dict[Path, bytes | None] = {}
        if package_update:
            entry_vars_path = production / "group_vars" / "entry.yml"
            exit_vars_path = production / "group_vars" / "exit.yml"
            for path in (all_vars_path, entry_vars_path, exit_vars_path, awg_package_lock):
                component_backup[path] = path.read_bytes() if path.is_file() else None
            if args.update_components:
                prepare_component_update(repo, production)
            else:
                prepare_amneziawg_update(production)
        if xray_release is not None:
            front_vars_path = production / "group_vars" / "front.yml"
            component_backup[front_vars_path] = front_vars_path.read_bytes()
            apply_xray_release(production, xray_release)
        if args.rotate_front_disguise:
            front_vars_path = production / "group_vars" / "front.yml"
            component_backup[front_vars_path] = front_vars_path.read_bytes()
            prepare_front_disguise_rotation(repo, production)
        final_variables = {
            "awg_enable_fail2ban": True,
            "awg_health_run_during_deploy": False,
            "awg_telegram_monitor_start_immediately": False,
            "awg_mtu_controller_result_path": str(mtu_result),
            "awg_package_controller_lock_path": str(awg_package_lock),
        }
        if package_update:
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
            if not transactional:
                raise
            if package_update:
                rollback_target = "ENTRY и EXIT..."
            elif args.rotate_front_disguise:
                rollback_target = "прежней маскировки XHTTP на FRONT..."
            else:
                rollback_target = "Xray-core на FRONT..."
            print(
                "Обновление не прошло проверку. Выполняется автоматический откат "
                + rollback_target
            )
            for path, content in component_backup.items():
                restore_file(path, content)
            rollback_variables = dict(final_variables)
            if package_update:
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
                if args.rotate_front_disguise:
                    fail(
                        "Смена маскировки XHTTP и автоматический откат завершились "
                        "ошибкой. Прежние имена возвращены в inventory; повторите "
                        "'kalimera-deploy --resume'"
                    )
                if not package_update:
                    fail(
                        "Обновление Xray-core и автоматический откат завершились "
                        "ошибкой. Прежняя версия возвращена в inventory; повторите "
                        "'kalimera-deploy --resume'"
                    )
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
        seal_local_controller_state(production)
        cleanup_deployment(repo, hosts_path, vault_password)
        atexit.unregister(cleanup_callback)
        # Копия состояния контроллера обновляется после каждого применения. Её
        # неудача не отменяет успешный deploy: о ней сообщит cascade-check.
        try:
            run_controller_backup(repo, production, vault_password)
        except SystemExit as backup_error:
            print(f"Резервная копия контроллера не обновлена: {backup_error}")
        if args.rollback_front_replacement:
            (_front_replacement_state_root() / "current.json").unlink(missing_ok=True)
            print("Откат FRONT применён и проверен; маркер восстановления удалён.")
        if args.update_components:
            print("Компоненты каскада обновлены транзакционно и успешно проверены.")
        elif args.update_amneziawg:
            print(
                "Пакеты AmneziaWG на ENTRY и EXIT обновлены и проверены; "
                "клиентские конфиги не изменились."
            )
        elif xray_release is not None:
            print(
                f"Xray-core {xray_release['front_xray_version']} установлен на FRONT "
                "и проверен через CDN; клиентские профили не изменились."
            )
        elif args.rotate_front_disguise:
            print(
                "Маскировка XHTTP на FRONT заменена и проверена через CDN. Выпустите "
                "заново все VLESS-профили этого каскада на FRONT: 'vless-user list', "
                "затем 'vless-user export ИМЯ' для каждого; профили с резервом - "
                "'vless-user auto ИМЯ ФАЙЛ_РЕЗЕРВА'. Старые профили больше не "
                "подключаются."
            )
        elif args.replace_front:
            print(
                "Новый FRONT применён. Для каждого direct-пользователя повторно "
                "выполните 'vless-user export ИМЯ' на новом FRONT и импортируйте "
                "JSON с новым origin-доменом. Затем проверьте direct/CDN VLESS-сессию, "
                "переключите CDN origin и выполните "
                "'kalimera-deploy --resume --commit-front-replacement'."
            )
        elif (
            args.enable_ru_proxy
            or args.disable_ru_proxy
            or args.enable_telegram
            or args.disable_telegram
        ):
            # Итог называет то, что изменилось: общее "повторно применена" не говорило,
            # включилась ли функция.
            if args.enable_ru_proxy:
                print(
                    "RU-прокси включён, каскад проверен. Состояние: ru-proxy status; "
                    "адреса для прокси: proxy-domain add ДОМЕН, proxy-address add АДРЕС."
                )
            if args.disable_ru_proxy:
                print(
                    "RU-прокси выключен, каскад проверен. Российский трафик выходит "
                    "напрямую с ENTRY; списки proxy-domain и proxy-address сохранены."
                )
            if args.enable_telegram:
                print(
                    "Telegram-уведомления включены, каскад проверен. Проверка доставки "
                    "на каждом сервере: telegram-test."
                )
            if args.disable_telegram:
                print("Telegram-уведомления выключены, каскад проверен.")
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
    # Межсерверный интерфейс на ENTRY не может делить сокет с клиентскими - у
    # каждого интерфейса свой ListenPort, независимо от того, поднимает его
    # kernel-модуль или запасной userspace-движок. Публичным портом каскада
    # остаётся UDP/443 на EXIT, а локальный порт межсерверного канала на ENTRY
    # выбирается отдельно и фильтруется по IP EXIT.
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
    proxy_scope = "all"
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
        proxy_scope = prompt_proxy_scope("all")

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
        "По умолчанию: два DoT-сервера (162.254.86.13 и 185.95.218.43) и Yandex DoH для RU-доменов через прокси.",
    )
    telegram_enabled = prompt_bool("Включить мониторинг через Telegram", False)
    telegram_token = ""
    telegram_chat = ""
    if telegram_enabled:
        telegram_token, telegram_chat = prompt_telegram_credentials()

    dot_upstreams = [
        {"address": "162.254.86.13", "tls_name": "vno01.dnscry.pt"},
        {"address": "185.95.218.43", "tls_name": "dns.digitale-gesellschaft.ch"},
    ]
    if not prompt_bool("Использовать два DNS-over-TLS по умолчанию (Литва и Швейцария)", True):
        dot_pairs = [item.strip() for item in prompt("Серверы DoT в виде IP:TLS-имя через запятую").split(",") if item.strip()]
        if not dot_pairs:
            fail("Укажите хотя бы один DoT-сервер в виде IP:TLS-имя")
        dot_upstreams = []
        for pair in dot_pairs:
            address, separator, tls_name = pair.partition(":")
            if not separator or not tls_name:
                fail(f"DoT-сервер должен быть в виде IP:TLS-имя: {pair}")
            try:
                ipaddress.IPv4Address(address)
            except ValueError:
                fail(f"Адрес DoT должен быть IPv4: {address}")
            if not re.fullmatch(r"[A-Za-z0-9.-]+", tls_name):
                fail(f"Некорректное TLS-имя DoT: {tls_name}")
            dot_upstreams.append({"address": address, "tls_name": tls_name})

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
            "entry_mobile_service_name": MOBILE_SERVICE_NAME,
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
            # Межсерверный канал поднимает kernel-модуль AmneziaWG, а не
            # отдельный userspace-движок: на одном и том же канале userspace
            # терял 6.4-7.8% пакетов против 0.85% у kernel-модуля, и именно это
            # выражалось в медленном зарубежном трафике. Полный набор полей 3.1
            # kernel принимает (проверено реальными awg setconf/showconf).
            # Запасной userspace-путь остаётся доступен через
            # scripts/toggle-transit-engine.py для хостов, где DKMS не собирается.
            "awg3_transit_enabled": False,
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
            "entry_ru_proxy_scope": proxy_scope,
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
            # Стороны транзита обязаны быть на одном движке - см. комментарий у
            # ENTRY выше и таблицу движков в scripts/toggle-transit-engine.py.
            # При kernel-модуле конфиг межсерверного интерфейса пишет роль exit,
            # поэтому exit_manage_awg_config включён; при userspace его писала бы
            # роль awg3_transit, и флаг был бы выключен.
            "exit_manage_awg_config": True,
            "exit_peer_migration_policy": "explicit",
            "awg3_transit_enabled": False,
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
                **new_front_disguise(),
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
    seal_local_controller_state(production)
    cleanup_deployment(repo, hosts_path, vault_password)
    atexit.unregister(cleanup_callback)
    try:
        run_controller_backup(repo, production, vault_password)
    except SystemExit as backup_error:
        print(f"Резервная копия контроллера не создана: {backup_error}")

    ui_success("Все активные серверы настроены, проверены и готовы к работе.")
    show_deployment_summary(production)
    show_generated_account_passwords(account_passwords)
    mark_account_passwords_delivered(production)
    account_passwords.clear()


if __name__ == "__main__":
    main()

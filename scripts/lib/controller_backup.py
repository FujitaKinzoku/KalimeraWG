#!/usr/bin/env python3
"""Резервная копия состояния контроллера ENTRY и её восстановление.

ENTRY - единственное место, где лежат inventory каскада, пароль Ansible Vault,
ключ оркестратора и состояние клиентов. Копия собирается в один архив, шифруется
AES-256-GCM отдельным ключом восстановления и хранится на EXIT и FRONT. Ключ
восстановления знают только ENTRY и владелец: серверу, который хранит копию, она
ничего не раскрывает.

В модуле нет обращений к сети и к Ansible: только сборка архива, шифрование и
раскладка файлов. Так всё это проверяется тестами без серверов.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import secrets
import shutil
import tarfile
from pathlib import Path, PurePosixPath
from typing import NamedTuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_VERSION = 1
KIND = "kalimera-controller-backup"
AAD_PREFIX = b"KalimeraWG controller backup v1\0"
KEY_PREFIX = "KWG1"
MANIFEST_NAME = "manifest.json"
# Пути внутри архива.
INVENTORY_DIR = "inventory"
RUNTIME_DIR = "runtime"
STATE_DIR = "state"
SSH_DIR = "ssh"
# Имена файлов контроллера внутри runtime-хранилища: те же, что в
# roles/runtime_secrets/templates/config.json.j2.
RUNTIME_VAULT_PASSWORD = "controller/production-vault.pass"
RUNTIME_SSH_KEY = "controller/awg-iac-production"
RUNTIME_CLIENTS = "controller/clients"
CONTROLLER_TARGET_PREFIX = "controller/"


class BackupError(RuntimeError):
    """Копию нельзя создать, прочитать или разложить; текст - для администратора."""


class Source(NamedTuple):
    """Файл или каталог на сервере и его имя внутри архива."""

    path: Path
    arcname: str


class RestorePaths(NamedTuple):
    """Куда раскладывается состояние. root - префикс путей служб ENTRY."""

    production: Path
    vault_password: Path
    ssh_private_key: Path
    state_root: Path
    root: Path = Path("/")


def new_recovery_key() -> bytes:
    return secrets.token_bytes(32)


def format_recovery_key(key: bytes) -> str:
    """Ключ для записи человеком: восемь групп и контрольная группа против опечаток."""
    if len(key) != 32:
        raise BackupError("ключ восстановления должен содержать 32 байта")
    body = key.hex()
    groups = [body[index:index + 8] for index in range(0, 64, 8)]
    groups.append(hashlib.sha256(key).hexdigest()[:8])
    return KEY_PREFIX + "-" + "-".join(groups)


def parse_recovery_key(text: str) -> bytes:
    compact = re.sub(r"[\s-]", "", text)
    if compact.upper().startswith(KEY_PREFIX):
        compact = compact[len(KEY_PREFIX):]
    compact = compact.lower()
    if not re.fullmatch(r"[0-9a-f]{72}", compact):
        raise BackupError(
            "ключ восстановления имеет неверный формат: ожидается строка вида "
            f"{KEY_PREFIX}-xxxxxxxx-... из девяти групп"
        )
    key = bytes.fromhex(compact[:64])
    if hashlib.sha256(key).hexdigest()[:8] != compact[64:]:
        raise BackupError("в ключе восстановления опечатка: контрольная группа не совпадает")
    return key


def _link_escapes(member_name: str, link_name: str) -> bool:
    link = PurePosixPath(link_name)
    resolved = PurePosixPath(posixpath.normpath(str(PurePosixPath(member_name).parent / link)))
    return link.is_absolute() or resolved.is_absolute() or (bool(resolved.parts) and resolved.parts[0] == "..")


def _scrub(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Одинаковый архив при одинаковом содержимом; ничего, что ведёт за его пределы."""
    if info.issym():
        if _link_escapes(info.name, info.linkname):
            raise BackupError(f"ссылка ведёт за пределы копии: {info.name}")
    elif info.islnk() or info.isdev() or info.isfifo():
        raise BackupError(f"в копию не входят жёсткие ссылки и устройства: {info.name}")
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    return info


def build_archive(manifest: dict, sources: list[Source]) -> tuple[bytes, str]:
    """Собрать архив. Возвращает сжатый архив и контрольную сумму содержимого.

    Сумма считается по содержимому без manifest.json: в нём время создания, а
    сумма нужна, чтобы не отправлять копию заново, пока состояние не менялось.
    """
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for source in sorted(sources, key=lambda item: item.arcname):
            if source.path.is_symlink():
                raise BackupError(f"источник копии - ссылка: {source.path}")
            if not source.path.exists():
                continue
            archive.add(source.path, arcname=source.arcname, recursive=True, filter=_scrub)
        content_sha256 = hashlib.sha256(stream.getvalue()).hexdigest()
        document = dict(manifest)
        document["version"] = FORMAT_VERSION
        document["content_sha256"] = content_sha256
        data = json.dumps(document, sort_keys=True, ensure_ascii=False, indent=1).encode("utf-8")
        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(data)
        info.mode = 0o600
        archive.addfile(_scrub(info), io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=6, fileobj=compressed, mtime=0) as gz:
        gz.write(stream.getvalue())
    return compressed.getvalue(), content_sha256


def encrypt(plaintext: bytes, key: bytes, cluster_id: str, created: str, release: str) -> bytes:
    """Зашифровать архив. created и release снаружи - подсказка, внутри они в manifest."""
    nonce = os.urandom(12)
    aad = AAD_PREFIX + cluster_id.encode("ascii")
    document = {
        "version": FORMAT_VERSION,
        "kind": KIND,
        "cluster_id": cluster_id,
        "created": created,
        "release": release,
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(AESGCM(key).encrypt(nonce, plaintext, aad)).decode("ascii"),
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def read_header(document_bytes: bytes) -> dict:
    """Открытая часть файла копии: чья она, когда создана. Содержимое не расшифровывается."""
    try:
        document = json.loads(document_bytes.decode("ascii"))
    except (UnicodeError, ValueError) as error:
        raise BackupError("файл не является резервной копией контроллера KalimeraWG") from error
    if not isinstance(document, dict) or document.get("kind") != KIND:
        raise BackupError("файл не является резервной копией контроллера KalimeraWG")
    if document.get("version") != FORMAT_VERSION:
        raise BackupError("копия создана другой версией формата; нужен выпуск KalimeraWG, который её создал")
    return document


def decrypt(document_bytes: bytes, key: bytes) -> bytes:
    document = read_header(document_bytes)
    try:
        cluster_id = str(document["cluster_id"])
        nonce = base64.b64decode(document["nonce"], validate=True)
        ciphertext = base64.b64decode(document["ciphertext"], validate=True)
        aad = AAD_PREFIX + cluster_id.encode("ascii")
    except (KeyError, ValueError, UnicodeError) as error:
        raise BackupError("файл резервной копии повреждён") from error
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as error:
        raise BackupError("ключ восстановления не подходит к этой копии, или файл повреждён") from error


def _safe_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.islnk() or member.isdev() or member.isfifo():
            raise BackupError("копия содержит небезопасный путь")
        if member.issym() and _link_escapes(member.name, member.linkname):
            raise BackupError("копия содержит небезопасную ссылку")
    return members


def extract(plaintext: bytes, target: Path) -> dict:
    """Распаковать архив в пустой каталог и вернуть manifest."""
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(target.iterdir()):
        raise BackupError(f"каталог распаковки не пуст: {target}")
    # Каталоги создаются доступными только root, как после открытия хранилища
    # секретов при загрузке: фильтр data не переносит права каталогов из архива.
    previous_umask = os.umask(0o077)
    try:
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as archive:
            archive.extractall(target, members=_safe_members(archive), filter="data")
        manifest = json.loads((target / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError, tarfile.TarError) as error:
        raise BackupError("содержимое копии повреждено") from error
    finally:
        os.umask(previous_umask)
    if not isinstance(manifest, dict) or manifest.get("version") != FORMAT_VERSION:
        raise BackupError("копия создана другой версией формата")
    return manifest


def _copy(source: Path, destination: Path, *, private_parent: bool = True) -> None:
    """Скопировать файл или каталог с его правами. private_parent - недостающие
    родительские каталоги создаются доступными только root (каталоги контроллера);
    иначе с обычными правами, как их создал бы пакет (/etc/amnezia)."""
    if private_parent:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True)
    else:
        shutil.copy2(source, destination)


def restore_layout(extracted: Path, manifest: dict, paths: RestorePaths) -> list[str]:
    """Разложить распакованную копию по местам на новом ENTRY.

    Конфигурации служб кладутся обычными файлами: первый же deploy переносит их в
    зашифрованное хранилище так же, как при чистой установке. Возвращает список
    восстановленного для отчёта администратору.
    """
    restored: list[str] = []
    inventory = extracted / INVENTORY_DIR
    if not (inventory / "hosts.yml").is_file():
        raise BackupError("в копии нет production inventory")
    if paths.production.exists():
        raise BackupError(f"{paths.production} уже существует: восстановление выполняется на чистом сервере")
    runtime = extracted / RUNTIME_DIR
    vault_password = runtime / RUNTIME_VAULT_PASSWORD
    ssh_key = runtime / RUNTIME_SSH_KEY
    if not vault_password.is_file() or not ssh_key.is_file():
        raise BackupError("в копии нет пароля Ansible Vault или ключа оркестратора")

    # Файлы контроллера раскладываются своими путями (paths), остальное - по списку
    # путей служб из копии.
    mappings = [
        mapping
        for mapping in manifest.get("mappings", [])
        if isinstance(mapping, dict)
        and mapping.get("source")
        and mapping.get("target")
        and not str(mapping["target"]).startswith(CONTROLLER_TARGET_PREFIX)
    ]
    # Проверка до первой записи: на сервере с развёрнутым хранилищем секретов эти
    # пути - ссылки в tmpfs, и запись по ним испортила бы работающую установку.
    destinations = [paths.root / str(mapping["source"]).lstrip("/") for mapping in mappings]
    for destination in [paths.vault_password, paths.ssh_private_key, *destinations]:
        if destination.is_symlink():
            raise BackupError(
                f"{destination} - ссылка в хранилище секретов: на этом сервере KalimeraWG уже установлен"
            )

    _copy(inventory, paths.production)
    restored.append("production inventory")
    _copy(vault_password, paths.vault_password)
    paths.vault_password.chmod(0o600)
    restored.append("пароль Ansible Vault")
    _copy(ssh_key, paths.ssh_private_key)
    paths.ssh_private_key.chmod(0o600)
    public_key = extracted / SSH_DIR / (paths.ssh_private_key.name + ".pub")
    if public_key.is_file():
        _copy(public_key, paths.ssh_private_key.with_name(paths.ssh_private_key.name + ".pub"))
    restored.append("ключ оркестратора")

    state = extracted / STATE_DIR
    if state.is_dir():
        for child in sorted(state.iterdir()):
            _copy(child, paths.state_root / child.name)
    clients = runtime / RUNTIME_CLIENTS
    if clients.is_dir():
        _copy(clients, paths.state_root / "clients")
        restored.append("сохранённые конфигурации клиентов")

    for mapping, destination in zip(mappings, destinations):
        source = runtime / str(mapping["target"])
        if not source.exists():
            continue
        _copy(source, destination, private_parent=False)
        restored.append(str(mapping["source"]))
    return restored

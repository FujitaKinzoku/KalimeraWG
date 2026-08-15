#!/usr/bin/env python3
"""Безопасно экспортировать одну резервную Shamir-долю вне репозитория."""

from __future__ import annotations

import argparse
import os
import pathlib
import stat

import yaml
from ansible.parsing.vault import VaultLib, VaultSecret


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument("--vault-password-file", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--share-index", type=int, default=5)
    args = parser.parse_args()

    repo = args.repo_root.expanduser().resolve()
    password_path = args.vault_password_file.expanduser().resolve()
    output = args.output.expanduser().resolve()
    vault_path = repo / "inventory" / "production" / "group_vars" / "all" / "vault.yml"
    try:
        output.relative_to(repo)
    except ValueError:
        pass
    else:
        fail("Резервную долю запрещено сохранять внутри репозитория")
    if output.exists():
        fail("Отказ от перезаписи существующего файла резервной доли")
    if not password_path.is_file() or not vault_path.is_file():
        fail("Не найден пароль Vault или production Vault")
    if stat.S_IMODE(password_path.stat().st_mode) & 0o077:
        fail("Права файла пароля Vault недостаточно строгие")
    secret = password_path.read_bytes().rstrip(b"\r\n")
    try:
        plaintext = VaultLib([("default", VaultSecret(secret))]).decrypt(
            vault_path.read_bytes()
        )
        document = yaml.safe_load(plaintext)
        shares = document["vault_runtime_secret_shares"]
        share = shares[args.share_index - 1]
    except (OSError, KeyError, IndexError, TypeError, ValueError) as error:
        fail(f"Не удалось получить указанную долю: {type(error).__name__}")
    if not isinstance(share, str) or not share:
        fail("Резервная доля имеет неправильный формат")

    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(share + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    print(f"Резервная доля #{args.share_index} сохранена без вывода содержимого: {output}")


if __name__ == "__main__":
    main()

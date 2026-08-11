#!/usr/bin/env python3
"""Atomically update clean, one-domain-per-line policy files."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import tempfile
from pathlib import Path

FILES = {"ru": "ru-domain", "exit": "se-domain", "se": "se-domain", "direct": "entry-domain", "entry": "entry-domain"}
DOMAIN_RE = re.compile(r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--policy", required=True, choices=(*FILES, "default"))
    return parser.parse_args()


def normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise SystemExit("Некорректное имя домена") from error
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise SystemExit("Укажите имя домена, а не IP-адрес")
    if not DOMAIN_RE.fullmatch(value):
        raise SystemExit("Некорректное имя домена")
    return value


def read_file(path: Path) -> tuple[list[str], list[str]]:
    comments: list[str] = []
    values: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            comments.append(line)
        else:
            values.append(normalize_domain(stripped))
    return comments, values


def atomic_write(path: Path, comments: list[str], values: list[str]) -> None:
    content = "\n".join([*comments, *sorted(set(values))]).rstrip() + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, path.stat().st_mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> None:
    args = parse_args()
    domain = normalize_domain(args.domain)
    paths = {name: args.directory / name for name in set(FILES.values())}
    for path in paths.values():
        if not path.is_file():
            raise SystemExit(f"Не найден обязательный файл доменов: {path}")
    documents = {name: read_file(path) for name, path in paths.items()}
    for name, (comments, values) in documents.items():
        documents[name] = (comments, [value for value in values if value != domain])
    if args.policy != "default":
        target = FILES[args.policy]
        documents[target][1].append(domain)
    for name, path in paths.items():
        atomic_write(path, *documents[name])
    print(f"Domain policy updated: {domain} -> {args.policy}")


if __name__ == "__main__":
    main()

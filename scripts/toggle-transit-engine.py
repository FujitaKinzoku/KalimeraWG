#!/usr/bin/env python3
"""Диагностическое переключение движка транзитного канала ENTRY<->EXIT
между userspace AWG3+ (amneziawg-go) и kernel-модулем AmneziaWG - для
A/B-сравнения производительности на уже развёрнутом production-каскаде.

Правит только inventory/production/group_vars/{entry,exit}.yml.
Применить изменение: sudo ./deploy --resume
"""

from __future__ import annotations

import argparse
import pathlib

import yaml

# Значения для каждого режима - добавляйте новые режимы/переменные сюда
# по ходу дальнейшего тестирования, не трогая остальной скрипт.
TRANSIT_ENGINE_VALUES: dict[str, dict[str, dict[str, object]]] = {
    "kernel": {
        "entry": {"awg3_transit_enabled": False},
        "exit": {"awg3_transit_enabled": False, "exit_manage_awg_config": True},
    },
    "userspace": {
        "entry": {"awg3_transit_enabled": True},
        "exit": {"awg3_transit_enabled": True, "exit_manage_awg_config": False},
    },
}


def fail(message: str) -> None:
    raise SystemExit(message)


def load_yaml(path: pathlib.Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"Ожидалась структура YAML mapping: {path}")
    return value


def yaml_write(path: pathlib.Path, value: dict) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    path.chmod(0o600)


def set_transit_engine(production: pathlib.Path, engine: str) -> bool:
    if engine not in TRANSIT_ENGINE_VALUES:
        fail(f"Неизвестный режим {engine!r}, ожидается один из {sorted(TRANSIT_ENGINE_VALUES)}")

    changed = False
    for host, overrides in TRANSIT_ENGINE_VALUES[engine].items():
        path = production / "group_vars" / f"{host}.yml"
        if not path.is_file():
            fail(f"Не найден production inventory: {path}")
        data = load_yaml(path)
        for key, value in overrides.items():
            if data.get(key) != value:
                data[key] = value
                changed = True
        yaml_write(path, data)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument("--engine", required=True, choices=sorted(TRANSIT_ENGINE_VALUES))
    args = parser.parse_args()

    production = args.repo_root.expanduser().resolve() / "inventory" / "production"
    changed = set_transit_engine(production, args.engine)
    if changed:
        print(f"Production inventory обновлён: движок транзита переключён на {args.engine!r}.")
        print("Применить: sudo ./deploy --resume")
    else:
        print(f"Production inventory уже настроен на {args.engine!r}, изменений нет.")


if __name__ == "__main__":
    main()

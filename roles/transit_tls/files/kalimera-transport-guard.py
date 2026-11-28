#!/usr/bin/env python3
"""Сторож транспорта на EXIT.

Туннель ENTRY - EXIT может идти одним из нескольких транспортов: напрямую по UDP
или внутри TLS по TCP. Одновременно открыт ровно один. Транспорт, которым не
пользуются, не слушает, а его порт закрыт межсетевым экраном даже для ENTRY.

Какой транспорт открыть, сообщает сам ENTRY - тем, что стучится в закрытый порт.
Отдельного канала управления нет: когда блокируется UDP, пройти может только тот
самый TCP-порт, который предстоит открыть. Пакеты ENTRY к закрытому порту считает
правило межсетевого экрана; программа раз в несколько секунд читает счётчик.

Правило переключения одно: транспорт открывается, когда ENTRY в него стучится, а
по открытому сейчас от ENTRY ничего не приходит дольше заданного времени.

  * ENTRY выключен или перезагружается - стука нет, ничего не меняется;
  * транспорт заблокирован - пакеты по нему не приходят, а стук в другой есть;
  * работающий транспорт закрыть стуком нельзя, в том числе подделав адрес ENTRY;
  * первые минуты после загрузки самого EXIT транспорт не меняется: ENTRY за это
    время успевает попробовать прямой.

Действующий транспорт хранится в /var/lib и переживает перезагрузку EXIT.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

CONFIG_PATH = Path("/etc/kalimera-transport/config.json")
IPTABLES = ("iptables", "-w", "10")


class Config:
    def __init__(self, document: dict) -> None:
        self.peer = str(document["peer_ipv4"])
        self.wan_interface = str(document["wan_interface"])
        self.awg_interface = str(document["awg_interface"])
        self.chain = str(document.get("chain", "KALIMERA-TRANSPORT"))
        self.transports: list[dict] = []
        for item in document["transports"]:
            if item["proto"] not in ("udp", "tcp"):
                raise ValueError(f"неизвестный протокол транспорта: {item['proto']}")
            self.transports.append(
                {
                    "name": str(item["name"]),
                    "label": str(item.get("label", item["name"])),
                    "proto": str(item["proto"]),
                    "port": int(item["port"]),
                    "service": str(item.get("service", "")),
                }
            )
        names = [item["name"] for item in self.transports]
        if len(names) < 2 or len(set(names)) != len(names):
            raise ValueError("нужно не меньше двух транспортов с разными именами")
        # Столько секунд открытый транспорт должен молчать, прежде чем его можно
        # закрыть. Больше интервала keepalive туннеля: исправный туннель не молчит.
        self.idle_seconds = int(document.get("idle_seconds", 75))
        # Сколько пакетов ENTRY к закрытому порту за одну проверку считается стуком
        # и сколько секунд стук остаётся свежим.
        self.knock_packets = int(document.get("knock_packets", 2))
        self.knock_fresh_seconds = int(document.get("knock_fresh_seconds", 30))
        # Сколько секунд после загрузки сервера транспорт не меняется. Пока EXIT
        # перезагружался, ENTRY не мог отличить это от блокировки и пробует оба
        # транспорта по очереди. За это время он успевает попробовать прямой, и
        # каскад не уходит на запасной транспорт из-за одной перезагрузки.
        self.boot_grace_seconds = int(document.get("boot_grace_seconds", 300))
        self.state_dir = Path(document["state_dir"])
        self.active_file = Path(document["active_file"])
        if self.idle_seconds < 1 or self.knock_packets < 1:
            raise ValueError("время молчания и порог стука должны быть положительными")

    def transport(self, name: str) -> dict:
        return next(item for item in self.transports if item["name"] == name)

    def names(self) -> list[str]:
        return [item["name"] for item in self.transports]


def load_config(path: Path = CONFIG_PATH) -> Config:
    return Config(json.loads(path.read_text(encoding="utf-8")))


def run(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        return subprocess.CompletedProcess(argv, 1, "", str(error))


def log(message: str) -> None:
    logger = shutil.which("logger")
    if logger:
        run([logger, "-t", "kalimera-transport-guard", message])


def atomic_write(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def read_active(cfg: Config) -> str:
    """Транспорт, открытый до перезагрузки; без записи - первый в списке."""
    try:
        value = cfg.active_file.read_text(encoding="utf-8").strip()
    except OSError:
        return cfg.names()[0]
    return value if value in cfg.names() else cfg.names()[0]


def empty_state(cfg: Config, now: int) -> dict:
    return {
        "active": read_active(cfg),
        "since": now,
        "last_contact": now,
        "rx": None,
        "knock_at": {},
        "last_switch": None,
        # Состояние лежит в /run и после перезагрузки создаётся заново: это время
        # и есть момент загрузки для сторожа.
        "booted": now,
    }


def read_state(cfg: Config, now: int) -> dict:
    state = empty_state(cfg, now)
    try:
        saved = json.loads((cfg.state_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return state
    if not isinstance(saved, dict) or saved.get("active") not in cfg.names():
        return state
    for key in ("active", "since", "last_contact", "rx", "last_switch", "booted"):
        if key in saved:
            state[key] = saved[key]
    if isinstance(saved.get("knock_at"), dict):
        state["knock_at"] = {
            name: int(value)
            for name, value in saved["knock_at"].items()
            if name in cfg.names() and isinstance(value, int)
        }
    return state


def write_state(cfg: Config, state: dict) -> None:
    cfg.state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write(cfg.state_dir / "state.json", json.dumps(state, ensure_ascii=False) + "\n")


def match_arguments(cfg: Config, transport: dict) -> list[str]:
    """Пакеты ENTRY на порт транспорта, пришедшие с внешнего интерфейса."""
    return [
        "-i", cfg.wan_interface, "-s", cfg.peer, "-p", transport["proto"],
        "--dport", str(transport["port"]),
    ]


def expected_rules(cfg: Config, active: str) -> list[list[str]]:
    """Правила цепочки: открытый транспорт принимается, остальные отбрасываются.

    Правило отбрасывания заодно считает пакеты: это и есть стук ENTRY.
    """
    rules: list[list[str]] = []
    for transport in cfg.transports:
        if transport["name"] == active:
            rules.append(match_arguments(cfg, transport) + ["-j", "ACCEPT"])
        else:
            rules.append(
                match_arguments(cfg, transport)
                + ["-m", "comment", "--comment", f"knock:{transport['name']}", "-j", "DROP"]
            )
    return rules


def firewall_matches(cfg: Config, active: str) -> bool:
    listing = run([*IPTABLES, "-S", cfg.chain])
    if listing.returncode != 0:
        return False
    rules = expected_rules(cfg, active)
    present = [line for line in listing.stdout.splitlines() if line.startswith("-A ")]
    if len(present) != len(rules):
        return False
    if any(run([*IPTABLES, "-C", cfg.chain, *rule]).returncode != 0 for rule in rules):
        return False
    # Цепочка должна стоять первой в INPUT: раньше правил UFW, которые разрешают
    # ENTRY порт прямого транспорта.
    hooks = [line for line in run([*IPTABLES, "-S", "INPUT"]).stdout.splitlines() if line.startswith("-A ")]
    return bool(hooks) and hooks[0].split() == ["-A", "INPUT", "-j", cfg.chain]


def apply_firewall(cfg: Config, active: str) -> bool:
    """Собрать цепочку заново. Счётчики стука при этом начинаются с нуля."""
    run([*IPTABLES, "-N", cfg.chain])
    if run([*IPTABLES, "-F", cfg.chain]).returncode != 0:
        return False
    for rule in expected_rules(cfg, active):
        if run([*IPTABLES, "-A", cfg.chain, *rule]).returncode != 0:
            return False
    while run([*IPTABLES, "-D", "INPUT", "-j", cfg.chain]).returncode == 0:
        pass
    return run([*IPTABLES, "-I", "INPUT", "1", "-j", cfg.chain]).returncode == 0


def read_knocks(cfg: Config) -> dict[str, int]:
    """Сколько пакетов ENTRY пришло на порт каждого закрытого транспорта."""
    knocks: dict[str, int] = {}
    listing = run([*IPTABLES, "-nvxL", cfg.chain])
    if listing.returncode != 0:
        return knocks
    for line in listing.stdout.splitlines():
        words = line.split()
        marker = next((word for word in words if word.startswith("knock:")), "")
        # В выводе с комментарием он окружён "/* ... */".
        name = marker.removeprefix("knock:")
        if name in cfg.names() and words and words[0].isdigit():
            knocks[name] = int(words[0])
    return knocks


def read_rx(cfg: Config) -> int | None:
    """Сколько байт туннель принял от ENTRY; None, если интерфейс не отвечает."""
    result = run(["awg", "show", cfg.awg_interface, "transfer"])
    if result.returncode != 0:
        return None
    total = 0
    for line in result.stdout.splitlines():
        words = line.split()
        if len(words) == 3 and words[1].isdigit():
            total += int(words[1])
    return total


def set_services(cfg: Config, active: str) -> None:
    """Служба открытого транспорта работает, остальные остановлены."""
    for transport in cfg.transports:
        if not transport["service"]:
            continue
        running = run(["systemctl", "is-active", "--quiet", transport["service"]]).returncode == 0
        if transport["name"] == active and not running:
            run(["systemctl", "start", transport["service"]], timeout=60)
        elif transport["name"] != active and running:
            run(["systemctl", "stop", transport["service"]], timeout=60)


def decide(cfg: Config, state: dict, now: int) -> str:
    """Какой транспорт должен быть открыт. Возвращает имя; прежнее - без перемен."""
    active = state["active"]
    if now - int(state.get("booted") or 0) < cfg.boot_grace_seconds:
        return active
    if now - int(state["last_contact"]) < cfg.idle_seconds:
        return active
    for name in cfg.names():
        if name == active:
            continue
        knocked = state["knock_at"].get(name)
        if knocked is not None and now - int(knocked) <= cfg.knock_fresh_seconds:
            return name
    return active


def tick(cfg: Config, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    state = read_state(cfg, now)
    active = state["active"]

    rx = read_rx(cfg)
    if rx is not None:
        # Растущий счётчик - ENTRY на связи. Первое чтение после запуска и сброс
        # счётчика при перезапуске интерфейса связью не считаются.
        if state["rx"] is not None and rx > int(state["rx"]):
            state["last_contact"] = now
        state["rx"] = rx

    # Цепочку могли сбросить перезагрузка или пересборка UFW: тогда стук за это
    # время не учтён, и решение откладывается до следующей проверки.
    intact = firewall_matches(cfg, active)
    target = active
    if intact:
        for name, packets in read_knocks(cfg).items():
            if packets >= cfg.knock_packets:
                state["knock_at"][name] = now
        target = decide(cfg, state, now)

    if target != active:
        previous = active
        state.update({"active": target, "since": now, "last_contact": now, "knock_at": {}})
        state["last_switch"] = {"at": now, "from": previous, "to": target}
        cfg.active_file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        atomic_write(cfg.active_file, target + "\n")
        log(
            f"транспорт туннеля переведён: {cfg.transport(previous)['label']} → "
            f"{cfg.transport(target)['label']}: ENTRY стучится в него, а прежний молчит"
        )
        active = target
        apply_firewall(cfg, active)
    elif not intact:
        apply_firewall(cfg, active)
    else:
        # Счётчики обнуляются после каждой проверки: стук должен быть свежим.
        run([*IPTABLES, "-Z", cfg.chain])
    set_services(cfg, active)
    write_state(cfg, state)
    return state


def format_age(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds} с"
    if seconds < 5400:
        return f"{seconds // 60} мин"
    return f"{seconds // 3600} ч"


def status_lines(cfg: Config, state: dict, now: int) -> list[str]:
    active = cfg.transport(state["active"])
    lines = [
        f"Открыт транспорт: {active['label']} ({active['proto']}/{active['port']}), "
        f"{format_age(now - int(state['since']))}",
        f"Пакеты от ENTRY по нему: {format_age(now - int(state['last_contact']))} назад",
    ]
    for transport in cfg.transports:
        if transport["name"] == state["active"]:
            continue
        knocked = state["knock_at"].get(transport["name"])
        note = "ENTRY не стучится" if knocked is None else f"ENTRY стучался {format_age(now - int(knocked))} назад"
        lines.append(f"Закрыт: {transport['label']} ({transport['proto']}/{transport['port']}); {note}")
    last = state.get("last_switch")
    if isinstance(last, dict) and last.get("at"):
        lines.append(
            f"Последнее переключение: {format_age(now - int(last['at']))} назад, "
            f"{cfg.transport(last['from'])['label']} → {cfg.transport(last['to'])['label']}"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="transport-guard", description="Транспорт туннеля ENTRY - EXIT на этом сервере."
    )
    parser.add_argument("--config", type=Path, default=CONFIG_PATH, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("tick", help=argparse.SUPPRESS)
    status = commands.add_parser("status", help="показать открытый транспорт")
    status.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("Команда выполняется от root.", file=sys.stderr)
        return 1
    try:
        cfg = load_config(args.config)
    except (OSError, ValueError, KeyError) as error:
        print(f"Настройки сторожа транспорта не читаются: {error}", file=sys.stderr)
        return 1
    if args.command == "tick":
        cfg.state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        with open(cfg.state_dir / "lock", "w", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return 0
            tick(cfg)
        return 0
    now = int(time.time())
    state = read_state(cfg, now)
    if getattr(args, "json", False):
        print(json.dumps(state, ensure_ascii=False))
    else:
        print("\n".join(status_lines(cfg, state, now)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

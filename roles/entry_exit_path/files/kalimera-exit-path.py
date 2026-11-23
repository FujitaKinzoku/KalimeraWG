#!/usr/bin/env python3
"""Переключатель путей до EXIT на ENTRY.

Каскад держит два туннеля: до основного EXIT и до резервного. Скрипт раз в
несколько секунд проверяет оба и решает, в какой из них ведёт маршрут таблицы
EXIT. Проверка - TCP-соединения через сам туннель к нескольким независимым
адресам: туннель считается живым, пока отвечает заданное их число. Одного
свежего handshake мало: он есть и тогда, когда сам EXIT потерял выход в интернет.

Правила:
  * на резервный путь - после нескольких неудачных проверок основного подряд и
    только если резервный отвечает;
  * обратно на основной - когда он непрерывно отвечает заданное время: внешний
    адрес клиентов не должен меняться туда-сюда при каждом сбое связи;
  * если не отвечают оба, маршрут не меняется: пакеты уходят в неработающий
    туннель и теряются, но с адреса ENTRY зарубежный трафик не выходит.

Состояние лежит в /run и после перезагрузки начинается с основного пути.
Закрепление пути командой use хранится в /var/lib и перезагрузку переживает.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CONFIG_PATH = Path("/etc/kalimera-exit-path/config.json")
PRIMARY = "primary"
STANDBY = "standby"
PATH_NAMES = (PRIMARY, STANDBY)
MODES = ("auto", PRIMARY, STANDBY)
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


class Config:
    def __init__(self, document: dict) -> None:
        self.paths: dict[str, dict] = {}
        for item in document["paths"]:
            if item["name"] not in PATH_NAMES:
                raise ValueError(f"неизвестный путь: {item['name']}")
            self.paths[item["name"]] = item
        if set(self.paths) != set(PATH_NAMES):
            raise ValueError("нужны оба пути: primary и standby")
        self.targets = [(str(host), int(port)) for host, port in document["probe_targets"]]
        self.quorum = int(document["probe_quorum"])
        self.probe_timeout = float(document["probe_timeout_seconds"])
        self.fail_threshold = int(document["fail_threshold"])
        self.failback_seconds = int(document["failback_seconds"])
        self.drill_seconds = int(document.get("drill_seconds", 300))
        self.table = int(document["table"])
        self.state_dir = Path(document["state_dir"])
        self.mode_file = Path(document["mode_file"])
        self.hold_file = Path(document["hold_file"]) if document.get("hold_file") else None
        self.dns_via_exit = bool(document.get("dns_via_exit", False))
        self.notify_command = [str(part) for part in document.get("notify_command", [])]
        if not self.targets or not (1 <= self.quorum <= len(self.targets)):
            raise ValueError("число ответивших адресов должно быть от 1 до числа адресов")
        if self.fail_threshold < 1 or self.failback_seconds < 0:
            raise ValueError("порог неудач и время возврата заданы неверно")

    def interface(self, name: str) -> str:
        return str(self.paths[name]["interface"])

    def label(self, name: str) -> str:
        return str(self.paths[name].get("label", name))


def load_config(path: Path = CONFIG_PATH) -> Config:
    return Config(json.loads(path.read_text(encoding="utf-8")))


def empty_state() -> dict:
    return {
        "active": PRIMARY,
        "since": 0,
        "reason": "",
        "drill_until": 0,
        "paths": {
            name: {"fail": 0, "healthy_since": None, "reached": None, "checked": 0}
            for name in PATH_NAMES
        },
        "last_switch": None,
    }


def read_state(cfg: Config) -> dict:
    state = empty_state()
    try:
        saved = json.loads((cfg.state_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return state
    if not isinstance(saved, dict) or saved.get("active") not in PATH_NAMES:
        return state
    for key in ("active", "since", "reason", "drill_until", "last_switch"):
        if key in saved:
            state[key] = saved[key]
    for name in PATH_NAMES:
        entry = (saved.get("paths") or {}).get(name)
        if isinstance(entry, dict):
            state["paths"][name].update(
                {key: entry[key] for key in state["paths"][name] if key in entry}
            )
    return state


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def write_state(cfg: Config, state: dict) -> None:
    cfg.state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write(cfg.state_dir / "state.json", json.dumps(state, ensure_ascii=False) + "\n")
    # Отдельный файл с именем интерфейса читают скрипт маршрутизации, сторож
    # RU-прокси и awg-health: им не нужен разбор JSON.
    atomic_write(cfg.state_dir / "active", cfg.interface(state["active"]) + "\n")


def read_mode(cfg: Config) -> str:
    try:
        value = cfg.mode_file.read_text(encoding="utf-8").strip()
    except OSError:
        return "auto"
    return value if value in MODES else "auto"


def write_mode(cfg: Config, mode: str) -> None:
    if mode == "auto":
        cfg.mode_file.unlink(missing_ok=True)
        return
    cfg.mode_file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write(cfg.mode_file, mode + "\n")


def probe_target(interface: str, host: str, port: int, timeout: float) -> bool:
    """Открыть TCP-соединение через указанный интерфейс и сразу закрыть его."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.setsockopt(
                socket.SOL_SOCKET, SO_BINDTODEVICE, interface.encode("ascii") + b"\0"
            )
            connection.settimeout(timeout)
            connection.connect((host, port))
        return True
    except OSError:
        return False


def probe_path(cfg: Config, name: str) -> int:
    """Сколько адресов ответило через туннель этого пути."""
    interface = cfg.interface(name)
    if not Path("/sys/class/net", interface).exists():
        return 0
    with ThreadPoolExecutor(max_workers=len(cfg.targets)) as pool:
        results = pool.map(
            lambda target: probe_target(interface, target[0], target[1], cfg.probe_timeout),
            cfg.targets,
        )
        return sum(1 for ok in results if ok)


def record_probe(state: dict, name: str, reached: int, quorum: int, now: int) -> None:
    entry = state["paths"][name]
    entry["reached"] = reached
    entry["checked"] = now
    if reached >= quorum:
        entry["fail"] = 0
        if entry["healthy_since"] is None:
            entry["healthy_since"] = now
    else:
        entry["fail"] = int(entry["fail"]) + 1
        entry["healthy_since"] = None


def path_is_healthy(state: dict, name: str) -> bool:
    entry = state["paths"][name]
    return entry["healthy_since"] is not None and int(entry["fail"]) == 0


def decide(state: dict, mode: str, cfg: Config, now: int) -> tuple[str, str]:
    """Выбрать путь. Возвращает имя пути и причину; причина пуста, если путь прежний."""
    active = state["active"]
    if mode in PATH_NAMES:
        return mode, ("закреплён командой exit-path use" if mode != active else "")
    primary = state["paths"][PRIMARY]
    standby = state["paths"][STANDBY]
    # Учебное переключение держит резервный путь, пока тот отвечает. Если он
    # перестал отвечать, действует обычное правило ниже и учение прекращается.
    if int(state.get("drill_until") or 0) > now and int(standby["fail"]) < cfg.fail_threshold:
        return STANDBY, ("учебное переключение" if active != STANDBY else "")
    if active == PRIMARY:
        if int(primary["fail"]) >= cfg.fail_threshold and path_is_healthy(state, STANDBY):
            return STANDBY, "основной путь не отвечает"
        return PRIMARY, ""
    if int(standby["fail"]) >= cfg.fail_threshold and path_is_healthy(state, PRIMARY):
        return PRIMARY, "резервный путь не отвечает"
    healthy_since = primary["healthy_since"]
    if healthy_since is not None and now - int(healthy_since) >= cfg.failback_seconds:
        return PRIMARY, "основной путь снова устойчиво отвечает"
    return STANDBY, ""


def deploy_in_progress(cfg: Config, now: int) -> bool:
    """Идёт ли deploy: он намеренно перезапускает туннели, и переключать путь не нужно.

    Отметку ставит и снимает сам deploy; забытая отметка перестаёт действовать
    через три часа, как и для службы самовосстановления.
    """
    if cfg.hold_file is None:
        return False
    try:
        return now - int(cfg.hold_file.stat().st_mtime) < 3 * 3600
    except OSError:
        return False


def run_quiet(argv: list[str], timeout: int = 15) -> int:
    try:
        return subprocess.run(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        ).returncode
    except (OSError, subprocess.SubprocessError):
        return 1


def log(message: str) -> None:
    logger = shutil.which("logger")
    if logger:
        run_quiet([logger, "-t", "kalimera-exit-path", message])


def current_route_interface(cfg: Config) -> str:
    try:
        output = subprocess.run(
            ["ip", "-4", "route", "show", "table", str(cfg.table)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in output.splitlines():
        words = line.split()
        if words[:1] == ["default"] and "dev" in words:
            return words[words.index("dev") + 1]
    return ""


def set_route(cfg: Config, name: str) -> bool:
    return (
        run_quiet(
            ["ip", "-4", "route", "replace", "default", "dev", cfg.interface(name),
             "table", str(cfg.table)]
        )
        == 0
    )


def flush_connections(cfg: Config, previous: str) -> None:
    """Забыть соединения, вышедшие через прежний туннель.

    ENTRY подменяет адрес клиента адресом своего конца туннеля. Запись conntrack
    продолжала бы подставлять адрес прежнего туннеля, и другой EXIT такие пакеты
    отбросил бы: соединение висело бы до тайм-аута. Без записи следующий пакет
    выходит уже с новым адресом, сайт отвечает сбросом, и приложение сразу
    открывает соединение заново.
    """
    address = str(cfg.paths[previous].get("tunnel_address", "")).split("/")[0]
    if not address:
        return
    conntrack = shutil.which("conntrack")
    if conntrack:
        run_quiet([conntrack, "-D", "--reply-dst", address])
        run_quiet([conntrack, "-D", "--orig-src", address])
    # Соединения самого ENTRY (backend FRONT для клиентов VLESS) привязаны к адресу
    # прежнего туннеля и без этого ждали бы собственного тайм-аута. Закрытый сокет
    # служба видит сразу, а клиент открывает соединение заново уже по новому пути.
    sockets = shutil.which("ss")
    if sockets:
        run_quiet([sockets, "-K", "-4", "src", address])


def sync_dns(cfg: Config, name: str) -> None:
    """Направить зарубежные запросы DNS в резолвер действующего EXIT."""
    if not cfg.dns_via_exit:
        return
    control = shutil.which("unbound-control")
    peer = str(cfg.paths[name].get("peer_tunnel_address", ""))
    if not control or not peer:
        return
    try:
        listing = subprocess.run(
            [control, "list_forwards"], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return
    root = next((line for line in listing.splitlines() if line.startswith(". ")), "")
    if any(word.split("@")[0] == peer for word in root.split()):
        return
    run_quiet([control, "forward", f"{peer}@53"])
    run_quiet([control, "flush_infra", "all"])


def notify(cfg: Config, message: str) -> None:
    if cfg.notify_command:
        run_quiet(cfg.notify_command + [message], timeout=45)


def apply_path(cfg: Config, state: dict, target: str, reason: str, now: int) -> bool:
    previous = state["active"]
    if not set_route(cfg, target):
        log(f"маршрут таблицы {cfg.table} не удалось перевести на {cfg.interface(target)}")
        return False
    state["active"] = target
    state["since"] = now
    state["reason"] = reason
    if target != STANDBY:
        state["drill_until"] = 0
    state["last_switch"] = {"at": now, "from": previous, "to": target, "reason": reason}
    write_state(cfg, state)
    flush_connections(cfg, previous)
    sync_dns(cfg, target)
    message = (
        f"Зарубежный трафик переведён: {cfg.label(previous)} → {cfg.label(target)}. "
        f"Причина: {reason}."
    )
    log(message)
    notify(cfg, message)
    return True


def tick(cfg: Config, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    state = read_state(cfg)
    mode = read_mode(cfg)
    for name in PATH_NAMES:
        record_probe(state, name, probe_path(cfg, name), cfg.quorum, now)
    if int(state.get("drill_until") or 0) and int(state["drill_until"]) <= now:
        state["drill_until"] = 0
    if not state.get("since"):
        state["since"] = now
    target, reason = decide(state, mode, cfg, now)
    if (
        target != state["active"]
        and mode == "auto"
        and not int(state.get("drill_until") or 0)
        and deploy_in_progress(cfg, now)
    ):
        target = state["active"]
    if target != state["active"]:
        if not apply_path(cfg, state, target, reason, now):
            write_state(cfg, state)
        return state
    write_state(cfg, state)
    # Маршрут мог заменить перезапуск маршрутизации или ручная команда: возвращаем
    # его к выбранному пути и держим резолвер Unbound согласованным с ним.
    if current_route_interface(cfg) != cfg.interface(state["active"]):
        set_route(cfg, state["active"])
    sync_dns(cfg, state["active"])
    return state


def format_age(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds} с"
    if seconds < 5400:
        return f"{seconds // 60} мин"
    return f"{seconds // 3600} ч"


def status_lines(cfg: Config, state: dict, mode: str, now: int) -> list[str]:
    active = state["active"]
    lines = [f"Зарубежный трафик идёт через: {cfg.label(active)} ({cfg.interface(active)})"]
    if state.get("since"):
        lines.append(f"  с этого пути не уходили: {format_age(now - int(state['since']))}")
    if mode == "auto":
        lines.append("Режим: автоматический")
    else:
        lines.append(f"Режим: закреплён {cfg.label(mode)}; вернуть автоматику: exit-path auto")
    if int(state.get("drill_until") or 0) > now:
        lines.append(
            f"Учебное переключение: ещё {format_age(int(state['drill_until']) - now)}"
        )
    for name in PATH_NAMES:
        entry = state["paths"][name]
        if entry["reached"] is None:
            verdict = "ещё не проверялся"
        elif int(entry["fail"]) == 0:
            verdict = (
                f"отвечает ({entry['reached']} из {len(cfg.targets)}), "
                f"без сбоев {format_age(now - int(entry['healthy_since'] or now))}"
            )
        else:
            verdict = (
                f"НЕ ОТВЕЧАЕТ ({entry['reached']} из {len(cfg.targets)}), "
                f"неудачных проверок подряд: {entry['fail']}"
            )
        lines.append(f"{cfg.label(name)} ({cfg.interface(name)}): {verdict}")
    last = state.get("last_switch")
    if isinstance(last, dict) and last.get("at"):
        lines.append(
            f"Последнее переключение: {format_age(now - int(last['at']))} назад, "
            f"{cfg.label(last['from'])} → {cfg.label(last['to'])}, причина: {last['reason']}"
        )
    return lines


def report_rows(cfg: Config, state: dict, mode: str, now: int) -> list[tuple[str, str]]:
    """Строки для cascade-check: уровень и текст."""
    rows: list[tuple[str, str]] = []
    active = state["active"]
    fresh = all(
        state["paths"][name]["checked"] and now - int(state["paths"][name]["checked"]) <= 120
        for name in PATH_NAMES
    )
    if not fresh:
        return [("WARN", "переключатель путей EXIT не проверял туннели последние две минуты")]
    for name in PATH_NAMES:
        entry = state["paths"][name]
        text = (
            f"{cfg.label(name)}: отвечает {entry['reached']} из {len(cfg.targets)} "
            "проверочных адресов"
        )
        rows.append(("OK" if int(entry["fail"]) == 0 else "WARN", text))
    if int(state.get("drill_until") or 0) > now:
        rows.append(("WARN", "идёт учебное переключение на резервный EXIT"))
    elif mode != "auto":
        rows.append(("WARN", f"путь закреплён вручную: {cfg.label(mode)}; автоматика: exit-path auto"))
    elif active == STANDBY:
        rows.append(("WARN", "зарубежный трафик идёт через резервный EXIT"))
    else:
        rows.append(("OK", "зарубежный трафик идёт через основной EXIT"))
    return rows


def command_tick(cfg: Config, _args: argparse.Namespace) -> int:
    tick(cfg)
    return 0


def command_status(cfg: Config, args: argparse.Namespace) -> int:
    now = int(time.time())
    state = read_state(cfg)
    mode = read_mode(cfg)
    if args.json:
        print(json.dumps({"mode": mode, "state": state}, ensure_ascii=False))
    elif args.report:
        for level, text in report_rows(cfg, state, mode, now):
            print(f"{level}\t{text}")
    else:
        print("\n".join(status_lines(cfg, state, mode, now)))
    return 0


def command_use(cfg: Config, args: argparse.Namespace) -> int:
    write_mode(cfg, args.path)
    state = tick(cfg)
    print(f"Путь закреплён: {cfg.label(args.path)}. Вернуть автоматику: exit-path auto")
    return 0 if state["active"] == args.path else 1


def command_auto(cfg: Config, _args: argparse.Namespace) -> int:
    write_mode(cfg, "auto")
    state = read_state(cfg)
    state["drill_until"] = 0
    write_state(cfg, state)
    tick(cfg)
    print("Режим автоматический: путь выбирается по результатам проверок.")
    return 0


def command_drill(cfg: Config, args: argparse.Namespace) -> int:
    if read_mode(cfg) != "auto":
        print("Путь закреплён вручную. Сначала: exit-path auto", file=sys.stderr)
        return 1
    state = tick(cfg)
    if not path_is_healthy(state, STANDBY):
        print(
            "Резервный EXIT не отвечает: учебное переключение отменено, трафик остался "
            "на прежнем пути.",
            file=sys.stderr,
        )
        return 1
    seconds = args.minutes * 60 if args.minutes else cfg.drill_seconds
    state["drill_until"] = int(time.time()) + seconds
    write_state(cfg, state)
    state = tick(cfg)
    if state["active"] != STANDBY:
        print("Переключить маршрут на резервный EXIT не удалось.", file=sys.stderr)
        return 1
    print(
        f"Трафик переведён на резервный EXIT на {format_age(seconds)}. Открытые соединения "
        "клиентов оборвались, внешний адрес сменился. Возврат произойдёт сам; "
        "прервать раньше: exit-path auto"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="exit-path",
        description="Выбор пути до EXIT: основной или резервный сервер.",
    )
    parser.add_argument("--config", type=Path, default=CONFIG_PATH, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("tick", help=argparse.SUPPRESS)
    status = commands.add_parser("status", help="показать состояние путей")
    status.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    status.add_argument("--report", action="store_true", help=argparse.SUPPRESS)
    use = commands.add_parser("use", help="закрепить путь: primary или standby")
    use.add_argument("path", choices=PATH_NAMES)
    commands.add_parser("auto", help="вернуть автоматический выбор пути")
    drill = commands.add_parser("drill", help="учебное переключение на резервный EXIT")
    drill.add_argument("--minutes", type=int, default=0, help="длительность, минут")
    args = parser.parse_args(argv)
    if args.command is None:
        args = parser.parse_args(["status"])
    if getattr(args, "minutes", 0) < 0 or getattr(args, "minutes", 0) > 240:
        parser.error("длительность учебного переключения: от 1 до 240 минут")
    try:
        cfg = load_config(args.config)
    except (OSError, ValueError, KeyError) as error:
        print(f"Настройки переключателя путей не читаются: {error}", file=sys.stderr)
        return 2
    if args.command == "status":
        return command_status(cfg, args)
    if os.geteuid() != 0:
        print("Команда меняет маршрутизацию и требует прав root.", file=sys.stderr)
        return 2
    cfg.state_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    with open(cfg.state_dir / "lock", "w", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | (fcntl.LOCK_NB if args.command == "tick" else 0))
        except OSError:
            return 0
        handler = {
            "tick": command_tick,
            "use": command_use,
            "auto": command_auto,
            "drill": command_drill,
        }[args.command]
        return handler(cfg, args)


if __name__ == "__main__":
    raise SystemExit(main())

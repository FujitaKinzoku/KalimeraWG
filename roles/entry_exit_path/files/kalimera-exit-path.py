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

Кроме «отвечает или нет» по каждому пути ведётся счёт проверок, прошедших со
второй попытки, пока путь отвечает: это потери пакетов в туннеле. Минуты, когда
путь не отвечал совсем, считаются отдельно. На выбор пути счёт не влияет, его
показывают exit-path status и cascade-check.

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
# Счёт потерь ведётся по минутам за последний час; вывод о потерях делается не
# раньше, чем наберётся столько проверок.
QUALITY_MINUTES = 60
QUALITY_MIN_PROBES = 60
REASON_FAILBACK = "основной путь снова устойчиво отвечает"
REASON_DRILL_END = "учебное переключение завершено"
REASON_RETEST = "проверка прямого транспорта"
REASON_TRANSPORT_DRILL = "учебный переход на запасной транспорт"
REASON_TRANSPORT_DRILL_END = "учебный переход на запасной транспорт завершён"
IPTABLES = ("iptables", "-w", "10")
# Цепочка, закрывающая прямой транспорт, подключается в начало обеих цепочек.
TRANSPORT_HOOKS = ("INPUT", "OUTPUT")


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
        # Первый пакет TCP-соединения ядро повторяет через 1 с. Подключение,
        # занявшее столько, прошло со второй попытки: пакет или ответ потерян.
        self.slow_probe_seconds = float(document.get("slow_probe_seconds", 0.9))
        self.loss_warn_percent = float(document.get("loss_warn_percent", 2))
        self.table = int(document["table"])
        self.state_dir = Path(document["state_dir"])
        self.mode_file = Path(document["mode_file"])
        self.hold_file = Path(document["hold_file"]) if document.get("hold_file") else None
        self.dns_via_exit = bool(document.get("dns_via_exit", False))
        self.notify_command = [str(part) for part in document.get("notify_command", [])]
        # Транспорты туннеля (см. раздел "Транспорт" ниже). Работавший транспорт
        # меняется после стольких секунд без ответа; только что выбранному даётся
        # больше: сторож на EXIT открывает его не сразу. Сторожу нужно 75 с
        # молчания прежнего транспорта, и считает он их своими проверками раз в
        # 10 с - до 95 с; затем handshake туннеля и ближайшая проверка здесь. При
        # 110 с запаса не оставалось вовсе, и одна потерянная секунда возвращала бы
        # путь на прежний транспорт.
        self.transport_fail_seconds = int(document.get("transport_fail_seconds", 60))
        self.transport_trial_seconds = int(document.get("transport_trial_seconds", 150))
        # Как часто путь на запасном транспорте проверяет прямой, пока не несёт
        # трафик, и в какой час по UTC это делает путь, который трафик несёт.
        self.transport_retest_seconds = int(document.get("transport_retest_seconds", 1800))
        hour = document.get("transport_retest_hour_utc")
        self.transport_retest_hour = None if hour is None else int(hour)
        # Цепочка межсетевого экрана, которой ENTRY закрывает у себя прямой
        # транспорт пути, пока тот идёт запасным.
        self.transport_chain = str(document.get("transport_chain", "KALIMERA-TRANSIT"))
        if not self.targets or not (1 <= self.quorum <= len(self.targets)):
            raise ValueError("число ответивших адресов должно быть от 1 до числа адресов")
        if self.fail_threshold < 1 or self.failback_seconds < 0:
            raise ValueError("порог неудач и время возврата заданы неверно")

    def interface(self, name: str) -> str:
        return str(self.paths[name]["interface"])

    def label(self, name: str) -> str:
        return str(self.paths[name].get("label", name))

    def transports(self, name: str) -> list[dict]:
        """Транспорты пути по порядку предпочтения; пусто, если транспорт один."""
        items = self.paths[name].get("transports") or []
        return items if len(items) >= 2 else []

    def transport_names(self, name: str) -> list[str]:
        return [str(item["name"]) for item in self.transports(name)]

    def transport(self, name: str, transport: str) -> dict:
        return next(item for item in self.transports(name) if item["name"] == transport)

    def transport_label(self, name: str, transport: str) -> str:
        return str(self.transport(name, transport).get("label", transport))


def load_config(path: Path = CONFIG_PATH) -> Config:
    return Config(json.loads(path.read_text(encoding="utf-8")))


def empty_state() -> dict:
    return {
        "active": PRIMARY,
        "since": 0,
        "reason": "",
        "drill_until": 0,
        "paths": {
            name: {
                "fail": 0,
                "healthy_since": None,
                "reached": None,
                "checked": 0,
                "rtt_ms": None,
                "quality": [],
                # Транспорт туннеля: какой выбран, с какого времени, отвечал ли путь
                # с тех пор, когда начались неудачи и когда проверять прямой.
                "transport": None,
                "transport_since": 0,
                "transport_ok": True,
                "fail_since": None,
                "retest_at": 0,
                "retest_now": False,
                "transport_drill_until": 0,
            }
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


def probe_target(interface: str, host: str, port: int, timeout: float) -> float | None:
    """Открыть TCP-соединение через указанный интерфейс и сразу закрыть его.

    Возвращает время подключения в секундах; None, если адрес не ответил.
    """
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.setsockopt(
                socket.SOL_SOCKET, SO_BINDTODEVICE, interface.encode("ascii") + b"\0"
            )
            connection.settimeout(timeout)
            connection.connect((host, port))
    except OSError:
        return None
    return time.monotonic() - started


def probe_path(cfg: Config, name: str) -> list[float | None]:
    """Время подключения к каждому проверочному адресу через туннель этого пути."""
    interface = cfg.interface(name)
    if not Path("/sys/class/net", interface).exists():
        return [None] * len(cfg.targets)
    with ThreadPoolExecutor(max_workers=len(cfg.targets)) as pool:
        return list(
            pool.map(
                lambda target: probe_target(interface, target[0], target[1], cfg.probe_timeout),
                cfg.targets,
            )
        )


def quality_items(history: object, now: int) -> list[list[int]]:
    """Записи счёта за последний час.

    Запись: [минута, проверок при отвечающем пути, из них с потерей, проверок,
    когда путь не отвечал совсем]. Записи прежней версии из трёх чисел
    отбрасываются: в них минуты отказа пути считались потерями.
    """
    minute = now // 60
    kept: list[list[int]] = []
    if not isinstance(history, list):
        return kept
    for item in history:
        if (
            isinstance(item, list)
            and len(item) == 4
            and all(isinstance(value, int) for value in item)
            and minute - QUALITY_MINUTES < item[0] <= minute
        ):
            kept.append(item)
    return kept


def quality_counts(entry: dict, now: int) -> tuple[int, int, int]:
    """Проверки пути за последний час: при отвечающем пути, из них с потерей,
    и проверки, когда путь не отвечал совсем."""
    items = quality_items(entry.get("quality"), now)
    return (
        sum(item[1] for item in items),
        sum(item[2] for item in items),
        sum(item[3] for item in items),
    )


def path_is_lossy(cfg: Config, entry: dict, now: int) -> bool:
    total, lost, _down = quality_counts(entry, now)
    return total >= QUALITY_MIN_PROBES and lost * 100 >= cfg.loss_warn_percent * total


def record_probe(
    state: dict, name: str, times: list[float | None], cfg: Config, now: int
) -> None:
    entry = state["paths"][name]
    answered = [value for value in times if value is not None]
    entry["reached"] = len(answered)
    entry["checked"] = now
    if len(answered) >= cfg.quorum:
        entry["fail"] = 0
        entry["fail_since"] = None
        entry["transport_ok"] = True
        if entry["healthy_since"] is None:
            entry["healthy_since"] = now
    else:
        if int(entry["fail"]) == 0:
            entry["fail_since"] = now
        entry["fail"] = int(entry["fail"]) + 1
        entry["healthy_since"] = None
    # Задержка пути - самое быстрое подключение без повторной отправки.
    clean = [value for value in answered if value < cfg.slow_probe_seconds]
    if clean:
        entry["rtt_ms"] = int(min(clean) * 1000)
    # Потери считаются только пока путь отвечает. Проверка, на которой путь не
    # ответил совсем, - отказ: его показывает счётчик неудач. Найдено на рабочем
    # каскаде: пока deploy настраивал новый резервный EXIT, туннель на ENTRY уже
    # был, но не отвечал, и шесть минут установки дали «23% потерь» на час.
    if len(answered) >= cfg.quorum:
        sample = [len(times), len(times) - len(clean), 0]
    else:
        sample = [0, 0, len(times)]
    history = quality_items(entry.get("quality"), now)
    minute = now // 60
    if history and history[-1][0] == minute:
        last = history[-1]
        history[-1] = [minute, last[1] + sample[0], last[2] + sample[1], last[3] + sample[2]]
    else:
        history.append([minute, *sample])
    entry["quality"] = history


def path_is_healthy(state: dict, name: str) -> bool:
    entry = state["paths"][name]
    return entry["healthy_since"] is not None and int(entry["fail"]) == 0


# --- Транспорт туннеля ---
#
# Туннель до EXIT идёт одним из транспортов: напрямую по UDP либо внутри TLS по
# TCP. На EXIT открыт только один; сторож транспорта открывает тот, в который
# ENTRY стучится, когда открытый молчит. Поэтому ENTRY достаточно направить
# туннель в нужный транспорт и подождать.
#
#   * путь перестал отвечать - через transport_fail_seconds пробуется следующий
#     транспорт; только что выбранному даётся transport_trial_seconds;
#   * путь на запасном транспорте время от времени проверяет прямой: пока не
#     несёт трафик - каждые transport_retest_seconds, иначе в назначенный час
#     или по команде exit-path retest, потому что проверка прерывает связь;
#   * прямой транспорт на любом сервере предпочтительнее запасного;
#   * пока путь идёт запасным транспортом, прямой закрыт и на ENTRY: иначе
#     пакеты EXIT возвращали бы туннель на прямой (см. closed_transport_rules).


def transport_rank(cfg: Config, state: dict, name: str) -> int:
    """0 - путь на прямом транспорте (или транспорт у него один), больше - на запасном."""
    names = cfg.transport_names(name)
    current = state["paths"][name].get("transport")
    return names.index(current) if current in names else 0


def retest_due(cfg: Config, state: dict, name: str, now: int) -> bool:
    entry = state["paths"][name]
    if entry.get("retest_now"):
        return True
    if state["active"] != name:
        return now >= int(entry.get("retest_at") or 0)
    # Путь несёт трафик: проверка прямого транспорта прерывает связь, поэтому она
    # идёт в назначенный час и не чаще раза за него.
    return (
        cfg.transport_retest_hour is not None
        and time.gmtime(now).tm_hour == cfg.transport_retest_hour
        and now - int(entry.get("transport_since") or 0) >= 3600
    )


def choose_transport(cfg: Config, state: dict, name: str, now: int) -> tuple[str, str]:
    """Каким транспортом идти пути. Причина пуста, если транспорт прежний."""
    entry = state["paths"][name]
    names = cfg.transport_names(name)
    current = entry["transport"]
    # Учебный переход держит запасной транспорт до конца учения, даже если тот
    # не отвечает: иначе учение не показало бы, что он не работает.
    if int(entry.get("transport_drill_until") or 0) > now:
        return names[1], (REASON_TRANSPORT_DRILL if current != names[1] else "")
    if int(entry["fail"]) > 0:
        if entry.get("transport_ok"):
            since, limit = entry.get("fail_since"), cfg.transport_fail_seconds
        else:
            since, limit = entry.get("transport_since"), cfg.transport_trial_seconds
        if since is not None and now - int(since) >= limit:
            return names[(names.index(current) + 1) % len(names)], "путь не отвечает"
        return current, ""
    if current != names[0] and retest_due(cfg, state, name, now):
        return names[0], REASON_RETEST
    return current, ""


def tunnel_endpoint(cfg: Config, name: str) -> tuple[str, str]:
    """Ключ пира туннеля и адрес, на который интерфейс отправляет пакеты."""
    try:
        output = subprocess.run(
            ["awg", "show", cfg.interface(name), "endpoints"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return "", ""
    for line in output.splitlines():
        words = line.split()
        if len(words) == 2:
            return words[0], words[1]
    return "", ""


def ensure_transport(cfg: Config, name: str, transport: str) -> None:
    """Привести туннель пути к выбранному транспорту: служба и адрес пира.

    Выполняется при каждой проверке: адрес пира возвращает к значению из
    конфигурации любой перезапуск интерфейса, например во время deploy.
    """
    for item in cfg.transports(name):
        unit = str(item.get("service") or "")
        if not unit:
            continue
        running = run_quiet(["systemctl", "is-active", "--quiet", unit]) == 0
        if item["name"] == transport and not running:
            run_quiet(["systemctl", "start", unit], timeout=60)
        elif item["name"] != transport and running:
            run_quiet(["systemctl", "stop", unit], timeout=60)
    key, endpoint = tunnel_endpoint(cfg, name)
    wanted = str(cfg.transport(name, transport)["endpoint"])
    if key and endpoint != wanted:
        run_quiet(["awg", "set", cfg.interface(name), "peer", key, "endpoint", wanted])


def closed_transport_rules(cfg: Config, state: dict) -> list[list[str]]:
    """Правила, которыми ENTRY закрывает у себя прямой транспорт путей на запасном.

    Туннель отправляет пакеты туда, откуда пришёл последний подлинный пакет пира.
    Пока сторож на EXIT не открыл запасной транспорт, EXIT продолжает слать пакеты
    напрямую - хвосты прежних соединений, keepalive, - и каждый такой пакет
    возвращал адрес пира на прямой транспорт. Найдено на рабочем каскаде: во
    время учебного перехода путь всё время отвечал напрямую, ENTRY показывал
    запасной транспорт, а сторож на EXIT так и не увидел, что открытый молчит.

    Поэтому прямой транспорт пути закрыт здесь в обе стороны, пока путь идёт
    запасным: входящие пакеты не трогают адрес пира, а исходящие не уходят на
    EXIT двумя транспортами сразу, даже в секунды после перезапуска интерфейса.
    """
    rules: list[list[str]] = []
    for name in PATH_NAMES:
        names = cfg.transport_names(name)
        current = state["paths"][name].get("transport")
        if not names or current not in names or current == names[0]:
            continue
        host, _, port = str(cfg.transport(name, names[0])["endpoint"]).rpartition(":")
        rules.append(["-s", host, "-p", "udp", "--sport", port, "-j", "DROP"])
        rules.append(["-d", host, "-p", "udp", "--dport", port, "-j", "DROP"])
    return rules


def chain_rules(chain: str) -> list[str] | None:
    """Правила цепочки межсетевого экрана; None, если цепочки нет."""
    try:
        result = subprocess.run(
            [*IPTABLES, "-S", chain], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line.startswith("-A ")]


def unhook_chain(hook: str, chain: str) -> None:
    for _ in range(8):
        if run_quiet([*IPTABLES, "-D", hook, "-j", chain]) != 0:
            return


def transport_firewall_matches(cfg: Config, rules: list[list[str]]) -> bool:
    chain = cfg.transport_chain
    present = chain_rules(chain)
    if present is None or len(present) != len(rules):
        return False
    if any(run_quiet([*IPTABLES, "-C", chain, *rule]) != 0 for rule in rules):
        return False
    # Цепочка стоит первой: раньше правил UFW, которые принимают ответные пакеты.
    for hook in TRANSPORT_HOOKS:
        hooked = chain_rules(hook)
        if not hooked or hooked[0].split() != ["-A", hook, "-j", chain]:
            return False
    return True


def sync_transport_firewall(cfg: Config, state: dict) -> bool:
    """Привести правила ENTRY к транспортам путей.

    Выполняется при каждой проверке: цепочку могла сбросить пересборка
    межсетевого экрана. Когда все пути идут прямым транспортом, цепочки нет.
    Возвращает False, если правила применить не удалось.
    """
    chain = cfg.transport_chain
    rules = closed_transport_rules(cfg, state)
    if not rules:
        if chain_rules(chain) is not None:
            for hook in TRANSPORT_HOOKS:
                unhook_chain(hook, chain)
            run_quiet([*IPTABLES, "-F", chain])
            run_quiet([*IPTABLES, "-X", chain])
        return True
    if transport_firewall_matches(cfg, rules):
        return True
    run_quiet([*IPTABLES, "-N", chain])
    done = run_quiet([*IPTABLES, "-F", chain]) == 0
    for rule in rules:
        done = run_quiet([*IPTABLES, "-A", chain, *rule]) == 0 and done
    for hook in TRANSPORT_HOOKS:
        unhook_chain(hook, chain)
        done = run_quiet([*IPTABLES, "-I", hook, "1", "-j", chain]) == 0 and done
    return done


def manage_transports(cfg: Config, state: dict, now: int) -> None:
    held = deploy_in_progress(cfg, now)
    managed: list[str] = []
    for name in PATH_NAMES:
        names = cfg.transport_names(name)
        if not names:
            continue
        managed.append(name)
        entry = state["paths"][name]
        if entry.get("transport") not in names:
            entry.update({"transport": names[0], "transport_since": now, "transport_ok": True})
        # Учебный переход закончился: путь сразу проверяет прямой транспорт.
        drill_ended = 0 < int(entry.get("transport_drill_until") or 0) <= now
        if drill_ended:
            entry["transport_drill_until"] = 0
            entry["retest_now"] = True
        # Во время deploy интерфейсы перезапускаются: транспорт не меняется, только
        # восстанавливается.
        target, reason = (entry["transport"], "") if held else choose_transport(cfg, state, name, now)
        if drill_ended and reason == REASON_RETEST:
            reason = REASON_TRANSPORT_DRILL_END
        if target != entry["transport"]:
            previous = entry["transport"]
            # Устойчивость пути считается заново: на новом транспорте он ещё не отвечал.
            entry.update(
                {
                    "transport": target,
                    "transport_since": now,
                    "transport_ok": False,
                    "retest_now": False,
                    "healthy_since": None,
                }
            )
            if target != names[0]:
                entry["retest_at"] = now + cfg.transport_retest_seconds
            message = (
                f"{cfg.label(name)}: транспорт туннеля {cfg.transport_label(name, previous)} → "
                f"{cfg.transport_label(name, target)}. Причина: {reason}."
            )
            log(message)
            # О плановой проверке прямого транспорта и об учениях не сообщается.
            if reason not in (REASON_RETEST, REASON_TRANSPORT_DRILL, REASON_TRANSPORT_DRILL_END):
                notify(cfg, message)
    if not managed:
        return
    # Сначала правила, потом адрес пира: пакет EXIT, пришедший между ними, вернул
    # бы туннель на прямой транспорт до следующей проверки.
    if not sync_transport_firewall(cfg, state):
        log("правила, закрывающие прямой транспорт на ENTRY, применить не удалось")
    for name in managed:
        ensure_transport(cfg, name, state["paths"][name]["transport"])


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
    primary_rank = transport_rank(cfg, state, PRIMARY)
    standby_rank = transport_rank(cfg, state, STANDBY)
    if active == PRIMARY:
        if int(primary["fail"]) >= cfg.fail_threshold and path_is_healthy(state, STANDBY):
            return STANDBY, "основной путь не отвечает"
        # Основной путь держится на запасном транспорте, а резервный сервер
        # устойчиво отвечает по прямому: прямой быстрее.
        if (
            primary_rank > standby_rank
            and path_is_healthy(state, STANDBY)
            and now - int(standby["healthy_since"]) >= cfg.failback_seconds
        ):
            return STANDBY, "основной путь работает через запасной транспорт"
        return PRIMARY, ""
    if int(standby["fail"]) >= cfg.fail_threshold and path_is_healthy(state, PRIMARY):
        return PRIMARY, "резервный путь не отвечает"
    healthy_since = primary["healthy_since"]
    if (
        healthy_since is not None
        and now - int(healthy_since) >= cfg.failback_seconds
        and primary_rank <= standby_rank
    ):
        return PRIMARY, REASON_FAILBACK
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
    """Направить зарубежные запросы DNS в резолвер действующего EXIT.

    Переводятся только зоны, которые уже смотрят в резолвер одного из EXIT: корневая
    и исключения se-domain внутри российских зон. Пока Unbound работает через серверы
    DoT - режим выключен либо идёт первое включение и резолвер на EXIT ещё не
    установлен, - пересылка не трогается: иначе зарубежные имена перестали бы
    разрешаться до конца deploy.
    """
    if not cfg.dns_via_exit:
        return
    control = shutil.which("unbound-control")
    peer = str(cfg.paths[name].get("peer_tunnel_address", ""))
    if not control or not peer:
        return
    peers = {str(path.get("peer_tunnel_address", "")) for path in cfg.paths.values()} - {""}
    try:
        listing = subprocess.run(
            [control, "list_forwards"], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return
    changed = False
    for line in listing.splitlines():
        # Строка вида "зона. IN forward адрес[@порт][#имя] ...".
        words = line.split()
        if len(words) < 4 or words[1:3] != ["IN", "forward"]:
            continue
        addresses = {word.split("@")[0].split("#")[0] for word in words[3:]}
        if not addresses & peers or addresses == {peer}:
            continue
        if words[0] == ".":
            run_quiet([control, "forward", f"{peer}@53"])
        else:
            run_quiet([control, "forward_remove", words[0]])
            run_quiet([control, "forward_add", words[0], f"{peer}@53"])
        changed = True
    if changed:
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
        record_probe(state, name, probe_path(cfg, name), cfg, now)
    manage_transports(cfg, state, now)
    drill_ended = 0 < int(state.get("drill_until") or 0) <= now
    if drill_ended:
        state["drill_until"] = 0
    if not state.get("since"):
        state["since"] = now
    target, reason = decide(state, mode, cfg, now)
    # Во время учения основной путь не отказывал: возврат с него называется своим
    # именем, а не восстановлением основного пути.
    if drill_ended and reason == REASON_FAILBACK:
        reason = REASON_DRILL_END
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


def format_share(part: int, total: int) -> str:
    return f"{part * 100 / total:.1f}".replace(".", ",")


def quality_text(cfg: Config, entry: dict, now: int) -> str:
    """Задержка пути и доля проверок с потерей за последний час."""
    parts: list[str] = []
    if entry.get("rtt_ms") is not None:
        parts.append(f"задержка {int(entry['rtt_ms'])} мс")
    total, lost, down = quality_counts(entry, now)
    if total < QUALITY_MIN_PROBES:
        parts.append("данных о потерях пока мало")
    elif lost == 0:
        parts.append(f"за час все проверки ({total}) прошли с первой попытки")
    else:
        verdict = ": путь теряет пакеты" if path_is_lossy(cfg, entry, now) else ""
        parts.append(
            f"за час {lost} из {total} проверок прошли со второй попытки или без ответа "
            f"({format_share(lost, total)}%){verdict}"
        )
    if down:
        parts.append(f"за час путь не отвечал совсем, проверок без ответа: {down}")
    return "; ".join(parts)


def transport_text(cfg: Config, state: dict, name: str, now: int) -> str:
    """Каким транспортом идёт туннель пути; пусто, если транспорт у пути один."""
    names = cfg.transport_names(name)
    entry = state["paths"][name]
    current = entry.get("transport")
    if current not in names:
        return ""
    label = cfg.transport_label(name, current)
    drill_until = int(entry.get("transport_drill_until") or 0)
    if drill_until > now:
        return f"транспорт: {label} (учебный переход, ещё {format_age(drill_until - now)})"
    if drill_until and current != names[0]:
        # Срок учения вышел, а очередная проверка ещё не прошла: она и вернёт путь
        # на прямой транспорт. Найдено на рабочем каскаде: в эти секунды статус
        # обещал проверку прямого транспорта через полчаса.
        return (
            f"транспорт: {label} (учебный переход завершён, возврат на прямой при "
            "следующей проверке)"
        )
    if current == names[0]:
        return f"транспорт: {label}"
    text = f"транспорт: {label} (запасной), {format_age(now - int(entry['transport_since']))}"
    if state["active"] != name:
        wait = int(entry.get("retest_at") or 0) - now
        when = "при следующей проверке" if wait <= 0 else f"через {format_age(wait)}"
        return f"{text}; прямой проверится {when}"
    if cfg.transport_retest_hour is None:
        return f"{text}; прямой проверяется по команде exit-path retest"
    return (
        f"{text}; прямой проверится в {cfg.transport_retest_hour:02d}:00 UTC "
        "или по команде exit-path retest"
    )


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
        if entry["reached"] is not None:
            lines.append(f"  {quality_text(cfg, entry, now)}")
        transport = transport_text(cfg, state, name, now)
        if transport:
            lines.append(f"  {transport}")
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
        # Путь отвечает, но проверки то и дело проходят со второй попытки:
        # скорость через него будет в разы ниже, чем обещает задержка.
        if int(entry["fail"]) == 0 and path_is_lossy(cfg, entry, now):
            total, lost, _down = quality_counts(entry, now)
            rows.append(
                (
                    "WARN",
                    f"{cfg.label(name)}: отвечает, но теряет пакеты: за час {lost} из {total} "
                    f"проверок прошли со второй попытки или без ответа ({format_share(lost, total)}%)",
                )
            )
            continue
        text = (
            f"{cfg.label(name)}: отвечает {entry['reached']} из {len(cfg.targets)} "
            "проверочных адресов"
        )
        rows.append(("OK" if int(entry["fail"]) == 0 else "WARN", text))
    # Запасной транспорт - работающий каскад, но уже без запаса: прямой путь до
    # этого сервера не проходит.
    for name in PATH_NAMES:
        entry = state["paths"][name]
        # Отметка учения снимается проверкой, которая возвращает путь на прямой
        # транспорт: до неё путь на запасном - это ещё учение, а не закрытый прямой.
        if int(entry.get("transport_drill_until") or 0):
            rows.append(("WARN", f"{cfg.label(name)}: идёт учебный переход на запасной транспорт"))
        elif int(entry["fail"]) == 0 and transport_rank(cfg, state, name) > 0:
            rows.append(
                (
                    "WARN",
                    f"{cfg.label(name)}: туннель идёт запасным транспортом "
                    f"({cfg.transport_label(name, entry['transport'])}), прямой не проходит",
                )
            )
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
    # Прерванное учение получает отметку в прошлом: проверка ниже увидит его
    # завершённым и так и назовёт возврат на основной путь.
    if int(state.get("drill_until") or 0):
        state["drill_until"] = 1
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


def command_retest(cfg: Config, _args: argparse.Namespace) -> int:
    """Проверить прямой транспорт на путях, которые идут запасным."""
    state = read_state(cfg)
    waiting = [
        name
        for name in PATH_NAMES
        if cfg.transport_names(name) and transport_rank(cfg, state, name) > 0
    ]
    if not waiting:
        print("Запасным транспортом не идёт ни один путь: проверять нечего.")
        return 0
    for name in waiting:
        state["paths"][name]["retest_now"] = True
    write_state(cfg, state)
    tick(cfg)
    names = ", ".join(cfg.label(name) for name in waiting)
    print(
        f"Проверка прямого транспорта начата: {names}. Она занимает до трёх минут; путь, "
        "который несёт трафик, на это время прерывается. Результат: exit-path status"
    )
    return 0


def command_transport_drill(cfg: Config, args: argparse.Namespace) -> int:
    """Учебный переход пути на запасной транспорт и обратно.

    Блокировать для этого ничего не нужно: ENTRY сам перестаёт пользоваться
    прямым транспортом и стучится в запасной. Сторож на EXIT видит то же, что при
    настоящей блокировке: открытый транспорт молчит, в закрытый стучатся.
    """
    name = args.path
    if not cfg.transport_names(name):
        print("Запасной транспорт не включён: учебный переход невозможен.", file=sys.stderr)
        return 1
    if 0 < args.minutes < 3:
        print(
            "Учебный переход короче трёх минут ничего не покажет: сторож на EXIT "
            "открывает запасной транспорт через полторы-две минуты.",
            file=sys.stderr,
        )
        return 1
    seconds = (args.minutes or 5) * 60
    state = read_state(cfg)
    state["paths"][name]["transport_drill_until"] = int(time.time()) + seconds
    write_state(cfg, state)
    state = tick(cfg)
    carries = state["active"] == name
    print(
        f"{cfg.label(name)}: учебный переход на запасной транспорт на {format_age(seconds)}. "
        "Сторож на EXIT откроет его через полторы-две минуты; затем путь ответит внутри TLS. "
        + (
            "Этот путь несёт трафик: на время перехода трафик уйдёт на другой сервер. "
            if carries
            else "Трафик идёт через другой сервер и переход не заметит. "
        )
        + "Ход: exit-path status; на EXIT: transport-guard status. Возврат произойдёт сам."
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
    commands.add_parser("retest", help="проверить прямой транспорт, если туннель идёт запасным")
    transport_drill = commands.add_parser(
        "transport-drill", help="учебный переход пути на запасной транспорт и обратно"
    )
    transport_drill.add_argument("path", nargs="?", choices=PATH_NAMES, default=STANDBY)
    transport_drill.add_argument("--minutes", type=int, default=0, help="длительность, минут")
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
            "retest": command_retest,
            "transport-drill": command_transport_drill,
        }[args.command]
        return handler(cfg, args)


if __name__ == "__main__":
    raise SystemExit(main())

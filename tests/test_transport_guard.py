"""Сторож транспорта на EXIT (roles/exit_transport/files/kalimera-transport-guard.py).

Требование владельца: одновременно открыт один транспорт туннеля ENTRY - EXIT,
второй не слушает и закрыт межсетевым экраном. Программа проверяется на
подставном межсетевом экране: он хранит цепочку и счётчики так же, как их видит
программа через команды iptables.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
GUARD_PATH = ROOT / "roles" / "exit_transport" / "files" / "kalimera-transport-guard.py"
SPEC = importlib.util.spec_from_file_location("kalimera_transport_guard", GUARD_PATH)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

CHAIN = "KALIMERA-TRANSPORT"
ENTRY = "192.0.2.10"


class FakeServer:
    """Межсетевой экран, туннель и службы EXIT глазами программы."""

    def __init__(self) -> None:
        self.chain: list[dict] | None = None  # правила: {"args": [...], "packets": int}
        self.input: list[list[str]] = [["-j", "ufw-before-input"]]
        self.rx = 1000
        self.awg_ok = True
        self.running: set[str] = set()
        self.start_fails: set[str] = set()
        self.calls: list[list[str]] = []

    # --- что происходит на сервере ---

    def packets_from_entry(self, proto: str, port: int, count: int = 3) -> str:
        """Пакеты ENTRY на порт: возвращает решение экрана и ведёт счётчик."""
        for rule in self.chain or []:
            args = rule["args"]
            if args[args.index("-p") + 1] == proto and args[args.index("--dport") + 1] == str(port):
                rule["packets"] += count
                return args[-1]
        return "UFW"

    def knock(self, name: str, count: int = 3) -> None:
        proto, port = {"awg": ("udp", 443), "tls": ("tcp", 443)}[name]
        self.packets_from_entry(proto, port, count)

    def tunnel_traffic(self, amount: int = 500) -> None:
        self.rx += amount

    # --- команды, которые выполняет программа ---

    def run(self, argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        done = lambda code=0, out="": subprocess.CompletedProcess(argv, code, out, "")  # noqa: E731
        if argv[:3] == ["iptables", "-w", "10"]:
            return self.iptables(argv[3:], done)
        if argv[:2] == ["awg", "show"]:
            return done(0, f"PEERKEY=\t{self.rx}\t777\n") if self.awg_ok else done(1)
        if argv[:2] == ["systemctl", "is-active"]:
            return done(0 if argv[-1] in self.running else 3)
        if argv[:2] == ["systemctl", "start"]:
            if argv[-1] in self.start_fails:
                return done(1)
            self.running.add(argv[-1])
            return done()
        if argv[:2] == ["systemctl", "stop"]:
            self.running.discard(argv[-1])
            return done()
        return done()

    def iptables(self, args: list[str], done) -> subprocess.CompletedProcess[str]:
        command = args[0]
        if command == "-N":
            if self.chain is not None:
                return done(1)
            self.chain = []
            return done()
        if command in ("-F", "-Z", "-A", "-C", "-nvxL") and args[1] == CHAIN and self.chain is None:
            return done(1)
        if command == "-F":
            self.chain = []
            return done()
        if command == "-Z":
            for rule in self.chain:
                rule["packets"] = 0
            return done()
        if command == "-A":
            self.chain.append({"args": args[2:], "packets": 0})
            return done()
        if command == "-C":
            return done(0 if any(rule["args"] == args[2:] for rule in self.chain) else 1)
        if command == "-S" and args[1] == CHAIN:
            if self.chain is None:
                return done(1)
            lines = [f"-N {CHAIN}"] + [f"-A {CHAIN} " + " ".join(rule["args"]) for rule in self.chain]
            return done(0, "\n".join(lines) + "\n")
        if command == "-S" and args[1] == "INPUT":
            lines = ["-P INPUT DROP"] + ["-A INPUT " + " ".join(rule) for rule in self.input]
            return done(0, "\n".join(lines) + "\n")
        if command == "-D" and args[1] == "INPUT":
            if args[2:] in self.input:
                self.input.remove(args[2:])
                return done()
            return done(1)
        if command == "-I" and args[1] == "INPUT":
            self.input.insert(int(args[2]) - 1, args[3:])
            return done()
        if command == "-nvxL":
            lines = [f"Chain {CHAIN} (1 references)", "    pkts      bytes target     prot opt in     out     source               destination"]
            for rule in self.chain:
                comment = ""
                if "--comment" in rule["args"]:
                    comment = f" /* {rule['args'][rule['args'].index('--comment') + 1]} */"
                lines.append(f"{rule['packets']:8d} {rule['packets'] * 60:10d} {rule['args'][-1]}{comment}")
            return done(0, "\n".join(lines) + "\n")
        raise AssertionError(f"неожиданная команда iptables: {args}")


class GuardCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.cfg = guard.Config(
            {
                "peer_ipv4": ENTRY,
                "wan_interface": "eth0",
                "awg_interface": "awg3",
                "transports": [
                    {"name": "awg", "label": "AmneziaWG по UDP", "proto": "udp", "port": 443},
                    {"name": "tls", "label": "TLS по TCP", "proto": "tcp", "port": 443,
                     "service": "kalimera-transit-tls.service"},
                ],
                "idle_seconds": 75,
                "knock_packets": 2,
                "knock_fresh_seconds": 30,
                "state_dir": str(self.dir / "run"),
                "active_file": str(self.dir / "lib" / "active"),
            }
        )
        self.server = FakeServer()
        self.messages: list[str] = []
        for name, replacement in {"run": self.server.run, "log": self.messages.append}.items():
            patcher = mock.patch.object(guard, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.now = 10_000

    def tick(self, seconds: int = 10) -> dict:
        self.now += seconds
        return guard.tick(self.cfg, self.now)

    def healthy_ticks(self, count: int) -> dict:
        """Туннель работает: между проверками от ENTRY приходят пакеты."""
        state: dict = {}
        for _ in range(count):
            self.server.tunnel_traffic()
            state = self.tick()
        return state

    def open_for_entry(self, name: str) -> bool:
        proto, port = {"awg": ("udp", 443), "tls": ("tcp", 443)}[name]
        return self.server.packets_from_entry(proto, port, 0) == "ACCEPT"


class FirewallTests(GuardCase):
    def test_first_run_opens_only_the_direct_transport(self) -> None:
        state = self.tick()
        self.assertEqual(state["active"], "awg")
        self.assertTrue(self.open_for_entry("awg"))
        self.assertFalse(self.open_for_entry("tls"))
        # Цепочка стоит раньше правил UFW и касается только адреса ENTRY.
        self.assertEqual(self.server.input[0], ["-j", CHAIN])
        for rule in self.server.chain:
            self.assertEqual(rule["args"][:4], ["-i", "eth0", "-s", ENTRY])
        # Служба второго транспорта не запущена: порт никто не слушает.
        self.assertEqual(self.server.running, set())

    def test_exactly_one_transport_is_open_at_any_moment(self) -> None:
        self.healthy_ticks(3)
        for _ in range(12):
            self.server.knock("tls")
            self.tick()
            self.assertEqual(
                sum(self.open_for_entry(name) for name in ("awg", "tls")), 1, "открыт ровно один"
            )
        self.assertTrue(self.open_for_entry("tls"))
        self.assertFalse(self.open_for_entry("awg"))
        self.assertEqual(self.server.running, {"kalimera-transit-tls.service"})

    def test_chain_lost_after_a_firewall_rebuild_is_restored(self) -> None:
        self.healthy_ticks(2)
        # Пересборка UFW: цепочка осталась, но переход в неё из INPUT пропал.
        self.server.input = [["-j", "ufw-before-input"]]
        self.healthy_ticks(1)
        self.assertEqual(self.server.input[0], ["-j", CHAIN])
        self.assertEqual(self.server.input.count(["-j", CHAIN]), 1)
        # Перезагрузка: цепочки нет совсем.
        self.server.chain = None
        self.server.input = [["-j", "ufw-before-input"]]
        self.healthy_ticks(1)
        self.assertTrue(self.open_for_entry("awg"))
        self.assertFalse(self.open_for_entry("tls"))

    def test_foreign_rule_in_the_chain_is_removed(self) -> None:
        self.healthy_ticks(2)
        self.server.chain.append({"args": ["-p", "tcp", "--dport", "22", "-j", "ACCEPT"], "packets": 0})
        self.healthy_ticks(1)
        self.assertEqual(len(self.server.chain), 2)


class SwitchTests(GuardCase):
    def test_blocked_transport_gives_way_to_the_one_entry_knocks_on(self) -> None:
        self.healthy_ticks(3)
        # UDP заблокирован: пакеты туннеля не приходят, ENTRY стучится в TCP.
        switched_after = None
        for step in range(1, 13):
            self.server.knock("tls")
            state = self.tick()
            if state["active"] == "tls" and switched_after is None:
                switched_after = step * 10
        self.assertEqual(state["active"], "tls")
        # Не раньше времени молчания и не позже одной проверки после него.
        self.assertGreaterEqual(switched_after, 75)
        self.assertLessEqual(switched_after, 90)
        self.assertEqual((self.dir / "lib" / "active").read_text(encoding="utf-8"), "tls\n")
        self.assertIn("AmneziaWG по UDP → TLS по TCP", self.messages[-1])
        self.assertEqual(state["last_switch"]["from"], "awg")

    def test_entry_that_is_down_changes_nothing(self) -> None:
        # ENTRY перезагружается: туннель молчит, но и стука нет.
        self.healthy_ticks(3)
        for _ in range(60):
            state = self.tick()
        self.assertEqual(state["active"], "awg")
        self.assertEqual(self.messages, [])
        self.assertEqual(self.server.running, set())

    def test_working_transport_cannot_be_closed_by_knocking(self) -> None:
        # Подделав адрес ENTRY, в закрытый порт можно стучать сколько угодно.
        for _ in range(30):
            self.server.tunnel_traffic()
            self.server.knock("tls", 50)
            state = self.tick()
        self.assertEqual(state["active"], "awg")
        self.assertFalse(self.open_for_entry("tls"))

    def test_old_knock_does_not_count(self) -> None:
        self.healthy_ticks(3)
        self.server.knock("tls")
        self.tick()
        # Стук был один раз, потом ENTRY замолчал совсем.
        for _ in range(20):
            state = self.tick()
        self.assertEqual(state["active"], "awg")

    def test_single_stray_packet_is_not_a_knock(self) -> None:
        self.healthy_ticks(3)
        for _ in range(12):
            self.server.knock("tls", 1)
            state = self.tick()
        self.assertEqual(state["active"], "awg")

    def test_return_to_the_direct_transport_needs_the_same_two_conditions(self) -> None:
        self.healthy_ticks(3)
        for _ in range(10):
            self.server.knock("tls")
            self.tick()
        # Туннель работает внутри TLS: стук в UDP его не закрывает.
        for _ in range(10):
            self.server.tunnel_traffic()
            self.server.knock("awg")
            state = self.tick()
        self.assertEqual(state["active"], "tls")
        # ENTRY ушёл с TLS проверить прямой путь: TLS молчит, стук в UDP приходит.
        for _ in range(10):
            self.server.knock("awg")
            state = self.tick()
        self.assertEqual(state["active"], "awg")
        self.assertEqual(self.server.running, set(), "служба TLS остановлена")
        self.assertFalse(self.open_for_entry("tls"))

    def test_new_transport_is_given_time_before_the_next_switch(self) -> None:
        self.healthy_ticks(3)
        for _ in range(10):
            self.server.knock("tls")
            state = self.tick()
        self.assertEqual(state["active"], "tls")
        switched = state["since"]
        # Сразу после перехода стук в прежний транспорт ничего не меняет: ENTRY
        # нужно время, чтобы подключиться по новому.
        while self.now + 10 - switched < 75:
            self.server.knock("awg")
            state = self.tick()
            self.assertEqual(state["active"], "tls")
        # Время вышло, по новому транспорту ENTRY так и не пришёл, а в прежний
        # стучится: сторож возвращается.
        for _ in range(2):
            self.server.knock("awg")
            state = self.tick()
        self.assertEqual(state["active"], "awg")

    def test_tunnel_counter_reset_is_not_taken_for_traffic(self) -> None:
        self.healthy_ticks(3)
        last_contact = guard.read_state(self.cfg, self.now)["last_contact"]
        # Интерфейс перезапущен: счётчик начался с нуля, пакетов от ENTRY не было.
        self.server.rx = 0
        state = self.tick()
        self.assertEqual(state["last_contact"], last_contact)
        self.server.awg_ok = False
        state = self.tick()
        self.assertEqual(state["last_contact"], last_contact)


class RestartTests(GuardCase):
    def test_transport_survives_a_reboot_of_exit(self) -> None:
        self.healthy_ticks(3)
        for _ in range(10):
            self.server.knock("tls")
            self.tick()
        # Перезагрузка EXIT: /run пуст, цепочки и службы нет.
        for path in (self.dir / "run").iterdir():
            path.unlink()
        self.server.chain = None
        self.server.input = [["-j", "ufw-before-input"]]
        self.server.running = set()
        state = self.tick()
        self.assertEqual(state["active"], "tls")
        self.assertTrue(self.open_for_entry("tls"))
        self.assertFalse(self.open_for_entry("awg"))
        self.assertEqual(self.server.running, {"kalimera-transit-tls.service"})

    def test_service_that_does_not_start_is_tried_again_and_can_be_left(self) -> None:
        self.server.start_fails.add("kalimera-transit-tls.service")
        self.healthy_ticks(3)
        for _ in range(10):
            self.server.knock("tls")
            state = self.tick()
        self.assertEqual(state["active"], "tls")
        starts = [call for call in self.server.calls if call[:2] == ["systemctl", "start"]]
        self.assertGreater(len(starts), 1)
        # ENTRY не дождался TLS и вернулся к прямому транспорту.
        for _ in range(10):
            self.server.knock("awg")
            state = self.tick()
        self.assertEqual(state["active"], "awg")

    def test_unknown_saved_transport_falls_back_to_the_first(self) -> None:
        (self.dir / "lib").mkdir()
        (self.dir / "lib" / "active").write_text("quic\n", encoding="utf-8")
        self.assertEqual(self.tick()["active"], "awg")

    def test_damaged_state_file_is_replaced(self) -> None:
        self.healthy_ticks(2)
        (self.dir / "run" / "state.json").write_text("{не json", encoding="utf-8")
        self.assertEqual(self.tick()["active"], "awg")
        json.loads((self.dir / "run" / "state.json").read_text(encoding="utf-8"))


class StatusTests(GuardCase):
    def test_status_names_the_open_and_the_closed_transport(self) -> None:
        self.healthy_ticks(3)
        text = "\n".join(guard.status_lines(self.cfg, guard.read_state(self.cfg, self.now), self.now + 5))
        self.assertIn("Открыт транспорт: AmneziaWG по UDP (udp/443)", text)
        self.assertIn("Пакеты от ENTRY по нему: 5 с назад", text)
        self.assertIn("Закрыт: TLS по TCP (tcp/443); ENTRY не стучится", text)

    def test_configuration_needs_two_distinct_transports(self) -> None:
        document = {
            "peer_ipv4": ENTRY, "wan_interface": "eth0", "awg_interface": "awg3",
            "transports": [{"name": "awg", "proto": "udp", "port": 443}],
            "state_dir": "/run/x", "active_file": "/var/lib/x/active",
        }
        with self.assertRaises(ValueError):
            guard.Config(document)
        document["transports"].append({"name": "awg", "proto": "tcp", "port": 443})
        with self.assertRaises(ValueError):
            guard.Config(document)
        document["transports"][1] = {"name": "tls", "proto": "sctp", "port": 443}
        with self.assertRaises(ValueError):
            guard.Config(document)


if __name__ == "__main__":
    unittest.main()

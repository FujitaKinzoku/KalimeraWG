"""Резервный EXIT: переключатель путей, установщик и шаблоны ENTRY.

Переключатель - отдельная программа на Python: её правила проверяются прямым
вызовом функций, а проверки туннелей и изменение маршрута подменяются. Установщик
работает с временным production inventory и настоящим Ansible Vault. Шаблоны
ENTRY рендерятся Jinja2 и запускаются в bash с подставными командами, как в
tests/test_selective_proxy.py, откуда взят общий каркас.
"""

from __future__ import annotations

import importlib.util
import json
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import jinja2
import yaml
from ansible.parsing.vault import VaultLib, VaultSecret

from test_selective_proxy import ROUTING, ShellCase, render

ROOT = Path(__file__).parents[1]
SELECTOR_PATH = ROOT / "roles" / "entry_exit_path" / "files" / "kalimera-exit-path.py"
SELECTOR_ROLE = ROOT / "roles" / "entry_exit_path"
STANDBY_CONF = ROOT / "roles" / "entry" / "templates" / "awg-standby.conf.j2"
WATCHDOG = ROOT / "roles" / "entry_watchdog" / "templates" / "awg-ru-proxy-watch.sh.j2"
SELF_HEAL = ROOT / "roles" / "health" / "templates" / "awg-self-heal.sh.j2"
CASCADE = ROOT / "roles" / "cascade_check" / "templates" / "cascade-check.sh.j2"
DEPLOY_PATH = ROOT / "scripts" / "lib" / "interactive_deploy.py"

SELECTOR_SPEC = importlib.util.spec_from_file_location("kalimera_exit_path", SELECTOR_PATH)
selector = importlib.util.module_from_spec(SELECTOR_SPEC)
SELECTOR_SPEC.loader.exec_module(selector)

DEPLOY_SPEC = importlib.util.spec_from_file_location("interactive_deploy_standby", DEPLOY_PATH)
deploy = importlib.util.module_from_spec(DEPLOY_SPEC)
DEPLOY_SPEC.loader.exec_module(deploy)

PRIMARY = selector.PRIMARY
STANDBY = selector.STANDBY
VAULT_PASSWORD = b"fixture-vault-password"
PROFILE = {
    "jc": 9, "jmin": 60, "jmax": 400, "s1": 40, "s2": 50, "s3": 30, "s4": 20,
    "h1": "100-200", "h2": "300-400", "h3": "500-600", "h4": "700-800",
    "i1": "<b 0xc3><r 100>", "i2": "<b 0x40><r 90>", "i3": "<b 0x41><r 60>",
    "i4": "<b 0x42><r 40>", "i5": "<b 0x43><r 30>",
}


class SelectorCase(unittest.TestCase):
    """Переключатель с подменёнными проверками туннелей и командами системы."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.cfg = selector.Config(
            {
                "paths": [
                    {"name": "primary", "label": "основной EXIT", "interface": "awg3",
                     "tunnel_address": "10.77.0.2", "peer_tunnel_address": "10.77.0.1"},
                    {"name": "standby", "label": "резервный EXIT", "interface": "awg4",
                     "tunnel_address": "10.78.0.2", "peer_tunnel_address": "10.78.0.1"},
                ],
                "probe_targets": [["192.0.2.1", 443], ["192.0.2.2", 443], ["192.0.2.3", 443]],
                "probe_quorum": 2,
                "probe_timeout_seconds": 1,
                "fail_threshold": 3,
                "failback_seconds": 900,
                "drill_seconds": 300,
                "table": 100,
                "state_dir": str(self.dir / "run"),
                "mode_file": str(self.dir / "lib" / "mode"),
                "hold_file": str(self.dir / "deploy.active"),
                "dns_via_exit": True,
            }
        )
        self.reach = {PRIMARY: 3, STANDBY: 3}
        # Сколько ответивших адресов ответили только на повторно отправленный пакет.
        self.slow = {PRIMARY: 0, STANDBY: 0}
        self.route = "awg3"
        self.route_ok = True
        self.routes: list[str] = []
        self.flushed: list[str] = []
        self.dns: list[str] = []
        self.messages: list[str] = []

        def set_route(_cfg, name: str) -> bool:
            if self.route_ok:
                self.route = self.cfg.interface(name)
                self.routes.append(self.route)
            return self.route_ok

        def probe_path(_cfg, name: str) -> list[float | None]:
            reached = self.reach[name]
            slow = min(self.slow[name], reached)
            return [1.05] * slow + [0.05] * (reached - slow) + [None] * (3 - reached)

        for name, replacement in {
            "probe_path": probe_path,
            "set_route": set_route,
            "current_route_interface": lambda _cfg: self.route,
            "flush_connections": lambda _cfg, previous: self.flushed.append(previous),
            "sync_dns": lambda _cfg, name: self.dns.append(name),
            "log": self.messages.append,
        }.items():
            patcher = mock.patch.object(selector, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def run_ticks(self, start: int, count: int, step: int = 10) -> dict:
        state: dict = {}
        for index in range(count):
            state = selector.tick(self.cfg, start + index * step)
        return state

    def active_file(self) -> str:
        return (self.dir / "run" / "active").read_text(encoding="utf-8").strip()


class SelectorDecisionTests(SelectorCase):
    def test_healthy_primary_keeps_the_traffic(self) -> None:
        state = self.run_ticks(1000, 5)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.routes, [])
        self.assertEqual(self.active_file(), "awg3")

    def test_switch_needs_three_failures_in_a_row(self) -> None:
        self.run_ticks(1000, 2)
        self.reach[PRIMARY] = 0
        state = self.run_ticks(1020, 2)
        self.assertEqual(state["active"], PRIMARY, "две неудачи - ещё не отказ")
        state = selector.tick(self.cfg, 1040)
        self.assertEqual(state["active"], STANDBY)
        self.assertEqual(self.routes, ["awg4"])
        self.assertEqual(self.active_file(), "awg4")
        # Соединения прежнего туннеля забыты, DNS переведён на резолвер резервного EXIT.
        self.assertEqual(self.flushed, [PRIMARY])
        self.assertEqual(self.dns[-1], STANDBY)
        self.assertIn("основной EXIT → резервный EXIT", self.messages[-1])

    def test_one_answer_of_three_is_a_failure(self) -> None:
        self.run_ticks(1000, 1)
        self.reach[PRIMARY] = 1
        state = self.run_ticks(1010, 3)
        self.assertEqual(state["active"], STANDBY)

    def test_single_failure_is_forgotten_after_a_good_probe(self) -> None:
        self.run_ticks(1000, 1)
        for moment, reached in ((1010, 0), (1020, 0), (1030, 3), (1040, 0), (1050, 0)):
            self.reach[PRIMARY] = reached
            state = selector.tick(self.cfg, moment)
        self.assertEqual(state["active"], PRIMARY)

    def test_nothing_changes_when_both_paths_are_dead(self) -> None:
        self.run_ticks(1000, 1)
        self.reach = {PRIMARY: 0, STANDBY: 0}
        state = self.run_ticks(1010, 10)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.routes, [])

    def test_dead_standby_is_never_chosen(self) -> None:
        self.reach[STANDBY] = 0
        self.run_ticks(1000, 2)
        self.reach[PRIMARY] = 0
        state = self.run_ticks(1020, 6)
        self.assertEqual(state["active"], PRIMARY)

    def test_return_waits_for_a_stable_primary(self) -> None:
        self.run_ticks(1000, 1)
        self.reach[PRIMARY] = 0
        self.run_ticks(1010, 3)
        self.reach[PRIMARY] = 3
        state = selector.tick(self.cfg, 1100)
        self.assertEqual(state["active"], STANDBY)
        state = selector.tick(self.cfg, 1100 + 890)
        self.assertEqual(state["active"], STANDBY, "основной отвечает меньше заданного времени")
        state = selector.tick(self.cfg, 1100 + 900)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.routes, ["awg4", "awg3"])
        self.assertEqual(self.flushed, [PRIMARY, STANDBY])

    def test_a_blip_restarts_the_wait_for_return(self) -> None:
        self.run_ticks(1000, 1)
        self.reach[PRIMARY] = 0
        self.run_ticks(1010, 3)
        self.reach[PRIMARY] = 3
        selector.tick(self.cfg, 1100)
        self.reach[PRIMARY] = 0
        selector.tick(self.cfg, 1600)
        self.reach[PRIMARY] = 3
        selector.tick(self.cfg, 1610)
        state = selector.tick(self.cfg, 1100 + 900)
        self.assertEqual(state["active"], STANDBY)
        state = selector.tick(self.cfg, 1610 + 900)
        self.assertEqual(state["active"], PRIMARY)

    def test_failing_standby_returns_to_a_working_primary_at_once(self) -> None:
        self.run_ticks(1000, 1)
        self.reach[PRIMARY] = 0
        self.run_ticks(1010, 3)
        self.reach = {PRIMARY: 3, STANDBY: 0}
        state = self.run_ticks(1100, 3)
        self.assertEqual(state["active"], PRIMARY)
        self.assertIn("резервный путь не отвечает", self.messages[-1])

    def test_failed_route_change_keeps_the_previous_path(self) -> None:
        self.run_ticks(1000, 1)
        self.reach[PRIMARY] = 0
        self.route_ok = False
        state = self.run_ticks(1010, 4)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.active_file(), "awg3")
        self.assertEqual(self.flushed, [])

    def test_deploy_holds_the_switch(self) -> None:
        self.run_ticks(1000, 1)
        mark = self.dir / "deploy.active"
        mark.write_text("", encoding="utf-8")
        self.reach[PRIMARY] = 0
        with mock.patch.object(selector, "deploy_in_progress", return_value=True):
            state = self.run_ticks(1010, 5)
        self.assertEqual(state["active"], PRIMARY)
        # Deploy снимает отметку последним шагом.
        mark.unlink()
        state = self.run_ticks(1100, 1)
        self.assertEqual(state["active"], STANDBY, "после deploy переключение выполняется")

    def test_route_replaced_by_someone_else_is_restored(self) -> None:
        self.run_ticks(1000, 1)
        self.route = "eth0"
        selector.tick(self.cfg, 1010)
        self.assertEqual(self.route, "awg3")

    def test_state_starts_from_the_primary_after_a_reboot(self) -> None:
        self.assertEqual(selector.read_state(self.cfg)["active"], PRIMARY)
        (self.dir / "run").mkdir()
        (self.dir / "run" / "state.json").write_text("not json", encoding="utf-8")
        self.assertEqual(selector.read_state(self.cfg)["active"], PRIMARY)


class SelectorManualTests(SelectorCase):
    def test_pinned_path_ignores_probes(self) -> None:
        selector.write_mode(self.cfg, STANDBY)
        state = self.run_ticks(1000, 2)
        self.assertEqual(state["active"], STANDBY)
        self.reach = {PRIMARY: 3, STANDBY: 0}
        state = self.run_ticks(2000, 200)
        self.assertEqual(state["active"], STANDBY, "закреплённый путь не меняется сам")
        selector.write_mode(self.cfg, "auto")
        state = self.run_ticks(5000, 3)
        self.assertEqual(state["active"], PRIMARY)

    def test_unknown_mode_file_means_automatic(self) -> None:
        self.cfg.mode_file.parent.mkdir(parents=True)
        self.cfg.mode_file.write_text("sideways\n", encoding="utf-8")
        self.assertEqual(selector.read_mode(self.cfg), "auto")

    def test_drill_switches_and_returns(self) -> None:
        self.run_ticks(1000, 100)
        state = selector.read_state(self.cfg)
        state["drill_until"] = 2000 + 300
        selector.write_state(self.cfg, state)
        state = selector.tick(self.cfg, 2000)
        self.assertEqual(state["active"], STANDBY)
        self.assertIn("учебное переключение", self.messages[-1])
        state = selector.tick(self.cfg, 2290)
        self.assertEqual(state["active"], STANDBY)
        # Основной путь всё это время отвечал, поэтому возврат сразу после учения.
        state = selector.tick(self.cfg, 2300)
        self.assertEqual(state["active"], PRIMARY)

    def test_drill_ends_when_the_standby_stops_answering(self) -> None:
        self.run_ticks(1000, 100)
        state = selector.read_state(self.cfg)
        state["drill_until"] = 2000 + 3000
        selector.write_state(self.cfg, state)
        selector.tick(self.cfg, 2000)
        self.reach[STANDBY] = 0
        state = self.run_ticks(2010, 3)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(state["drill_until"], 0)
        self.reach[STANDBY] = 3
        state = self.run_ticks(2100, 3)
        self.assertEqual(state["active"], PRIMARY, "прерванное учение не возобновляется")

    def test_drill_command_refuses_a_dead_standby(self) -> None:
        self.reach[STANDBY] = 0
        arguments = mock.Mock(minutes=0)
        with mock.patch("sys.stderr"):
            self.assertEqual(selector.command_drill(self.cfg, arguments), 1)
        self.assertEqual(selector.read_state(self.cfg)["active"], PRIMARY)


class SelectorReportTests(SelectorCase):
    def rows(self, now: int) -> list[tuple[str, str]]:
        return selector.report_rows(
            self.cfg, selector.read_state(self.cfg), selector.read_mode(self.cfg), now
        )

    def test_healthy_cascade_reports_three_ok_rows(self) -> None:
        self.run_ticks(1000, 2)
        rows = self.rows(1015)
        self.assertEqual([level for level, _ in rows], ["OK", "OK", "OK"])
        self.assertIn("через основной EXIT", rows[-1][1])

    def test_work_on_the_standby_is_a_warning(self) -> None:
        self.run_ticks(1000, 1)
        self.reach[PRIMARY] = 0
        self.run_ticks(1010, 3)
        rows = self.rows(1035)
        self.assertEqual(rows[0][0], "WARN")
        self.assertIn("основной EXIT: отвечает 0 из 3", rows[0][1])
        self.assertEqual(rows[-1], ("WARN", "зарубежный трафик идёт через резервный EXIT"))

    def test_dead_standby_is_a_warning_while_traffic_is_fine(self) -> None:
        self.reach[STANDBY] = 0
        self.run_ticks(1000, 2)
        rows = self.rows(1015)
        self.assertEqual([level for level, _ in rows], ["OK", "WARN", "OK"])

    def test_stopped_selector_is_reported(self) -> None:
        self.run_ticks(1000, 2)
        rows = self.rows(1000 + 600)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "WARN")
        self.assertIn("не проверял туннели", rows[0][1])

    def test_status_text_names_the_active_path(self) -> None:
        self.run_ticks(1000, 2)
        text = "\n".join(
            selector.status_lines(self.cfg, selector.read_state(self.cfg), "auto", 1015)
        )
        self.assertIn("Зарубежный трафик идёт через: основной EXIT (awg3)", text)
        self.assertIn("Режим: автоматический", text)
        self.assertIn("резервный EXIT (awg4): отвечает (3 из 3)", text)


class SelectorQualityTests(SelectorCase):
    """Потери пакетов на пути, который формально отвечает.

    Найдено на рабочем каскаде: туннель до резервного EXIT терял около 3% пакетов
    и давал 0,9 Мбит/с вместо 36, а команда status писала «отвечает (3 из 3), без
    сбоев 44 мин».
    """

    def status(self, now: int) -> str:
        return "\n".join(
            selector.status_lines(self.cfg, selector.read_state(self.cfg), "auto", now)
        )

    def rows(self, now: int) -> list[tuple[str, str]]:
        return selector.report_rows(
            self.cfg, selector.read_state(self.cfg), selector.read_mode(self.cfg), now
        )

    def run_lossy_ticks(self, start: int, count: int, every: int) -> None:
        """Каждая every-я проверка резервного пути проходит со второй попытки."""
        for index in range(count):
            self.slow[STANDBY] = 1 if index % every == 0 else 0
            selector.tick(self.cfg, start + index * 10)

    def test_clean_paths_show_the_delay_and_no_losses(self) -> None:
        self.run_ticks(6000, 25)
        text = self.status(6245)
        self.assertEqual(
            text.count("  задержка 50 мс; за час все проверки (75) прошли с первой попытки"), 2, text
        )
        self.assertEqual([level for level, _ in self.rows(6245)], ["OK", "OK", "OK"])

    def test_lossy_standby_is_reported_while_it_still_answers(self) -> None:
        self.run_lossy_ticks(6000, 30, every=5)
        state = selector.read_state(self.cfg)
        # Правила выбора пути потери не меняют: резервный путь по-прежнему годен.
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(state["paths"][STANDBY]["fail"], 0)
        self.assertTrue(selector.path_is_healthy(state, STANDBY))
        rows = self.rows(6295)
        self.assertEqual([level for level, _ in rows], ["OK", "WARN", "OK"])
        self.assertEqual(
            rows[1][1],
            "резервный EXIT: отвечает, но теряет пакеты: за час 6 из 90 проверок "
            "прошли со второй попытки или без ответа (6,7%)",
        )
        text = self.status(6295)
        self.assertIn("резервный EXIT (awg4): отвечает (3 из 3)", text)
        self.assertIn(
            "  задержка 50 мс; за час 6 из 90 проверок прошли со второй попытки или без ответа "
            "(6,7%): путь теряет пакеты",
            text,
        )
        self.assertIn("  задержка 50 мс; за час все проверки (90) прошли с первой попытки", text)

    def test_unanswered_probe_counts_as_a_loss(self) -> None:
        # Отвечают два адреса из трёх: путь жив по правилу большинства, но третья
        # проверка каждый раз теряется.
        self.reach[STANDBY] = 2
        self.run_ticks(6000, 20)
        rows = self.rows(6195)
        self.assertEqual(rows[1][0], "WARN")
        self.assertIn("за час 20 из 60 проверок", rows[1][1])
        self.assertIn("(33,3%)", rows[1][1])

    def test_rare_loss_stays_below_the_warning(self) -> None:
        self.run_lossy_ticks(6000, 30, every=30)
        self.assertEqual([level for level, _ in self.rows(6295)], ["OK", "OK", "OK"])
        text = self.status(6295)
        self.assertIn("за час 1 из 90 проверок прошли со второй попытки или без ответа (1,1%)", text)
        self.assertNotIn("путь теряет пакеты", text)

    def test_few_probes_give_no_verdict(self) -> None:
        self.slow[STANDBY] = 3
        self.run_ticks(6000, 2)
        self.assertEqual([level for level, _ in self.rows(6015)], ["OK", "OK", "OK"])
        text = self.status(6015)
        # Ни одного подключения с первой попытки: задержку назвать не из чего.
        self.assertIn("резервный EXIT (awg4): отвечает (3 из 3), без сбоев 15 с\n  данных о потерях пока мало", text)
        self.assertIn("  задержка 50 мс; данных о потерях пока мало", text)

    def test_losses_older_than_an_hour_are_forgotten(self) -> None:
        self.run_lossy_ticks(6000, 30, every=2)
        self.assertEqual(self.rows(6295)[1][0], "WARN")
        self.slow[STANDBY] = 0
        self.run_ticks(6000 + 2 * 3600, 25)
        later = 6000 + 2 * 3600 + 245
        self.assertEqual([level for level, _ in self.rows(later)], ["OK", "OK", "OK"])
        self.assertIn("за час все проверки (75) прошли с первой попытки", self.status(later))
        history = selector.read_state(self.cfg)["paths"][STANDBY]["quality"]
        self.assertTrue(all(item[0] > (later // 60) - 60 for item in history), history)

    def test_state_of_the_previous_version_is_accepted(self) -> None:
        # Служба обновляется на работающем ENTRY: в /run лежит состояние без новых
        # полей, а испорченный счёт не должен останавливать проверки.
        run = self.dir / "run"
        run.mkdir()
        (run / "state.json").write_text(
            json.dumps(
                {
                    "active": "primary",
                    "since": 5000,
                    "reason": "",
                    "drill_until": 0,
                    "paths": {
                        "primary": {"fail": 0, "healthy_since": 5000, "reached": 3, "checked": 5990},
                        "standby": {
                            "fail": 0, "healthy_since": 5000, "reached": 3, "checked": 5990,
                            "quality": "мусор", "rtt_ms": None,
                        },
                    },
                    "last_switch": None,
                }
            ),
            encoding="utf-8",
        )
        state = selector.tick(self.cfg, 6000)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(state["paths"][PRIMARY]["healthy_since"], 5000)
        self.assertEqual(state["paths"][PRIMARY]["quality"], [[100, 3, 0]])
        self.assertEqual(state["paths"][STANDBY]["quality"], [[100, 3, 0]])
        self.assertEqual(state["paths"][STANDBY]["rtt_ms"], 50)


class SelectorProbeTests(unittest.TestCase):
    def test_probe_returns_the_connect_time_or_nothing(self) -> None:
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        with mock.patch.object(selector.socket, "socket", return_value=connection), \
                mock.patch.object(selector.time, "monotonic", side_effect=[10.0, 10.25]):
            self.assertAlmostEqual(selector.probe_target("awg4", "192.0.2.1", 443, 3), 0.25)
        connection.setsockopt.assert_called_once_with(
            selector.socket.SOL_SOCKET, selector.SO_BINDTODEVICE, b"awg4\0"
        )
        connection.connect.side_effect = OSError("timed out")
        with mock.patch.object(selector.socket, "socket", return_value=connection):
            self.assertIsNone(selector.probe_target("awg4", "192.0.2.1", 443, 3))

    def test_missing_interface_answers_nothing(self) -> None:
        cfg = selector.Config(
            {
                "paths": [
                    {"name": "primary", "interface": "kalimera-none0"},
                    {"name": "standby", "interface": "kalimera-none1"},
                ],
                "probe_targets": [["192.0.2.1", 443], ["192.0.2.2", 443]],
                "probe_quorum": 1,
                "probe_timeout_seconds": 1,
                "fail_threshold": 3,
                "failback_seconds": 900,
                "table": 100,
                "state_dir": "/nonexistent/run",
                "mode_file": "/nonexistent/mode",
            }
        )
        self.assertEqual(selector.probe_path(cfg, PRIMARY), [None, None])


class SelectorSystemTests(unittest.TestCase):
    def config(self, directory: Path, **overrides) -> object:
        document = {
            "paths": [
                {"name": "primary", "interface": "awg3", "tunnel_address": "10.77.0.2",
                 "peer_tunnel_address": "10.77.0.1"},
                {"name": "standby", "interface": "awg4", "tunnel_address": "10.78.0.2",
                 "peer_tunnel_address": "10.78.0.1"},
            ],
            "probe_targets": [["192.0.2.1", 443]],
            "probe_quorum": 1,
            "probe_timeout_seconds": 1,
            "fail_threshold": 3,
            "failback_seconds": 900,
            "table": 100,
            "state_dir": str(directory / "run"),
            "mode_file": str(directory / "mode"),
            "dns_via_exit": True,
        }
        document.update(overrides)
        return selector.Config(document)

    def test_dns_follows_the_active_exit_only_when_it_differs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self.config(Path(temporary))
            calls: list[list[str]] = []
            listing = mock.Mock(stdout=". IN forward 10.77.0.1@53\nru. IN forward 77.88.8.8\n")
            with mock.patch.object(selector.shutil, "which", return_value="/usr/sbin/unbound-control"), \
                    mock.patch.object(selector.subprocess, "run", return_value=listing), \
                    mock.patch.object(selector, "run_quiet", side_effect=lambda argv, **_: calls.append(argv) or 0):
                selector.sync_dns(cfg, PRIMARY)
                self.assertEqual(calls, [], "резолвер уже тот, что нужен")
                selector.sync_dns(cfg, STANDBY)
            self.assertEqual(calls[0], ["/usr/sbin/unbound-control", "forward", "10.78.0.1@53"])

    def test_dns_is_left_alone_when_it_does_not_go_through_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self.config(Path(temporary), dns_via_exit=False)
            with mock.patch.object(selector.shutil, "which") as which:
                selector.sync_dns(cfg, STANDBY)
            which.assert_not_called()

    def test_connections_of_the_previous_tunnel_are_forgotten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self.config(Path(temporary))
            calls: list[list[str]] = []
            with mock.patch.object(selector.shutil, "which", side_effect=lambda name: f"/usr/sbin/{name}"), \
                    mock.patch.object(selector, "run_quiet", side_effect=lambda argv, **_: calls.append(argv) or 0):
                selector.flush_connections(cfg, PRIMARY)
            self.assertEqual(
                calls,
                [
                    ["/usr/sbin/conntrack", "-D", "--reply-dst", "10.77.0.2"],
                    ["/usr/sbin/conntrack", "-D", "--orig-src", "10.77.0.2"],
                    # Сокеты самого ENTRY, привязанные к адресу прежнего туннеля.
                    ["/usr/sbin/ss", "-K", "-4", "src", "10.77.0.2"],
                ],
            )

    def test_missing_tools_do_not_stop_the_switch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self.config(Path(temporary))
            with mock.patch.object(selector.shutil, "which", return_value=None), \
                    mock.patch.object(selector, "run_quiet") as run_quiet:
                selector.flush_connections(cfg, PRIMARY)
                selector.sync_dns(cfg, STANDBY)
            run_quiet.assert_not_called()

    def test_switch_is_announced_through_the_telegram_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cfg = self.config(
                Path(temporary), notify_command=["/usr/local/sbin/awg-telegram-monitor", "--notify"]
            )
            calls: list[list[str]] = []
            with mock.patch.object(selector, "run_quiet", side_effect=lambda argv, **_: calls.append(argv) or 0):
                selector.notify(cfg, "Зарубежный трафик переведён")
            self.assertEqual(
                calls,
                [["/usr/local/sbin/awg-telegram-monitor", "--notify", "Зарубежный трафик переведён"]],
            )
            calls.clear()
            with mock.patch.object(selector, "run_quiet", side_effect=lambda argv, **_: calls.append(argv) or 0):
                selector.notify(self.config(Path(temporary)), "текст")
            self.assertEqual(calls, [], "без Telegram-монитора сообщение не отправляется")

    def test_forgotten_deploy_mark_expires(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            mark = directory / "deploy.active"
            mark.write_text("", encoding="utf-8")
            cfg = self.config(directory, hold_file=str(mark))
            now = int(mark.stat().st_mtime)
            self.assertTrue(selector.deploy_in_progress(cfg, now + 60))
            self.assertFalse(selector.deploy_in_progress(cfg, now + 3 * 3600 + 1))

    def test_broken_settings_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                self.config(Path(temporary), probe_quorum=5)
            with self.assertRaises(ValueError):
                self.config(Path(temporary), paths=[{"name": "primary", "interface": "awg3"}])

    def test_role_settings_are_valid_for_the_program(self) -> None:
        environment = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
        environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
        environment.filters["to_nice_json"] = lambda value, **kwargs: json.dumps(value, indent=4, **kwargs)
        defaults = yaml.safe_load((SELECTOR_ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
        defaults = {key: value for key, value in defaults.items() if "{{" not in str(value)}
        text = environment.from_string(
            (SELECTOR_ROLE / "templates" / "config.json.j2").read_text(encoding="utf-8")
        ).render(
            **defaults,
            entry_exit_interface="awg3",
            entry_exit_tunnel_address="10.77.0.2/32",
            awg3_peer_tunnel_address="10.77.0.1",
            entry_standby_exit_interface="awg4",
            entry_standby_exit_tunnel_address="10.78.0.2/32",
            entry_standby_exit_peer_tunnel_address="10.78.0.1",
            entry_exit_table=100,
            entry_dns_default_via_exit=True,
        )
        cfg = selector.Config(json.loads(text))
        self.assertEqual(cfg.interface(STANDBY), "awg4")
        self.assertEqual(cfg.paths[PRIMARY]["tunnel_address"], "10.77.0.2")
        self.assertEqual(cfg.label(STANDBY), "резервный EXIT")
        self.assertEqual(len(cfg.targets), 3)
        self.assertEqual(cfg.quorum, 2)
        self.assertTrue(cfg.dns_via_exit)
        self.assertEqual(str(cfg.hold_file), "/run/kalimera-deploy.active")
        self.assertEqual(cfg.notify_command, [], "без Telegram-монитора уведомлять нечем")


class StandbyRoutingTests(ShellCase):
    tools = ("ip", "iptables", "iptables-restore", "ipset")

    def apply(self, *, standby: bool, active: str | None = None) -> list[str]:
        ports = self.dir / "ru-direct-ports"
        ports.write_text("", encoding="utf-8")
        (self.dir / "proxy-udp.mode").write_text("proxy\n", encoding="utf-8")
        self.flag("missing-sb-ru")
        if active is not None:
            state = self.run_dir / "kalimera-exit-path"
            state.mkdir(exist_ok=True)
            (state / "active").write_text(active + "\n", encoding="utf-8")
        script = self.install(
            "awg-entry-routing",
            render(
                ROUTING,
                entry_client_interface="awg0",
                entry_client_subnet="10.66.0.0/24",
                entry_client_listen_address="10.66.0.1",
                entry_exit_interface="awg3",
                entry_ru_proxy_interface="sb-ru",
                entry_wan_interface="eth0",
                entry_exit_mark="0x1",
                entry_exit_table=100,
                entry_exit_rule_priority=100,
                entry_ru_mark="0x2",
                entry_ru_table=200,
                entry_ru_rule_priority=110,
                entry_ru_direct_tcp_ports_file=str(ports),
                entry_ru_proxy_disabled_flag=str(self.dir / "proxy.disabled"),
                entry_ru_proxy_manual_disabled_flag=str(self.dir / "proxy.manual-off"),
                entry_ru_proxy_udp_mode_path=str(self.dir / "proxy-udp.mode"),
                entry_ru_zone_cache_path=str(self.dir / "ru.zone"),
                entry_ru_proxy_enabled=False,
                entry_ru_proxy_scope="all",
                entry_ru_proxy_address_file=str(self.policy / "proxy-address"),
                entry_standby_exit_enabled=standby,
                entry_standby_exit_interface="awg4",
            ),
        )
        result = self.execute(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.calls.read_text(encoding="utf-8").splitlines()

    def test_cascade_without_a_standby_is_unchanged(self) -> None:
        calls = self.apply(standby=False, active="awg4")
        self.assertIn("ip route replace default dev awg3 table 100", calls)
        self.assertFalse([line for line in calls if "awg4" in line])

    def test_both_tunnels_get_nat_and_the_primary_gets_the_route(self) -> None:
        calls = self.apply(standby=True)
        self.assertIn("ip route replace default dev awg3 table 100", calls)
        for interface in ("awg3", "awg4", "eth0"):
            self.assertIn(
                f"iptables -w 10 -t nat -A POSTROUTING -s 10.66.0.0/24 -o {interface} -j MASQUERADE",
                calls,
            )

    def test_route_follows_the_path_chosen_by_the_selector(self) -> None:
        calls = self.apply(standby=True, active="awg4")
        self.assertIn("ip route replace default dev awg4 table 100", calls)
        self.assertNotIn("ip route replace default dev awg3 table 100", calls)
        # Запасной маршрут unreachable остаётся и при работе на резервном пути.
        self.assertIn("ip route replace unreachable default metric 4294967295 table 100", calls)

    def test_unknown_name_in_the_state_file_means_the_primary(self) -> None:
        calls = self.apply(standby=True, active="eth0")
        self.assertIn("ip route replace default dev awg3 table 100", calls)

    def test_missing_standby_interface_means_the_primary(self) -> None:
        self.flag("missing-awg4")
        calls = self.apply(standby=True, active="awg4")
        self.assertIn("ip route replace default dev awg3 table 100", calls)


class StandbyTemplateTests(unittest.TestCase):
    def test_standby_tunnel_has_its_own_keys_profile_and_port(self) -> None:
        text = render(
            STANDBY_CONF,
            vault_awg_entry_standby_exit_private_key="PRIVATE",
            vault_awg_entry_standby_exit_peer_public_key="PEER",
            vault_awg_entry_standby_exit_psk="PSK",
            vault_awg_standby_header_protection_key="HEADER",
            entry_standby_exit_tunnel_address="10.78.0.2/32",
            entry_standby_exit_peer_tunnel_address="10.78.0.1",
            entry_standby_exit_listen_port=39747,
            entry_standby_exit_endpoint="198.51.100.7:443",
            entry_standby_exit_allowed_ips=["0.0.0.0/0"],
            entry_standby_exit_persistent_keepalive=25,
            entry_standby_exit_obfuscation=PROFILE,
            entry_awg1_mtu=1420,
            awg3_shared_effective_mtu=1368,
            awg3_content_padding_addition="0",
            awg3_rekey_after_time="120-180",
            awg3_rekey_timeout="5-8",
            awg3_reject_after_time="180-240",
            awg3_keepalive_timeout="10-15",
            awg3_max_handshake_attempts="18-24",
            awg3_random_trailers=False,
            awg3_disable_cookies=False,
        )
        for line in (
            "PrivateKey = PRIVATE",
            "Address = 10.78.0.2/32",
            "ListenPort = 39747",
            "MTU = 1368",
            # Маршрут таблицы EXIT выбирает переключатель путей, а не awg-quick.
            "Table = off",
            "PostUp = ip -4 route replace 10.78.0.1/32 dev %i",
            "S4 = 20",
            "HeaderProtectionKey = HEADER",
            "PublicKey = PEER",
            "PresharedKey = PSK",
            "AllowedIPs = 0.0.0.0/0",
            "Endpoint = 198.51.100.7:443",
            "PersistentKeepalive = 25",
        ):
            self.assertIn(line + "\n", text)

    def test_watchdog_accepts_either_tunnel_only_with_a_standby(self) -> None:
        source = WATCHDOG.read_text(encoding="utf-8")
        environment = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
        environment.filters["quote"] = lambda value: shlex.quote(str(value))
        environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
        plain = environment.from_string(source).render(entry_exit_interface="awg3")
        self.assertIn('grep -Eq "^default .*dev ${EXIT_IF}( |$)"', plain)
        self.assertNotIn("STANDBY_EXIT_IF", plain)
        standby = environment.from_string(source).render(
            entry_exit_interface="awg3",
            entry_standby_exit_enabled=True,
            entry_standby_exit_interface="awg4",
        )
        self.assertIn("readonly STANDBY_EXIT_IF=awg4\n", standby)
        self.assertIn('dev (${EXIT_IF}|${STANDBY_EXIT_IF})( |$)', standby)

    def classify(self, label: str, *, active: str | None, standby: bool = True) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            active_file = directory / "active"
            if active is not None:
                active_file.write_text(active + "\n", encoding="utf-8")
            environment = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
            environment.filters["quote"] = lambda value: shlex.quote(str(value))
            environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
            text = environment.from_string(SELF_HEAL.read_text(encoding="utf-8")).render(
                awg_node_role="entry",
                entry_exit_interface="awg3",
                entry_standby_exit_enabled=standby,
                entry_standby_exit_interface="awg4",
                entry_exit_path_active_file=str(active_file),
            )
            body = (
                "set -Eeuo pipefail\nreadonly unit_prefix='модуль systemd '\n"
                + text[text.index("classify() {"):text.index("# Порядок выполнения")]
                + f"classify {shlex.quote(label)}\n"
                + 'printf \'%s|%s\\n\' "$plan_action" "$plan_reason"\n'
            )
            result = subprocess.run(
                [shlex.split("bash")[0], "-c", body], capture_output=True, text=True, timeout=30
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            return result.stdout.strip()

    def test_dead_primary_is_not_restarted_while_traffic_is_on_the_standby(self) -> None:
        from test_selective_proxy import bash_path

        bash_path()
        label = "свежий handshake ENTRY–EXIT"
        self.assertEqual(self.classify(label, active="awg3"), "transit|")
        self.assertEqual(self.classify(label, active=None), "transit|")
        plan = self.classify(label, active="awg4")
        self.assertTrue(plan.startswith("|external:основной EXIT не отвечает"), plan)
        # Без резервного EXIT файл состояния ничего не значит.
        self.assertEqual(self.classify(label, active="awg4", standby=False), "transit|")

    def test_standby_tunnel_and_selector_have_their_own_repairs(self) -> None:
        from test_selective_proxy import bash_path

        bash_path()
        self.assertEqual(
            self.classify("служба AWG до резервного EXIT", active=None), "transit_standby|"
        )
        self.assertEqual(
            self.classify("таймер переключателя путей EXIT", active=None), "timer_exit_path|"
        )
        self.assertEqual(
            self.classify("MTU интерфейса резервного EXIT применён", active=None), "|deploy"
        )


def write_vault(path: Path, document: dict) -> None:
    vault = VaultLib([("default", VaultSecret(VAULT_PASSWORD))])
    path.write_bytes(vault.encrypt(yaml.safe_dump(document, sort_keys=False).encode("utf-8")))


def read_vault(path: Path) -> dict:
    vault = VaultLib([("default", VaultSecret(VAULT_PASSWORD))])
    return yaml.safe_load(vault.decrypt(path.read_bytes()))


class InstallerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        (self.home / ".ssh").mkdir(parents=True)
        (self.home / ".ssh" / "awg-iac-production").write_text("key\n", encoding="utf-8")
        (self.home / ".ssh" / "awg-iac-production.pub").write_text("pub\n", encoding="utf-8")
        self.production = self.root / "production"
        self.vault_password = self.root / "vault.pass"
        self.vault_password.write_bytes(VAULT_PASSWORD + b"\n")
        group_vars = self.production / "group_vars"
        (group_vars / "all").mkdir(parents=True)
        self.hosts_path = self.production / "hosts.yml"
        self.all_path = group_vars / "all" / "main.yml"
        self.vault_path = group_vars / "all" / "vault.yml"
        self.entry_path = group_vars / "entry.yml"
        self.exit_path = group_vars / "exit.yml"
        self.front_path = group_vars / "front.yml"
        deploy.yaml_write(
            self.hosts_path,
            {
                "all": {
                    "children": {
                        "entry": {"hosts": {"entry-managed": {
                            "ansible_connection": "local",
                            "runtime_secrets_share_index": 1,
                        }}},
                        "exit": {"hosts": {"exit-managed": {
                            "ansible_host": "192.0.2.20",
                            "ansible_user": "kalimera",
                            "ansible_port": 56777,
                            "ssh_listen_port": 56777,
                            "runtime_secrets_share_index": 2,
                        }}},
                        "front": {"hosts": {"front-managed": {
                            "ansible_host": "192.0.2.30",
                            "ansible_port": 56777,
                            "ssh_listen_port": 56777,
                            "runtime_secrets_share_index": 3,
                        }}},
                    }
                }
            },
        )
        deploy.yaml_write(
            self.all_path,
            {
                "security_finalize_admin_access": True,
                "security_manage_admin_account": True,
                "security_admin_authorized_keys": ["ssh-ed25519 AAAA admin"],
            },
        )
        deploy.yaml_write(
            self.entry_path,
            {
                "awg3_transit_enabled": False,
                "entry_manage_awg_configs": True,
                "awg3_transit_listen_port": 39745,
                "security_interserver_listen_port": 39745,
                "security_interserver_peer_ipv4": "192.0.2.20",
                "front_public_ipv4": "192.0.2.30",
                "entry_awg0_listen_port": 443,
                "entry_mobile_client_listen_port": 8443,
                "entry_mobile_legacy_internal_port": 39746,
                "entry_client_subnet": "10.66.0.0/24",
                "entry_mobile_client_subnet": "10.68.0.0/24",
                "entry_awg1_obfuscation": dict(PROFILE),
            },
        )
        deploy.yaml_write(
            self.exit_path,
            {
                "awg3_transit_enabled": False,
                "exit_awg_subnet": "10.77.0.0/24",
                "exit_awg_listen_port": 443,
                "security_interserver_peer_ipv4": "192.0.2.10",
            },
        )
        deploy.yaml_write(self.front_path, {"awg_node_role": "front"})
        write_vault(
            self.vault_path,
            {
                "vault_awg_exit_private_key": "primary-exit-key",
                "vault_runtime_secret_key_sha256": "0" * 64,
                "vault_runtime_secret_shares": [
                    f"kalimerawgruntimev1-{index}-{'ab' * 32}" for index in range(1, 6)
                ],
                "vault_entry_kalimera_password": "entry-password",
                "vault_entry_kalimera_password_hash": "$6$entry",
                "vault_entry_root_password_hash": "$6$entryroot",
                "vault_exit_kalimera_password": "exit-password",
                "vault_exit_kalimera_password_hash": "$6$exit",
                "vault_exit_root_password_hash": "$6$exitroot",
                "vault_front_kalimera_password": "front-password",
                "vault_front_kalimera_password_hash": "$6$front",
                "vault_front_root_password_hash": "$6$frontroot",
            },
        )
        patcher = mock.patch.object(deploy.Path, "home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    CLEAN_ROUTE = {"count": 100, "clean": 100, "slow": 0, "failed": 0, "rtt_ms": 90}

    def enable(
        self,
        address: str = "198.51.100.7",
        user: str = "root",
        route: dict | None = None,
        proceed: bool = False,
    ) -> bool:
        answers = iter([address, user])
        ports = iter([22, 56777])
        with mock.patch.object(deploy, "prompt", side_effect=lambda *_a, **_k: next(answers)), \
                mock.patch.object(deploy, "prompt_port", side_effect=lambda *_a, **_k: next(ports)), \
                mock.patch.object(deploy.getpass, "getpass", return_value="initial-password"), \
                mock.patch.object(deploy, "require_public_endpoint"), \
                mock.patch.object(deploy, "resolve_single_public_ipv4", side_effect=lambda value, _label: value), \
                mock.patch.object(deploy, "bootstrap_key", return_value="initial-password") as bootstrap, \
                mock.patch.object(deploy, "remote_observed_ssh_source_ipv4", return_value="192.0.2.10"), \
                mock.patch.object(
                    deploy, "probe_tcp_route", return_value=dict(route or self.CLEAN_ROUTE)
                ) as probe, \
                mock.patch.object(deploy, "prompt_bool", return_value=proceed) as asked, \
                mock.patch.object(deploy, "ui_panel") as panel, \
                mock.patch("builtins.print"):
            self.bootstrap = bootstrap
            self.probe = probe
            self.asked = asked
            self.panel = panel
            return deploy.enable_standby_exit(self.production, self.vault_password)

    def disable(self, confirm: bool = True, active: str = "awg3") -> bool:
        """Отключение резервного EXIT; active - интерфейс, выбранный переключателем."""
        state_dir = Path(self.tmp.name) / "exit-path"
        state_dir.mkdir(exist_ok=True)
        (state_dir / "active").write_text(active + "\n", encoding="utf-8")
        entry = deploy.load_yaml(self.entry_path)
        if entry.get("entry_standby_exit_enabled"):
            entry["entry_exit_path_state_dir"] = str(state_dir)
            deploy.yaml_write(self.entry_path, entry)
        with mock.patch.object(deploy, "prompt_bool", return_value=confirm) as asked, \
                mock.patch.object(deploy, "forget_ssh_host") as forget, \
                mock.patch.object(deploy, "ui_panel") as panel, \
                mock.patch("builtins.print"):
            self.asked = asked
            self.forget = forget
            self.panel = panel
            return deploy.disable_standby_exit(self.production, self.vault_password)


class InstallerTests(InstallerCase):
    def test_standby_exit_is_added_as_the_second_exit_host(self) -> None:
        self.assertTrue(self.enable())
        hosts = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"]
        self.assertEqual(list(hosts), ["exit-managed", "exit-standby-managed"])
        standby = hosts["exit-standby-managed"]
        self.assertTrue(standby["exit_standby"])
        self.assertEqual(standby["ansible_host"], "198.51.100.7")
        self.assertEqual(standby["ansible_port"], 22)
        self.assertEqual(standby["ssh_listen_port"], 56777)
        self.assertTrue(standby["security_allow_ssh_port_change"])
        self.assertEqual(standby["security_automation_source_ipv4"], "192.0.2.10")
        self.assertEqual(standby["exit_awg_subnet"], "10.78.0.0/24")
        self.assertEqual(standby["exit_awg_address"], "10.78.0.1/24")
        self.assertEqual(standby["awg3_peer_tunnel_address"], "10.78.0.2")
        # Роль exit читает прежние имена секретов; у резервного сервера они ведут
        # к его собственным ключам, а не к ключам основного EXIT.
        self.assertEqual(standby["vault_awg_exit_private_key"], "{{ vault_awg_standby_exit_private_key }}")
        self.assertEqual(standby["vault_exit_peers"], "{{ vault_standby_exit_peers }}")
        self.assertEqual(
            standby["vault_awg3_header_protection_key"], "{{ vault_awg_standby_header_protection_key }}"
        )
        self.bootstrap.assert_called_once()

    def test_entry_gets_the_second_tunnel(self) -> None:
        self.enable()
        entry = deploy.load_yaml(self.entry_path)
        self.assertTrue(entry["entry_standby_exit_enabled"])
        self.assertEqual(entry["entry_standby_exit_interface"], "awg4")
        self.assertEqual(entry["entry_standby_exit_public_ipv4"], "198.51.100.7")
        self.assertEqual(entry["entry_standby_exit_endpoint"], "198.51.100.7:443")
        self.assertEqual(entry["entry_standby_exit_tunnel_address"], "10.78.0.2/32")
        self.assertEqual(entry["entry_standby_exit_peer_tunnel_address"], "10.78.0.1")
        self.assertEqual(entry["entry_standby_exit_subnet"], "10.78.0.0/24")
        # 39746 занят прежней схемой мобильного AWG, поэтому взят следующий порт.
        self.assertEqual(entry["entry_standby_exit_listen_port"], 39747)
        profile = entry["entry_standby_exit_obfuscation"]
        self.assertEqual(profile["s4"], PROFILE["s4"], "S4 общий: MTU каскада один на оба пути")
        self.assertNotEqual(profile["h1"], PROFILE["h1"])
        deploy.validate_awg_obfuscation(profile)
        standby = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"][
            "exit-standby-managed"
        ]
        self.assertEqual(standby["exit_awg_obfuscation"], profile)
        self.assertEqual(standby["awg3_peer_endpoint_port"], 39747)

    def test_keys_of_the_two_ends_match_and_the_primary_is_untouched(self) -> None:
        self.enable()
        vault = read_vault(self.vault_path)
        self.assertEqual(vault["vault_awg_exit_private_key"], "primary-exit-key")
        self.assertEqual(
            vault["vault_awg_entry_standby_exit_peer_public_key"],
            deploy.awg_public_key(vault["vault_awg_standby_exit_private_key"]),
        )
        peer = vault["vault_standby_exit_peers"][0]
        self.assertEqual(
            peer["public_key"], deploy.awg_public_key(vault["vault_awg_entry_standby_exit_private_key"])
        )
        self.assertEqual(peer["preshared_key"], vault["vault_awg_entry_standby_exit_psk"])
        self.assertEqual(peer["allowed_ips"], ["10.78.0.2/32"])
        self.assertEqual(len(vault["vault_awg_standby_header_protection_key"]), 44)
        self.assertNotIn("vault_exit_standby_become_password", vault)

    def test_exit_role_finds_entry_in_the_peers_of_the_standby(self) -> None:
        # Роль exit требует, чтобы адрес ENTRY в туннеле был в AllowedIPs списка
        # peers. Общее значение каскада относится к туннелю основного EXIT.
        self.enable()
        standby = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"][
            "exit-standby-managed"
        ]
        peers = read_vault(self.vault_path)["vault_standby_exit_peers"]
        self.assertEqual(standby["awg_interserver_entry_address"], "10.78.0.2/32")
        self.assertIn(standby["awg_interserver_entry_address"], peers[0]["allowed_ips"])
        role = (ROOT / "roles" / "exit" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("awg_interserver_entry_address in", role)

    def test_inventory_written_by_an_earlier_build_is_completed(self) -> None:
        self.enable()
        document = deploy.load_yaml(self.hosts_path)
        del document["all"]["children"]["exit"]["hosts"]["exit-standby-managed"][
            "awg_interserver_entry_address"
        ]
        deploy.yaml_write(self.hosts_path, document)
        with mock.patch("builtins.print"):
            self.assertTrue(deploy.repair_standby_exit_inventory(self.production))
            self.assertFalse(deploy.repair_standby_exit_inventory(self.production))
        standby = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"][
            "exit-standby-managed"
        ]
        self.assertEqual(standby["awg_interserver_entry_address"], "10.78.0.2/32")

    def test_cascade_without_a_standby_is_not_touched_by_the_repair(self) -> None:
        before = self.hosts_path.read_text(encoding="utf-8")
        self.assertFalse(deploy.repair_standby_exit_inventory(self.production))
        self.assertEqual(self.hosts_path.read_text(encoding="utf-8"), before)

    def test_new_server_goes_through_the_two_step_ssh_transition(self) -> None:
        self.enable()
        self.assertIs(deploy.load_yaml(self.all_path)["security_finalize_admin_access"], False)

    def test_non_root_login_keeps_its_password_in_the_vault(self) -> None:
        self.enable(user="ubuntu")
        vault = read_vault(self.vault_path)
        self.assertEqual(vault["vault_exit_standby_become_password"], "initial-password")
        standby = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"][
            "exit-standby-managed"
        ]
        self.assertEqual(standby["ansible_become_password"], "{{ vault_exit_standby_become_password }}")

    def test_second_run_changes_nothing(self) -> None:
        self.enable()
        before = self.hosts_path.read_text(encoding="utf-8")
        self.assertFalse(self.enable(address="198.51.100.99"))
        self.assertEqual(self.hosts_path.read_text(encoding="utf-8"), before)

    def test_address_of_another_cascade_server_is_refused(self) -> None:
        for address in ("192.0.2.20", "192.0.2.10", "192.0.2.30"):
            with self.subTest(address=address), self.assertRaises(SystemExit):
                self.enable(address=address)
        hosts = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"]
        self.assertEqual(list(hosts), ["exit-managed"])

    def test_userspace_transit_is_refused_before_any_question(self) -> None:
        entry = deploy.load_yaml(self.entry_path)
        entry["awg3_transit_enabled"] = True
        deploy.yaml_write(self.entry_path, entry)
        with self.assertRaises(SystemExit):
            self.enable()
        self.bootstrap.assert_not_called()

    def test_failed_key_installation_leaves_the_inventory_as_it_was(self) -> None:
        before = self.entry_path.read_text(encoding="utf-8")
        answers = iter(["198.51.100.7", "root"])
        ports = iter([22, 56777])
        with mock.patch.object(deploy, "prompt", side_effect=lambda *_a, **_k: next(answers)), \
                mock.patch.object(deploy, "prompt_port", side_effect=lambda *_a, **_k: next(ports)), \
                mock.patch.object(deploy.getpass, "getpass", return_value="initial-password"), \
                mock.patch.object(deploy, "require_public_endpoint"), \
                mock.patch.object(deploy, "resolve_single_public_ipv4", side_effect=lambda value, _label: value), \
                mock.patch.object(deploy, "bootstrap_key", side_effect=SystemExit(1)), \
                mock.patch.object(deploy, "probe_tcp_route", return_value=dict(self.CLEAN_ROUTE)), \
                mock.patch.object(deploy, "ui_panel"), mock.patch("builtins.print"):
            with self.assertRaises(SystemExit):
                deploy.enable_standby_exit(self.production, self.vault_password)
        self.assertEqual(self.entry_path.read_text(encoding="utf-8"), before)
        self.assertNotIn("vault_awg_standby_exit_private_key", read_vault(self.vault_path))

    # Проверка маршрута до нового сервера. Найдено на рабочем каскаде: сервер был
    # исправен, а маршрут между хостингами терял 3-5% пакетов - это выяснилось
    # только после установки.

    def test_clean_route_is_checked_and_asks_nothing(self) -> None:
        self.assertTrue(self.enable())
        self.probe.assert_called_once_with("198.51.100.7", 22)
        self.asked.assert_not_called()
        self.bootstrap.assert_called_once()

    def test_lossy_route_stops_the_connection_unless_the_owner_insists(self) -> None:
        before_hosts = self.hosts_path.read_text(encoding="utf-8")
        before_entry = self.entry_path.read_text(encoding="utf-8")
        lossy = {"count": 100, "clean": 91, "slow": 8, "failed": 1, "rtt_ms": 95}
        with self.assertRaises(SystemExit) as stopped:
            self.enable(route=lossy)
        self.assertEqual(stopped.exception.code, 0)
        self.asked.assert_called_once_with("Всё равно подключить этот сервер", False)
        text = " ".join(self.panel.call_args.args[1])
        self.assertIn("с первой попытки прошли 91, со второй - 8, без ответа - 1", text)
        self.bootstrap.assert_not_called()
        self.assertEqual(self.hosts_path.read_text(encoding="utf-8"), before_hosts)
        self.assertEqual(self.entry_path.read_text(encoding="utf-8"), before_entry)
        self.assertNotIn("vault_awg_standby_exit_private_key", read_vault(self.vault_path))
        # Владелец настоял: сервер подключается, как обычно.
        self.assertTrue(self.enable(route=lossy, proceed=True))
        self.bootstrap.assert_called_once()

    def test_single_slow_connection_is_not_a_reason_to_ask(self) -> None:
        self.assertTrue(self.enable(route={"count": 100, "clean": 99, "slow": 1, "failed": 0, "rtt_ms": 95}))
        self.asked.assert_not_called()

    def test_silent_port_is_reported_before_anything_changes(self) -> None:
        before = self.hosts_path.read_text(encoding="utf-8")
        with self.assertRaises(SystemExit) as stopped:
            self.enable(route={"count": 5, "clean": 0, "slow": 0, "failed": 5, "rtt_ms": None})
        self.assertNotEqual(stopped.exception.code, 0)
        self.bootstrap.assert_not_called()
        self.assertEqual(self.hosts_path.read_text(encoding="utf-8"), before)

    def test_route_is_not_measured_from_a_machine_that_is_not_entry(self) -> None:
        document = deploy.load_yaml(self.hosts_path)
        entry = document["all"]["children"]["entry"]["hosts"]["entry-managed"]
        del entry["ansible_connection"]
        entry["ansible_host"] = "192.0.2.10"
        deploy.yaml_write(self.hosts_path, document)
        self.assertTrue(self.enable())
        self.probe.assert_not_called()

    def test_probe_counts_the_connections_that_needed_a_second_attempt(self) -> None:
        # Времена подключения: два чистых, одно со второй попытки, одно без ответа.
        # Значения точно представимы в двоичном виде: разность часов без погрешности.
        outcomes = iter([0.0625, 0.125, 1.5, None])
        clock = {"now": 100.0}

        def connect(_address, timeout):
            value = next(outcomes)
            if value is None:
                raise OSError("timed out")
            clock["now"] += value
            return mock.MagicMock()

        with mock.patch.object(deploy.socket, "create_connection", side_effect=connect) as created, \
                mock.patch.object(deploy.time, "monotonic", side_effect=lambda: clock["now"]), \
                mock.patch.object(deploy.time, "sleep") as pause:
            result = deploy.probe_tcp_route("198.51.100.7", 22, count=4)
        self.assertEqual(result, {"count": 4, "clean": 2, "slow": 1, "failed": 1, "rtt_ms": 125})
        created.assert_called_with(("198.51.100.7", 22), timeout=5.0)
        self.assertEqual(pause.call_count, 3)

    def test_probe_gives_up_on_a_closed_port(self) -> None:
        with mock.patch.object(deploy.socket, "create_connection", side_effect=OSError("refused")) as created, \
                mock.patch.object(deploy.time, "sleep"):
            result = deploy.probe_tcp_route("198.51.100.7", 22)
        self.assertEqual(created.call_count, 5)
        self.assertEqual(result, {"count": 5, "clean": 0, "slow": 0, "failed": 5, "rtt_ms": None})

    def test_tunnel_subnet_avoids_the_occupied_ones(self) -> None:
        self.assertEqual(str(deploy.standby_transit_network(["10.77.0.0/24"])), "10.78.0.0/24")
        self.assertEqual(
            str(deploy.standby_transit_network(["10.78.0.0/24", "10.79.0.1/24", None, "bad"])),
            "10.80.0.0/24",
        )


class StandbyRemovalTests(InstallerCase):
    """Отключение резервного EXIT: без него сервер нельзя было ни заменить, ни убрать."""

    def exit_hosts(self) -> list[str]:
        return list(deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"])

    def test_disable_returns_the_cascade_to_one_exit(self) -> None:
        self.enable()
        self.assertTrue(self.disable())
        self.asked.assert_called_once_with("Отключить резервный EXIT", False)
        self.assertEqual(self.exit_hosts(), ["exit-managed"])
        entry = deploy.load_yaml(self.entry_path)
        self.assertEqual([key for key in entry if key.startswith("entry_standby_exit_")], [])
        # Остальные настройки ENTRY на месте.
        self.assertEqual(entry["awg3_transit_listen_port"], 39745)
        self.assertEqual(entry["entry_awg1_obfuscation"], PROFILE)
        vault = read_vault(self.vault_path)
        self.assertEqual([key for key in deploy.STANDBY_EXIT_VAULT_KEYS if key in vault], [])
        self.assertEqual(vault["vault_awg_exit_private_key"], "primary-exit-key")
        self.forget.assert_called_once_with("198.51.100.7", {22, 56777})
        # Владельцу сказано, что сам сервер остаётся с ключами.
        self.assertIn("удалите сервер у хостера", " ".join(self.panel.call_args.args[1]))

    def test_disable_is_refused_while_traffic_goes_through_the_standby(self) -> None:
        self.enable()
        with self.assertRaises(SystemExit) as stopped:
            self.disable(active="awg4")
        self.assertNotEqual(stopped.exception.code, 0)
        self.asked.assert_not_called()
        self.assertEqual(self.exit_hosts(), ["exit-managed", "exit-standby-managed"])
        self.assertIn("vault_awg_standby_exit_private_key", read_vault(self.vault_path))

    def test_declined_disable_changes_nothing(self) -> None:
        self.enable()
        before = self.hosts_path.read_text(encoding="utf-8")
        with self.assertRaises(SystemExit) as stopped:
            self.disable(confirm=False)
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(self.hosts_path.read_text(encoding="utf-8"), before)
        self.assertTrue(deploy.load_yaml(self.entry_path)["entry_standby_exit_enabled"])
        self.forget.assert_not_called()

    def test_cascade_without_a_standby_has_nothing_to_disable(self) -> None:
        before = self.hosts_path.read_text(encoding="utf-8")
        self.assertFalse(self.disable())
        self.asked.assert_not_called()
        self.assertEqual(self.hosts_path.read_text(encoding="utf-8"), before)

    def test_interrupted_disable_is_finished_by_the_next_run(self) -> None:
        self.enable()
        document = deploy.load_yaml(self.hosts_path)
        del document["all"]["children"]["exit"]["hosts"]["exit-standby-managed"]
        deploy.yaml_write(self.hosts_path, document)
        self.assertTrue(self.disable())
        entry = deploy.load_yaml(self.entry_path)
        self.assertEqual([key for key in entry if key.startswith("entry_standby_exit_")], [])
        self.assertNotIn("vault_awg_standby_exit_private_key", read_vault(self.vault_path))
        self.assertFalse(self.disable())

    def test_password_of_a_non_root_login_leaves_the_vault(self) -> None:
        self.enable(user="ubuntu")
        self.assertIn("vault_exit_standby_become_password", read_vault(self.vault_path))
        self.disable()
        self.assertNotIn("vault_exit_standby_become_password", read_vault(self.vault_path))

    def test_share_is_freed_and_goes_to_the_next_standby(self) -> None:
        self.enable()
        with mock.patch("builtins.print"):
            deploy.ensure_runtime_secret_material(self.production, self.vault_password)
        self.assertIn(
            "exit-standby-managed", read_vault(self.vault_path)["vault_runtime_exchange_public_keys"]
        )
        self.disable()
        with mock.patch("builtins.print"):
            deploy.ensure_runtime_secret_material(self.production, self.vault_password)
        vault = read_vault(self.vault_path)
        # Ключ обмена долями отключённого сервера убран: остальные ему больше не отвечают.
        self.assertNotIn("exit-standby-managed", vault["vault_runtime_exchange_public_keys"])
        self.assertNotIn("exit-standby-managed", vault["vault_runtime_exchange_private_keys"])
        children = deploy.load_yaml(self.hosts_path)["all"]["children"]
        self.assertEqual(
            [
                values["runtime_secrets_share_index"]
                for group in ("entry", "exit", "front")
                for values in children[group]["hosts"].values()
            ],
            [1, 2, 3],
        )
        # Новый сервер подключается той же командой и получает освободившуюся долю.
        self.assertTrue(self.enable(address="198.51.100.99"))
        with mock.patch("builtins.print"):
            deploy.ensure_runtime_secret_material(self.production, self.vault_password)
        standby = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"][
            "exit-standby-managed"
        ]
        self.assertEqual(standby["ansible_host"], "198.51.100.99")
        self.assertEqual(standby["runtime_secrets_share_index"], 4)

    def test_host_keys_of_the_removed_server_are_forgotten(self) -> None:
        ssh_dir = self.home / ".ssh"
        ssh_dir.mkdir(parents=True, exist_ok=True)
        (ssh_dir / "known_hosts").write_text("198.51.100.7 ssh-ed25519 AAAA\n", encoding="utf-8")
        calls: list[list[str]] = []
        with mock.patch.object(deploy.shutil, "which", return_value="/usr/bin/ssh-keygen"), \
                mock.patch.object(
                    deploy.subprocess, "run", side_effect=lambda argv, **_k: calls.append(argv)
                ):
            deploy.forget_ssh_host("198.51.100.7", {22, 56777})
        known_hosts = str(ssh_dir / "known_hosts")
        self.assertEqual(
            calls,
            [
                ["/usr/bin/ssh-keygen", "-R", "198.51.100.7", "-f", known_hosts],
                ["/usr/bin/ssh-keygen", "-R", "[198.51.100.7]:56777", "-f", known_hosts],
            ],
        )

    def test_admin_gateway_allows_both_commands(self) -> None:
        gateway = (
            ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("'--resume --enable-standby-exit'|'--resume --disable-standby-exit'|", gateway)

    def test_entry_roles_remove_what_the_standby_left(self) -> None:
        # Отключение меняет только inventory: туннель, переключатель и настройку
        # модуля на ENTRY убирают роли при обычном deploy.
        entry_role = (ROOT / "roles" / "entry" / "tasks" / "main.yml").read_text(encoding="utf-8")
        selector_role = (SELECTOR_ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        operations = (ROOT / "roles" / "operations" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("Остановка туннеля отключённого резервного EXIT", entry_role)
        self.assertIn("Удаление конфигурации отключённого резервного EXIT", entry_role)
        self.assertIn("Удаление файлов отключённого переключателя путей EXIT", selector_role)
        self.assertIn(
            "Удаление восстановления состояния интерфейса отключённого резервного EXIT", operations
        )


class InstallerFollowUpTests(InstallerCase):
    def test_existing_servers_keep_their_shares_and_the_standby_takes_the_free_one(self) -> None:
        self.enable()
        with mock.patch("builtins.print"):
            deploy.ensure_runtime_secret_material(self.production, self.vault_password)
        children = deploy.load_yaml(self.hosts_path)["all"]["children"]
        indices = {
            name: values["runtime_secrets_share_index"]
            for group in ("entry", "exit", "front")
            for name, values in children[group]["hosts"].items()
        }
        self.assertEqual(
            indices,
            {"entry-managed": 1, "exit-managed": 2, "front-managed": 3, "exit-standby-managed": 4},
        )
        vault = read_vault(self.vault_path)
        self.assertEqual(
            set(vault["vault_runtime_exchange_public_keys"]),
            {"entry-managed", "exit-managed", "front-managed", "exit-standby-managed"},
        )
        # Пятая доля - аварийная копия владельца: серверу она не выдаётся.
        self.assertNotIn(5, indices.values())

    def test_both_exit_servers_share_the_exit_accounts(self) -> None:
        self.enable()
        with mock.patch("builtins.print"):
            deploy.ensure_admin_account_material(self.production, self.vault_password, ROOT)
        hosts = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"]
        for name in ("exit-managed", "exit-standby-managed"):
            self.assertEqual(
                hosts[name]["security_admin_password_hash"], "{{ vault_exit_kalimera_password_hash }}"
            )
            self.assertEqual(
                hosts[name]["security_root_password_hash"], "{{ vault_exit_root_password_hash }}"
            )

    def test_exit_servers_are_rebooted_one_by_one_standby_first(self) -> None:
        plain = deploy.load_yaml(self.hosts_path)
        self.assertEqual(deploy.cascade_reboot_plan(plain), ["front", "exit", "entry"])
        self.enable()
        self.assertEqual(
            deploy.cascade_reboot_plan(deploy.load_yaml(self.hosts_path)),
            ["front", "exit-standby-managed", "exit-managed", "entry"],
        )
        self.assertEqual(deploy.SERVER_NAMES["exit-standby-managed"], "EXIT резервный")


class CascadeCheckStandbyTests(unittest.TestCase):
    def setUp(self) -> None:
        from test_cascade_check import bash_path, cascade_values
        from test_cascade_check import render as render_cascade

        self.bash = bash_path()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.rows = self.dir / "rows.tsv"
        self.rows.write_text("", encoding="utf-8")
        self.exit_path = self.dir / "exit-path"
        values = cascade_values(self.dir)
        values.update(
            cascade_check_standby_present=True,
            cascade_check_standby_host="198.51.100.7",
            cascade_check_standby_port=56777,
            cascade_check_cdn_enabled=False,
            entry_exit_path_command_path=str(self.exit_path),
        )
        self.script = self.dir / "cascade-check"
        self.script.write_text(render_cascade(CASCADE, **values), encoding="utf-8")
        self.plain = self.dir / "cascade-check-plain"
        self.plain.write_text(render_cascade(CASCADE, **cascade_values(self.dir)), encoding="utf-8")

    def run_body(self, body: str, script: Path | None = None) -> subprocess.CompletedProcess[str]:
        preamble = (
            f"source {shlex.quote(str(script or self.script))}\n"
            f"work={shlex.quote(str(self.dir))}\n"
            f"rows_file={shlex.quote(str(self.rows))}\n"
        )
        return subprocess.run(
            [self.bash, "-c", preamble + body],
            capture_output=True,
            text=True,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "KALIMERA_REPORT_STYLE": "plain"},
            timeout=60,
        )

    def test_selector_rows_become_entry_rows(self) -> None:
        self.exit_path.write_text(
            "#!/bin/sh\n"
            "printf 'OK\\tосновной EXIT: отвечает 3 из 3 проверочных адресов\\n'\n"
            "printf 'WARN\\tрезервный EXIT: отвечает 0 из 3 проверочных адресов\\n'\n"
            "printf 'OK\\tзарубежный трафик идёт через основной EXIT\\n'\n",
            encoding="utf-8",
        )
        self.exit_path.chmod(0o755)
        result = self.run_body('path_rows\ncat "$rows_file"\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("\t") for line in result.stdout.splitlines()]
        self.assertEqual([row[:2] for row in rows], [["ENTRY", "OK"], ["ENTRY", "WARN"], ["ENTRY", "OK"]])
        self.assertEqual(rows[1][2], "пути до EXIT: резервный EXIT: отвечает 0 из 3 проверочных адресов")
        self.assertIn("exit-path status", rows[1][4])

    def test_silent_selector_is_a_warning(self) -> None:
        self.exit_path.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        self.exit_path.chmod(0o755)
        result = self.run_body('path_rows\ncat "$rows_file"\n')
        self.assertEqual(result.stdout.split("\t")[:3], ["ENTRY", "WARN", "пути до EXIT"])

    def test_standby_report_has_its_own_section_and_summary_line(self) -> None:
        self.rows.write_text(
            "ENTRY\tOK\tслужба\t\t\t\n"
            "EXIT\tOK\tслужба\t\t\t\n"
            "EXIT2\tWARN\tсамовосстановление: за 7 дней сбоев 1, восстановлено 0\tошибка\tподсказка\t\n"
            "FRONT\tOK\tслужба\t\t\t\n"
            "LINK\tOK\tENTRY → EXIT: SSH\tTCP 50 мс\t\t50\n"
            "LINK\tOK\tENTRY → EXIT резервный: SSH\tTCP 70 мс\t\t70\n",
            encoding="utf-8",
        )
        result = self.run_body("render\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("EXIT резервный: удалённый отчёт", result.stdout)
        self.assertIn("EXIT резервный: OK 0 · WARN 1 · FAIL 0", result.stdout)
        self.assertRegex(result.stdout, r"EXIT резервный: OK 0 · WARN 1 · FAIL 0 · .*70 мс")
        self.assertIn("EXIT резервный: за 7 дней сбоев 1", result.stdout)

    def test_cascade_without_a_standby_has_no_such_section(self) -> None:
        self.rows.write_text("ENTRY\tOK\tслужба\t\t\t\nEXIT\tOK\tслужба\t\t\t\n", encoding="utf-8")
        result = self.run_body("render\n", script=self.plain)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("резервный", result.stdout)


if __name__ == "__main__":
    unittest.main()

"""Транспорт туннеля в переключателе путей на ENTRY.

У каждого пути до EXIT два транспорта: прямой (AmneziaWG по UDP) и запасной (тот
же туннель внутри TLS по TCP). На EXIT открыт один; сторож транспорта открывает
тот, в который ENTRY стучится. Здесь проверяются решения ENTRY: когда уходить на
запасной транспорт, когда проверять прямой и какой путь выбирать для трафика.
Сам EXIT подменён таблицей "какой транспорт какого сервера сейчас проходит".
"""

from __future__ import annotations

import copy
import subprocess
import time
import unittest
from unittest import mock

from test_standby_exit import PRIMARY, STANDBY, SelectorCase, selector

TLS_UNIT = "kalimera-transit-tls@{}.service"


def path_document(name: str, label: str, interface: str, subnet: int, address: str) -> dict:
    return {
        "name": name,
        "label": label,
        "interface": interface,
        "tunnel_address": f"10.{subnet}.0.2",
        "peer_tunnel_address": f"10.{subnet}.0.1",
        "transports": [
            {"name": "awg", "label": "прямой", "endpoint": f"{address}:443"},
            {"name": "tls", "label": "внутри TLS", "endpoint": "127.0.0.1:20443",
             "service": TLS_UNIT.format(name)},
        ],
    }


class TransportCase(SelectorCase):
    def setUp(self) -> None:
        super().setUp()
        self.document = {
            "paths": [
                path_document("primary", "основной EXIT", "awg3", 77, "198.51.100.1"),
                path_document("standby", "резервный EXIT", "awg4", 78, "198.51.100.2"),
            ],
            "probe_targets": [["192.0.2.1", 443], ["192.0.2.2", 443], ["192.0.2.3", 443]],
            "probe_quorum": 2,
            "probe_timeout_seconds": 1,
            "fail_threshold": 3,
            "failback_seconds": 900,
            "table": 100,
            "state_dir": str(self.dir / "run"),
            "mode_file": str(self.dir / "lib" / "mode"),
            "hold_file": str(self.dir / "deploy.active"),
            "transport_fail_seconds": 60,
            "transport_trial_seconds": 150,
            "transport_retest_seconds": 1800,
        }
        self.cfg = selector.Config(self.document)
        # Какой транспорт какого сервера проходит. Сторож на EXIT открывает тот, в
        # который стучится ENTRY, поэтому путь отвечает, если проходит выбранный.
        self.passes = {
            (PRIMARY, "awg"): True, (PRIMARY, "tls"): True,
            (STANDBY, "awg"): True, (STANDBY, "tls"): True,
        }
        self.applied: list[tuple[str, str]] = []
        self.notices: list[str] = []
        # Что ENTRY закрывает у себя на каждой проверке и в каком порядке идут
        # правила и перевод адреса пира.
        self.closed: list[list[list[str]]] = []
        self.sequence: list[object] = []
        self.firewall_ok = True

        def ensure_transport(_cfg, path: str, transport: str) -> None:
            self.applied.append((path, transport))
            self.sequence.append((path, transport))

        def sync_transport_firewall(cfg, state: dict) -> bool:
            self.closed.append(selector.closed_transport_rules(cfg, state))
            self.sequence.append("firewall")
            return self.firewall_ok

        for name, replacement in {
            "ensure_transport": ensure_transport,
            "sync_transport_firewall": sync_transport_firewall,
            "notify": lambda _cfg, message: self.notices.append(message),
        }.items():
            patcher = mock.patch.object(selector, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.now = 100_000

    def transport(self, name: str) -> str:
        return selector.read_state(self.cfg)["paths"][name]["transport"] or "awg"

    def step(self, seconds: int = 10) -> dict:
        self.now += seconds
        for name in (PRIMARY, STANDBY):
            self.reach[name] = 3 if self.passes[(name, self.transport(name))] else 0
        return selector.tick(self.cfg, self.now)

    def steps(self, count: int) -> dict:
        state: dict = {}
        for _ in range(count):
            state = self.step()
        return state

    def until(self, condition, limit: int = 400) -> int:
        """Шагать, пока условие не выполнится; вернуть прошедшие секунды."""
        started = self.now
        for _ in range(limit):
            if condition(self.step()):
                return self.now - started
        self.fail("условие не выполнилось за отведённое время")


class FallbackTests(TransportCase):
    def test_healthy_paths_stay_on_the_direct_transport(self) -> None:
        state = self.steps(6)
        self.assertEqual(state["paths"][PRIMARY]["transport"], "awg")
        self.assertEqual(state["paths"][STANDBY]["transport"], "awg")
        self.assertEqual(set(self.applied), {(PRIMARY, "awg"), (STANDBY, "awg")})
        self.assertEqual(self.notices, [])

    def test_blocked_direct_transport_moves_the_tunnel_into_tls(self) -> None:
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = False
        # Трафик уходит на резервный сервер за три проверки, как и раньше.
        took = self.until(lambda state: state["active"] == STANDBY)
        self.assertEqual(took, 30)
        # Сам основной путь пробует запасной транспорт через минуту без ответа.
        took += self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls")
        self.assertEqual(took, 70)
        self.assertIn("основной EXIT: транспорт туннеля прямой → внутри TLS", self.notices[-1])
        state = self.step()
        self.assertEqual(state["paths"][PRIMARY]["fail"], 0)
        self.assertTrue(state["paths"][PRIMARY]["transport_ok"])
        self.assertEqual(self.applied[-2:], [(PRIMARY, "tls"), (STANDBY, "awg")])

    def test_path_on_tls_has_its_direct_transport_closed_on_entry(self) -> None:
        # Найдено на рабочем каскаде: адрес пира туннеля следует за последним
        # подлинным пакетом, и пакеты EXIT по прямому транспорту возвращали туннель
        # на него. Учебный переход шёл напрямую, а сторож на EXIT не переключался.
        self.steps(3)
        self.assertEqual(self.closed[-1], [], "пока пути идут напрямую, ENTRY ничего не закрывает")
        self.passes[(PRIMARY, "awg")] = False
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls")
        self.assertEqual(
            self.closed[-1],
            [
                ["-s", "198.51.100.1", "-p", "udp", "--sport", "443", "-j", "DROP"],
                ["-d", "198.51.100.1", "-p", "udp", "--dport", "443", "-j", "DROP"],
            ],
            "закрыт прямой транспорт только того сервера, который идёт запасным",
        )
        # Правила раньше адреса пира: пакет EXIT между ними вернул бы туннель назад.
        self.assertEqual(self.sequence[-3:], ["firewall", (PRIMARY, "tls"), (STANDBY, "awg")])
        # Прямой транспорт ожил: при его проверке ENTRY снова его открывает.
        self.passes[(PRIMARY, "awg")] = True
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "awg", limit=400)
        self.assertEqual(self.closed[-1], [])

    def test_rules_that_fail_to_apply_are_logged(self) -> None:
        self.steps(3)
        self.firewall_ok = False
        self.messages.clear()
        self.step()
        self.assertEqual(
            self.messages, ["правила, закрывающие прямой транспорт на ENTRY, применить не удалось"]
        )

    def test_both_transports_dead_alternate_without_touching_the_healthy_path(self) -> None:
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = self.passes[(PRIMARY, "tls")] = False
        seen: list[str] = []
        for _ in range(60):
            state = self.step()
            transport = state["paths"][PRIMARY]["transport"]
            if not seen or seen[-1] != transport:
                seen.append(transport)
        # Прямой - минута, запасной - время, за которое сторож успел бы его открыть.
        self.assertEqual(seen[:4], ["awg", "tls", "awg", "tls"])
        self.assertEqual(state["active"], STANDBY)
        self.assertEqual(state["paths"][STANDBY]["transport"], "awg")
        self.assertEqual(state["paths"][STANDBY]["fail"], 0)

    def test_fresh_transport_gets_time_for_the_guard_on_exit(self) -> None:
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = self.passes[(PRIMARY, "tls")] = False
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls")
        switched = self.now
        took = self.until(lambda state: state["paths"][PRIMARY]["transport"] == "awg")
        # Сторож открывает транспорт через 75-95 с молчания прежнего (свои проверки
        # раз в 10 с), затем нужны handshake туннеля и проверка пути: новому
        # транспорту даётся больше, чем работавшему, и с запасом.
        self.assertEqual(took, 150)
        self.assertGreaterEqual(self.now - switched, 95 + 30)
        # То же значение действует без явной настройки.
        plain = {key: value for key, value in self.document.items() if key != "transport_trial_seconds"}
        self.assertEqual(selector.Config(plain).transport_trial_seconds, 150)

    def test_single_exit_in_trouble_runs_on_tls(self) -> None:
        # Резервный сервер недоступен целиком, у основного закрыт UDP.
        self.passes[(STANDBY, "awg")] = self.passes[(STANDBY, "tls")] = False
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = False
        took = self.until(lambda state: state["paths"][PRIMARY]["fail"] == 0 and
                          state["paths"][PRIMARY]["transport"] == "tls")
        self.assertLessEqual(took, 80)
        state = self.steps(30)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(state["paths"][PRIMARY]["transport"], "tls", "трафик не прерывается проверками")

    def test_deploy_does_not_change_the_transport(self) -> None:
        self.steps(3)
        (self.dir / "deploy.active").write_text("", encoding="utf-8")
        self.passes[(PRIMARY, "awg")] = False
        with mock.patch.object(selector, "deploy_in_progress", return_value=True):
            state = self.steps(12)
        self.assertEqual(state["paths"][PRIMARY]["transport"], "awg")
        # Адрес пира при этом восстанавливается на каждой проверке.
        self.assertIn((PRIMARY, "awg"), self.applied[-2:])


class PreferenceTests(TransportCase):
    def test_traffic_does_not_return_to_a_primary_that_runs_on_tls(self) -> None:
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = False
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls")
        # Основной путь отвечает внутри TLS дольше времени возврата, но резервный
        # сервер работает по прямому транспорту.
        state = self.steps(120)
        self.assertEqual(state["paths"][PRIMARY]["fail"], 0)
        self.assertEqual(state["active"], STANDBY)

    def test_active_primary_on_tls_yields_to_a_standby_on_the_direct_transport(self) -> None:
        self.passes[(STANDBY, "awg")] = self.passes[(STANDBY, "tls")] = False
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = False
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls" and
                   state["paths"][PRIMARY]["fail"] == 0)
        # Резервный сервер вернулся и отвечает по прямому транспорту.
        self.passes[(STANDBY, "awg")] = True
        recovered = self.now
        self.until(lambda state: state["active"] == STANDBY, limit=200)
        self.assertGreaterEqual(self.now - recovered, 900)
        state = selector.read_state(self.cfg)
        self.assertEqual(state["last_switch"]["reason"], "основной путь работает через запасной транспорт")

    def test_both_paths_on_tls_prefer_the_primary_as_before(self) -> None:
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = self.passes[(STANDBY, "awg")] = False
        self.until(lambda state: all(
            state["paths"][name]["transport"] == "tls" and state["paths"][name]["fail"] == 0
            for name in (PRIMARY, STANDBY)
        ))
        self.until(lambda state: state["active"] == PRIMARY, limit=200)


class RetestTests(TransportCase):
    def on_tls(self) -> None:
        """Основной путь на запасном транспорте, трафик на резервном сервере."""
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = False
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls" and
                   state["paths"][PRIMARY]["fail"] == 0)

    def test_idle_path_retests_the_direct_transport_and_comes_back(self) -> None:
        self.on_tls()
        started = self.now
        self.notices.clear()
        routes = list(self.routes)
        took = self.until(lambda state: state["paths"][PRIMARY]["transport"] == "awg", limit=400)
        self.assertGreaterEqual(took, 1800 - 20)
        self.assertLessEqual(took, 1800 + 20)
        # Прямой по-прежнему закрыт: через время на попытку путь возвращается в TLS.
        took = self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls")
        self.assertEqual(took, 150)
        state = self.step()
        self.assertEqual(state["paths"][PRIMARY]["fail"], 0)
        self.assertGreaterEqual(state["paths"][PRIMARY]["retest_at"], self.now + 1700)
        # Проверки идут по расписанию и уведомлений не дают; возврат в TLS даёт.
        self.assertEqual(len(self.notices), 1)
        self.assertIn("прямой → внутри TLS", self.notices[0])
        # Найдено тестом: в момент ухода на прямой транспорт путь ещё числился
        # устойчивым по времени, набранному внутри TLS, и трафик возвращался на
        # него до того, как прямой транспорт хоть раз ответил.
        self.assertEqual(state["active"], STANDBY)
        self.assertEqual(self.routes, routes, "трафик проверку не заметил")
        self.assertGreater(self.now - started, 1800)

    def test_recovered_direct_transport_brings_the_traffic_back_to_the_primary(self) -> None:
        self.on_tls()
        self.passes[(PRIMARY, "awg")] = True
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "awg" and
                   state["paths"][PRIMARY]["fail"] == 0, limit=400)
        recovered = self.now
        self.until(lambda state: state["active"] == PRIMARY, limit=200)
        self.assertGreaterEqual(self.now - recovered, 900 - 10)
        self.assertEqual(self.transport(PRIMARY), "awg")

    def test_path_that_carries_traffic_is_retested_only_at_the_set_hour(self) -> None:
        self.cfg.transport_retest_hour = 3
        self.passes[(STANDBY, "awg")] = self.passes[(STANDBY, "tls")] = False
        # 12:00 UTC.
        self.now = int(time.mktime(time.strptime("2026-11-27 12:00", "%Y-%m-%d %H:%M"))) - time.timezone
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = False
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls" and
                   state["paths"][PRIMARY]["fail"] == 0)
        changes: list[int] = []
        previous = "tls"
        # До 05:00 следующих суток, шаг 10 с.
        while time.gmtime(self.now).tm_hour != 5 or time.gmtime(self.now).tm_mday == 27:
            state = self.step()
            current = state["paths"][PRIMARY]["transport"]
            if current != previous:
                changes.append(self.now)
                previous = current
        hours = [time.gmtime(moment).tm_hour for moment in changes]
        # Одна проверка: уход на прямой в 03:00 и возврат в TLS.
        self.assertEqual(hours, [3, 3])
        self.assertEqual(changes[1] - changes[0], 150)

    def test_retest_command_checks_the_active_path_now(self) -> None:
        self.passes[(STANDBY, "awg")] = self.passes[(STANDBY, "tls")] = False
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = False
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls" and
                   state["paths"][PRIMARY]["fail"] == 0)
        self.steps(20)
        self.assertEqual(self.transport(PRIMARY), "tls")
        self.reach[PRIMARY] = 3
        with mock.patch("builtins.print") as printed, \
                mock.patch.object(selector.time, "time", return_value=self.now + 10):
            self.now += 10
            self.assertEqual(selector.command_retest(self.cfg, mock.Mock()), 0)
        self.assertIn("основной EXIT", printed.call_args.args[0])
        self.assertEqual(self.transport(PRIMARY), "awg")
        self.assertFalse(selector.read_state(self.cfg)["paths"][PRIMARY]["retest_now"])

    def test_retest_command_has_nothing_to_do_on_the_direct_transport(self) -> None:
        self.steps(3)
        with mock.patch("builtins.print") as printed:
            self.assertEqual(selector.command_retest(self.cfg, mock.Mock()), 0)
        self.assertIn("проверять нечего", printed.call_args.args[0])


class DrillTests(TransportCase):
    """Учебный переход: проверка запасного транспорта без настоящей блокировки."""

    def drill(self, name: str, minutes: int = 5) -> int:
        self.reach[PRIMARY] = self.reach[STANDBY] = 3
        self.now += 10
        with mock.patch("builtins.print") as printed, mock.patch("sys.stderr"), \
                mock.patch.object(selector.time, "time", return_value=self.now):
            code = selector.command_transport_drill(self.cfg, mock.Mock(path=name, minutes=minutes))
        self.printed = printed
        return code

    def test_drill_on_the_idle_path_does_not_touch_the_traffic(self) -> None:
        self.steps(3)
        routes = list(self.routes)
        self.assertEqual(self.drill(STANDBY), 0)
        self.assertIn("Трафик идёт через другой сервер", self.printed.call_args.args[0])
        self.assertEqual(self.transport(STANDBY), "tls")
        # С первой же проверки ENTRY не принимает от этого сервера пакеты прямого
        # транспорта и не отправляет их: иначе путь продолжал бы отвечать напрямую.
        self.assertEqual(
            self.closed[-1],
            [
                ["-s", "198.51.100.2", "-p", "udp", "--sport", "443", "-j", "DROP"],
                ["-d", "198.51.100.2", "-p", "udp", "--dport", "443", "-j", "DROP"],
            ],
        )
        state = self.steps(6)
        self.assertEqual(len(self.closed[-1]), 2)
        text = "\n".join(selector.status_lines(self.cfg, state, "auto", self.now))
        self.assertIn("  транспорт: внутри TLS (учебный переход, ещё 4 мин)", text)
        self.assertIn(
            ("WARN", "резервный EXIT: идёт учебный переход на запасной транспорт"),
            selector.report_rows(self.cfg, state, "auto", self.now),
        )
        # По истечении срока путь сам возвращается на прямой транспорт.
        self.until(lambda current: current["paths"][STANDBY]["transport"] == "awg")
        self.assertIn("учебный переход на запасной транспорт завершён", self.messages[-1])
        self.assertEqual(self.closed[-1], [], "прямой транспорт снова открыт на ENTRY")
        state = self.steps(3)
        self.assertEqual(state["paths"][STANDBY]["fail"], 0)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.routes, routes)
        self.assertEqual(self.notices, [], "учения уведомлений не дают")

    def test_status_between_the_end_of_the_drill_and_the_next_check(self) -> None:
        # Найдено на рабочем каскаде: в секунды между концом учения и очередной
        # проверкой статус обещал проверку прямого транспорта «через 24 мин», хотя
        # путь возвращается на него следующей же проверкой.
        self.steps(3)
        self.drill(STANDBY)
        state = self.steps(29)
        until = state["paths"][STANDBY]["transport_drill_until"]
        self.assertEqual(until - self.now, 10)
        self.assertEqual(state["paths"][STANDBY]["transport"], "tls")
        moment = until + 3
        text = "\n".join(selector.status_lines(self.cfg, state, "auto", moment))
        self.assertIn(
            "  транспорт: внутри TLS (учебный переход завершён, возврат на прямой при "
            "следующей проверке)",
            text,
        )
        self.assertNotIn("прямой проверится", text)
        rows = selector.report_rows(self.cfg, state, "auto", moment)
        self.assertIn(("WARN", "резервный EXIT: идёт учебный переход на запасной транспорт"), rows)
        self.assertFalse(any("прямой не проходит" in row for _level, row in rows))
        # Следующая проверка возвращает путь на прямой транспорт и снимает отметку.
        self.now = moment
        state = self.step(7)
        self.assertEqual(state["paths"][STANDBY]["transport"], "awg")
        self.assertEqual(state["paths"][STANDBY]["transport_drill_until"], 0)
        text = "\n".join(selector.status_lines(self.cfg, state, "auto", self.now))
        self.assertNotIn("учебный переход", text)

    def test_drill_keeps_tls_even_when_it_does_not_answer(self) -> None:
        # Запасной транспорт сломан: учение должно это показать, а не скрыть
        # возвратом на прямой через две минуты.
        self.steps(3)
        self.passes[(STANDBY, "tls")] = False
        self.drill(STANDBY)
        started = self.now
        seen = set()
        while self.now - started < 290:
            state = self.step()
            seen.add(state["paths"][STANDBY]["transport"])
        self.assertEqual(seen, {"tls"})
        self.assertGreater(state["paths"][STANDBY]["fail"], 20)
        self.until(lambda current: current["paths"][STANDBY]["transport"] == "awg" and
                   current["paths"][STANDBY]["fail"] == 0)

    def test_drill_on_the_path_that_carries_traffic_is_announced(self) -> None:
        self.steps(3)
        self.assertEqual(self.drill(PRIMARY), 0)
        self.assertIn("на время перехода трафик уйдёт на другой сервер", self.printed.call_args.args[0])

    def test_drill_shorter_than_the_guard_needs_is_refused(self) -> None:
        self.steps(3)
        self.assertEqual(self.drill(STANDBY, minutes=2), 1)
        self.assertEqual(self.transport(STANDBY), "awg")

    def test_drill_without_a_second_transport_is_refused(self) -> None:
        for path in self.cfg.paths.values():
            path.pop("transports")
        self.assertEqual(self.drill(STANDBY), 1)


class ReportTests(TransportCase):
    def test_status_and_report_name_the_fallback_transport(self) -> None:
        self.steps(3)
        self.passes[(PRIMARY, "awg")] = False
        self.until(lambda state: state["paths"][PRIMARY]["transport"] == "tls" and
                   state["paths"][PRIMARY]["fail"] == 0)
        state = self.steps(6)
        text = "\n".join(selector.status_lines(self.cfg, state, "auto", self.now))
        self.assertIn("  транспорт: внутри TLS (запасной), 70 с; прямой проверится через", text)
        self.assertIn("  транспорт: прямой\n", text + "\n")
        rows = selector.report_rows(self.cfg, state, "auto", self.now)
        self.assertIn(
            # Проходит ли прямой сейчас, неизвестно: строка говорит, когда это проверится.
            ("WARN", "основной EXIT: туннель идёт запасным транспортом (внутри TLS); "
                     "прямой проверится через 28 мин"),
            rows,
        )

    def test_pinning_a_path_that_runs_on_tls_says_so(self) -> None:
        # Найдено на рабочем каскаде: резервный путь сам ушёл на запасной транспорт,
        # трафик закрепили на нём для сравнения и сравнивали как прямой.
        self.steps(3)
        self.passes[(STANDBY, "awg")] = False
        self.until(lambda state: state["paths"][STANDBY]["transport"] == "tls" and
                   state["paths"][STANDBY]["fail"] == 0)
        self.reach[PRIMARY] = self.reach[STANDBY] = 3
        self.now += 10
        with mock.patch("builtins.print") as printed, \
                mock.patch.object(selector.time, "time", return_value=self.now):
            self.assertEqual(selector.command_use(self.cfg, mock.Mock(path=STANDBY)), 0)
        lines = [call.args[0] for call in printed.call_args_list]
        self.assertEqual(lines[0], "Путь закреплён: резервный EXIT. Вернуть автоматику: exit-path auto")
        self.assertIn("идёт запасным транспортом (внутри TLS): он медленнее прямого", lines[1])
        self.assertIn("exit-path retest", lines[1])
        self.assertEqual(self.transport(STANDBY), "tls")
        # Путь на прямом транспорте закрепляется без оговорок.
        self.now += 10
        with mock.patch("builtins.print") as printed, \
                mock.patch.object(selector.time, "time", return_value=self.now):
            self.assertEqual(selector.command_use(self.cfg, mock.Mock(path=PRIMARY)), 0)
        self.assertEqual(len(printed.call_args_list), 1)

    def test_cascade_without_a_second_transport_reports_nothing_new(self) -> None:
        for path in self.cfg.paths.values():
            path.pop("transports")
        self.applied.clear()
        self.closed.clear()
        state = self.steps(4)
        self.assertEqual(self.applied, [])
        self.assertEqual(self.closed, [], "межсетевой экран ENTRY не трогается")
        self.assertIsNone(state["paths"][PRIMARY]["transport"])
        text = "\n".join(selector.status_lines(self.cfg, state, "auto", self.now))
        self.assertNotIn("транспорт", text)
        self.assertEqual(
            [level for level, _ in selector.report_rows(self.cfg, state, "auto", self.now)],
            ["OK", "OK", "OK"],
        )


class EndpointTests(unittest.TestCase):
    """ensure_transport: служба запасного транспорта и адрес пира туннеля."""

    def setUp(self) -> None:
        self.cfg = selector.Config(
            {
                "paths": [
                    path_document("primary", "основной EXIT", "awg3", 77, "198.51.100.1"),
                    path_document("standby", "резервный EXIT", "awg4", 78, "198.51.100.2"),
                ],
                "probe_targets": [["192.0.2.1", 443]],
                "probe_quorum": 1,
                "probe_timeout_seconds": 1,
                "fail_threshold": 3,
                "failback_seconds": 900,
                "table": 100,
                "state_dir": "/nonexistent/run",
                "mode_file": "/nonexistent/mode",
            }
        )
        self.running: set[str] = set()
        self.endpoint = "198.51.100.1:443"
        self.calls: list[list[str]] = []

    def run_quiet(self, argv: list[str], **_kwargs) -> int:
        if argv[:2] == ["systemctl", "is-active"]:
            return 0 if argv[-1] in self.running else 3
        self.calls.append(argv)
        if argv[:2] == ["systemctl", "start"]:
            self.running.add(argv[-1])
        if argv[:2] == ["systemctl", "stop"]:
            self.running.discard(argv[-1])
        if argv[:2] == ["awg", "set"]:
            self.endpoint = argv[-1]
        return 0

    def ensure(self, transport: str) -> list[list[str]]:
        self.calls.clear()
        with mock.patch.object(selector, "run_quiet", side_effect=self.run_quiet), \
                mock.patch.object(selector, "tunnel_endpoint", side_effect=lambda *_a: ("PEERKEY=", self.endpoint)):
            selector.ensure_transport(self.cfg, PRIMARY, transport)
        return list(self.calls)

    def test_tls_starts_the_relay_and_points_the_tunnel_at_it(self) -> None:
        unit = TLS_UNIT.format("primary")
        self.assertEqual(
            self.ensure("tls"),
            [
                ["systemctl", "start", unit],
                ["awg", "set", "awg3", "peer", "PEERKEY=", "endpoint", "127.0.0.1:20443"],
            ],
        )
        self.assertEqual(self.ensure("tls"), [], "повторная проверка ничего не меняет")

    def test_direct_transport_stops_the_relay(self) -> None:
        self.ensure("tls")
        unit = TLS_UNIT.format("primary")
        self.assertEqual(
            self.ensure("awg"),
            [
                ["systemctl", "stop", unit],
                ["awg", "set", "awg3", "peer", "PEERKEY=", "endpoint", "198.51.100.1:443"],
            ],
        )
        self.assertEqual(self.running, set(), "пока запасной транспорт не нужен, он не работает")

    def test_interface_restart_gets_the_endpoint_restored(self) -> None:
        self.ensure("tls")
        # Перезапуск интерфейса во время deploy вернул адрес из конфигурации.
        self.endpoint = "198.51.100.1:443"
        self.assertEqual(
            self.ensure("tls"),
            [["awg", "set", "awg3", "peer", "PEERKEY=", "endpoint", "127.0.0.1:20443"]],
        )

    def test_interface_that_is_down_is_left_alone(self) -> None:
        with mock.patch.object(selector, "run_quiet", side_effect=self.run_quiet), \
                mock.patch.object(selector, "tunnel_endpoint", return_value=("", "")):
            selector.ensure_transport(self.cfg, PRIMARY, "awg")
        self.assertEqual([call for call in self.calls if call[:2] == ["awg", "set"]], [])


class FakeFirewall:
    """Межсетевой экран ENTRY глазами переключателя: цепочки и правила в них."""

    def __init__(self) -> None:
        self.chains: dict[str, list[list[str]]] = {
            "INPUT": [["-j", "ufw-before-input"]],
            "OUTPUT": [["-o", "eth0", "-m", "mark", "--mark", "0x1", "-j", "REJECT"]],
        }
        self.changes: list[list[str]] = []
        self.broken = False

    def run(self, argv: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        done = lambda code=0, out="": subprocess.CompletedProcess(argv, code, out, "")  # noqa: E731
        if list(argv[:3]) != ["iptables", "-w", "10"]:
            raise AssertionError(f"неожиданная команда: {argv}")
        command, chain, rest = argv[3], argv[4], list(argv[5:])
        if command == "-S":
            if chain not in self.chains:
                return done(1)
            lines = [f"-N {chain}"] + [f"-A {chain} " + " ".join(rule) for rule in self.chains[chain]]
            return done(0, "\n".join(lines) + "\n")
        if command == "-C":
            return done(0 if rest in self.chains.get(chain, []) else 1)
        self.changes.append(list(argv[3:]))
        if self.broken:
            return done(4)
        if command == "-N":
            if chain in self.chains:
                return done(1)
            self.chains[chain] = []
            return done()
        if chain not in self.chains:
            return done(1)
        rules = self.chains[chain]
        if command == "-F":
            rules.clear()
        elif command == "-A":
            rules.append(rest)
        elif command == "-I":
            rules.insert(int(rest[0]) - 1, rest[1:])
        elif command == "-D":
            if rest not in rules:
                return done(1)
            rules.remove(rest)
        elif command == "-X":
            used = any(["-j", chain] in other for other in self.chains.values())
            if rules or used:
                return done(1)
            del self.chains[chain]
        else:
            raise AssertionError(f"неожиданная команда iptables: {argv[3:]}")
        return done()


class EntryFirewallTests(unittest.TestCase):
    """sync_transport_firewall: прямой транспорт пути на запасном закрыт и на ENTRY.

    Найдено на рабочем каскаде. Адрес пира туннеля следует за последним подлинным
    пакетом. Пока сторож на EXIT не открыл запасной транспорт, EXIT шлёт пакеты
    напрямую, и туннель возвращался на прямой транспорт: учебный переход ничего
    не переключил, хотя ENTRY показывал запасной транспорт и «отвечает».
    """

    CHAIN = "KALIMERA-TRANSIT"

    def setUp(self) -> None:
        self.cfg = selector.Config(
            {
                "paths": [
                    path_document("primary", "основной EXIT", "awg3", 77, "198.51.100.1"),
                    path_document("standby", "резервный EXIT", "awg4", 78, "198.51.100.2"),
                ],
                "probe_targets": [["192.0.2.1", 443]],
                "probe_quorum": 1,
                "probe_timeout_seconds": 1,
                "fail_threshold": 3,
                "failback_seconds": 900,
                "table": 100,
                "state_dir": "/nonexistent/run",
                "mode_file": "/nonexistent/mode",
            }
        )
        self.firewall = FakeFirewall()
        self.pristine = copy.deepcopy(self.firewall.chains)
        patcher = mock.patch.object(selector.subprocess, "run", side_effect=self.firewall.run)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.state = selector.empty_state()

    def sync(self, primary: str | None = "awg", standby: str | None = "awg") -> bool:
        self.state["paths"][PRIMARY]["transport"] = primary
        self.state["paths"][STANDBY]["transport"] = standby
        self.firewall.changes.clear()
        return selector.sync_transport_firewall(self.cfg, self.state)

    @staticmethod
    def closed(address: str) -> list[list[str]]:
        return [
            ["-s", address, "-p", "udp", "--sport", "443", "-j", "DROP"],
            ["-d", address, "-p", "udp", "--dport", "443", "-j", "DROP"],
        ]

    def test_direct_transports_leave_the_firewall_alone(self) -> None:
        self.assertTrue(self.sync())
        self.assertEqual(self.firewall.changes, [])
        self.assertEqual(self.firewall.chains, self.pristine)
        # Сразу после перезагрузки транспорт ещё не выбран: это тоже прямой.
        self.assertTrue(self.sync(primary=None, standby=None))
        self.assertEqual(self.firewall.chains, self.pristine)

    def test_path_on_tls_is_closed_in_both_directions_ahead_of_ufw(self) -> None:
        self.assertTrue(self.sync(standby="tls"))
        chains = self.firewall.chains
        self.assertEqual(chains[self.CHAIN], self.closed("198.51.100.2"))
        # Раньше правил UFW: иначе ответные пакеты приняло бы правило для
        # установленных соединений, и адрес пира туннеля вернулся бы на прямой.
        for hook in ("INPUT", "OUTPUT"):
            self.assertEqual(chains[hook][0], ["-j", self.CHAIN], hook)
            self.assertEqual(chains[hook][1:], self.pristine[hook], hook)
        self.assertTrue(self.sync(standby="tls"))
        self.assertEqual(self.firewall.changes, [], "повторная проверка ничего не меняет")

    def test_both_paths_on_tls_close_both_servers(self) -> None:
        self.assertTrue(self.sync(primary="tls", standby="tls"))
        self.assertEqual(
            self.firewall.chains[self.CHAIN], self.closed("198.51.100.1") + self.closed("198.51.100.2")
        )
        # Один путь вернулся на прямой: второй остаётся закрытым.
        self.assertTrue(self.sync(primary="tls"))
        self.assertEqual(self.firewall.chains[self.CHAIN], self.closed("198.51.100.1"))
        for hook in ("INPUT", "OUTPUT"):
            self.assertEqual(self.firewall.chains[hook].count(["-j", self.CHAIN]), 1, hook)

    def test_return_to_the_direct_transport_removes_the_chain(self) -> None:
        self.sync(standby="tls")
        self.assertTrue(self.sync())
        self.assertEqual(self.firewall.chains, self.pristine)
        self.assertTrue(self.sync())
        self.assertEqual(self.firewall.changes, [])

    def test_rebuilt_firewall_gets_the_rules_back(self) -> None:
        self.sync(standby="tls")
        # Пересборка UFW убрала подключение цепочки, а другая программа вставила
        # своё правило в начало OUTPUT.
        self.firewall.chains["INPUT"] = [["-j", "ufw-before-input"]]
        self.firewall.chains["OUTPUT"].insert(0, ["-o", "lo", "-j", "ACCEPT"])
        self.assertTrue(self.sync(standby="tls"))
        for hook in ("INPUT", "OUTPUT"):
            self.assertEqual(self.firewall.chains[hook][0], ["-j", self.CHAIN], hook)
            self.assertEqual(self.firewall.chains[hook].count(["-j", self.CHAIN]), 1, hook)
        self.assertIn(["-o", "lo", "-j", "ACCEPT"], self.firewall.chains["OUTPUT"])
        # Цепочку очистили.
        self.firewall.chains[self.CHAIN].clear()
        self.assertTrue(self.sync(standby="tls"))
        self.assertEqual(self.firewall.chains[self.CHAIN], self.closed("198.51.100.2"))
        # В цепочке оказалось чужое правило.
        self.firewall.chains[self.CHAIN].append(["-p", "icmp", "-j", "DROP"])
        self.assertTrue(self.sync(standby="tls"))
        self.assertEqual(self.firewall.chains[self.CHAIN], self.closed("198.51.100.2"))

    def test_rules_that_cannot_be_applied_are_reported(self) -> None:
        self.firewall.broken = True
        self.assertFalse(self.sync(standby="tls"))

    def test_chain_name_comes_from_the_settings(self) -> None:
        self.cfg.transport_chain = "OTHER-CHAIN"
        self.assertTrue(self.sync(primary="tls"))
        self.assertEqual(self.firewall.chains["OTHER-CHAIN"], self.closed("198.51.100.1"))
        self.assertNotIn(self.CHAIN, self.firewall.chains)


if __name__ == "__main__":
    unittest.main()

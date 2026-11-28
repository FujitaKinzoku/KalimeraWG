"""Уход с пути до EXIT, который отвечает, но теряет пакеты.

Найдено на рабочем каскаде: основной путь несколько часов терял до 7,6% проверок
при чистом резервном. Переключатель путей менял путь, только когда тот переставал
отвечать, поэтому трафик оставался на теряющем пути, а пользователи видели
зависающее видео. Правило включается командой kalimera-deploy --resume
--enable-loss-switch; выключенное, оно ничего не меняет.

Каждый переход меняет внешний адрес клиентов и обрывает их соединения, поэтому
здесь проверяется не только уход, но и то, что трафик не мечется между путями.
"""

from __future__ import annotations

import json
import random
import unittest
from pathlib import Path
from unittest import mock

import yaml

from test_standby_exit import PRIMARY, STANDBY, InstallerCase, SelectorCase, deploy, selector
from test_transport_selector import TransportCase

ROOT = Path(__file__).parents[1]
SELECTOR_ROLE = ROOT / "roles" / "entry_exit_path"
START = 6000  # начало минуты: счёт потерь ведётся по минутам


class LossCase(SelectorCase):
    def setUp(self) -> None:
        super().setUp()
        self.now = START
        self.notices: list[str] = []
        patcher = mock.patch.object(selector, "notify", lambda _cfg, message: self.notices.append(message))
        patcher.start()
        self.addCleanup(patcher.stop)

    def enable(self) -> None:
        self.cfg.loss_switch_percent = 5.0
        self.cfg.loss_switch_minutes = 10
        self.cfg.loss_clean_percent = 1.0
        self.cfg.loss_return_minutes = 30

    def run_minutes(self, minutes: float, primary_every: int = 0, standby_every: int = 0) -> dict:
        """Проверки раз в 10 с; каждая N-я проверка пути проходит со второй попытки.

        Одна из трёх проверок на каждой пятой проверке пути - это 6,7% проверок,
        близко к тому, что было на рабочем каскаде.
        """
        state: dict = {}
        for _ in range(int(minutes * 6)):
            index = (self.now - START) // 10
            self.slow[PRIMARY] = 1 if primary_every and index % primary_every == 0 else 0
            self.slow[STANDBY] = 1 if standby_every and index % standby_every == 0 else 0
            state = selector.tick(self.cfg, self.now)
            self.now += 10
        return state

    def until_active(self, name: str, limit_minutes: int, **loss) -> float:
        """Минуты до перехода трафика на путь name; тест падает, если его нет."""
        started = self.now
        for _ in range(limit_minutes * 6):
            if self.run_minutes(1 / 6, **loss)["active"] == name:
                return (self.now - started) / 60
        self.fail(f"трафик не перешёл на {name} за {limit_minutes} мин")

    def status(self) -> str:
        return "\n".join(
            selector.status_lines(self.cfg, selector.read_state(self.cfg), "auto", self.now)
        )


class DisabledTests(LossCase):
    def test_without_the_rule_a_lossy_path_keeps_the_traffic(self) -> None:
        state = self.run_minutes(60, primary_every=5)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.routes, [])
        self.assertNotIn("уход с теряющего пути", self.status())

    def test_rule_is_off_unless_the_settings_name_a_threshold(self) -> None:
        self.assertEqual(self.cfg.loss_switch_percent, 0)
        self.assertEqual(selector.loss_move_reason(self.cfg, selector.empty_state(), PRIMARY, STANDBY, START), "")
        self.assertTrue(selector.primary_may_return(self.cfg, selector.empty_state(), START))


class MoveTests(LossCase):
    def setUp(self) -> None:
        super().setUp()
        self.enable()

    def test_sustained_loss_moves_the_traffic_to_the_clean_path(self) -> None:
        self.run_minutes(12)
        took = self.until_active(STANDBY, 15, primary_every=5)
        # Не раньше, чем потери заняли большую часть десятиминутного окна.
        self.assertGreaterEqual(took, 6)
        self.assertLessEqual(took, 10)
        state = selector.read_state(self.cfg)
        self.assertRegex(
            state["last_switch"]["reason"],
            r"^основной путь теряет пакеты: за 10 мин \d,\d% проверок прошли со второй попытки "
            r"или без ответа$",
        )
        self.assertEqual(self.routes, ["awg4"])
        self.assertEqual(self.flushed, [PRIMARY])
        # О переходе сообщается так же, как об отказе пути.
        self.assertEqual(len(self.notices), 1)
        self.assertIn("основной EXIT → резервный EXIT", self.notices[0])
        self.assertIn("теряет пакеты", self.notices[0])

    def test_verdict_waits_for_a_full_window_after_a_start(self) -> None:
        # После перезагрузки ENTRY история пуста: по двум минутам о потерях не судят.
        took = self.until_active(STANDBY, 15, primary_every=5)
        self.assertGreaterEqual(took, 9)
        self.assertLessEqual(took, 10.5)

    def test_short_burst_does_not_move_the_traffic(self) -> None:
        self.run_minutes(15)
        # Минута, в которую теряется каждая третья проверка, и снова чисто.
        self.run_minutes(1, primary_every=1)
        state = self.run_minutes(20)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.routes, [])

    def test_loss_below_the_threshold_does_not_move_the_traffic(self) -> None:
        # Каждая восьмая проверка: 4,2% при пороге 5%.
        state = self.run_minutes(60, primary_every=8)
        self.assertEqual(state["active"], PRIMARY)

    def test_lossy_standby_is_not_a_place_to_go(self) -> None:
        state = self.run_minutes(40, primary_every=5, standby_every=5)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.routes, [])

    def test_standby_that_was_silent_minutes_ago_is_not_clean_yet(self) -> None:
        self.run_minutes(5, primary_every=5)
        self.reach[STANDBY] = 0
        self.run_minutes(1 / 6, primary_every=5)
        self.reach[STANDBY] = 3
        silent_at = self.now
        took = self.until_active(STANDBY, 20, primary_every=5)
        # Минута с проверкой без ответа должна выйти из десятиминутного окна.
        self.assertGreaterEqual(took, 9)
        self.assertGreater(self.now - silent_at, 9 * 60)

    def test_pinned_path_ignores_losses(self) -> None:
        selector.write_mode(self.cfg, PRIMARY)
        state = self.run_minutes(40, primary_every=5)
        self.assertEqual(state["active"], PRIMARY)

    def test_deploy_holds_the_move(self) -> None:
        self.run_minutes(12)
        with mock.patch.object(selector, "deploy_in_progress", return_value=True):
            state = self.run_minutes(20, primary_every=5)
        self.assertEqual(state["active"], PRIMARY)
        # Deploy закончился: правило действует сразу, окно уже заполнено.
        self.assertLessEqual(self.until_active(STANDBY, 3, primary_every=5), 1)


class ReturnTests(LossCase):
    def setUp(self) -> None:
        super().setUp()
        self.enable()
        self.run_minutes(12)
        self.until_active(STANDBY, 15, primary_every=5)

    def test_traffic_does_not_bounce_back_to_the_lossy_primary(self) -> None:
        # Основной путь всё это время «устойчиво отвечает», и прежнее правило
        # возврата (15 минут без сбоев) вернуло бы трафик на него немедленно.
        state = self.run_minutes(40, primary_every=5)
        self.assertEqual(state["active"], STANDBY)
        self.assertEqual(self.routes, ["awg4"])
        text = self.status()
        self.assertIn(
            "  уход с теряющего пути: при 5,0% проверок с потерей за 10 мин, если другой путь чист",
            text,
        )
        self.assertIn(
            "  возврат на основной EXIT: когда за 30 мин потерь на нём будет не больше 1,0%", text
        )

    def test_clean_primary_gets_the_traffic_back_after_the_long_window(self) -> None:
        self.run_minutes(5, primary_every=5)
        took = self.until_active(PRIMARY, 45)
        # Потери должны почти целиком выйти из получасового окна.
        self.assertGreaterEqual(took, 24)
        self.assertLessEqual(took, 31)
        state = selector.read_state(self.cfg)
        self.assertEqual(state["last_switch"]["reason"], selector.REASON_FAILBACK)
        self.assertEqual(self.routes, ["awg4", "awg3"])
        self.assertNotIn("возврат на основной EXIT", self.status())

    def test_lossy_standby_gives_the_traffic_back_to_a_clean_primary_sooner(self) -> None:
        # Теперь пакеты теряет резервный путь, а основной чист уже десять минут:
        # ждать получаса незачем.
        took = self.until_active(PRIMARY, 20, standby_every=5)
        self.assertGreaterEqual(took, 8)
        self.assertLessEqual(took, 12)
        reason = selector.read_state(self.cfg)["last_switch"]["reason"]
        self.assertTrue(reason.startswith("резервный путь теряет пакеты: за 10 мин "), reason)

    def test_dead_standby_returns_the_traffic_to_a_lossy_primary_at_once(self) -> None:
        # Теряющий путь лучше неотвечающего: прежнее правило отказа не изменилось.
        self.reach[STANDBY] = 0
        took = self.until_active(PRIMARY, 2, primary_every=5)
        self.assertLessEqual(took, 0.6)
        self.assertEqual(selector.read_state(self.cfg)["last_switch"]["reason"], "резервный путь не отвечает")


class OutageTests(LossCase):
    def test_return_after_an_outage_keeps_its_fifteen_minutes(self) -> None:
        self.enable()
        self.run_minutes(35)
        self.reach[PRIMARY] = 0
        took = self.until_active(STANDBY, 2)
        self.assertLessEqual(took, 0.6)
        self.assertEqual(selector.read_state(self.cfg)["last_switch"]["reason"], "основной путь не отвечает")
        self.run_minutes(5)
        self.reach[PRIMARY] = 3
        took = self.until_active(PRIMARY, 30)
        # Минуты отказа - не потери: возврат через прежние 15 минут, а не через 30.
        self.assertGreaterEqual(took, 15)
        self.assertLessEqual(took, 15.5)

    def test_primary_that_came_back_lossy_does_not_get_the_traffic(self) -> None:
        self.enable()
        self.run_minutes(35)
        self.reach[PRIMARY] = 0
        self.until_active(STANDBY, 2)
        self.reach[PRIMARY] = 3
        state = self.run_minutes(40, primary_every=5)
        self.assertEqual(state["active"], STANDBY)


class SoakTests(LossCase):
    """Случайные потери, как на настоящем канале, а не каждая пятая проверка."""

    def run_random(self, hours: float, primary: float, standby: float, seed: int) -> dict:
        """Каждая из трёх проверок пути теряется с заданной вероятностью."""
        dice = random.Random(seed)
        state: dict = {}
        for _ in range(int(hours * 360)):
            self.slow[PRIMARY] = sum(dice.random() < primary for _ in range(3))
            self.slow[STANDBY] = sum(dice.random() < standby for _ in range(3))
            state = selector.tick(self.cfg, self.now)
            self.now += 10
        return state

    def test_ordinary_noise_never_moves_the_traffic_in_a_day(self) -> None:
        self.enable()
        # 0,5% проверок на обоих путях: выше, чем у исправных путей рабочего каскада.
        state = self.run_random(24, primary=0.005, standby=0.005, seed=1)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.routes, [])

    def test_evening_of_losses_costs_one_move_there_and_one_back(self) -> None:
        self.enable()
        self.run_random(1, primary=0.003, standby=0.003, seed=2)
        # Три часа основной путь теряет 7% проверок, резервный чист.
        state = self.run_random(3, primary=0.07, standby=0.003, seed=3)
        self.assertEqual(state["active"], STANDBY)
        self.assertEqual(self.routes, ["awg4"], "за три часа потерь трафик ушёл один раз и не возвращался")
        state = self.run_random(3, primary=0.003, standby=0.003, seed=4)
        self.assertEqual(state["active"], PRIMARY)
        self.assertEqual(self.routes, ["awg4", "awg3"])


class TransportRankTests(TransportCase):
    def test_traffic_does_not_leave_a_direct_path_for_one_inside_tls(self) -> None:
        self.cfg.loss_switch_percent = 5.0
        self.steps(3)
        self.passes[(STANDBY, "awg")] = False
        self.until(lambda state: state["paths"][STANDBY]["transport"] == "tls" and
                   state["paths"][STANDBY]["fail"] == 0)
        # Запасной транспорт - это уже работа без запаса: туда трафик с прямого
        # пути из-за потерь не уходит.
        self.cfg.transport_retest_seconds = 10**6
        for index in range(20 * 6):
            self.slow[PRIMARY] = 1 if index % 5 == 0 else 0
            state = self.step()
        self.assertEqual(state["paths"][STANDBY]["transport"], "tls")
        self.assertEqual(state["active"], PRIMARY)


class SettingsTests(unittest.TestCase):
    BASE = {
        "paths": [
            {"name": "primary", "label": "основной EXIT", "interface": "awg3"},
            {"name": "standby", "label": "резервный EXIT", "interface": "awg4"},
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

    def test_thresholds_are_checked_only_when_the_rule_is_on(self) -> None:
        cfg = selector.Config(dict(self.BASE))
        self.assertEqual(
            (cfg.loss_switch_percent, cfg.loss_switch_minutes, cfg.loss_clean_percent, cfg.loss_return_minutes),
            (0, 10, 1, 30),
        )
        selector.Config(dict(self.BASE, loss_switch_percent=5, loss_clean_percent=1))
        for wrong in (
            {"loss_switch_percent": 5, "loss_clean_percent": 5},
            {"loss_switch_percent": 5, "loss_switch_minutes": 1},
            {"loss_switch_percent": 5, "loss_return_minutes": 61},
            {"loss_switch_percent": -1},
        ):
            with self.assertRaises(ValueError, msg=str(wrong)):
                selector.Config(dict(self.BASE, **wrong))

    def variables(self) -> dict:
        defaults = yaml.safe_load((SELECTOR_ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
        return dict(
            {key: value for key, value in defaults.items() if "{{" not in str(value)},
            entry_exit_interface="awg3",
            entry_exit_tunnel_address="10.77.0.2/32",
            awg3_peer_tunnel_address="10.77.0.1",
            entry_standby_exit_interface="awg4",
            entry_standby_exit_tunnel_address="10.78.0.2/32",
            entry_standby_exit_peer_tunnel_address="10.78.0.1",
            entry_exit_table=100,
            entry_exit_path_state_dir="/run/kalimera-exit-path",
        )

    def test_role_passes_the_thresholds_only_when_enabled(self) -> None:
        from test_fallback_transport import render

        template = SELECTOR_ROLE / "templates" / "config.json.j2"
        variables = self.variables()
        self.assertIs(variables["entry_exit_path_loss_switch_enabled"], False, "по умолчанию выключено")
        plain = json.loads(render(template, **variables))
        self.assertEqual([key for key in plain if key.startswith("loss_switch") or key.startswith("loss_clean")
                          or key.startswith("loss_return")], [])
        self.assertEqual(selector.Config(plain).loss_switch_percent, 0)
        enabled = json.loads(render(template, **dict(variables, entry_exit_path_loss_switch_enabled=True)))
        cfg = selector.Config(enabled)
        self.assertEqual(
            (cfg.loss_switch_percent, cfg.loss_switch_minutes, cfg.loss_clean_percent, cfg.loss_return_minutes),
            (5, 10, 1, 30),
        )
        # Правило не мешает настройкам запасного транспорта и наоборот.
        both = json.loads(render(
            template,
            **dict(
                variables,
                entry_exit_path_loss_switch_enabled=True,
                transit_tls_enabled=True,
                security_interserver_peer_ipv4="192.0.2.20",
                entry_exit_endpoint="192.0.2.20:443",
                entry_standby_exit_public_ipv4="198.51.100.7",
                entry_standby_exit_endpoint="198.51.100.7:443",
            ),
        ))
        cfg = selector.Config(both)
        self.assertEqual(cfg.loss_switch_percent, 5)
        self.assertEqual(cfg.transport_chain, "KALIMERA-TRANSIT")

    def test_role_refuses_thresholds_the_program_would_refuse(self) -> None:
        tasks = yaml.safe_load((SELECTOR_ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
        checks = tasks[0]["ansible.builtin.assert"]["that"]
        for expected in (
            "entry_exit_path_loss_clean_percent | float < entry_exit_path_loss_switch_percent | float",
            "entry_exit_path_loss_switch_minutes | int >= 2",
            "entry_exit_path_loss_return_minutes | int <= 60",
        ):
            self.assertIn(expected, checks)


class InstallerLossTests(InstallerCase):
    def switch(self, enabled: bool) -> bool:
        with mock.patch("builtins.print"):
            return deploy.set_loss_switch(self.production, enabled)

    def test_rule_needs_a_standby_exit(self) -> None:
        before = self.entry_path.read_text(encoding="utf-8")
        with self.assertRaises(SystemExit) as stopped:
            self.switch(True)
        self.assertIn("--enable-standby-exit", str(stopped.exception))
        self.assertEqual(self.entry_path.read_text(encoding="utf-8"), before)

    def test_flag_is_one_variable_of_the_entry(self) -> None:
        self.enable()
        before = deploy.load_yaml(self.entry_path)
        self.assertTrue(self.switch(True))
        entry = deploy.load_yaml(self.entry_path)
        self.assertIs(entry["entry_exit_path_loss_switch_enabled"], True)
        self.assertEqual({key: value for key, value in entry.items()
                          if key != "entry_exit_path_loss_switch_enabled"}, before)
        self.assertFalse(self.switch(True), "повторное включение ничего не меняет")
        self.assertTrue(self.switch(False))
        self.assertEqual(deploy.load_yaml(self.entry_path), before)
        self.assertFalse(self.switch(False))

    def test_rule_goes_away_with_the_standby_exit(self) -> None:
        self.enable()
        self.switch(True)
        self.assertTrue(self.disable())
        self.assertNotIn("entry_exit_path_loss_switch_enabled", deploy.load_yaml(self.entry_path))

    def test_admin_gateway_allows_both_commands(self) -> None:
        gateway = (
            ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("'--resume --enable-loss-switch'|'--resume --disable-loss-switch'|", gateway)
        self.assertIn("--enable-loss-switch, --disable-loss-switch,", gateway)

    def test_flags_work_only_with_resume_and_one_at_a_time(self) -> None:
        source = (ROOT / "scripts" / "lib" / "interactive_deploy.py").read_text(encoding="utf-8")
        self.assertIn('("--enable-loss-switch", args.enable_loss_switch),', source)
        self.assertIn('("--disable-loss-switch", args.disable_loss_switch),', source)
        self.assertIn(
            'parser.error("--enable-loss-switch и --disable-loss-switch нельзя указывать вместе")', source
        )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Команды обслуживания каскада: время ночного обслуживания и cascade-reboot.

cascade-reboot перезагружает FRONT, затем EXIT: для каждого сервера запоминает
boot_id, планирует перезагрузку, ждёт новый boot_id и проверяет каскад. ENTRY
перезагружается последним и проверяется после загрузки отдельным юнитом systemd.
Все вызовы Ansible ограничены по времени, поэтому команда не зависает молча.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "scripts" / "lib" / "interactive_deploy.py"
SPEC = importlib.util.spec_from_file_location("interactive_deploy", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

BOOT_A = "0f1e2d3c-1111-2222-3333-444455556666"
BOOT_B = "9a8b7c6d-aaaa-bbbb-cccc-ddddeeeeffff"


def completed(returncode: int, stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["cascade-check"], returncode=returncode, stdout=stdout, stderr=""
    )


def hosts_document(*groups: str) -> dict:
    children = {
        group: {"hosts": {f"{group}.example.invalid": {"ansible_host": "192.0.2.10"}}}
        for group in groups
    }
    return {"all": {"children": children}}


class MaintenanceTimeTests(unittest.TestCase):
    def test_builds_systemd_calendar_in_the_named_zone(self) -> None:
        self.assertEqual(
            MODULE.maintenance_calendar("02:20", "Asia/Manila"),
            "*-*-* 02:20:00 Asia/Manila",
        )

    def test_rejects_malformed_time_and_unknown_zone(self) -> None:
        for time_value in ("2:20", "24:00", "02:60", "02:20:00"):
            with self.subTest(time=time_value), self.assertRaises(SystemExit):
                MODULE.maintenance_calendar(time_value, "Asia/Manila")
        for zone in ("Mars/Olympus", "../etc/passwd", ""):
            with self.subTest(zone=zone), self.assertRaises(SystemExit):
                MODULE.maintenance_calendar("02:20", zone)

    def test_setting_the_time_keeps_other_group_variables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary) / "production"
            all_root = production / "group_vars" / "all"
            all_root.mkdir(parents=True)
            (all_root / "main.yml").write_text(
                yaml.safe_dump({"awg_maintenance_calendar": "*-*-* 05:20:00", "other": 1}),
                encoding="utf-8",
            )
            previous = MODULE.set_maintenance_calendar(production, "*-*-* 02:20:00 Asia/Manila")
            saved = yaml.safe_load((all_root / "main.yml").read_text(encoding="utf-8"))
        self.assertEqual(previous, "*-*-* 05:20:00")
        self.assertEqual(saved["awg_maintenance_calendar"], "*-*-* 02:20:00 Asia/Manila")
        self.assertEqual(saved["other"], 1)


class CascadeRebootPlanTests(unittest.TestCase):
    def test_order_is_front_exit_entry(self) -> None:
        self.assertEqual(
            MODULE.cascade_reboot_plan(hosts_document("entry", "exit", "front")),
            ["front", "exit", "entry"],
        )

    def test_missing_front_is_skipped(self) -> None:
        self.assertEqual(
            MODULE.cascade_reboot_plan(hosts_document("entry", "exit")),
            ["exit", "entry"],
        )

    def test_entry_is_never_rebooted_through_ansible(self) -> None:
        with self.assertRaises(SystemExit):
            MODULE.schedule_host_reboot(ROOT, ROOT / "hosts.yml", ROOT / "vault", "entry")


class BootIdTests(unittest.TestCase):
    def test_boot_id_is_taken_from_the_adhoc_output(self) -> None:
        output = f"front.example.invalid | CHANGED | rc=0 | (stdout) {BOOT_A}\n"
        with mock.patch.object(
            MODULE, "ansible_adhoc", return_value=completed(0, output)
        ):
            self.assertEqual(
                MODULE.read_boot_id(ROOT, ROOT / "hosts.yml", ROOT / "vault", "front"), BOOT_A
            )

    def test_unreachable_host_gives_no_boot_id(self) -> None:
        with mock.patch.object(MODULE, "ansible_adhoc", return_value=None):
            self.assertIsNone(
                MODULE.read_boot_id(ROOT, ROOT / "hosts.yml", ROOT / "vault", "front")
            )

    def test_permission_denied_stops_at_once_instead_of_retrying(self) -> None:
        # Повторные попытки с отклонённым ключом приводят к бану Fail2Ban.
        denied = completed(2, "front | UNREACHABLE! => Permission denied (publickey).\n")
        with mock.patch.object(MODULE, "ansible_adhoc", return_value=denied):
            with self.assertRaises(SystemExit):
                MODULE.read_boot_id(ROOT, ROOT / "hosts.yml", ROOT / "vault", "front")

    def test_adhoc_calls_are_bounded_by_a_timeout(self) -> None:
        with mock.patch.object(
            MODULE, "require_command", return_value="ansible"
        ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(0, BOOT_A)) as run:
            MODULE.ansible_adhoc(ROOT, ROOT / "hosts.yml", ROOT / "vault", "front", "command", "true")
        self.assertEqual(run.call_args.kwargs["timeout"], MODULE.ADHOC_TIMEOUT_SECONDS)

    def test_timed_out_adhoc_returns_none(self) -> None:
        with mock.patch.object(MODULE, "require_command", return_value="ansible"), mock.patch.object(
            MODULE.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="ansible", timeout=60),
        ):
            self.assertIsNone(
                MODULE.ansible_adhoc(ROOT, ROOT / "hosts.yml", ROOT / "vault", "front", "command", "true")
            )


class WaitForHostRebootTests(unittest.TestCase):
    def test_waits_until_the_boot_id_changes(self) -> None:
        results = [None, BOOT_A, BOOT_B]
        with mock.patch.object(MODULE, "read_boot_id", side_effect=results), mock.patch.object(
            MODULE.time, "sleep"
        ), mock.patch("builtins.print"):
            self.assertTrue(
                MODULE.wait_for_host_reboot(
                    ROOT, ROOT / "hosts.yml", ROOT / "vault", "front", BOOT_A, attempts=5, delay_seconds=1
                )
            )

    def test_same_boot_id_means_the_reboot_did_not_happen(self) -> None:
        with mock.patch.object(MODULE, "read_boot_id", return_value=BOOT_A), mock.patch.object(
            MODULE.time, "sleep"
        ), mock.patch("builtins.print"):
            self.assertFalse(
                MODULE.wait_for_host_reboot(
                    ROOT, ROOT / "hosts.yml", ROOT / "vault", "front", BOOT_A, attempts=3, delay_seconds=1
                )
            )


class WaitForCascadeTests(unittest.TestCase):
    def test_returns_true_once_the_cascade_recovers(self) -> None:
        results = [completed(1), completed(1), completed(0, "ok")]
        with mock.patch.object(MODULE, "run_cascade_check", side_effect=results), mock.patch.object(
            MODULE.time, "sleep"
        ) as sleep, mock.patch("builtins.print"):
            self.assertTrue(MODULE.wait_for_cascade(attempts=5, delay_seconds=1))
        self.assertEqual(sleep.call_count, 2)

    def test_warn_still_counts_as_working_cascade(self) -> None:
        with mock.patch.object(MODULE, "run_cascade_check", return_value=completed(3)), mock.patch(
            "builtins.print"
        ):
            self.assertTrue(MODULE.wait_for_cascade(attempts=2, delay_seconds=1))

    def test_gives_up_after_all_attempts(self) -> None:
        with mock.patch.object(
            MODULE, "run_cascade_check", return_value=completed(1, "FAIL")
        ), mock.patch.object(MODULE.time, "sleep"), mock.patch("builtins.print"):
            self.assertFalse(MODULE.wait_for_cascade(attempts=3, delay_seconds=1))


def guard(
    group: str, *, need: bool = True, fail: tuple[str, ...] = (), wait: tuple[str, ...] = (),
    hold: tuple[str, ...] = (), reason: str = "linux-image-6.8.0-100-generic",
):
    """Ответ предохранителей сервера: по умолчанию исправен, перезагрузка требуется."""
    rows = (
        [("FAIL", label, "") for label in fail]
        + [("WAIT", label, "") for label in wait]
        + [("HOLD", label, "") for label in hold]
    )
    return MODULE.GuardReport(group, True, need, reason if need else "", tuple(rows))


def guards(**overrides):
    """Подставной run_reboot_guard: overrides[group] - ответ или список ответов по вызовам."""
    calls: list[tuple[str, str]] = []

    def run(_repo, _hosts, _vault, group, mode):
        calls.append((group, mode))
        answer = overrides.get(group, guard(group))
        if isinstance(answer, list):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        return answer

    run.calls = calls
    return run


class CascadeRebootRunTests(unittest.TestCase):
    def setUp(self) -> None:
        # Предохранители пройдены на всех серверах, если тест не задаёт иное.
        patcher = mock.patch.object(MODULE, "run_reboot_guard", side_effect=guards())
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_guarded(self, guard_run, *, confirmed: bool = True, force: bool = False):
        """Запуск cascade-reboot с заданными ответами предохранителей."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            scheduled: list[str] = []
            with mock.patch.object(MODULE, "run_reboot_guard", side_effect=guard_run), mock.patch.object(
                MODULE.subprocess, "run", return_value=completed(3)
            ), mock.patch.object(MODULE, "read_boot_id", return_value=BOOT_A), mock.patch.object(
                MODULE, "schedule_host_reboot", side_effect=lambda *args: scheduled.append(args[-1]) or True
            ), mock.patch.object(MODULE, "wait_for_host_reboot", return_value=True), mock.patch.object(
                MODULE, "wait_for_cascade", return_value=True
            ), mock.patch.object(MODULE, "schedule_entry_reboot") as entry, mock.patch(
                "builtins.print"
            ) as printed:
                error = None
                try:
                    MODULE.run_cascade_reboot(
                        root, production, root / "vault.pass", confirmed=confirmed, force=force
                    )
                except SystemExit as stop:
                    error = str(stop)
        lines = [call.args[0] for call in printed.call_args_list if call.args]
        return scheduled, entry, lines, error

    def test_server_that_may_not_come_back_is_not_rebooted(self) -> None:
        # Ядро без модуля AmneziaWG: после перезагрузки EXIT каскад не поднялся бы.
        run = guards(**{"exit": guard("exit", fail=("модуль AmneziaWG не собран для ядра 6.8.0-100-generic",))})
        scheduled, entry, lines, error = self.run_guarded(run)
        self.assertEqual(scheduled, [])  # не перезагружен и FRONT: проверка идёт до первого шага
        entry.assert_not_called()
        self.assertIn("FAIL exit: модуль AmneziaWG не собран для ядра 6.8.0-100-generic", lines)
        self.assertIn("exit может не подняться", error)
        self.assertIn("cascade-reboot --yes --force", error)

    def test_running_package_installation_stops_a_manual_reboot_too(self) -> None:
        run = guards(**{"front": guard("front", wait=("идёт установка пакетов",))})
        scheduled, _entry, _lines, error = self.run_guarded(run)
        self.assertEqual(scheduled, [])
        self.assertIn("front может не подняться", error)

    def test_rules_of_the_automatic_reboot_do_not_stop_a_manual_one(self) -> None:
        # Человек, запустивший перезагрузку сам, уже принял решение: свежее ядро
        # её не останавливает, о правиле только сообщается.
        run = guards(**{"exit": guard("exit", hold=("ядро 6.8.0-100-generic установлено недавно",))})
        scheduled, entry, lines, error = self.run_guarded(run)
        self.assertIsNone(error)
        self.assertEqual(scheduled, ["front", "exit"])
        entry.assert_called_once()
        self.assertTrue(any("автоматическая перезагрузка отложена" in line for line in lines), lines)

    def test_each_server_is_prepared_right_before_its_reboot(self) -> None:
        run = guards()
        scheduled, entry, _lines, error = self.run_guarded(run)
        self.assertIsNone(error)
        self.assertEqual(scheduled, ["front", "exit"])
        self.assertEqual(
            run.calls,
            [("front", "check"), ("exit", "check"), ("entry", "check"),
             ("front", "prepare"), ("exit", "prepare"), ("entry", "prepare")],
        )
        entry.assert_called_once()

    def test_failed_preparation_stops_before_that_server(self) -> None:
        # Секреты не удалось сохранить в пакет: после перезагрузки они пропали бы.
        broken = guard("exit", fail=("секреты не сохранены в зашифрованный пакет",))
        run = guards(**{"exit": [guard("exit"), broken]})
        scheduled, entry, _lines, error = self.run_guarded(run)
        self.assertEqual(scheduled, ["front"])
        entry.assert_not_called()
        self.assertIn("exit не перезагружен", error)

    def test_force_overrides_the_guards(self) -> None:
        run = guards(**{"exit": guard("exit", fail=("initramfs ядра повреждён",))})
        scheduled, entry, _lines, error = self.run_guarded(run, force=True)
        self.assertIsNone(error)
        self.assertEqual(scheduled, ["front", "exit"])
        entry.assert_called_once()

    def test_silent_guard_blocks_the_reboot(self) -> None:
        run = guards(**{"front": MODULE.GuardReport("front", answered=False)})
        scheduled, _entry, lines, error = self.run_guarded(run)
        self.assertEqual(scheduled, [])
        self.assertTrue(any("предохранители перезагрузки не ответили" in line for line in lines), lines)
        self.assertIsNotNone(error)

    def test_dry_run_shows_the_guards_and_reboots_nothing(self) -> None:
        run = guards(**{"entry": guard("entry", need=False)})
        scheduled, entry, lines, error = self.run_guarded(run, confirmed=False)
        self.assertIsNone(error)
        self.assertEqual(scheduled, [])
        entry.assert_not_called()
        self.assertIn("OK   front: предохранители пройдены, перезагрузка требуется", lines)
        self.assertIn("OK   entry: предохранители пройдены, перезагрузка не требуется", lines)
        self.assertNotIn(("front", "prepare"), run.calls)

    def make_production(self, root: Path) -> Path:
        production = root / "production"
        (production / "group_vars" / "all").mkdir(parents=True)
        (production / "group_vars" / "all" / "vault.yml").write_text("x", encoding="utf-8")
        MODULE.yaml_write(production / "hosts.yml", hosts_document("entry", "exit", "front"))
        (root / "vault.pass").write_text("pass\n", encoding="utf-8")
        return production

    def test_refuses_when_a_server_does_not_answer_before_any_reboot(self) -> None:
        # Недоступный EXIT обнаруживается до первой перезагрузки: FRONT не трогаем.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            with mock.patch.object(
                MODULE, "read_boot_id", side_effect=[BOOT_A, None]
            ), mock.patch.object(MODULE, "schedule_host_reboot") as schedule, mock.patch(
                "builtins.print"
            ):
                with self.assertRaises(SystemExit):
                    MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        schedule.assert_not_called()

    def test_cascade_errors_do_not_block_the_reboot(self) -> None:
        # Ошибка каскада может требовать перезагрузки, поэтому FAIL не блокирует запуск.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            scheduled: list[str] = []
            with mock.patch.object(
                MODULE, "run_cascade_check", return_value=completed(1, "FAIL")
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE, "read_boot_id", side_effect=[BOOT_A, BOOT_A]
            ), mock.patch.object(
                MODULE,
                "schedule_host_reboot",
                side_effect=lambda *args: scheduled.append(args[-1]) or True,
            ), mock.patch.object(
                MODULE, "wait_for_host_reboot", return_value=True
            ), mock.patch.object(
                MODULE, "wait_for_cascade", return_value=True
            ), mock.patch.object(MODULE, "schedule_entry_reboot"), mock.patch(
                "builtins.print"
            ):
                MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        self.assertEqual(scheduled, ["front", "exit"])

    def test_without_confirmation_nothing_is_rebooted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            with mock.patch.object(
                MODULE, "run_cascade_check", return_value=completed(0)
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE, "schedule_host_reboot"
            ) as schedule, mock.patch.object(MODULE, "schedule_entry_reboot") as entry, mock.patch.object(
                MODULE, "read_boot_id", return_value=BOOT_A
            ), mock.patch(
                "builtins.print"
            ):
                MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=False)
        schedule.assert_not_called()
        entry.assert_not_called()

    def test_reboots_front_then_exit_then_schedules_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            scheduled: list[str] = []
            with mock.patch.object(
                MODULE, "run_cascade_check", return_value=completed(0)
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE, "read_boot_id", side_effect=[BOOT_A, BOOT_A]
            ), mock.patch.object(
                MODULE,
                "schedule_host_reboot",
                side_effect=lambda *args: scheduled.append(args[-1]) or True,
            ), mock.patch.object(
                MODULE, "wait_for_host_reboot", return_value=True
            ), mock.patch.object(
                MODULE, "wait_for_cascade", return_value=True
            ), mock.patch.object(MODULE, "schedule_entry_reboot") as entry, mock.patch(
                "builtins.print"
            ):
                MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        self.assertEqual(scheduled, ["front", "exit"])
        entry.assert_called_once()

    def run_with_pending_list_changes(self, seal_code: int) -> tuple[list[list[str]], mock.Mock, mock.Mock]:
        """Запуск с отметкой о несохранённых списках; seal отвечает кодом seal_code."""
        commands: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            commands.append([str(part) for part in argv])
            return completed(seal_code if argv[-1] == "seal" else 3)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            marker = root / "kalimera-lists.seal-pending"
            marker.write_text("", encoding="utf-8")
            with mock.patch.object(MODULE, "LIST_SEAL_PENDING", marker), mock.patch.object(
                MODULE.subprocess, "run", side_effect=fake_run
            ), mock.patch.object(MODULE, "read_boot_id", return_value=BOOT_A), mock.patch.object(
                MODULE, "schedule_host_reboot", return_value=True
            ) as schedule, mock.patch.object(
                MODULE, "wait_for_host_reboot", return_value=True
            ), mock.patch.object(
                MODULE, "wait_for_cascade", return_value=True
            ), mock.patch.object(MODULE, "schedule_entry_reboot") as entry, mock.patch(
                "builtins.print"
            ):
                MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        return commands, schedule, entry

    def test_unsaved_list_changes_are_saved_before_the_reboot(self) -> None:
        # Списки доменов лежат в tmpfs: изменение, не попавшее в зашифрованный пакет,
        # после перезагрузки ENTRY пропало бы.
        commands, schedule, entry = self.run_with_pending_list_changes(seal_code=0)
        self.assertIn(["/usr/local/sbin/kalimera-secretctl", "seal"], commands)
        self.assertEqual(schedule.call_count, 2)
        entry.assert_called_once()

    def test_unsaved_list_changes_stop_the_reboot_when_they_cannot_be_saved(self) -> None:
        with self.assertRaises(SystemExit) as error:
            self.run_with_pending_list_changes(seal_code=1)
        self.assertIn("sudo kalimera-secretctl seal", str(error.exception))

    def test_check_errors_stop_the_next_reboot_unless_forced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            scheduled: list[str] = []
            with mock.patch.object(
                MODULE, "read_boot_id", side_effect=[BOOT_A, BOOT_A]
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE,
                "schedule_host_reboot",
                side_effect=lambda *args: scheduled.append(args[-1]) or True,
            ), mock.patch.object(
                MODULE, "wait_for_host_reboot", return_value=True
            ), mock.patch.object(
                MODULE, "wait_for_cascade", return_value=False
            ), mock.patch.object(MODULE, "schedule_entry_reboot") as entry, mock.patch(
                "builtins.print"
            ):
                with self.assertRaises(SystemExit):
                    MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        self.assertEqual(scheduled, ["front"])
        entry.assert_not_called()

    def test_force_continues_past_check_errors_and_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            scheduled: list[str] = []
            with mock.patch.object(
                MODULE, "read_boot_id", side_effect=[BOOT_A, BOOT_A]
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE,
                "schedule_host_reboot",
                side_effect=lambda *args: scheduled.append(args[-1]) or True,
            ), mock.patch.object(
                MODULE, "wait_for_host_reboot", return_value=True
            ), mock.patch.object(
                MODULE, "wait_for_cascade", return_value=False
            ), mock.patch.object(MODULE, "schedule_entry_reboot") as entry, mock.patch(
                "builtins.print"
            ) as printed:
                MODULE.run_cascade_reboot(
                    root, production, root / "vault.pass", confirmed=True, force=True
                )
        lines = [str(call.args[0]) for call in printed.call_args_list if call.args]
        self.assertEqual(scheduled, ["front", "exit"])
        entry.assert_called_once()
        self.assertTrue(any("ВНИМАНИЕ: после front остались ошибки" in line for line in lines))

    def test_dry_run_reports_each_server_with_ok_lines(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            with mock.patch.object(
                MODULE, "read_boot_id", side_effect=[BOOT_A, BOOT_B]
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE, "schedule_host_reboot"
            ) as schedule, mock.patch("builtins.print") as printed:
                MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=False)
        lines = [call.args[0] for call in printed.call_args_list if call.args]
        self.assertIn("OK   front: SSH отвечает, загрузка 0f1e2d3c", lines)
        self.assertIn("OK   exit: SSH отвечает, загрузка 9a8b7c6d", lines)
        self.assertIn("OK   перезагрузка возможна: все серверы отвечают", lines)
        schedule.assert_not_called()

    def test_dry_run_marks_unreachable_server_as_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            with mock.patch.object(
                MODULE, "read_boot_id", side_effect=[BOOT_A, None]
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE, "schedule_host_reboot"
            ) as schedule, mock.patch("builtins.print") as printed:
                with self.assertRaises(SystemExit):
                    MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=False)
        lines = [call.args[0] for call in printed.call_args_list if call.args]
        self.assertIn("FAIL exit: SSH не отвечает", lines)
        schedule.assert_not_called()

    def test_stops_when_boot_state_cannot_be_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            with mock.patch.object(
                MODULE, "run_cascade_check", return_value=completed(0)
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE, "read_boot_id", return_value=None
            ), mock.patch.object(MODULE, "schedule_host_reboot") as schedule, mock.patch(
                "builtins.print"
            ):
                with self.assertRaises(SystemExit):
                    MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        schedule.assert_not_called()

    def test_stops_when_a_server_does_not_come_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            scheduled: list[str] = []
            with mock.patch.object(
                MODULE, "run_cascade_check", return_value=completed(0)
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE, "read_boot_id", return_value=BOOT_A
            ), mock.patch.object(
                MODULE,
                "schedule_host_reboot",
                side_effect=lambda *args: scheduled.append(args[-1]) or True,
            ), mock.patch.object(
                MODULE, "wait_for_host_reboot", return_value=False
            ), mock.patch.object(MODULE, "schedule_entry_reboot") as entry, mock.patch(
                "builtins.print"
            ):
                with self.assertRaises(SystemExit):
                    MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        self.assertEqual(scheduled, ["front"])
        entry.assert_not_called()


class CascadeProblemsTests(unittest.TestCase):
    def test_lists_fail_and_warn_detail_lines_only(self) -> None:
        report = (
            "OK   ok line\n"
            "FAIL ENTRY → EXIT: SSH: порт не отвечает за 5 с\n"
            "│ FAIL cascade-check: работа каскада нарушена\n"
            "WARN требуется перезагрузка\n"
        )
        self.assertEqual(
            MODULE.cascade_problems(report),
            ["FAIL ENTRY → EXIT: SSH: порт не отвечает за 5 с", "WARN требуется перезагрузка"],
        )


class EntryVerifyTests(unittest.TestCase):
    def test_unit_waits_longer_than_the_verification_script(self) -> None:
        # По умолчанию systemd снимает oneshot через 90 с, а скрипт спит 120 с и
        # повторяет проверку до десяти минут.
        self.assertIn("TimeoutStartSec=1800", MODULE.cascade_verify_unit())

    def test_script_saves_report_and_disables_its_unit(self) -> None:
        script = MODULE.cascade_verify_script()
        self.assertIn("/usr/local/sbin/cascade-check", script)
        self.assertIn("last-verify.txt", script)
        self.assertIn('echo "rc=$rc"', script)
        self.assertIn("systemctl disable kalimera-cascade-verify.service", script)

    def run_verify(self, results: str, *, automatic: bool, deadline_now: bool = False) -> tuple[Path, str]:
        """Выполнить скрипт проверки после загрузки ENTRY с подставными командами.

        results - коды возврата cascade-check по попыткам, последний повторяется;
        deadline_now - десять минут ожидания истекают сразу после первой попытки.
        """
        shell = shutil.which("sh")
        if shell is None or os.name == "nt":
            self.skipTest("нужен sh на Linux")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        state = root / "state"
        state.mkdir()
        fakes = {
            "cascade-check": (
                f'count=$(( $(cat {root}/count 2>/dev/null || echo 0) + 1 )); echo "$count" > {root}/count\n'
                f'set -- {results}; shift $(( count > $# ? $# - 1 : count - 1 ))\n'
                'echo "отчёт cascade-check"; exit "$1"\n'
            ),
            # Журналы лежат отдельно от самих подставных команд: запись в собственный
            # файл заставила бы sh выполнить дописанную строку как продолжение скрипта.
            "notifier": f'printf \'%s\\n\' "$2" >> {root}/sent\n',
            "sleep": f'echo "sleep $1" >> {root}/sleep.log\n',
            "systemctl": f'echo "systemctl $*" >> {root}/systemctl.log\n',
        }
        for name, body in fakes.items():
            path = root / name
            path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
            path.chmod(0o755)
        if automatic:
            (state / "auto-pending").write_text("2026-11-22 03:50 UTC\n", encoding="utf-8")
        with mock.patch.object(MODULE, "CASCADE_VERIFY_DIR", state), mock.patch.object(
            MODULE, "CASCADE_CHECK_PATH", root / "cascade-check"
        ), mock.patch.object(MODULE, "AUTO_PENDING_FILE", state / "auto-pending"), mock.patch.object(
            MODULE, "AUTO_BLOCK_FILE", state / "auto-blocked"
        ), mock.patch.object(MODULE, "AUTO_STATUS_FILE", state / "auto-status"), mock.patch.object(
            MODULE, "TELEGRAM_NOTIFIER_PATH", root / "notifier"
        ):
            script = MODULE.cascade_verify_script()
        self.assertIn("+ 600 ))", script)
        if deadline_now:
            script = script.replace("+ 600 ))", "+ 0 ))")
        path = root / "verify.sh"
        path.write_text(script, encoding="utf-8")
        env = {**os.environ, "PATH": f"{root}{os.pathsep}{os.environ['PATH']}"}
        result = subprocess.run([shell, str(path)], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        sent = (root / "sent").read_text(encoding="utf-8") if (root / "sent").exists() else ""
        return state, sent

    def test_check_is_repeated_until_the_cascade_is_up(self) -> None:
        # Туннели и хранилище секретов поднимаются не сразу после загрузки.
        state, sent = self.run_verify("1 1 3", automatic=True)
        self.assertIn("rc=3", (state / "last-verify.txt").read_text(encoding="utf-8"))
        self.assertEqual(sent, "AWG ENTRY: автоматическая перезагрузка каскада завершена; каскад исправен\n")
        self.assertFalse((state / "auto-blocked").exists())
        self.assertFalse((state / "auto-pending").exists())
        self.assertIn("выполнена, каскад исправен", (state / "auto-status").read_text(encoding="utf-8"))

    def test_cascade_that_stays_down_stops_the_automation(self) -> None:
        state, sent = self.run_verify("1", automatic=True, deadline_now=True)
        self.assertIn("rc=1", (state / "last-verify.txt").read_text(encoding="utf-8"))
        self.assertIn("после перезагрузки ENTRY каскад не прошёл проверку", (state / "auto-blocked").read_text(encoding="utf-8"))
        self.assertTrue(sent.startswith("AWG ENTRY: автоматическая перезагрузка каскада остановлена\n"), sent)
        self.assertIn("cascade-reboot auto on", sent)

    def test_manual_reboot_sends_nothing_and_never_stops_the_automation(self) -> None:
        state, sent = self.run_verify("1", automatic=False, deadline_now=True)
        self.assertEqual(sent, "")
        self.assertFalse((state / "auto-blocked").exists())
        self.assertIn("rc=1", (state / "last-verify.txt").read_text(encoding="utf-8"))

    def test_unit_runs_the_script_after_the_network(self) -> None:
        unit = MODULE.cascade_verify_unit()
        self.assertIn(f"ExecStart={MODULE.CASCADE_VERIFY_SCRIPT}", unit)
        self.assertIn("After=network-online.target", unit)
        self.assertIn("WantedBy=multi-user.target", unit)


class GuardParsingTests(unittest.TestCase):
    def test_rows_are_read_from_the_plain_output(self) -> None:
        report = MODULE.parse_guard_output(
            "exit",
            "exit.example.invalid | FAILED | rc=1 >>\n"
            "NEED\tyes\tlinux-image-6.8.0-100-generic\n"
            "OK\tпакеты в согласованном состоянии\t\n"
            "FAIL\tмодуль AmneziaWG не собран для ядра 6.8.0-100-generic\tsudo awg-kernel-guard\n"
            "HOLD\tядро 6.8.0-100-generic установлено недавно\t10 ч назад\n"
            "non-zero return code\n",
        )
        self.assertTrue(report.answered and report.need)
        self.assertEqual(report.need_reason, "linux-image-6.8.0-100-generic")
        self.assertEqual(
            report.problems("FAIL"), ["модуль AmneziaWG не собран для ядра 6.8.0-100-generic: sudo awg-kernel-guard"]
        )
        self.assertEqual(report.problems("HOLD"), ["ядро 6.8.0-100-generic установлено недавно: 10 ч назад"])

    def test_output_without_the_need_row_is_not_an_answer(self) -> None:
        # Программа не установлена или команда не выполнилась: считать сервер
        # проверенным по умолчанию нельзя.
        for output in ("", "exit | UNREACHABLE!\n", "bash: kalimera-reboot-guard: command not found\n"):
            with self.subTest(output=output):
                self.assertFalse(MODULE.parse_guard_output("exit", output).answered)

    def test_remote_guard_is_called_with_plain_output_and_a_long_timeout(self) -> None:
        answer = completed(0, "NEED\tno\t\nOK\tпакеты в согласованном состоянии\t\n")
        with mock.patch.object(MODULE, "ansible_adhoc", return_value=answer) as adhoc:
            report = MODULE.run_reboot_guard(ROOT, ROOT / "hosts.yml", ROOT / "vault", "front", "prepare")
        self.assertTrue(report.answered)
        self.assertFalse(report.need)
        self.assertEqual(adhoc.call_args.args[4:6], ("command", f"{MODULE.REBOOT_GUARD_PATH} prepare"))
        self.assertEqual(
            adhoc.call_args.kwargs, {"become": True, "oneline": False, "timeout": MODULE.GUARD_TIMEOUT_SECONDS}
        )

    def test_unreachable_server_gives_no_answer(self) -> None:
        with mock.patch.object(MODULE, "ansible_adhoc", return_value=None):
            self.assertFalse(
                MODULE.run_reboot_guard(ROOT, ROOT / "hosts.yml", ROOT / "vault", "exit", "check").answered
            )

    def test_plain_output_drops_the_one_line_flag(self) -> None:
        with mock.patch.object(MODULE, "require_command", return_value="ansible"), mock.patch.object(
            MODULE.subprocess, "run", return_value=completed(0)
        ) as run:
            MODULE.ansible_adhoc(ROOT, ROOT / "hosts.yml", ROOT / "vault", "front", "command", "true")
            self.assertIn("-o", run.call_args.args[0])
            MODULE.ansible_adhoc(
                ROOT, ROOT / "hosts.yml", ROOT / "vault", "front", "command", "true", oneline=False, timeout=5
            )
            self.assertNotIn("-o", run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["timeout"], 5)


class AutoRebootCase(unittest.TestCase):
    PLAN = ["front", "exit", "entry"]

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.sent: list[str] = []
        patches = {
            "AUTO_BLOCK_FILE": self.state / "auto-blocked",
            "AUTO_OFF_FILE": self.state / "auto-off",
            "AUTO_LAST_FILE": self.state / "auto-last",
            "AUTO_PENDING_FILE": self.state / "auto-pending",
            "AUTO_STATUS_FILE": self.state / "auto-status",
            "CASCADE_VERIFY_DIR": self.state,
        }
        for name, value in patches.items():
            patcher = mock.patch.object(MODULE, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, replacement in (
            ("telegram_notify", lambda text: self.sent.append(text) or True),
            ("print", mock.Mock()),
        ):
            target = MODULE if name != "print" else None
            patcher = mock.patch.object(target, name, replacement) if target else mock.patch("builtins.print")
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(MODULE.time, "sleep")
        self.sleep = patcher.start()
        self.addCleanup(patcher.stop)

    def decide(self, guard_run, *, rows=(), settings=None, now=None):
        with mock.patch.object(MODULE, "run_reboot_guard", side_effect=guard_run):
            return MODULE.decide_auto_reboot(
                self.root, self.root / "hosts.yml", self.root / "vault", self.PLAN,
                settings or MODULE.AutoRebootSettings(), list(rows), now=now,
            )


class AutoRebootDecisionTests(AutoRebootCase):
    def test_healthy_cascade_with_a_pending_update_is_rebooted(self) -> None:
        decision = self.decide(guards())
        self.assertEqual(decision.action, "reboot")
        self.assertEqual(decision.groups, ("front", "exit", "entry"))
        self.assertEqual(decision.line(), "выполняется сейчас: FRONT, EXIT, ENTRY (linux-image-6.8.0-100-generic)")

    def test_nothing_to_do_without_a_pending_update(self) -> None:
        run = guards(**{group: guard(group, need=False) for group in self.PLAN})
        self.assertEqual(self.decide(run).line(), "не требуется")

    def test_only_servers_that_need_it_are_rebooted(self) -> None:
        run = guards(**{"exit": guard("exit", need=False), "entry": guard("entry", need=False)})
        self.assertEqual(self.decide(run).groups, ("front",))

    def test_any_guard_failure_defers_the_whole_reboot(self) -> None:
        # Серверы перезагружаются одним окном: если один не готов, ждут все.
        run = guards(**{"exit": guard("exit", fail=("initramfs ядра 6.8.0-100-generic повреждён",))})
        decision = self.decide(run)
        self.assertEqual(decision.action, "deferred")
        self.assertEqual(decision.reason, "EXIT: initramfs ядра 6.8.0-100-generic повреждён")

    def test_fresh_kernel_defers_the_automatic_reboot(self) -> None:
        run = guards(**{"entry": guard("entry", hold=("ядро 6.8.0-100-generic установлено недавно",))})
        decision = self.decide(run)
        self.assertEqual(decision.action, "deferred")
        self.assertIn("ENTRY: ядро 6.8.0-100-generic установлено недавно", decision.reason)

    def test_problem_on_a_server_that_is_not_rebooted_does_not_block(self) -> None:
        # EXIT перезагружать не нужно: его свежее ядро не мешает перезагрузить FRONT.
        run = guards(**{
            "exit": guard("exit", need=False, hold=("сервер загружен недавно",)),
            "entry": guard("entry", need=False),
        })
        self.assertEqual(self.decide(run).action, "reboot")

    def test_cascade_with_errors_is_not_rebooted(self) -> None:
        # Исправный каскад не должен стать неисправным из-за планового обновления,
        # а неисправному перезагрузка без присмотра может добавить отказов.
        rows = [
            ("ENTRY", "OK", "служба dnsmasq", "", "", ""),
            ("LINK", "FAIL", "туннель ENTRY–EXIT: TCP через туннель", "ни одного подключения за 10 с", "", ""),
        ]
        decision = self.decide(guards(), rows=rows)
        self.assertEqual(decision.action, "deferred")
        self.assertIn("LINK: туннель ENTRY–EXIT: TCP через туннель: ни одного подключения за 10 с", decision.reason)

    def test_warnings_do_not_block(self) -> None:
        rows = [("ENTRY", "WARN", "неисправные модули systemd", "certbot.service", "", "")]
        self.assertEqual(self.decide(guards(), rows=rows).action, "reboot")

    def test_silent_server_defers(self) -> None:
        run = guards(**{"front": MODULE.GuardReport("front", answered=False)})
        decision = self.decide(run)
        self.assertEqual((decision.action, decision.reason), ("deferred", "предохранители не ответили: FRONT"))

    def test_not_more_often_than_the_interval(self) -> None:
        now = 1_800_000_000.0
        (self.state / "auto-last").write_text(str(int(now - 2 * 86400)), encoding="utf-8")
        decision = self.decide(guards(), now=now)
        self.assertEqual(decision.action, "deferred")
        self.assertIn("была 2 дн. назад, интервал 6 дн.", decision.reason)
        (self.state / "auto-last").write_text(str(int(now - 7 * 86400)), encoding="utf-8")
        self.assertEqual(self.decide(guards(), now=now).action, "reboot")

    def test_running_package_installation_is_waited_for(self) -> None:
        busy = guard("exit", wait=("идёт установка пакетов",))
        run = guards(**{"exit": [busy, busy, guard("exit")]})
        self.assertEqual(self.decide(run).action, "reboot")
        self.assertEqual(self.sleep.call_count, 2)

    def test_installation_that_never_ends_defers(self) -> None:
        run = guards(**{"exit": guard("exit", wait=("идёт установка пакетов",))})
        decision = self.decide(run)
        self.assertEqual(decision.action, "deferred")
        self.assertEqual(self.sleep.call_count, MODULE.GUARD_WAIT_ATTEMPTS - 1)

    def test_switched_off_in_three_ways(self) -> None:
        decision = self.decide(guards(), settings=MODULE.AutoRebootSettings(enabled=False))
        self.assertEqual(decision.action, "disabled")
        (self.state / "auto-off").write_text("x\n", encoding="utf-8")
        self.assertIn("cascade-reboot auto off", self.decide(guards()).reason)
        (self.state / "auto-off").unlink()
        (self.state / "auto-blocked").write_text("2026-11-22 03:50 UTC: EXIT не вернулся после перезагрузки\n", encoding="utf-8")
        decision = self.decide(guards())
        self.assertEqual(decision.action, "blocked")
        self.assertIn("EXIT не вернулся после перезагрузки", decision.line())
        self.assertIn("cascade-reboot auto on", decision.line())

    def test_stopped_automation_does_not_even_ask_the_servers(self) -> None:
        (self.state / "auto-blocked").write_text("причина\n", encoding="utf-8")
        run = guards()
        self.decide(run)
        self.assertEqual(run.calls, [])

    def test_settings_come_from_the_inventory(self) -> None:
        production = self.root / "production"
        (production / "group_vars" / "all").mkdir(parents=True)
        self.assertEqual(MODULE.auto_reboot_settings(production), MODULE.AutoRebootSettings(True, 6))
        MODULE.yaml_write(
            production / "group_vars" / "all" / "main.yml",
            {"awg_auto_reboot_enabled": False, "awg_auto_reboot_min_interval_days": 13},
        )
        self.assertEqual(MODULE.auto_reboot_settings(production), MODULE.AutoRebootSettings(False, 13))


class AutoRebootRunTests(AutoRebootCase):
    def execute(self, guard_run, groups=("front", "exit", "entry"), *, returns=True, cascade=True, boot=BOOT_A):
        scheduled: list[str] = []
        with mock.patch.object(MODULE, "run_reboot_guard", side_effect=guard_run), mock.patch.object(
            MODULE, "read_boot_id", return_value=boot
        ), mock.patch.object(
            MODULE, "schedule_host_reboot", side_effect=lambda *args: scheduled.append(args[-1]) or True
        ), mock.patch.object(MODULE, "wait_for_host_reboot", return_value=returns), mock.patch.object(
            MODULE, "wait_for_cascade", return_value=cascade
        ), mock.patch.object(MODULE, "schedule_entry_reboot") as entry:
            MODULE.execute_auto_reboot(self.root, self.root / "hosts.yml", self.root / "vault", tuple(groups))
        return scheduled, entry

    def test_servers_are_rebooted_one_by_one_and_entry_reports_after_boot(self) -> None:
        run = guards()
        scheduled, entry = self.execute(run)
        self.assertEqual(scheduled, ["front", "exit"])
        entry.assert_called_once()
        # Перед каждой перезагрузкой - подготовка именно этого сервера.
        self.assertEqual(run.calls, [("front", "prepare"), ("exit", "prepare"), ("entry", "prepare")])
        # Итог сообщит проверка после загрузки ENTRY: до неё сообщений нет.
        self.assertTrue((self.state / "auto-pending").exists())
        self.assertEqual(self.sent, [])
        self.assertTrue((self.state / "auto-last").read_text(encoding="utf-8").strip().isdigit())

    def test_without_entry_the_result_is_reported_at_once(self) -> None:
        scheduled, entry = self.execute(guards(), groups=("front", "exit"))
        self.assertEqual(scheduled, ["front", "exit"])
        entry.assert_not_called()
        self.assertEqual(
            self.sent, ["AWG ENTRY: автоматическая перезагрузка каскада завершена (FRONT, EXIT); каскад исправен"]
        )
        self.assertFalse((self.state / "auto-blocked").exists())

    def test_server_that_does_not_come_back_stops_everything(self) -> None:
        scheduled, entry = self.execute(guards(), returns=False)
        self.assertEqual(scheduled, ["front"])  # EXIT и ENTRY не тронуты
        entry.assert_not_called()
        self.assertIn("FRONT не вернулся после перезагрузки", (self.state / "auto-blocked").read_text(encoding="utf-8"))
        self.assertEqual(len(self.sent), 1)
        self.assertTrue(self.sent[0].startswith("AWG ENTRY: автоматическая перезагрузка каскада остановлена\n"))
        self.assertIn("Остальные серверы не перезагружались.", self.sent[0])
        self.assertIn("cascade-reboot auto on", self.sent[0])

    def test_cascade_broken_after_a_reboot_stops_everything(self) -> None:
        scheduled, entry = self.execute(guards(), cascade=False)
        self.assertEqual(scheduled, ["front"])
        entry.assert_not_called()
        self.assertIn("после перезагрузки FRONT каскад не прошёл проверку", (self.state / "auto-blocked").read_text(encoding="utf-8"))

    def test_failed_preparation_is_a_delay_not_a_failure(self) -> None:
        # Сервер ещё не тронут: автоматика не останавливается, а ждёт следующего окна.
        broken = guard("exit", fail=("секреты не сохранены в зашифрованный пакет",))
        scheduled, entry = self.execute(guards(**{"exit": broken}))
        self.assertEqual(scheduled, ["front"])
        entry.assert_not_called()
        self.assertFalse((self.state / "auto-blocked").exists())
        self.assertEqual(len(self.sent), 1)
        self.assertTrue(self.sent[0].startswith("AWG ENTRY: автоматическая перезагрузка каскада отложена\n"))
        self.assertIn("EXIT: подготовка не пройдена - секреты не сохранены в зашифрованный пакет", self.sent[0])
        self.assertIn("Перезагружены: FRONT.", self.sent[0])

    def test_entry_is_not_rebooted_when_its_preparation_fails(self) -> None:
        broken = guard("entry", fail=("хранилище секретов не откроется после перезагрузки",))
        scheduled, entry = self.execute(guards(**{"entry": broken}))
        self.assertEqual(scheduled, ["front", "exit"])
        entry.assert_not_called()
        self.assertFalse((self.state / "auto-pending").exists())

    def test_server_silent_before_its_reboot_stops_everything(self) -> None:
        scheduled, entry = self.execute(guards(), boot=None)
        self.assertEqual(scheduled, [])
        entry.assert_not_called()
        self.assertIn("FRONT перестал отвечать перед перезагрузкой", (self.state / "auto-blocked").read_text(encoding="utf-8"))


class WeeklyRunTests(AutoRebootCase):
    def weekly(self, guard_run, rows, *, execute=None):
        production = self.root / "production"
        (production / "group_vars" / "all").mkdir(parents=True, exist_ok=True)
        (production / "group_vars" / "all" / "vault.yml").write_text("x", encoding="utf-8")
        MODULE.yaml_write(production / "hosts.yml", hosts_document("entry", "exit", "front"))
        (self.root / "vault.pass").write_text("pass\n", encoding="utf-8")
        with mock.patch.object(MODULE, "run_reboot_guard", side_effect=guard_run), mock.patch.object(
            MODULE, "read_cascade_rows", return_value=(0, rows)
        ), mock.patch.object(MODULE, "execute_auto_reboot", side_effect=execute) as executed:
            MODULE.run_cascade_weekly(self.root, production, self.root / "vault.pass")
        return executed

    def test_digest_is_sent_before_the_reboot_starts(self) -> None:
        # Счёт самовосстановления хранится в RAM: после перезагрузки его уже нет.
        order: list[str] = []
        self.sent = order
        rows = [("ENTRY", "OK", "самовосстановление: за 7 дней сбоев 2, восстановлено 2", "", "", "")]
        executed = self.weekly(guards(), rows, execute=lambda *args: order.append("reboot"))
        executed.assert_called_once()
        self.assertEqual(executed.call_args.args[3], ("front", "exit", "entry"))
        self.assertEqual(len(order), 2)
        self.assertTrue(order[0].startswith("AWG ENTRY: еженедельная сводка каскада\n"))
        self.assertIn("Перезагрузка: выполняется сейчас: FRONT, EXIT, ENTRY", order[0])
        self.assertEqual(order[1], "reboot")

    def test_quiet_week_still_sends_the_digest(self) -> None:
        # Сводка служит сигналом жизни: не пришла - стоит заглянуть.
        run = guards(**{group: guard(group, need=False) for group in self.PLAN})
        executed = self.weekly(run, [("ENTRY", "OK", "служба dnsmasq", "", "", "")])
        executed.assert_not_called()
        self.assertEqual(len(self.sent), 1)
        self.assertIn("Перезагрузка: не требуется", self.sent[0])
        self.assertIn("не требуется", (self.state / "auto-status").read_text(encoding="utf-8"))

    def test_interrupted_reboot_stops_the_automation(self) -> None:
        def interrupted(*_args):
            raise SystemExit("exit отклонил ключ ENTRY (Permission denied)")

        self.weekly(guards(), [], execute=interrupted)
        self.assertIn(
            "перезагрузка прервана: exit отклонил ключ ENTRY", (self.state / "auto-blocked").read_text(encoding="utf-8")
        )


class WeeklyDigestTests(unittest.TestCase):
    def test_healthy_cascade(self) -> None:
        rows = [
            ("ENTRY", "OK", "служба dnsmasq", "", "", ""),
            ("ENTRY", "OK", "самовосстановление: за 7 дней сбоев 2, восстановлено 2", "Fail2Ban активен (перезапуск Fail2Ban)", "", ""),
            ("EXIT", "OK", "самовосстановление: за 7 дней сбоев не было", "", "", ""),
            ("LINK", "OK", "ENTRY → EXIT: SSH", "TCP 50 мс", "", "50"),
        ]
        self.assertEqual(
            MODULE.weekly_digest(rows, "не требуется").splitlines(),
            [
                "AWG ENTRY: еженедельная сводка каскада",
                "Состояние: все проверки пройдены (OK 4 · WARN 0 · FAIL 0)",
                "Самовосстановление:",
                "  ENTRY: за 7 дней сбоев 2, восстановлено 2",
                "  EXIT: за 7 дней сбоев не было",
                "Обновления компонентов: нет",
                "Перезагрузка: не требуется",
            ],
        )

    def test_problems_updates_and_unrepaired_errors_are_listed(self) -> None:
        update = "обновление компонента: доступен AmneziaWG: amneziawg-dkms 1.0 → 1.1"
        command = "на ENTRY: kalimera-deploy --resume --update-amneziawg"
        rows = [
            ("ENTRY", "OK", update, command, "", ""),
            ("EXIT", "OK", update, command, "", ""),
            (
                "EXIT", "WARN", "самовосстановление: за 7 дней сбоев 1, восстановлено 0, не восстановлено 1",
                "служба Unbound - попытки исчерпаны", "подробности: self-heal status", "",
            ),
            ("FRONT", "WARN", "регистрация домена example.uk истекает 2026-12-11 (через 19 дн.)", "", "продлите", ""),
            ("LINK", "FAIL", "туннель ENTRY–EXIT: TCP через туннель", "ни одного подключения за 10 с", "", ""),
        ]
        text = MODULE.weekly_digest(rows, "требуется, отложена - EXIT: ядро установлено недавно")
        self.assertIn("Состояние: работа каскада нарушена (OK 2 · WARN 2 · FAIL 1)", text)
        self.assertIn("  WARN FRONT: регистрация домена example.uk истекает 2026-12-11 (через 19 дн.)", text)
        self.assertIn("  FAIL LINK: туннель ENTRY–EXIT: TCP через туннель: ни одного подключения за 10 с", text)
        self.assertIn(
            "  EXIT: за 7 дней сбоев 1, восстановлено 0, не восстановлено 1 - служба Unbound - попытки исчерпаны", text
        )
        # Одно обновление, найденное на двух серверах, называется один раз и с командой.
        self.assertEqual(text.count("доступен AmneziaWG"), 1)
        self.assertIn("  доступен AmneziaWG: amneziawg-dkms 1.0 → 1.1 → " + command, text)
        self.assertTrue(text.endswith("Перезагрузка: требуется, отложена - EXIT: ядро установлено недавно"))

    def test_missing_report_is_said_plainly(self) -> None:
        text = MODULE.weekly_digest([], "не требуется")
        self.assertIn("Состояние: отчёт cascade-check не получен", text)

    def test_long_list_of_problems_is_cut(self) -> None:
        rows = [("ENTRY", "WARN", f"замечание {index}", "", "", "") for index in range(12)]
        text = MODULE.weekly_digest(rows, "не требуется")
        self.assertIn("… и ещё замечаний: 4; подробности: cascade-check", text)

    def test_rows_are_read_from_cascade_check_tsv(self) -> None:
        output = "ENTRY\tOK\tслужба\t\t\t\nLINK\tWARN\tтуннель\t731 мс\tпроверьте\t731\nмусор\n"
        with mock.patch.object(MODULE.Path, "is_file", return_value=True), mock.patch.object(
            MODULE.subprocess, "run", return_value=completed(3, output)
        ) as run:
            code, rows = MODULE.read_cascade_rows()
        self.assertEqual(run.call_args.args[0], [str(MODULE.CASCADE_CHECK_PATH), "--tsv"])
        self.assertEqual(code, 3)
        self.assertEqual(rows, [("ENTRY", "OK", "служба", "", "", ""), ("LINK", "WARN", "туннель", "731 мс", "проверьте", "731")])


class AutoSwitchTests(AutoRebootCase):
    def test_switching_on_clears_the_stop_after_a_failure(self) -> None:
        (self.state / "auto-off").write_text("x\n", encoding="utf-8")
        (self.state / "auto-blocked").write_text("причина\n", encoding="utf-8")
        MODULE.set_auto_reboot(True)
        self.assertFalse((self.state / "auto-off").exists())
        self.assertFalse((self.state / "auto-blocked").exists())
        MODULE.set_auto_reboot(False)
        self.assertTrue((self.state / "auto-off").exists())

    def test_status_names_the_state_and_the_reason(self) -> None:
        production = self.root / "production"
        (production / "group_vars" / "all").mkdir(parents=True)
        with mock.patch.object(MODULE.subprocess, "run", return_value=completed(0, "Sun 2026-11-22 03:50:00 UTC\n")):
            self.assertEqual(
                MODULE.auto_reboot_status_lines(production),
                ["Автоматическая перезагрузка: включена", "Следующее еженедельное окно: Sun 2026-11-22 03:50:00 UTC"],
            )
            (self.state / "auto-blocked").write_text("2026-11-22 03:55 UTC: EXIT не вернулся после перезагрузки\n", encoding="utf-8")
            lines = MODULE.auto_reboot_status_lines(production)
        self.assertIn("остановлена после неудачи - 2026-11-22 03:55 UTC: EXIT не вернулся после перезагрузки", lines[0])
        self.assertIn("cascade-reboot auto on", lines[0])


class StatusOutputTests(AutoRebootCase):
    def test_window_is_shown_with_its_schedule(self) -> None:
        # Найдено на рабочем каскаде: окно «воскресенье 03:50 Asia/Manila» показано
        # как «Sat 19:50 UTC» - без расписания это выглядело ошибкой дня недели.
        answers = {
            "NextElapseUSecRealtime": "Sat 2026-11-21 19:50:00 UTC\n",
            "TimersCalendar": "{ OnCalendar=Sun *-*-* 03:50:00 Asia/Manila ; next_elapse=Sat 2026-11-21 19:50:00 UTC }\n",
        }
        production = self.root / "production"
        (production / "group_vars" / "all").mkdir(parents=True)
        with mock.patch.object(
            MODULE.subprocess, "run", side_effect=lambda argv, **_kwargs: completed(0, answers[argv[4]])
        ):
            lines = MODULE.auto_reboot_status_lines(production)
        self.assertEqual(
            lines[-1],
            "Следующее еженедельное окно: Sat 2026-11-21 19:50:00 UTC (расписание: Sun *-*-* 03:50:00 Asia/Manila)",
        )

    def test_last_check_is_a_summary_not_the_whole_report(self) -> None:
        # Раньше печатался весь отчёт cascade-check: сотни строк, за которыми не
        # было видно состояния автоматики.
        report = self.state / "last-verify.txt"
        body = "".join(f"OK   проверка {index}\n" for index in range(250))
        report.write_text(body + "GOOD: все проверки пройдены (250)\nrc=0\n", encoding="utf-8")
        lines = MODULE.last_verify_lines(report)
        self.assertEqual(len(lines), 2, lines)
        self.assertRegex(
            lines[0],
            r"^Проверка после последней перезагрузки ENTRY \(\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\): каскад исправен$",
        )
        self.assertEqual(lines[1], f"Полный отчёт: sudo cat {report}")

    def test_last_check_lists_what_failed(self) -> None:
        report = self.state / "last-verify.txt"
        report.write_text(
            "OK   служба dnsmasq\nFAIL туннель ENTRY–EXIT: TCP через туннель: ни одного подключения за 10 с\n"
            "WARN неисправные модули systemd: certbot.service\nrc=1\n",
            encoding="utf-8",
        )
        lines = MODULE.last_verify_lines(report)
        self.assertTrue(lines[0].endswith(": каскад не прошёл проверку"), lines[0])
        self.assertEqual(
            lines[1:3],
            [
                "  FAIL туннель ENTRY–EXIT: TCP через туннель: ни одного подключения за 10 с",
                "  WARN неисправные модули systemd: certbot.service",
            ],
        )
        report.write_text("WARN замечание\nrc=3\n", encoding="utf-8")
        self.assertTrue(MODULE.last_verify_lines(report)[0].endswith(": каскад работает, есть замечания"))

    def test_status_without_a_report_tells_running_from_never(self) -> None:
        with mock.patch.object(MODULE.subprocess, "run", return_value=completed(0)), mock.patch(
            "builtins.print"
        ) as printed:
            MODULE.cascade_reboot_status()
        self.assertIn("ещё идёт", printed.call_args.args[0])
        with mock.patch.object(MODULE.subprocess, "run", return_value=completed(1)), mock.patch(
            "builtins.print"
        ) as printed:
            MODULE.cascade_reboot_status()
        self.assertIn("ещё не перезагружался", printed.call_args.args[0])


class CascadeConfirmTests(AutoRebootCase):
    OK_ROWS = [("ENTRY", "OK", "служба dnsmasq", "", "", "")]
    FAIL_ROWS = [("DNS", "FAIL", "DNS: yandex.ru напрямую через RU DoH", "нет ответа", "", "")]

    def confirmed(self, *answers):
        results = list(answers)
        with mock.patch.object(MODULE, "read_cascade_rows", side_effect=lambda: results.pop(0)) as read:
            code, rows = MODULE.read_confirmed_cascade_rows()
        return code, rows, read.call_count

    def test_one_off_failure_is_not_taken_for_a_broken_cascade(self) -> None:
        # Найдено на рабочем каскаде: первый cascade-check дал FAIL из-за одного
        # потерянного ответа DNS, второй прошёл. По единственному запуску автоматика
        # отложила бы перезагрузку на неделю.
        code, rows, calls = self.confirmed((1, self.FAIL_ROWS), (0, self.OK_ROWS))
        self.assertEqual((code, rows, calls), (0, self.OK_ROWS, 2))
        self.assertEqual(self.sleep.call_count, 1)

    def test_healthy_report_is_read_once(self) -> None:
        self.assertEqual(self.confirmed((0, self.OK_ROWS))[2], 1)
        self.sleep.assert_not_called()

    def test_lasting_failure_is_reported_after_three_runs(self) -> None:
        code, rows, calls = self.confirmed((1, self.FAIL_ROWS), (1, self.FAIL_ROWS), (1, self.FAIL_ROWS))
        self.assertEqual((code, rows, calls), (1, self.FAIL_ROWS, 3))

    def test_missing_report_is_asked_for_again(self) -> None:
        code, rows, calls = self.confirmed((1, []), (0, self.OK_ROWS))
        self.assertEqual((rows, calls), (self.OK_ROWS, 2))


class CommandWiringTests(unittest.TestCase):
    def test_automation_commands_are_exposed_on_entry(self) -> None:
        gateway = (ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("'auto on') reboot_args=(--cascade-reboot-auto on)", gateway)
        self.assertIn("'auto off') reboot_args=(--cascade-reboot-auto off)", gateway)
        tasks = (ROOT / "roles" / "operations" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("{src: reboot-guard.sh.j2, dest: kalimera-reboot-guard}", tasks)
        self.assertIn("name: kalimera-weekly.timer", tasks)
        manifest = (ROOT / "roles" / "operations" / "templates" / "awg-managed-integrity.sh.j2").read_text(
            encoding="utf-8"
        )
        for path in ("/usr/local/sbin/kalimera-reboot-guard", "/etc/systemd/system/kalimera-weekly.timer"):
            self.assertIn(path, manifest)

    def test_weekly_job_does_not_depend_on_package_indexes(self) -> None:
        # Окно не должно сорваться из-за недоступности PyPI или Ansible Galaxy:
        # программа запускается из окружения, установленного последним deploy.
        script = (ROOT / "roles" / "operations" / "templates" / "kalimera-weekly.sh.j2").read_text(encoding="utf-8")
        direct = script.index('exec "$venv/bin/python"')
        self.assertLess(direct, script.index('exec "$repo/deploy" --cascade-weekly'))
        self.assertIn("--cascade-weekly", script[direct:])

    def test_missed_window_is_not_caught_up(self) -> None:
        # Перезагрузка в случайное время после включения сервера хуже, чем через неделю.
        timer = (ROOT / "roles" / "operations" / "templates" / "kalimera-weekly.timer.j2").read_text(encoding="utf-8")
        self.assertIn("Persistent=false", timer)
        self.assertIn("RandomizedDelaySec=0", timer)

    def weekly_calendar(self, **variables) -> str:
        import jinja2

        environment = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
        text = (ROOT / "roles" / "operations" / "templates" / "kalimera-weekly.timer.j2").read_text(encoding="utf-8")
        rendered = environment.from_string(text).render(**variables)
        self.assertTrue(rendered.startswith("[Unit]\n"), rendered[:80])
        return next(line for line in rendered.splitlines() if line.startswith("OnCalendar=")).removeprefix("OnCalendar=")

    def test_window_follows_the_nightly_maintenance(self) -> None:
        cases = (
            ({}, "Sun *-*-* 06:50:00"),
            ({"awg_maintenance_calendar": "*-*-* 02:20:00 Asia/Manila"}, "Sun *-*-* 03:50:00 Asia/Manila"),
            ({"awg_maintenance_calendar": "*-*-* 05:20:00", "awg_weekly_day": "Wed"}, "Wed *-*-* 06:50:00"),
            # Окно после полуночи приходится на следующий день недели.
            ({"awg_maintenance_calendar": "*-*-* 23:30:00 Europe/Moscow", "awg_weekly_day": "Sat"}, "Sun *-*-* 01:00:00 Europe/Moscow"),
            ({"awg_maintenance_calendar": "*-*-* 23:30:00", "awg_weekly_day": "Sun"}, "Mon *-*-* 01:00:00"),
            ({"awg_weekly_offset_minutes": 30}, "Sun *-*-* 05:50:00"),
            # Готовое выражение и нестандартное время обслуживания.
            ({"awg_weekly_calendar": "Tue *-*-* 04:00:00 UTC"}, "Tue *-*-* 04:00:00 UTC"),
            ({"awg_maintenance_calendar": "Mon..Fri 05:20"}, "Sun *-*-* 07:00:00"),
            ({"awg_weekly_day": "воскресенье"}, "Sun *-*-* 07:00:00"),
        )
        for variables, expected in cases:
            with self.subTest(variables=variables):
                self.assertEqual(self.weekly_calendar(**variables), expected)

    def test_gateway_accepts_only_fixed_forms_and_only_on_entry(self) -> None:
        text = (ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("cascade-reboot)", text)
        self.assertIn("maintenance-time)", text)
        self.assertIn("'--yes') reboot_args=(--cascade-reboot --yes)", text)
        self.assertIn("'status') reboot_args=(--cascade-reboot-status)", text)
        self.assertIn("maintenance_args=(--maintenance-show)", text)
        self.assertIn('(--maintenance-time "$1" --maintenance-zone "$2")', text)
        self.assertIn("cascade-reboot запускается только на ENTRY", text)
        self.assertIn("maintenance-time запускается только на ENTRY", text)

    def test_shell_functions_exist_only_in_the_entry_block(self) -> None:
        text = (ROOT / "roles" / "terminal" / "templates" / "kalimera-shell-tools.sh.j2").read_text(
            encoding="utf-8"
        )
        start = text.index("{% if awg_node_role | default('') == 'entry' %}")
        end = text.index("{% endif %}", start)
        block = text[start:end]
        self.assertIn("function cascade-reboot { _kalimera_admin cascade-reboot", block)
        self.assertIn("function maintenance-time { _kalimera_admin maintenance-time", block)

    def test_menu_groups_all_cascade_commands_in_one_section(self) -> None:
        text = (ROOT / "roles" / "terminal" / "templates" / "kalimera-status.py.j2").read_text(
            encoding="utf-8"
        )
        start = text.index('"КАСКАД: ПРОВЕРКА И ОБСЛУЖИВАНИЕ"')
        section = text[start : text.index("preferred_label_width", start)]
        for command in (
            "cascade-check",
            "cascade-reboot",
            "cascade-reboot --yes",
            "cascade-reboot status",
            "maintenance-time ЧЧ:ММ ЗОНА",
            "maintenance-time show",
        ):
            with self.subTest(command=command):
                self.assertIn(f'"{command}"', section)


if __name__ == "__main__":
    unittest.main()

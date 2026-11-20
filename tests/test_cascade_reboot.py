#!/usr/bin/env python3
"""Команды обслуживания каскада: время ночного обслуживания и cascade-reboot.

cascade-reboot перезагружает FRONT, затем EXIT: для каждого сервера запоминает
boot_id, планирует перезагрузку, ждёт новый boot_id и проверяет каскад. ENTRY
перезагружается последним и проверяется после загрузки отдельным юнитом systemd.
Все вызовы Ansible ограничены по времени, поэтому команда не зависает молча.
"""

from __future__ import annotations

import importlib.util
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


class CascadeRebootRunTests(unittest.TestCase):
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
        # По умолчанию systemd снимает oneshot через 90 с, а скрипт спит 120 с.
        self.assertIn("TimeoutStartSec=900", MODULE.cascade_verify_unit())

    def test_script_saves_report_and_disables_its_unit(self) -> None:
        script = MODULE.cascade_verify_script()
        self.assertIn("/usr/local/sbin/cascade-check", script)
        self.assertIn("last-verify.txt", script)
        self.assertIn('echo "rc=$?"', script)
        self.assertIn("systemctl disable kalimera-cascade-verify.service", script)

    def test_unit_runs_the_script_after_the_network(self) -> None:
        unit = MODULE.cascade_verify_unit()
        self.assertIn(f"ExecStart={MODULE.CASCADE_VERIFY_SCRIPT}", unit)
        self.assertIn("After=network-online.target", unit)
        self.assertIn("WantedBy=multi-user.target", unit)


class CommandWiringTests(unittest.TestCase):
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

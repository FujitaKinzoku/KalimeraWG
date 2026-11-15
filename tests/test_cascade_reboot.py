#!/usr/bin/env python3
"""Команды обслуживания каскада: время ночного обслуживания и cascade-reboot.

cascade-reboot перезагружает FRONT, затем EXIT, проверяя каскад после каждого
сервера; ENTRY перезагружается последним и проверяется после загрузки отдельным
юнитом systemd. Проверяется порядок, остановка при ошибке и защита от запуска
без подтверждения.
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
            MODULE.reboot_cascade_group(ROOT, ROOT / "hosts.yml", ROOT / "vault", "entry")


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

    def test_refuses_to_start_when_the_cascade_already_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            with mock.patch.object(
                MODULE, "run_cascade_check", return_value=completed(1, "FAIL")
            ), mock.patch.object(MODULE, "reboot_cascade_group") as reboot, mock.patch(
                "builtins.print"
            ):
                with self.assertRaises(SystemExit):
                    MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        reboot.assert_not_called()

    def test_without_confirmation_nothing_is_rebooted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            with mock.patch.object(
                MODULE, "run_cascade_check", return_value=completed(0)
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE, "reboot_cascade_group"
            ) as reboot, mock.patch.object(MODULE, "schedule_entry_reboot") as schedule, mock.patch(
                "builtins.print"
            ):
                MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=False)
        reboot.assert_not_called()
        schedule.assert_not_called()

    def test_reboots_front_then_exit_then_schedules_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            rebooted: list[str] = []
            with mock.patch.object(
                MODULE, "run_cascade_check", return_value=completed(0)
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE,
                "reboot_cascade_group",
                side_effect=lambda *args: rebooted.append(args[-1]),
            ), mock.patch.object(
                MODULE, "wait_for_cascade", return_value=True
            ), mock.patch.object(MODULE, "schedule_entry_reboot") as schedule, mock.patch(
                "builtins.print"
            ):
                MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        self.assertEqual(rebooted, ["front", "exit"])
        schedule.assert_called_once()

    def test_stops_when_a_server_does_not_recover(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = self.make_production(root)
            rebooted: list[str] = []
            with mock.patch.object(
                MODULE, "run_cascade_check", return_value=completed(0)
            ), mock.patch.object(MODULE.subprocess, "run", return_value=completed(3)), mock.patch.object(
                MODULE,
                "reboot_cascade_group",
                side_effect=lambda *args: rebooted.append(args[-1]),
            ), mock.patch.object(
                MODULE, "wait_for_cascade", return_value=False
            ), mock.patch.object(MODULE, "schedule_entry_reboot") as schedule, mock.patch(
                "builtins.print"
            ):
                with self.assertRaises(SystemExit):
                    MODULE.run_cascade_reboot(root, production, root / "vault.pass", confirmed=True)
        self.assertEqual(rebooted, ["front"])
        schedule.assert_not_called()


class EntryVerifyTests(unittest.TestCase):
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
    def test_reboot_playbook_targets_only_the_selected_group(self) -> None:
        text = (ROOT / "playbooks" / "reboot.yml").read_text(encoding="utf-8")
        self.assertIn('hosts: "{{ cascade_reboot_group }}"', text)
        self.assertIn("ansible.builtin.reboot:", text)
        self.assertNotIn("hosts: entry", text)

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


if __name__ == "__main__":
    unittest.main()

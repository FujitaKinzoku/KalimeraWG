"""Таймер fwupd-refresh отключается на всех серверах при установке.

На VPS он ежедневно пытался обновить метаданные прошивок с LVFS, падал по
таймауту, если LVFS недоступен, и оставлял failed-модуль, из-за которого
server-audit не проходил на исправном сервере.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).parents[1]
TASKS = REPO / "roles" / "common" / "tasks" / "main.yml"
DEFAULTS = REPO / "roles" / "common" / "defaults" / "main.yml"


def conditions(task: dict) -> list[str]:
    when = task.get("when", [])
    return [when] if isinstance(when, str) else list(when)


class CommonFwupdRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))

    def test_toggle_is_on_by_default(self) -> None:
        defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        self.assertIs(defaults["common_disable_fwupd_refresh"], True)

    def test_timer_is_disabled_and_stopped_only_when_present(self) -> None:
        disable = [
            task
            for task in self.tasks
            if task.get("ansible.builtin.systemd_service", {}).get("name")
            == "fwupd-refresh.timer"
        ]
        self.assertEqual(len(disable), 1)
        module = disable[0]["ansible.builtin.systemd_service"]
        self.assertIs(module["enabled"], False)
        self.assertEqual(module["state"], "stopped")
        self.assertIn("common_disable_fwupd_refresh | bool", conditions(disable[0]))
        self.assertIn("common_fwupd_refresh_timer.stat.exists", conditions(disable[0]))

    def test_package_is_not_removed(self) -> None:
        for task in self.tasks:
            apt = task.get("ansible.builtin.apt", {})
            self.assertNotEqual(apt.get("state"), "absent")
            self.assertNotIn("fwupd", str(apt.get("name", "")))


if __name__ == "__main__":
    unittest.main()

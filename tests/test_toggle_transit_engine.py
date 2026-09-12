#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

import yaml


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "toggle-transit-engine.py"
SPEC = importlib.util.spec_from_file_location("toggle_transit_engine", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ToggleTransitEngineTests(unittest.TestCase):
    def _write_production(self, root: Path) -> Path:
        production = root / "production"
        group_vars = production / "group_vars"
        group_vars.mkdir(parents=True)
        (group_vars / "entry.yml").write_text(
            yaml.safe_dump(
                {
                    "entry_exit_interface": "awg3",
                    "entry_exit_tunnel_address": "10.77.0.2/32",
                    "awg3_transit_enabled": True,
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        (group_vars / "exit.yml").write_text(
            yaml.safe_dump(
                {
                    "exit_awg_address": "10.77.0.1/24",
                    "awg3_transit_enabled": True,
                    "exit_manage_awg_config": False,
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return production

    def test_kernel_engine_disables_userspace_transit_and_enables_awg0(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = self._write_production(Path(temporary))

            changed = MODULE.set_transit_engine(production, "kernel")

            self.assertTrue(changed)
            entry = MODULE.load_yaml(production / "group_vars" / "entry.yml")
            exit_vars = MODULE.load_yaml(production / "group_vars" / "exit.yml")
            self.assertEqual(entry["awg3_transit_enabled"], False)
            self.assertEqual(exit_vars["awg3_transit_enabled"], False)
            self.assertEqual(exit_vars["exit_manage_awg_config"], True)
            # Unrelated keys survive untouched.
            self.assertEqual(entry["entry_exit_tunnel_address"], "10.77.0.2/32")
            self.assertEqual(exit_vars["exit_awg_address"], "10.77.0.1/24")

    def test_userspace_engine_reverts_to_original_production_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = self._write_production(Path(temporary))

            MODULE.set_transit_engine(production, "kernel")
            changed_back = MODULE.set_transit_engine(production, "userspace")

            self.assertTrue(changed_back)
            entry = MODULE.load_yaml(production / "group_vars" / "entry.yml")
            exit_vars = MODULE.load_yaml(production / "group_vars" / "exit.yml")
            self.assertEqual(entry["awg3_transit_enabled"], True)
            self.assertEqual(exit_vars["awg3_transit_enabled"], True)
            self.assertEqual(exit_vars["exit_manage_awg_config"], False)

    def test_reapplying_same_engine_reports_no_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = self._write_production(Path(temporary))

            MODULE.set_transit_engine(production, "kernel")
            changed_again = MODULE.set_transit_engine(production, "kernel")

            self.assertFalse(changed_again)

    def test_unknown_engine_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = self._write_production(Path(temporary))

            with self.assertRaises(SystemExit):
                MODULE.set_transit_engine(production, "bogus")

    def test_missing_inventory_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary) / "production"
            production.mkdir()
            (production / "group_vars").mkdir()

            with self.assertRaises(SystemExit):
                MODULE.set_transit_engine(production, "kernel")


class ExitRoleInterfacePathTests(unittest.TestCase):
    """Пути AWG на EXIT должны выводиться из имени интерфейса.

    Захардкоженный awg0 ломал kernel-путь при exit_awg_interface: awg3 -
    роль писала awg0.conf, а awg-quick@awg3.service ждал awg3.conf через
    LoadCredential и падал с 243/CREDENTIALS.
    """

    REPO = Path(__file__).parents[1]
    DERIVED_KEYS = (
        "exit_awg_config_path",
        "exit_awg_candidate_path",
        "exit_awg_backup_dir",
    )

    def test_exit_awg_paths_derive_from_interface_name(self) -> None:
        defaults = yaml.safe_load(
            (self.REPO / "roles" / "exit" / "defaults" / "main.yml").read_text(
                encoding="utf-8"
            )
        )
        for key in self.DERIVED_KEYS:
            with self.subTest(key=key):
                self.assertIn("{{ exit_awg_interface }}", defaults[key])
                self.assertNotIn("awg0", defaults[key])

    def test_exit_awg_paths_stay_backward_compatible_for_awg0(self) -> None:
        import jinja2

        defaults = yaml.safe_load(
            (self.REPO / "roles" / "exit" / "defaults" / "main.yml").read_text(
                encoding="utf-8"
            )
        )
        rendered = {
            key: jinja2.Template(defaults[key]).render(exit_awg_interface="awg0")
            for key in self.DERIVED_KEYS
        }
        self.assertEqual(
            rendered["exit_awg_config_path"], "/etc/amnezia/amneziawg/awg0.conf"
        )
        self.assertEqual(rendered["exit_awg_candidate_path"], "/run/ansible-awg0.conf")
        self.assertEqual(
            rendered["exit_awg_backup_dir"], "/root/config-backups/exit/awg0"
        )

    def test_exit_backup_destination_is_not_hardcoded_to_awg0(self) -> None:
        tasks = (self.REPO / "roles" / "exit" / "tasks" / "main.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("awg0.conf.{{ ansible_date_time", tasks)
        self.assertIn(
            "{{ exit_awg_interface }}.conf.{{ ansible_date_time", tasks
        )


if __name__ == "__main__":
    unittest.main()

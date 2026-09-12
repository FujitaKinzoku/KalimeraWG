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


AWG31_FIELDS = (
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
    "I1",
    "I2",
    "I3",
    "I4",
    "I5",
    "HeaderProtectionKey",
    "ContentPaddingAddition",
    "RekeyAfterTime",
    "RekeyTimeout",
    "RejectAfterTime",
    "KeepaliveTimeout",
    "MaxHandshakeAttempts",
    "RandomTrailers",
    "DisableCookies",
)


class KernelTransitProfileTests(unittest.TestCase):
    """Kernel-путь транзита должен нести тот же профиль AWG 3.1, что и userspace.

    Модуль amneziawg v3.1 принимает весь набор через netlink (проверено на
    реальном awg setconf/showconf), поэтому урезать kernel-профиль до I1 без
    HeaderProtectionKey/ContentPaddingAddition/RandomTrailers больше незачем.
    """

    REPO = Path(__file__).parents[1]
    ENTRY_TEMPLATE = REPO / "roles" / "entry" / "templates" / "awg1.conf.j2"
    EXIT_TEMPLATE = REPO / "roles" / "exit" / "templates" / "awg0.conf.j2"

    def test_both_kernel_templates_carry_full_awg31_field_set(self) -> None:
        for template in (self.ENTRY_TEMPLATE, self.EXIT_TEMPLATE):
            text = template.read_text(encoding="utf-8")
            for field in AWG31_FIELDS:
                with self.subTest(template=template.name, field=field):
                    self.assertRegex(text, rf"(?m)^{field} = ")

    def test_kernel_templates_take_i2_i5_from_the_shared_profile(self) -> None:
        entry = self.ENTRY_TEMPLATE.read_text(encoding="utf-8")
        exit_text = self.EXIT_TEMPLATE.read_text(encoding="utf-8")
        for index in range(1, 6):
            with self.subTest(index=index):
                self.assertIn(f"entry_awg1_obfuscation.i{index}", entry)
                self.assertIn(f"exit_awg_obfuscation.i{index}", exit_text)

    def test_entry_kernel_template_restores_the_peer_route(self) -> None:
        entry = self.ENTRY_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("Table = off", entry)
        self.assertIn("PostUp = ip -4 route replace", entry)
        self.assertIn("awg3_peer_tunnel_address", entry)

    def _render_entry(self, **overrides: object) -> str:
        import jinja2

        context: dict[str, object] = {
            "vault_awg_entry_exit_private_key": "PRIV",
            "entry_exit_tunnel_address": "10.77.0.2/32",
            "entry_awg1_mtu": 1420,
            "awg3_peer_tunnel_address": "10.77.0.1",
            "entry_awg1_obfuscation": {
                "jc": 12,
                "jmin": 64,
                "jmax": 512,
                "s1": 17,
                "s2": 23,
                "s3": 23,
                "s4": 29,
                "h1": "1-2",
                "h2": "3-4",
                "h3": "5-6",
                "h4": "7-8",
                "i1": "<b 0x01><r 10>",
                "i2": "<b 0x02><r 10>",
                "i3": "<b 0x03><r 10>",
                "i4": "<b 0x04><r 10>",
                "i5": "<b 0x05><r 10>",
            },
            "vault_awg3_header_protection_key": "HPK",
            "awg3_content_padding_addition": "8-32",
            "awg3_rekey_after_time": "120-180",
            "awg3_rekey_timeout": "5-8",
            "awg3_reject_after_time": "180-240",
            "awg3_keepalive_timeout": "10-15",
            "awg3_max_handshake_attempts": "18-24",
            "awg3_random_trailers": True,
            "awg3_disable_cookies": False,
            "vault_awg_entry_exit_peer_public_key": "PUB",
            "vault_awg_entry_exit_psk": "PSK",
            "entry_exit_allowed_ips": ["0.0.0.0/0"],
            "entry_exit_endpoint": "198.51.100.1:443",
            "entry_exit_persistent_keepalive": 25,
        }
        context.update(overrides)
        # trim_blocks=True повторяет окружение Ansible; фильтр bool -
        # ansible-специфичный, в ванильном Jinja2 его нет. Это структурная
        # проверка рендера, полная ansible-верность шаблонов проверяется
        # отдельно в CI (render-shell.yml и ansible syntax check).
        environment = jinja2.Environment(trim_blocks=True, autoescape=False)
        environment.filters["bool"] = lambda value: str(value).strip().lower() in {
            "true",
            "yes",
            "on",
            "1",
        }
        template = environment.from_string(
            self.ENTRY_TEMPLATE.read_text(encoding="utf-8")
        )
        return template.render(**context)

    def test_entry_template_renders_cleanly_with_ansible_trim_blocks(self) -> None:
        rendered = self._render_entry()
        self.assertIn("PostUp = ip -4 route replace 10.77.0.1/32 dev %i", rendered)
        self.assertIn("RandomTrailers = on", rendered)
        self.assertIn("DisableCookies = off", rendered)
        self.assertIn("I5 = <b 0x05><r 10>", rendered)
        # Ни одной пустой строки внутри [Interface] - иначе awg-quick
        # обрежет секцию на первой из них.
        interface_block = rendered.split("[Peer]")[0]
        self.assertNotIn("\n\n", interface_block.rstrip() + "\n")

    def test_entry_template_omits_peer_route_when_address_is_unset(self) -> None:
        rendered = self._render_entry(awg3_peer_tunnel_address="")
        self.assertNotIn("PostUp", rendered)
        self.assertNotIn("PostDown", rendered)
        self.assertIn("Table = off", rendered)


if __name__ == "__main__":
    unittest.main()

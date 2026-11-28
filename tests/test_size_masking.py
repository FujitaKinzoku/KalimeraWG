"""Маскировка размеров пакетов AmneziaWG 3.1 без потерь.

С RandomTrailers приёмник (модуль ядра и amneziawg-go) принимает за сообщение
рукопожатия любой пакет не короче ожидаемого и сверяет четыре байта с
диапазонами H1, H2, H3. При диапазонах шириной в десятки миллионов значений
около 3% пакетов данных отбрасывалось; измерено на amneziawg-go. Поэтому
профили с HeaderProtectionKey получают одиночные H1-H4, а поля включаются
отдельной командой, которая сначала заменяет диапазоны.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "scripts" / "lib" / "interactive_deploy.py"
SPEC = importlib.util.spec_from_file_location("interactive_deploy_size_masking", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

GATEWAY = ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
MOBILE_DEFAULTS = ROOT / "roles" / "awg3_mobile" / "defaults" / "main.yml"
TRANSIT_DEFAULTS = ROOT / "roles" / "awg3_transit" / "defaults" / "main.yml"
HEADERS = ("h1", "h2", "h3", "h4")


def false_handshake_share(profile: dict) -> float:
    """Доля пакетов данных, которые приёмник с RandomTrailers примет за рукопожатие.

    Так считают обе реализации: значение по смещению S1, S2, S3 сравнивается с
    диапазонами H1, H2, H3, а у пакета данных оно равномерно случайно.
    """
    total = 0
    for name in ("h1", "h2", "h3"):
        low, _, high = str(profile[name]).partition("-")
        total += int(high or low) - int(low) + 1
    return total / 2 ** 32


def wide_profile() -> dict:
    """Профиль прежнего вида: H1-H4 диапазонами, как у установленных каскадов."""
    profile = MODULE.awg3_transit_obfuscation()
    profile.update(zip(HEADERS, MODULE.awg_random_header_ranges()))
    MODULE.validate_awg_obfuscation(profile)
    return profile


class GeneratorTests(unittest.TestCase):
    def test_profiles_with_header_protection_get_single_headers(self) -> None:
        for build in (MODULE.awg_mobile_awg3_obfuscation, MODULE.awg3_transit_obfuscation):
            for _ in range(50):
                profile = build()
                self.assertTrue(MODULE.awg_headers_are_single(profile), build.__name__)
                values = [int(profile[name]) for name in HEADERS]
                self.assertEqual(len(set(values)), 4)
                # 1-4 - номера сообщений обычного WireGuard.
                self.assertTrue(all(5 <= value <= 2_147_483_647 for value in values))
                self.assertLess(false_handshake_share(profile), 1e-9)

    def test_standby_profile_also_gets_single_headers(self) -> None:
        primary = MODULE.awg3_transit_obfuscation()
        standby = MODULE.standby_transit_profile(primary)
        self.assertTrue(MODULE.awg_headers_are_single(standby))
        self.assertEqual(standby["s4"], primary["s4"])

    def test_profile_without_header_protection_keeps_ranges(self) -> None:
        # У клиентов KeeneticOS ключа защиты заголовка нет: поле типа видно на
        # проводе, и диапазон там работает. Хвостов эти профили не используют.
        profile = MODULE.awg_server_obfuscation()
        self.assertFalse(MODULE.awg_headers_are_single(profile))
        self.assertTrue(all("-" in str(profile[name]) for name in HEADERS))

    def test_ranges_of_the_old_generator_cost_percents_of_packets(self) -> None:
        # Это и есть причина прежних потерь: с хвостами такие диапазоны дают
        # проценты ложных срабатываний, одиночные значения - ничего.
        shares = [false_handshake_share(wide_profile()) for _ in range(200)]
        self.assertGreater(sum(shares) / len(shares), 0.01)
        self.assertGreater(max(shares), 0.03)
        # Ширины из клиентского конфига, на котором потери измерены: 3,19%.
        measured = {"h1": "400000000-455090170", "h2": "100000000-165318578", "h3": "900000000-916414057"}
        self.assertAlmostEqual(false_handshake_share(measured) * 100, 3.19, places=2)

    def test_replacing_headers_keeps_the_rest_of_the_profile(self) -> None:
        before = wide_profile()
        headers = MODULE.awg_single_headers()
        after = MODULE.awg_profile_with_single_headers(before, headers)
        self.assertEqual({key: after[key] for key in HEADERS}, headers)
        self.assertEqual(
            {key: value for key, value in after.items() if key not in HEADERS},
            {key: value for key, value in before.items() if key not in HEADERS},
        )
        self.assertFalse(MODULE.awg_headers_are_single(before))

    def test_values_follow_the_official_client(self) -> None:
        self.assertEqual(MODULE.SIZE_MASKING_PADDING, "10-100")
        self.assertEqual(MODULE.SIZE_MASKING_TRANSIT_VALUES, {
            "awg3_content_padding_addition": "10-100",
            "awg3_random_trailers": True,
            "awg3_disable_cookies": True,
        })
        self.assertEqual(MODULE.SIZE_MASKING_MOBILE_VALUES, {
            "awg3_mobile_content_padding_addition": "10-100",
            "awg3_mobile_random_trailers": True,
            "awg3_mobile_disable_cookies": True,
        })


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.production = Path(self.directory.name)
        (self.production / "group_vars" / "all").mkdir(parents=True)
        self.transit = wide_profile()
        self.standby = wide_profile()
        self.mobile = MODULE.awg_mobile_awg3_obfuscation()
        self.mobile.update(zip(HEADERS, MODULE.awg_random_header_ranges()))
        self.keenetic = MODULE.awg_server_obfuscation()

    def write(self, standby: bool = True, mobile: bool = True) -> None:
        entry = {
            "entry_awg0_obfuscation": self.keenetic,
            "entry_awg1_obfuscation": dict(self.transit),
            "awg3_transit_obfuscation": dict(self.transit),
            "entry_mobile_client_enabled": mobile,
        }
        if mobile:
            entry["entry_mobile_awg_obfuscation"] = dict(self.mobile)
        hosts = {"all": {"children": {"exit": {"hosts": {"exit-managed": {"ansible_host": "192.0.2.20"}}}}}}
        if standby:
            entry["entry_standby_exit_obfuscation"] = dict(self.standby)
            hosts["all"]["children"]["exit"]["hosts"][MODULE.STANDBY_EXIT_HOST] = {
                "ansible_host": "198.51.100.7",
                "exit_awg_obfuscation": dict(self.standby),
                "awg3_transit_obfuscation": dict(self.standby),
            }
        documents = {
            "hosts.yml": hosts,
            "group_vars/all/main.yml": {"awg_package_version_mode": "stable"},
            "group_vars/entry.yml": entry,
            "group_vars/exit.yml": {
                "exit_awg_obfuscation": dict(self.transit),
                "awg3_transit_obfuscation": dict(self.transit),
            },
        }
        for name, document in documents.items():
            (self.production / name).write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    def read(self, name: str) -> dict:
        return yaml.safe_load((self.production / name).read_text(encoding="utf-8"))

    def run_command(self, enabled: bool, answer: str = "y") -> bool:
        with mock.patch("builtins.input", return_value=answer), mock.patch("builtins.print"):
            return MODULE.set_size_masking(self.production, enabled)

    def test_enable_replaces_ranges_on_both_ends_of_every_link(self) -> None:
        self.write()
        self.assertTrue(self.run_command(True))
        entry, exit_vars = self.read("group_vars/entry.yml"), self.read("group_vars/exit.yml")
        all_vars, hosts = self.read("group_vars/all/main.yml"), self.read("hosts.yml")
        standby_host = hosts["all"]["children"]["exit"]["hosts"][MODULE.STANDBY_EXIT_HOST]

        primary = entry["entry_awg1_obfuscation"]
        self.assertTrue(MODULE.awg_headers_are_single(primary))
        # Обе стороны основного канала получили один и тот же профиль.
        for copy in (entry["awg3_transit_obfuscation"], exit_vars["exit_awg_obfuscation"],
                     exit_vars["awg3_transit_obfuscation"]):
            self.assertEqual(copy, primary)
        standby = entry["entry_standby_exit_obfuscation"]
        self.assertTrue(MODULE.awg_headers_are_single(standby))
        self.assertEqual(standby_host["exit_awg_obfuscation"], standby)
        self.assertEqual(standby_host["awg3_transit_obfuscation"], standby)
        self.assertNotEqual([standby[key] for key in HEADERS], [primary[key] for key in HEADERS])
        mobile = entry["entry_mobile_awg_obfuscation"]
        self.assertTrue(MODULE.awg_headers_are_single(mobile))

        # Меняются только H1-H4: остальные поля профилей прежние.
        for after, before in ((primary, self.transit), (standby, self.standby), (mobile, self.mobile)):
            self.assertEqual(
                {key: value for key, value in after.items() if key not in HEADERS},
                {key: value for key, value in before.items() if key not in HEADERS},
            )
            self.assertLess(false_handshake_share(after), 1e-9)
        # Профиль клиентов KeeneticOS не тронут.
        self.assertEqual(entry["entry_awg0_obfuscation"], self.keenetic)

        for key, value in MODULE.SIZE_MASKING_TRANSIT_VALUES.items():
            self.assertEqual(all_vars[key], value)
        for key, value in MODULE.SIZE_MASKING_MOBILE_VALUES.items():
            self.assertEqual(entry[key], value)
        self.assertEqual(all_vars["awg_package_version_mode"], "stable")
        self.assertEqual(MODULE.size_masking_state(self.production), {"transit": True, "mobile": True})

    def test_repeat_and_disable(self) -> None:
        self.write()
        self.run_command(True)
        enabled = {name: self.read(name) for name in ("group_vars/entry.yml", "group_vars/exit.yml", "hosts.yml")}
        self.assertFalse(self.run_command(True))
        self.assertEqual(self.read("group_vars/entry.yml"), enabled["group_vars/entry.yml"])

        self.assertTrue(self.run_command(False))
        entry, all_vars = self.read("group_vars/entry.yml"), self.read("group_vars/all/main.yml")
        self.assertEqual(all_vars["awg3_content_padding_addition"], "0")
        self.assertIs(all_vars["awg3_random_trailers"], False)
        self.assertIs(all_vars["awg3_disable_cookies"], False)
        self.assertEqual(entry["awg3_mobile_content_padding_addition"], "0")
        self.assertIs(entry["awg3_mobile_random_trailers"], False)
        # Одиночные H остаются: они безвредны и не требуют ещё одной смены профиля.
        self.assertEqual(entry["entry_awg1_obfuscation"], enabled["group_vars/entry.yml"]["entry_awg1_obfuscation"])
        self.assertEqual(self.read("group_vars/exit.yml"), enabled["group_vars/exit.yml"])
        self.assertFalse(self.run_command(False))

    def test_cascade_without_standby_and_mobile(self) -> None:
        self.write(standby=False, mobile=False)
        self.assertTrue(self.run_command(True))
        entry = self.read("group_vars/entry.yml")
        self.assertTrue(MODULE.awg_headers_are_single(entry["entry_awg1_obfuscation"]))
        self.assertNotIn("entry_mobile_awg_obfuscation", entry)
        self.assertNotIn("awg3_mobile_random_trailers", entry)
        self.assertNotIn("entry_standby_exit_obfuscation", entry)
        self.assertFalse(self.run_command(True))

    def test_nothing_changes_without_confirmation(self) -> None:
        self.write()
        before = {name: (self.production / name).read_bytes() for name in
                  ("hosts.yml", "group_vars/all/main.yml", "group_vars/entry.yml", "group_vars/exit.yml")}
        with self.assertRaises(SystemExit):
            self.run_command(True, answer="")
        for name, content in before.items():
            self.assertEqual((self.production / name).read_bytes(), content, name)

    def test_incomplete_standby_stops_before_any_write(self) -> None:
        self.write()
        entry = self.read("group_vars/entry.yml")
        del entry["entry_standby_exit_obfuscation"]
        (self.production / "group_vars" / "entry.yml").write_text(yaml.safe_dump(entry), encoding="utf-8")
        before = (self.production / "group_vars" / "exit.yml").read_bytes()
        with self.assertRaises(SystemExit):
            self.run_command(True)
        self.assertEqual((self.production / "group_vars" / "exit.yml").read_bytes(), before)
        self.assertNotIn("awg3_random_trailers", self.read("group_vars/all/main.yml"))

    def test_warning_names_mobile_clients_only_when_mobile_is_used(self) -> None:
        for mobile, expected in ((True, True), (False, False)):
            self.write(mobile=mobile)
            with mock.patch("builtins.input", return_value="y"), mock.patch("builtins.print") as printed:
                MODULE.set_size_masking(self.production, True)
            text = "\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
            self.assertEqual("Клиентов mobile/AWG3+ после обновления" in text, expected)
            self.assertIn("несколько минут", text)


class WiringTests(unittest.TestCase):
    def test_role_defaults_stay_off(self) -> None:
        # Каскады, установленные раньше, имеют диапазоны H: включение полей по
        # умолчанию в роли вернуло бы им потери и сломало бы mobile-клиентов.
        mobile = yaml.safe_load(MOBILE_DEFAULTS.read_text(encoding="utf-8"))
        transit = yaml.safe_load(TRANSIT_DEFAULTS.read_text(encoding="utf-8"))
        self.assertEqual(mobile["awg3_mobile_content_padding_addition"], "0")
        self.assertIs(mobile["awg3_mobile_random_trailers"], False)
        self.assertIs(mobile["awg3_mobile_disable_cookies"], False)
        self.assertEqual(transit["awg3_content_padding_addition"], "0")
        self.assertIs(transit["awg3_random_trailers"], False)
        self.assertIs(transit["awg3_disable_cookies"], False)
        for path in (MOBILE_DEFAULTS, TRANSIT_DEFAULTS):
            text = path.read_text(encoding="utf-8")
            self.assertIn("--enable-size-masking", text)
            self.assertNotIn('"8-32" и true', text)

    def test_flags_are_wired(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        gateway = GATEWAY.read_text(encoding="utf-8")
        for flag in ("--enable-size-masking", "--disable-size-masking"):
            self.assertIn(f'("{flag}", args.{flag[2:].replace("-", "_")}),', source)
            self.assertIn(f"'--resume {flag}'|", gateway)
            self.assertIn(f"{flag},", gateway)
        self.assertIn("set_size_masking(production, True)", source)
        self.assertIn("set_size_masking(production, False)", source)

    def test_templates_print_single_headers_as_they_are(self) -> None:
        # Шаблоны подставляют значение H как есть: одиночное число - допустимая
        # запись и для awg-tools, и для UAPI.
        for path in (
            ROOT / "roles" / "entry" / "templates" / "awg1.conf.j2",
            ROOT / "roles" / "entry" / "templates" / "awg-standby.conf.j2",
            ROOT / "roles" / "exit" / "templates" / "awg0.conf.j2",
            ROOT / "roles" / "awg3_mobile" / "templates" / "mobile.conf.j2",
        ):
            text = path.read_text(encoding="utf-8")
            self.assertTrue(re.search(r"^H1 = \{\{ [a-z0-9_]+\.h1 \}\}$", text, re.MULTILINE), path.name)
            self.assertIn("RandomTrailers = {{ 'on' if ", text)


if __name__ == "__main__":
    unittest.main()

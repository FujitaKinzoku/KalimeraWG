"""Собственные имена маскировки XHTTP для каждой установки FRONT.

Общие имена (прежние PHPESSID/mc_token/X-Client-State) используют и другие
сервисы, поэтому они становятся приметой. Новая установка получает набор из
правдоподобных легенд, существующий FRONT меняет его только по явной команде
--rotate-front-disguise, иначе выданные профили перестали бы работать.
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
SPEC = importlib.util.spec_from_file_location("interactive_deploy_disguise", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

FRONT_TASKS = ROOT / "roles" / "front" / "tasks" / "main.yml"
FRONT_DEFAULTS = ROOT / "roles" / "front" / "defaults" / "main.yml"
# Предопределённые таблицы Xray-core (transport/internet/splithttp/config.go).
XRAY_TABLES = {
    "hex": "0123456789abcdef",
    "HEX": "0123456789ABCDEF",
    "base36": "0123456789abcdefghijklmnopqrstuvwxyz",
    "BASE36": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "Base62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
}


def role_patterns() -> dict[str, str]:
    """Регулярные выражения проверок роли front для имён маскировки."""
    text = FRONT_TASKS.read_text(encoding="utf-8")
    patterns = {}
    for key in (
        "front_xhttp_disguise_session_cookie",
        "front_xhttp_disguise_padding_key",
        "front_xhttp_uplink_data_key",
    ):
        match = re.search(rf"- {key} is match\('([^']+)'\)", text)
        assert match, key
        patterns[key] = match.group(1)
    return patterns


class NewDisguiseTests(unittest.TestCase):
    def test_every_generated_set_passes_role_validation(self) -> None:
        patterns = role_patterns()
        for _ in range(200):
            disguise = MODULE.new_front_disguise()
            self.assertEqual(set(disguise), set(MODULE.FRONT_DISGUISE_KEYS))
            for key, pattern in patterns.items():
                self.assertRegex(str(disguise[key]), pattern)
            self.assertIn(disguise["front_xhttp_disguise_session_table"], XRAY_TABLES)
            self.assertTrue(16 <= int(disguise["front_xhttp_disguise_session_length"]) <= 64)
            # nginx молча выбрасывает заголовки с подчёркиванием.
            self.assertNotIn("_", disguise["front_xhttp_uplink_data_key"])

    def test_legends_match_framework_defaults(self) -> None:
        legends = {legend["cookie"]: legend for legend in MODULE.FRONT_DISGUISE_LEGENDS}
        self.assertEqual((legends["PHPSESSID"]["table"], legends["PHPSESSID"]["length"]), ("hex", 32))
        self.assertEqual((legends["JSESSIONID"]["table"], legends["JSESSIONID"]["length"]), ("HEX", 32))
        self.assertEqual((legends["sessionid"]["table"], legends["sessionid"]["length"]), ("base36", 32))
        # Прежняя общая легенда и её опечатка больше не выдаются.
        self.assertNotIn("PHPESSID", legends)
        for legend in MODULE.FRONT_DISGUISE_LEGENDS:
            self.assertNotIn("mc_token", legend["padding"])

    def test_header_names_keep_checked_cdn_budget(self) -> None:
        for name in MODULE.FRONT_UPLINK_HEADER_NAMES:
            self.assertLessEqual(len(name), len("X-Request-Context"))
            self.assertTrue(name.startswith("X-"))

    def test_rotation_always_changes_visible_names(self) -> None:
        current = {
            "front_xhttp_disguise_session_cookie": "PHPSESSID",
            "front_xhttp_uplink_data_key": "X-Client-State",
        }
        for _ in range(200):
            rotated = MODULE.new_front_disguise(current)
            self.assertTrue(
                rotated["front_xhttp_disguise_session_cookie"] != "PHPSESSID"
                or rotated["front_xhttp_uplink_data_key"] != "X-Client-State"
            )


class RotationInventoryTests(unittest.TestCase):
    def test_existing_front_without_names_gets_new_set_and_previous_is_role_default(self) -> None:
        defaults = yaml.safe_load(FRONT_DEFAULTS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary)
            front = production / "group_vars" / "front.yml"
            front.parent.mkdir(parents=True)
            front.write_text(
                yaml.safe_dump({"front_xhttp_path": "/kept", "front_xhttp_disguise_enabled": True}),
                encoding="utf-8",
            )
            previous = MODULE.prepare_front_disguise_rotation(ROOT, production)
            after = yaml.safe_load(front.read_text(encoding="utf-8"))
        self.assertEqual(previous["front_xhttp_disguise_session_cookie"], defaults["front_xhttp_disguise_session_cookie"])
        self.assertEqual(previous["front_xhttp_uplink_data_key"], defaults["front_xhttp_uplink_data_key"])
        for key in MODULE.FRONT_DISGUISE_KEYS:
            self.assertIn(key, after)
        # Путь XHTTP не меняется: на него могут ссылаться правила кэширования CDN.
        self.assertEqual(after["front_xhttp_path"], "/kept")

    def test_rotation_without_front_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(SystemExit):
                MODULE.prepare_front_disguise_rotation(ROOT, Path(temporary))

    def test_role_defaults_keep_existing_fronts_working(self) -> None:
        # FRONT, установленный до v3.1.0, не хранит имён в inventory: значения
        # роли по умолчанию обязаны остаться прежними, иначе обычный
        # --resume молча сломал бы все его клиентские профили.
        defaults = yaml.safe_load(FRONT_DEFAULTS.read_text(encoding="utf-8"))
        self.assertEqual(defaults["front_xhttp_disguise_session_cookie"], "PHPESSID")
        self.assertEqual(defaults["front_xhttp_disguise_padding_key"], "mc_token")
        self.assertEqual(defaults["front_xhttp_uplink_data_key"], "X-Client-State")
        self.assertEqual(defaults["front_xhttp_disguise_session_table"], "hex")
        self.assertEqual(defaults["front_xhttp_disguise_session_length"], 32)

    def test_new_installations_write_own_names(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertEqual(source.count("**new_front_disguise(),"), 2)
        enable = source[source.index("def enable_front_profile") :]
        self.assertIn("**new_front_disguise(),", enable[: enable.index("\ndef ")])


class RotationArgumentTests(unittest.TestCase):
    def run_main(self, *arguments: str) -> int:
        argv = ["deploy", "--repo-root", str(ROOT), *arguments]
        with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit) as raised:
            MODULE.main()
        return raised.exception.code

    def test_requires_resume_and_is_exclusive(self) -> None:
        self.assertEqual(self.run_main("--rotate-front-disguise"), 2)
        self.assertEqual(self.run_main("--resume", "--rotate-front-disguise", "--update-xray"), 2)
        self.assertEqual(self.run_main("--resume", "--rotate-front-disguise", "--replace-front"), 2)

    def test_admin_wrapper_allows_rotation(self) -> None:
        wrapper = (ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("'--resume --rotate-front-disguise'", wrapper)


if __name__ == "__main__":
    unittest.main()

"""Оформление отчётов awg-health, server-audit и kalimera-updates.

В терминале строки OK зелёные, FAIL и WARN жёлтые, а в конце печатается
рамка: зелёная OK, жёлтая WARN (каскад работает) или красная FAIL (работа
каскада нарушена) с рекомендациями. Без терминала вывод прежний: его
разбирают Telegram-монитор, Ansible и обслуживание. Скрипты запускаются в
bash с KALIMERA_REPORT_STYLE=fancy|plain вместо настоящего терминала.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import jinja2

ROOT = Path(__file__).parents[1]
TEMPLATES = {
    "awg-health": ROOT / "roles" / "health" / "templates" / "awg-health.sh.j2",
    "server-audit": ROOT / "roles" / "operations" / "templates" / "server-audit.sh.j2",
    "kalimera-updates": ROOT / "roles" / "operations" / "templates" / "kalimera-updates.sh.j2",
}
BLOCK = re.compile(r"\{% raw %\}\n# >>> kalimera-report.*?# <<< kalimera-report\n\{% endraw %\}\n", re.S)
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def environment() -> jinja2.Environment:
    env = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    return env


def block_text() -> str:
    match = BLOCK.search(TEMPLATES["awg-health"].read_text(encoding="utf-8"))
    assert match, "общий блок не найден"
    return environment().from_string(match.group(0)).render()


def health_prologue(role: str = "entry") -> str:
    source = TEMPLATES["awg-health"].read_text(encoding="utf-8")
    end = source.index("has_rule() {")
    return environment().from_string(source[:end]).render(awg_node_role=role)


def bash(script: str, *args: str, style: str = "fancy", columns: str = "80") -> subprocess.CompletedProcess:
    executable = shutil.which("bash")
    if executable is None or os.name == "nt":
        raise unittest.SkipTest("нужен bash на Linux")
    with tempfile.TemporaryDirectory() as temporary:
        bin_dir = Path(temporary) / "bin"
        bin_dir.mkdir()
        # Ширина терминала задаётся подставным tput: настоящего терминала нет.
        tput = bin_dir / "tput"
        tput.write_text(f"#!/bin/sh\necho {columns}\n", encoding="utf-8")
        tput.chmod(0o755)
        path = Path(temporary) / "script.sh"
        path.write_text(script, encoding="utf-8")
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "KALIMERA_REPORT_STYLE": style,
        }
        return subprocess.run(
            [executable, str(path), *args], capture_output=True, text=True, env=env
        )


def box_lines(output: str) -> list[str]:
    plain = ANSI.sub("", output)
    return [line for line in plain.splitlines() if line and line[0] in "┌│├└"]


class SharedBlockTests(unittest.TestCase):
    def test_block_is_identical_in_all_three_commands(self) -> None:
        blocks = {}
        for name, path in TEMPLATES.items():
            found = BLOCK.findall(path.read_text(encoding="utf-8"))
            self.assertEqual(len(found), 1, name)
            blocks[name] = found[0]
        self.assertEqual(len(set(blocks.values())), 1, "блок оформления различается")

    def test_box_is_aligned_with_cyrillic_and_wrapping(self) -> None:
        script = "set -Eeuo pipefail\n" + block_text() + (
            "report_note FAIL 'свежий handshake ENTRY–EXIT' "
            "'проверьте, что второй сервер каскада включён и хостинг не блокирует его UDP-порт'\n"
            "report_note WARN 'журналирование UFW отключено' 'на ENTRY: kalimera-deploy --resume'\n"
            "report_note WARN 'coredump не сохраняются' 'на ENTRY: kalimera-deploy --resume'\n"
            "report_note_lines\n"
            "report_box FAIL 'awg-health entry: работа каскада нарушена' \"${report_box_lines[@]}\"\n"
        )
        if shutil.which("bash") is None or os.name == "nt":
            self.skipTest("нужен bash на Linux")
        for columns in ("80", "50", "200"):
            with self.subTest(columns=columns):
                result = bash(script, columns=columns)
                self.assertEqual(result.returncode, 0, result.stderr)
                lines = box_lines(result.stdout)
                expected = min(max(int(columns), 40), 100)
                self.assertTrue(lines)
                self.assertEqual({len(line) for line in lines}, {expected}, lines)
        plain = ANSI.sub("", result.stdout)
        # Критичное - первым, одинаковая рекомендация - один раз.
        self.assertLess(plain.index("✗ свежий handshake"), plain.index("! журналирование UFW"))
        self.assertEqual(plain.count("kalimera-deploy --resume"), 1)
        self.assertIn("\x1b[1;31m┌", result.stdout)

    def test_long_list_is_cut(self) -> None:
        notes = "".join(f"report_note WARN 'замечание {i}' 'одно и то же'\n" for i in range(15))
        script = "set -Eeuo pipefail\n" + block_text() + notes + (
            "report_note_lines\nprintf '%s\\n' \"${report_box_lines[@]}\"\n"
        )
        result = bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("! замечание 11", result.stdout)
        self.assertNotIn("! замечание 12", result.stdout)
        self.assertIn("и ещё замечаний: 3", result.stdout)

    def test_plain_mode_has_no_escape_codes_and_no_box(self) -> None:
        script = "set -Eeuo pipefail\n" + block_text() + (
            "report_line OK 'проверка'\nreport_line FAIL 'ошибка'\n"
            "report_box OK 'заголовок' 'строка'\n"
        )
        result = bash(script, style="plain")
        self.assertEqual(result.stdout, "OK   проверка\nFAIL ошибка\n")


class HealthTests(unittest.TestCase):
    def run_health(self, body: str, *args: str, style: str = "fancy") -> subprocess.CompletedProcess:
        return bash(health_prologue() + body + "health_finish\n", *args, style=style)

    def test_all_passed_is_green_box(self) -> None:
        result = self.run_health("check 'служба' true\n", "--strict")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("\x1b[32mOK   служба", result.stdout)
        self.assertIn("\x1b[1;32m┌", result.stdout)
        self.assertIn("OK awg-health entry: все проверки пройдены (1)", ANSI.sub("", result.stdout))

    def test_only_minor_failures_are_yellow_and_exit_3(self) -> None:
        result = self.run_health(
            "check 'служба' true\ncheck_minor 'журналирование UFW отключено' false\n", "--strict"
        )
        self.assertEqual(result.returncode, 3, result.stderr)
        plain = ANSI.sub("", result.stdout)
        self.assertIn("\x1b[33mFAIL журналирование UFW отключено", result.stdout)
        self.assertIn("WARN awg-health entry: каскад работает, замечаний: 1", plain)
        self.assertIn("→ на ENTRY: kalimera-deploy --resume восстановит политику без журналов", plain)

    def test_critical_failure_is_red_and_exit_1(self) -> None:
        result = self.run_health(
            "check 'правило policy routing для mark 0x1' false\n"
            "check 'служба dnsmasq' systemctl is-active --quiet kalimera-test-absent.service\n"
            "check_minor 'Fail2Ban активен' false\n",
            "--strict",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        plain = ANSI.sub("", result.stdout)
        self.assertIn("\x1b[1;31m┌", result.stdout)
        self.assertIn("критичных ошибок: 2 из 3", plain)
        self.assertIn("sudo systemctl reload awg-entry-routing.service", plain)
        self.assertIn("restart unbound.service dnsmasq.service", plain)

    def test_service_hint_names_the_unit(self) -> None:
        result = self.run_health(
            "check 'служба клиентского AWG' systemctl is-active --quiet awg-quick@awg0.service\n"
            "check 'таймер чего-то' systemctl is-active --quiet kalimera-test.timer\n"
        )
        plain = ANSI.sub("", result.stdout)
        self.assertIn("sudo systemctl status awg-quick@awg0.service", plain)
        self.assertIn("sudo systemctl enable --now kalimera-test.timer", plain)

    def test_without_strict_exit_is_zero(self) -> None:
        result = self.run_health("check 'служба' false\n")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_plain_output_keeps_old_format(self) -> None:
        result = self.run_health(
            "check 'служба' true\ncheck_minor 'coredump не сохраняются' false\n"
            "check_value 'пересылка IPv4' 0 1\n",
            "--strict",
            style="plain",
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stdout,
            "OK   служба\nFAIL coredump не сохраняются\n"
            "FAIL пересылка IPv4 (ожидалось 1, получено 0)\nBAD: ошибок проверки: 2\n",
        )


if __name__ == "__main__":
    unittest.main()

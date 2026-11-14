"""cascade-check и kalimera-report: разбор строк, сводка, ключ и проводка ролей.

Шаблоны рендерятся Jinja2 с подставными значениями, функции запускаются в bash
через source: основной вызов main() при подключении не выполняется. Ключ и
сеть не нужны: ssh подменяется скриптом в PATH.
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
REPORT = ROOT / "roles" / "cascade_check" / "templates" / "kalimera-report.sh.j2"
CASCADE = ROOT / "roles" / "cascade_check" / "templates" / "cascade-check.sh.j2"
AWG_HEALTH = ROOT / "roles" / "health" / "templates" / "awg-health.sh.j2"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def render(template: Path, **variables) -> str:
    environment = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    return environment.from_string(template.read_text(encoding="utf-8")).render(**variables)


def shared_block(text: str) -> str:
    start = text.index("# >>> kalimera-report")
    end = text.index("\n", text.index("# <<< kalimera-report")) + 1
    return text[start:end]


def bash_path() -> str:
    executable = shutil.which("bash")
    if executable is None or os.name == "nt":
        raise unittest.SkipTest("нужен bash на Linux")
    return executable


def cascade_values(directory: Path, key: Path | None = None) -> dict:
    return {
        "cascade_check_report_path": str(directory / "missing-report"),
        "cascade_check_key_path": str(key or directory / "id_ed25519"),
        "cascade_check_known_hosts_path": str(directory / "known_hosts"),
        "cascade_check_user": "kalimera-report",
        "cascade_check_exit_host": "192.0.2.20",
        "cascade_check_exit_port": 56777,
        "cascade_check_front_present": True,
        "cascade_check_front_host": "192.0.2.30",
        "cascade_check_front_port": 56777,
        "cascade_check_cdn_enabled": True,
        "cascade_check_cdn_domain": "cdn.example.invalid",
    }


def row(segment: str, status: str, label: str, value: str = "", hint: str = "", ms: str = "") -> str:
    """Строка отчёта: СЕГМЕНТ, СТАТУС, ПРОВЕРКА, ЗНАЧЕНИЕ, РЕКОМЕНДАЦИЯ, МИЛЛИСЕКУНДЫ."""
    return "\t".join((segment, status, label, value, hint, ms)) + "\n"


class ShellcheckTests(unittest.TestCase):
    def test_rendered_scripts_pass_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None or os.name == "nt":
            self.skipTest("нужен shellcheck")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            report = directory / "kalimera-report"
            report.write_text(render(REPORT, awg_node_role="entry"), encoding="utf-8")
            cascade = directory / "cascade-check"
            cascade.write_text(render(CASCADE, **cascade_values(directory)), encoding="utf-8")
            result = subprocess.run(
                [shellcheck, "--exclude=SC2317", str(report), str(cascade)],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class CascadeCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.fakebin = self.dir / "bin"
        self.fakebin.mkdir()
        self.key = self.dir / "id_ed25519"
        self.key.write_text("not-a-real-key\n", encoding="utf-8")
        self.known_hosts = self.dir / "known_hosts"
        self.known_hosts.write_text("", encoding="utf-8")
        self.rows = self.dir / "rows.tsv"
        self.rows.write_text("", encoding="utf-8")
        self.script = self.dir / "cascade-check"
        self.script.write_text(render(CASCADE, **cascade_values(self.dir, self.key)), encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_body(self, body: str, *, style: str = "plain", fake_ssh: str | None = None):
        if fake_ssh is not None:
            ssh = self.fakebin / "ssh"
            ssh.write_text("#!/bin/sh\n" + fake_ssh, encoding="utf-8")
            ssh.chmod(0o755)
        env = {
            **os.environ,
            "KALIMERA_REPORT_STYLE": style,
            "PATH": f"{self.fakebin}{os.pathsep}{os.environ['PATH']}",
        }
        preamble = (
            f"source {shlex.quote(str(self.script))}\n"
            f"work={shlex.quote(str(self.dir))}\n"
            f"rows_file={shlex.quote(str(self.rows))}\n"
        )
        return subprocess.run(
            [bash_path(), "-c", preamble + body],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    def test_empty_middle_fields_are_kept(self) -> None:
        raw = self.dir / "raw.tsv"
        raw.write_text(row("ENTRY", "FAIL", "проверка", "", "рекомендация"), encoding="utf-8")
        result = self.run_body(f"import_rows local {shlex.quote(str(raw))}\ncat \"$rows_file\"\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        # read с табуляцией сдвинул бы рекомендацию в поле значения.
        self.assertEqual(result.stdout, row("ENTRY", "FAIL", "проверка", "", "рекомендация"))

    def test_milliseconds_field_is_kept(self) -> None:
        raw = self.dir / "raw.tsv"
        raw.write_text(row("LINK", "OK", "ENTRY → EXIT: SSH", "TCP 58 мс", "", "58"), encoding="utf-8")
        result = self.run_body(f"import_rows local {shlex.quote(str(raw))}\ncat \"$rows_file\"\n")
        self.assertEqual(result.stdout, row("LINK", "OK", "ENTRY → EXIT: SSH", "TCP 58 мс", "", "58"))

    def test_remote_rows_take_the_expected_segment(self) -> None:
        raw = self.dir / "raw.tsv"
        raw.write_text(
            row("ENTRY", "OK", "служба")
            + row("EXIT", "OK", "автопроверка", "значение"),
            encoding="utf-8",
        )
        result = self.run_body(f"import_rows EXIT {shlex.quote(str(raw))}\ncat \"$rows_file\"\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            row("EXIT", "OK", "служба") + row("EXIT", "OK", "автопроверка", "значение"),
        )

    def test_remote_link_rows_keep_the_link_segment(self) -> None:
        raw = self.dir / "raw.tsv"
        raw.write_text(row("LINK", "OK", "выход в Интернет с EXIT", "HTTP 200", "", "54"), encoding="utf-8")
        result = self.run_body(f"import_rows EXIT {shlex.quote(str(raw))}\ncat \"$rows_file\"\n")
        self.assertEqual(result.stdout, row("LINK", "OK", "выход в Интернет с EXIT", "HTTP 200", "", "54"))

    def test_local_rows_cannot_claim_another_segment(self) -> None:
        raw = self.dir / "raw.tsv"
        raw.write_text(row("FRONT", "OK", "чужая строка"), encoding="utf-8")
        result = self.run_body(f"import_rows local {shlex.quote(str(raw))}\ncat \"$rows_file\"\n")
        self.assertEqual(result.stdout, row("ENTRY", "OK", "чужая строка"))

    def test_control_characters_are_removed(self) -> None:
        raw = self.dir / "raw.tsv"
        raw.write_bytes(row("EXIT", "OK", "\x1b[31mметка\x07").encode("utf-8"))
        result = self.run_body(f"import_rows EXIT {shlex.quote(str(raw))}\ncat \"$rows_file\"\n")
        self.assertEqual(result.stdout, row("EXIT", "OK", "[31mметка"))

    def test_lines_with_wrong_shape_are_dropped(self) -> None:
        raw = self.dir / "raw.tsv"
        raw.write_text(
            "без табуляций\n" + row("EXIT", "BAD", "статус") + "EXIT\tOK\t\t\t\t\n",
            encoding="utf-8",
        )
        result = self.run_body(f"import_rows EXIT {shlex.quote(str(raw))}\ncat \"$rows_file\"\n")
        self.assertEqual(result.stdout, "")

    def test_exit_codes_follow_the_worst_status(self) -> None:
        cases = (
            (row("ENTRY", "OK", "всё"), 0, "GOOD:"),
            (row("ENTRY", "WARN", "замечание", "", "сделать"), 3, "WARN:"),
            (row("ENTRY", "FAIL", "ошибка", "", "сделать"), 1, "BAD:"),
        )
        for text, code, word in cases:
            with self.subTest(word=word):
                self.rows.write_text(text, encoding="utf-8")
                result = self.run_body('render\nexit "$exit_code"\n')
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                self.assertIn(word, result.stdout)

    def test_fancy_box_lists_fail_first_with_its_recommendation(self) -> None:
        self.rows.write_text(
            row("ENTRY", "OK", "служба")
            + row("ENTRY", "FAIL", "свежий handshake", "нет", "перезапустите туннель"),
            encoding="utf-8",
        )
        result = self.run_body('render\nexit "$exit_code"\n', style="fancy")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        plain = ANSI.sub("", result.stdout)
        self.assertIn("\x1b[1;31m┌", result.stdout)
        self.assertIn("✗ свежий handshake: нет", plain)
        self.assertIn("→ перезапустите туннель", plain)
        self.assertIn("ИТОГ: OK 1 · WARN 0 · FAIL 1", plain)
        # Итоговая рамка - последняя: после неё ничего не печатается.
        self.assertTrue(plain.rstrip().endswith("┘"), plain[-300:])

    def test_summary_groups_appear_in_order(self) -> None:
        self.rows.write_text(
            row("ENTRY", "OK", "служба")
            + row("LINK", "OK", "ENTRY → EXIT: SSH", "TCP 58 мс", "", "58")
            + row("DNS", "OK", "DNS: yandex.ru (РФ)", "77.88.44.55 за 1 мс", "", "1")
            + row("EXIT", "OK", "служба EXIT"),
            encoding="utf-8",
        )
        result = self.run_body("render\n")
        plain = ANSI.sub("", result.stdout)
        # Заголовки разделов в деталях похожи на группы сводки ("DNS: ..."),
        # поэтому поиск идёт от начала сводки.
        start = plain.index("СЕРВЕРЫ")
        positions = [plain.index(title, start) for title in ("СЕРВЕРЫ", "СВЯЗИ И ЗАДЕРЖКИ", "DNS", "ИТОГ")]
        self.assertEqual(positions, sorted(positions), plain)

    def test_server_line_shows_response_time_from_the_ssh_link(self) -> None:
        self.rows.write_text(
            row("ENTRY", "OK", "служба")
            + row("LINK", "OK", "ENTRY → EXIT: SSH", "TCP 58 мс", "", "58")
            + row("EXIT", "OK", "служба EXIT"),
            encoding="utf-8",
        )
        result = self.run_body("render\n")
        self.assertIn("EXIT: OK 1 · WARN 0 · FAIL 0 · отклик 58 мс (SSH)", result.stdout)

    def test_dns_status_is_the_worst_check(self) -> None:
        self.rows.write_text(
            row("DNS", "OK", "DNS: example.com", "1.2.3.4 за 1 мс", "", "1")
            + row("DNS", "WARN", "DNS: yandex.ru", "медленно", "проверьте резолвер", "400"),
            encoding="utf-8",
        )
        result = self.run_body("render\n")
        self.assertIn("статус DNS: WARN (1 из 2)", result.stdout)

    def test_fancy_summary_colors_each_group(self) -> None:
        self.rows.write_text(
            row("ENTRY", "OK", "служба")
            + row("LINK", "OK", "туннель ENTRY–EXIT: TCP через туннель", "3 из 3, среднее 49 мс", "", "49")
            + row("DNS", "OK", "DNS: example.com", "1.2.3.4 за 1 мс", "", "1"),
            encoding="utf-8",
        )
        result = self.run_body("render\n", style="fancy")
        self.assertIn("\x1b[1;32m┌", result.stdout)  # рамка итога зелёная
        self.assertIn("\x1b[36m", result.stdout)  # связи и задержки голубые
        self.assertIn("\x1b[32m", result.stdout)  # серверы и DNS по статусу OK

    def test_same_recommendation_is_printed_once(self) -> None:
        self.rows.write_text(
            row("ENTRY", "WARN", "первое", "", "сделать одно")
            + row("ENTRY", "WARN", "второе", "", "сделать одно"),
            encoding="utf-8",
        )
        result = self.run_body("render\n")
        self.assertEqual(result.stdout.count("→ сделать одно"), 1, result.stdout)

    def test_failed_ssh_becomes_a_fail_row(self) -> None:
        result = self.run_body(
            'collect_remote EXIT 192.0.2.20 56777\ncat "$rows_file"\n',
            fake_ssh='echo "Permission denied (publickey)." >&2\nexit 255\n',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "EXIT\tFAIL\tудалённый отчёт по SSH\tPermission denied (publickey).\t",
            result.stdout,
        )

    def test_remote_report_rows_are_checked_and_relabelled(self) -> None:
        result = self.run_body(
            'collect_remote EXIT 192.0.2.20 56777\ncat "$rows_file"\n',
            fake_ssh=(
                "printf 'ENTRY\\tOK\\tслужба\\t\\t\\t\\n'\n"
                "printf 'EXIT\\tOK\\tавтопроверка EXIT\\tзначение\\t\\t\\n'\n"
                "printf 'мусор без табуляций\\n'\n"
                "printf 'EXIT\\tBAD\\tстатус\\t\\t\\t\\n'\n"
                "exit 0\n"
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            row("EXIT", "OK", "служба")
            + row("EXIT", "OK", "автопроверка EXIT", "значение"),
        )

    def test_ssh_is_restricted_to_the_report_user_and_known_host(self) -> None:
        args_file = self.dir / "ssh-args.txt"
        self.run_body(
            'collect_remote EXIT 192.0.2.20 56777\n',
            fake_ssh=f"printf '%s\\n' \"$@\" >{shlex.quote(str(args_file))}\nexit 0\n",
        )
        args = args_file.read_text(encoding="utf-8").split("\n")
        for expected in (
            "-F",
            "/dev/null",
            "-n",
            "BatchMode=yes",
            "IdentitiesOnly=yes",
            "StrictHostKeyChecking=yes",
            f"UserKnownHostsFile={self.known_hosts}",
            "-p",
            "56777",
            "kalimera-report@192.0.2.20",
        ):
            self.assertIn(expected, args)
        self.assertEqual(args[args.index("-i") + 1], str(self.key))

    def test_front_section_is_skipped_when_absent(self) -> None:
        text = self.script.read_text(encoding="utf-8")
        self.assertIn("readonly front_present=true", text)
        self.script.write_text(
            text.replace("readonly front_present=true", "readonly front_present=false"),
            encoding="utf-8",
        )
        result = self.run_body("render\n")
        self.assertIn("в каскаде не используется", result.stdout)
        self.assertNotIn("FRONT: OK", result.stdout)

    def test_cdn_group_combines_the_edge_probe_and_front_checks(self) -> None:
        self.rows.write_text(
            row("CDN", "OK", "CDN: TLS и HTTPS", "TLS за 35 мс, HTTP 404, всего 80 мс", "", "80")
            + row("FRONT", "OK", "TLS endpoint CDN доступен"),
            encoding="utf-8",
        )
        result = self.run_body("render\n")
        plain = ANSI.sub("", result.stdout)
        # Заголовок группы - отдельная строка сводки; заголовок раздела деталей
        # ("CDN: проверка с ENTRY") на отдельной строке не стоит.
        group = plain.index("\nCDN\n")
        self.assertIn("CDN: TLS и HTTPS", plain[group:])
        self.assertIn("TLS endpoint CDN доступен", plain[group:])
        self.assertLess(plain.index("\nСВЯЗИ И ЗАДЕРЖКИ\n"), group)
        self.assertLess(group, plain.index("\nDNS\n"))

    def test_cdn_group_says_when_cdn_is_not_used(self) -> None:
        text = self.script.read_text(encoding="utf-8")
        self.assertIn("readonly cdn_enabled=true", text)
        self.script.write_text(
            text.replace("readonly cdn_enabled=true", "readonly cdn_enabled=false"),
            encoding="utf-8",
        )
        result = self.run_body("render\n")
        self.assertIn("CDN не используется в каскаде", result.stdout)
        self.assertIn("в каскаде не используется", result.stdout)

    def test_block_is_identical_to_awg_health(self) -> None:
        self.assertEqual(
            shared_block(self.script.read_text(encoding="utf-8")),
            shared_block(AWG_HEALTH.read_text(encoding="utf-8")),
        )


class KalimeraReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.script = self.dir / "kalimera-report"
        self.script.write_text(
            render(
                REPORT,
                awg_node_role="entry",
                entry_client_listen_address="10.66.0.1",
                entry_dns_default_port=5353,
                entry_dns_ru_port=5354,
                entry_exit_interface="awg1",
                entry_ru_proxy_enabled=True,
                entry_ru_proxy_manual_disabled_flag=str(self.dir / "no-manual"),
                entry_ru_proxy_disabled_flag=str(self.dir / "no-failopen"),
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_body(self, body: str):
        return subprocess.run(
            [
                bash_path(),
                "-c",
                f"source {shlex.quote(str(self.script))}\n" + body,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_awg_health_export_becomes_entry_rows(self) -> None:
        export = self.dir / "health"
        export.write_text(
            "OK\tслужба\t\n"
            "FAIL\tправило mark 0x1\tsudo systemctl reload awg-entry-routing.service\n"
            "OK\tстрогая проверка роли сервера\t\n"
            "WARN\tcoredump не сохраняются\t\n",
            encoding="utf-8",
        )
        result = self.run_body(f"import_rows {shlex.quote(str(export))}\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            row("ENTRY", "OK", "служба")
            + row("ENTRY", "FAIL", "правило mark 0x1", "", "sudo systemctl reload awg-entry-routing.service")
            + row("ENTRY", "WARN", "coredump не сохраняются"),
        )

    def test_rendered_script_passes_bash_syntax_check(self) -> None:
        result = subprocess.run([bash_path(), "-n", str(self.script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_report_is_root_only_and_has_one_forced_entry_point(self) -> None:
        text = REPORT.read_text(encoding="utf-8")
        self.assertIn("kalimera-report запускается от root", text)
        self.assertIn("--tsv) [[ $# -eq 1 ]]", text)

    def test_dns_rows_belong_to_the_dns_segment(self) -> None:
        text = REPORT.read_text(encoding="utf-8")
        self.assertIn("emit DNS OK", text)
        self.assertIn("emit DNS FAIL", text)

    def test_link_rows_are_measured_in_milliseconds(self) -> None:
        text = REPORT.read_text(encoding="utf-8")
        # Задержки уходят в шестое поле: сводка берёт их оттуда.
        self.assertIn("'' \"$ms\"", text)
        self.assertIn("'' \"$avg\"", text)


class CascadeRolePolicyTests(unittest.TestCase):
    def test_report_key_is_limited_to_entry_address_and_one_command(self) -> None:
        tasks = (ROOT / "roles" / "cascade_check" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn('from="{{ security_cascade_report_source_ipv4 }}"', tasks)
        self.assertIn(
            'command="sudo -n {{ cascade_check_report_path }} --tsv"', tasks
        )
        for option in ("no-pty", "no-port-forwarding", "no-agent-forwarding", "no-X11-forwarding"):
            self.assertIn(option, tasks)
        self.assertIn(
            "{{ security_cascade_report_user }} ALL=(root) NOPASSWD: "
            "{{ cascade_check_report_path }} --tsv",
            tasks,
        )
        self.assertIn("exclusive: true", tasks)

    def test_report_user_is_a_system_account_without_password(self) -> None:
        tasks = (ROOT / "roles" / "cascade_check" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("system: true", tasks)
        self.assertNotIn("password:", tasks)

    def test_cascade_role_follows_health_on_every_host(self) -> None:
        # После health: к этому моменту роли уже задали переменные (адрес ENTRY
        # для FRONT из роли front), которые попадают в отчёт kalimera-report.
        expected = {"site.yml": 3, "entry.yml": 1, "exit.yml": 1, "front.yml": 1}
        pattern = re.compile(
            r"- role: health\n\s+when: awg_adoption_mode == 'apply'\n"
            r"(?:\s+#[^\n]*\n)*"
            r"\s+- role: cascade_check\n"
        )
        for name, count in expected.items():
            with self.subTest(playbook=name):
                text = (ROOT / "playbooks" / name).read_text(encoding="utf-8")
                self.assertEqual(len(pattern.findall(text)), count)

    def test_entry_playbooks_do_not_require_a_manual_source_address(self) -> None:
        # Адрес ENTRY сервер-получатель видит сам (SSH_CONNECTION), поэтому
        # плейбуки ENTRY ни требуют его задавать, ни сверяют ansible_host.
        for name in ("site.yml", "entry.yml"):
            with self.subTest(playbook=name):
                text = (ROOT / "playbooks" / name).read_text(encoding="utf-8")
                self.assertNotIn("cascade_check_entry_source_ipv4", text)
                self.assertNotIn("Проверка внешнего адреса ENTRY", text)

    def test_report_source_is_the_address_exit_and_front_see(self) -> None:
        source = (ROOT / "roles" / "cascade_check" / "tasks" / "report_source.yml").read_text(
            encoding="utf-8"
        )
        # Адрес берётся из SSH_CONNECTION сессии деплоя; без become sudo его бы сбросил.
        self.assertIn("$SSH_CONNECTION", source)
        self.assertIn("become: false", source)
        self.assertIn("security_cascade_report_source_ipv4", source)
        # Адрес выбирается в pre_tasks EXIT и FRONT, то есть до их ролей.
        plays = {
            "site.yml": ("Настройка EXIT сервера", "Настройка FRONT сервера"),
            "exit.yml": ("hosts: exit",),
            "front.yml": ("hosts: front",),
        }
        for name, markers in plays.items():
            text = (ROOT / "playbooks" / name).read_text(encoding="utf-8")
            for marker in markers:
                with self.subTest(playbook=name, play=marker):
                    start = text.index(marker)
                    include = text.index("tasks_from: report_source", start)
                    self.assertLess(include, text.index("roles:", start))
        defaults = (ROOT / "roles" / "security" / "defaults" / "main.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("hostvars[groups['entry'][0]].ansible_host", defaults)

    def test_menu_shows_a_green_line_when_no_reboot_is_needed(self) -> None:
        status = (ROOT / "roles" / "terminal" / "templates" / "kalimera-status.py.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn('"ПЕРЕЗАГРУЗКА"', status)
        self.assertIn('("Статус", "перезагрузка не требуется", "OK")', status)

    def test_menu_colours_follow_the_scheme(self) -> None:
        # Зелёный - OK, синий - информация, жёлтый - действие или несоответствие,
        # красный - критическая ошибка.
        status = (ROOT / "roles" / "terminal" / "templates" / "kalimera-status.py.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn('RED = "\\033[1;31m"', status)
        self.assertIn('else RED if level == "FAIL"', status)
        self.assertIn('else YELLOW if level in {"WARN", "UPD", "NOTE"}', status)
        self.assertIn('rows.append(("", "→ " + fields[3], "NOTE"))', status)
        self.assertIn(
            '"выключите No Limit Mode, иначе резерв не включится", "INFO"', status
        )

    def test_admin_gateway_allows_only_the_named_command(self) -> None:
        gateway = (
            ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("|cascade-check|kalimera-updates)", gateway)

    def test_managed_files_are_sealed(self) -> None:
        text = (
            ROOT / "roles" / "operations" / "templates" / "awg-managed-integrity.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("/usr/local/sbin/kalimera-report", text)
        self.assertIn("/usr/local/sbin/cascade-check", text)


if __name__ == "__main__":
    unittest.main()

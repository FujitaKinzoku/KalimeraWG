"""Российские имена через российский DoT в режиме без RU-прокси.

awg-ru-dns-sync рендерится Jinja2 с путями во временный каталог и запускается в
bash. unbound-checkconf, systemctl и dig подменяются скриптами в PATH, поэтому
настоящий Unbound, сеть и root не нужны. Остальные проверки смотрят, что зоны
пересобираются из команд управления доменами и DoT, а отчёты показывают режим.
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
import yaml

ROOT = Path(__file__).parents[1]
SYNC = ROOT / "roles" / "entry_dns" / "templates" / "awg-ru-dns-sync.sh.j2"
DEFAULTS = ROOT / "roles" / "entry_dns" / "defaults" / "main.yml"
TASKS = ROOT / "roles" / "entry_dns" / "tasks" / "main.yml"
DOMAIN_ADMIN = ROOT / "roles" / "operations" / "templates" / "domain-admin.sh.j2"
DOT_SWITCH = ROOT / "roles" / "operations" / "templates" / "dot-switch.sh.j2"
DNS_STATUS = ROOT / "roles" / "operations" / "templates" / "dns-status.sh.j2"
INTEGRITY = ROOT / "roles" / "operations" / "templates" / "awg-managed-integrity.sh.j2"
HEALTH = ROOT / "roles" / "health" / "templates" / "awg-health.sh.j2"
REPORT = ROOT / "roles" / "cascade_check" / "templates" / "kalimera-report.sh.j2"
STATUS = ROOT / "roles" / "terminal" / "templates" / "kalimera-status.py.j2"

YANDEX = ("77.88.8.8@853#common.dot.dns.yandex.net", "77.88.8.1@853#common.dot.dns.yandex.net")
DEFAULT_DOT = ("195.72.60.66@853#sto01.dnscry.pt", "195.123.212.200@853#rix01.dnscry.pt")

FAKE_TOOL = """#!/usr/bin/env bash
# Подставная команда: записывает вызов и отвечает по файлам-переключателям.
state={state}
printf '%s %s\\n' "$(basename "$0")" "$*" >>"$state/calls.log"
case "$(basename "$0")" in
    unbound-checkconf)
        if [[ $# -gt 0 && -e "$state/candidate-invalid" ]]; then exit 1; fi
        if [[ $# -eq 0 && -e "$state/config-invalid" ]]; then exit 1; fi
        ;;
    systemctl)
        if [[ "$1" == is-active && -e "$state/unbound-inactive" ]]; then exit 3; fi
        ;;
    dig)
        [[ -e "$state/probe-fails" ]] || echo 77.88.55.88
        ;;
    unbound-control)
        [[ ! -e "$state/control-fails" ]] || exit 1
        cat "$state/forwards.txt"
        ;;
esac
"""


def load_defaults() -> dict:
    return yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))


def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    env.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    return env


def render(template: Path, **variables) -> str:
    return environment().from_string(template.read_text(encoding="utf-8")).render(**variables)


def bash_path() -> str:
    executable = shutil.which("bash")
    if executable is None or os.name == "nt":
        raise unittest.SkipTest("нужен bash на Linux")
    return executable


def zones_of(text: str) -> dict[str, dict]:
    """Зоны файла Unbound: имя -> признак TLS и список серверов."""
    zones: dict[str, dict] = {}
    current: dict | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "forward-zone:":
            current = {"tls": False, "servers": []}
        elif current is not None and stripped.startswith("name:"):
            zones[stripped.split('"')[1]] = current
        elif current is not None and stripped == "forward-tls-upstream: yes":
            current["tls"] = True
        elif current is not None and stripped.startswith("forward-addr:"):
            current["servers"].append(stripped.split()[1])
    return zones


class SyncCase(unittest.TestCase):
    """Каталог с подставными командами и отрендеренной программой."""

    def setUp(self) -> None:
        self.bash = bash_path()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.conf = self.dir / "conf.d"
        self.policy = self.dir / "policy"
        self.run_dir = self.dir / "run"
        self.fakebin = self.dir / "bin"
        for directory in (self.conf, self.policy, self.run_dir, self.fakebin):
            directory.mkdir()
        self.output = self.conf / "91-awg-ru-dot.conf"
        self.calls = self.dir / "calls.log"
        self.calls.write_text("", encoding="utf-8")
        for name in ("unbound-checkconf", "systemctl", "dig", "unbound-control"):
            tool = self.fakebin / name
            tool.write_text(FAKE_TOOL.format(state=shlex.quote(str(self.dir))), encoding="utf-8")
            tool.chmod(0o755)
        self.write_base(DEFAULT_DOT)
        self.script = self.dir / "awg-ru-dns-sync"
        self.render_sync()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def sync_variables(self, **overrides) -> dict:
        defaults = load_defaults()
        variables = {
            "entry_dns_ru_dot_active": True,
            "entry_dns_ru_dot_zones": defaults["entry_dns_ru_dot_zones"],
            "entry_dns_ru_dot_upstreams": defaults["entry_dns_ru_dot_upstreams"],
            "entry_unbound_config_dir": str(self.conf),
            "awg_domain_policy_dir": str(self.policy),
            "entry_dns_ru_dot_runtime_dir": str(self.run_dir),
            "entry_dns_default_port": 5353,
        }
        variables.update(overrides)
        return variables

    def render_sync(self, **overrides) -> None:
        text = render(SYNC, **self.sync_variables(**overrides))
        # Проверка root заменяется: тест работает от обычного пользователя.
        self.assertIn("[[ $EUID -eq 0 ]] ||", text)
        self.script.write_text(text.replace("[[ $EUID -eq 0 ]] ||", "true ||", 1), encoding="utf-8")
        self.script.chmod(0o755)

    def write_base(self, servers: tuple[str, ...], *, tls: bool = True) -> None:
        lines = ["server:", "    port: 5353", "", "forward-zone:", '    name: "."']
        if tls:
            lines.append("    forward-tls-upstream: yes")
        lines += [f"    forward-addr: {server}" for server in servers]
        (self.conf / "90-awg-dot.conf").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def write_list(self, name: str, *domains: str) -> None:
        (self.policy / name).write_text("".join(f"{domain}\n" for domain in domains), encoding="utf-8")

    def sync(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "PATH": f"{self.fakebin}{os.pathsep}{os.environ['PATH']}",
            "AWG_RU_DNS_SYNC_RETRY_SECONDS": "0",
        }
        return subprocess.run(
            [self.bash, str(self.script), *arguments],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    def flag(self, name: str, present: bool = True) -> None:
        path = self.dir / name
        if present:
            path.write_text("", encoding="utf-8")
        else:
            path.unlink(missing_ok=True)

    def call_count(self, prefix: str) -> int:
        return sum(line.startswith(prefix) for line in self.calls.read_text(encoding="utf-8").splitlines())

    def zones(self) -> dict[str, dict]:
        return zones_of(self.output.read_text(encoding="utf-8"))


class RuDotSyncTests(SyncCase):
    def test_russian_zones_and_lists_go_to_the_russian_resolver(self) -> None:
        self.write_list("ru-domain", "vk.com", "userapi.com")
        self.write_list("entry-domain", "example-bank.com")
        self.write_list("se-domain", "googlevideo.com")
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "Зоны российских имён применены: 5 через российский DoT, исключений se-domain: 0.\n",
        )
        zones = self.zones()
        self.assertEqual(
            sorted(zones), ["example-bank.com.", "ru.", "userapi.com.", "vk.com.", "xn--p1ai."]
        )
        for name, zone in zones.items():
            self.assertTrue(zone["tls"], name)
            self.assertEqual(zone["servers"], list(YANDEX), name)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.call_count("systemctl restart unbound.service"), 1)

    def test_candidate_and_full_configuration_are_checked_before_restart(self) -> None:
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls.read_text(encoding="utf-8").splitlines()
        candidate = next(i for i, line in enumerate(calls) if line.startswith("unbound-checkconf /"))
        full = calls.index("unbound-checkconf ")
        restart = calls.index("systemctl restart unbound.service")
        self.assertLess(candidate, full)
        self.assertLess(full, restart)
        # После перезапуска российское имя запрашивается у локального Unbound.
        self.assertIn("dig +short +time=3 +tries=1 @127.0.0.1 -p 5353 yandex.ru A", calls[restart + 1])

    def test_se_domain_inside_a_russian_zone_keeps_the_default_resolvers(self) -> None:
        self.write_list("ru-domain", "vk.com")
        self.write_list("se-domain", "music.yandex.ru", "static.vk.com", "googlevideo.com")
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("исключений se-domain: 2.", result.stdout)
        zones = self.zones()
        for name in ("music.yandex.ru.", "static.vk.com."):
            self.assertTrue(zones[name]["tls"], name)
            self.assertEqual(zones[name]["servers"], list(DEFAULT_DOT), name)
        self.assertEqual(zones["vk.com."]["servers"], list(YANDEX))
        self.assertNotIn("googlevideo.com.", zones)

    def test_exception_follows_plain_dns_through_exit(self) -> None:
        # entry_dns_default_via_exit: серверы по умолчанию без TLS, порт 53 на EXIT.
        self.write_base(("10.77.0.1@53",), tls=False)
        self.write_list("se-domain", "music.yandex.ru")
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        zone = self.zones()["music.yandex.ru."]
        self.assertFalse(zone["tls"])
        self.assertEqual(zone["servers"], ["10.77.0.1@53"])
        self.assertTrue(self.zones()["ru."]["tls"])

    def test_name_in_both_lists_is_treated_as_se_domain(self) -> None:
        self.write_list("ru-domain", "example.com", "shop.example.ru")
        self.write_list("se-domain", "example.com", "example.ru")
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        zones = self.zones()
        self.assertNotIn("example.com.", zones)
        # Более точное российское правило остаётся внутри исключения se-domain.
        self.assertEqual(zones["example.ru."]["servers"], list(DEFAULT_DOT))
        self.assertEqual(zones["shop.example.ru."]["servers"], list(YANDEX))

    def test_comments_case_and_invalid_names_are_normalised(self) -> None:
        (self.policy / "ru-domain").write_text(
            "# комментарий\n\n  VK.com.  \nuserapi.com # хвост\nне-домен\n-bad-.com\nlocalhost\n",
            encoding="utf-8",
        )
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(self.zones()), ["ru.", "userapi.com.", "vk.com.", "xn--p1ai."])

    def test_missing_policy_lists_leave_only_the_static_zones(self) -> None:
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(self.zones()), ["ru.", "xn--p1ai."])

    def test_second_run_is_silent_and_does_not_restart(self) -> None:
        self.write_list("ru-domain", "vk.com")
        self.assertEqual(self.sync().returncode, 0)
        before = self.output.read_text(encoding="utf-8")
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.output.read_text(encoding="utf-8"), before)
        self.assertEqual(self.call_count("systemctl restart unbound.service"), 1)

    def test_no_restart_writes_the_file_and_leaves_the_restart_to_the_caller(self) -> None:
        self.write_list("se-domain", "music.yandex.ru")
        result = self.sync("--no-restart")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("music.yandex.ru.", self.zones())
        self.assertEqual(self.call_count("systemctl"), 0)
        self.assertEqual(self.call_count("dig"), 0)

    def test_new_default_resolvers_reach_the_exceptions(self) -> None:
        self.write_list("se-domain", "music.yandex.ru")
        self.assertEqual(self.sync().returncode, 0)
        self.write_base(("185.95.218.43@853#dns.digitale-gesellschaft.ch",))
        result = self.sync("--no-restart")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.zones()["music.yandex.ru."]["servers"],
            ["185.95.218.43@853#dns.digitale-gesellschaft.ch"],
        )
        self.assertEqual(self.zones()["ru."]["servers"], list(YANDEX))

    def test_stopped_unbound_is_not_started_by_the_sync(self) -> None:
        self.flag("unbound-inactive")
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.exists())
        self.assertEqual(self.call_count("systemctl restart"), 0)

    def test_proxy_mode_removes_the_zone_file(self) -> None:
        self.assertEqual(self.sync().returncode, 0)
        self.render_sync(entry_dns_ru_dot_active=False)
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(
            result.stdout, "Зоны российских имён удалены: работает RU-прокси или режим выключен.\n"
        )
        self.assertEqual(self.call_count("systemctl restart unbound.service"), 2)

    def test_proxy_mode_without_a_zone_file_does_nothing(self) -> None:
        self.render_sync(entry_dns_ru_dot_active=False)
        result = self.sync()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.output.exists())
        self.assertEqual(self.calls.read_text(encoding="utf-8"), "")

    def test_failed_probe_restores_the_previous_zone_file(self) -> None:
        self.write_list("ru-domain", "vk.com")
        self.assertEqual(self.sync().returncode, 0)
        before = self.output.read_text(encoding="utf-8")
        self.write_list("ru-domain", "vk.com", "userapi.com")
        self.flag("probe-fails")
        result = self.sync()
        self.assertEqual(result.returncode, 1)
        self.assertIn("российские серверы DoT недоступны", result.stderr)
        self.assertIn("entry_dns_ru_dot_enabled: false", result.stderr)
        self.assertIn("предыдущая конфигурация Unbound восстановлена", result.stderr)
        self.assertEqual(self.output.read_text(encoding="utf-8"), before)
        # Перезапуск после первой сборки, после новой и после возврата прежнего файла.
        self.assertEqual(self.call_count("systemctl restart unbound.service"), 3)

    def test_failed_probe_on_first_run_leaves_no_zone_file(self) -> None:
        self.flag("probe-fails")
        result = self.sync()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.call_count("systemctl restart unbound.service"), 2)

    def test_invalid_candidate_is_never_installed(self) -> None:
        self.flag("candidate-invalid")
        result = self.sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.call_count("systemctl restart"), 0)

    def test_invalid_full_configuration_restores_the_previous_file(self) -> None:
        self.assertEqual(self.sync().returncode, 0)
        before = self.output.read_text(encoding="utf-8")
        self.write_list("ru-domain", "vk.com")
        self.flag("config-invalid")
        result = self.sync()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(encoding="utf-8"), before)

    def test_exceptions_require_default_resolvers(self) -> None:
        (self.conf / "90-awg-dot.conf").unlink()
        self.write_list("se-domain", "music.yandex.ru")
        result = self.sync()
        self.assertEqual(result.returncode, 1)
        self.assertIn("нет серверов по умолчанию", result.stderr)
        self.assertFalse(self.output.exists())

    def test_empty_zone_set_never_becomes_the_root_zone(self) -> None:
        self.render_sync(entry_dns_ru_dot_zones=[])
        result = self.sync("--no-restart")
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.output.read_text(encoding="utf-8")
        self.assertNotIn("forward-zone:", text)
        self.assertNotIn('name: "."', text)

    def test_temporary_files_and_lock_stay_in_the_runtime_directory(self) -> None:
        self.assertEqual(self.sync().returncode, 0)
        self.assertEqual([path.name for path in self.run_dir.iterdir()], ["awg-ru-dns-sync.lock"])
        self.assertEqual(sorted(path.name for path in self.conf.iterdir()), ["90-awg-dot.conf", "91-awg-ru-dot.conf"])

    def test_usage_errors(self) -> None:
        for arguments in (("--unknown",), ("--no-restart", "extra"), ("--help", "extra")):
            result = self.sync(*arguments)
            self.assertEqual(result.returncode, 2, arguments)
            self.assertIn("Использование: awg-ru-dns-sync [--no-restart]", result.stderr)
        result = self.sync("--help")
        self.assertEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_rendered_script_requires_root(self) -> None:
        text = render(SYNC, **self.sync_variables())
        self.assertIn("[[ $EUID -eq 0 ]] || { echo 'Запустите команду от root.' >&2; exit 1; }", text)

    def test_rendered_scripts_pass_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("нужен shellcheck")
        inactive = self.dir / "awg-ru-dns-sync-inactive"
        inactive.write_text(
            render(SYNC, **self.sync_variables(entry_dns_ru_dot_active=False)), encoding="utf-8"
        )
        result = subprocess.run(
            [shellcheck, "--exclude=SC2317", str(self.script), str(inactive)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class DnsStatusTests(SyncCase):
    def render_status(self) -> Path:
        script = self.dir / "dns-status"
        script.write_text(
            render(
                DNS_STATUS,
                sing_box_config_path=str(self.dir / "no-sing-box.json"),
                entry_dns_dot_override_path=str(self.dir / "no-dot-override.json"),
                sing_box_dns_override_path=str(self.dir / "no-doh-override.json"),
                entry_ru_proxy_disabled_flag=str(self.dir / "no-failopen"),
                entry_ru_proxy_manual_disabled_flag=str(self.dir / "no-manual"),
                awg_domain_policy_dir=str(self.policy),
                entry_client_listen_address="10.66.0.1",
                entry_dns_default_port=5353,
                entry_dns_ru_port=5354,
                sing_box_service_name="sing-box.service",
                entry_unbound_config_dir=str(self.conf),
            ),
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script

    def status(self) -> subprocess.CompletedProcess[str]:
        # На сервере три списка существуют всегда: их создаёт роль operations.
        for name in ("ru-domain", "se-domain", "entry-domain"):
            (self.policy / name).touch()
        env = {
            **os.environ,
            "PATH": f"{self.fakebin}{os.pathsep}{os.environ['PATH']}",
            "NO_COLOR": "1",
        }
        return subprocess.run(
            [self.bash, str(self.render_status())], capture_output=True, text=True, env=env, timeout=60
        )

    def test_russian_dot_section_shows_servers_counts_and_probe(self) -> None:
        self.write_list("ru-domain", "vk.com")
        self.write_list("se-domain", "music.yandex.ru")
        self.assertEqual(self.sync().returncode, 0)
        result = self.status()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DoT российских имён\n  " + YANDEX[0] + "\n  " + YANDEX[1] + "\n", result.stdout)
        self.assertIn(
            "Режим RU DNS: DoT напрямую с ENTRY · зон: 3 · исключений se-domain: 1 · тест: OK",
            result.stdout,
        )
        # Серверы исключения se-domain в списке российских серверов не показываются.
        self.assertNotIn(DEFAULT_DOT[0], result.stdout.split("DoT российских имён")[1])
        self.assertNotIn("DoH не настроен", result.stdout)

    def test_without_zone_file_the_previous_text_remains(self) -> None:
        result = self.status()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("DoT российских имён", result.stdout)
        self.assertIn("DoH не настроен: RU-прокси не выбран при установке.", result.stdout)
        self.assertIn("Режим RU DNS: серверы DoT по умолчанию", result.stdout)

    def test_rendered_script_passes_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("нужен shellcheck")
        result = subprocess.run(
            [shellcheck, "--exclude=SC2317", str(self.render_status())], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class HealthCheckTests(SyncCase):
    """Функция ru_dot_dns_is_active из awg-health на подставном unbound-control."""

    def fragment(self) -> str:
        text = HEALTH.read_text(encoding="utf-8")
        function = text.index("ru_dot_dns_is_active() {")
        start = text.rindex("{% if entry_dns_ru_dot_active | default(false) | bool %}", 0, function)
        end = text.index("{% endif %}", function) + len("{% endif %}")
        defaults = load_defaults()
        return environment().from_string(text[start:end]).render(
            entry_dns_ru_dot_active=True,
            entry_dns_ru_dot_zones=defaults["entry_dns_ru_dot_zones"],
            entry_dns_ru_dot_upstreams=defaults["entry_dns_ru_dot_upstreams"],
            entry_dns_default_port=5353,
        )

    def verdict(self, forwards: str) -> str:
        (self.dir / "forwards.txt").write_text(forwards, encoding="utf-8")
        body = "set -Eeuo pipefail\n" + self.fragment() + "\nif ru_dot_dns_is_active; then echo PASS; else echo FAIL; fi\n"
        env = {**os.environ, "PATH": f"{self.fakebin}{os.pathsep}{os.environ['PATH']}"}
        result = subprocess.run([self.bash, "-c", body], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_loaded_russian_zones_pass(self) -> None:
        forwards = (
            ". IN forward 195.72.60.66 195.123.212.200\n"
            "ru. IN forward 77.88.8.8 77.88.8.1\n"
            "vk.com. IN forward 77.88.8.8 77.88.8.1\n"
            "xn--p1ai. IN forward 77.88.8.1 77.88.8.8\n"
        )
        self.assertEqual(self.verdict(forwards), "PASS")

    def test_missing_zone_fails(self) -> None:
        forwards = ". IN forward 195.72.60.66\nru. IN forward 77.88.8.8 77.88.8.1\n"
        self.assertEqual(self.verdict(forwards), "FAIL")

    def test_zone_on_other_resolvers_fails(self) -> None:
        forwards = (
            ". IN forward 195.72.60.66\n"
            "ru. IN forward 77.88.8.88 195.72.60.66\n"
            "xn--p1ai. IN forward 77.88.8.8\n"
        )
        self.assertEqual(self.verdict(forwards), "FAIL")

    def test_longer_zone_name_does_not_count_as_the_russian_zone(self) -> None:
        forwards = "guru. IN forward 77.88.8.8\nxn--p1ai. IN forward 77.88.8.8\n"
        self.assertEqual(self.verdict(forwards), "FAIL")

    def test_unanswered_probe_fails(self) -> None:
        self.flag("probe-fails")
        forwards = "ru. IN forward 77.88.8.8\nxn--p1ai. IN forward 77.88.8.8\n"
        self.assertEqual(self.verdict(forwards), "FAIL")

    def test_unreachable_control_socket_fails(self) -> None:
        self.flag("control-fails")
        self.assertEqual(self.verdict("ru. IN forward 77.88.8.8\nxn--p1ai. IN forward 77.88.8.8\n"), "FAIL")

    def test_check_is_rendered_only_for_the_direct_mode(self) -> None:
        text = HEALTH.read_text(encoding="utf-8")
        check = "check 'российские имена разрешает российский DoT с ENTRY' ru_dot_dns_is_active"
        position = text.index(check)
        guard = "{% if entry_dns_ru_dot_active | default(false) | bool %}\n"
        self.assertTrue(text[:position].endswith(guard))
        self.assertEqual(text.count(guard), 2)
        # Рекомендация подбирается раньше общей подсказки про DNS.
        self.assertLess(text.index("*'российский DoT'*)"), text.index("*DNS*|*Unbound*"))


class ReportRouteTests(unittest.TestCase):
    def route(self, **variables) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "kalimera-report"
            script.write_text(
                render(
                    REPORT,
                    awg_node_role="entry",
                    entry_client_listen_address="10.66.0.1",
                    entry_ru_proxy_manual_disabled_flag=str(Path(temporary) / "no-manual"),
                    entry_ru_proxy_disabled_flag=str(Path(temporary) / "no-failopen"),
                    **variables,
                ),
                encoding="utf-8",
            )
            body = (
                f"source {shlex.quote(str(script))}\n"
                "dns_probe() { printf '77.88.55.88 4\\n'; }\n"
                "check_dns\n"
            )
            result = subprocess.run([bash_path(), "-c", body], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()[0]

    def test_direct_mode_names_the_russian_dot_route(self) -> None:
        row = self.route(entry_ru_proxy_enabled=False, entry_dns_ru_dot_active=True)
        self.assertIn("DNS: yandex.ru (РФ) через клиентский резолвер", row)
        self.assertIn("маршрут: Unbound → российский DoT напрямую с ENTRY (RU-прокси не используется)", row)

    def test_disabled_mode_keeps_the_previous_route(self) -> None:
        row = self.route(entry_ru_proxy_enabled=False, entry_dns_ru_dot_active=False)
        self.assertIn("маршрут: Unbound (RU DoH недоступен, RU-прокси выключен)", row)

    def test_missing_variable_means_disabled(self) -> None:
        row = self.route(entry_ru_proxy_enabled=False)
        self.assertIn("маршрут: Unbound (RU DoH недоступен, RU-прокси выключен)", row)


class StatusPanelTests(unittest.TestCase):
    def current_ru_dot(self, content: str | None) -> str:
        text = STATUS.read_text(encoding="utf-8")
        start = text.index("def current_ru_dot() -> str:")
        source = text[start:text.index("\ndef ", start + 1)]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "91-awg-ru-dot.conf"
            if content is not None:
                path.write_text(content, encoding="utf-8")
            namespace = {"re": re, "Path": lambda _name: path}
            exec(source, namespace)  # noqa: S102 - функция из шаблона проекта
            return namespace["current_ru_dot"]()

    def test_servers_of_the_first_zone_are_shown(self) -> None:
        content = (
            "# Сформировано awg-ru-dns-sync.\n"
            'forward-zone:\n    name: "ru."\n    forward-tls-upstream: yes\n'
            f"    forward-addr: {YANDEX[0]}\n    forward-addr: {YANDEX[1]}\n"
            "# Имена se-domain внутри российских зон: серверы DoT по умолчанию.\n"
            'forward-zone:\n    name: "music.yandex.ru."\n'
            f"    forward-addr: {DEFAULT_DOT[0]}\n"
        )
        self.assertEqual(self.current_ru_dot(content), ", ".join(YANDEX))

    def test_missing_or_empty_file_gives_an_empty_value(self) -> None:
        self.assertEqual(self.current_ru_dot(None), "")
        self.assertEqual(self.current_ru_dot("# Сформировано awg-ru-dns-sync.\n"), "")

    def test_panel_no_longer_shows_doh_without_the_proxy(self) -> None:
        text = STATUS.read_text(encoding="utf-8")
        self.assertIn('("RU DNS", ru_dns, "INFO")', text)
        self.assertIn('ru_dns = f"Unbound DoT напрямую с ENTRY: {ru_dot}"', text)
        self.assertIn('if CONFIG["proxy_configured"]:\n            ru_dns = f"{doh_note}: {current_doh()}"', text)


class WiringTests(unittest.TestCase):
    def test_defaults_point_russian_zones_to_yandex_dot(self) -> None:
        defaults = load_defaults()
        self.assertIs(defaults["entry_dns_ru_dot_enabled"], True)
        self.assertEqual(defaults["entry_dns_ru_dot_zones"], ["ru", "xn--p1ai"])
        self.assertEqual(
            defaults["entry_dns_ru_dot_upstreams"],
            [
                {"address": "77.88.8.8", "tls_name": "common.dot.dns.yandex.net"},
                {"address": "77.88.8.1", "tls_name": "common.dot.dns.yandex.net"},
            ],
        )
        self.assertEqual(defaults["entry_dns_ru_dot_probe_name"], "yandex.ru")

    def test_mode_is_active_only_without_the_proxy(self) -> None:
        expression = load_defaults()["entry_dns_ru_dot_active"]
        cases = {
            (True, False): "True",
            (True, True): "False",
            (False, False): "False",
            (False, True): "False",
        }
        for (enabled, proxy), expected in cases.items():
            rendered = environment().from_string(expression).render(
                entry_dns_ru_dot_enabled=enabled, entry_ru_proxy_enabled=proxy
            )
            self.assertEqual(rendered, expected, (enabled, proxy))
        # В inventory без RU-прокси переменной может не быть вовсе.
        self.assertEqual(
            environment().from_string(expression).render(entry_dns_ru_dot_enabled=True), "True"
        )

    def test_role_installs_the_program_and_then_builds_the_zones(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        names = [task["name"] for task in tasks]
        install = names.index("Российские имена: программа сборки зон Unbound")
        build = names.index("Российские имена: зоны Unbound для режима без RU-прокси")
        self.assertLess(install, build)
        self.assertEqual(tasks[install]["ansible.builtin.template"]["dest"], "/usr/local/sbin/awg-ru-dns-sync")
        self.assertEqual(tasks[install]["ansible.builtin.template"]["mode"], "0750")
        # Программа ставится и запускается в обоих режимах: с RU-прокси она убирает зоны.
        self.assertNotIn("when", tasks[install])
        self.assertNotIn("when", tasks[build])
        self.assertEqual(tasks[build]["ansible.builtin.command"]["argv"], ["/usr/local/sbin/awg-ru-dns-sync"])
        # Основная конфигурация Unbound к этому шагу уже установлена и служба запущена.
        self.assertLess(names.index("Включение: DNS ENTRY сервера - этап 21"), build)

    def test_resolver_lists_are_validated_without_a_loop(self) -> None:
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        task = next(item for item in tasks if item["name"] == "Российские имена: списки зон и серверов DoT не пусты")
        self.assertNotIn("loop", task)
        self.assertIn("entry_dns_ru_dot_upstreams | length >= 1", task["ansible.builtin.assert"]["that"])
        self.assertIn("entry_dns_ru_dot_zones | length >= 1", task["ansible.builtin.assert"]["that"])

    def test_domain_commands_rebuild_the_zones(self) -> None:
        text = DOMAIN_ADMIN.read_text(encoding="utf-8")
        hook = "if [[ -x /usr/local/sbin/awg-ru-dns-sync ]]; then\n    /usr/local/sbin/awg-ru-dns-sync\nfi\n"
        self.assertIn(hook, text)
        # Сбой сборки зон отменяет изменение списка: вызов стоит до completed=true.
        self.assertLess(text.index(hook), text.index("\ncompleted=true\n"))
        # Отложенное изменение (--defer) зоны не трогает.
        self.assertLess(text.index("применение отложено"), text.index(hook))

    def test_dot_switch_rebuilds_the_zones_before_its_single_restart(self) -> None:
        text = DOT_SWITCH.read_text(encoding="utf-8")
        hook = "    /usr/local/sbin/awg-ru-dns-sync --no-restart\n"
        restart = "\nsystemctl restart unbound.service\n"
        self.assertEqual(text.count(hook), 1)
        self.assertLess(text.index("committed=true"), text.index(hook))
        self.assertLess(text.index(hook), text.index(restart))
        # При откате зоны пересобираются под восстановленные серверы.
        cleanup = text[text.index("cleanup() {"):text.index("trap cleanup EXIT")]
        self.assertIn("/usr/local/sbin/awg-ru-dns-sync --no-restart >/dev/null 2>&1 || true", cleanup)
        self.assertLess(
            cleanup.index("awg-ru-dns-sync --no-restart"), cleanup.index("systemctl restart unbound.service")
        )

    def test_program_is_sealed_and_the_generated_file_is_not(self) -> None:
        text = INTEGRITY.read_text(encoding="utf-8")
        self.assertIn("\n/usr/local/sbin/awg-ru-dns-sync\n", text)
        # Файл зон меняют ru-domain, se-domain, entry-domain и dot-switch.
        self.assertNotIn("91-awg-ru-dot.conf", text)

    def test_zone_file_is_separate_from_the_file_dot_switch_rewrites(self) -> None:
        text = SYNC.read_text(encoding="utf-8")
        self.assertIn("'/91-awg-ru-dot.conf'", text)
        self.assertIn("'/90-awg-dot.conf'", text)
        # Блок raw: без него Jinja принимает ${#массив[@]} за начало комментария.
        raw = text.index("{% raw %}")
        self.assertLess(raw, text.index("${#russian[@]}"))
        self.assertLess(raw, text.index("${#exceptions[@]}"))


if __name__ == "__main__":
    unittest.main()

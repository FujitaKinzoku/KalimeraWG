"""Отказ от шифрованного DNS клиентов: служебные имена DoH не разрешаются.

Причина изменения найдена на рабочем каскаде. Приложение AmneziaVPN ставит на
адаптер DNS 1.1.1.1, браузер видит известного провайдера и сам переходит на DoH.
Запросы имён идут мимо резолвера ENTRY: списки доменов на такой браузер не
действуют, а запрос через EXIT попадал на узел Cloudflare, который не разрешал
имена ФНС.
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
DEFAULTS = ROOT / "roles" / "entry_dns" / "defaults" / "main.yml"
TASKS = ROOT / "roles" / "entry_dns" / "tasks" / "main.yml"
TEMPLATE = ROOT / "roles" / "entry_dns" / "templates" / "64-awg-client-doh.conf.j2"
HEALTH = ROOT / "roles" / "health" / "templates" / "awg-health.sh.j2"
INTEGRITY = ROOT / "roles" / "operations" / "templates" / "awg-managed-integrity.sh.j2"
ROLLBACK = ROOT / "playbooks" / "rollback-entry.yml"

NAME = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def defaults() -> dict:
    return yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))


def render(**variables) -> str:
    env = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    env.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    return env.from_string(TEMPLATE.read_text(encoding="utf-8")).render(**variables)


class DefaultsTests(unittest.TestCase):
    def test_fallback_is_on_and_the_file_is_managed(self) -> None:
        values = defaults()
        self.assertIs(values["entry_dns_client_doh_fallback_enabled"], True)
        managed = {item["name"]: item["template"] for item in values["entry_dnsmasq_managed_files"]}
        self.assertEqual(managed["64-awg-client-doh.conf"], TEMPLATE.name)

    def test_names_are_valid_and_unique(self) -> None:
        names = defaults()["entry_dns_client_doh_names"]
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            self.assertRegex(name, NAME)

    def test_list_covers_the_providers_browsers_switch_to_by_themselves(self) -> None:
        names = defaults()["entry_dns_client_doh_names"]
        for name in (
            "use-application-dns.net",  # сигнальное имя Firefox
            "resolver.arpa",  # обнаружение шифрованного резолвера системой
            "cloudflare-dns.com",  # chrome.cloudflare-dns.com при DNS 1.1.1.1
            "dns.google",
            "dns.quad9.net",
        ):
            self.assertIn(name, names)

    def test_deploy_rejects_malformed_names(self) -> None:
        tasks = TASKS.read_text(encoding="utf-8")
        block = tasks[tasks.index("служебные имена шифрованного DNS клиентов"):]
        block = block[: block.index("\n- name:")]
        self.assertIn("entry_dns_client_doh_names", block)
        self.assertIn("reject('match'", block)
        self.assertIn("when: entry_dns_client_doh_fallback_enabled | bool", block)


class TemplateTests(unittest.TestCase):
    def test_enabled_file_answers_no_such_name_for_every_listed_name(self) -> None:
        names = defaults()["entry_dns_client_doh_names"]
        text = render(entry_dns_client_doh_fallback_enabled=True, entry_dns_client_doh_names=names)
        rules = [line for line in text.splitlines() if line and not line.startswith("#")]
        # server=/имя/ без адреса: dnsmasq не пересылает запрос и отвечает, что имени нет.
        self.assertEqual(rules, [f"server=/{name}/" for name in names])

    def test_disabled_file_has_no_rules(self) -> None:
        text = render(
            entry_dns_client_doh_fallback_enabled=False,
            entry_dns_client_doh_names=defaults()["entry_dns_client_doh_names"],
        )
        self.assertNotIn("server=", text)
        self.assertIn("entry_dns_client_doh_fallback_enabled: false", text)

    def test_file_is_never_empty(self) -> None:
        # Файл входит в манифест целостности и должен существовать в обоих режимах.
        for enabled in (True, False):
            text = render(entry_dns_client_doh_fallback_enabled=enabled, entry_dns_client_doh_names=[])
            self.assertTrue(text.strip())


class WiringTests(unittest.TestCase):
    def test_file_is_sealed_and_can_be_rolled_back(self) -> None:
        self.assertIn("/etc/dnsmasq.d/64-awg-client-doh.conf\n", INTEGRITY.read_text(encoding="utf-8"))
        self.assertIn("- 64-awg-client-doh.conf\n", ROLLBACK.read_text(encoding="utf-8"))

    def test_health_check_follows_the_switch(self) -> None:
        text = HEALTH.read_text(encoding="utf-8")
        position = text.index("check 'служебные имена DoH не разрешаются")
        before = text[:position]
        condition = before[before.rindex("{% if"):]
        self.assertIn("entry_dns_client_doh_fallback_enabled", condition)
        self.assertIn("use-application-dns.net", condition)
        self.assertNotIn("{% endif %}", condition)


class HealthFunctionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bash = shutil.which("bash")
        if self.bash is None or os.name == "nt":
            self.skipTest("нужен bash на Linux")
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def verdict(self, answer: str) -> str:
        text = HEALTH.read_text(encoding="utf-8")
        start = text.index("client_doh_names_refused() {")
        source = text[start:text.index("\n}\n", start) + 3]
        source = re.sub(r"\{\{[^}]*\}\}", "10.66.0.1", source)
        (self.dir / "answer.txt").write_text(answer, encoding="utf-8")
        dig = self.dir / "dig"
        dig.write_text(
            "#!/usr/bin/env bash\n"
            f"printf '%s\\n' \"$*\" >{shlex.quote(str(self.dir / 'arguments.txt'))}\n"
            f"cat {shlex.quote(str(self.dir / 'answer.txt'))}\n",
            encoding="utf-8",
        )
        dig.chmod(0o755)
        body = (
            "set -Eeuo pipefail\n" + source
            + "\nif client_doh_names_refused; then echo PASS; else echo FAIL; fi\n"
        )
        env = {**os.environ, "PATH": f"{self.dir}{os.pathsep}{os.environ['PATH']}"}
        result = subprocess.run([self.bash, "-c", body], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    @staticmethod
    def header(status: str, answers: int) -> str:
        return (
            ";; Got answer:\n"
            f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 4242\n"
            f";; flags: qr aa rd ra; QUERY: 1, ANSWER: {answers}, AUTHORITY: 0, ADDITIONAL: 1\n"
        )

    def test_refusal_passes(self) -> None:
        self.assertEqual(self.verdict(self.header("NXDOMAIN", 0)), "PASS")
        self.assertEqual(self.verdict(self.header("NOERROR", 0)), "PASS")

    def test_query_goes_to_the_client_resolver_for_the_canary_name(self) -> None:
        self.verdict(self.header("NXDOMAIN", 0))
        arguments = (self.dir / "arguments.txt").read_text(encoding="utf-8")
        self.assertIn("@10.66.0.1", arguments)
        self.assertIn("use-application-dns.net A", arguments)

    def test_resolved_name_fails(self) -> None:
        self.assertEqual(self.verdict(self.header("NOERROR", 2)), "FAIL")

    def test_resolver_failure_is_not_a_refusal(self) -> None:
        self.assertEqual(self.verdict(self.header("SERVFAIL", 0)), "FAIL")
        self.assertEqual(self.verdict(";; communications error to 10.66.0.1#53: timed out\n"), "FAIL")
        self.assertEqual(self.verdict(""), "FAIL")


if __name__ == "__main__":
    unittest.main()

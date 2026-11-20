"""Сообщения команд управления описывают то, что произошло на самом деле.

Повод: на рабочем каскаде "proxy-domain del vk.ru" отвечала "vk.ru удалён из
proxy-domain", хотя домена в списке не было. Те же проверки сделаны для остальных
команд, где ответ не зависел от результата. Списки доменов и proxy-address
проверяются в test_selective_proxy.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import jinja2

ROOT = Path(__file__).parents[1]
TEMPLATES = ROOT / "roles" / "operations" / "templates"

FAKE_TOOL = """#!/usr/bin/env bash
state={state}
name="$(basename "$0")"
printf '%s %s\\n' "$name" "$*" >>"$state/calls.log"
if [[ "$name" == fail2ban-client && "$*" == *unbanip* ]]; then
    cat "$state/unbanned.txt"
fi
"""


def render(name: str, **variables) -> str:
    # Нестрогий режим: проверяемая ветка использует малую часть переменных шаблона.
    env = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    env.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    return env.from_string((TEMPLATES / name).read_text(encoding="utf-8")).render(**variables)


class CommandCase(unittest.TestCase):
    tools: tuple[str, ...] = ()

    def setUp(self) -> None:
        self.bash = shutil.which("bash")
        if self.bash is None or os.name == "nt":
            self.skipTest("нужен bash на Linux")
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.fakebin = self.dir / "bin"
        self.run_dir = self.dir / "run"
        self.fakebin.mkdir()
        self.run_dir.mkdir()
        self.calls = self.dir / "calls.log"
        self.calls.write_text("", encoding="utf-8")
        for name in self.tools:
            self.fake(self.fakebin / name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def fake(self, path: Path) -> Path:
        path.write_text(FAKE_TOOL.format(state=shlex.quote(str(self.dir))), encoding="utf-8")
        path.chmod(0o755)
        return path

    def install(self, name: str, text: str) -> Path:
        text = text.replace("[[ $EUID -eq 0 ]] ||", "true ||", 1)
        text = text.replace("/run/", f"{self.run_dir}/")
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)
        return path

    def execute(self, script: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "PATH": f"{self.fakebin}{os.pathsep}{os.environ['PATH']}"}
        return subprocess.run(
            [self.bash, str(script), *arguments], capture_output=True, text=True, env=env, timeout=60
        )

    def called(self, prefix: str) -> list[str]:
        return [line for line in self.calls.read_text(encoding="utf-8").splitlines() if line.startswith(prefix)]


class DirectPortsTests(CommandCase):
    def script(self) -> Path:
        self.ports = self.dir / "ports.list"
        self.ports.write_text("", encoding="utf-8")
        routing = self.fake(self.dir / "awg-entry-routing")
        text = render(
            "ru-direct-ports.sh.j2",
            entry_ru_direct_tcp_ports_file=str(self.ports),
            entry_routing_script_path=str(routing),
        ).replace("/root/config-backups/entry/routing", str(self.dir / "backups"))
        return self.install("ru-direct-ports", text)

    def test_messages_say_what_actually_happened(self) -> None:
        script = self.script()
        self.assertEqual(self.execute(script, "clear").stdout, "Политика прямых RU-портов уже пуста.\n")
        self.assertEqual(self.execute(script, "del", "443").stdout, "TCP-порт 443 не найден в прямом RU-маршруте.\n")
        self.assertFalse(self.called("awg-entry-routing"))
        self.assertEqual(self.execute(script, "add", "443").stdout, "TCP-порт 443 добавлен в прямой RU-маршрут.\n")
        self.assertEqual(self.execute(script, "add", "443").stdout, "TCP-порт 443 уже есть в прямом RU-маршруте.\n")
        self.assertEqual(len(self.called("awg-entry-routing apply")), 1)
        self.assertEqual(self.execute(script, "del", "443").stdout, "TCP-порт 443 удалён из прямого RU-маршрута.\n")
        self.execute(script, "add", "8443")
        self.assertEqual(self.execute(script, "clear").stdout, "Политика прямых RU-портов очищена.\n")


class Fail2BanResetTests(CommandCase):
    tools = ("fail2ban-client",)

    def reset(self, unbanned: str) -> subprocess.CompletedProcess[str]:
        (self.dir / "unbanned.txt").write_text(unbanned, encoding="utf-8")
        script = self.install("f2b-reset", (TEMPLATES / "f2b-reset.sh.j2").read_text(encoding="utf-8"))
        return self.execute(script, "203.0.113.7")

    def test_address_that_was_not_banned_is_reported_as_such(self) -> None:
        result = self.reset("0\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Адрес 203.0.113.7 не был заблокирован в jail sshd.", result.stdout)
        self.assertNotIn("удалён из блокировок", result.stdout)
        self.assertTrue(self.called("fail2ban-client set sshd unbanip 203.0.113.7"))

    def test_banned_address_is_reported_as_removed(self) -> None:
        result = self.reset("1\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Адрес 203.0.113.7 удалён из блокировок jail sshd.", result.stdout)


class ProxySwitchTests(CommandCase):
    tools = ("systemctl",)

    def script(self, *, enabled: bool, scope: str = "all") -> Path:
        self.manual = self.dir / "state" / "proxy.manual-off"
        text = render(
            "ru-proxy.sh.j2",
            entry_ru_proxy_enabled=enabled,
            entry_ru_proxy_scope=scope,
            entry_ru_proxy_disabled_flag=str(self.dir / "state" / "proxy.disabled"),
            entry_ru_proxy_manual_disabled_flag=str(self.manual),
            entry_routing_script_path=str(self.fake(self.dir / "awg-entry-routing")),
            awg_dns_policy_path=str(self.fake(self.dir / "awg-dns-policy")),
            entry_ru_proxy_watch_timer_name="awg-ru-proxy-watch.timer",
            entry_ru_proxy_watch_service_name="awg-ru-proxy-watch.service",
            entry_ru_proxy_connect_timeout=5,
            entry_ru_proxy_max_probe_time=10,
        )
        return self.install("ru-proxy", text)

    def test_switching_off_names_what_changes_in_each_scope(self) -> None:
        result = self.execute(self.script(enabled=True, scope="all"), "off")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "RU-трафик теперь выходит напрямую через ENTRY.\n")
        self.assertTrue(self.manual.exists())

        self.manual.unlink()
        result = self.execute(self.script(enabled=True, scope="selected"), "off")
        self.assertEqual(
            result.stdout,
            "RU-прокси выключен: адреса из proxy-domain и proxy-address теперь выходят напрямую через ENTRY.\n",
        )

    def test_repeated_switch_off_says_it_was_already_off(self) -> None:
        script = self.script(enabled=True, scope="selected")
        self.execute(script, "off")
        result = self.execute(script, "off")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "RU-прокси уже был выключен вручную; состояние применено повторно.\n")

    def test_switch_off_without_a_configured_proxy_changes_nothing(self) -> None:
        result = self.execute(self.script(enabled=False), "off")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, "RU-прокси не настроен: российский трафик и так выходит напрямую через ENTRY.\n"
        )
        self.assertFalse(self.manual.exists())
        self.assertFalse(self.called("systemctl"))
        self.assertFalse(self.called("awg-entry-routing"))


class ProxySetResetTests(CommandCase):
    # Команда в начале проверяет наличие jq и sing-box.
    tools = ("jq", "sing-box")

    def reset(self, *, with_override: bool) -> subprocess.CompletedProcess[str]:
        config = self.dir / "config.json"
        config.write_text("{}", encoding="utf-8")
        self.override = self.dir / "proxy-override.json"
        if with_override:
            self.override.write_text("{}", encoding="utf-8")
        text = render(
            "ru-proxy-set.sh.j2",
            sing_box_runtime_override_path=str(self.override),
            runtime_secrets_enabled=False,
        )
        self.assertIn("readonly config=/etc/sing-box/config.json\n", text)
        text = text.replace("/etc/sing-box/config.json", str(config))
        self.assertIn(f"readonly override={shlex.quote(str(self.override))}\n", text)
        return self.execute(self.install("ru-proxy-set", text), "reset")

    def test_reset_without_an_override_says_there_is_nothing_to_remove(self) -> None:
        result = self.reset(with_override=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, "Локального переопределения нет: параметры прокси уже берутся из inventory.\n"
        )

    def test_reset_removes_an_existing_override(self) -> None:
        result = self.reset(with_override=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Локальное переопределение удалено.", result.stdout)
        self.assertFalse(self.override.exists())


class TelegramMessageTests(CommandCase):
    def monitor(self, audit_output: str, audit_code: int) -> str:
        """Запустить мониторинг и вернуть текст, переданный в Telegram."""
        env_file = self.dir / "telegram.env"
        env_file.write_text("TELEGRAM_BOT_TOKEN=123456:test-token-value\nTELEGRAM_CHAT_ID=1\n", encoding="utf-8")
        audit = self.dir / "server-audit"
        audit.write_text(
            "#!/usr/bin/env bash\n" f"cat {shlex.quote(str(self.dir / 'audit.txt'))}\nexit {audit_code}\n",
            encoding="utf-8",
        )
        audit.chmod(0o755)
        (self.dir / "audit.txt").write_text(audit_output, encoding="utf-8")
        curl = self.fakebin / "curl"
        curl.write_text(
            "#!/usr/bin/env bash\n"
            "cat >/dev/null\n"
            'for argument in "$@"; do\n'
            f'    [[ "$argument" != text=* ]] || printf \'%s\' "${{argument#text=}}" >{shlex.quote(str(self.dir / "sent.txt"))}\n'
            "done\n",
            encoding="utf-8",
        )
        curl.chmod(0o755)
        text = render(
            "telegram-monitor.sh.j2",
            awg_telegram_monitor_env_path=str(env_file),
            awg_telegram_monitor_state_dir=str(self.dir / "state"),
            awg_node_role="entry",
            entry_ru_proxy_enabled=False,
            awg_server_audit_path=str(audit),
        )
        result = self.execute(self.install("awg-telegram-monitor", text))
        self.assertEqual(result.returncode, 0, result.stderr)
        return (self.dir / "sent.txt").read_text(encoding="utf-8")

    def test_reason_starts_on_its_own_line(self) -> None:
        # В двойных кавычках запись \n остаётся двумя символами: Telegram показывал
        # "не пройдена\nFAIL ..." одной строкой с обратной косой чертой.
        sent = self.monitor("OK   UFW активен\nFAIL служба dnsmasq\nFAIL служба Unbound\n", 1)
        self.assertEqual(
            sent.splitlines(),
            ["AWG ENTRY: проверка состояния не пройдена", "FAIL служба dnsmasq", "FAIL служба Unbound"],
        )
        self.assertNotIn("\\n", sent)

    def test_template_has_no_literal_backslash_n_in_messages(self) -> None:
        text = (TEMPLATES / "telegram-monitor.sh.j2").read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.lstrip().startswith(("message=", "reason=\"${", "reason='")):
                self.assertNotIn("\\n", line, line)


class PipelineTests(unittest.TestCase):
    """Проверки не обрывают чтение конвейера: при pipefail это давало ложный отказ."""

    def test_status_and_watchdog_read_the_whole_output(self) -> None:
        watchdog = ROOT / "roles" / "entry_watchdog" / "templates" / "awg-ru-proxy-watch.sh.j2"
        for path in (TEMPLATES / "dns-status.sh.j2", watchdog):
            code = "\n".join(
                line for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")
            )
            self.assertNotRegex(code, r"\|\s*\n?\s*grep -[A-Za-z]*q", path.name)


class KernelGuardTests(CommandCase):
    def test_kernel_list_is_separated_by_comma_and_space(self) -> None:
        text = (TEMPLATES / "awg-kernel-guard.sh.j2").read_text(encoding="utf-8")
        tail = text[text.index('kernel_list="$('):]
        script = self.dir / "list.sh"
        script.write_text(
            "#!/usr/bin/env bash\nset -Eeuo pipefail\nkernels=(6.8.0-87-generic 6.8.0-88-generic)\n" + tail,
            encoding="utf-8",
        )
        result = self.execute(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "AmneziaWG готов для ядер: 6.8.0-87-generic, 6.8.0-88-generic.\n")


if __name__ == "__main__":
    unittest.main()

"""Зарубежные имена через резолвер EXIT внутри туннеля.

Режим включает команда kalimera-deploy --resume --enable-dns-via-exit. Задача:
российский хостер ENTRY не должен видеть ни одного запроса DNS о зарубежных
узлах, даже зашифрованного. Проверяются места, где режим мог бы сломать каскад
или тихо не включиться: первое включение (резолвера на EXIT ещё нет), работа
через резервный EXIT и команды владельца.
"""

from __future__ import annotations

import importlib.util
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from test_cascade_check import REPORT, bash_path, render, row
from test_managed_integrity_reseal import (
    BASE_CONF,
    DOT_CONF,
    dot_switch_text,
    sandbox,
    without_root_check,
)

ROOT = Path(__file__).parents[1]
SELECTOR_PATH = ROOT / "roles" / "entry_exit_path" / "files" / "kalimera-exit-path.py"
DEPLOY_PATH = ROOT / "scripts" / "lib" / "interactive_deploy.py"
DOT_TEMPLATE = ROOT / "roles" / "entry_dns" / "templates" / "90-awg-dot.conf.j2"
DNS_STATUS = ROOT / "roles" / "operations" / "templates" / "dns-status.sh.j2"

SELECTOR_SPEC = importlib.util.spec_from_file_location("kalimera_exit_path_dns", SELECTOR_PATH)
selector = importlib.util.module_from_spec(SELECTOR_SPEC)
SELECTOR_SPEC.loader.exec_module(selector)

DEPLOY_SPEC = importlib.util.spec_from_file_location("interactive_deploy_dns", DEPLOY_PATH)
deploy = importlib.util.module_from_spec(DEPLOY_SPEC)
DEPLOY_SPEC.loader.exec_module(deploy)

# Конфигурация Unbound в режиме "через резолвер EXIT": пересылка без TLS на адрес
# EXIT в туннеле.
VIA_EXIT_CONF = (
    "server:\n"
    "    port: 5353\n"
    "    log-queries: no\n"
    "\n"
    "forward-zone:\n"
    '    name: "."\n'
    "    forward-addr: 10.77.0.1@53\n"
)


class SelectorDnsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = selector.Config(
            {
                "paths": [
                    {"name": "primary", "interface": "awg3", "tunnel_address": "10.77.0.2",
                     "peer_tunnel_address": "10.77.0.1"},
                    {"name": "standby", "interface": "awg4", "tunnel_address": "10.78.0.2",
                     "peer_tunnel_address": "10.78.0.1"},
                ],
                "probe_targets": [["192.0.2.1", 443]],
                "probe_quorum": 1,
                "probe_timeout_seconds": 1,
                "fail_threshold": 3,
                "failback_seconds": 900,
                "table": 100,
                "state_dir": "/nonexistent/run",
                "mode_file": "/nonexistent/mode",
                "dns_via_exit": True,
            }
        )

    def sync(self, listing: str, name: str) -> list[list[str]]:
        calls: list[list[str]] = []
        with mock.patch.object(selector.shutil, "which", return_value="/usr/sbin/unbound-control"), \
                mock.patch.object(selector.subprocess, "run", return_value=mock.Mock(stdout=listing)), \
                mock.patch.object(selector, "run_quiet", side_effect=lambda argv, **_: calls.append(argv) or 0):
            selector.sync_dns(self.cfg, name)
        return [call[1:] for call in calls]

    def test_forwarding_to_dot_servers_is_left_alone(self) -> None:
        # Первое включение: переключатель уже знает о режиме, а резолвера на EXIT
        # ещё нет. Перевод пересылки сейчас оставил бы каскад без зарубежных имён
        # до конца deploy.
        listing = (
            ". IN forward 162.254.86.13@853#vno01.dnscry.pt 185.95.218.43@853#dns.digitale-gesellschaft.ch\n"
            "ru. IN forward 77.88.8.8@853#common.dot.dns.yandex.net\n"
        )
        self.assertEqual(self.sync(listing, "primary"), [])
        self.assertEqual(self.sync(listing, "standby"), [])

    def test_root_zone_follows_the_active_exit(self) -> None:
        listing = ". IN forward 10.77.0.1@53\nru. IN forward 77.88.8.8@853#common.dot.dns.yandex.net\n"
        self.assertEqual(self.sync(listing, "primary"), [])
        self.assertEqual(
            self.sync(listing, "standby"), [["forward", "10.78.0.1@53"], ["flush_infra", "all"]]
        )

    def test_exceptions_inside_russian_zones_follow_the_active_exit(self) -> None:
        # Имя se-domain внутри зоны .ru: его зона смотрит в резолвер EXIT, как и
        # корневая. Без перевода оно перестало бы разрешаться на резервном пути.
        listing = (
            ". IN forward 10.77.0.1@53\n"
            "ru. IN forward 77.88.8.8@853#common.dot.dns.yandex.net 77.88.8.1@853#common.dot.dns.yandex.net\n"
            "example.ru. IN forward 10.77.0.1@53\n"
        )
        self.assertEqual(
            self.sync(listing, "standby"),
            [
                ["forward", "10.78.0.1@53"],
                ["forward_remove", "example.ru."],
                ["forward_add", "example.ru.", "10.78.0.1@53"],
                ["flush_infra", "all"],
            ],
        )

    def test_return_to_the_primary_moves_the_zones_back(self) -> None:
        listing = ". IN forward 10.78.0.1@53\nexample.ru. IN forward 10.78.0.1@53\n"
        self.assertEqual(
            self.sync(listing, "primary"),
            [
                ["forward", "10.77.0.1@53"],
                ["forward_remove", "example.ru."],
                ["forward_add", "example.ru.", "10.77.0.1@53"],
                ["flush_infra", "all"],
            ],
        )

    def test_disabled_mode_never_asks_unbound(self) -> None:
        self.cfg.dns_via_exit = False
        with mock.patch.object(selector.shutil, "which") as which:
            selector.sync_dns(self.cfg, "standby")
        which.assert_not_called()


class InstallerDnsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.production = Path(self.tmp.name) / "production"
        (self.production / "group_vars" / "all").mkdir(parents=True)
        self.all_path = self.production / "group_vars" / "all" / "main.yml"
        deploy.yaml_write(self.all_path, {"security_admin_user": "kalimera"})

    def switch(self, enabled: bool) -> bool:
        with mock.patch("builtins.print"):
            return deploy.set_dns_via_exit(self.production, enabled)

    def test_flag_is_written_for_entry_and_exit_alike(self) -> None:
        # Переменная общая: роль EXIT ставит по ней резолвер, роль ENTRY - пересылку.
        self.assertTrue(self.switch(True))
        values = yaml.safe_load(self.all_path.read_text(encoding="utf-8"))
        self.assertIs(values["entry_dns_default_via_exit"], True)
        self.assertEqual(values["security_admin_user"], "kalimera")
        self.assertFalse(self.switch(True), "повторное включение ничего не меняет")
        self.assertTrue(self.switch(False))
        self.assertIs(
            yaml.safe_load(self.all_path.read_text(encoding="utf-8"))["entry_dns_default_via_exit"], False
        )

    def test_cascade_without_the_variable_counts_as_disabled(self) -> None:
        before = self.all_path.read_text(encoding="utf-8")
        self.assertFalse(self.switch(False))
        self.assertEqual(self.all_path.read_text(encoding="utf-8"), before)

    def test_admin_gateway_allows_both_commands(self) -> None:
        gateway = (
            ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("'--resume --enable-dns-via-exit'|'--resume --disable-dns-via-exit'|", gateway)


class UnboundTemplateTests(unittest.TestCase):
    def forward_zone(self, **variables) -> str:
        values = {
            "entry_dns_default_port": 5353,
            "awg3_peer_tunnel_address": "10.77.0.1",
            "entry_dns_dot_upstreams_resolved": [
                {"address": "162.254.86.13", "tls_name": "vno01.dnscry.pt"},
            ],
            **variables,
        }
        text = render(DOT_TEMPLATE, **values)
        return text[text.index("forward-zone:"):]

    def test_effective_mode_forwards_into_the_tunnel_without_dot(self) -> None:
        zone = self.forward_zone(entry_dns_default_via_exit=True, entry_dns_via_exit_effective=True)
        self.assertIn("    forward-addr: 10.77.0.1@53\n", zone)
        self.assertNotIn("forward-tls-upstream", zone)
        self.assertNotIn("@853", zone)

    def test_first_enabling_stays_on_dot_until_the_exit_resolver_answers(self) -> None:
        zone = self.forward_zone(entry_dns_default_via_exit=True, entry_dns_via_exit_effective=False)
        self.assertIn("    forward-tls-upstream: yes\n", zone)
        self.assertIn("    forward-addr: 162.254.86.13@853#vno01.dnscry.pt\n", zone)
        self.assertNotIn("10.77.0.1", zone)

    def test_disabled_mode_is_dot(self) -> None:
        self.assertIn("forward-tls-upstream: yes", self.forward_zone())

    def test_switch_tasks_touch_only_the_forwarding_file(self) -> None:
        # Завершение первого включения идёт отдельным play: там роли DNS не видны
        # значения других ролей, поэтому вся роль повторно не выполняется.
        tasks = yaml.safe_load(
            (ROOT / "roles" / "entry_dns" / "tasks" / "via_exit_switch.yml").read_text(encoding="utf-8")
        )
        text = yaml.safe_dump(tasks, allow_unicode=True)
        self.assertIn("90-awg-dot.conf.j2", text)
        self.assertNotIn("dnsmasq", text)
        site = (ROOT / "playbooks" / "site.yml").read_text(encoding="utf-8")
        self.assertIn("tasks_from: via_exit_switch", site)
        # Перевод идёт после play EXIT и до шифрования секретов и фиксации сумм.
        self.assertLess(site.index("- name: Настройка EXIT сервера"), site.index("tasks_from: via_exit_switch"))
        self.assertLess(
            site.index("tasks_from: via_exit_switch"),
            site.index("- name: Фиксация контрольных сумм управляемой конфигурации"),
        )


class ReportDnsTests(unittest.TestCase):
    def rows(self, config: str, **variables) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "90-awg-dot.conf").write_text(config, encoding="utf-8")
            script = directory / "kalimera-report"
            script.write_text(
                render(
                    REPORT,
                    awg_node_role="entry",
                    entry_client_listen_address="10.66.0.1",
                    entry_unbound_config_dir=str(directory),
                    entry_ru_proxy_manual_disabled_flag=str(directory / "no-manual"),
                    entry_ru_proxy_disabled_flag=str(directory / "no-failopen"),
                    **variables,
                ),
                encoding="utf-8",
            )
            body = (
                f"source {shlex.quote(str(script))}\n"
                "dns_probe() { printf '93.184.216.34 4\\n'; }\n"
                "check_dns\n"
            )
            result = subprocess.run([bash_path(), "-c", body], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def foreign(self, rows: list[str]) -> str:
        return next(line for line in rows if "example.com (не РФ)" in line)

    def test_route_of_foreign_names_is_named(self) -> None:
        rows = self.rows(VIA_EXIT_CONF, entry_dns_default_via_exit=True)
        self.assertIn(
            "маршрут: Unbound → резолвер EXIT внутри туннеля, с ENTRY наружу запрос не уходит",
            self.foreign(rows),
        )
        self.assertFalse([line for line in rows if "\tWARN\t" in line])
        rows = self.rows(BASE_CONF)
        self.assertIn("маршрут: Unbound → серверы DoT напрямую с ENTRY", self.foreign(rows))
        self.assertFalse([line for line in rows if "\tWARN\t" in line])

    def test_enabled_mode_that_does_not_act_is_a_warning(self) -> None:
        rows = self.rows(BASE_CONF, entry_dns_default_via_exit=True)
        self.assertIn("маршрут: Unbound → серверы DoT напрямую с ENTRY", self.foreign(rows))
        self.assertIn(
            row(
                "DNS",
                "WARN",
                "зарубежные имена: режим «через резолвер EXIT» включён, но не действует",
                "запросы идут с ENTRY на серверы DoT",
                "резолвер EXIT не ответил при deploy: awg-health --strict на EXIT, затем на ENTRY "
                "kalimera-deploy --resume",
            ).rstrip("\n"),
            rows,
        )


class OwnerCommandTests(unittest.TestCase):
    def test_dot_switch_refuses_to_bring_queries_back_to_entry(self) -> None:
        # dot-switch заменяет строки пересылки. В режиме "через EXIT" это вернуло бы
        # запросы на ENTRY, причём без TLS: строки forward-tls-upstream в файле нет.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = Path(f"{root}{DOT_CONF}")
            config.parent.mkdir(parents=True)
            config.write_text(VIA_EXIT_CONF, encoding="utf-8")
            program = root / "dot-switch"
            program.write_text(sandbox(without_root_check(dot_switch_text()), root), encoding="utf-8")
            for arguments in (("custom", "9.9.9.9", "dns.quad9.net"), ("reset",)):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        [bash_path(), str(program), *arguments],
                        capture_output=True, text=True, timeout=60, env={**os.environ},
                    )
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("резолвер EXIT внутри туннеля", result.stderr)
                    self.assertIn("kalimera-deploy --resume --disable-dns-via-exit", result.stderr)
            self.assertEqual(config.read_text(encoding="utf-8"), VIA_EXIT_CONF)

    def test_dns_status_names_the_mode(self) -> None:
        text = DNS_STATUS.read_text(encoding="utf-8")
        self.assertIn("Зарубежные имена: резолвер EXIT внутри туннеля", text)
        self.assertIn("Зарубежные имена: серверы DoT, запросы идут с ENTRY", text)
        self.assertIn("unbound-control list_forwards", text)


if __name__ == "__main__":
    unittest.main()

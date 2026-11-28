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
from test_standby_exit import PRIMARY, STANDBY, SelectorCase
from test_standby_exit import selector as path_selector
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
            selector.flush_dns_infra(self.cfg)
        which.assert_not_called()

    def test_both_resolvers_stay_whichever_path_carries_the_traffic(self) -> None:
        # Измерено: с резолверами обоих EXIT пропадание одного туннеля на 200 секунд
        # не оставило без ответа ни одного запроса - Unbound обходит его сам.
        self.cfg.dns_both_exits = True
        listing = ". IN forward 10.77.0.1 10.78.0.1\nexample.ru. IN forward 10.78.0.1 10.77.0.1\n"
        self.assertEqual(self.sync(listing, "primary"), [])
        self.assertEqual(self.sync(listing, "standby"), [])

    def test_forwarding_narrowed_to_one_resolver_gets_both_back(self) -> None:
        # Состояние прежней версии: пересылка смотрит в резолвер одного сервера.
        self.cfg.dns_both_exits = True
        listing = ". IN forward 10.77.0.1\nexample.ru. IN forward 10.77.0.1\n"
        self.assertEqual(
            self.sync(listing, "standby"),
            [
                ["forward", "10.78.0.1@53", "10.77.0.1@53"],
                ["forward_remove", "example.ru."],
                ["forward_add", "example.ru.", "10.78.0.1@53", "10.77.0.1@53"],
                ["flush_infra", "all"],
            ],
        )

    def test_both_resolvers_never_replace_dot_servers(self) -> None:
        self.cfg.dns_both_exits = True
        listing = ". IN forward 162.254.86.13@853#vno01.dnscry.pt\nru. IN forward 77.88.8.8@853#x\n"
        self.assertEqual(self.sync(listing, "primary"), [])

    def test_recovered_path_makes_unbound_forget_the_dead_resolver(self) -> None:
        calls: list[list[str]] = []
        with mock.patch.object(selector.shutil, "which", return_value="/usr/sbin/unbound-control"), \
                mock.patch.object(selector, "run_quiet", side_effect=lambda argv, **_: calls.append(argv) or 0):
            selector.flush_dns_infra(self.cfg)
        self.assertEqual(calls, [["/usr/sbin/unbound-control", "flush_infra", "all"]])


class RecoveryFlushTests(SelectorCase):
    """Когда переключатель путей сбрасывает в Unbound отметку о недоступности.

    Измерено на Unbound 1.19.2: резолвер, не отвечавший около трёх минут, Unbound
    считает неработающим и после возвращения связи к нему не обращается -
    зарубежные имена не разрешались бы до часа.
    """

    def setUp(self) -> None:
        super().setUp()
        self.primary, self.standby = PRIMARY, STANDBY
        self.infra_flushes = 0

        def flush(_cfg) -> None:
            self.infra_flushes += 1

        patcher = mock.patch.object(path_selector, "flush_dns_infra", flush)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.now = 6000

    def tick(self, primary: int = 3, standby: int = 3) -> dict:
        self.reach[self.primary] = primary
        self.reach[self.standby] = standby
        state = path_selector.tick(self.cfg, self.now)
        self.now += 10
        return state

    def test_healthy_paths_never_flush(self) -> None:
        for _ in range(30):
            self.tick()
        self.assertEqual(self.infra_flushes, 0)

    def test_active_path_that_answers_again_flushes_once(self) -> None:
        self.tick()
        # Оба пути недоступны: уходить некуда, трафик и пересылка DNS остаются на основном.
        for _ in range(25):
            state = self.tick(primary=0, standby=0)
        self.assertEqual(state["active"], self.primary)
        self.assertEqual(self.infra_flushes, 0, "пока путь не отвечает, сбрасывать нечего")
        self.tick()
        self.assertEqual(self.infra_flushes, 1)
        for _ in range(5):
            self.tick()
        self.assertEqual(self.infra_flushes, 1, "один раз на восстановление")

    def test_short_blip_of_the_active_path_flushes_too(self) -> None:
        # Отметка в Unbound копится и за короткие сбои: сброс дёшев.
        self.tick()
        self.tick(primary=0)
        self.assertEqual(self.infra_flushes, 0)
        self.tick()
        self.assertEqual(self.infra_flushes, 1)

    def test_idle_path_does_not_flush(self) -> None:
        self.tick()
        for _ in range(5):
            self.tick(standby=0)
        self.tick()
        self.assertEqual(self.infra_flushes, 0, "через резервный путь имена сейчас не разрешаются")

    def test_path_switch_is_left_to_the_forwarding_change(self) -> None:
        # При переходе на другой путь пересылку меняет sync_dns, и он же сбрасывает
        # отметки: отдельный сброс не нужен.
        self.tick()
        for _ in range(3):
            state = self.tick(primary=0)
        self.assertEqual(state["active"], self.standby)
        self.assertEqual(self.dns[-1], self.standby)
        self.assertEqual(self.infra_flushes, 0)


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

    def test_standby_exit_adds_its_resolver(self) -> None:
        mode = {"entry_dns_default_via_exit": True, "entry_dns_via_exit_effective": True}
        standby = {
            "entry_standby_exit_enabled": True,
            "entry_standby_exit_peer_tunnel_address": "10.78.0.1",
        }
        zone = self.forward_zone(**mode, **standby)
        self.assertEqual(
            [line.strip() for line in zone.splitlines() if line.strip().startswith("forward-addr:")],
            ["forward-addr: 10.77.0.1@53", "forward-addr: 10.78.0.1@53"],
        )
        self.assertNotIn("forward-tls-upstream", zone)
        # Без резервного EXIT и при явном отказе резолвер один.
        for variables in (
            {},
            {"entry_standby_exit_enabled": False, "entry_standby_exit_peer_tunnel_address": "10.78.0.1"},
            dict(standby, entry_dns_via_exit_both=False),
        ):
            zone = self.forward_zone(**mode, **variables)
            self.assertEqual(zone.count("forward-addr:"), 1, variables)
            self.assertIn("    forward-addr: 10.77.0.1@53\n", zone)
        # Пока действуют серверы DoT, резолверы EXIT в файл не попадают.
        zone = self.forward_zone(entry_dns_default_via_exit=True, entry_dns_via_exit_effective=False, **standby)
        self.assertNotIn("10.78.0.1", zone)

    def test_selector_is_told_to_keep_both_resolvers(self) -> None:
        defaults = yaml.safe_load(
            (ROOT / "roles" / "entry_dns" / "defaults" / "main.yml").read_text(encoding="utf-8")
        )
        self.assertIs(defaults["entry_dns_via_exit_both"], True)
        template = (ROOT / "roles" / "entry_exit_path" / "templates" / "config.json.j2").read_text(encoding="utf-8")
        self.assertIn("'dns_both_exits': entry_dns_via_exit_both | default(true) | bool,", template)
        # Исключения se-domain берут адреса из того же файла: оба резолвера попадают и туда.
        sync = (ROOT / "roles" / "entry_dns" / "templates" / "awg-ru-dns-sync.sh.j2").read_text(encoding="utf-8")
        self.assertIn("forward-addr:[[:space:]]*([^[:space:]]+)", sync)

    def server_section(self, **variables) -> str:
        values = {
            "entry_dns_default_port": 5353,
            "awg3_peer_tunnel_address": "10.77.0.1",
            "entry_dns_dot_upstreams_resolved": [
                {"address": "162.254.86.13", "tls_name": "vno01.dnscry.pt"},
            ],
            **variables,
        }
        text = render(DOT_TEMPLATE, **values)
        return text[:text.index("forward-zone:")]

    def test_resolver_that_was_unreachable_is_tried_again(self) -> None:
        # Измерено на Unbound 1.19.2 (тот же, что на серверах): сервер пересылки,
        # не отвечавший 200 секунд, Unbound считал неработающим, и за 150 секунд
        # после возвращения связи не разрешилось ни одно имя. С проверкой таких
        # серверов ответы возвращались через 85 секунд, с коротким сроком жизни
        # сведений о сервере - через 20.
        via_exit = self.server_section(entry_dns_default_via_exit=True, entry_dns_via_exit_effective=True)
        self.assertIn("    infra-keep-probing: yes\n", via_exit)
        self.assertIn("    infra-host-ttl: 60\n", via_exit)
        self.assertEqual(via_exit.count("infra-host-ttl:"), 1)
        # Серверы DoT: срок прежний (он выбран ради скорости), проверка включена.
        dot = self.server_section()
        self.assertIn("    infra-keep-probing: yes\n", dot)
        self.assertIn("    infra-host-ttl: 3600\n", dot)
        self.assertEqual(dot.count("infra-host-ttl:"), 1)
        # Первое включение режима: ENTRY ещё на серверах DoT.
        pending = self.server_section(entry_dns_default_via_exit=True, entry_dns_via_exit_effective=False)
        self.assertIn("    infra-host-ttl: 3600\n", pending)

    def test_recovery_settings_come_from_the_role(self) -> None:
        defaults = yaml.safe_load(
            (ROOT / "roles" / "entry_dns" / "defaults" / "main.yml").read_text(encoding="utf-8")
        )
        self.assertIs(defaults["entry_dns_infra_keep_probing"], True)
        self.assertEqual(defaults["entry_dns_via_exit_infra_host_ttl"], 60)
        self.assertEqual(defaults["entry_dns_infra_host_ttl"], 3600)
        custom = self.server_section(
            entry_dns_default_via_exit=True, entry_dns_via_exit_effective=True,
            entry_dns_via_exit_infra_host_ttl=120, entry_dns_infra_keep_probing=False,
        )
        self.assertIn("    infra-host-ttl: 120\n", custom)
        self.assertIn("    infra-keep-probing: no\n", custom)

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

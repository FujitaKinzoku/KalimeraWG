"""RU-прокси для выбранных адресов и включение функций на работающем каскаде.

Шаблоны рендерятся Jinja2 и запускаются в bash с подставными ip, iptables, ipset и
systemctl: настоящая сеть и root не нужны. Проверяется, какие адреса получают метку
прокси в каждой области, как списки proxy-domain и proxy-address попадают в dnsmasq,
ipset и конфигурацию VLESS, и что установщик меняет только inventory и Vault.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import jinja2
import yaml
from ansible.parsing.vault import VaultLib, VaultSecret

ROOT = Path(__file__).parents[1]
ROUTING = ROOT / "roles" / "entry_routing" / "templates" / "awg-entry-routing.sh.j2"
DOMAIN_ADMIN = ROOT / "roles" / "operations" / "templates" / "domain-admin.sh.j2"
PROXY_ADDRESS = ROOT / "roles" / "operations" / "templates" / "proxy-address.sh.j2"
DNS_POLICY = ROOT / "roles" / "operations" / "templates" / "awg-dns-policy.sh.j2"
FRONT_BACKEND = ROOT / "roles" / "front_backend" / "templates" / "front-backend.json.j2"
HEALTH = ROOT / "roles" / "health" / "templates" / "awg-health.sh.j2"
REPORT = ROOT / "roles" / "cascade_check" / "templates" / "kalimera-report.sh.j2"
GATEWAY = ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
SHELL_TOOLS = ROOT / "roles" / "terminal" / "templates" / "kalimera-shell-tools.sh.j2"
OPERATIONS_TASKS = ROOT / "roles" / "operations" / "tasks" / "main.yml"
SING_BOX_TASKS = ROOT / "roles" / "sing_box" / "tasks" / "main.yml"
ROUTING_DEFAULTS = ROOT / "roles" / "entry_routing" / "defaults" / "main.yml"
DNS_DEFAULTS = ROOT / "roles" / "entry_dns" / "defaults" / "main.yml"
DNS_SYNC = ROOT / "roles" / "entry_dns" / "templates" / "awg-ru-dns-sync.sh.j2"

MODULE_PATH = ROOT / "scripts" / "lib" / "interactive_deploy.py"
SPEC = importlib.util.spec_from_file_location("interactive_deploy_selective", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

MARK = "-j MARK --set-xmark 0x2/0xffffffff"
# Отказ UDP к адресам из списков; "-m set" отличает его от правила для порта 853.
UDP_REJECT = "iptables -w 10 -I FORWARD 1 -i awg0 -s 10.66.0.0/24 -p udp -m set"

FAKE_TOOL = """#!/usr/bin/env bash
# Подставная команда: записывает вызов и отвечает по файлам-переключателям.
state={state}
name="$(basename "$0")"
printf '%s %s\\n' "$name" "$*" >>"$state/calls.log"
case "$name" in
    ip)
        if [[ "$1" == link && "$2" == show ]]; then
            [[ ! -e "$state/missing-$3" ]] || exit 1
        elif [[ "$1" == -o && "$2" == link ]]; then
            [[ ! -e "$state/missing-$5" ]] || exit 1
            echo "7: $5: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380"
        elif [[ "$1" == rule && "$2" == del ]]; then
            exit 1
        fi
        ;;
    iptables)
        # Правил ещё нет: проверка -C всегда отвечает "не найдено".
        [[ " $* " != *" -C "* ]] || exit 1
        ;;
    iptables-restore) cat >"$state/restore.txt" ;;
    ipset)
        [[ "$1" != restore ]] || cat >>"$state/ipset-restore.txt"
        ;;
    systemctl)
        if [[ "$1" == is-active ]]; then
            [[ -e "$state/proxy-active" ]] || exit 3
        fi
        ;;
    awg-entry-routing)
        [[ ! -e "$state/routing-fails" ]] || exit 1
        ;;
esac
"""


def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    env.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    env.filters["to_json"] = json.dumps
    return env


def render(template: Path, **variables) -> str:
    return environment().from_string(template.read_text(encoding="utf-8")).render(**variables)


def bash_path() -> str:
    executable = shutil.which("bash")
    if executable is None or os.name == "nt":
        raise unittest.SkipTest("нужен bash на Linux")
    return executable


class ShellCase(unittest.TestCase):
    """Временный каталог с подставными командами."""

    tools: tuple[str, ...] = ()

    def setUp(self) -> None:
        self.bash = bash_path()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.fakebin = self.dir / "bin"
        self.run_dir = self.dir / "run"
        self.policy = self.dir / "policy"
        for directory in (self.fakebin, self.run_dir, self.policy):
            directory.mkdir()
        self.calls = self.dir / "calls.log"
        self.calls.write_text("", encoding="utf-8")
        for name in self.tools:
            tool = self.fakebin / name
            tool.write_text(FAKE_TOOL.format(state=shlex.quote(str(self.dir))), encoding="utf-8")
            tool.chmod(0o755)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def flag(self, name: str, present: bool = True) -> None:
        path = self.dir / name
        if present:
            path.write_text("", encoding="utf-8")
        else:
            path.unlink(missing_ok=True)

    def install(self, name: str, text: str) -> Path:
        """Записать программу: проверка root снимается, /run ведёт во временный каталог."""
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

    def call_lines(self, prefix: str) -> list[str]:
        return [
            line
            for line in self.calls.read_text(encoding="utf-8").splitlines()
            if line.startswith(prefix)
        ]


class RoutingChainTests(ShellCase):
    tools = ("ip", "iptables", "iptables-restore", "ipset")

    def routing(self, *, enabled: bool, scope: str = "all", udp: str = "proxy") -> list[str]:
        ports = self.dir / "ru-direct-ports"
        ports.write_text("", encoding="utf-8")
        (self.dir / "proxy-udp.mode").write_text(udp + "\n", encoding="utf-8")
        script = self.install(
            "awg-entry-routing",
            render(
                ROUTING,
                entry_client_interface="awg0",
                entry_client_subnet="10.66.0.0/24",
                entry_client_listen_address="10.66.0.1",
                entry_exit_interface="awg3",
                entry_ru_proxy_interface="sb-ru",
                entry_wan_interface="eth0",
                entry_exit_mark="0x1",
                entry_exit_table=100,
                entry_exit_rule_priority=100,
                entry_ru_mark="0x2",
                entry_ru_table=200,
                entry_ru_rule_priority=110,
                entry_ru_direct_tcp_ports_file=str(ports),
                entry_ru_proxy_disabled_flag=str(self.dir / "proxy.disabled"),
                entry_ru_proxy_manual_disabled_flag=str(self.dir / "proxy.manual-off"),
                entry_ru_proxy_udp_mode_path=str(self.dir / "proxy-udp.mode"),
                entry_ru_zone_cache_path=str(self.dir / "ru.zone"),
                entry_ru_proxy_enabled=enabled,
                entry_ru_proxy_scope=scope,
                entry_ru_proxy_address_file=str(self.policy / "proxy-address"),
            ),
        )
        result = self.execute(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        return (self.dir / "restore.txt").read_text(encoding="utf-8").splitlines()

    @staticmethod
    def index(rules: list[str], fragment: str) -> int:
        matches = [i for i, rule in enumerate(rules) if fragment in rule]
        if not matches:
            raise AssertionError(f"правило не найдено: {fragment}")
        return matches[0]

    def test_without_proxy_the_lists_do_not_change_routing(self) -> None:
        # Без RU-прокси его TUN-интерфейса на сервере нет.
        self.flag("missing-sb-ru")
        rules = self.routing(enabled=False)
        self.assertFalse([rule for rule in rules if "force_proxy" in rule])
        self.assertFalse([rule for rule in rules if "0x2" in rule])
        self.assertIn("-A AWG_RU_PROXY -m set --match-set ru dst -j RETURN", rules)
        self.assertEqual(rules[-3], "-A AWG_RU_PROXY -j MARK --set-xmark 0x1/0xffffffff")

    def test_selected_scope_marks_only_the_proxy_lists(self) -> None:
        rules = self.routing(enabled=True, scope="selected")
        for set_name in ("force_proxy", "force_proxy_net"):
            self.assertIn(f"-A AWG_RU_PROXY -m set --match-set {set_name} dst {MARK}", rules)
        # Российские сети и ru-domain выходят напрямую с ENTRY: метки прокси у них нет.
        for set_name in ("force_ru", "ru"):
            self.assertNotIn(f"-A AWG_RU_PROXY -m set --match-set {set_name} dst {MARK}", rules)
            self.assertIn(f"-A AWG_RU_PROXY -m set --match-set {set_name} dst -j RETURN", rules)

    def test_all_scope_marks_russian_networks_and_the_proxy_lists(self) -> None:
        rules = self.routing(enabled=True, scope="all")
        for set_name in ("force_proxy", "force_proxy_net", "force_ru", "ru"):
            self.assertIn(f"-A AWG_RU_PROXY -m set --match-set {set_name} dst {MARK}", rules)

    def test_explicit_lists_keep_their_order(self) -> None:
        rules = self.routing(enabled=True, scope="selected")
        bank = self.index(rules, "--match-set force_entry_bank dst -j ACCEPT")
        se_domain = self.index(rules, "--match-set force_exit dst -j MARK")
        proxy = self.index(rules, f"--match-set force_proxy dst {MARK}")
        russian = self.index(rules, "--match-set ru dst -j RETURN")
        default = self.index(rules, "-A AWG_RU_PROXY -j MARK --set-xmark 0x1")
        self.assertLess(bank, se_domain)
        self.assertLess(se_domain, proxy)
        self.assertLess(proxy, russian)
        self.assertLess(russian, default)

    def test_proxy_failure_sends_the_lists_directly_from_entry(self) -> None:
        for failure in ("missing-sb-ru", "proxy.disabled", "proxy.manual-off"):
            with self.subTest(failure=failure):
                self.flag(failure)
                rules = self.routing(enabled=True, scope="selected")
                self.flag(failure, False)
                self.assertFalse([rule for rule in rules if "0x2" in rule])
                self.assertIn("-A AWG_RU_PROXY -m set --match-set force_proxy dst -j RETURN", rules)
                self.assertFalse(self.call_lines(UDP_REJECT))
                self.calls.write_text("", encoding="utf-8")

    def test_udp_without_socks_support_is_rejected_not_leaked(self) -> None:
        rules = self.routing(enabled=True, scope="selected", udp="direct")
        udp = self.index(rules, "-p udp -m set --match-set force_proxy dst -j RETURN")
        mark = self.index(rules, f"--match-set force_proxy dst {MARK}")
        self.assertLess(udp, mark)
        rejects = self.call_lines(UDP_REJECT)
        self.assertEqual(len(rejects), 2)
        for set_name, line in zip(("force_proxy", "force_proxy_net"), rejects):
            self.assertIn(f"--match-set {set_name} dst -j REJECT --reject-with icmp-port-unreachable", line)
        # Российские сети в области selected идут напрямую без отдельного правила UDP.
        self.assertFalse([rule for rule in rules if "-p udp" in rule and "--match-set ru " in rule])

    def test_udp_through_a_capable_proxy_is_not_rejected(self) -> None:
        rules = self.routing(enabled=True, scope="selected", udp="proxy")
        self.assertFalse([rule for rule in rules if "-p udp" in rule])
        self.assertFalse(self.call_lines(UDP_REJECT))

    def test_all_scope_keeps_direct_udp_for_russian_networks(self) -> None:
        rules = self.routing(enabled=True, scope="all", udp="direct")
        self.assertIn("-A AWG_RU_PROXY -p udp -m set --match-set ru dst -j RETURN", rules)
        self.assertIn("-A AWG_RU_PROXY -p udp -m set --match-set force_ru dst -j RETURN", rules)

    def test_address_list_is_loaded_into_the_network_set(self) -> None:
        (self.policy / "proxy-address").write_text(
            "# комментарий\n203.0.113.7\n198.51.100.0/24\nне адрес\n203.0.113.9/33\n\n",
            encoding="utf-8",
        )
        self.routing(enabled=True, scope="selected")
        restored = (self.dir / "ipset-restore.txt").read_text(encoding="utf-8").splitlines()
        self.assertIn("flush force_proxy_net", restored)
        self.assertIn("add force_proxy_net 203.0.113.7", restored)
        self.assertIn("add force_proxy_net 198.51.100.0/24", restored)
        self.assertEqual(len([line for line in restored if line.startswith("add force_proxy_net")]), 2)

    def test_sets_exist_even_without_the_proxy(self) -> None:
        self.flag("missing-sb-ru")
        self.routing(enabled=False)
        created = self.call_lines("ipset create force_proxy")
        self.assertEqual(len(created), 2)
        self.assertIn("hash:ip", created[0])
        self.assertIn("hash:net", created[1])

    def test_rendered_script_passes_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("нужен shellcheck")
        self.routing(enabled=True, scope="selected")
        result = subprocess.run(
            [shellcheck, "--exclude=SC2317", str(self.dir / "awg-entry-routing")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ProxyDomainTests(ShellCase):
    tools = ("systemctl", "dnsmasq", "ipset")

    def domain_admin(self, *, enabled: bool, scope: str = "all") -> Path:
        self.dnsmasq = self.dir / "dnsmasq.d"
        self.dnsmasq.mkdir(exist_ok=True)
        text = render(
            DOMAIN_ADMIN,
            awg_domain_policy_dir=str(self.policy),
            entry_ru_proxy_disabled_flag=str(self.dir / "proxy.disabled"),
            entry_ru_proxy_manual_disabled_flag=str(self.dir / "proxy.manual-off"),
            entry_ru_proxy_enabled=enabled,
            entry_ru_proxy_scope=scope,
            sing_box_service_name="sing-box.service",
            entry_dns_default_port=5353,
            entry_dns_ru_port=5354,
            reality_fallback_enabled=False,
        ).replace("/etc/dnsmasq.d/", f"{self.dnsmasq}/")
        script = self.install("awg-domain-admin", text)
        for name in ("ru-domain", "se-domain", "entry-domain", "proxy-domain"):
            link = self.dir / name
            if not link.exists():
                link.symlink_to(script)
        return script

    def run_command(self, name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self.execute(self.dir / name, *arguments)

    def policy_file(self) -> str:
        return (self.dnsmasq / "63-awg-local-domain-policy.conf").read_text(encoding="utf-8")

    def test_proxy_domain_fills_the_proxy_set_and_uses_russian_doh(self) -> None:
        self.domain_admin(enabled=True, scope="selected")
        self.flag("proxy-active")
        result = self.run_command("proxy-domain", "add", "Kinopoisk.RU.")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kinopoisk.ru добавлен в proxy-domain.", result.stdout)
        text = self.policy_file()
        self.assertIn("ipset=/kinopoisk.ru/force_proxy\n", text)
        self.assertIn("server=/kinopoisk.ru/127.0.0.1#5354\n", text)

    def test_inactive_proxy_resolves_the_list_through_unbound(self) -> None:
        self.domain_admin(enabled=True, scope="selected")
        self.assertEqual(self.run_command("proxy-domain", "add", "kinopoisk.ru").returncode, 0)
        self.assertIn("server=/kinopoisk.ru/127.0.0.1#5353\n", self.policy_file())

    def test_selected_scope_keeps_ru_domain_on_unbound(self) -> None:
        self.domain_admin(enabled=True, scope="selected")
        self.flag("proxy-active")
        self.assertEqual(self.run_command("ru-domain", "add", "vk.com").returncode, 0)
        text = self.policy_file()
        self.assertIn("ipset=/vk.com/force_ru\n", text)
        self.assertIn("server=/vk.com/127.0.0.1#5353\n", text)
        self.assertNotIn("server=/vk.com/127.0.0.1#5354", text)

    def test_all_scope_keeps_ru_domain_on_russian_doh(self) -> None:
        self.domain_admin(enabled=True, scope="all")
        self.flag("proxy-active")
        self.assertEqual(self.run_command("ru-domain", "add", "vk.com").returncode, 0)
        self.assertIn("server=/vk.com/127.0.0.1#5354\n", self.policy_file())

    def test_domain_belongs_to_one_list_only(self) -> None:
        self.domain_admin(enabled=True, scope="selected")
        self.assertEqual(self.run_command("ru-domain", "add", "kinopoisk.ru").returncode, 0)
        self.assertEqual(self.run_command("proxy-domain", "add", "kinopoisk.ru").returncode, 0)
        self.assertEqual(self.run_command("ru-domain", "list").stdout, "")
        self.assertEqual(self.run_command("proxy-domain", "list").stdout, "kinopoisk.ru\n")
        text = self.policy_file()
        self.assertNotIn("force_ru", text)
        self.assertIn("ipset=/kinopoisk.ru/force_proxy\n", text)

    def test_removal_and_clear(self) -> None:
        self.domain_admin(enabled=True, scope="selected")
        self.run_command("proxy-domain", "add", "kinopoisk.ru")
        self.run_command("proxy-domain", "add", "okko.tv")
        result = self.run_command("proxy-domain", "del", "okko.tv")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("okko.tv", self.policy_file())
        self.assertEqual(self.run_command("proxy-domain", "clear").returncode, 0)
        self.assertNotIn("force_proxy", self.policy_file())

    def test_disabled_proxy_keeps_the_list_and_says_so(self) -> None:
        self.domain_admin(enabled=False)
        result = self.run_command("proxy-domain", "add", "kinopoisk.ru")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kalimera-deploy --resume --enable-ru-proxy", result.stdout)
        self.assertNotIn("DNS-запроса", result.stdout)
        self.assertEqual(self.run_command("proxy-domain", "list").stdout, "kinopoisk.ru\n")

    def flushed_sets(self) -> list[str]:
        """Наборы, очищенные с прошлого вызова; журнал вызовов обнуляется."""
        flushed = [line.split()[2] for line in self.call_lines("ipset flush ")]
        self.calls.write_text("", encoding="utf-8")
        return flushed

    def test_adding_a_name_keeps_the_address_sets(self) -> None:
        # Найдено на рабочем каскаде: любое изменение списков очищало все наборы, и
        # адрес graphql.kinopoisk.ru выпадал из force_proxy до нового DNS-запроса
        # устройства - до часа запросы шли мимо прокси.
        self.domain_admin(enabled=True, scope="selected")
        self.assertEqual(self.run_command("proxy-domain", "add", "kinopoisk.ru").returncode, 0)
        self.assertEqual(self.flushed_sets(), [])
        self.assertEqual(self.run_command("proxy-domain", "add", "okko.tv").returncode, 0)
        self.assertEqual(self.run_command("ru-domain", "add", "vk.com").returncode, 0)
        self.assertEqual(self.run_command("se-domain", "add", "nalog.ru").returncode, 0)
        self.assertEqual(self.flushed_sets(), [])

    def test_removal_flushes_only_the_set_that_lost_the_name(self) -> None:
        self.domain_admin(enabled=True, scope="selected")
        self.run_command("proxy-domain", "add", "kinopoisk.ru")
        self.run_command("se-domain", "add", "nalog.ru")
        self.run_command("ru-domain", "add", "vk.com")
        self.flushed_sets()
        self.assertEqual(self.run_command("se-domain", "del", "nalog.ru").returncode, 0)
        self.assertEqual(self.flushed_sets(), ["force_exit"])
        # Перенос имени в другой список: очищается только набор прежнего списка.
        self.assertEqual(self.run_command("proxy-domain", "add", "vk.com").returncode, 0)
        self.assertEqual(self.flushed_sets(), ["force_ru"])
        self.assertEqual(self.run_command("proxy-domain", "clear").returncode, 0)
        self.assertEqual(self.flushed_sets(), ["force_proxy"])

    def test_deferred_removal_is_flushed_when_the_policy_is_applied(self) -> None:
        self.domain_admin(enabled=True, scope="selected")
        self.run_command("se-domain", "add", "nalog.ru")
        self.flushed_sets()
        self.assertEqual(self.run_command("se-domain", "del", "nalog.ru", "--defer").returncode, 0)
        self.assertEqual(self.flushed_sets(), [])
        self.assertEqual(self.run_command("ru-domain", "sync").returncode, 0)
        self.assertEqual(self.flushed_sets(), ["force_exit"])

    def test_resolver_switch_keeps_the_address_sets(self) -> None:
        # Watchdog при отказе прокси меняет только резолвер имён: адреса остаются.
        self.domain_admin(enabled=True, scope="selected")
        self.flag("proxy-active")
        self.run_command("proxy-domain", "add", "kinopoisk.ru")
        self.flushed_sets()
        self.flag("proxy-active", present=False)
        self.assertEqual(self.run_command("ru-domain", "sync").returncode, 0)
        self.assertIn("server=/kinopoisk.ru/127.0.0.1#5353\n", self.policy_file())
        self.assertEqual(self.flushed_sets(), [])

    def test_adding_with_a_working_proxy_explains_the_dns_delay(self) -> None:
        self.domain_admin(enabled=True, scope="selected")
        result = self.run_command("proxy-domain", "add", "kinopoisk.ru")
        self.assertIn("после нового DNS-запроса имени", result.stdout)
        self.assertNotIn("DNS-запроса", self.run_command("ru-domain", "add", "vk.com").stdout)
        self.assertNotIn("DNS-запроса", self.run_command("proxy-domain", "del", "kinopoisk.ru").stdout)

    def test_messages_name_the_domain(self) -> None:
        # Раньше циклы чтения списков затирали имя, и сообщение выходило без домена.
        self.domain_admin(enabled=False)
        added = self.run_command("ru-domain", "add", "vk.com")
        self.assertEqual(added.stdout, "vk.com добавлен в ru-domain.\n")
        removed = self.run_command("ru-domain", "del", "vk.com")
        self.assertEqual(removed.stdout, "vk.com удалён из ru-domain.\n")

    def test_invalid_domain_is_rejected(self) -> None:
        self.domain_admin(enabled=True, scope="selected")
        result = self.run_command("proxy-domain", "add", "не домен")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.run_command("proxy-domain", "list").stdout, "")

    def test_vless_rule_set_is_written_from_the_same_list(self) -> None:
        text = DOMAIN_ADMIN.read_text(encoding="utf-8")
        block = text[text.index("readonly REALITY_PROXY_RULE_SET="):text.index("{% endif %}", text.index("readonly REALITY_PROXY_RULE_SET="))]
        self.assertIn('"$DIR/proxy-domain"', block)
        self.assertIn('{"domain_suffix": $domains}', block)
        self.assertIn("reality_fallback_proxy_rule_set_path", block)

    def test_rendered_script_passes_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("нужен shellcheck")
        script = self.domain_admin(enabled=True, scope="selected")
        result = subprocess.run(
            [shellcheck, "--exclude=SC2317", str(script)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ProxyAddressTests(ShellCase):
    tools = ("awg-entry-routing",)

    def proxy_address(self, *, enabled: bool = True, reality: bool = False) -> Path:
        self.rules = self.dir / "proxy-addresses.json"
        text = render(
            PROXY_ADDRESS,
            entry_ru_proxy_address_file=str(self.policy / "proxy-address"),
            entry_routing_script_path=str(self.fakebin / "awg-entry-routing"),
            entry_ru_proxy_enabled=enabled,
            reality_fallback_enabled=reality,
            reality_fallback_proxy_address_rule_set_path=str(self.rules),
        ).replace("/root/config-backups/", f"{self.dir}/backups/")
        return self.install("proxy-address", text)

    def listed(self, script: Path) -> list[str]:
        return self.execute(script, "list").stdout.splitlines()

    def test_addresses_and_networks_are_normalised(self) -> None:
        script = self.proxy_address()
        for value in ("203.0.113.7", "203.0.113.9/32", "198.51.100.0/24"):
            result = self.execute(script, "add", value)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.listed(script), ["198.51.100.0/24", "203.0.113.7", "203.0.113.9"])
        self.assertEqual(len(self.call_lines("awg-entry-routing apply")), 3)

    def test_wrong_values_are_rejected(self) -> None:
        script = self.proxy_address()
        for value in ("kinopoisk.ru", "203.0.113.7/24", "0.0.0.0/0", "300.1.1.1", "2001:db8::1"):
            with self.subTest(value=value):
                result = self.execute(script, "add", value)
                self.assertEqual(result.returncode, 2)
        self.assertEqual(self.listed(script), [])
        self.assertFalse(self.call_lines("awg-entry-routing"))

    def test_repeat_is_reported_without_reapplying(self) -> None:
        script = self.proxy_address()
        self.assertEqual(self.execute(script, "add", "203.0.113.7").returncode, 0)
        result = self.execute(script, "add", "203.0.113.7")
        self.assertEqual(result.returncode, 0)
        self.assertIn("уже соответствует запросу", result.stdout)
        self.assertEqual(len(self.call_lines("awg-entry-routing apply")), 1)

    def test_delete_and_clear(self) -> None:
        script = self.proxy_address()
        self.execute(script, "add", "203.0.113.7")
        self.execute(script, "add", "198.51.100.0/24")
        self.assertEqual(self.execute(script, "del", "203.0.113.7").returncode, 0)
        self.assertEqual(self.listed(script), ["198.51.100.0/24"])
        self.assertEqual(self.execute(script, "clear").returncode, 0)
        self.assertEqual(self.listed(script), [])

    def test_routing_failure_restores_the_list(self) -> None:
        script = self.proxy_address()
        self.assertEqual(self.execute(script, "add", "203.0.113.7").returncode, 0)
        self.flag("routing-fails")
        result = self.execute(script, "add", "198.51.100.0/24")
        self.assertEqual(result.returncode, 1)
        self.assertIn("отменено из-за ошибки маршрутизации", result.stderr)
        self.flag("routing-fails", False)
        self.assertEqual(self.listed(script), ["203.0.113.7"])

    def test_sync_reapplies_an_unchanged_list(self) -> None:
        script = self.proxy_address()
        self.execute(script, "add", "203.0.113.7")
        result = self.execute(script, "sync")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.call_lines("awg-entry-routing apply")), 2)

    def test_disabled_proxy_keeps_the_list_and_says_so(self) -> None:
        script = self.proxy_address(enabled=False)
        result = self.execute(script, "add", "203.0.113.7")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kalimera-deploy --resume --enable-ru-proxy", result.stdout)

    def test_vless_rule_set_follows_the_list(self) -> None:
        if shutil.which("jq") is None:
            self.skipTest("нужен jq")
        script = self.proxy_address(reality=True)
        self.execute(script, "add", "203.0.113.7")
        self.execute(script, "add", "198.51.100.0/24")
        document = json.loads(self.rules.read_text(encoding="utf-8"))
        self.assertEqual(document, {"version": 1, "rules": [{"ip_cidr": ["198.51.100.0/24", "203.0.113.7"]}]})
        self.execute(script, "clear")
        self.assertEqual(json.loads(self.rules.read_text(encoding="utf-8")), {"version": 1, "rules": []})

    def test_rendered_script_passes_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("нужен shellcheck")
        for reality in (False, True):
            script = self.proxy_address(reality=reality)
            result = subprocess.run(
                [shellcheck, "--exclude=SC2317", str(script)], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class FrontBackendTests(unittest.TestCase):
    def backend(self, **variables) -> dict:
        values = {
            "reality_fallback_port": 8444,
            "reality_fallback_front_client_uuid": "00000000-0000-4000-8000-000000000000",
            "reality_fallback_dest": "yandex.ru",
            "reality_fallback_dest_port": 443,
            "reality_fallback_private_key": "fixture-private-key",
            "reality_fallback_short_id": "0123456789abcdef",
            "entry_exit_mark": "0x1",
            "entry_ru_mark": "0x2",
            "reality_fallback_ru_rule_set_path": "/rules/ru-domains.json",
            "reality_fallback_ru_zone_rule_set_path": "/rules/ru-zone.json",
            "reality_fallback_se_rule_set_path": "/rules/se-domains.json",
            "reality_fallback_proxy_rule_set_path": "/rules/proxy-domains.json",
            "reality_fallback_proxy_address_rule_set_path": "/rules/proxy-addresses.json",
            "entry_dns_default_port": 5353,
            "entry_client_listen_address": "10.66.0.1",
        }
        values.update(variables)
        return json.loads(render(FRONT_BACKEND, **values))

    @staticmethod
    def outbound(document: dict, tag: str) -> dict:
        return next(item for item in document["outbounds"] if item["tag"] == tag)

    @staticmethod
    def proxy_rule(document: dict) -> dict | None:
        for rule in document["route"]["rules"]:
            if "front-proxy-domains" in rule.get("rule_set", []):
                return rule
        return None

    def test_without_proxy_nothing_changes(self) -> None:
        document = self.backend(entry_ru_proxy_enabled=False)
        self.assertEqual([item["tag"] for item in document["outbounds"]], ["direct-exit", "direct-ru"])
        self.assertEqual(self.outbound(document, "direct-ru")["routing_mark"], "0x2")
        self.assertIsNone(self.proxy_rule(document))
        self.assertEqual(len(document["route"]["rule_set"]), 3)

    def test_missing_variables_mean_no_proxy(self) -> None:
        document = self.backend()
        self.assertIsNone(self.proxy_rule(document))

    def test_selected_scope_splits_russian_and_proxied_destinations(self) -> None:
        document = self.backend(entry_ru_proxy_enabled=True, entry_ru_proxy_scope="selected")
        # Российские назначения выходят напрямую с ENTRY: метки прокси у direct-ru нет.
        self.assertNotIn("routing_mark", self.outbound(document, "direct-ru"))
        proxy = self.outbound(document, "proxy-ru")
        self.assertEqual(proxy["routing_mark"], "0x2")
        self.assertEqual(proxy["domain_resolver"]["server"], "entry-split-dns")
        rule = self.proxy_rule(document)
        self.assertEqual(rule["outbound"], "proxy-ru")
        self.assertEqual(rule["rule_set"], ["front-proxy-domains", "front-proxy-addresses"])

    def test_all_scope_sends_the_lists_with_the_russian_traffic(self) -> None:
        document = self.backend(entry_ru_proxy_enabled=True, entry_ru_proxy_scope="all")
        self.assertEqual(self.outbound(document, "direct-ru")["routing_mark"], "0x2")
        self.assertEqual([item["tag"] for item in document["outbounds"]], ["direct-exit", "direct-ru"])
        self.assertEqual(self.proxy_rule(document)["outbound"], "direct-ru")

    def test_proxy_lists_stand_between_se_domain_and_russian_rules(self) -> None:
        for scope in ("all", "selected"):
            with self.subTest(scope=scope):
                document = self.backend(entry_ru_proxy_enabled=True, entry_ru_proxy_scope=scope)
                rules = document["route"]["rules"]
                self.assertEqual(rules[0]["action"], "sniff")
                self.assertEqual(rules[1]["action"], "hijack-dns")
                self.assertEqual(rules[2]["rule_set"], ["front-se-domains"])
                self.assertEqual(rules[3], self.proxy_rule(document))
                self.assertEqual(rules[4]["domain_suffix"], [".ru", ".xn--p1ai"])
                tags = [item["tag"] for item in document["route"]["rule_set"]]
                self.assertEqual(tags[-2:], ["front-proxy-domains", "front-proxy-addresses"])


class PolicyWiringTests(unittest.TestCase):
    def test_scope_defaults_to_all(self) -> None:
        defaults = yaml.safe_load(ROUTING_DEFAULTS.read_text(encoding="utf-8"))
        self.assertEqual(defaults["entry_ru_proxy_scope"], "all")
        tasks = (ROOT / "roles" / "entry_routing" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("entry_ru_proxy_scope in ['all', 'selected']", tasks)

    def test_russian_dot_is_active_without_proxy_and_in_selected_scope(self) -> None:
        expression = yaml.safe_load(DNS_DEFAULTS.read_text(encoding="utf-8"))["entry_dns_ru_dot_active"]
        cases = {
            (False, "all"): "True",
            (True, "all"): "False",
            (True, "selected"): "True",
            (False, "selected"): "True",
        }
        for (proxy, scope), expected in cases.items():
            rendered = environment().from_string(expression).render(
                entry_dns_ru_dot_enabled=True, entry_ru_proxy_enabled=proxy, entry_ru_proxy_scope=scope
            )
            self.assertEqual(rendered, expected, (proxy, scope))

    def test_dns_policy_never_sends_russian_zones_to_the_proxy_in_selected_scope(self) -> None:
        values = {
            "entry_dns_default_port": 5353,
            "entry_dns_ru_port": 5354,
            "entry_ru_proxy_disabled_flag": "/run/flag",
            "entry_ru_proxy_manual_disabled_flag": "/run/manual",
            "sing_box_service_name": "sing-box.service",
        }
        selected = render(DNS_POLICY, entry_ru_proxy_enabled=True, entry_ru_proxy_scope="selected", **values)
        self.assertIn("readonly proxy_scope=selected\n", selected)
        # Российский DoH для зон включается только в области all.
        self.assertIn('if [[ "$proxy_scope" == all ]] && systemctl is-active --quiet', selected)
        for scope_values in ({"entry_ru_proxy_enabled": True, "entry_ru_proxy_scope": "all"}, {}):
            self.assertIn("readonly proxy_scope=all\n", render(DNS_POLICY, **scope_values, **values))

    def test_zone_builder_counts_proxy_domain_only_with_the_proxy(self) -> None:
        text = DNS_SYNC.read_text(encoding="utf-8")
        self.assertIn("readonly proxy_lists={{ 'true' if (entry_ru_proxy_enabled | default(false) | bool) else 'false' }}", text)
        block = text[text.index('if [[ "$proxy_lists" == true ]]; then'):]
        self.assertIn("list_names proxy-domain", block[: block.index("mapfile -t se_names")])
        # Запись в каталог только для чтения (песочница watchdog) не считается ошибкой.
        self.assertEqual(text.count("    skip_if_read_only\n"), 2)

    def test_commands_are_installed_and_exposed(self) -> None:
        tasks = OPERATIONS_TASKS.read_text(encoding="utf-8")
        self.assertIn("- {name: proxy-domain}", tasks)
        self.assertIn("- {name: proxy-address}", tasks)
        self.assertIn("- {src: proxy-address.sh.j2, dest: proxy-address}", tasks)
        self.assertIn("loop: [ru-domain, se-domain, entry-domain, proxy-domain]", tasks)
        self.assertIn("argv: [/usr/local/sbin/proxy-address, sync]", tasks)
        gateway = GATEWAY.read_text(encoding="utf-8")
        self.assertIn("|entry-domain|proxy-domain|proxy-address|ru-proxy|", gateway)
        tools = SHELL_TOOLS.read_text(encoding="utf-8")
        self.assertIn('function proxy-domain { _kalimera_admin proxy-domain "$@"; }', tools)
        self.assertIn('function proxy-address { _kalimera_admin proxy-address "$@"; }', tools)

    def test_gateway_allows_the_feature_switches_only_with_resume(self) -> None:
        gateway = GATEWAY.read_text(encoding="utf-8")
        for flag in ("--enable-ru-proxy", "--disable-ru-proxy", "--enable-telegram", "--disable-telegram"):
            self.assertIn(f"'--resume {flag}'", gateway)
            self.assertNotIn(f"|'{flag}'", gateway)

    def test_rule_set_stubs_exist_before_the_backend_starts(self) -> None:
        tasks = SING_BOX_TASKS.read_text(encoding="utf-8")
        self.assertIn('- "{{ reality_fallback_proxy_rule_set_path }}"', tasks)
        self.assertIn('- "{{ reality_fallback_proxy_address_rule_set_path }}"', tasks)
        self.assertIn("entry_ru_proxy_scope | default('all') == 'selected'", tasks)

    def test_health_checks_follow_the_scope(self) -> None:
        text = HEALTH.read_text(encoding="utf-8")
        self.assertIn("check 'ipset force_proxy' ipset list force_proxy", text)
        self.assertIn("check 'ipset force_proxy_net' ipset list force_proxy_net", text)
        self.assertIn(
            "check 'списки proxy-domain и proxy-address направляются в RU-прокси' proxy_lists_marked", text
        )
        selected = text[text.index("{% if (entry_ru_proxy_scope | default('all')) == 'selected' %}"):]
        selected = selected[: selected.index("{% endif %}")]
        self.assertIn("ru_networks_bypass_proxy", selected.split("{% else %}")[0])
        self.assertIn("udp_ru_bypass_absent", selected.split("{% else %}")[1])


class HealthFunctionTests(ShellCase):
    tools = ("iptables",)

    def verdict(self, function: str, rules: str, *arguments: str) -> str:
        text = HEALTH.read_text(encoding="utf-8")
        start = text.index(f"{function}() {{")
        source = text[start:text.index("\n}\n", start) + 3]
        tool = self.fakebin / "iptables"
        tool.write_text(
            "#!/usr/bin/env bash\n"
            f"rules={shlex.quote(str(self.dir / 'rules.txt'))}\n"
            'if [[ " $* " == *" -S "* ]]; then cat "$rules"; exit 0; fi\n'
            "# -C: правило есть, если оно дословно записано в файле правил.\n"
            'all="$*"\n'
            'wanted="${all#*-C }"\n'
            'grep -Fxq -- "-A $wanted" "$rules"\n',
            encoding="utf-8",
        )
        tool.chmod(0o755)
        (self.dir / "rules.txt").write_text(rules, encoding="utf-8")
        body = (
            "set -Eeuo pipefail\n" + source + f"\nif {function} {' '.join(map(shlex.quote, arguments))}; "
            "then echo PASS; else echo FAIL; fi\n"
        )
        env = {**os.environ, "PATH": f"{self.fakebin}{os.pathsep}{os.environ['PATH']}"}
        result = subprocess.run([self.bash, "-c", body], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_russian_networks_must_not_be_marked_in_selected_scope(self) -> None:
        direct = (
            f"-A AWG_RU_PROXY -m set --match-set force_proxy dst {MARK}\n"
            "-A AWG_RU_PROXY -m set --match-set ru dst -j RETURN\n"
        )
        self.assertEqual(self.verdict("ru_networks_bypass_proxy", direct), "PASS")
        marked = direct + f"-A AWG_RU_PROXY -m set --match-set ru dst {MARK}\n"
        self.assertEqual(self.verdict("ru_networks_bypass_proxy", marked), "FAIL")

    def test_both_proxy_sets_must_be_marked(self) -> None:
        both = "".join(
            f"-A AWG_RU_PROXY -m set --match-set {name} dst {MARK}\n" for name in ("force_proxy", "force_proxy_net")
        )
        self.assertEqual(self.verdict("proxy_lists_marked", both, "0x2"), "PASS")
        only_one = f"-A AWG_RU_PROXY -m set --match-set force_proxy dst {MARK}\n"
        self.assertEqual(self.verdict("proxy_lists_marked", only_one, "0x2"), "FAIL")


class ReportTests(unittest.TestCase):
    def rows(self, body: str, **variables) -> list[str]:
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
            result = subprocess.run(
                [bash_path(), "-c", f"source {shlex.quote(str(script))}\n" + body],
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def test_selected_scope_names_what_goes_through_the_proxy(self) -> None:
        rows = self.rows(
            "systemctl() { return 0; }\ncheck_ru_proxy\n",
            entry_ru_proxy_enabled=True,
            entry_ru_proxy_scope="selected",
        )
        self.assertIn("активен: трафик к выбранным доменам и адресам идёт через SOCKS5/TUN", rows[0])

    def test_all_scope_keeps_the_previous_text(self) -> None:
        rows = self.rows(
            "systemctl() { return 0; }\ncheck_ru_proxy\n",
            entry_ru_proxy_enabled=True,
        )
        self.assertIn("активен: РФ-трафик клиентов идёт через SOCKS5/TUN", rows[0])

    def test_selected_scope_reports_russian_dns_through_dot(self) -> None:
        rows = self.rows(
            "dns_probe() { printf '77.88.55.88 4\\n'; }\nru_state=active\ncheck_dns\n",
            entry_ru_proxy_enabled=True,
            entry_ru_proxy_scope="selected",
            entry_dns_ru_dot_active=True,
        )
        self.assertIn("российский DoT напрямую с ENTRY (через RU-прокси идут только выбранные адреса)", rows[0])
        # Прямая проверка российского DoH остаётся: через него разрешаются имена proxy-domain.
        self.assertTrue(any("DNS: yandex.ru напрямую через RU DoH" in row for row in rows))


class InstallerCase(unittest.TestCase):
    """Production inventory и Vault во временном каталоге."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.production = self.root / "production"
        self.entry_path = self.production / "group_vars" / "entry.yml"
        self.all_path = self.production / "group_vars" / "all" / "main.yml"
        self.vault_path = self.production / "group_vars" / "all" / "vault.yml"
        self.entry_path.parent.mkdir(parents=True)
        self.all_path.parent.mkdir(parents=True)
        self.entry_path.write_text(
            "entry_ru_proxy_enabled: false\n"
            "entry_proxy_server: 127.0.0.1\n"
            "entry_proxy_port: 1080\n"
            "entry_awg0_obfuscation:\n  jc: 4\n",
            encoding="utf-8",
        )
        self.all_path.write_text("awg_telegram_monitor_enabled: false\n", encoding="utf-8")
        self.password_path = self.root / "vault.pass"
        self.password_path.write_bytes(b"fixture-vault-password\n")
        self.password_path.chmod(0o600)
        self.vault = VaultLib([("default", VaultSecret(b"fixture-vault-password"))])
        self.initial_vault = {
            "vault_awg_entry_private_key": "existing-private",
            "vault_entry_client_peers": [{"name": "phone", "public_key": "client-key"}],
        }
        self.vault_path.write_bytes(
            self.vault.encrypt(yaml.safe_dump(self.initial_vault, sort_keys=False).encode())
        )
        self.vault_path.chmod(0o600)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def entry(self) -> dict:
        return yaml.safe_load(self.entry_path.read_text(encoding="utf-8"))

    def all_vars(self) -> dict:
        return yaml.safe_load(self.all_path.read_text(encoding="utf-8"))

    def secrets(self) -> dict:
        return yaml.safe_load(self.vault.decrypt(self.vault_path.read_bytes()))

    def enable_proxy(self, answers: list[str], hidden: list[str], probe: str | None = "198.51.100.20", confirm: bool = True) -> bool:
        prompts = iter(answers)
        hidden_answers = iter(hidden)
        with (
            mock.patch.object(MODULE, "prompt", side_effect=lambda *_args, **_kwargs: next(prompts)),
            mock.patch.object(MODULE, "prompt_port", return_value=1337),
            mock.patch.object(MODULE, "prompt_bool", return_value=confirm),
            mock.patch.object(MODULE.getpass, "getpass", side_effect=lambda *_: next(hidden_answers)),
            mock.patch.object(MODULE, "probe_socks5_proxy", return_value=probe),
            mock.patch("builtins.print"),
        ):
            return MODULE.enable_ru_proxy(self.production, self.password_path)


class EnableProxyTests(InstallerCase):
    def test_enabling_changes_only_the_proxy_settings(self) -> None:
        # Ответы: адрес, ожидаемый внешний адрес, область (1 - выбранные адреса).
        self.assertTrue(self.enable_proxy(["proxy.example.net", "", "1"], ["login", "secret"]))
        entry = self.entry()
        self.assertIs(entry["entry_ru_proxy_enabled"], True)
        self.assertEqual(entry["entry_proxy_server"], "proxy.example.net")
        self.assertEqual(entry["entry_proxy_port"], 1337)
        self.assertEqual(entry["entry_ru_proxy_expected_ip"], "")
        self.assertEqual(entry["entry_ru_proxy_scope"], "selected")
        # Профиль обфускации и ключи клиентов не тронуты: конфиги клиентов остаются действительными.
        self.assertEqual(entry["entry_awg0_obfuscation"], {"jc": 4})
        secrets_document = self.secrets()
        self.assertEqual(secrets_document["vault_proxy_username"], "login")
        self.assertEqual(secrets_document["vault_proxy_password"], "secret")
        for key, value in self.initial_vault.items():
            self.assertEqual(secrets_document[key], value)
        self.assertEqual(self.vault_path.stat().st_mode & 0o777, 0o600)

    def test_scope_all_is_recorded(self) -> None:
        self.assertTrue(self.enable_proxy(["proxy.example.net", "198.51.100.20", "2"], ["", ""]))
        entry = self.entry()
        self.assertEqual(entry["entry_ru_proxy_scope"], "all")
        self.assertEqual(entry["entry_ru_proxy_expected_ip"], "198.51.100.20")

    def test_repeat_with_the_same_answers_changes_nothing(self) -> None:
        self.enable_proxy(["proxy.example.net", "", "1"], ["login", "secret"])
        before = (self.entry_path.read_bytes(), self.vault_path.read_bytes())
        self.assertFalse(self.enable_proxy(["proxy.example.net", "", "1"], ["login", "secret"]))
        self.assertEqual((self.entry_path.read_bytes(), self.vault_path.read_bytes()), before)

    def test_invalid_input_stops_before_any_change(self) -> None:
        before = (self.entry_path.read_bytes(), self.vault_path.read_bytes())
        cases = (
            (["bad host!", "", "1"], ["", ""]),
            (["proxy.example.net", "", "1"], ["login", ""]),
            (["proxy.example.net", "не адрес", "1"], ["", ""]),
            (["proxy.example.net", "", "3"], ["", ""]),
        )
        for answers, hidden in cases:
            with self.subTest(answers=answers, hidden=hidden), self.assertRaises(SystemExit):
                self.enable_proxy(answers, hidden)
            self.assertEqual((self.entry_path.read_bytes(), self.vault_path.read_bytes()), before)

    def test_unreachable_proxy_needs_an_explicit_confirmation(self) -> None:
        before = self.entry_path.read_bytes()
        with self.assertRaises(SystemExit):
            self.enable_proxy(["proxy.example.net", "", "1"], ["", ""], probe=None, confirm=False)
        self.assertEqual(self.entry_path.read_bytes(), before)
        self.assertTrue(self.enable_proxy(["proxy.example.net", "", "1"], ["", ""], probe=None, confirm=True))
        self.assertIs(self.entry()["entry_ru_proxy_enabled"], True)

    def test_disabling_keeps_the_settings_for_later(self) -> None:
        self.enable_proxy(["proxy.example.net", "", "1"], ["login", "secret"])
        with mock.patch("builtins.print"):
            self.assertTrue(MODULE.disable_ru_proxy(self.production))
            self.assertFalse(MODULE.disable_ru_proxy(self.production))
        entry = self.entry()
        self.assertIs(entry["entry_ru_proxy_enabled"], False)
        self.assertEqual(entry["entry_proxy_server"], "proxy.example.net")
        self.assertEqual(entry["entry_ru_proxy_scope"], "selected")

    def test_probe_keeps_credentials_out_of_the_command_line(self) -> None:
        captured: dict[str, object] = {}

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["input"] = kwargs["input"]
            return subprocess.CompletedProcess(argv, 0, "198.51.100.20\n", "")

        with (
            mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/curl"),
            mock.patch.object(MODULE.subprocess, "run", side_effect=fake_run),
        ):
            address = MODULE.probe_socks5_proxy("proxy.example.net", 1337, "login", 'pa"ss')
        self.assertEqual(address, "198.51.100.20")
        self.assertEqual(captured["argv"], ["/usr/bin/curl", "--config", "-"])
        self.assertIn('proxy = "socks5h://proxy.example.net:1337"', captured["input"])
        self.assertIn('proxy-user = "login:pa\\"ss"', captured["input"])

    def test_probe_reports_failure_as_none(self) -> None:
        def fake_run(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 7, "", "connection refused")

        with (
            mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/curl"),
            mock.patch.object(MODULE.subprocess, "run", side_effect=fake_run),
        ):
            self.assertIsNone(MODULE.probe_socks5_proxy("proxy.example.net", 1337, "", ""))


class EnableTelegramTests(InstallerCase):
    TOKEN = "123456789:" + "A" * 35

    def enable(self) -> bool:
        with (
            mock.patch.object(MODULE, "prompt_telegram_credentials", return_value=(self.TOKEN, "-100123456")),
            mock.patch("builtins.print"),
        ):
            return MODULE.enable_telegram_monitor(self.production, self.password_path)

    def test_enabling_stores_the_bot_in_the_vault(self) -> None:
        self.assertTrue(self.enable())
        self.assertIs(self.all_vars()["awg_telegram_monitor_enabled"], True)
        secrets_document = self.secrets()
        self.assertEqual(secrets_document["vault_telegram_bot_token"], self.TOKEN)
        self.assertEqual(secrets_document["vault_telegram_chat_id"], "-100123456")
        for key, value in self.initial_vault.items():
            self.assertEqual(secrets_document[key], value)
        self.assertFalse(self.enable())

    def test_disabling_removes_the_token(self) -> None:
        self.enable()
        with mock.patch("builtins.print"):
            self.assertTrue(MODULE.disable_telegram_monitor(self.production, self.password_path))
            self.assertFalse(MODULE.disable_telegram_monitor(self.production, self.password_path))
        self.assertIs(self.all_vars()["awg_telegram_monitor_enabled"], False)
        secrets_document = self.secrets()
        self.assertNotIn("vault_telegram_bot_token", secrets_document)
        self.assertNotIn("vault_telegram_chat_id", secrets_document)
        self.assertEqual(secrets_document["vault_awg_entry_private_key"], "existing-private")

    def test_fresh_install_and_the_switch_share_one_prompt(self) -> None:
        text = MODULE_PATH.read_text(encoding="utf-8")
        self.assertEqual(text.count('"ЛИЧНЫЙ TELEGRAM-БОТ"'), 1)
        self.assertEqual(text.count("prompt_telegram_credentials()"), 3)


class DeployArgumentTests(unittest.TestCase):
    def error(self, *arguments: str) -> str:
        argv = ["interactive_deploy.py", "--repo-root", "/nonexistent", *arguments]
        stderr = mock.MagicMock()
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(sys, "stderr", stderr),
            self.assertRaises(SystemExit) as raised,
        ):
            MODULE.main()
        self.assertEqual(raised.exception.code, 2)
        return "".join(call.args[0] for call in stderr.write.call_args_list)

    def test_feature_switches_need_resume(self) -> None:
        for flag in ("--enable-ru-proxy", "--disable-ru-proxy", "--enable-telegram", "--disable-telegram"):
            self.assertIn(f"{flag} используется только вместе с --resume", self.error(flag))

    def test_opposite_switches_are_rejected(self) -> None:
        self.assertIn("нельзя указывать вместе", self.error("--resume", "--enable-ru-proxy", "--disable-ru-proxy"))
        self.assertIn("нельзя указывать вместе", self.error("--resume", "--enable-telegram", "--disable-telegram"))

    def test_feature_switches_do_not_mix_with_updates(self) -> None:
        self.assertIn(
            "нельзя объединять с обновлениями компонентов",
            self.error("--resume", "--enable-ru-proxy", "--update-xray"),
        )

    def test_switches_run_before_the_deploy(self) -> None:
        text = MODULE_PATH.read_text(encoding="utf-8")
        resume = text[text.index("        if args.enable_mobile:\n            enable_mobile_profile"):]
        deploy = resume.index('ansible(\n                    repo, hosts_path, vault_password, "playbooks/site.yml"')
        for call in (
            "enable_ru_proxy(production, vault_password)",
            "disable_ru_proxy(production)",
            "enable_telegram_monitor(production, vault_password)",
            "disable_telegram_monitor(production, vault_password)",
        ):
            self.assertLess(resume.index(call), deploy)
        # Клиентские конфиги пересоздаёт только обновление компонентов.
        self.assertNotIn("prepare_component_update", resume[: resume.index("update_saved_client_configs_cps")])


if __name__ == "__main__":
    unittest.main()

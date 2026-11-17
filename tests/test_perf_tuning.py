"""Быстродействие каскада: MSS на EXIT, sysctl сервера, кэш Unbound и прогрев.

Шаблоны рендерятся Jinja2 с подставными значениями, как в test_dns_upstreams.py.
Выражение MSS проверяется на значениях живого каскада: awg3 на EXIT имеет MTU 1368.
"""

from __future__ import annotations

import json
import shlex
import unittest
from pathlib import Path

import jinja2
import yaml

ROOT = Path(__file__).parents[1]
EXIT_DEFAULTS = ROOT / "roles" / "exit" / "defaults" / "main.yml"
EXIT_CONF = ROOT / "roles" / "exit" / "templates" / "awg0.conf.j2"
TRANSIT_SETUP = ROOT / "roles" / "awg3_transit" / "templates" / "transit-setup.sh.j2"
HEALTH = ROOT / "roles" / "health" / "templates" / "awg-health.sh.j2"
SYSCTL = ROOT / "roles" / "security" / "templates" / "sysctl.conf.j2"
UNBOUND = ROOT / "roles" / "entry_dns" / "templates" / "90-awg-dot.conf.j2"
ENTRY_DNS_DEFAULTS = ROOT / "roles" / "entry_dns" / "defaults" / "main.yml"
EXAMPLE_EXIT = ROOT / "inventory" / "example" / "group_vars" / "exit.yml"
FRONT_BACKEND = ROOT / "roles" / "front_backend" / "templates" / "front-backend.json.j2"
SET_MSS = "--set-mss {{ exit_tcp_mss_effective }}"

FRONT_BACKEND_VARS = {
    "reality_fallback_port": 8444,
    "reality_fallback_front_client_uuid": "00000000-0000-4000-8000-000000000000",
    "reality_fallback_dest": "example.com",
    "reality_fallback_dest_port": 443,
    "reality_fallback_private_key": "TEST-KEY",
    "reality_fallback_short_id": "0123456789abcdef",
    "reality_fallback_ru_rule_set_path": "/tmp/ru-domains.json",
    "reality_fallback_ru_zone_rule_set_path": "/tmp/ru-zone.json",
    "reality_fallback_se_rule_set_path": "/tmp/se-domains.json",
    "entry_exit_mark": "0x1",
    "entry_ru_mark": "0x2",
    "entry_dns_default_port": 5353,
    "entry_client_listen_address": "10.66.0.1",
}

UNBOUND_BASE = {
    "entry_dns_default_port": 5353,
    "entry_dns_dot_upstreams_resolved": [
        {"address": "185.95.218.43", "tls_name": "dns.digitale-gesellschaft.ch"},
    ],
}


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def render(template: Path, **variables) -> str:
    environment = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    return environment.from_string(template.read_text(encoding="utf-8")).render(**variables)


def compile_expression(text: str):
    environment = jinja2.Environment(undefined=jinja2.StrictUndefined)
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    body = text.strip()
    assert body.startswith("{{") and body.endswith("}}"), text
    return environment.compile_expression(body[2:-2].strip())


class ExitMssValueTests(unittest.TestCase):
    """Значение MSS = MTU интерфейса минус 40 байт, без фиксированного числа."""

    def mss(self, **inventory) -> int:
        expression = load_yaml(EXIT_DEFAULTS)["exit_tcp_mss_effective"]
        return int(compile_expression(expression)(**inventory))

    def test_fixed_value_is_no_longer_a_variable(self) -> None:
        self.assertNotIn("exit_tcp_mss", load_yaml(EXIT_DEFAULTS))

    def test_kernel_path_takes_shared_mtu_minus_forty(self) -> None:
        self.assertEqual(
            self.mss(awg3_transit_enabled=False, awg3_shared_effective_mtu=1368, exit_awg_mtu=1420),
            1328,
        )

    def test_kernel_path_falls_back_to_exit_mtu(self) -> None:
        self.assertEqual(self.mss(awg3_transit_enabled=False, exit_awg_mtu=1420), 1380)

    def test_transit_path_takes_its_own_interface_mtu(self) -> None:
        self.assertEqual(
            self.mss(
                awg3_transit_enabled=True,
                awg3_transit_effective_mtu=1290,
                awg3_shared_effective_mtu=1368,
                exit_awg_mtu=1420,
            ),
            1250,
        )

    def test_segment_with_headers_fits_the_interface(self) -> None:
        for mtu in (1280, 1368, 1420):
            with self.subTest(mtu=mtu):
                mss = self.mss(
                    awg3_transit_enabled=False,
                    awg3_shared_effective_mtu=mtu,
                    exit_awg_mtu=1420,
                )
                self.assertLessEqual(mss + 40, mtu)


class ExitMssRulesTests(unittest.TestCase):
    def test_kernel_config_sets_the_computed_mss_in_both_directions(self) -> None:
        text = EXIT_CONF.read_text(encoding="utf-8")
        self.assertIn(f"-o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS {SET_MSS}", text)
        self.assertIn(f"-i %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS {SET_MSS}", text)
        self.assertNotIn("clamp-mss-to-pmtu", text)

    def test_userspace_transit_uses_the_same_rule_in_both_directions(self) -> None:
        # Вверх: по одной строке для -o и -i, в каждой правило проверяется (-C) и
        # добавляется (-A), это 4 вхождения. Вниз: удаление (-D) для -o и -i, 2 вхождения.
        text = TRANSIT_SETUP.read_text(encoding="utf-8")
        self.assertNotIn("clamp-mss-to-pmtu", text)
        self.assertEqual(text.count(SET_MSS), 6)

    def test_health_expects_the_same_rule_for_both_engines(self) -> None:
        text = HEALTH.read_text(encoding="utf-8")
        self.assertIn(
            "check 'исходящий TCP MSS EXIT сервера' iptables -w 10 -t mangle -C FORWARD "
            "-o {{ exit_awg_interface | quote }} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS "
            + SET_MSS,
            text,
        )
        self.assertEqual(text.count(SET_MSS), 4)

    def test_no_fixed_mss_variable_is_left_in_roles_or_examples(self) -> None:
        paths = [path for path in (ROOT / "roles").rglob("*") if path.is_file()]
        paths.append(EXAMPLE_EXIT)
        for path in paths:
            if path.suffix not in {".j2", ".yml"}:
                continue
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=str(path)):
                self.assertNotIn("exit_tcp_mss }}", text)
                self.assertNotIn("exit_tcp_mss:", text)


class ServerTcpTests(unittest.TestCase):
    def test_server_tcp_uses_bbr_and_keeps_window_after_idle(self) -> None:
        text = SYSCTL.read_text(encoding="utf-8")
        self.assertIn("net.ipv4.tcp_congestion_control = bbr\n", text)
        self.assertIn("net.ipv4.tcp_slow_start_after_idle = 0\n", text)
        self.assertIn("net.ipv4.tcp_mtu_probing = 1\n", text)


class UnboundCacheTests(unittest.TestCase):
    def test_defaults_enable_larger_cache_prefetch_key_and_hour_long_serve_expired(self) -> None:
        defaults = load_yaml(ENTRY_DNS_DEFAULTS)
        self.assertEqual(defaults["entry_dns_msg_cache_size"], "32m")
        self.assertEqual(defaults["entry_dns_rrset_cache_size"], "64m")
        self.assertIs(defaults["entry_dns_prefetch_key"], True)
        self.assertEqual(defaults["entry_dns_serve_expired_ttl"], 3600)

    def test_template_fallback_matches_the_role_default(self) -> None:
        # Шаблон рендерится и без переменной (тесты, старые inventory): запасное
        # значение в нём обязано совпадать со значением роли.
        default = load_yaml(ENTRY_DNS_DEFAULTS)["entry_dns_serve_expired_ttl"]
        text = render(UNBOUND, **UNBOUND_BASE)
        self.assertIn(f"    serve-expired-ttl: {default}\n", text)

    def test_rendered_config_carries_the_defaults(self) -> None:
        defaults = load_yaml(ENTRY_DNS_DEFAULTS)
        text = render(
            UNBOUND,
            **UNBOUND_BASE,
            entry_dns_msg_cache_size=defaults["entry_dns_msg_cache_size"],
            entry_dns_rrset_cache_size=defaults["entry_dns_rrset_cache_size"],
            entry_dns_prefetch_key=defaults["entry_dns_prefetch_key"],
            entry_dns_serve_expired_ttl=defaults["entry_dns_serve_expired_ttl"],
        )
        self.assertIn("    msg-cache-size: 32m\n", text)
        self.assertIn("    rrset-cache-size: 64m\n", text)
        self.assertIn("    prefetch-key: yes\n", text)
        self.assertIn("    serve-expired: yes\n", text)
        self.assertIn("    serve-expired-ttl: 3600\n", text)
        # Без явного нуля Unbound может сначала ждать DoT-сервер и только потом
        # отдать устаревший ответ: тогда кэш не ускоряет повторный запрос.
        self.assertIn("    serve-expired-client-timeout: 0\n", text)

    def test_serve_expired_can_be_turned_off(self) -> None:
        text = render(
            UNBOUND,
            **UNBOUND_BASE,
            entry_dns_msg_cache_size="32m",
            entry_dns_rrset_cache_size="64m",
            entry_dns_prefetch_key=True,
            entry_dns_serve_expired_ttl=0,
        )
        self.assertNotIn("serve-expired", text)


class FrontBackendDnsTests(unittest.TestCase):
    """DNS клиентов VLESS отвечает резолвер ENTRY, а не резолвер из настроек клиента."""

    def config(self) -> dict:
        return json.loads(render(FRONT_BACKEND, **FRONT_BACKEND_VARS))

    def test_dns_is_hijacked_right_after_sniff(self) -> None:
        rules = self.config()["route"]["rules"]
        self.assertEqual(rules[0], {"inbound": ["front-reality-in"], "action": "sniff"})
        self.assertEqual(
            rules[1],
            {"inbound": ["front-reality-in"], "protocol": "dns", "action": "hijack-dns"},
        )

    def test_hijacked_queries_go_to_the_entry_resolver(self) -> None:
        dns = self.config()["dns"]
        self.assertEqual(
            dns["rules"],
            [{"inbound": ["front-reality-in"], "action": "route", "server": "entry-split-dns"}],
        )
        servers = {server["tag"]: server for server in dns["servers"]}
        self.assertEqual(servers["entry-split-dns"]["server"], "10.66.0.1")
        self.assertEqual(servers["entry-split-dns"]["server_port"], 53)
        self.assertEqual(dns["final"], "bootstrap-unbound")
        self.assertIs(dns["disable_cache"], True)

    def test_routing_rules_keep_their_order_after_the_hijack(self) -> None:
        rules = self.config()["route"]["rules"]
        self.assertEqual(len(rules), 5)
        self.assertEqual(rules[2]["rule_set"], ["front-se-domains"])
        self.assertEqual(rules[2]["outbound"], "direct-exit")
        self.assertEqual(rules[3]["domain_suffix"], [".ru", ".xn--p1ai"])
        self.assertEqual(rules[4]["rule_set"], ["front-ru-domains", "front-ru-zone"])
        self.assertEqual(rules[4]["outbound"], "direct-ru")


class WarmNamesTests(unittest.TestCase):
    def names(self) -> list:
        return load_yaml(ENTRY_DNS_DEFAULTS)["entry_dns_warm_names"]

    def test_names_without_a_records_and_the_video_apex_are_not_warmed(self) -> None:
        names = self.names()
        for name in ("cdninstagram.com", "ytimg.com", "googlevideo.com"):
            with self.subTest(name=name):
                self.assertNotIn(name, names)

    def test_hosts_that_clients_resolve_are_warmed(self) -> None:
        names = self.names()
        for name in ("www.youtube.com", "i.ytimg.com", "www.instagram.com", "graph.instagram.com"):
            with self.subTest(name=name):
                self.assertIn(name, names)

    def test_list_has_no_duplicates(self) -> None:
        names = self.names()
        self.assertEqual(len(names), len(set(names)))


if __name__ == "__main__":
    unittest.main()

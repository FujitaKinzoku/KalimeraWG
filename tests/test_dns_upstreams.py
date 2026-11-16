"""DNS ENTRY: cache-min-ttl и prefetch в Unbound, пары IP:TLS-имя в dot-switch.

Шаблон Unbound рендерится Jinja2 с подставными значениями. Команду dot-switch
в тестах не запустить: ей нужны root, systemd и работающий Unbound, поэтому
проверяется её текст, включая правила разбора аргументов.
"""

from __future__ import annotations

import shlex
import unittest
from pathlib import Path

import jinja2
import yaml

ROOT = Path(__file__).parents[1]
UNBOUND = ROOT / "roles" / "entry_dns" / "templates" / "90-awg-dot.conf.j2"
DOT_SWITCH = ROOT / "roles" / "operations" / "templates" / "dot-switch.sh.j2"
ENTRY_DEFAULTS = ROOT / "roles" / "entry_dns" / "defaults" / "main.yml"


def render(template: Path, **variables) -> str:
    environment = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    return environment.from_string(template.read_text(encoding="utf-8")).render(**variables)


class UnboundPrefetchTests(unittest.TestCase):
    base = {
        "entry_dns_default_port": 5353,
        "entry_dns_dot_upstreams_resolved": [
            {"address": "185.95.218.43", "tls_name": "dns.digitale-gesellschaft.ch"},
            {"address": "9.9.9.9", "tls_name": "dns.quad9.net"},
        ],
    }

    def test_prefetch_and_min_ttl_are_on_by_default(self) -> None:
        text = render(UNBOUND, **self.base)
        self.assertIn("    cache-min-ttl: 300\n", text)
        self.assertIn("    prefetch: yes\n", text)

    def test_prefetch_can_be_turned_off(self) -> None:
        text = render(UNBOUND, **self.base, entry_dns_prefetch=False)
        self.assertIn("    prefetch: no\n", text)

    def test_every_upstream_keeps_its_own_tls_name(self) -> None:
        text = render(UNBOUND, **self.base)
        self.assertIn("forward-addr: 185.95.218.43@853#dns.digitale-gesellschaft.ch", text)
        self.assertIn("forward-addr: 9.9.9.9@853#dns.quad9.net", text)


class DotSwitchPairsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOT_SWITCH.read_text(encoding="utf-8")

    def test_usage_mentions_the_pair_form(self) -> None:
        self.assertIn("custom IP:TLS_NAME[,IP:TLS_NAME...]", self.text)

    def test_two_arguments_are_pairs_and_three_keep_the_old_form(self) -> None:
        self.assertIn("if [[ $# -eq 2 ]]; then", self.text)
        self.assertIn('pairs="$2"', self.text)
        self.assertIn("elif [[ $# -eq 3 ]]; then", self.text)

    def test_pair_without_separator_is_rejected(self) -> None:
        self.assertIn('[[ "$pair" == *:* ]] ||', self.text)

    def test_pair_is_split_into_address_and_tls_name(self) -> None:
        self.assertIn('values+=("${pair%%:*}")', self.text)
        self.assertIn('tls_values+=("${pair#*:}")', self.text)


def compile_expression(text: str):
    environment = jinja2.Environment(undefined=jinja2.StrictUndefined)
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    body = text.strip()
    assert body.startswith("{{") and body.endswith("}}"), text
    return environment.compile_expression(body[2:-2].strip())


class DefaultDotResolutionTests(unittest.TestCase):
    """Какой список DoT действует, если в inventory Mullvad, пусто или свой список."""

    def setUp(self) -> None:
        self.defaults = yaml.safe_load(ENTRY_DEFAULTS.read_text(encoding="utf-8"))
        self.default_pair = self.defaults["entry_dns_default_dot_upstreams"]

    def resolve(self, **inventory) -> list:
        legacy = compile_expression(self.defaults["entry_dns_inventory_dot_legacy"])(**inventory)
        return compile_expression(self.defaults["entry_dns_dot_upstreams_resolved"])(
            **inventory,
            entry_dns_default_dot_upstreams=self.default_pair,
            entry_dns_inventory_dot_legacy=legacy,
        )

    def test_default_pair_is_the_dnscry_and_digitale_pair(self) -> None:
        self.assertEqual(
            self.default_pair,
            [
                {"address": "162.254.86.13", "tls_name": "vno01.dnscry.pt"},
                {"address": "185.95.218.43", "tls_name": "dns.digitale-gesellschaft.ch"},
            ],
        )

    def test_mullvad_inventory_gets_the_default_pair(self) -> None:
        mullvad = [{"address": "194.242.2.2", "tls_name": "dns.mullvad.net"}]
        self.assertEqual(self.resolve(entry_dot_upstreams=mullvad), self.default_pair)

    def test_missing_or_empty_list_gets_the_default_pair(self) -> None:
        self.assertEqual(self.resolve(), self.default_pair)
        self.assertEqual(self.resolve(entry_dot_upstreams=[]), self.default_pair)

    def test_custom_list_is_kept(self) -> None:
        custom = [{"address": "9.9.9.9", "tls_name": "dns.quad9.net"}]
        self.assertEqual(self.resolve(entry_dot_upstreams=custom), custom)

    def test_list_mixing_mullvad_and_others_is_kept(self) -> None:
        mixed = [
            {"address": "194.242.2.2", "tls_name": "dns.mullvad.net"},
            {"address": "9.9.9.9", "tls_name": "dns.quad9.net"},
        ]
        self.assertEqual(self.resolve(entry_dot_upstreams=mixed), mixed)


WARM_SCRIPT = ROOT / "roles" / "entry_dns" / "templates" / "kalimera-dns-warm.sh.j2"
WARM_SERVICE = ROOT / "roles" / "entry_dns" / "templates" / "kalimera-dns-warm.service.j2"
WARM_TIMER = ROOT / "roles" / "entry_dns" / "templates" / "kalimera-dns-warm.timer.j2"


class WarmTimerTests(unittest.TestCase):
    """Прогрев кэша Unbound: скрипт, юниты systemd и срок жизни данных о задержке."""

    def script(self, **variables) -> str:
        base = {
            "entry_dns_default_port": 5353,
            "entry_dns_warm_names": ["youtube.com", "t.me"],
            "groups": {"front": []},
            "hostvars": {},
        }
        return render(WARM_SCRIPT, **{**base, **variables})

    def test_script_queries_local_unbound_with_the_popular_names(self) -> None:
        text = self.script()
        self.assertIn("readonly port=5353", text)
        self.assertIn("youtube.com", text)
        self.assertIn("t.me", text)
        self.assertIn('-p "$port" @127.0.0.1', text)

    def test_script_also_warms_the_front_cdn_domain(self) -> None:
        text = self.script(
            groups={"front": ["front-1"]},
            hostvars={"front-1": {"front_cdn_domain": "cdn.example.invalid"}},
        )
        self.assertIn("cdn.example.invalid", text)

    def test_script_ignores_errors_and_writes_nothing(self) -> None:
        text = self.script()
        self.assertIn("|| true", text)
        self.assertIn("exit 0", text)
        self.assertIn("/dev/null", text)
        self.assertNotIn("logger", text)
        self.assertNotIn("tee", text)

    def test_service_is_oneshot_and_discards_output(self) -> None:
        text = render(WARM_SERVICE)
        self.assertIn("Type=oneshot", text)
        self.assertIn("StandardOutput=null", text)
        self.assertIn("ExecStart=/usr/local/sbin/kalimera-dns-warm", text)

    def test_timer_runs_at_the_configured_interval(self) -> None:
        text = render(WARM_TIMER, entry_dns_warm_interval_seconds=60)
        self.assertIn("OnUnitActiveSec=60s", text)
        self.assertIn("Unit=kalimera-dns-warm.service", text)

    def test_unbound_keeps_upstream_latency_data_longer(self) -> None:
        text = render(UNBOUND, **UnboundPrefetchTests.base)
        self.assertIn("    infra-host-ttl: 3600\n", text)


if __name__ == "__main__":
    unittest.main()

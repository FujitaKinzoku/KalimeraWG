from __future__ import annotations

import re
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


class IfupdownCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.defaults_text = (
            REPOSITORY / "roles/security/defaults/main.yml"
        ).read_text(encoding="utf-8")
        cls.tasks_text = (
            REPOSITORY / "roles/security/tasks/main.yml"
        ).read_text(encoding="utf-8")

    def read_default_list(self, name: str) -> list[str]:
        match = re.search(
            rf"(?m)^{re.escape(name)}:\n((?:  - .+\n)+)",
            self.defaults_text,
        )
        self.assertIsNotNone(match)
        values = []
        for line in match.group(1).splitlines():
            value = line.removeprefix("  - ")
            self.assertTrue(value.startswith("'") and value.endswith("'"))
            values.append(value[1:-1].replace("''", "'"))
        return values

    def test_ipv6_hook_rewrite_is_narrow_and_idempotent(self) -> None:
        pattern = "".join(
            self.read_default_list(
                "security_ifupdown_ipv6_hook_regexp_parts"
            )
        )
        source = """\
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
 address 162.19.214.162
 gateway 100.100.99.1
 netmask 255.255.255.255
 dns-nameservers 8.8.8.8 8.8.4.4
 up ip addr add 2001:db8::10/64 dev eth0
 up ip -6 route add 2001:db8::1 dev eth0
 down ip addr del 2001:db8::10/64 dev eth0
"""
        replacement = (
            "# KalimeraWG: IPv6-hook отключён, поскольку IPv6 запрещён "
            "политикой каскада\n# \\1"
        )

        normalized = re.sub(
            pattern,
            replacement,
            source,
            flags=re.MULTILINE,
        )
        normalized_again = re.sub(
            pattern,
            replacement,
            normalized,
            flags=re.MULTILINE,
        )

        self.assertEqual(normalized, normalized_again)
        self.assertIn("address 162.19.214.162", normalized)
        self.assertIn("gateway 100.100.99.1", normalized)
        self.assertIn("dns-nameservers 8.8.8.8 8.8.4.4", normalized)
        self.assertNotRegex(normalized, r"(?m)^\s*up ip addr add 2001:")
        self.assertNotRegex(normalized, r"(?m)^\s*up ip -6 route add")
        self.assertEqual(normalized.count("KalimeraWG: IPv6-hook"), 3)

    def test_ipv4_hooks_are_not_changed(self) -> None:
        pattern = "".join(
            self.read_default_list(
                "security_ifupdown_ipv6_hook_regexp_parts"
            )
        )
        ipv4_hook = " up ip route add 192.0.2.0/24 via 162.19.214.1\n"

        self.assertIsNone(re.search(pattern, ipv4_hook, flags=re.MULTILINE))

    def test_unmanaged_networkd_wait_does_not_stop_network_services(self) -> None:
        match = re.search(
            r'(?ms)^- name: "Отключение ожидания интерфейса, не управляемого '
            r'systemd-networkd"\n(?P<task>.*?)(?=^- name: |\Z)',
            self.tasks_text,
        )
        self.assertIsNotNone(match)
        task = match.group("task")

        self.assertIn("name: systemd-networkd-wait-online.service", task)
        self.assertIn("enabled: false", task)
        self.assertNotRegex(task, r"(?m)^\s+state:")

    def test_ifupdown_recovery_only_resets_historical_failure(self) -> None:
        match = re.search(
            r'(?ms)^- name: "Сброс исторических ошибок ifupdown после '
            r'нормализации IPv6-hooks"\n(?P<task>.*?)(?=^- name: |\Z)',
            self.tasks_text,
        )
        self.assertIsNotNone(match)
        task = match.group("task")

        self.assertIn("reset-failed", task)
        self.assertNotIn("restart", task)
        self.assertNotIn("state: restarted", task)


if __name__ == "__main__":
    unittest.main()

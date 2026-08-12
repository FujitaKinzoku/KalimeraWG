import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InstallResilienceTests(unittest.TestCase):
    def test_dns_guard_precedes_apt_timer_changes(self) -> None:
        site = (ROOT / "playbooks/site.yml").read_text(encoding="utf-8")

        dns_guard = site.index("Проверка системного DNS до изменения состояния серверов")
        apt_retries = site.index("Настройка ограниченных повторных попыток APT")
        timers = site.index("Временная остановка таймеров автоматического обновления")

        self.assertLess(dns_guard, apt_retries)
        self.assertLess(apt_retries, timers)
        self.assertIn("/usr/bin/getent ahostsv4", site)
        self.assertIn('Acquire::Retries "5";', site)
        self.assertNotIn("resolvectl dns", site)

    def test_ipset_is_an_initial_dependency(self) -> None:
        common_defaults = (ROOT / "roles/common/defaults/main.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("  - ipset\n", common_defaults)

    def test_entry_system_resolver_uses_local_unbound(self) -> None:
        tasks = (ROOT / "roles/entry_dns/tasks/main.yml").read_text(encoding="utf-8")
        template = (
            ROOT / "roles/entry_dns/templates/60-kalimerawg-resolved.conf.j2"
        ).read_text(encoding="utf-8")
        health = (ROOT / "roles/health/templates/awg-health.sh.j2").read_text(
            encoding="utf-8"
        )

        self.assertIn("systemd-resolved", tasks)
        self.assertIn("resolvectl, flush-caches", tasks)
        self.assertIn("/usr/bin/getent, ahostsv4, example.com", tasks)
        self.assertIn("DNS=127.0.0.1:{{ entry_dns_default_port }}", template)
        self.assertIn("FallbackDNS=", template)
        self.assertIn("системное разрешение имён", health)

    def test_bootstrap_apt_commands_retry_transient_failures(self) -> None:
        for relative_path in ("install.sh", "deploy"):
            content = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn("Acquire::Retries=5", content, relative_path)


if __name__ == "__main__":
    unittest.main()

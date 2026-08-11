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

    def test_bootstrap_apt_commands_retry_transient_failures(self) -> None:
        for relative_path in ("install.sh", "deploy"):
            content = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn("Acquire::Retries=5", content, relative_path)


if __name__ == "__main__":
    unittest.main()

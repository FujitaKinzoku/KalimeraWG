import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InstallResilienceTests(unittest.TestCase):
    def test_readmes_use_fixed_valid_cascade_diagrams(self) -> None:
        for readme_name, asset_name in (
            ("README.md", "cascade-ru.svg"),
            ("README.en.md", "cascade-en.svg"),
        ):
            readme = (ROOT / readme_name).read_text(encoding="utf-8")
            diagram = ROOT / "assets" / asset_name
            root = ET.parse(diagram).getroot()

            self.assertIn(f'assets/{asset_name}', readme)
            self.assertNotIn("```mermaid", readme)
            self.assertEqual(root.attrib["viewBox"], "0 0 1440 620")

    def test_release_version_is_used_by_installer_and_deploy(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        deploy = (ROOT / "deploy").read_text(encoding="utf-8")

        self.assertEqual(version, "1.0.0")
        self.assertIn('REPOSITORY_REF="${KALIMERA_VERSION:-v1.0.0}"', installer)
        self.assertIn('installed_version', installer)
        self.assertIn('if [[ $# -eq 1 && $1 == --version ]]', deploy)

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

    def test_awg3_start_failure_reports_only_sanitized_diagnostics(self) -> None:
        tasks = (ROOT / "roles/awg3_transit/tasks/main.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('rescue:', tasks)
        self.assertIn('until: awg3_transit_start_result is succeeded', tasks)
        self.assertIn('retries: 3', tasks)
        self.assertIn('journalctl -u "{{ awg3_transit_service_name }}"', tasks)
        self.assertIn('-p ExecMainStatus', tasks)
        self.assertIn('ss -H -lunp', tasks)
        self.assertIn('[КЛЮЧ СКРЫТ]', tasks)
        self.assertIn('Конфигурация и ключевой материал не выводились.', tasks)
        self.assertNotIn('cat "{{ awg3_transit_config_path }}"', tasks)
        self.assertNotIn('slurp:', tasks)

    def test_awg3_restart_cleans_stale_userspace_state_and_retries(self) -> None:
        setup = (ROOT / "roles/awg3_transit/templates/transit-setup.sh.j2").read_text(
            encoding="utf-8"
        )
        unit = (ROOT / "roles/awg3_transit/templates/awg3-transit.service.j2").read_text(
            encoding="utf-8"
        )
        restart = (ROOT / "roles/awg3_transit/templates/transit-restart.sh.j2").read_text(
            encoding="utf-8"
        )
        handler = (ROOT / "roles/awg3_transit/handlers/main.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('cleanup_interface()', setup)
        self.assertIn('ip link delete dev "$iface"', setup)
        self.assertIn('rm -f -- "$socket"', setup)
        self.assertIn('ExecStartPre={{ awg3_transit_setup_path }} prepare', unit)
        self.assertIn('KillMode=mixed', unit)
        self.assertIn('for attempt in 1 2 3', restart)
        self.assertIn('systemctl daemon-reload', restart)
        self.assertIn('[КЛЮЧ СКРЫТ]', restart)
        self.assertIn('awg3_transit_restart_path', handler)

    def test_one_time_passwords_are_shown_only_after_successful_summary(self) -> None:
        installer = (ROOT / "scripts/lib/interactive_deploy.py").read_text(
            encoding="utf-8"
        )
        generation = installer.index('account_passwords = {')
        success = installer.rindex(
            'ui_success("ENTRY и EXIT настроены, проверены и готовы к подключению клиента.")'
        )
        summary = installer.rindex('show_deployment_summary(production)')
        display = installer.rindex('show_generated_account_passwords(account_passwords)')

        self.assertLess(generation, success)
        self.assertLess(success, summary)
        self.assertLess(summary, display)
        self.assertIn('"security_account_passwords_delivered": False', installer)
        self.assertIn('mark_account_passwords_delivered(production)', installer)

    def test_fresh_local_entry_never_probes_root_over_loopback_ssh(self) -> None:
        installer = (ROOT / "scripts/lib/interactive_deploy.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('if not local_entry:\n        check_ssh(entry_host', installer)
        self.assertIn('variables.get("ansible_connection") == "local"', installer)


if __name__ == "__main__":
    unittest.main()

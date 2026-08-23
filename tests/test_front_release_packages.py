from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FrontReleasePackagesTest(unittest.TestCase):
    def test_verified_allowlist_transport_is_unchanged(self) -> None:
        defaults = (ROOT / "roles/front/defaults/main.yml").read_text(encoding="utf-8")
        xray = (ROOT / "roles/front/templates/xray-config.json.j2").read_text(
            encoding="utf-8"
        )
        nginx = (ROOT / "roles/front/templates/nginx-front.conf.j2").read_text(
            encoding="utf-8"
        )
        backend = (
            ROOT / "roles/front_backend/templates/front-backend.json.j2"
        ).read_text(encoding="utf-8")

        self.assertIn("front_xhttp_mode: packet-up", defaults)
        self.assertIn("front_reality_flow: xtls-rprx-vision-udp443", defaults)
        self.assertIn('"network": "xhttp"', xray)
        self.assertIn('"uplinkHTTPMethod": "GET"', xray)
        for directive in (
            "keepalive 64;",
            "proxy_buffering off;",
            "proxy_request_buffering off;",
            "proxy_set_header Connection \"\";",
            "proxy_read_timeout 1h;",
            "proxy_send_timeout 1h;",
        ):
            self.assertIn(directive, nginx)
        self.assertIn('"flow": "xtls-rprx-vision"', backend)
        self.assertIn('"disabled": true', backend)

    def test_user_management_only_replaces_xray_clients(self) -> None:
        manager = (
            ROOT / "roles/front/templates/vless-user.py.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('settings["clients"] =', manager)
        self.assertNotIn('config["streamSettings"] =', manager)
        self.assertNotIn('config["outbounds"] =', manager)
        self.assertIn("seal_runtime()", manager)
        self.assertIn("seal_integrity()", manager)
        self.assertIn("restart_xray()", manager)
        self.assertIn("EXPORT_DIR / f\"{record['name']}.json\"", manager)
        self.assertIn('print(f"Открыть конфигурацию: nano {path}"', manager)
        self.assertIn("0o600", manager)
        self.assertIn('"protocol": "socks"', manager)
        self.assertIn('"port": 10809', manager)
        self.assertIn('"flow": ""', manager)
        self.assertIn('"fingerprint": "firefox"', manager)
        self.assertIn('"protocol": "blackhole"', manager)
        self.assertIn('"domainStrategy": "AsIs"', manager)
        self.assertIn('"remarks": "Kalimera-FRONT-disguiseV2"', manager)

    def test_client_export_has_isolated_update_playbook(self) -> None:
        playbook = (
            ROOT / "playbooks/update-vless-client-export.yml"
        ).read_text(encoding="utf-8")
        tasks = (
            ROOT / "roles/front/tasks/client-export-update.yml"
        ).read_text(encoding="utf-8")
        entry_facts = (
            ROOT / "roles/sing_box/tasks/front-export-facts.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("tasks_from: client-export-update.yml", playbook)
        self.assertIn("tasks_from: front-export-facts.yml", playbook)
        self.assertIn("public: true", playbook)
        self.assertIn("name: health", playbook)
        self.assertIn(
            "{{ playbook_dir }}/../inventory/production/group_vars/front.yml",
            playbook,
        )
        self.assertNotIn("{{ inventory_dir }}", playbook)
        self.assertIn("vless-client-settings.json.j2", tasks)
        self.assertIn("vless-user.py.j2", tasks)
        self.assertIn("front_vless_user_command_path", tasks)
        self.assertIn("run\n      - -test", tasks)
        self.assertIn("kalimera-secretctl", tasks)
        self.assertIn("awg-managed-integrity", tasks)
        self.assertIn("- key: front_vless_encryption_enabled", playbook)
        self.assertIn("- key: front_xhttp_disguise_enabled", playbook)
        self.assertIn("vlessenc", tasks)
        self.assertIn("ML-KEM-768", tasks)
        self.assertIn("Удаление неполной пары VLESS Encryption", tasks)
        self.assertIn("xray-config.json.j2", tasks)
        self.assertIn("notify: Перезапустить Xray-core FRONT", tasks)
        self.assertIn("Строгая проверка FRONT", tasks)
        self.assertNotIn("systemd_service", tasks)
        self.assertIn("reality_fallback_public_key", entry_facts)
        self.assertIn("reality_fallback_front_client_uuid", entry_facts)
        self.assertIn("sing_box_reality_dest_override_path", entry_facts)
        self.assertNotIn("systemd_service", entry_facts)

    def test_front_encryption_profile_is_enabled_by_every_installer_path(self) -> None:
        defaults = (ROOT / "roles/front/defaults/main.yml").read_text(
            encoding="utf-8"
        )
        example = (ROOT / "inventory/example/group_vars/front.yml").read_text(
            encoding="utf-8"
        )
        installer = (ROOT / "scripts/lib/interactive_deploy.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("front_vless_encryption_enabled: true", defaults)
        self.assertIn("front_xhttp_disguise_enabled: true", defaults)
        self.assertIn("front_vless_encryption_enabled: true", example)
        self.assertIn("front_xhttp_disguise_enabled: true", example)
        self.assertGreaterEqual(
            installer.count('"front_vless_encryption_enabled": True'), 3
        )
        self.assertGreaterEqual(
            installer.count('"front_xhttp_disguise_enabled": True'), 3
        )

    def test_xray_cannot_modify_runtime_configuration_tree(self) -> None:
        tasks = (ROOT / "roles/front/tasks/main.yml").read_text(encoding="utf-8")
        service = (ROOT / "roles/front/templates/xray.service.j2").read_text(
            encoding="utf-8"
        )
        manager = (ROOT / "roles/front/templates/vless-user.py.j2").read_text(
            encoding="utf-8"
        )
        directory_task = tasks[
            tasks.index('- name: "Создание: каталог состояния Xray-core"') :
            tasks.index('- name: "Проверка: пара VLESS Encryption уже создана"')
        ]
        base_config_task = tasks[
            tasks.index('- name: "Установка: базовая конфигурация Xray-core FRONT"') :
            tasks.index('- name: "Установка: параметры защищённого экспорта VLESS JSON"')
        ]
        self.assertIn("owner: root", directory_task)
        self.assertIn('mode: "0750"', directory_task)
        self.assertIn("owner: root", base_config_task)
        self.assertIn('mode: "0640"', base_config_task)
        self.assertNotIn("ReadWritePaths=", service)
        self.assertIn("os.chown(temporary, 0, account.pw_gid)", manager)
        audit = (ROOT / "roles/operations/templates/server-audit.sh.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("xray_read_only_config_ok", audit)
        self.assertIn("root:xray:640", audit)
        self.assertIn('target="$(readlink -f -- "$file")"', audit)
        self.assertIn('"$target" == /run/kalimera-secrets/*', audit)
        self.assertIn('"$group" == root || "$group" == xray', audit)
        self.assertIn('! runuser -u xray -- test -w "$target"', audit)

        health = (ROOT / "roles/health/templates/awg-health.sh.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn('resolved="$(readlink -f -- "$state_dir")"', health)
        self.assertIn('stat -Lc %U -- "$state_dir"', health)
        self.assertIn("front_vless_encryption_is_enabled", health)
        self.assertIn("mlkem768x25519plus.native.0rtt.", health)
        self.assertIn("VLESS Encryption ML-KEM-768 включён", health)
        self.assertIn(
            "security_admin_command_path | default('/usr/local/libexec/kalimera-admin-command')",
            health,
        )

    def test_front_ufw_is_only_managed_by_security_role(self) -> None:
        front_tasks = (ROOT / "roles/front/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        security_tasks = (ROOT / "roles/security/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("community.general.ufw", front_tasks)
        self.assertIn(
            "Разрешение веб-доступа к FRONT в управляемой политике UFW",
            security_tasks,
        )
        health = (ROOT / "roles/health/templates/awg-health.sh.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("['entry', 'exit', 'front']", health)

    def test_role_audit_and_admin_commands_match_front_backend(self) -> None:
        audit = (ROOT / "roles/operations/templates/server-audit.sh.j2").read_text(
            encoding="utf-8"
        )
        shell_tools = (
            ROOT / "roles/terminal/templates/kalimera-shell-tools.sh.j2"
        ).read_text(encoding="utf-8")
        admin = (
            ROOT / "roles/security/templates/kalimera-admin-command.sh.j2"
        ).read_text(encoding="utf-8")
        proxy = (
            ROOT / "roles/operations/templates/ru-proxy.sh.j2"
        ).read_text(encoding="utf-8")
        prompt = (
            ROOT / "roles/terminal/templates/kalimera-prompt.sh.j2"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'known_tcp="$known_tcp {{ reality_fallback_port | default(8444) | int }}"',
            audit,
        )
        self.assertIn(
            "root authorized_keys не содержит посторонних ключей", audit
        )
        self.assertIn("обнаружены неожиданные внешние слушатели", audit)
        self.assertIn(
            "function reality-dest-switch { _kalimera_admin reality-dest-switch",
            shell_tools,
        )
        self.assertIn("|reality-dest-switch|", admin)
        self.assertIn("Маршрутизация через RU-прокси: НЕ НАСТРОЕНА", proxy)
        self.assertIn("'FRONT' if 'front' in group_names", prompt)

    def test_front_backend_gets_minimal_rule_set_access(self) -> None:
        backend_tasks = (
            ROOT / "roles/front_backend/tasks/main.yml"
        ).read_text(encoding="utf-8")
        runtime_config = (
            ROOT / "roles/runtime_secrets/templates/config.json.j2"
        ).read_text(encoding="utf-8")
        secretctl = (
            ROOT / "roles/runtime_secrets/templates/secretctl.py.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("'access_group': 'sing-box'", runtime_config)
        self.assertIn("'read_paths': ['reality/rules']", runtime_config)
        self.assertIn("def apply_runtime_access(config: dict)", secretctl)
        self.assertIn("apply_runtime_access(config)", secretctl)
        recovery = backend_tasks.index(
            "Восстановление минимального доступа backend FRONT к публичным rule-set"
        )
        handlers = backend_tasks.index("Применение обработчиков backend FRONT")
        self.assertLess(recovery, handlers)

    def test_standalone_front_playbook_seals_runtime_and_integrity(self) -> None:
        playbook = (ROOT / "playbooks/front.yml").read_text(encoding="utf-8")
        self.assertIn("role: runtime_secrets", playbook)
        self.assertIn("awg-managed-integrity, seal", playbook)

    def test_replacement_is_staged_and_preserves_cdn_identifiers(self) -> None:
        installer = (ROOT / "scripts/lib/interactive_deploy.py").read_text(
            encoding="utf-8"
        )
        security = (ROOT / "roles/security/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("def prepare_front_replacement", installer)
        self.assertIn("def commit_front_replacement", installer)
        self.assertIn("def rollback_front_replacement", installer)
        self.assertIn('"front_replacement_state": "prepared"', installer)
        self.assertIn("front_previous_public_ipv4", security)
        replacement = installer[
            installer.index("def prepare_front_replacement") :
            installer.index("def rollback_front_replacement")
        ]
        self.assertNotIn('front_vars["front_xhttp_path"] =', replacement)
        self.assertNotIn('front_vars["front_cdn_domain"] =', replacement)

    def test_no_subscription_or_direct_entry_user_path_returns(self) -> None:
        front_tasks = (ROOT / "roles/front/tasks/main.yml").read_text(encoding="utf-8")
        nginx = (ROOT / "roles/front/templates/nginx-front.conf.j2").read_text(
            encoding="utf-8"
        )
        entry = (ROOT / "inventory/example/group_vars/entry.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("not (front_subscription_enabled", front_tasks)
        self.assertNotIn("subscription", nginx.lower())
        self.assertIn("reality_fallback_direct_client_enabled: false", entry)

    def test_ru_zone_updater_can_only_write_the_public_rule_set_directory(self) -> None:
        defaults = (ROOT / "roles/sing_box/defaults/main.yml").read_text(
            encoding="utf-8"
        )
        tasks = (ROOT / "roles/sing_box/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        service = (
            ROOT / "roles/entry_routing/templates/awg-ru-zone-update.service.j2"
        ).read_text(encoding="utf-8")
        routing_tasks = (ROOT / "roles/entry_routing/tasks/main.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            'reality_fallback_rule_set_dir: "{{ reality_fallback_state_dir }}/rules"',
            defaults,
        )
        self.assertIn(
            'reality_fallback_ru_zone_rule_set_path: "{{ reality_fallback_rule_set_dir }}/ru-zone.json"',
            defaults,
        )
        self.assertIn(
            'path: "{{ reality_fallback_rule_set_dir }}"',
            tasks,
        )
        self.assertIn(
            "reality_fallback_rule_set_dir | default('/etc/sing-box/reality/rules')",
            service,
        )
        self.assertNotIn("{% if reality_fallback_enabled", service)
        self.assertIn("ProtectClock=true", service)
        self.assertNotIn("ReadWritePaths={{ reality_fallback_state_dir }}", service)
        self.assertIn(
            '"([.rules[]?.ip_cidr[]?] | length) >= $minimum"', routing_tasks
        )
        self.assertIn("entry_ru_zone_reality_rule_set.rc", routing_tasks)


if __name__ == "__main__":
    unittest.main()

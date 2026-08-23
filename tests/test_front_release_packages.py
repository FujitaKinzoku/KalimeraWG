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


if __name__ == "__main__":
    unittest.main()

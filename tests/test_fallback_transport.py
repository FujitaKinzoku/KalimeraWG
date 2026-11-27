"""Запасной транспорт туннеля ENTRY - EXIT: установщик, шаблоны и роль.

Требование владельца: одновременно работает один транспорт, запасной не слушает,
и его порт закрыт. Сами решения о переключении проверяют test_transport_guard.py
(сторож на EXIT) и test_transport_selector.py (переключатель путей на ENTRY).
Здесь - всё, что ставит роль: служба не должна включаться при загрузке, сервер
должен принимать только пакеты туннеля, а команда установщика - не оставлять
inventory в половинчатом состоянии.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from unittest import mock

import jinja2
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from test_standby_exit import InstallerCase, deploy, read_vault, selector

ROOT = Path(__file__).parents[1]
ROLE = ROOT / "roles" / "transit_tls"
SELECTOR_ROLE = ROOT / "roles" / "entry_exit_path"
NAMES = {"st-4k7m2x.example.com": "192.0.2.20", "lm-9vu8g1.example.com": "198.51.100.7"}
STANDBY = "exit-standby-managed"


def environment() -> jinja2.Environment:
    env = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
    env.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    env.filters["to_nice_json"] = lambda value, **kwargs: json.dumps(value, indent=4, **kwargs)
    env.filters["quote"] = lambda value: str(value)
    return env


def render(template: Path, **variables) -> str:
    return environment().from_string(template.read_text(encoding="utf-8")).render(**variables)


def role_defaults() -> dict:
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    return {key: value for key, value in defaults.items() if "{{" not in str(value)}


class TransportInstallerCase(InstallerCase):
    def enable_transport(self, names: dict[str, str] | None = None, port: int = 443) -> bool:
        table = NAMES if names is None else names
        answers = iter(table)
        with mock.patch.object(deploy, "prompt", side_effect=lambda *_a, **_k: next(answers)), \
                mock.patch.object(deploy, "prompt_port", return_value=port), \
                mock.patch.object(
                    deploy, "resolve_single_public_ipv4", side_effect=lambda value, _l: table.get(value, value)
                ), \
                mock.patch.object(deploy, "ui_panel"), mock.patch("builtins.print"):
            return deploy.enable_fallback_transport(self.production, self.vault_password)

    def disable_transport(self, confirm: bool = True, state: dict | None = None) -> bool:
        state_dir = self.root / "exit-path"
        state_dir.mkdir(exist_ok=True)
        if state is not None:
            (state_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        entry = deploy.load_yaml(self.entry_path)
        entry["entry_exit_path_state_dir"] = str(state_dir)
        deploy.yaml_write(self.entry_path, entry)
        with mock.patch.object(deploy, "prompt_bool", return_value=confirm) as asked, \
                mock.patch("builtins.print"):
            self.asked = asked
            return deploy.disable_fallback_transport(self.production, self.vault_password)

    def exit_hosts(self) -> dict:
        return deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"]


class InstallerTests(TransportInstallerCase):
    def test_each_exit_gets_its_own_name_identity_and_certificate(self) -> None:
        self.enable()
        self.assertTrue(self.enable_transport())
        all_vars = deploy.load_yaml(self.all_path)
        self.assertIs(all_vars["transit_tls_enabled"], True)
        self.assertEqual(all_vars["transit_tls_port"], 443)
        hosts = self.exit_hosts()
        self.assertEqual(hosts["exit-managed"]["transit_tls_server_name"], "st-4k7m2x.example.com")
        self.assertEqual(hosts[STANDBY]["transit_tls_server_name"], "lm-9vu8g1.example.com")
        material = read_vault(self.vault_path)["vault_transit_tls"]
        self.assertEqual(set(material), {"exit-managed", STANDBY})
        self.assertNotEqual(material["exit-managed"]["uuid"], material[STANDBY]["uuid"])
        for host, name in (("exit-managed", "st-4k7m2x.example.com"), (STANDBY, "lm-9vu8g1.example.com")):
            item = material[host]
            self.assertRegex(item["uuid"], r"^[0-9a-f-]{36}$")
            certificate = x509.load_pem_x509_certificate(item["certificate"].encode())
            names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(names.get_values_for_type(x509.DNSName), [name])
            # Ключ в Vault - тот, на который выпущен сертификат.
            key = serialization.load_pem_private_key(item["private_key"].encode(), password=None)
            self.assertEqual(
                key.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                ),
                certificate.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                ),
            )
            # Срок с запасом: сертификат закрытый, перевыпускать его некому.
            self.assertGreater((certificate.not_valid_after_utc - certificate.not_valid_before_utc).days, 3000)

    def test_cascade_without_a_standby_exit_is_refused(self) -> None:
        # Транспортом управляет переключатель путей, а он есть только с резервным EXIT.
        before = self.all_path.read_text(encoding="utf-8")
        with self.assertRaises(SystemExit) as stopped:
            self.enable_transport()
        self.assertNotEqual(stopped.exception.code, 0)
        self.assertEqual(self.all_path.read_text(encoding="utf-8"), before)

    def test_name_that_points_elsewhere_is_refused_before_anything_is_written(self) -> None:
        self.enable()
        before_hosts = self.hosts_path.read_text(encoding="utf-8")
        wrong = {"st-4k7m2x.example.com": "192.0.2.20", "lm-9vu8g1.example.com": "203.0.113.9"}
        with self.assertRaises(SystemExit):
            self.enable_transport(wrong)
        self.assertEqual(self.hosts_path.read_text(encoding="utf-8"), before_hosts)
        self.assertNotIn("vault_transit_tls", read_vault(self.vault_path))
        self.assertNotIn("transit_tls_enabled", deploy.load_yaml(self.all_path))

    def test_names_must_be_real_and_distinct(self) -> None:
        self.enable()
        for names in (
            {"не имя": "192.0.2.20", "lm-9vu8g1.example.com": "198.51.100.7"},
            {"vpn": "192.0.2.20", "lm-9vu8g1.example.com": "198.51.100.7"},
        ):
            with self.subTest(names=names), self.assertRaises(SystemExit):
                self.enable_transport(names)
        # Одно имя на оба сервера: адреса у серверов разные.
        same = iter(["st-4k7m2x.example.com", "st-4k7m2x.example.com"])
        with mock.patch.object(deploy, "prompt", side_effect=lambda *_a, **_k: next(same)), \
                mock.patch.object(deploy, "prompt_port", return_value=443), \
                mock.patch.object(deploy, "resolve_single_public_ipv4", side_effect=lambda value, _l: {
                    "st-4k7m2x.example.com": "192.0.2.20"}.get(value, value)), \
                mock.patch.object(deploy, "ui_panel"), mock.patch("builtins.print"), \
                self.assertRaises(SystemExit):
            deploy.enable_fallback_transport(self.production, self.vault_password)
        self.assertNotIn("transit_tls_enabled", deploy.load_yaml(self.all_path))

    def test_second_enabling_changes_nothing(self) -> None:
        self.enable()
        self.enable_transport()
        before = read_vault(self.vault_path)["vault_transit_tls"]
        self.assertFalse(self.enable_transport())
        self.assertEqual(read_vault(self.vault_path)["vault_transit_tls"], before)

    def test_disable_removes_names_identity_and_keys(self) -> None:
        self.enable()
        self.enable_transport()
        self.assertTrue(self.disable_transport())
        self.asked.assert_called_once_with("Выключить запасной транспорт туннеля", False)
        all_vars = deploy.load_yaml(self.all_path)
        self.assertNotIn("transit_tls_enabled", all_vars)
        self.assertNotIn("transit_tls_port", all_vars)
        for values in self.exit_hosts().values():
            self.assertNotIn("transit_tls_server_name", values)
        self.assertNotIn("vault_transit_tls", read_vault(self.vault_path))
        self.assertFalse(self.disable_transport())

    def test_disable_is_refused_while_a_tunnel_runs_inside_tls(self) -> None:
        self.enable()
        self.enable_transport()
        state = {"paths": {"primary": {"transport": "tls"}, "standby": {"transport": "awg"}}}
        with self.assertRaises(SystemExit) as stopped:
            self.disable_transport(state=state)
        self.assertNotEqual(stopped.exception.code, 0)
        self.asked.assert_not_called()
        self.assertTrue(deploy.load_yaml(self.all_path)["transit_tls_enabled"])

    def test_declined_disable_changes_nothing(self) -> None:
        self.enable()
        self.enable_transport()
        with self.assertRaises(SystemExit) as stopped:
            self.disable_transport(confirm=False)
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("vault_transit_tls", read_vault(self.vault_path))

    def test_standby_exit_cannot_be_detached_while_the_transport_is_on(self) -> None:
        self.enable()
        self.enable_transport()
        with self.assertRaises(SystemExit) as stopped:
            self.disable()
        self.assertNotEqual(stopped.exception.code, 0)
        self.assertIn(STANDBY, self.exit_hosts())

    def test_admin_gateway_allows_the_commands(self) -> None:
        gateway = (
            ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "'--resume --enable-fallback-transport'|'--resume --disable-fallback-transport'|", gateway
        )
        self.assertRegex(gateway, r"\|exit-path\|transport-guard\|kalimera-secretctl\|")


class TemplateTests(unittest.TestCase):
    material = {"uuid": "11111111-2222-3333-4444-555555555555",
                "certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                "private_key": "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n"}

    def server(self) -> dict:
        variables = {
            **role_defaults(),
            "transit_tls_material": self.material,
            "exit_awg_listen_port": 443,
            "transit_tls_server_name": "st-4k7m2x.example.com",
        }
        return json.loads(render(ROLE / "templates" / "server.json.j2", **variables))

    def client(self) -> dict:
        return json.loads(render(
            ROLE / "templates" / "client.json.j2",
            **role_defaults(),
            transit_tls_path={
                "name": "primary", "address": "192.0.2.20", "server_name": "st-4k7m2x.example.com",
                "awg_port": "443", "local_port": 20443, "uuid": self.material["uuid"],
                "certificate": self.material["certificate"],
            },
        ))

    def test_server_carries_only_the_tunnel_and_keeps_no_log(self) -> None:
        server = self.server()
        self.assertEqual(server["log"], {"disabled": True})
        rules = server["route"]["rules"]
        self.assertEqual(
            rules,
            [
                {"network": ["udp"], "ip_cidr": ["127.0.0.1/32"], "port": [443],
                 "action": "route", "outbound": "awg"},
                {"action": "reject"},
            ],
        )
        inbound = server["inbounds"][0]
        self.assertEqual((inbound["type"], inbound["listen_port"]), ("vless", 443))
        self.assertEqual(inbound["users"], [{"uuid": self.material["uuid"]}])
        tls = inbound["tls"]
        self.assertEqual((tls["server_name"], tls["min_version"]), ("st-4k7m2x.example.com", "1.3"))
        self.assertEqual(tls["key"][0], "-----BEGIN PRIVATE KEY-----")

    def test_client_listens_on_loopback_and_trusts_one_certificate(self) -> None:
        client = self.client()
        self.assertEqual(client["log"], {"disabled": True})
        inbound = client["inbounds"][0]
        self.assertEqual(
            (inbound["listen"], inbound["listen_port"], inbound["network"]), ("127.0.0.1", 20443, "udp")
        )
        self.assertEqual((inbound["override_address"], inbound["override_port"]), ("127.0.0.1", 443))
        outbound = client["outbounds"][0]
        self.assertEqual((outbound["server"], outbound["server_port"]), ("192.0.2.20", 443))
        tls = outbound["tls"]
        self.assertEqual(tls["certificate"], self.material["certificate"].strip().splitlines())
        self.assertEqual(tls["utls"], {"enabled": True, "fingerprint": "chrome"})
        self.assertNotIn("insecure", tls)
        self.assertNotIn("key", tls, "закрытый ключ EXIT на ENTRY не попадает")

    def test_guard_settings_are_valid_for_the_program(self) -> None:
        from test_transport_guard import guard

        cfg = guard.Config(json.loads(render(
            ROLE / "templates" / "guard-config.json.j2",
            **role_defaults(),
            security_interserver_peer_ipv4="192.0.2.10",
            exit_wan_interface="eth0",
            exit_awg_interface="awg3",
            exit_awg_listen_port=443,
        )))
        self.assertEqual(cfg.peer, "192.0.2.10")
        self.assertEqual(
            [(item["name"], item["proto"], item["port"], item["service"]) for item in cfg.transports],
            [("awg", "udp", 443, ""), ("tls", "tcp", 443, "kalimera-transit-tls.service")],
        )
        # Больше самого длинного интервала keepalive туннеля (30 с) с запасом на проверку.
        self.assertGreaterEqual(cfg.idle_seconds, 60)
        self.assertEqual(str(cfg.active_file), "/var/lib/kalimera-transport/active")

    def test_selector_settings_name_both_transports_of_each_path(self) -> None:
        defaults = yaml.safe_load((SELECTOR_ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
        defaults = {key: value for key, value in defaults.items() if "{{" not in str(value)}
        variables = dict(
            **defaults,
            entry_exit_interface="awg3",
            entry_exit_tunnel_address="10.77.0.2/32",
            awg3_peer_tunnel_address="10.77.0.1",
            entry_standby_exit_interface="awg4",
            entry_standby_exit_tunnel_address="10.78.0.2/32",
            entry_standby_exit_peer_tunnel_address="10.78.0.1",
            entry_exit_table=100,
            security_interserver_peer_ipv4="192.0.2.20",
            entry_exit_endpoint="exit.example.com:443",
            entry_standby_exit_public_ipv4="198.51.100.7",
            entry_standby_exit_endpoint="198.51.100.7:443",
        )
        template = SELECTOR_ROLE / "templates" / "config.json.j2"
        cfg = selector.Config(json.loads(render(template, transit_tls_enabled=True, **variables)))
        self.assertEqual(
            [(item["name"], item["endpoint"], item.get("service")) for item in cfg.transports("primary")],
            [
                # Адрес числом, а не именем: его сверяют с тем, что показывает интерфейс.
                ("awg", "192.0.2.20:443", None),
                ("tls", "127.0.0.1:20443", "kalimera-transit-tls@primary.service"),
            ],
        )
        self.assertEqual(cfg.transports("standby")[1]["endpoint"], "127.0.0.1:20444")
        self.assertEqual(cfg.transport_retest_hour, 1)
        # Без запасного транспорта настройки прежние.
        plain = json.loads(render(template, **variables))
        self.assertNotIn("transports", plain["paths"][0])
        self.assertNotIn("transport_retest_hour_utc", plain)


class RoleTests(unittest.TestCase):
    """То, что нельзя сломать правкой роли, не нарушив требование владельца."""

    def setUp(self) -> None:
        self.tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))

    def test_transport_service_never_starts_at_boot(self) -> None:
        for name in ("kalimera-transit-tls.service.j2", "kalimera-transit-tls@.service.j2"):
            unit = (ROLE / "templates" / name).read_text(encoding="utf-8")
            self.assertNotIn("[Install]", unit, name)
            self.assertNotIn("WantedBy", unit, name)
            # Закрытый ключ служба получает через systemd credentials и сама не читает.
            self.assertIn("LoadCredential=transit.json:", unit)
            self.assertIn("-c %d/transit.json run", unit)
        enabled = [
            task["ansible.builtin.systemd_service"]["name"]
            for task in self.tasks
            if task.get("ansible.builtin.systemd_service", {}).get("enabled") is True
        ]
        self.assertEqual(enabled, ["{{ transport_guard_timer_name }}"], "включается только таймер сторожа")
        started = [
            task["name"]
            for task in self.tasks
            if task.get("ansible.builtin.systemd_service", {}).get("state") == "started"
        ]
        self.assertEqual(started, ["Включение таймера сторожа транспорта"])

    def test_configuration_update_does_not_open_a_closed_transport(self) -> None:
        handlers = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
        for handler in handlers:
            command = handler.get("ansible.builtin.command")
            if command:
                self.assertIn("try-restart", command["argv"], handler["name"])
        text = (ROLE / "handlers" / "main.yml").read_text(encoding="utf-8")
        self.assertNotRegex(text, r"state:\s*(re)?started")

    def test_sing_box_package_service_is_stopped_on_exit(self) -> None:
        task = next(t for t in self.tasks if t["name"] == "Отключение службы sing-box из пакета на EXIT")
        self.assertEqual(
            task["ansible.builtin.systemd_service"],
            {"name": "sing-box.service", "enabled": False, "state": "stopped"},
        )
        self.assertIn("awg_node_role == 'exit'", task["when"])

    def test_secrets_are_never_printed_by_the_role(self) -> None:
        for task in self.tasks:
            text = yaml.safe_dump(task, allow_unicode=True)
            if "vault_transit_tls" in text or "ansible-transit-tls" in text and "state: absent" not in text:
                self.assertTrue(task.get("no_log"), task["name"])

    def test_disabled_transport_is_removed_from_both_servers(self) -> None:
        names = [task["name"] for task in self.tasks]
        for expected in (
            "Остановка отключённого сторожа транспорта и его службы",
            "Удаление цепочки сторожа транспорта",
            "Удаление файлов отключённого запасного транспорта EXIT",
            "Остановка отключённого запасного транспорта ENTRY",
            "Удаление файлов отключённого запасного транспорта ENTRY",
        ):
            self.assertIn(expected, names)

    def test_role_runs_before_the_selector_on_entry_and_on_every_exit(self) -> None:
        site = (ROOT / "playbooks" / "site.yml").read_text(encoding="utf-8")
        entry_play = site[site.index("- name: Настройка ENTRY сервера"):site.index("- name: Настройка EXIT сервера")]
        exit_play = site[site.index("- name: Настройка EXIT сервера"):site.index("- name: Настройка FRONT сервера")]
        self.assertLess(entry_play.index("role: transit_tls"), entry_play.index("role: entry_exit_path"))
        self.assertLess(entry_play.index("role: sing_box"), entry_play.index("role: transit_tls"))
        self.assertLess(exit_play.index("role: transit_tls"), exit_play.index("role: health"))

    def test_health_and_self_heal_know_the_guard(self) -> None:
        health = (ROOT / "roles" / "health" / "templates" / "awg-health.sh.j2").read_text(encoding="utf-8")
        heal = (ROOT / "roles" / "health" / "templates" / "awg-self-heal.sh.j2").read_text(encoding="utf-8")
        for label in re.findall(r"^check '([^']*сторож[^']*)'", health, flags=re.MULTILINE):
            self.assertIn(f"'{label}')", heal, label)
        self.assertIn("kalimera-transit-tls.service|kalimera-transit-tls@*.service)", heal)
        # Самовосстановление не запускает службу закрытого транспорта.
        self.assertIn('plan_action="unit_reset:$1"', heal)


if __name__ == "__main__":
    unittest.main()

"""Замена основного EXIT новым сервером: kalimera-deploy --resume --replace-exit.

Самое уязвимое место каскада - зарубежный адрес EXIT: блокируют именно его.
Резервный EXIT берёт трафик на себя сам, но вернуть запас раньше было нечем:
установщик умел подключать и отключать только резервный сервер, а с недоступным
основным не проходил ни один deploy. Здесь проверяется, что новый сервер занимает
место основного целиком, что прежнему ничего не остаётся от нового туннеля и что
отказ на любом шаге до установки ключа не меняет ни inventory, ни Vault.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from test_standby_exit import InstallerCase, deploy, read_vault, selector, write_vault
from test_transport_selector import TransportCase

ROOT = Path(__file__).parents[1]
OLD = "192.0.2.20"
NEW = "203.0.113.50"
STANDBY = "198.51.100.7"


class ReplaceCase(InstallerCase):
    def setUp(self) -> None:
        super().setUp()
        entry = deploy.load_yaml(self.entry_path)
        entry.update(
            {
                "entry_exit_tunnel_address": "10.77.0.2/32",
                "entry_exit_endpoint": f"{OLD}:443",
                "awg3_peer_endpoint_host": OLD,
                "awg3_transit_obfuscation": dict(entry["entry_awg1_obfuscation"]),
            }
        )
        deploy.yaml_write(self.entry_path, entry)
        exit_vars = deploy.load_yaml(self.exit_path)
        exit_vars.update(
            {
                "exit_awg_obfuscation": dict(entry["entry_awg1_obfuscation"]),
                "awg3_transit_obfuscation": dict(entry["entry_awg1_obfuscation"]),
                "runtime_secrets_advertise_ipv4": OLD,
            }
        )
        deploy.yaml_write(self.exit_path, exit_vars)
        # Установленный сервер: вход kalimera с паролем sudo из Vault.
        hosts = deploy.load_yaml(self.hosts_path)
        hosts["all"]["children"]["exit"]["hosts"]["exit-managed"].update(
            {
                "ansible_become": True,
                "ansible_become_method": "sudo",
                "ansible_become_password": "{{ vault_exit_kalimera_password }}",
                "ansible_ssh_private_key_file": str(self.home / ".ssh" / "awg-iac-production"),
                "security_allow_ssh_port_change": False,
                "security_previous_ssh_port": 22,
                "security_automation_source_ipv4": "192.0.2.10",
            }
        )
        deploy.yaml_write(self.hosts_path, hosts)
        vault = read_vault(self.vault_path)
        vault.update(
            {
                "vault_awg_entry_exit_private_key": "old-entry-transit-key",
                "vault_awg_entry_exit_peer_public_key": "old-exit-public",
                "vault_awg_entry_exit_entry_public_key": "old-entry-public",
                "vault_awg_entry_exit_psk": "old-psk",
                "vault_awg3_header_protection_key": "old-header-key",
                "vault_exit_peers": [{"name": "entry", "public_key": "old-entry-public",
                                      "allowed_ips": ["10.77.0.2/32"], "preshared_key": "old-psk"}],
                "vault_runtime_exchange_private_keys": {
                    "entry-managed": "entry-exchange", "exit-managed": "old-exit-exchange",
                },
                "vault_runtime_exchange_public_keys": {
                    "entry-managed": "entry-exchange-pub", "exit-managed": "old-exit-exchange-pub",
                },
            }
        )
        write_vault(self.vault_path, vault)
        self.dns: dict[str, str] = {}
        self.all_vars_before = self.all_path.read_text(encoding="utf-8")

    def traffic_through(self, interface: str) -> None:
        """Какой интерфейс выбрал переключатель путей на этом ENTRY."""
        state_dir = Path(self.tmp.name) / "exit-path"
        state_dir.mkdir(exist_ok=True)
        (state_dir / "active").write_text(interface + "\n", encoding="utf-8")
        entry = deploy.load_yaml(self.entry_path)
        entry["entry_exit_path_state_dir"] = str(state_dir)
        deploy.yaml_write(self.entry_path, entry)

    def snapshot(self) -> tuple:
        return (
            self.hosts_path.read_text(encoding="utf-8"),
            self.entry_path.read_text(encoding="utf-8"),
            self.exit_path.read_text(encoding="utf-8"),
            self.all_path.read_text(encoding="utf-8"),
            read_vault(self.vault_path),
        )

    def replace(
        self,
        address: str = NEW,
        user: str = "root",
        confirmations: tuple[bool, ...] = (True,),
        tls_name: str | None = None,
        bootstrap: object = None,
        route: dict | None = None,
    ) -> bool:
        answers = iter([address, user] + ([tls_name] if tls_name is not None else []))
        ports = iter([22, 56777])
        decisions = iter(confirmations)
        self.events: list[str] = []

        def bootstrap_key(*_args, **_kwargs) -> str:
            self.events.append("bootstrap")
            if isinstance(bootstrap, BaseException):
                raise bootstrap
            return "initial-password"

        def forget(host: str, ports_: set[int]) -> None:
            self.events.append(f"forget {host} {sorted(ports_)}")

        with mock.patch.object(deploy, "prompt", side_effect=lambda *_a, **_k: next(answers)) as asked, \
                mock.patch.object(deploy, "prompt_port", side_effect=lambda *_a, **_k: next(ports)), \
                mock.patch.object(deploy, "prompt_bool", side_effect=lambda *_a, **_k: next(decisions)) as confirmed, \
                mock.patch.object(deploy.getpass, "getpass", return_value="initial-password"), \
                mock.patch.object(deploy, "require_public_endpoint"), \
                mock.patch.object(
                    deploy, "resolve_single_public_ipv4",
                    side_effect=lambda value, _label: self.dns.get(value, value),
                ), \
                mock.patch.object(deploy, "bootstrap_key", side_effect=bootstrap_key), \
                mock.patch.object(deploy, "remote_observed_ssh_source_ipv4", return_value="192.0.2.10"), \
                mock.patch.object(
                    deploy, "probe_tcp_route", return_value=dict(route or self.CLEAN_ROUTE)
                ), \
                mock.patch.object(deploy, "forget_ssh_host", side_effect=forget), \
                mock.patch.object(deploy, "ui_panel") as panel, \
                mock.patch("builtins.print") as printed:
            self.asked = asked
            self.confirmed = confirmed
            self.panel = panel
            self.printed = printed
            return deploy.replace_exit(self.production, self.vault_password)

    def primary(self) -> dict:
        return deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"]["exit-managed"]


class ReplaceTests(ReplaceCase):
    def test_new_server_takes_the_place_of_the_primary_everywhere(self) -> None:
        old_profile = deploy.load_yaml(self.entry_path)["entry_awg1_obfuscation"]
        self.assertTrue(self.replace())
        host = self.primary()
        self.assertEqual(
            {key: host[key] for key in (
                "ansible_host", "ansible_user", "ansible_port", "ssh_listen_port",
                "security_allow_ssh_port_change", "security_automation_source_ipv4",
                "runtime_secrets_share_index", "ansible_become",
            )},
            {
                "ansible_host": NEW, "ansible_user": "root", "ansible_port": 22,
                "ssh_listen_port": 56777, "security_allow_ssh_port_change": True,
                "security_automation_source_ipv4": "192.0.2.10",
                # Доля ключа хранилища та же: её номер закреплён за местом в каскаде.
                "runtime_secrets_share_index": 2, "ansible_become": True,
            },
        )
        # От прежнего входа kalimera ничего не осталось: новый сервер ещё с root.
        for stale in ("ansible_become_password", "ansible_become_method", "security_previous_ssh_port"):
            self.assertNotIn(stale, host)
        entry = deploy.load_yaml(self.entry_path)
        self.assertEqual(entry["security_interserver_peer_ipv4"], NEW)
        self.assertEqual(entry["entry_exit_endpoint"], f"{NEW}:443")
        self.assertEqual(entry["awg3_peer_endpoint_host"], NEW)
        exit_vars = deploy.load_yaml(self.exit_path)
        self.assertEqual(exit_vars["runtime_secrets_advertise_ipv4"], NEW)
        # Адрес ENTRY на стороне EXIT не тронут.
        self.assertEqual(exit_vars["security_interserver_peer_ipv4"], "192.0.2.10")
        # Профиль маскировки новый и один на обе стороны туннеля; S4 прежний: он
        # входит в расчёт MTU, записанного в клиентских конфигах.
        profile = entry["entry_awg1_obfuscation"]
        self.assertNotEqual(profile, old_profile)
        self.assertEqual(profile["s4"], old_profile["s4"])
        self.assertEqual(entry["awg3_transit_obfuscation"], profile)
        self.assertEqual(exit_vars["exit_awg_obfuscation"], profile)
        self.assertEqual(exit_vars["awg3_transit_obfuscation"], profile)
        # Новый сервер проходит тот же двухшаговый переход SSH, что при установке.
        self.assertIs(deploy.load_yaml(self.all_path)["security_finalize_admin_access"], False)
        self.assertIn(f"forget {OLD} [22, 56777]", self.events)
        self.assertLess(self.events.index("bootstrap"), self.events.index(f"forget {OLD} [22, 56777]"))
        self.assertIn(f"{OLD} → {NEW}", self.printed.call_args.args[0])

    def test_old_server_keeps_nothing_of_the_new_tunnel(self) -> None:
        before = read_vault(self.vault_path)
        self.replace()
        vault = read_vault(self.vault_path)
        rotated = (
            "vault_awg_entry_exit_private_key", "vault_awg_entry_exit_peer_public_key",
            "vault_awg_entry_exit_entry_public_key", "vault_awg_entry_exit_psk",
            "vault_awg_exit_private_key", "vault_awg3_header_protection_key",
        )
        for key in rotated:
            self.assertNotEqual(vault[key], before[key], key)
        # Обе стороны согласованы между собой.
        self.assertEqual(
            deploy.awg_public_key(vault["vault_awg_exit_private_key"]),
            vault["vault_awg_entry_exit_peer_public_key"],
        )
        self.assertEqual(
            deploy.awg_public_key(vault["vault_awg_entry_exit_private_key"]),
            vault["vault_awg_entry_exit_entry_public_key"],
        )
        self.assertEqual(
            vault["vault_exit_peers"],
            [{
                "name": "entry",
                "public_key": vault["vault_awg_entry_exit_entry_public_key"],
                "allowed_ips": ["10.77.0.2/32"],
                "preshared_key": vault["vault_awg_entry_exit_psk"],
            }],
        )
        # Ключи обмена долями хранилища у нового сервера будут свои: запись
        # прежнего убрана, её создаст следующий шаг deploy.
        self.assertEqual(vault["vault_runtime_exchange_private_keys"], {"entry-managed": "entry-exchange"})
        self.assertEqual(vault["vault_runtime_exchange_public_keys"], {"entry-managed": "entry-exchange-pub"})
        with mock.patch("builtins.print"):
            deploy.ensure_runtime_secret_material(self.production, self.vault_password)
        renewed = read_vault(self.vault_path)["vault_runtime_exchange_private_keys"]["exit-managed"]
        self.assertNotEqual(renewed, "old-exit-exchange")
        # Учётные записи те же, что на прежнем EXIT, и остальной Vault не тронут.
        for key in ("vault_exit_kalimera_password", "vault_exit_kalimera_password_hash",
                    "vault_exit_root_password_hash", "vault_entry_kalimera_password",
                    "vault_runtime_secret_shares", "vault_runtime_secret_key_sha256"):
            self.assertEqual(vault[key], before[key], key)

    def test_owner_is_told_what_stays_on_the_old_server(self) -> None:
        self.replace()
        text = " ".join(self.panel.call_args.args[1])
        self.assertIn(f"Прежний сервер ({OLD}) не изменяется", text)
        self.assertIn("удалите его у хостера", text)
        # Без резервного EXIT замена - это перерыв, и об этом сказано до вопроса.
        self.assertIn("зарубежный трафик не будет работать", text)
        self.confirmed.assert_called_once_with("Заменить основной EXIT новым сервером", False)

    def test_declined_replacement_changes_nothing(self) -> None:
        before = self.snapshot()
        with self.assertRaises(SystemExit) as stopped:
            self.replace(confirmations=(False,))
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.events, [])

    def test_server_that_refuses_the_key_changes_nothing(self) -> None:
        # Неверный пароль, закрытый порт, сервер ещё не готов: всё это выясняется до
        # того, как inventory и Vault перестанут описывать работающий каскад.
        before = self.snapshot()
        with self.assertRaises(SystemExit):
            self.replace(bootstrap=SystemExit("Не удалось установить SSH-ключ"))
        self.assertEqual(self.snapshot(), before)

    def test_lossy_route_is_reported_before_anything_changes(self) -> None:
        before = self.snapshot()
        lossy = {"count": 100, "clean": 90, "slow": 8, "failed": 2, "rtt_ms": 90}
        with self.assertRaises(SystemExit) as stopped:
            self.replace(confirmations=(True, False), route=lossy)
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("bootstrap", self.events)
        self.assertIn("Новый основной EXIT не подключён", self.printed.call_args.args[0])

    def test_address_of_another_cascade_server_is_refused(self) -> None:
        before = self.snapshot()
        for taken in ("192.0.2.10", "192.0.2.30"):
            with self.assertRaises(SystemExit) as stopped:
                self.replace(address=taken)
            self.assertIn("уже занят другим сервером каскада", str(stopped.exception))
        self.assertEqual(self.snapshot(), before)

    def test_reinstalled_server_on_the_same_address_is_confirmed(self) -> None:
        before = self.snapshot()
        with self.assertRaises(SystemExit) as stopped:
            self.replace(address=OLD, confirmations=(True, False))
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(self.replace(address=OLD, confirmations=(True, True)))
        self.assertEqual(
            self.confirmed.call_args.args[0],
            "Адрес совпадает с нынешним основным EXIT. Сервер переустановлен начисто",
        )
        # Переустановленный сервер предъявит новый ключ узла: прежняя запись о нём
        # убирается до первого подключения.
        self.assertEqual(self.events, [f"forget {OLD} [22, 56777]", "bootstrap"])
        self.assertEqual(self.primary()["ansible_host"], OLD)

    def test_sudo_user_gets_its_password_into_the_vault(self) -> None:
        self.replace(user="ubuntu")
        self.assertEqual(self.primary()["ansible_user"], "ubuntu")
        self.assertEqual(self.primary()["ansible_become_password"], "{{ vault_exit_become_password }}")
        self.assertEqual(read_vault(self.vault_path)["vault_exit_become_password"], "initial-password")

    def test_userspace_transit_is_refused(self) -> None:
        entry = deploy.load_yaml(self.entry_path)
        entry["awg3_transit_enabled"] = True
        deploy.yaml_write(self.entry_path, entry)
        before = self.snapshot()
        with self.assertRaises(SystemExit) as stopped:
            self.replace()
        self.assertIn("kernel-модулем AmneziaWG", str(stopped.exception))
        self.assertEqual(self.snapshot(), before)


class ReplaceWithStandbyTests(ReplaceCase):
    def setUp(self) -> None:
        super().setUp()
        self.enable()
        self.dns = {}

    def test_traffic_on_the_primary_stops_the_replacement(self) -> None:
        # Deploy удерживает путь от переключения: трафик, оставшийся на основном
        # EXIT, не шёл бы никуда до конца установки нового сервера.
        self.traffic_through("awg3")
        before = self.snapshot()
        with self.assertRaises(SystemExit) as stopped:
            self.replace()
        self.assertIn("exit-path use standby", str(stopped.exception))
        self.assertIn("exit-path auto", str(stopped.exception))
        self.assertEqual(self.snapshot(), before)

    def test_standby_carries_the_traffic_and_stays_untouched(self) -> None:
        self.traffic_through("awg4")
        hosts_before = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"]
        entry_before = deploy.load_yaml(self.entry_path)
        vault_before = read_vault(self.vault_path)
        self.assertTrue(self.replace())
        hosts = deploy.load_yaml(self.hosts_path)["all"]["children"]["exit"]["hosts"]
        self.assertEqual(list(hosts), ["exit-managed", deploy.STANDBY_EXIT_HOST])
        self.assertEqual(hosts[deploy.STANDBY_EXIT_HOST], hosts_before[deploy.STANDBY_EXIT_HOST])
        entry = deploy.load_yaml(self.entry_path)
        for key, value in entry_before.items():
            if key.startswith("entry_standby_exit_"):
                self.assertEqual(entry[key], value, key)
        vault = read_vault(self.vault_path)
        for key in deploy.STANDBY_EXIT_VAULT_KEYS:
            if key in vault_before:
                self.assertEqual(vault[key], vault_before[key], key)
        # S4 у обоих туннелей по-прежнему один: MTU каскада общий.
        self.assertEqual(
            entry["entry_awg1_obfuscation"]["s4"], entry["entry_standby_exit_obfuscation"]["s4"]
        )
        text = " ".join(self.panel.call_args.args[1])
        self.assertIn("трафик всё это время идёт через резервный EXIT", text)
        self.assertNotIn("не будет работать", text)

    def test_address_of_the_standby_is_refused(self) -> None:
        self.traffic_through("awg4")
        before = self.snapshot()
        with self.assertRaises(SystemExit) as stopped:
            self.replace(address=STANDBY)
        self.assertIn("уже занят другим сервером каскада", str(stopped.exception))
        self.assertEqual(self.snapshot(), before)


class ReplaceWithFallbackTransportTests(ReplaceCase):
    """Запасной транспорт: имя должно указывать на новый адрес, ключ - новый."""

    def setUp(self) -> None:
        super().setUp()
        self.enable()
        self.traffic_through("awg4")
        hosts = deploy.load_yaml(self.hosts_path)
        exit_hosts = hosts["all"]["children"]["exit"]["hosts"]
        exit_hosts["exit-managed"]["transit_tls_server_name"] = "st-4k7m2x.example.com"
        exit_hosts[deploy.STANDBY_EXIT_HOST]["transit_tls_server_name"] = "lm-9vu8g1.example.com"
        deploy.yaml_write(self.hosts_path, hosts)
        all_vars = deploy.load_yaml(self.all_path)
        all_vars.update({"transit_tls_enabled": True, "transit_tls_port": 443})
        deploy.yaml_write(self.all_path, all_vars)
        vault = read_vault(self.vault_path)
        vault[deploy.TRANSIT_TLS_VAULT_KEY] = {
            "exit-managed": {"uuid": "old-uuid", "certificate": "old-cert", "private_key": "old-key"},
            deploy.STANDBY_EXIT_HOST: {"uuid": "standby-uuid", "certificate": "standby-cert",
                                       "private_key": "standby-key"},
        }
        write_vault(self.vault_path, vault)

    def test_name_that_still_points_at_the_old_address_stops_the_replacement(self) -> None:
        self.dns = {"st-4k7m2x.example.com": OLD}
        before = self.snapshot()
        with self.assertRaises(SystemExit) as stopped:
            self.replace(tls_name="st-4k7m2x.example.com")
        self.assertIn(f"указывает на {OLD}, а адрес нового EXIT - {NEW}", str(stopped.exception))
        self.assertIn("Исправьте A-запись", str(stopped.exception))
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("bootstrap", self.events)
        # Прежнее имя предложено по умолчанию: обычно меняют запись, а не имя.
        self.assertEqual(self.asked.call_args.args[1], "st-4k7m2x.example.com")

    def test_new_server_gets_its_own_certificate_and_identifier(self) -> None:
        self.dns = {"st-4k7m2x.example.com": NEW}
        self.assertTrue(self.replace(tls_name="st-4k7m2x.example.com"))
        material = read_vault(self.vault_path)[deploy.TRANSIT_TLS_VAULT_KEY]
        self.assertEqual(
            material[deploy.STANDBY_EXIT_HOST],
            {"uuid": "standby-uuid", "certificate": "standby-cert", "private_key": "standby-key"},
        )
        new = material["exit-managed"]
        self.assertNotEqual(new["uuid"], "old-uuid")
        self.assertIn("BEGIN CERTIFICATE", new["certificate"])
        self.assertIn("PRIVATE KEY", new["private_key"])
        self.assertEqual(self.primary()["transit_tls_server_name"], "st-4k7m2x.example.com")

    def test_another_name_may_be_given_but_not_the_standby_one(self) -> None:
        self.dns = {"nw-7q2c5d.example.com": NEW, "lm-9vu8g1.example.com": NEW}
        before = self.snapshot()
        with self.assertRaises(SystemExit) as stopped:
            self.replace(tls_name="lm-9vu8g1.example.com")
        self.assertIn("своё имя запасного транспорта", str(stopped.exception))
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(self.replace(tls_name="nw-7q2c5d.example.com"))
        self.assertEqual(self.primary()["transit_tls_server_name"], "nw-7q2c5d.example.com")


class CommandTests(unittest.TestCase):
    def test_admin_gateway_allows_the_command(self) -> None:
        gateway = (
            ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("'--resume --replace-exit'|", gateway)
        self.assertIn("--replace-exit,", gateway)

    def test_command_runs_alone_and_before_the_secret_material_step(self) -> None:
        source = (ROOT / "scripts" / "lib" / "interactive_deploy.py").read_text(encoding="utf-8")
        # Команда спрашивает данные сервера: она не объединяется с другими.
        self.assertIn('("--replace-exit", args.replace_exit),', source)
        # Ключи обмена долями новому серверу создаёт шаг, который идёт следом.
        self.assertLess(
            source.index("replace_exit(production, vault_password)"),
            source.index("ensure_runtime_secret_material(production, vault_password)\n        pending"),
        )


class SelectorAddressChangeTests(TransportCase):
    """Переключатель путей: у пути сменился адрес сервера."""

    def on_tls(self) -> None:
        self.steps(3)
        self.passes[("primary", "awg")] = self.passes[("primary", "tls")] = False
        self.until(lambda state: state["paths"]["primary"]["transport"] == "tls")

    def replace_server(self) -> None:
        self.cfg.paths["primary"]["transports"][0]["endpoint"] = f"{NEW}:443"

    def test_path_stuck_on_tls_of_the_old_server_starts_the_new_one_on_direct(self) -> None:
        # Найдено при разборе замены: прежний сервер недоступен, путь по очереди
        # пробует оба транспорта и к моменту замены может числиться на запасном.
        # Сторож на только что установленном EXIT держит открытым прямой, а deploy
        # транспорт не меняет: без сброса туннель до нового сервера не поднялся бы.
        self.on_tls()
        self.messages.clear()
        self.replace_server()
        with mock.patch.object(selector, "deploy_in_progress", return_value=True):
            state = self.step()
        self.assertEqual(state["paths"]["primary"]["transport"], "awg")
        self.assertEqual(state["paths"]["primary"]["direct_endpoint"], f"{NEW}:443")
        self.assertIn("основной EXIT: адрес сервера сменился", self.messages[0])
        # Прямой транспорт прежнего сервера на ENTRY больше не закрыт, нового - не закрывался.
        self.assertEqual(self.closed[-1], [])
        self.assertEqual(self.applied[-2:], [("primary", "awg"), ("standby", "awg")])
        # Новый сервер ответил: путь работает на прямом транспорте.
        self.passes[("primary", "awg")] = True
        state = self.step()
        self.assertEqual(state["paths"]["primary"]["fail"], 0)
        self.assertEqual(state["paths"]["primary"]["transport"], "awg")

    def test_unchanged_address_resets_nothing(self) -> None:
        self.on_tls()
        since = selector.read_state(self.cfg)["paths"]["primary"]["transport_since"]
        state = self.step()
        self.assertEqual(state["paths"]["primary"]["transport"], "tls")
        self.assertEqual(state["paths"]["primary"]["transport_since"], since)

    def test_first_check_after_an_upgrade_only_records_the_address(self) -> None:
        # Состояние прежней версии адреса не содержит: это не замена сервера.
        self.on_tls()
        state = selector.read_state(self.cfg)
        state["paths"]["primary"]["direct_endpoint"] = None
        selector.write_state(self.cfg, state)
        state = self.step()
        self.assertEqual(state["paths"]["primary"]["transport"], "tls")
        self.assertEqual(state["paths"]["primary"]["direct_endpoint"], "198.51.100.1:443")

    def test_traffic_waits_for_the_new_server_to_answer(self) -> None:
        self.steps(3)
        self.replace_server()
        self.passes[("primary", "awg")] = False
        state = self.steps(4)
        # Путь на новом адресе ещё не отвечал: устойчивым он не считается, и трафик
        # ушёл на резервный, как при обычном отказе.
        self.assertIsNone(state["paths"]["primary"]["healthy_since"])
        self.assertEqual(state["active"], "standby")


if __name__ == "__main__":
    unittest.main()

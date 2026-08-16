#!/usr/bin/env python3
from __future__ import annotations

import base64
import importlib.util
import os
import pty
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from ansible.parsing.vault import VaultLib, VaultSecret


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "lib" / "interactive_deploy.py"
SPEC = importlib.util.spec_from_file_location("interactive_deploy", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InteractiveDeployTests(unittest.TestCase):
    def test_local_entry_public_ipv4_uses_route_source_not_loopback(self) -> None:
        connection = mock.Mock()
        connection.getsockname.return_value = ("198.51.100.44", 49152)
        with (
            mock.patch.object(
                MODULE.socket,
                "getaddrinfo",
                return_value=[
                    (
                        MODULE.socket.AF_INET,
                        MODULE.socket.SOCK_DGRAM,
                        17,
                        "",
                        ("198.51.100.20", 0),
                    )
                ],
            ),
            mock.patch.object(MODULE.socket, "socket", return_value=connection),
            mock.patch.object(
                MODULE.ipaddress,
                "ip_address",
                return_value=mock.Mock(is_global=True),
            ),
        ):
            self.assertEqual(
                MODULE.detect_local_public_ipv4("exit.example.invalid"),
                "198.51.100.44",
            )
        connection.connect.assert_called_once_with(("198.51.100.20", 443))
        connection.close.assert_called_once()

    def test_local_entry_behind_nat_requires_explicit_public_endpoint(self) -> None:
        connection = mock.Mock()
        connection.getsockname.return_value = ("10.0.0.10", 49152)
        with (
            mock.patch.object(
                MODULE.socket, "getaddrinfo", side_effect=MODULE.socket.gaierror
            ),
            mock.patch.object(MODULE.socket, "socket", return_value=connection),
        ):
            self.assertEqual(MODULE.detect_local_public_ipv4("unresolved.invalid"), "")

    def test_ssh_transition_skips_root_loopback_probe_for_local_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = root / "inventory" / "production"
            all_root = production / "group_vars" / "all"
            all_root.mkdir(parents=True)
            hosts_path = production / "hosts.yml"
            vault_password = root / "vault.pass"
            private_key = root / "automation-key"
            vault_password.write_text("fixture\n", encoding="utf-8")
            private_key.write_text("fixture\n", encoding="utf-8")
            MODULE.yaml_write(
                all_root / "main.yml",
                {
                    "security_manage_admin_account": True,
                    "security_finalize_admin_access": False,
                },
            )
            hosts_document = {
                "all": {
                    "children": {
                        "entry": {
                            "hosts": {
                                "entry-managed": {
                                    "ansible_host": "127.0.0.1",
                                    "ansible_connection": "local",
                                    "ansible_user": "root",
                                    "ansible_port": 22,
                                    "ssh_listen_port": 56777,
                                    "ansible_ssh_private_key_file": str(private_key),
                                    "security_allow_ssh_port_change": True,
                                }
                            }
                        },
                        "exit": {
                            "hosts": {
                                "exit-managed": {
                                    "ansible_host": "198.51.100.20",
                                    "ansible_user": "root",
                                    "ansible_port": 22,
                                    "ssh_listen_port": 56778,
                                    "ansible_ssh_private_key_file": str(private_key),
                                    "security_allow_ssh_port_change": True,
                                }
                            }
                        },
                    }
                }
            }
            MODULE.yaml_write(hosts_path, hosts_document)
            with (
                mock.patch.object(MODULE, "ansible"),
                mock.patch.object(MODULE, "check_ssh") as check_ssh,
                mock.patch.object(MODULE, "require_operator_ssh_confirmation"),
                mock.patch.object(MODULE, "remove_bootstrap_become_passwords"),
            ):
                self.assertTrue(
                    MODULE.complete_ssh_transition(
                        root / "repo",
                        hosts_path,
                        vault_password,
                        hosts_document,
                        root / "mtu.yml",
                        root / "package-lock.txt",
                    )
                )

            check_ssh.assert_called_once_with(
                "198.51.100.20", "root", 56778, private_key
            )
            updated = MODULE.load_yaml(hosts_path)
            entry = updated["all"]["children"]["entry"]["hosts"]["entry-managed"]
            self.assertEqual(entry["ansible_port"], 56777)
            self.assertTrue(entry["ansible_connection"] == "local")

    def test_generated_account_password_has_all_required_character_classes(self) -> None:
        password = MODULE.generate_account_password(30)
        self.assertEqual(len(password), 30)
        self.assertRegex(password, r"[a-z]")
        self.assertRegex(password, r"[A-Z]")
        self.assertRegex(password, r"[0-9]")
        self.assertRegex(password, r"[!@#$%^&*_+=-]")
        with self.assertRaises(ValueError):
            MODULE.generate_account_password(24)

    def test_component_update_uses_candidate_awg_and_stable_sing_box(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            production = repo / "inventory" / "production"
            example = repo / "inventory" / "example"
            all_vars_path = production / "group_vars" / "all" / "main.yml"
            entry_vars_path = production / "group_vars" / "entry.yml"
            stable_entry_path = example / "group_vars" / "entry.yml"
            awg3_defaults_path = repo / "roles" / "awg3_transit" / "defaults" / "main.yml"
            all_vars_path.parent.mkdir(parents=True)
            stable_entry_path.parent.mkdir(parents=True)
            awg3_defaults_path.parent.mkdir(parents=True)
            MODULE.yaml_write(
                all_vars_path,
                {
                    "awg_package_version_mode": "pinned",
                    "awg_package_versions": {"amneziawg": "old"},
                },
            )
            MODULE.yaml_write(
                entry_vars_path,
                {
                    "entry_sing_box_version": "1.0.0",
                    "entry_sing_box_packages": {"x86_64": {"url": "old"}},
                },
            )
            MODULE.yaml_write(
                stable_entry_path,
                {
                    "entry_sing_box_version": "2.0.0",
                    "entry_sing_box_packages": {
                        "x86_64": {"url": "new", "checksum": "sha256:test"}
                    },
                },
            )
            MODULE.yaml_write(
                awg3_defaults_path,
                {
                    "awg3_go_version": "1.25.12",
                    "awg3_go_archives": {"x86_64": {"checksum": "sha256:go"}},
                    "awg3_go_source_version": "v3",
                    "awg3_go_source_commit": "a" * 40,
                    "awg3_tools_source_version": "v3",
                    "awg3_tools_source_commit": "b" * 40,
                },
            )

            MODULE.prepare_component_update(repo, production)

            all_vars = MODULE.load_yaml(all_vars_path)
            entry_vars = MODULE.load_yaml(entry_vars_path)
            self.assertEqual(all_vars["awg_package_version_mode"], "candidate")
            self.assertNotIn("awg_package_versions", all_vars)
            self.assertEqual(entry_vars["entry_sing_box_version"], "2.0.0")
            self.assertEqual(entry_vars["entry_sing_box_packages"]["x86_64"]["url"], "new")
            self.assertEqual(all_vars["awg3_go_source_commit"], "a" * 40)

    def test_failed_component_update_restores_inventory_and_runs_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            home = root / "home"
            production = repo / "inventory" / "production"
            all_vars_path = production / "group_vars" / "all" / "main.yml"
            entry_vars_path = production / "group_vars" / "entry.yml"
            vault_path = production / "group_vars" / "all" / "vault.yml"
            hosts_path = production / "hosts.yml"
            stable_entry_path = (
                repo / "inventory" / "example" / "group_vars" / "entry.yml"
            )
            awg3_defaults_path = (
                repo / "roles" / "awg3_transit" / "defaults" / "main.yml"
            )
            awg3_defaults_path.parent.mkdir(parents=True)
            stable_entry_path.parent.mkdir(parents=True)
            original_all = {
                "awg_package_version_mode": "pinned",
                "awg_package_versions": {
                    "amneziawg": "old",
                    "amneziawg_dkms": "old",
                    "amneziawg_tools": "old",
                },
                "security_admin_authorized_keys": ["ssh-ed25519 fixture"],
                "security_require_admin_authorized_key": True,
            }
            original_entry = {
                "entry_sing_box_version": "1.0.0",
                "entry_sing_box_packages": {"x86_64": {"url": "old"}},
            }
            MODULE.yaml_write(all_vars_path, original_all)
            MODULE.yaml_write(entry_vars_path, original_entry)
            MODULE.yaml_write(
                stable_entry_path,
                {
                    "entry_sing_box_version": "2.0.0",
                    "entry_sing_box_packages": {"x86_64": {"url": "new"}},
                },
            )
            awg3_manifest = {
                "awg3_go_version": "1.25.12",
                "awg3_go_archives": {"x86_64": {"checksum": "sha256:go"}},
                "awg3_go_source_version": "v3",
                "awg3_go_source_commit": "a" * 40,
                "awg3_tools_source_version": "v3",
                "awg3_tools_source_commit": "b" * 40,
            }
            MODULE.yaml_write(awg3_defaults_path, awg3_manifest)
            MODULE.yaml_write(
                hosts_path,
                {
                    "all": {
                        "children": {
                            "entry": {
                                "hosts": {
                                    "entry-managed": {
                                        "security_allow_ssh_port_change": False
                                    }
                                }
                            },
                            "exit": {
                                "hosts": {
                                    "exit-managed": {
                                        "security_allow_ssh_port_change": False
                                    }
                                }
                            },
                        }
                    }
                },
            )
            vault_path.write_text("$ANSIBLE_VAULT;1.1;AES256\n", encoding="utf-8")
            vault_password = home / ".config" / "awg-iac" / "production-vault.pass"
            vault_password.parent.mkdir(parents=True)
            vault_password.write_text("fixture\n", encoding="utf-8")
            package_lock = (
                home
                / ".local"
                / "share"
                / "awg-iac"
                / "production"
                / "amneziawg-package-lock.txt"
            )
            package_lock.parent.mkdir(parents=True)
            original_lock = (
                "amneziawg=old\namneziawg-dkms=old\namneziawg-tools=old\n"
            )
            package_lock.write_text(original_lock, encoding="utf-8")

            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.object(MODULE, "migrate_production_inventory"),
                mock.patch.object(MODULE, "ensure_runtime_secret_material"),
                mock.patch.object(MODULE, "ensure_admin_account_material"),
                mock.patch.object(MODULE, "complete_ssh_transition", return_value=False),
                mock.patch.object(
                    MODULE,
                    "ansible",
                    side_effect=[SystemExit("candidate failed"), None, None],
                ) as ansible_run,
                mock.patch.object(MODULE, "cleanup_deployment"),
                mock.patch.object(MODULE.atexit, "register"),
                mock.patch.object(MODULE.atexit, "unregister"),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "interactive_deploy.py",
                        "--repo-root",
                        str(repo),
                        "--resume",
                        "--update-components",
                    ],
                ),
            ):
                with self.assertRaisesRegex(SystemExit, "Предыдущая рабочая версия"):
                    MODULE.main()

            self.assertEqual(MODULE.load_yaml(all_vars_path), original_all)
            self.assertEqual(MODULE.load_yaml(entry_vars_path), original_entry)
            self.assertEqual(package_lock.read_text(encoding="utf-8"), original_lock)
            self.assertEqual(ansible_run.call_count, 3)
            rollback_extra = ansible_run.call_args_list[1].args[4]
            self.assertIs(rollback_extra["awg_package_rollback"], True)
            self.assertIs(rollback_extra["awg_package_refresh"], False)
            self.assertEqual(
                rollback_extra["awg_package_transaction_id"],
                ansible_run.call_args_list[0].args[4]["awg_package_transaction_id"],
            )

    def test_terminal_only_updates_role_without_full_deployment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            home = root / "home"
            production = repo / "inventory" / "production"
            (production / "group_vars" / "all").mkdir(parents=True)
            (production / "hosts.yml").write_text("all: {}\n", encoding="utf-8")
            (production / "group_vars" / "all" / "vault.yml").write_text(
                "$ANSIBLE_VAULT;1.1;AES256\n", encoding="utf-8"
            )
            vault_password = home / ".config" / "awg-iac" / "production-vault.pass"
            vault_password.parent.mkdir(parents=True)
            vault_password.write_text("test-only\n", encoding="utf-8")

            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.object(MODULE, "ansible") as ansible_run,
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "interactive_deploy.py",
                        "--repo-root",
                        str(repo),
                        "--terminal-only",
                    ],
                ),
            ):
                MODULE.main()

            ansible_run.assert_called_once_with(
                repo.resolve(),
                production / "hosts.yml",
                vault_password,
                "playbooks/terminal.yml",
            )

    def test_validation_does_not_require_executable_secret_scanner(self) -> None:
        repository = MODULE_PATH.parents[2]
        validation = (repository / "scripts" / "validate.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("bash ./scripts/check-secrets.sh", validation)

    def test_telegram_credentials_require_full_token_and_numeric_chat_id(self) -> None:
        token = "1234567890:" + "A" * 24
        self.assertTrue(MODULE.telegram_credentials_valid(token, "123456789"))
        self.assertTrue(MODULE.telegram_credentials_valid(token, "-1001234567890"))
        self.assertFalse(
            MODULE.telegram_credentials_valid("1234567890", "123456789")
        )
        self.assertFalse(MODULE.telegram_credentials_valid(token, "not-a-chat-id"))

    def test_telegram_chat_is_discovered_from_latest_update(self) -> None:
        updates = [
            {"update_id": 1, "message": {"chat": {"id": 100, "first_name": "Old"}}},
            {
                "update_id": 2,
                "message": {
                    "chat": {"id": -100200300, "title": "Kalimera", "type": "group"}
                },
            },
        ]
        self.assertEqual(
            MODULE.telegram_latest_chat_from_updates(updates),
            ("-100200300", "Kalimera"),
        )
        self.assertIsNone(MODULE.telegram_latest_chat_from_updates([]))

    def test_installer_explains_personal_bot_creation(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("официальный @BotFather", source)
        self.assertIn("Отправьте команду /newbot", source)
        self.assertIn("KalimeraWG не предоставляет общего бота", source)

    def test_telegram_monitor_starts_only_after_final_configuration(self) -> None:
        root = MODULE_PATH.parents[2]
        source = MODULE_PATH.read_text(encoding="utf-8")
        operations = (root / "roles/operations/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        finalizer = (root / "playbooks/finalize-monitoring.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('"awg_telegram_monitor_start_immediately": False', source)
        self.assertIn('"playbooks/finalize-monitoring.yml"', source)
        verify_positions = [
            match.start()
            for match in re.finditer('"playbooks/verify.yml"', source)
        ]
        finalizer_positions = [
            match.start()
            for match in re.finditer('"playbooks/finalize-monitoring.yml"', source)
        ]
        self.assertEqual(len(finalizer_positions), 2)
        for finalizer_position in finalizer_positions:
            self.assertTrue(any(position < finalizer_position for position in verify_positions))
            self.assertTrue(any(position > finalizer_position for position in verify_positions))
        self.assertIn("awg_telegram_monitor_start_immediately", operations)
        self.assertIn('content: "healthy\\n"', finalizer)
        self.assertIn("/proc/sys/kernel/random/boot_id", finalizer)
        self.assertIn("Включение Telegram-мониторинга", finalizer)
        self.assertIn("telegram_monitor_deferred_flag", finalizer)

    def test_telegram_monitor_reports_reboot_and_automatic_fail_open(self) -> None:
        repository = MODULE_PATH.parents[2]
        monitor = (
            repository / "roles/operations/templates/telegram-monitor.sh.j2"
        ).read_text(encoding="utf-8")
        timer = (
            repository / "roles/operations/templates/telegram-monitor.timer.j2"
        ).read_text(encoding="utf-8")
        operations = (repository / "roles/operations/tasks/main.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("current=degraded", monitor)
        self.assertIn("PROXY_DISABLED_FLAG", monitor)
        self.assertIn("PROXY_MANUAL_FLAG", monitor)
        self.assertIn("сервер перезапущен", monitor)
        self.assertNotIn('host="$(hostname', monitor)
        self.assertIn("[BOT_TOKEN]", monitor)
        self.assertIn("RU-прокси восстановлен", monitor)
        self.assertIn('case "${0##*/}:${1:-}"', monitor)
        self.assertIn("telegram-test:--help", monitor)
        self.assertIn("Persistent=true", timer)
        self.assertIn("dest: /usr/local/sbin/telegram-test", operations)

    def test_terminal_role_is_pinned_and_preserves_shell_files(self) -> None:
        repository = MODULE_PATH.parents[2]
        defaults = (
            repository / "roles" / "terminal" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        tasks = (
            repository / "roles" / "terminal" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("d69e4d549a1881a37300fe6b4a05478bd9157dfc", defaults)
        self.assertIn("{{ awg_backup_root }}/terminal", defaults)
        self.assertIn("ansible.builtin.blockinfile", tasks)
        common_defaults = (
            repository / "roles" / "common" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("/root/config-backups", common_defaults)
        self.assertNotIn("dest: /root/.profile", tasks)
        self.assertNotIn("dest: /root/.blerc", tasks)

    def test_updates_guard_next_kernel_and_ufw_keeps_icmp_policy(self) -> None:
        repository = MODULE_PATH.parents[2]
        operations = (repository / "roles/operations/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        guard = (
            repository / "roles/operations/templates/awg-kernel-guard.sh.j2"
        ).read_text(encoding="utf-8")
        update_all = (
            repository / "roles/operations/templates/update-all.sh.j2"
        ).read_text(encoding="utf-8")
        maintenance = (
            repository / "roles/operations/templates/maintenance.sh.j2"
        ).read_text(encoding="utf-8")
        security = (repository / "roles/security/tasks/main.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("awg-kernel-guard.sh.j2", operations)
        self.assertIn(
            "ansible.builtin.command: /usr/local/sbin/awg-kernel-guard", operations
        )
        self.assertIn("readlink -f /vmlinuz", guard)
        self.assertIn('linux-headers-$kernel_release', guard)
        self.assertIn("dkms status", guard)
        self.assertIn("'^amneziawg/'", guard)
        self.assertIn("dpkg-query -W", guard)
        self.assertIn("/lib/modules/*", guard)
        self.assertIn("linux-image-unsigned-", guard)
        self.assertNotIn("Пакет amneziawg-dkms не установлен", guard)
        self.assertIn('dkms autoinstall -k "$kernel_release"', guard)
        self.assertIn('modinfo -k "$kernel_release" amneziawg', guard)
        self.assertIn("/usr/local/sbin/awg-kernel-guard", update_all)
        self.assertIn("/usr/local/sbin/awg-kernel-guard", maintenance)
        self.assertIn("path: /etc/ufw/sysctl.conf", security)
        self.assertIn("line: net/ipv4/icmp_echo_ignore_all=1", security)

    def test_deploy_uses_fail_open_only_for_transient_proxy_errors(self) -> None:
        repository = MODULE_PATH.parents[2]
        operations = (repository / "roles/operations/tasks/main.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("operations_ru_proxy_udp_existing_state", operations)
        self.assertIn(
            "operations_ru_proxy_capability.rc not in [0, 68, 69]",
            operations,
        )
        self.assertIn(
            "operations_ru_proxy_capability.rc | default(0) in [68, 69]",
            operations,
        )
        self.assertIn(
            "not operations_ru_proxy_udp_existing_state.stat.exists", operations
        )
        self.assertIn("content: \"direct\\n\"", operations)
        self.assertIn("watchdog применит общий fail-open", operations)

    def test_non_tty_ui_never_emits_escape_sequences(self) -> None:
        with (
            mock.patch.object(MODULE.sys.stdout, "isatty", return_value=False),
            mock.patch("builtins.print") as output,
        ):
            MODULE.ui_panel("ПРОВЕРКА", ["без цвета"], "magenta")
        rendered = "\n".join(
            str(argument)
            for call in output.call_args_list
            for argument in call.args
        )
        self.assertNotIn("\x1b", rendered)
        self.assertIn("ПРОВЕРКА", rendered)

    def test_resume_migrates_known_unstable_ru_tun_stack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            production = Path(directory) / "production"
            entry_path = production / "group_vars" / "entry.yml"
            entry_path.parent.mkdir(parents=True)
            entry_path.write_text(
                "entry_ru_tun_stack: mixed\n"
                "entry_ru_endpoint_independent_nat: false\n"
                "entry_mobile_client_available: true\n"
                "entry_mobile_client_public_port: 53\n"
                "entry_mobile_client_internal_port: 39746\n"
                "entry_mobile_i1_mode: quic-ios-test\n"
                "entry_awg0_obfuscation:\n"
                "  i1: '<b 0xc1><r 1161>'\n",
                encoding="utf-8",
            )
            exit_path = production / "group_vars" / "exit.yml"
            exit_path.write_text(
                "awg3_transit_obfuscation:\n"
                "  i1: '<b 0xc1><r 1161>'\n",
                encoding="utf-8",
            )
            self.assertTrue(MODULE.migrate_production_inventory(production))
            migrated = yaml.safe_load(entry_path.read_text(encoding="utf-8"))
            self.assertEqual(migrated["entry_ru_tun_stack"], "gvisor")
            self.assertIs(migrated["entry_ru_endpoint_independent_nat"], True)
            self.assertEqual(migrated["entry_mobile_client_listen_port"], 8443)
            self.assertEqual(migrated["entry_mobile_legacy_public_port"], 53)
            self.assertEqual(migrated["entry_mobile_legacy_internal_port"], 39746)
            self.assertEqual(migrated["entry_mobile_i1_mode"], "quic-ios")
            self.assertNotIn("entry_mobile_client_public_port", migrated)
            self.assertNotIn("entry_mobile_client_internal_port", migrated)
            self.assertEqual(
                migrated["entry_awg0_obfuscation"]["i1"],
                "<b 0xc1><r 1000><r 161>",
            )
            migrated_exit = yaml.safe_load(exit_path.read_text(encoding="utf-8"))
            self.assertEqual(
                migrated_exit["awg3_transit_obfuscation"]["i1"],
                "<b 0xc1><r 1000><r 161>",
            )
            self.assertFalse(MODULE.migrate_production_inventory(production))

    def test_resume_can_add_missing_mobile_profile_and_encrypted_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            production = Path(directory) / "production"
            entry_path = production / "group_vars" / "entry.yml"
            vault_path = production / "group_vars" / "all" / "vault.yml"
            password_path = Path(directory) / "vault.pass"
            entry_path.parent.mkdir(parents=True)
            vault_path.parent.mkdir(parents=True)
            entry_path.write_text(
                "entry_client_subnet: 10.66.0.0/24\n"
                "entry_legacy_client_subnet: 10.67.0.0/24\n"
                "awg3_transit_address: 10.77.0.2/32\n"
                "entry_mobile_client_available: false\n",
                encoding="utf-8",
            )
            password = b"fixture-mobile-vault-password"
            password_path.write_bytes(password + b"\n")
            password_path.chmod(0o600)
            vault_lib = VaultLib([("default", VaultSecret(password))])
            vault_path.write_bytes(
                vault_lib.encrypt(
                    yaml.safe_dump(
                        {
                            "vault_awg_entry_private_key": "existing-private",
                            "vault_entry_client_peers": [],
                        },
                        sort_keys=False,
                    ).encode()
                )
            )
            vault_path.chmod(0o600)

            self.assertTrue(
                MODULE.enable_mobile_profile(production, password_path)
            )
            entry = yaml.safe_load(entry_path.read_text(encoding="utf-8"))
            self.assertTrue(entry["entry_mobile_client_available"])
            self.assertFalse(entry["entry_mobile_client_enabled"])
            self.assertEqual(entry["entry_mobile_client_subnet"], "10.68.0.0/24")
            self.assertEqual(entry["entry_mobile_client_address"], "10.68.0.1/24")
            self.assertEqual(entry["entry_mobile_client_listen_port"], 8443)
            self.assertEqual(entry["entry_mobile_i1_mode"], "quic-ios")
            self.assertIn("entry_mobile_awg_obfuscation", entry)

            decrypted = yaml.safe_load(vault_lib.decrypt(vault_path.read_bytes()))
            mobile_private = decrypted["vault_awg_entry_mobile_private_key"]
            self.assertTrue(mobile_private)
            self.assertEqual(decrypted["vault_entry_mobile_client_peers"], [])
            self.assertEqual(entry_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(vault_path.stat().st_mode & 0o777, 0o600)

            self.assertFalse(
                MODULE.enable_mobile_profile(production, password_path)
            )
            repeated = yaml.safe_load(vault_lib.decrypt(vault_path.read_bytes()))
            self.assertEqual(
                repeated["vault_awg_entry_mobile_private_key"], mobile_private
            )

    def test_resume_migrates_saved_client_cps_without_exposing_other_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clients = Path(directory) / "clients"
            clients.mkdir()
            config = clients / "client.conf"
            config.write_text(
                "[Interface]\n"
                "Address = 10.0.0.2/32\n"
                "I1 = <b 0xc1><r 1161>\n"
                "I2 = <r 99>\n",
                encoding="utf-8",
            )
            MODULE.update_saved_client_configs_cps(clients)
            migrated = config.read_text(encoding="utf-8")
            self.assertIn("Address = 10.0.0.2/32", migrated)
            self.assertIn("I1 = <b 0xc1><r 1000><r 161>", migrated)
            self.assertIn("I2 = <r 99>", migrated)

    def test_apt_wait_uses_one_quiet_remote_loop(self) -> None:
        site = (MODULE_PATH.parents[2] / "playbooks" / "site.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("awg_apt_wait_timeout_seconds", site)
        self.assertIn("/usr/bin/sleep 5", site)
        self.assertIn("unattended_upgrade_pattern=", site)
        self.assertIn("/usr/bin/unattended-upgrade([[:space:]]|$)", site)
        self.assertNotIn("pgrep -x unattended-upgr", site)
        self.assertNotIn("unattended-upgrade-shutdown", site)
        self.assertNotIn("FAILED - RETRYING", site)
        self.assertNotIn("retries: 120", site)

    @staticmethod
    def run_bash_readline(value: bytes) -> str:
        pid, descriptor = pty.fork()
        if pid == 0:
            os.execlp(
                "bash",
                "bash",
                "-c",
                'IFS= read -e -r value; printf "RESULT=<%s>\\n" "$value"',
            )

        os.write(descriptor, value)
        output = bytearray()
        while True:
            try:
                chunk = os.read(descriptor, 1024)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
        os.waitpid(pid, 0)
        os.close(descriptor)
        return output.decode(errors="replace")

    def test_bootstrap_readline_edits_with_backspace_and_arrows(self) -> None:
        deploy = (MODULE_PATH.parents[2] / "deploy").read_text(encoding="utf-8")
        self.assertIn("IFS= read -e -r answer", deploy)
        self.assertIn("openssl sshpass ssss", deploy)
        self.assertIn("RESULT=<user>", self.run_bash_readline(b"usea\x08r\n"))
        self.assertIn("RESULT=<usra>", self.run_bash_readline(b"usea\x1b[D\x08r\n"))

    def test_line_editing_accepts_both_backspace_encodings(self) -> None:
        readline = mock.Mock()
        with mock.patch.dict(sys.modules, {"readline": readline}):
            MODULE.configure_line_editing()

        readline.parse_and_bind.assert_has_calls(
            [
                mock.call('"\\C-h": backward-delete-char'),
                mock.call('"\\C-?": backward-delete-char'),
            ]
        )

    def test_fail_uses_clean_system_exit(self) -> None:
        with self.assertRaisesRegex(SystemExit, "проверка"):
            MODULE.fail("проверка")

    def test_public_firewall_address_requires_one_ipv4(self) -> None:
        with mock.patch.object(
            MODULE.socket,
            "getaddrinfo",
            return_value=[(MODULE.socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))],
        ):
            self.assertEqual(
                MODULE.resolve_single_public_ipv4("entry.example", "ENTRY"),
                "93.184.216.34",
            )
        with mock.patch.object(
            MODULE.socket,
            "getaddrinfo",
            return_value=[
                (MODULE.socket.AF_INET, 0, 0, "", ("93.184.216.34", 0)),
                (MODULE.socket.AF_INET, 0, 0, "", ("8.8.8.8", 0)),
            ],
        ):
            with self.assertRaisesRegex(SystemExit, "ровно в один"):
                MODULE.resolve_single_public_ipv4("entry.example", "ENTRY")

    def test_interserver_firewall_is_address_restricted(self) -> None:
        security = (
            MODULE_PATH.parents[2] / "roles" / "security" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('from_ip: "{{ security_interserver_peer_ipv4 }}"', security)
        self.assertIn('interface: "{{ entry_wan_interface if', security)
        self.assertIn("Удаление прежнего общего правила межсерверного AWG", security)
        self.assertIn("state: reset", security)
        self.assertIn("policy: deny\n    direction: incoming", security)
        self.assertIn("policy: deny\n    direction: routed", security)
        self.assertIn("policy: allow\n    direction: outgoing", security)
        self.assertIn('interface: "{{ awg3_transit_interface }}"', security)
        self.assertIn('from_ip: "{{ awg3_peer_tunnel_address }}"', security)
        transit = (
            MODULE_PATH.parents[2]
            / "roles"
            / "awg3_transit"
            / "templates"
            / "transit.conf.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("ListenPort = {{ awg3_transit_listen_port }}", transit)
        self.assertIn(
            "Endpoint = {{ awg3_peer_endpoint_host }}:{{ awg3_peer_endpoint_port }}",
            transit,
        )

    def test_runtime_policy_commands_reconcile_network_state(self) -> None:
        root = MODULE_PATH.parents[2]
        domains = (root / "roles/operations/templates/domain-admin.sh.j2").read_text(
            encoding="utf-8"
        )
        for set_name in ("force_ru", "force_exit", "force_entry_bank"):
            self.assertIn(f'ipset flush "$policy_set"', domains)
            self.assertIn(set_name, domains)
        self.assertIn("--defer", domains)
        self.assertIn("systemctl reset-failed dnsmasq.service", domains)

        profile = (root / "scripts/apply-policy-profile.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('"$command_name" add "$value" --defer', profile)
        self.assertIn("ru-domain sync", profile)
        self.assertIn("ru-direct-ports apply", profile)
        self.assertIn("restore_snapshot", profile)

        routing = (
            root / "roles/entry_routing/templates/awg-entry-routing.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertNotIn("--dports", routing)
        self.assertIn("flock -w 30 9", routing)
        self.assertNotIn("flock -n 9 || exit 0", routing)
        self.assertIn('for direct_port in "${DIRECT_PORTS[@]}"', routing)
        self.assertIn('PROXY_UDP_MODE" == direct', routing)

        proxy_set = (
            root / "roles/operations/templates/ru-proxy-set.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn('"$capability" --config "$tmp"', proxy_set)
        self.assertIn("--update-state", proxy_set)
        self.assertIn('"$routing" apply', proxy_set)
        self.assertIn('install -m 0600 "$override_tmp" "$override"', proxy_set)
        self.assertIn('systemctl stop "$watchdog_timer" "$watchdog_service"', proxy_set)
        self.assertIn("restore_runtime_flags", proxy_set)
        self.assertIn('printf \'0\\n\' >"$watchdog_state/failure.count"', proxy_set)

        vpn_user = (
            root / "roles/operations/templates/vpn-user.sh.j2"
        ).read_text(encoding="utf-8")
        peer_service = (
            root / "roles/operations/templates/awg-local-peer-apply.service.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("shopt -s nullglob", vpn_user)
        self.assertIn("Этап: %s; код: %s", vpn_user)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", vpn_user)
        self.assertNotIn("AllowedIPs = $server_address/32", vpn_user)
        self.assertIn('client_prefix="${subnet#*/}"', vpn_user)
        self.assertIn("Address = $client_ip/$client_prefix", vpn_user)
        self.assertNotIn(".service{% if", peer_service)
        self.assertIn(
            "After=awg-quick@{{ entry_legacy_client_interface }}.service",
            peer_service,
        )

        dns_defaults = (
            root / "roles/entry_dns/defaults/main.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("61-ru-split-dns.conf", dns_defaults)
        dns_policy = (
            root / "roles/operations/templates/awg-dns-policy.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("ru-domain sync", dns_policy)

        sing_box_tasks = (
            root / "roles/sing_box/tasks/main.yml"
        ).read_text(encoding="utf-8")
        dropin = (
            root / "roles/sing_box/templates/50-awg-routing-reconcile.conf.j2"
        ).read_text(encoding="utf-8")
        self.assertLess(
            sing_box_tasks.index("Связывание запуска sing-box"),
            sing_box_tasks.index("Применение: прокси sing-box — этап 17"),
        )
        self.assertIn("ExecStartPost=+/bin/sh -c", dropin)
        self.assertIn("try-restart awg-entry-routing.service", dropin)
        self.assertIn("|| true", dropin)

    def test_administrative_commands_are_safe_and_runtime_state_is_persistent(self) -> None:
        root = MODULE_PATH.parents[2]
        templates = root / "roles" / "operations" / "templates"
        operations = (root / "roles/operations/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        vpn_user = (templates / "vpn-user.sh.j2").read_text(encoding="utf-8")
        domains = (templates / "domain-admin.sh.j2").read_text(encoding="utf-8")
        dns_policy = (templates / "awg-dns-policy.sh.j2").read_text(
            encoding="utf-8"
        )
        peer_apply = (templates / "awg-local-peer-apply.sh.j2").read_text(
            encoding="utf-8"
        )
        dot = (templates / "dot-switch.sh.j2").read_text(encoding="utf-8")
        doh = (templates / "doh-switch.sh.j2").read_text(encoding="utf-8")
        dns_status = (templates / "dns-status.sh.j2").read_text(encoding="utf-8")
        fail2ban = (templates / "f2b-reset.sh.j2").read_text(encoding="utf-8")
        update_all = (templates / "update-all.sh.j2").read_text(encoding="utf-8")
        maintenance = (templates / "maintenance.sh.j2").read_text(encoding="utf-8")
        entry_dns_tasks = (root / "roles/entry_dns/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        sing_box_tasks = (root / "roles/sing_box/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        terminal_tasks = (root / "roles/terminal/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        shell_tools = (
            root / "roles/terminal/templates/kalimera-shell-tools.sh.j2"
        ).read_text(encoding="utf-8")
        terminal_help = (
            root / "roles/terminal/templates/kalimera-help.sh.j2"
        ).read_text(encoding="utf-8")
        terminal_status = (
            root / "roles/terminal/templates/kalimera-status.py.j2"
        ).read_text(encoding="utf-8")

        self.assertIn("vpn-user list", vpn_user)
        self.assertIn("vpn-user delete NAME [--yes]", vpn_user)
        self.assertIn('awg set "$iface" peer "$public_key" remove', vpn_user)
        self.assertIn("config-backups/entry/clients/deleted", vpn_user)
        self.assertIn("управляется зашифрованным inventory", vpn_user)
        self.assertIn('"$client_ip" "$profile" >"$peer_file"', vpn_user)
        self.assertIn("#_Profile", vpn_user)

        self.assertIn("restore_state", domains)
        self.assertIn("предыдущая конфигурация восстановлена", domains)
        self.assertIn("Изменение базовой DNS-политики отменено", dns_policy)
        self.assertIn("validate_directory", peer_apply)
        self.assertIn("ipaddress.ip_network", peer_apply)
        self.assertIn("entry_dns_dot_override_path", entry_dns_tasks)
        self.assertIn("sing_box_dns_override_path", sing_box_tasks)
        self.assertIn("dot-override.json", dot)
        self.assertIn("doh-override.json", doh)
        self.assertIn("sing-box check", doh)
        self.assertIn("Основной DNS-тест", dns_status)
        self.assertIn("doh-switch.sh.j2", operations)
        self.assertIn("dns-status.sh.j2", operations)

        self.assertIn("f2b-reset [status|IP|--all]", fail2ban)
        self.assertNotIn(
            "fail2ban-client unban --all\nfail2ban-client status", fail2ban
        )
        self.assertIn("{{ awg_server_audit_path | quote }}", update_all)
        self.assertNotIn("systemctl reset-failed", update_all)
        self.assertIn("{{ awg_server_audit_path | quote }} --quiet", maintenance)

        telegram = (templates / "telegram-monitor.sh.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("Использование: telegram-test", telegram)

        self.assertIn("kalimera-help.sh.j2", terminal_tasks)
        self.assertIn("kalimera-status.py.j2", terminal_tasks)
        self.assertIn("/usr/local/sbin/kalimera-status", terminal_help)
        self.assertIn("--with-commands", terminal_help)
        self.assertIn("/var/lib/awg-iac/mtu.yml", terminal_status)
        self.assertIn("server-audit", terminal_status)
        self.assertIn("forward-addr", terminal_status)
        self.assertIn("yandex-doh-ru", terminal_status)
        self.assertIn("KALIMERA_HELP_SHOWN", shell_tools)

    def test_awg3_source_and_mtu_are_reproducible_and_bidirectional(self) -> None:
        root = MODULE_PATH.parents[2]
        defaults = (root / "roles/awg3_transit/defaults/main.yml").read_text(
            encoding="utf-8"
        )
        tasks = (root / "roles/awg3_transit/tasks/main.yml").read_text(
            encoding="utf-8"
        )
        site = (root / "playbooks/site.yml").read_text(encoding="utf-8")
        setup = (
            root / "roles/awg3_transit/templates/transit-setup.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("awg3_go_source_commit:", defaults)
        self.assertIn("awg3_tools_source_commit:", defaults)
        self.assertIn("Проверка неизменности исходного кода AWG 3+", tasks)
        self.assertIn("awg3_go_cached_binary", tasks)
        self.assertIn("awg3_tools_cached_binary", tasks)
        self.assertIn("Временное разрешение ICMP только от второго сервера", site)
        self.assertIn("Закрытие временного ICMP-доступа", site)
        self.assertIn("awg3_shared_effective_mtu", site)
        self.assertIn('ip -4 route replace "${peer}/32"', setup)

    def test_security_closes_icmp_before_health_role(self) -> None:
        root = MODULE_PATH.parents[2]
        security_tasks = (
            root / "roles" / "security" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        health_template = (
            root / "roles" / "health" / "templates" / "awg-health.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("name: net.ipv4.icmp_echo_ignore_all", security_tasks)
        self.assertIn(
            "Гарантированный запрет ответов ICMP echo после согласования MTU",
            security_tasks,
        )
        self.assertIn(
            "check_value 'ответы на ICMP echo отключены'", health_template
        )

    def test_security_hardening_keeps_one_compatible_baseline(self) -> None:
        root = MODULE_PATH.parents[2]
        security_tasks = (
            root / "roles" / "security" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        security_defaults = (
            root / "roles" / "security" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        ssh = (
            root / "roles" / "security" / "templates" / "sshd-awg.conf.j2"
        ).read_text(encoding="utf-8")
        sysctl = (
            root / "roles" / "security" / "templates" / "sysctl.conf.j2"
        ).read_text(encoding="utf-8")
        health = (
            root / "roles" / "health" / "templates" / "awg-health.sh.j2"
        ).read_text(encoding="utf-8")

        self.assertIn("security_restrict_automation_key: true", security_defaults)
        self.assertIn('from="{{ security_automation_source_ipv4 }}"', security_tasks)
        self.assertIn("no-port-forwarding", security_tasks)
        self.assertIn("Banner none", ssh)
        self.assertIn("PermitUserRC no", ssh)
        self.assertIn("HostKey {{ host_key_path }}", ssh)
        self.assertIn("Создание отсутствующего Ed25519 host key", security_tasks)
        self.assertIn("Получение публичной части Ed25519 host key", security_tasks)
        self.assertIn("Проверка fingerprint Ed25519 host key", security_tasks)
        self.assertIn("Поиск доступных закрытых SSH host keys", security_tasks)
        self.assertIn("security_ssh_host_key_paths", security_tasks)
        self.assertNotIn("patterns: ssh_host_*_key", security_tasks)
        self.assertIn("ssh_host_ed25519_key", security_tasks)
        self.assertIn("ssh_host_ecdsa_key", security_tasks)
        self.assertIn("ssh_host_rsa_key", security_tasks)
        self.assertIn("ssh_host_dsa_key' not in", security_tasks)
        self.assertIn("kernel.unprivileged_bpf_disabled = 1", sysctl)
        self.assertNotIn("kernel.modules_disabled", sysctl)
        self.assertIn("169.254.0.0/16", security_tasks)
        self.assertIn("Изоляция служебного AWG 3+", security_tasks)
        self.assertIn("взаимно изолированы", health)

    def test_no_logs_baseline_keeps_only_volatile_operational_state(self) -> None:
        root = MODULE_PATH.parents[2]
        journal = (
            root / "roles" / "security" / "templates" /
            "journald-limits.conf.j2"
        ).read_text(encoding="utf-8")
        coredump = (
            root / "roles" / "security" / "templates" /
            "coredump-no-storage.conf.j2"
        ).read_text(encoding="utf-8")
        accounting = (
            root / "roles" / "security" / "templates" /
            "volatile-accounting.conf.j2"
        ).read_text(encoding="utf-8")
        security_tasks = (
            root / "roles" / "security" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        fail2ban = (
            root / "roles" / "fail2ban" / "templates" / "fail2ban.local.j2"
        ).read_text(encoding="utf-8")
        dnsmasq = (
            root / "roles" / "entry_dns" / "templates" /
            "50-awg-base.conf.j2"
        ).read_text(encoding="utf-8")
        resolved = (
            root / "roles" / "entry_dns" / "templates" /
            "60-kalimerawg-resolved.conf.j2"
        ).read_text(encoding="utf-8")
        unbound = (
            root / "roles" / "entry_dns" / "templates" /
            "90-awg-dot.conf.j2"
        ).read_text(encoding="utf-8")
        sing_box = (
            root / "roles" / "sing_box" / "templates" / "config.json.j2"
        ).read_text(encoding="utf-8")
        shell = (
            root / "roles" / "terminal" / "templates" /
            "kalimera-shell-tools.sh.j2"
        ).read_text(encoding="utf-8")
        audit = (
            root / "roles" / "operations" / "templates" /
            "server-audit.sh.j2"
        ).read_text(encoding="utf-8")
        health = (
            root / "roles" / "health" / "templates" /
            "awg-health.sh.j2"
        ).read_text(encoding="utf-8")
        security_defaults = (
            root / "roles" / "security" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("Storage=volatile", journal)
        self.assertIn("ForwardToSyslog=no", journal)
        self.assertIn("zz-kalimerawg-no-logs.conf", security_defaults)
        self.assertIn("systemd_config_last_value", health)
        self.assertIn("ForwardToSyslog)\" == no", health)
        self.assertIn("systemd_config_last_value", audit)
        self.assertIn("ForwardToSyslog)\" == no", audit)
        self.assertNotIn("SystemMaxUse", journal)
        self.assertIn("Storage=none", coredump)
        self.assertIn("ProcessSizeMax=0", coredump)
        self.assertIn("L+ /var/log/wtmp", accounting)
        self.assertIn("security_volatile_accounting_dir", accounting)
        self.assertIn("masked: true", security_tasks)
        self.assertIn("/var/log/journal", security_tasks)
        self.assertIn("/root/.bash_history", security_tasks)
        self.assertIn("src: /dev/null", security_tasks)
        self.assertIn("dbfile = :memory:", fail2ban)
        self.assertIn("logtarget = SYSTEMD-JOURNAL", fail2ban)
        self.assertIn("cache-size=0", dnsmasq)
        self.assertNotIn("log-queries", dnsmasq)
        self.assertIn("Cache=no", resolved)
        self.assertIn("log-queries: no", unbound)
        self.assertIn("log-replies: no", unbound)
        self.assertNotIn("log-destaddr", unbound)
        self.assertIn('"disabled": true', sing_box)
        self.assertIn('"disable_cache": true', sing_box)
        self.assertIn("export HISTFILE=/dev/null", shell)
        self.assertIn("постоянные журналы активности отсутствуют", audit)
        self.assertIn("/root/.wget-hsts", audit)

    def test_amnezia_ppa_and_managed_integrity_are_verified(self) -> None:
        root = MODULE_PATH.parents[2]
        awg_defaults = (
            root / "roles" / "amneziawg" / "defaults" / "main.yml"
        ).read_text(encoding="utf-8")
        awg_tasks = (
            root / "roles" / "amneziawg" / "tasks" / "main.yml"
        ).read_text(encoding="utf-8")
        source = (
            root / "roles" / "amneziawg" / "templates" /
            "amnezia-ppa.sources.j2"
        ).read_text(encoding="utf-8")
        audit = (
            root / "roles" / "operations" / "templates" /
            "server-audit.sh.j2"
        ).read_text(encoding="utf-8")
        site = (root / "playbooks" / "site.yml").read_text(encoding="utf-8")

        fingerprint = "75C9DD72C799870E310542E24166F2C257290828"
        self.assertIn(fingerprint, awg_defaults)
        self.assertIn("Проверка полного отпечатка", awg_tasks)
        self.assertIn("Signed-By: {{ amneziawg_ppa_keyring_path }}", source)
        self.assertIn("awg_managed_integrity_path", audit)
        self.assertIn("argv: [/usr/local/sbin/awg-managed-integrity, seal]", site)

    def test_awg_key_material_has_wireguard_shape(self) -> None:
        private = MODULE.awg_private_key()
        public = MODULE.awg_public_key(private)
        psk = MODULE.awg_psk()
        self.assertEqual(len(base64.b64decode(private)), 32)
        self.assertEqual(len(base64.b64decode(public)), 32)
        self.assertEqual(len(base64.b64decode(psk)), 32)
        self.assertNotEqual(private, public)

    def test_client_profiles_keep_interface_parameters_compatible(self) -> None:
        server = MODULE.awg_server_obfuscation()
        for profile_name in ("performance", "balanced", "masking"):
            limits = MODULE.AWG_CLIENT_PROFILES[profile_name]
            self.assertGreaterEqual(limits["jc"][0], 0)
            self.assertLessEqual(limits["jc"][1], 10)
            self.assertGreaterEqual(limits["jmin"][0], 64)
            self.assertLessEqual(limits["jmax"][1], 1024)
            self.assertLessEqual(limits["jmin"][1], limits["jmax"][0])
            client = MODULE.awg_client_obfuscation(profile_name, server)
            self.assertLessEqual(limits["jc"][0], client["jc"])
            self.assertLessEqual(client["jc"], limits["jc"][1])
            self.assertLessEqual(limits["jmin"][0], client["jmin"])
            self.assertLessEqual(client["jmin"], limits["jmin"][1])
            self.assertLessEqual(limits["jmax"][0], client["jmax"])
            self.assertLessEqual(client["jmax"], limits["jmax"][1])
            for key in (
                "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
                "i1", "i2", "i3", "i4", "i5",
            ):
                self.assertEqual(client[key], server[key])

    def test_modern_profile_matches_documented_bounds(self) -> None:
        for _ in range(100):
            server = MODULE.awg_server_obfuscation()
            self.assertGreaterEqual(server["jc"], 4)
            self.assertLessEqual(server["jc"], 12)
            self.assertLessEqual(server["jmin"], server["jmax"])
            self.assertNotEqual(server["s1"] + 56, server["s2"])
            self.assertNotEqual(server["s2"] + 28, server["s3"])
            for key in ("s1", "s2", "s3"):
                self.assertGreaterEqual(server[key], 0)
                self.assertLessEqual(server[key], 64)
            self.assertGreaterEqual(server["s4"], 12)
            self.assertLessEqual(server["s4"], 32)
            self.assertTrue(all(server[f"i{index}"] for index in range(1, 6)))
            for index in range(1, 5):
                self.assertRegex(str(server[f"h{index}"]), r"^[0-9]+-[0-9]+$")

    def test_i1_is_a_1200_byte_quic_initial_shaped_signature(self) -> None:
        with mock.patch.object(MODULE, "random_between", side_effect=[4, 8, 8]):
            signature = MODULE.awg_quic_initial_signature()

        self.assertEqual(
            signature,
            "<b 0xc30000000108><r 8><b 0x08><r 8>"
            "<b 0x004496><r 1000><r 174>",
        )
        self.assertIn("00000001", signature)
        random_sizes = [int(value) for value in re.findall(r"<r ([0-9]+)>", signature)]
        self.assertLessEqual(max(random_sizes), MODULE.AWG_CPS_RANDOM_TAG_MAX)
        self.assertEqual(
            6 + 8 + 1 + 8 + 3 + 1000 + 174,
            MODULE.AWG_QUIC_INITIAL_SIZE,
        )
        self.assertEqual(
            MODULE.awg_cps_signature_size(signature),
            MODULE.AWG_QUIC_INITIAL_SIZE,
        )

    def test_generated_profiles_fit_minimum_outer_pmtu(self) -> None:
        profiles = (
            MODULE.awg_server_obfuscation(),
            MODULE.awg_legacy_server_obfuscation(),
            MODULE.awg_mobile_dns_obfuscation(),
            MODULE.awg_mobile_quic_obfuscation(),
            MODULE.awg3_transit_obfuscation(),
        )
        for profile in profiles:
            MODULE.validate_awg_obfuscation(profile)
            for index in range(1, 6):
                packet_size = MODULE.awg_cps_signature_size(str(profile[f"i{index}"]))
                self.assertLessEqual(
                    packet_size + 28,
                    MODULE.AWG_MINIMUM_OUTER_PMTU,
                )

    def test_profile_validator_rejects_overlapping_headers(self) -> None:
        profile = MODULE.awg_server_obfuscation()
        profile["h2"] = profile["h1"]
        with self.assertRaises(SystemExit):
            MODULE.validate_awg_obfuscation(profile)

    def test_profile_validator_rejects_oversized_cps_packet(self) -> None:
        profile = MODULE.awg_server_obfuscation()
        profile["i1"] = "<r 1000><r 300>"
        with self.assertRaises(SystemExit):
            MODULE.validate_awg_obfuscation(profile)

    def test_oversized_cps_random_tags_are_migrated_without_size_change(self) -> None:
        signature = "<b 0xc10000000110><r 16><b 0x00><r 1161>"
        normalized = MODULE.normalize_awg_cps_signature(signature)
        self.assertEqual(
            normalized,
            "<b 0xc10000000110><r 16><b 0x00><r 1000><r 161>",
        )
        self.assertEqual(
            sum(int(value) for value in re.findall(r"<r ([0-9]+)>", signature)),
            sum(int(value) for value in re.findall(r"<r ([0-9]+)>", normalized)),
        )

    def test_modern_i2_i5_signatures_remain_populated_and_bounded(self) -> None:
        server = MODULE.awg_server_obfuscation()
        for key in ("i2", "i3", "i4", "i5"):
            value = str(server[key])
            self.assertTrue(value.startswith("<b 0x"))
            self.assertIn("><r ", value)
            random_size = int(value.rsplit("<r ", 1)[1].removesuffix(">"))
            self.assertGreater(random_size, 0)
            self.assertLess(random_size, 192)

    def test_old_profile_uses_only_base_scalar_asc(self) -> None:
        server = MODULE.awg_legacy_server_obfuscation()
        client = MODULE.awg_client_obfuscation("old", server)
        self.assertNotEqual(server["s1"] + 56, server["s2"])
        for key in ("s1", "s2"):
            self.assertGreaterEqual(server[key], 0)
            self.assertLessEqual(server[key], 64)
        for index in range(1, 5):
            self.assertIsInstance(server[f"h{index}"], int)
        for key in ("s3", "s4"):
            self.assertEqual(client[key], 0)
        for index in range(1, 6):
            self.assertEqual(client[f"i{index}"], "")

    def test_mobile_profile_matches_confirmed_ios_dns_signature(self) -> None:
        server = MODULE.awg_mobile_dns_obfuscation()
        client = MODULE.awg_client_obfuscation("mobile", server)
        self.assertEqual((client["jc"], client["jmin"], client["jmax"]), (5, 10, 50))
        self.assertEqual(client["s4"], 0)
        self.assertTrue(str(client["i1"]).startswith("<r 2><b 0x8580"))
        self.assertIn("69636c6f756403636f6d", str(client["i1"]))
        for index in range(2, 6):
            self.assertEqual(client[f"i{index}"], "")

    def test_mobile_quic_test_changes_only_i1(self) -> None:
        dns_profile = MODULE.awg_mobile_dns_obfuscation()
        with mock.patch.object(MODULE, "random_between", side_effect=[4, 8, 8]):
            quic_profile = MODULE.awg_mobile_quic_obfuscation()

        for key in (
            "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
            "h1", "h2", "h3", "h4", "i2", "i3", "i4", "i5",
        ):
            self.assertEqual(quic_profile[key], dns_profile[key])
        self.assertEqual(
            quic_profile["i1"],
            "<b 0xc30000000108><r 8><b 0x08><r 8>"
            "<b 0x004496><r 1000><r 174>",
        )

    def test_mobile_i1_mode_is_stable_and_reversible(self) -> None:
        dns_profile = MODULE.awg_mobile_dns_obfuscation()
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary)
            entry_path = production / "group_vars" / "entry.yml"
            entry_path.parent.mkdir(parents=True)
            MODULE.yaml_write(
                entry_path,
                {
                    "entry_mobile_i1_mode": "dns-ios",
                    "entry_mobile_awg_obfuscation": dns_profile,
                },
            )
            with mock.patch.object(MODULE, "random_between", side_effect=[4, 8, 8]):
                self.assertTrue(
                    MODULE.set_mobile_i1_mode(production, "quic-ios")
                )
            first_quic = MODULE.load_yaml(entry_path)[
                "entry_mobile_awg_obfuscation"
            ]["i1"]

            with mock.patch.object(
                MODULE,
                "awg_quic_initial_signature",
                side_effect=AssertionError("I1 не должен ротироваться при resume"),
            ):
                self.assertFalse(
                    MODULE.set_mobile_i1_mode(production, "quic-ios")
                )
            self.assertEqual(
                MODULE.load_yaml(entry_path)["entry_mobile_awg_obfuscation"]["i1"],
                first_quic,
            )

            self.assertTrue(MODULE.set_mobile_i1_mode(production, "dns-ios"))
            restored = MODULE.load_yaml(entry_path)
            self.assertEqual(restored["entry_mobile_i1_mode"], "dns-ios")
            self.assertEqual(
                restored["entry_mobile_awg_obfuscation"]["i1"],
                dns_profile["i1"],
            )

    def test_mobile_interface_uses_direct_8443_and_cleans_legacy_dns_redirect(self) -> None:
        root = MODULE_PATH.parents[2]
        config = (root / "roles/entry/templates/awg-mobile.conf.j2").read_text(
            encoding="utf-8"
        )
        firewall = (
            root / "roles/entry/templates/awg-mobile-firewall.sh.j2"
        ).read_text(encoding="utf-8")
        user = (
            root / "roles/operations/templates/vpn-user.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("ListenPort = {{ entry_mobile_client_listen_port }}", config)
        self.assertIn("vault_entry_mobile_client_peers", config)
        self.assertIn("I1 = {{ entry_mobile_awg_obfuscation.i1 }}", config)
        self.assertNotIn("I2 =", config)
        self.assertIn("readonly comment=awg-mobile-public-quic", firewall)
        self.assertIn("--dport \"$listen_port\"", firewall)
        self.assertIn("-j ACCEPT", firewall)
        self.assertIn("remove_legacy_redirect", firewall)
        self.assertIn("check-dns-clean", firewall)
        self.assertNotIn("-A PREROUTING", firewall)
        self.assertIn("vpn-user NAME [performance|balanced|masking|mobile|old]", user)
        self.assertIn("./deploy --resume --enable-mobile", user)

    def test_optional_interfaces_refresh_routes_without_dns_or_policy_reset(self) -> None:
        root = MODULE_PATH.parents[2]
        routing = (
            root / "roles/entry_routing/templates/awg-entry-routing.sh.j2"
        ).read_text(encoding="utf-8")
        for template_name in ("awg-mobile.sh.j2", "awg-old.sh.j2"):
            control = (
                root / "roles/operations/templates" / template_name
            ).read_text(encoding="utf-8")
            self.assertIn('refresh_network() {\n    "$routing" apply\n}', control)
            self.assertNotIn('"$routing" remove', control)
            self.assertNotIn("try-restart dnsmasq.service", control)
        self.assertIn('if ! ip link show "$client_if"', routing)
        self.assertIn("чистое состояние без сброса общих policy-routing таблиц", routing)

    def test_entry_candidate_keeps_interface_name_valid_for_awg_quick(self) -> None:
        root = MODULE_PATH.parents[2]
        tasks = (root / "roles/entry/tasks/manage_config.yml").read_text(
            encoding="utf-8"
        )
        defaults = (root / "roles/entry/defaults/main.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "{{ entry_awg_candidate_root }}/{{ entry_awg_config_item.interface }}.conf",
            tasks,
        )
        self.assertNotIn(
            "/run/ansible-{{ entry_awg_config_item.interface }}.conf",
            tasks,
        )
        self.assertIn("entry_awg_candidate_root: /run/awg-ansible", defaults)

    def test_awg3_profile_meets_header_protection_padding_requirement(self) -> None:
        profile = MODULE.awg3_transit_obfuscation()
        for key in ("s1", "s2", "s3", "s4"):
            self.assertGreaterEqual(profile[key], 12)
        for key in ("s1", "s2", "s3"):
            self.assertLessEqual(profile[key], 64)
        self.assertLessEqual(profile["s4"], 32)

    def test_vpn_user_keeps_server_header_ranges(self) -> None:
        template = (
            MODULE_PATH.parents[2]
            / "roles"
            / "operations"
            / "templates"
            / "vpn-user.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertNotIn("client_header", template)
        self.assertNotIn("h_width", template)
        for key in ("h1", "h2", "h3", "h4"):
            self.assertIn(
                f"{key.upper()} = {{{{ entry_awg0_obfuscation.{key} }}}}", template
            )

    def test_key_bootstrap_retries_password_and_names_server(self) -> None:
        with (
            mock.patch.object(MODULE, "require_command", side_effect=lambda name: name),
            mock.patch.object(
                MODULE.subprocess,
                "run",
                side_effect=[
                    mock.Mock(returncode=5),
                    mock.Mock(returncode=0),
                ],
            ) as run,
            mock.patch.object(MODULE.getpass, "getpass", return_value="corrected-value"),
            mock.patch("builtins.print") as output,
        ):
            password = MODULE.bootstrap_key(
                "exit.invalid",
                "root",
                22,
                "initial-value",
                Path("public-key.pub"),
                "EXIT сервер",
            )

        self.assertEqual(password, "corrected-value")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].kwargs["env"]["SSHPASS"], "initial-value")
        self.assertEqual(run.call_args_list[1].kwargs["env"]["SSHPASS"], "corrected-value")
        self.assertEqual(run.call_args_list[0].kwargs["timeout"], 45)
        bootstrap_command = run.call_args_list[0].args[0]
        for option in (
            "ConnectTimeout=10",
            "ConnectionAttempts=1",
            "ServerAliveInterval=5",
            "ServerAliveCountMax=2",
        ):
            self.assertIn(option, bootstrap_command)
        self.assertTrue(
            any("EXIT сервер отклонил" in str(call) for call in output.call_args_list)
        )

    def test_key_bootstrap_limits_total_wait_time(self) -> None:
        with (
            mock.patch.object(MODULE, "require_command", side_effect=lambda name: name),
            mock.patch.object(
                MODULE.subprocess,
                "run",
                side_effect=[
                    MODULE.subprocess.TimeoutExpired("ssh-copy-id", 45),
                    mock.Mock(returncode=0),
                ],
            ) as run,
            mock.patch.object(MODULE.getpass, "getpass", return_value="retry-value"),
            mock.patch("builtins.print") as output,
        ):
            password = MODULE.bootstrap_key(
                "exit.invalid",
                "root",
                56777,
                "initial-value",
                Path("public-key.pub"),
                "EXIT сервер",
            )

        self.assertEqual(password, "initial-value")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].kwargs["env"]["SSHPASS"], "initial-value")
        self.assertTrue(
            any("не ответил за 45 секунд" in str(call) for call in output.call_args_list)
        )

    def test_runtime_secret_uses_true_shamir_2_of_5_without_output(self) -> None:
        shares = [
            f"kalimerawgruntimev1-{index}-{'a' * 64}"
            for index in range(1, 6)
        ]
        with (
            mock.patch.object(MODULE, "require_command", return_value="ssss-split"),
            mock.patch.object(
                MODULE.subprocess,
                "run",
                return_value=mock.Mock(returncode=0, stdout="\n".join(shares) + "\n"),
            ) as run,
        ):
            result = MODULE.split_runtime_secret("1" * 64)

        self.assertEqual(result, shares)
        command = run.call_args.args[0]
        self.assertIn("-t", command)
        self.assertEqual(command[command.index("-t") + 1], "2")
        self.assertEqual(command[command.index("-n") + 1], "5")
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_runtime_secret_inventory_assigns_unique_second_exit_share(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = root / "inventory" / "production"
            all_root = production / "group_vars" / "all"
            all_root.mkdir(parents=True)
            password_path = root / "vault.pass"
            password_path.write_bytes(b"test-vault-password\n")
            MODULE.yaml_write(all_root / "main.yml", {})
            MODULE.yaml_write(
                production / "group_vars" / "entry.yml",
                {"security_interserver_peer_ipv4": "198.51.100.20"},
            )
            MODULE.yaml_write(
                production / "group_vars" / "exit.yml",
                {"security_interserver_peer_ipv4": "198.51.100.10"},
            )
            hosts = {
                "all": {
                    "children": {
                        "entry": {
                            "hosts": {
                                "entry-managed": {"ansible_host": "198.51.100.10"}
                            }
                        },
                        "exit": {
                            "hosts": {
                                "exit-managed": {"ansible_host": "198.51.100.20"},
                                "exit-secondary": {"ansible_host": "198.51.100.30"},
                            }
                        },
                    }
                }
            }
            MODULE.yaml_write(production / "hosts.yml", hosts)
            vault = VaultLib(
                [("default", VaultSecret(b"test-vault-password"))]
            )
            (all_root / "vault.yml").write_bytes(
                vault.encrypt(yaml.safe_dump({}).encode("utf-8"))
            )
            shares = [
                f"kalimerawgruntimev1-{index}-{'a' * 64}"
                for index in range(1, 6)
            ]
            exchange_counter = iter(range(1, 4))

            def exchange_keypair() -> tuple[str, str]:
                index = next(exchange_counter)
                return f"private-{index}", f"ssh-ed25519 public-{index} exchange"

            with (
                mock.patch.object(MODULE, "split_runtime_secret", return_value=shares),
                mock.patch.object(
                    MODULE, "ssh_exchange_keypair", side_effect=exchange_keypair
                ),
            ):
                self.assertTrue(
                    MODULE.ensure_runtime_secret_material(production, password_path)
                )

            updated_hosts = yaml.safe_load(
                (production / "hosts.yml").read_text(encoding="utf-8")
            )["all"]["children"]
            self.assertEqual(
                updated_hosts["entry"]["hosts"]["entry-managed"][
                    "runtime_secrets_share_index"
                ],
                1,
            )
            self.assertEqual(
                updated_hosts["exit"]["hosts"]["exit-managed"][
                    "runtime_secrets_share_index"
                ],
                2,
            )
            self.assertEqual(
                updated_hosts["exit"]["hosts"]["exit-secondary"][
                    "runtime_secrets_share_index"
                ],
                3,
            )
            self.assertEqual(
                updated_hosts["exit"]["hosts"]["exit-secondary"][
                    "runtime_secrets_advertise_ipv4"
                ],
                "198.51.100.30",
            )
            decrypted = yaml.safe_load(
                vault.decrypt((all_root / "vault.yml").read_bytes())
            )
            self.assertEqual(
                set(decrypted["vault_runtime_exchange_private_keys"]),
                {"entry-managed", "exit-managed", "exit-secondary"},
            )
            self.assertFalse(
                MODULE.ensure_runtime_secret_material(production, password_path)
            )

    def test_admin_account_material_is_generated_once_and_only_hashes_persist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = root / "inventory" / "production"
            all_root = production / "group_vars" / "all"
            all_root.mkdir(parents=True)
            password_path = root / "vault.pass"
            password_path.write_bytes(b"test-vault-password\n")
            MODULE.yaml_write(
                all_root / "main.yml",
                {
                    "security_admin_authorized_keys": [
                        "ssh-ed25519 AAAAfixture admin@example"
                    ]
                },
            )
            MODULE.yaml_write(
                production / "hosts.yml",
                {
                    "all": {
                        "children": {
                            "entry": {"hosts": {"entry-managed": {}}},
                            "exit": {"hosts": {"exit-managed": {}}},
                        }
                    }
                },
            )
            vault = VaultLib(
                [("default", VaultSecret(b"test-vault-password"))]
            )
            (all_root / "vault.yml").write_bytes(
                vault.encrypt(yaml.safe_dump({}).encode("utf-8"))
            )
            generated = iter(
                [
                    "Aa2!" + "a" * 26,
                    "Bb3@" + "b" * 26,
                    "Cc4#" + "c" * 26,
                    "Dd5$" + "d" * 26,
                ]
            )
            with (
                mock.patch.object(
                    MODULE, "generate_account_password", side_effect=lambda: next(generated)
                ),
                mock.patch.object(
                    MODULE,
                    "hash_account_password",
                    side_effect=lambda password: f"$6$fixture${password[:4]}",
                ),
                mock.patch.object(MODULE, "show_generated_account_passwords") as show,
            ):
                self.assertTrue(
                    MODULE.ensure_admin_account_material(
                        production, password_path, root / "repo"
                    )
                )
                self.assertFalse(
                    MODULE.ensure_admin_account_material(
                        production, password_path, root / "repo"
                    )
                )
            show.assert_called_once()

            decrypted = yaml.safe_load(
                vault.decrypt((all_root / "vault.yml").read_bytes())
            )
            self.assertEqual(len(decrypted), 4)
            self.assertTrue(all(value.startswith("$6$") for value in decrypted.values()))
            self.assertNotIn("Aa2!", (all_root / "vault.yml").read_text(encoding="utf-8"))
            all_vars = yaml.safe_load(
                (all_root / "main.yml").read_text(encoding="utf-8")
            )
            self.assertTrue(all_vars["security_manage_admin_account"])
            self.assertFalse(all_vars["security_finalize_admin_access"])
            self.assertTrue(all_vars["security_require_admin_authorized_key"])

    def test_undelivered_account_passwords_are_rotated_and_deferred_on_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            production = root / "inventory" / "production"
            all_root = production / "group_vars" / "all"
            all_root.mkdir(parents=True)
            password_path = root / "vault.pass"
            password_path.write_bytes(b"test-vault-password\n")
            MODULE.yaml_write(
                all_root / "main.yml",
                {
                    "security_admin_authorized_keys": [
                        "ssh-ed25519 AAAAfixture admin@example"
                    ],
                    "security_manage_admin_account": True,
                    "security_account_passwords_delivered": False,
                },
            )
            MODULE.yaml_write(
                production / "hosts.yml",
                {
                    "all": {
                        "children": {
                            "entry": {"hosts": {"entry-managed": {}}},
                            "exit": {"hosts": {"exit-managed": {}}},
                        }
                    }
                },
            )
            old_hashes = {
                "vault_entry_kalimera_password_hash": "$6$old$entry-admin",
                "vault_entry_root_password_hash": "$6$old$entry-root",
                "vault_exit_kalimera_password_hash": "$6$old$exit-admin",
                "vault_exit_root_password_hash": "$6$old$exit-root",
            }
            vault = VaultLib([("default", VaultSecret(b"test-vault-password"))])
            (all_root / "vault.yml").write_bytes(
                vault.encrypt(yaml.safe_dump(old_hashes).encode("utf-8"))
            )
            generated = iter(
                [
                    "Aa2!" + "a" * 26,
                    "Bb3@" + "b" * 26,
                    "Cc4#" + "c" * 26,
                    "Dd5$" + "d" * 26,
                ]
            )
            pending: dict[str, str] = {}
            with (
                mock.patch.object(
                    MODULE, "generate_account_password", side_effect=lambda: next(generated)
                ),
                mock.patch.object(
                    MODULE,
                    "hash_account_password",
                    side_effect=lambda password: f"$6$new${password[:4]}",
                ),
                mock.patch.object(MODULE, "show_generated_account_passwords") as show,
            ):
                self.assertTrue(
                    MODULE.ensure_admin_account_material(
                        production,
                        password_path,
                        root / "repo",
                        pending_passwords=pending,
                        regenerate_undelivered=True,
                    )
                )
            show.assert_not_called()
            self.assertEqual(len(pending), 4)
            decrypted = yaml.safe_load(
                vault.decrypt((all_root / "vault.yml").read_bytes())
            )
            self.assertTrue(all(value.startswith("$6$new$") for value in decrypted.values()))

            MODULE.mark_account_passwords_delivered(production)
            second_pending: dict[str, str] = {}
            self.assertFalse(
                MODULE.ensure_admin_account_material(
                    production,
                    password_path,
                    root / "repo",
                    pending_passwords=second_pending,
                    regenerate_undelivered=True,
                )
            )
            self.assertEqual(second_pending, {})

    def test_remote_direct_mode_generates_final_two_phase_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            home = root / "home"
            shutil.copytree(MODULE_PATH.parents[2] / "inventory" / "example", repo / "inventory" / "example")
            ssh_key = home / ".ssh" / "awg-iac-production"
            ssh_key.parent.mkdir(parents=True)
            ssh_key.write_text("fixture-private-key\n", encoding="utf-8")
            Path(str(ssh_key) + ".pub").write_text(
                "ssh-ed25519 AAAA fixture\n", encoding="utf-8"
            )
            vault_password = home / ".config" / "awg-iac" / "production-vault.pass"
            vault_password.parent.mkdir(parents=True)
            vault_password.write_text("fixture-vault-value\n", encoding="utf-8")
            vault_password.chmod(0o600)

            admin_public_key = "ssh-ed25519 " + base64.b64encode(b"fixture-admin-public-key-material").decode()
            answers = iter(
                [
                    "n",
                    "entry.invalid",
                    "exit.invalid",
                    "ubuntu",
                    "deployer",
                    "22",
                    "2222",
                    "56777",
                    "56778",
                    "",
                    "",
                    "39744",
                    "",
                    admin_public_key,
                    "",
                    "",
                    "1",
                    "n",
                    "y",
                    "y",
                    "exit.invalid",
                    "entry.invalid",
                    "vpn-user",
                    "2",
                    "10.66.0.0/24",
                    "10.67.0.0/24",
                    "10.68.0.0/24",
                    "10.77.0.0/24",
                    "y",
                ]
            )
            hidden_answers = iter(["entry-login-value", "exit-login-value"])

            def simulated_run(_argv, **_kwargs):
                state = home / ".local" / "share" / "awg-iac" / "production"
                state.mkdir(parents=True, exist_ok=True)
                (state / "amneziawg-package-lock.txt").write_text(
                    "amneziawg=1.0\namneziawg-dkms=1.0\namneziawg-tools=1.0\n",
                    encoding="utf-8",
                )
                (state / "mtu.yml").write_text(
                    "shared_outer_pmtu: 1450\ntransit_mtu: 1320\n"
                    "client_mtu: 1320\nlegacy_client_mtu: 1240\n"
                    "mobile_client_mtu: 1320\n",
                    encoding="utf-8",
                )

            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch("builtins.input", side_effect=lambda _="": next(answers)),
                mock.patch("getpass.getpass", side_effect=lambda _="": next(hidden_answers)),
                mock.patch.object(MODULE, "require_command", side_effect=lambda name: name),
                mock.patch.object(
                    MODULE,
                    "hash_account_password",
                    side_effect=lambda password: f"$6$fixture${password[:8]}",
                ),
                mock.patch.object(MODULE, "show_generated_account_passwords"),
                mock.patch.object(
                    MODULE,
                    "detect_local_public_ipv4",
                    return_value="8.8.8.8",
                ),
                mock.patch.object(
                    MODULE,
                    "split_runtime_secret",
                    return_value=[
                        f"kalimerawgruntimev1-{index}-{'a' * 64}"
                        for index in range(1, 6)
                    ],
                ),
                mock.patch.object(MODULE, "run", side_effect=simulated_run) as run,
                mock.patch.object(MODULE, "cleanup_deployment"),
                mock.patch.object(
                    MODULE,
                    "bootstrap_key",
                    side_effect=lambda _host, _user, _port, password, _key, _label: password,
                ),
                mock.patch.object(MODULE, "require_public_endpoint"),
                mock.patch.object(
                    MODULE,
                    "resolve_single_public_ipv4",
                    side_effect=lambda value, _label: {
                        "entry.invalid": "198.51.100.10",
                        "exit.invalid": "198.51.100.20",
                    }[value],
                ),
                mock.patch.object(sys, "argv", ["interactive_deploy.py", "--repo-root", str(repo)]),
            ):
                MODULE.main()

            site_commands = [
                call.args[0]
                for call in run.call_args_list
                if any(str(argument).endswith("playbooks/site.yml") for argument in call.args[0])
            ]
            self.assertEqual(len(site_commands), 2)
            self.assertIn("awg_prepare_apt=true", site_commands[0])
            self.assertIn("awg_restore_apt=false", site_commands[0])
            self.assertIn("awg_prepare_apt=false", site_commands[1])
            self.assertIn("awg_restore_apt=true", site_commands[1])

            inventory = yaml.safe_load(
                (repo / "inventory" / "production" / "hosts.yml").read_text(encoding="utf-8")
            )
            entry = inventory["all"]["children"]["entry"]["hosts"]["entry-managed"]
            exit_node = inventory["all"]["children"]["exit"]["hosts"]["exit-managed"]
            self.assertEqual(entry["ansible_port"], 56777)
            self.assertEqual(exit_node["ansible_port"], 56778)
            self.assertEqual(entry["ansible_user"], "root")
            self.assertEqual(exit_node["ansible_user"], "root")
            self.assertNotIn("ansible_become_password", entry)
            self.assertNotIn("ansible_become_password", exit_node)
            self.assertFalse(entry["security_allow_ssh_port_change"])
            self.assertEqual(entry["security_previous_ssh_port"], 22)
            self.assertEqual(entry["security_automation_source_ipv4"], "8.8.8.8")
            self.assertEqual(
                entry["security_admin_password_hash"],
                "{{ vault_entry_kalimera_password_hash }}",
            )
            entry_vars = yaml.safe_load(
                (repo / "inventory" / "production" / "group_vars" / "entry.yml").read_text(encoding="utf-8")
            )
            self.assertFalse(entry_vars["entry_ru_proxy_enabled"])
            self.assertEqual(entry_vars["entry_wan_interface"], "auto")
            self.assertTrue(entry_vars["awg3_transit_enabled"])
            self.assertEqual(entry_vars["entry_exit_interface"], "awg3")
            self.assertTrue(entry_vars["entry_legacy_client_available"])
            self.assertFalse(entry_vars["entry_legacy_client_enabled"])
            self.assertEqual(entry_vars["entry_legacy_client_listen_port"], 39744)
            self.assertTrue(entry_vars["entry_mobile_client_available"])
            self.assertFalse(entry_vars["entry_mobile_client_enabled"])
            self.assertEqual(entry_vars["entry_mobile_client_listen_port"], 8443)
            self.assertEqual(entry_vars["entry_mobile_i1_mode"], "quic-ios")
            self.assertEqual(entry_vars["entry_mobile_legacy_public_port"], 53)
            self.assertEqual(entry_vars["entry_mobile_legacy_internal_port"], 39746)
            self.assertEqual(entry_vars["entry_awg0_listen_port"], 443)
            self.assertEqual(entry_vars["awg3_transit_listen_port"], 39745)
            self.assertEqual(entry_vars["security_interserver_listen_port"], 39745)
            self.assertEqual(entry_vars["awg3_peer_endpoint_port"], 443)
            self.assertEqual(
                entry_vars["security_interserver_peer_ipv4"], "198.51.100.20"
            )
            exit_vars = yaml.safe_load(
                (repo / "inventory" / "production" / "group_vars" / "exit.yml").read_text(encoding="utf-8")
            )
            self.assertEqual(exit_vars["exit_awg_listen_port"], 443)
            self.assertEqual(exit_vars["awg3_transit_listen_port"], 443)
            self.assertEqual(exit_vars["awg3_peer_endpoint_port"], 39745)
            self.assertEqual(
                exit_vars["security_interserver_peer_ipv4"], "198.51.100.10"
            )
            all_vars = yaml.safe_load(
                (repo / "inventory" / "production" / "group_vars" / "all" / "main.yml").read_text(encoding="utf-8")
            )
            self.assertEqual(len(all_vars["security_admin_authorized_keys"]), 1)
            self.assertTrue(all_vars["security_manage_admin_account"])
            self.assertEqual(all_vars["security_admin_user"], "kalimera")
            self.assertTrue(all_vars["security_finalize_admin_access"])
            self.assertTrue(all_vars["security_account_passwords_delivered"])
            self.assertEqual(all_vars["awg_package_version_mode"], "pinned")
            self.assertEqual(all_vars["awg_package_versions"]["amneziawg"], "1.0")
            self.assertTrue(all_vars["runtime_secrets_enabled"])
            self.assertEqual(all_vars["runtime_secrets_threshold"], 2)
            self.assertEqual(all_vars["runtime_secrets_total_shares"], 5)
            self.assertRegex(all_vars["runtime_secrets_cluster_id"], r"^[0-9a-f]{32}$")
            self.assertEqual(entry_vars["runtime_secrets_share_index"], 1)
            self.assertEqual(exit_vars["runtime_secrets_share_index"], 2)

            encrypted = (
                repo / "inventory" / "production" / "group_vars" / "all" / "vault.yml"
            ).read_bytes()
            plaintext = VaultLib(
                [("default", VaultSecret(b"fixture-vault-value"))]
            ).decrypt(encrypted)
            vault = yaml.safe_load(plaintext)
            self.assertIn("vault_awg_entry_private_key", vault)
            self.assertRegex(vault["vault_entry_kalimera_password_hash"], r"^[$]6[$]")
            self.assertRegex(vault["vault_entry_root_password_hash"], r"^[$]6[$]")
            self.assertRegex(vault["vault_exit_kalimera_password_hash"], r"^[$]6[$]")
            self.assertRegex(vault["vault_exit_root_password_hash"], r"^[$]6[$]")
            self.assertNotIn("vault_entry_become_password", vault)
            self.assertNotIn("vault_exit_become_password", vault)
            self.assertIn("vault_awg_entry_legacy_private_key", vault)
            self.assertIn("vault_awg_entry_mobile_private_key", vault)
            self.assertIn("vault_awg3_header_protection_key", vault)
            self.assertEqual(len(vault["vault_runtime_secret_shares"]), 5)
            self.assertEqual(
                set(vault["vault_runtime_exchange_private_keys"]),
                {"entry-managed", "exit-managed"},
            )
            self.assertEqual(vault["vault_proxy_username"], "")
            self.assertEqual(
                vault["vault_entry_client_peers"][0]["allowed_ips"],
                ["10.66.0.2/32"],
            )
            client_config = home / ".local" / "share" / "awg-iac" / "production" / "clients" / "vpn-user.conf"
            self.assertTrue(client_config.is_file())
            self.assertEqual(client_config.stat().st_mode & 0o777, 0o600)
            client_text = client_config.read_text(encoding="utf-8")
            self.assertIn("MTU = 1320", client_text)
            self.assertIn("Address = 10.66.0.2/24", client_text)
            self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", client_text)
            self.assertNotIn("AllowedIPs = 10.66.0.1/32", client_text)
            for key in ("S3", "S4", "I1", "I2", "I3", "I4", "I5"):
                self.assertIn(f"{key} =", client_text)
            for key in ("H1", "H2", "H3", "H4"):
                value = next(
                    line.split("=", 1)[1].strip()
                    for line in client_text.splitlines()
                    if line.startswith(f"{key} =")
                )
                self.assertRegex(value, r"^[0-9]+-[0-9]+$")
                self.assertEqual(
                    value, str(entry_vars["entry_awg0_obfuscation"][key.lower()])
                )


if __name__ == "__main__":
    unittest.main()

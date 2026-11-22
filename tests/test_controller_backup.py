"""Резервная копия состояния контроллера и восстановление ENTRY.

Сборка архива, шифрование и раскладка состояния проверяются на временных
каталогах; отправка на серверы - с подставным Ansible. Настоящие серверы и root
не нужны.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import jinja2
import yaml

ROOT = Path(__file__).parents[1]
LIB = ROOT / "scripts" / "lib"
OPERATIONS = ROOT / "roles" / "operations"
REPORT = ROOT / "roles" / "cascade_check" / "templates" / "kalimera-report.sh.j2"
GATEWAY = ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
WRAPPER = OPERATIONS / "templates" / "kalimera-weekly.sh.j2"
SERVICE = OPERATIONS / "templates" / "kalimera-controller-backup.service.j2"
TIMER = OPERATIONS / "templates" / "kalimera-controller-backup.timer.j2"
TASKS = OPERATIONS / "tasks" / "main.yml"
DEFAULTS = OPERATIONS / "defaults" / "main.yml"
SHELL_TOOLS = ROOT / "roles" / "terminal" / "templates" / "kalimera-shell-tools.sh.j2"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DEPLOY = load("interactive_deploy_backup", LIB / "interactive_deploy.py")
# Тот же объект модуля, что использует установщик: иначе исключения не совпали бы.
BACKUP = sys.modules["controller_backup"]


def render(template: Path, **variables) -> str:
    environment = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    return environment.from_string(template.read_text(encoding="utf-8")).render(**variables)


def bash_path() -> str:
    executable = shutil.which("bash")
    if executable is None or os.name == "nt":
        raise unittest.SkipTest("нужен bash на Linux")
    return executable


class RecoveryKeyTests(unittest.TestCase):
    def test_key_survives_being_written_down_by_a_person(self) -> None:
        key = BACKUP.new_recovery_key()
        text = BACKUP.format_recovery_key(key)
        self.assertRegex(text, r"^KWG1(-[0-9a-f]{8}){9}$")
        # Пробелы, переносы строк и регистр префикса при вводе не важны.
        for variant in (text, f"  {text}\n", text.replace("-", " "), text.lower(), text[5:]):
            self.assertEqual(BACKUP.parse_recovery_key(variant), key)

    def test_typo_is_named_not_reported_as_a_wrong_key(self) -> None:
        text = BACKUP.format_recovery_key(bytes(range(32)))
        wrong = text[:6] + ("0" if text[6] != "0" else "1") + text[7:]
        with self.assertRaisesRegex(BACKUP.BackupError, "опечатка"):
            BACKUP.parse_recovery_key(wrong)
        with self.assertRaisesRegex(BACKUP.BackupError, "неверный формат"):
            BACKUP.parse_recovery_key("KWG1-1234")


class Layout:
    """Состояние ENTRY во временном каталоге: то, что входит в копию."""

    def __init__(self, base: Path) -> None:
        self.production = base / "repo" / "inventory" / "production"
        self.runtime = base / "run" / "kalimera-secrets"
        self.state = base / "home" / ".local" / "share" / "awg-iac" / "production"
        self.ssh_key = base / "home" / ".ssh" / "awg-iac-production"
        (self.production / "group_vars" / "all").mkdir(parents=True)
        (self.production / "hosts.yml").write_text("all: {children: {}}\n", encoding="utf-8")
        (self.production / "group_vars" / "all" / "vault.yml").write_text("$ANSIBLE_VAULT;1.1\n", encoding="utf-8")
        files = {
            "controller/production-vault.pass": "vault-password\n",
            "controller/awg-iac-production": "PRIVATE KEY\n",
            "controller/clients/phone.conf": "[Interface]\nMTU = 1380\n",
            "amneziawg/awg0.conf": "[Interface]\nPrivateKey = entry\n",
            "awg/domain-policy/ru-domain": "example.ru\n",
            "awg/client-peers/laptop.conf": "[Peer]\n",
            "awg/controller-backup.key": "key\n",
            "telegram/monitor.env": "TOKEN=1\n",
        }
        for name, text in files.items():
            path = self.runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            path.chmod(0o600)
        (self.runtime / ".unlocked").write_text("cluster\n", encoding="utf-8")
        self.state.mkdir(parents=True)
        (self.state / "mtu.yml").write_text("client_mtu: 1380\n", encoding="utf-8")
        (self.state / "amneziawg-package-lock.txt").write_text("amneziawg=1.0\n", encoding="utf-8")
        # На управляющем ENTRY каталог клиентов - ссылка в хранилище секретов.
        (self.state / "clients").symlink_to(self.runtime / "controller" / "clients")
        self.ssh_key.parent.mkdir(parents=True)
        self.ssh_key.with_name("awg-iac-production.pub").write_text("ssh-ed25519 AAAA awg-iac-production\n", encoding="utf-8")
        self.mappings = [
            {"source": "/etc/amnezia/amneziawg", "target": "amneziawg"},
            {"source": "/etc/awg", "target": "awg"},
            {"source": "/etc/sing-box", "target": "sing-box"},
            {"source": "/etc/awg-telegram-monitor.env", "target": "telegram/monitor.env"},
            {"source": "/root/.config/awg-iac/production-vault.pass", "target": "controller/production-vault.pass"},
            {"source": "/root/.ssh/awg-iac-production", "target": "controller/awg-iac-production"},
            {"source": "/root/.local/share/awg-iac/production/clients", "target": "controller/clients"},
        ]

    def sources(self) -> list:
        return DEPLOY.controller_backup_sources(self.production, self.state, self.runtime, self.ssh_key)

    def archive(self, **manifest) -> tuple[bytes, str]:
        return BACKUP.build_archive({"release": "3.8.0", "mappings": self.mappings, **manifest}, self.sources())


class ArchiveCase(unittest.TestCase):
    def setUp(self) -> None:
        if os.name == "nt":
            self.skipTest("нужны символические ссылки Linux")
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.layout = Layout(self.dir)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def names(self, plaintext: bytes) -> list[str]:
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as archive:
            return archive.getnames()


class ArchiveTests(ArchiveCase):
    def test_copy_holds_everything_a_new_entry_needs(self) -> None:
        plaintext, _digest = self.layout.archive()
        names = self.names(plaintext)
        for expected in (
            "inventory/hosts.yml",
            "inventory/group_vars/all/vault.yml",
            "runtime/controller/production-vault.pass",
            "runtime/controller/awg-iac-production",
            "runtime/controller/clients/phone.conf",
            "runtime/amneziawg/awg0.conf",
            "runtime/awg/client-peers/laptop.conf",
            "runtime/awg/controller-backup.key",
            "state/mtu.yml",
            "state/amneziawg-package-lock.txt",
            "ssh/awg-iac-production.pub",
            "manifest.json",
        ):
            self.assertIn(expected, names)
        # Отметка открытого хранилища и ссылка на каталог клиентов в копию не входят.
        self.assertNotIn("runtime/.unlocked", names)
        self.assertFalse([name for name in names if name.startswith("state/clients")])

    def test_same_state_gives_the_same_digest_whatever_the_time(self) -> None:
        # По сумме решается, отправлять ли копию заново: время создания в неё не входит.
        first, first_digest = self.layout.archive(created="2026-11-22 06:40 UTC")
        os.utime(self.layout.runtime / "amneziawg" / "awg0.conf", (1, 1))
        second, second_digest = self.layout.archive(created="2026-11-23 06:40 UTC")
        self.assertEqual(first_digest, second_digest)
        self.assertNotEqual(first, second)
        (self.layout.runtime / "awg" / "client-peers" / "tablet.conf").write_text("[Peer]\n", encoding="utf-8")
        self.assertNotEqual(self.layout.archive()[1], first_digest)

    def test_link_leading_outside_is_refused(self) -> None:
        (self.layout.runtime / "awg" / "outside").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(BACKUP.BackupError, "за пределы копии"):
            self.layout.archive()

    def test_encrypted_copy_opens_only_with_its_key(self) -> None:
        plaintext, _digest = self.layout.archive()
        key = BACKUP.new_recovery_key()
        document = BACKUP.encrypt(plaintext, key, "c" * 32, "2026-11-22 06:40 UTC", "3.8.0")
        header = BACKUP.read_header(document)
        self.assertEqual((header["created"], header["release"]), ("2026-11-22 06:40 UTC", "3.8.0"))
        # Серверу, который хранит файл, содержимое не видно.
        self.assertNotIn(b"vault-password", document)
        self.assertNotIn(b"PRIVATE KEY", document)
        self.assertEqual(BACKUP.decrypt(document, key), plaintext)
        with self.assertRaisesRegex(BACKUP.BackupError, "не подходит"):
            BACKUP.decrypt(document, BACKUP.new_recovery_key())
        damaged = json.loads(document)
        damaged["cluster_id"] = "d" * 32
        with self.assertRaisesRegex(BACKUP.BackupError, "не подходит"):
            BACKUP.decrypt(json.dumps(damaged).encode("ascii"), key)
        with self.assertRaisesRegex(BACKUP.BackupError, "не является резервной копией"):
            BACKUP.decrypt(b"not a backup", key)


class RestoreTests(ArchiveCase):
    def restore(self, plaintext: bytes) -> tuple[list[str], "BACKUP.RestorePaths", Path]:
        new = self.dir / "new-entry"
        manifest = BACKUP.extract(plaintext, new / "work")
        paths = BACKUP.RestorePaths(
            production=new / "repo" / "inventory" / "production",
            vault_password=new / "home" / ".config" / "awg-iac" / "production-vault.pass",
            ssh_private_key=new / "home" / ".ssh" / "awg-iac-production",
            state_root=new / "home" / ".local" / "share" / "awg-iac" / "production",
            root=new / "root",
        )
        return BACKUP.restore_layout(new / "work", manifest, paths), paths, new

    def test_state_lands_where_the_installer_and_the_services_expect_it(self) -> None:
        restored, paths, new = self.restore(self.layout.archive()[0])
        self.assertEqual((paths.production / "hosts.yml").read_text(encoding="utf-8"), "all: {children: {}}\n")
        self.assertEqual(paths.vault_password.read_text(encoding="utf-8"), "vault-password\n")
        self.assertEqual(paths.ssh_private_key.read_text(encoding="utf-8"), "PRIVATE KEY\n")
        self.assertTrue(paths.ssh_private_key.with_name("awg-iac-production.pub").is_file())
        self.assertEqual((paths.state_root / "mtu.yml").read_text(encoding="utf-8"), "client_mtu: 1380\n")
        self.assertTrue((paths.state_root / "clients" / "phone.conf").is_file())
        # Конфигурации служб - обычными файлами: первый deploy перенесёт их в
        # хранилище секретов, как при чистой установке.
        root = new / "root"
        self.assertEqual((root / "etc/amnezia/amneziawg/awg0.conf").read_text(encoding="utf-8"), "[Interface]\nPrivateKey = entry\n")
        self.assertTrue((root / "etc/awg/client-peers/laptop.conf").is_file())
        self.assertTrue((root / "etc/awg/controller-backup.key").is_file())
        self.assertTrue((root / "etc/awg-telegram-monitor.env").is_file())
        # Того, чего в копии не было (RU-прокси выключен), на сервере не появляется.
        self.assertFalse((root / "etc/sing-box").exists())
        self.assertIn("production inventory", restored)
        self.assertIn("/etc/amnezia/amneziawg", restored)
        # Файлы контроллера раскладываются своими путями, а не по списку служб.
        self.assertFalse((root / "root/.ssh").exists())

    def test_secrets_stay_readable_by_root_only(self) -> None:
        _restored, paths, new = self.restore(self.layout.archive()[0])
        for path in (
            paths.vault_password,
            paths.ssh_private_key,
            new / "root" / "etc/amnezia/amneziawg/awg0.conf",
        ):
            self.assertEqual(path.stat().st_mode & 0o077, 0, path)
        self.assertEqual((new / "root" / "etc/awg").stat().st_mode & 0o077, 0)

    def test_server_with_an_installation_is_left_untouched(self) -> None:
        plaintext = self.layout.archive()[0]
        new = self.dir / "new-entry"
        manifest = BACKUP.extract(plaintext, new / "work")
        paths = BACKUP.RestorePaths(
            production=new / "production",
            vault_password=new / "vault.pass",
            ssh_private_key=new / "ssh" / "awg-iac-production",
            state_root=new / "state",
            root=new / "root",
        )
        # Путь службы - ссылка в хранилище секретов: KalimeraWG уже установлен.
        (new / "root" / "etc").mkdir(parents=True)
        (new / "root" / "etc" / "awg").symlink_to(self.layout.runtime / "awg")
        with self.assertRaisesRegex(BACKUP.BackupError, "уже установлен"):
            BACKUP.restore_layout(new / "work", manifest, paths)
        self.assertFalse(paths.production.exists())
        self.assertFalse(paths.vault_password.exists())
        (new / "root" / "etc" / "awg").unlink()
        paths.production.mkdir(parents=True)
        with self.assertRaisesRegex(BACKUP.BackupError, "уже существует"):
            BACKUP.restore_layout(new / "work", manifest, paths)

    def test_unsafe_archive_is_refused(self) -> None:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            info = tarfile.TarInfo("../escape")
            info.size = 0
            archive.addfile(info, io.BytesIO(b""))
        with self.assertRaisesRegex(BACKUP.BackupError, "небезопасный путь"):
            BACKUP.extract(stream.getvalue(), self.dir / "unsafe")


class RunBackupTests(ArchiveCase):
    """run_controller_backup с подставным Ansible и путями во временном каталоге."""

    def setUp(self) -> None:
        super().setUp()
        self.repo = self.dir / "repo"
        (self.repo / "VERSION").write_text("3.8.0\n", encoding="utf-8")
        hosts = {
            "all": {
                "children": {
                    "entry": {"hosts": {"entry-managed": {"ansible_connection": "local"}}},
                    "exit": {"hosts": {"exit-managed": {"ansible_host": "192.0.2.20"}}},
                    "front": {"hosts": {"front-managed": {"ansible_host": "192.0.2.30"}}},
                }
            }
        }
        (self.layout.production / "hosts.yml").write_text(yaml.safe_dump(hosts), encoding="utf-8")
        config = self.dir / "config.json"
        config.write_text(
            json.dumps({"runtime_root": str(self.layout.runtime), "cluster_id": "c" * 32, "mappings": self.layout.mappings}),
            encoding="utf-8",
        )
        self.key = BACKUP.new_recovery_key()
        self.key_path = self.layout.runtime / "awg" / "controller-backup.key"
        self.key_path.write_text(BACKUP.format_recovery_key(self.key) + "\n", encoding="ascii")
        self.status_dir = self.dir / "var" / "controller-backup"
        self.pushed: list[tuple[str, bytes]] = []
        self.refuse: set[str] = set()

        def adhoc(_repo, _hosts, _vault, group, module, module_args, **kwargs):
            source = Path(module_args.split("src=", 1)[1].split(" ", 1)[0])
            self.assertEqual(module, "ansible.builtin.copy")
            self.assertIn("mode=0600", module_args)
            # Файл принадлежит root и идёт дольше обычной короткой команды.
            self.assertTrue(kwargs["become"])
            self.assertGreaterEqual(kwargs["timeout"], 300)
            if group in self.refuse:
                return subprocess.CompletedProcess([], 2, "", "UNREACHABLE")
            self.pushed.append((group, source.read_bytes()))
            return subprocess.CompletedProcess([], 0, "CHANGED", "")

        self.staging = self.dir / "staging"
        self.staging.mkdir()
        patches = [
            mock.patch.object(DEPLOY, "RUNTIME_SECRETS_CONFIG", config),
            mock.patch.object(DEPLOY, "CONTROLLER_BACKUP_KEY", self.key_path),
            mock.patch.object(DEPLOY, "CONTROLLER_BACKUP_DIR", self.status_dir),
            mock.patch.object(DEPLOY, "CONTROLLER_BACKUP_STATUS", self.status_dir / "status"),
            # Файл для отправки пишется в /run: в тесте - во временный каталог.
            mock.patch.object(DEPLOY, "CONTROLLER_BACKUP_STAGING_DIR", self.staging),
            mock.patch.object(DEPLOY, "ansible_adhoc", adhoc),
            mock.patch.object(DEPLOY.Path, "home", staticmethod(lambda: self.dir / "home")),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def run_backup(self, **kwargs) -> tuple[bool, str]:
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            result = DEPLOY.run_controller_backup(self.repo, self.layout.production, self.dir / "vault.pass", **kwargs)
        return result, output.getvalue()

    def status(self) -> dict[str, str]:
        return DEPLOY.read_controller_backup_status()

    def test_copy_is_stored_on_both_servers_and_opens_with_the_key(self) -> None:
        result, output = self.run_backup()
        self.assertTrue(result, output)
        self.assertEqual([group for group, _document in self.pushed], ["exit", "front"])
        self.assertIn("сохранена: EXIT, FRONT", output)
        plaintext = BACKUP.decrypt(self.pushed[0][1], self.key)
        self.assertIn("runtime/controller/production-vault.pass", self.names(plaintext))
        status = self.status()
        self.assertEqual((status["stored"], status["failed"]), ("exit,front", ""))
        # Файл для отправки удалён: расшифрованных и промежуточных копий не остаётся.
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_unchanged_state_is_not_sent_again(self) -> None:
        self.run_backup()
        self.pushed.clear()
        result, output = self.run_backup()
        self.assertTrue(result)
        self.assertEqual(self.pushed, [])
        self.assertIn("актуальна", output)
        # Новый клиент меняет состояние: копия уходит заново.
        (self.layout.runtime / "awg" / "client-peers" / "tablet.conf").write_text("[Peer]\n", encoding="utf-8")
        self.run_backup()
        self.assertEqual(len(self.pushed), 2)

    def test_unchanged_copy_is_refreshed_after_a_week(self) -> None:
        # Так обнаруживается сервер, на котором файл копии пропал.
        self.run_backup()
        self.pushed.clear()
        status = self.status()
        old = int(time.time()) - 7 * 86400
        DEPLOY.write_controller_backup_status(status["digest"], ["exit", "front"], [], old)
        self.run_backup()
        self.assertEqual(len(self.pushed), 2)

    def test_unreachable_server_is_named_and_retried(self) -> None:
        self.refuse = {"front"}
        result, output = self.run_backup()
        self.assertFalse(result)
        self.assertIn("не сохранена: FRONT", output)
        self.assertEqual((self.status()["stored"], self.status()["failed"]), ("exit", "front"))
        self.refuse = set()
        self.pushed.clear()
        result, _output = self.run_backup()
        self.assertTrue(result)
        self.assertEqual(len(self.pushed), 2)

    def test_closed_secret_store_stops_the_copy(self) -> None:
        (self.layout.runtime / ".unlocked").unlink()
        with self.assertRaises(SystemExit) as raised:
            self.run_backup()
        self.assertIn("закрыто", str(raised.exception))
        self.assertEqual(self.pushed, [])

    def test_separate_controller_is_told_to_keep_its_own_copy(self) -> None:
        hosts = yaml.safe_load((self.layout.production / "hosts.yml").read_text(encoding="utf-8"))
        hosts["all"]["children"]["entry"]["hosts"]["entry-managed"] = {"ansible_host": "192.0.2.10"}
        (self.layout.production / "hosts.yml").write_text(yaml.safe_dump(hosts), encoding="utf-8")
        result, output = self.run_backup()
        self.assertFalse(result)
        self.assertIn("управляющий компьютер отдельный", output)
        self.assertEqual(self.pushed, [])

    def test_new_key_is_sealed_before_any_copy_is_sent(self) -> None:
        # Ключ лежит в tmpfs: копия, зашифрованная несохранённым ключом, после
        # перезагрузки ENTRY осталась бы без ключа.
        self.key_path.unlink()
        calls: list[list[str]] = []

        def seal(argv, **_kwargs):
            calls.append(list(argv))
            self.assertEqual(self.pushed, [])
            return subprocess.CompletedProcess(argv, 0, "changed\n", "")

        with mock.patch.object(DEPLOY.subprocess, "run", seal):
            result, output = self.run_backup()
        self.assertTrue(result, output)
        self.assertEqual(calls, [[str(DEPLOY.SECRETCTL_PATH), "seal"]])
        self.assertIn("controller-backup key", output)
        key = BACKUP.parse_recovery_key(self.key_path.read_text(encoding="ascii"))
        self.assertEqual(self.key_path.stat().st_mode & 0o077, 0)
        BACKUP.decrypt(self.pushed[0][1], key)

    def test_key_that_could_not_be_sealed_is_not_kept(self) -> None:
        self.key_path.unlink()
        failed = subprocess.CompletedProcess([], 1, "", "peer не выдал допустимую долю")
        with mock.patch.object(DEPLOY.subprocess, "run", lambda *_args, **_kwargs: failed):
            with self.assertRaises(SystemExit) as raised:
                self.run_backup()
        self.assertIn("не сохранён в зашифрованный пакет", str(raised.exception))
        self.assertFalse(self.key_path.exists())
        self.assertEqual(self.pushed, [])


class RestoreEntryTests(ArchiveCase):
    """Команда --restore-entry: от файла копии и ключа до разложенного состояния."""

    def setUp(self) -> None:
        super().setUp()
        self.new = self.dir / "new-entry"
        self.repo = self.new / "repo"
        self.repo.mkdir(parents=True)
        (self.repo / "VERSION").write_text("3.8.0\n", encoding="utf-8")
        self.production = self.repo / "inventory" / "production"
        self.vault_password = self.new / "home" / ".config" / "awg-iac" / "production-vault.pass"
        # Пути служб в копии абсолютные; в тесте они ведут во временный каталог.
        self.service_root = self.new / "server"
        self.layout.mappings = [
            {"source": str(self.service_root / "etc/amnezia/amneziawg"), "target": "amneziawg"},
            {"source": str(self.service_root / "etc/awg"), "target": "awg"},
            {"source": "/root/.config/awg-iac/production-vault.pass", "target": "controller/production-vault.pass"},
            {"source": "/root/.ssh/awg-iac-production", "target": "controller/awg-iac-production"},
        ]
        self.key = BACKUP.new_recovery_key()
        plaintext, _digest = self.layout.archive(created="2026-11-22 06:40 UTC")
        self.capsule = self.new / "controller.kbk"
        self.capsule.write_bytes(BACKUP.encrypt(plaintext, self.key, "c" * 32, "2026-11-22 06:40 UTC", "3.8.0"))
        self.key_file = self.new / "recovery.key"
        self.key_file.write_text(BACKUP.format_recovery_key(self.key) + "\n", encoding="ascii")
        staging = self.new / "run"
        staging.mkdir()
        for patch in (
            mock.patch.object(DEPLOY.os, "geteuid", lambda: 0),
            mock.patch.object(DEPLOY, "CONTROLLER_BACKUP_STAGING_DIR", staging),
            mock.patch.object(DEPLOY.Path, "home", staticmethod(lambda: self.new / "home")),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.staging = staging

    def restore(self, key_file: Path | None = None) -> str:
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            DEPLOY.restore_entry(self.repo, self.production, self.vault_password, self.capsule, key_file or self.key_file)
        return output.getvalue()

    def test_new_server_gets_the_controller_and_the_service_state(self) -> None:
        output = self.restore()
        self.assertIn("Копия контроллера от 2026-11-22 06:40 UTC, выпуск KalimeraWG 3.8.0.", output)
        self.assertIn("Восстановлено из копии: production inventory", output)
        self.assertTrue((self.production / "hosts.yml").is_file())
        self.assertEqual(self.vault_password.read_text(encoding="utf-8"), "vault-password\n")
        self.assertTrue((self.new / "home" / ".ssh" / "awg-iac-production").is_file())
        self.assertTrue((self.service_root / "etc/amnezia/amneziawg/awg0.conf").is_file())
        self.assertTrue((self.service_root / "etc/awg/client-peers/laptop.conf").is_file())
        # Распакованная копия удалена: открытое состояние остаётся только на своих местах.
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_wrong_key_changes_nothing(self) -> None:
        other = self.new / "other.key"
        other.write_text(BACKUP.format_recovery_key(BACKUP.new_recovery_key()), encoding="ascii")
        with self.assertRaises(SystemExit) as raised:
            self.restore(other)
        self.assertIn("не подходит", str(raised.exception))
        self.assertFalse(self.production.exists())
        self.assertFalse(self.vault_password.exists())
        self.assertEqual(list(self.staging.iterdir()), [])

    def test_key_is_asked_without_echo_when_no_file_is_given(self) -> None:
        output = io.StringIO()
        with mock.patch.object(DEPLOY.getpass, "getpass", lambda _prompt: BACKUP.format_recovery_key(self.key)):
            with mock.patch("sys.stdout", output):
                DEPLOY.restore_entry(self.repo, self.production, self.vault_password, self.capsule, None)
        self.assertTrue(self.production.is_dir())

    def test_installed_server_is_refused(self) -> None:
        self.production.mkdir(parents=True)
        with self.assertRaises(SystemExit) as raised:
            self.restore()
        self.assertIn("на чистом сервере", str(raised.exception))

    def test_other_release_needs_a_confirmation(self) -> None:
        (self.repo / "VERSION").write_text("3.9.0\n", encoding="utf-8")
        with mock.patch.object(DEPLOY, "prompt_bool", lambda *_args: False):
            with self.assertRaises(SystemExit) as raised:
                self.restore()
        self.assertIn("состояние сервера не менялось", str(raised.exception))
        self.assertFalse(self.production.exists())
        with mock.patch.object(DEPLOY, "prompt_bool", lambda *_args: True):
            output = self.restore()
        self.assertIn("Копия создана выпуском 3.8.0, а здесь выпуск 3.9.0", output)
        self.assertTrue(self.production.is_dir())

    def test_changed_address_is_explained_after_the_restore(self) -> None:
        # EXIT и FRONT разрешают ключ оркестратора только с прежнего адреса ENTRY.
        hosts = {
            "all": {
                "children": {
                    "entry": {"hosts": {"entry-managed": {"ansible_connection": "local"}}},
                    "exit": {"hosts": {"exit-managed": {"ansible_host": "192.0.2.20", "ansible_user": "kalimera", "ansible_port": 56777, "ansible_ssh_private_key_file": "/root/.ssh/awg-iac-production"}}},
                    "front": {"hosts": {"front-managed": {"ansible_host": "192.0.2.30", "ansible_user": "kalimera", "ansible_port": 56777, "ansible_ssh_private_key_file": "/root/.ssh/awg-iac-production"}}},
                }
            }
        }
        with mock.patch.object(DEPLOY, "ssh_connection_works", lambda host, *_args: host != "192.0.2.30"):
            with self.assertRaises(SystemExit) as raised:
                DEPLOY.require_restored_access(hosts)
        message = str(raised.exception)
        self.assertIn("front-managed (192.0.2.30)", message)
        self.assertNotIn("exit-managed", message)
        self.assertIn("прежнего публичного адреса ENTRY", message)
        self.assertIn("повторять --restore-entry не нужно", message)
        with mock.patch.object(DEPLOY, "ssh_connection_works", lambda *_args: True):
            DEPLOY.require_restored_access(hosts)

    def test_restore_is_not_mixed_with_other_modes(self) -> None:
        for extra in (["--resume"], ["--controller-backup"], ["--cascade-reboot"]):
            argv = ["deploy", "--repo-root", str(self.repo), "--restore-entry", str(self.capsule), *extra]
            with mock.patch.object(sys, "argv", argv), mock.patch("sys.stderr", io.StringIO()) as errors:
                with self.assertRaises(SystemExit) as raised:
                    DEPLOY.main()
            self.assertEqual(raised.exception.code, 2, extra)
            self.assertIn("--restore-entry выполняется отдельно", errors.getvalue())
        argv = ["deploy", "--repo-root", str(self.repo), "--recovery-key-file", str(self.key_file)]
        with mock.patch.object(sys, "argv", argv), mock.patch("sys.stderr", io.StringIO()) as errors:
            with self.assertRaises(SystemExit):
                DEPLOY.main()
        self.assertIn("только вместе с --restore-entry", errors.getvalue())


class ReportRowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bash = bash_path()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def row(self, status: str | None, **variables) -> str:
        values = {
            "awg_node_role": "entry",
            "runtime_secrets_enabled": True,
            "runtime_secrets_controller_vault_password_path": "/root/.config/awg-iac/production-vault.pass",
            "awg_controller_backup_dir": str(self.dir),
            **variables,
        }
        if status is not None:
            (self.dir / "status").write_text(status + "\n", encoding="utf-8")
        script = self.dir / "kalimera-report"
        script.write_text(render(REPORT, **values), encoding="utf-8")
        result = subprocess.run(
            [self.bash, "-c", f"source {shlex.quote(str(script))}\ncheck_controller_backup\n"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def status(self, *, age_days: float = 0, stored: str = "exit,front", failed: str = "") -> str:
        epoch = int(time.time() - age_days * 86400)
        return "\t".join((str(epoch), "2026-11-22 06:41 UTC", "a" * 64, stored, failed, str(epoch)))

    def test_fresh_copy_on_both_servers_is_ok(self) -> None:
        self.assertEqual(
            self.row(self.status()),
            "ENTRY\tOK\tрезервная копия состояния контроллера сохранена\t2026-11-22 06:41 UTC: EXIT, FRONT\t\t\n",
        )

    def test_missing_copy_is_a_warning_with_the_command(self) -> None:
        output = self.row(None)
        self.assertTrue(output.startswith("ENTRY\tWARN\tрезервная копия состояния контроллера не создана\t\t"), output)
        self.assertIn("controller-backup key", output)

    def test_server_without_the_copy_is_named(self) -> None:
        output = self.row(self.status(stored="exit", failed="front"))
        self.assertIn("\tWARN\tрезервная копия состояния контроллера сохранена не на всех серверах\t", output)
        self.assertIn("нет на FRONT", output)

    def test_stale_copy_is_a_warning(self) -> None:
        output = self.row(self.status(age_days=4))
        self.assertIn("\tWARN\tрезервная копия состояния контроллера устарела\t2026-11-22 06:41 UTC\t", output)

    def test_no_row_without_a_local_controller(self) -> None:
        self.assertEqual(self.row(None, runtime_secrets_controller_vault_password_path=""), "")
        self.assertEqual(self.row(None, runtime_secrets_enabled=False), "")


class RoleTests(unittest.TestCase):
    def test_wrapper_runs_only_the_two_planned_jobs(self) -> None:
        bash = bash_path()
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "kalimera-weekly"
            script.write_text(
                render(WRAPPER, security_controller_repo_path=f"{directory}/repo", kalimera_controller_venv_path=f"{directory}/venv"),
                encoding="utf-8",
            )
            for arguments, code in ((["--resume"], 2), (["--controller-backup", "x"], 2), (["--controller-backup"], 0), ([], 0)):
                result = subprocess.run([bash, str(script), *arguments], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, code, (arguments, result.stderr))

    def test_daily_timer_runs_the_copy_and_a_missed_run_is_made_up(self) -> None:
        self.assertIn("--controller-backup\n", SERVICE.read_text(encoding="utf-8"))
        # Не сохранённая на одном сервере копия - не отказ службы: о ней сообщает отчёт.
        self.assertIn("SuccessExitStatus=1\n", SERVICE.read_text(encoding="utf-8"))
        self.assertIn("Persistent=true\n", TIMER.read_text(encoding="utf-8"))
        tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        directory = next(task for task in tasks if task["name"] == "Создание каталога резервной копии состояния контроллера")
        # Каталог нужен на каждом сервере: EXIT и FRONT хранят в нём файл копии.
        self.assertNotIn("when", directory)
        enable = next(task for task in tasks if task["name"] == "Включение ежедневной резервной копии контроллера")
        self.assertIn("awg_node_role == 'entry'", enable["when"])
        defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        self.assertEqual(defaults["awg_controller_backup_dir"], str(DEPLOY.CONTROLLER_BACKUP_DIR))

    def gateway(self, role: str, *arguments: str, directory: Path) -> subprocess.CompletedProcess[str]:
        script = directory / f"gateway-{role}"
        text = render(
            GATEWAY,
            awg_node_role=role,
            security_controller_repo_path=str(directory / "repo"),
            awg_controller_backup_dir=str(directory / "backup"),
        ).replace("[[ $EUID -eq 0 ]] ||", "true ||", 1)
        script.write_text(text, encoding="utf-8")
        return subprocess.run([bash_path(), str(script), "controller-backup", *arguments], capture_output=True, text=True, timeout=30)

    def test_storing_server_hands_out_only_the_encrypted_file(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            result = self.gateway("exit", "export", directory=directory)
            self.assertEqual(result.returncode, 1)
            self.assertIn("нет", result.stderr)
            (directory / "backup").mkdir()
            (directory / "backup" / "controller.kbk").write_text('{"kind":"kalimera-controller-backup"}\n', encoding="utf-8")
            result = self.gateway("exit", "export", directory=directory)
            self.assertEqual((result.returncode, result.stdout), (0, '{"kind":"kalimera-controller-backup"}\n'))
            # Ключ и создание копии - только на ENTRY.
            for arguments in ((), ("key",)):
                self.assertEqual(self.gateway("front", *arguments, directory=directory).returncode, 2)

    def test_entry_runs_the_copy_and_shows_the_key_through_the_installer(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "repo").mkdir()
            deploy = directory / "repo" / "deploy"
            deploy.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*"\n', encoding="utf-8")
            deploy.chmod(0o755)
            self.assertEqual(self.gateway("entry", directory=directory).stdout, "--controller-backup\n")
            self.assertEqual(self.gateway("entry", "key", directory=directory).stdout, "--controller-backup-key\n")
            self.assertEqual(self.gateway("entry", "export", directory=directory).returncode, 2)

    def test_command_is_available_to_the_administrator(self) -> None:
        self.assertIn('function controller-backup { _kalimera_admin controller-backup "$@"; }', SHELL_TOOLS.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

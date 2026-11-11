"""Установленный ключ PPA AmneziaWG не должен требовать keyserver.ubuntu.com.

get_url с force: false всё равно делает условный запрос, и при недоступном
keyserver deploy падал, хотя правильный ключ уже лежал на сервере. Тест
запускает настоящие задачи роли с настоящим GPG-ключом и заведомо
недоступным адресом ключа.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
TASKS = ROOT / "roles" / "amneziawg" / "tasks" / "main.yml"
KEY_TASKS = (
    "Проверка уже установленного ключа PPA AmneziaWG",
    "Загрузка отдельного ключа PPA AmneziaWG",
    "Права установленного ключа PPA AmneziaWG",
    "Проверка полного отпечатка ключа PPA AmneziaWG",
)
UNREACHABLE_URL = "http://127.0.0.1:9/pks/lookup?op=get"


def key_tasks() -> list[dict]:
    tasks = {task["name"]: task for task in yaml.safe_load(TASKS.read_text(encoding="utf-8"))}
    selected = []
    for name in KEY_TASKS:
        task = dict(tasks[name])
        # Тест идёт без root: владелец root здесь недостижим и к логике не относится.
        for module in ("ansible.builtin.get_url", "ansible.builtin.file"):
            if module in task:
                task[module] = {
                    key: value
                    for key, value in task[module].items()
                    if key not in ("owner", "group")
                }
        selected.append(task)
    return selected


class PpaKeyOfflineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.playbook_bin = shutil.which("ansible-playbook")
        if self.playbook_bin is None or os.name == "nt" or not Path("/usr/bin/gpg").exists():
            self.skipTest("нужны ansible-playbook и /usr/bin/gpg на Linux")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.gnupg = self.root / "gnupg"
        self.gnupg.mkdir(mode=0o700)
        self.fingerprint = self.generate_key("ppa@example.invalid")

    def tearDown(self) -> None:
        subprocess.run(
            ["gpgconf", "--kill", "all"],
            env={**os.environ, "GNUPGHOME": str(self.gnupg)},
            check=False,
            capture_output=True,
        )
        self.temporary.cleanup()

    def gpg(self, *args: str) -> str:
        return subprocess.run(
            ["/usr/bin/gpg", "--batch", "--homedir", str(self.gnupg), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def generate_key(self, uid: str) -> str:
        self.gpg(
            "--pinentry-mode", "loopback", "--passphrase", "",
            "--quick-gen-key", uid, "ed25519", "sign", "never",
        )
        for line in self.gpg("--with-colons", "--list-keys", uid).splitlines():
            if line.startswith("fpr:"):
                return line.split(":")[9]
        raise AssertionError("отпечаток тестового ключа не найден")

    def write_key(self, uid: str, path: Path) -> None:
        path.write_text(self.gpg("--armor", "--export", uid), encoding="utf-8")

    def run_tasks(self, keyring: Path) -> subprocess.CompletedProcess[str]:
        playbook = self.root / "play.yml"
        playbook.write_text(
            yaml.safe_dump(
                [
                    {
                        "hosts": "localhost",
                        "connection": "local",
                        "gather_facts": False,
                        "vars": {
                            "amneziawg_ppa_key_url": UNREACHABLE_URL,
                            "amneziawg_ppa_keyring_path": str(keyring),
                            "amneziawg_ppa_fingerprint": self.fingerprint,
                        },
                        "tasks": key_tasks(),
                    }
                ],
                allow_unicode=True,
            ),
            encoding="utf-8",
        )
        return subprocess.run(
            [self.playbook_bin, "-i", "localhost,", str(playbook)],
            capture_output=True,
            text=True,
            env={**os.environ, "ANSIBLE_NOCOLOR": "1", "ANSIBLE_FORCE_COLOR": "0"},
            timeout=180,
        )

    def test_installed_key_needs_no_keyserver(self) -> None:
        keyring = self.root / "amnezia-ppa.asc"
        self.write_key("ppa@example.invalid", keyring)
        result = self.run_tasks(keyring)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # ansible.cfg проекта скрывает пропущенные задачи, поэтому пропуск
        # загрузки виден по итогам PLAY RECAP и отсутствию обращения к адресу.
        self.assertRegex(result.stdout, r"localhost\s*:.*\bskipped=1\b")
        self.assertNotIn("127.0.0.1:9", result.stdout + result.stderr)

    def test_missing_key_is_downloaded(self) -> None:
        keyring = self.root / "amnezia-ppa.asc"
        result = self.run_tasks(keyring)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("127.0.0.1:9", result.stdout)
        self.assertFalse(keyring.exists())

    def test_wrong_key_is_replaced(self) -> None:
        keyring = self.root / "amnezia-ppa.asc"
        self.generate_key("other@example.invalid")
        self.write_key("other@example.invalid", keyring)
        result = self.run_tasks(keyring)
        # Попытка скачать правильный ключ (здесь недоступный) вместо чужого.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("127.0.0.1:9", result.stdout)


if __name__ == "__main__":
    unittest.main()

"""Недоступный PPA AmneziaWG не должен ронять обычный deploy.

Launchpad регулярно бывает недоступен часами. Установленным и закреплённым
пакетам AmneziaWG он не нужен, поэтому обычный --resume продолжается с
предупреждением. Остановка - только когда PPA действительно нужен (первая
установка, обновление пакетов) или когда не ответили репозитории Ubuntu.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
TASKS = ROOT / "roles" / "common" / "tasks" / "apt-refresh.yml"
MODULE_PATH = ROOT / "scripts" / "lib" / "interactive_deploy.py"

PPA_DOWN = (
    "W: Failed to fetch https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/noble/InRelease"
    "  Could not connect to ppa.launchpadcontent.net:443 (185.125.189.187), connection timed out\n"
    "W: Some index files failed to download. They have been ignored, or old ones used instead.\n"
)
MIRROR_DOWN = (
    "W: Failed to fetch http://mirror.example.invalid/ubuntu/dists/noble-updates/InRelease"
    "  Could not connect to mirror.example.invalid:80, connection timed out\n"
)


def run_refresh(
    *,
    apt_stderr: str = "",
    apt_rc: int = 0,
    amneziawg_installed: bool = True,
    refresh: bool = False,
    role: str = "entry",
) -> subprocess.CompletedProcess[str]:
    playbook_bin = shutil.which("ansible-playbook")
    if playbook_bin is None or os.name == "nt":
        raise unittest.SkipTest("нужен ansible-playbook на Linux")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        apt = root / "apt-get"
        apt.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\\n'\n"
            f"cat >&2 <<'EOF'\n{apt_stderr}EOF\n"
            f"exit {apt_rc}\n",
            encoding="utf-8",
        )
        dpkg = root / "dpkg-query"
        dpkg.write_text(
            "#!/usr/bin/env bash\n"
            + ("printf 'ii '\n" if amneziawg_installed else "exit 1\n"),
            encoding="utf-8",
        )
        for path in (apt, dpkg):
            path.chmod(0o755)
        playbook = root / "play.yml"
        playbook.write_text(
            textwrap.dedent(
                f"""\
                - hosts: localhost
                  connection: local
                  gather_facts: false
                  vars:
                    awg_node_role: {role}
                    awg_package_refresh: {str(refresh).lower()}
                    common_apt_optional_source_pattern: ppa.launchpadcontent.net/amnezia/
                    common_apt_get_path: {apt}
                    common_dpkg_query_path: {dpkg}
                  tasks:
                    - ansible.builtin.include_tasks: {TASKS}
                """
            ),
            encoding="utf-8",
        )
        return subprocess.run(
            [playbook_bin, "-i", "localhost,", str(playbook)],
            capture_output=True,
            text=True,
            env={**os.environ, "ANSIBLE_NOCOLOR": "1", "ANSIBLE_FORCE_COLOR": "0"},
        )


class AptRefreshTests(unittest.TestCase):
    def test_all_sources_reachable(self) -> None:
        result = run_refresh()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("недоступен", result.stdout)

    def test_ppa_down_with_installed_packages_continues(self) -> None:
        result = run_refresh(apt_stderr=PPA_DOWN)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("PPA AmneziaWG на Launchpad сейчас недоступен", result.stdout)

    def test_ppa_down_on_first_install_stops_clearly(self) -> None:
        result = run_refresh(apt_stderr=PPA_DOWN, amneziawg_installed=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("нужно установить", result.stdout)
        self.assertIn("Серверы не изменены", result.stdout)

    def test_ppa_down_during_package_update_stops_clearly(self) -> None:
        result = run_refresh(apt_stderr=PPA_DOWN, refresh=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("нужно обновить", result.stdout)

    def test_ubuntu_mirror_down_stops(self) -> None:
        result = run_refresh(apt_stderr=MIRROR_DOWN)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Не отвечают репозитории пакетов", result.stdout)
        self.assertIn("mirror.example.invalid", result.stdout)

    def test_apt_error_exit_stops(self) -> None:
        result = run_refresh(apt_stderr="E: The repository is not signed.\n", apt_rc=100)
        self.assertNotEqual(result.returncode, 0)

    def test_front_ignores_amneziawg_check(self) -> None:
        result = run_refresh(role="front", amneziawg_installed=False)
        self.assertEqual(result.returncode, 0, result.stdout)


class UpdatePrecheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("interactive_deploy_ppa", MODULE_PATH)
        assert spec and spec.loader
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_unreachable_ppa_blocks_update_before_changes(self) -> None:
        with mock.patch.object(self.module, "_http_get", side_effect=OSError("timed out")):
            with self.assertRaises(SystemExit) as raised:
                self.module.require_amneziawg_ppa(ROOT)
        self.assertIn("Серверы не изменены", str(raised.exception))

    def test_reachable_ppa_passes(self) -> None:
        with mock.patch.object(self.module, "_http_get", return_value=b"") as get:
            self.module.require_amneziawg_ppa(ROOT)
        self.assertTrue(get.call_args.args[0].endswith("/dists/noble/InRelease"))

    def test_precheck_runs_before_ssh_transition(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        main = source[source.index("\ndef main()"):]
        self.assertLess(
            main.index("require_amneziawg_ppa(repo)"),
            main.index("complete_ssh_transition("),
        )


if __name__ == "__main__":
    unittest.main()

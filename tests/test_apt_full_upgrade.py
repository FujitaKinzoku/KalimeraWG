"""Общая часть ночного обслуживания и update-all: все обновления и новое ядро.

Шаблон apt-full-upgrade.inc.j2 запускается в bash с подставными apt-get,
apt-mark, apt-cache, dpkg-query и uname, которые записывают свои вызовы.
Проверяется, что AmneziaWG и sing-box удерживаются только на время работы,
обновление не задаёт вопросов о конфигурационных файлах, а новое ядро
ставится метапакетом той же сборки (на ENTRY и EXIT - с заголовками).
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import jinja2

ROOT = Path(__file__).parents[1]
TEMPLATES = ROOT / "roles" / "operations" / "templates"

FAKES = {
    "apt-get": 'printf "apt-get %s\\n" "$*" >>"$CALLS"',
    "apt-mark": textwrap.dedent(
        """\
        printf 'apt-mark %s\\n' "$*" >>"$CALLS"
        [[ "$1" != showhold ]] || printf '%s\\n' $FAKE_ALREADY_HELD
        """
    ),
    "apt-cache": textwrap.dedent(
        """\
        [[ "$1" == show && " $FAKE_KNOWN_PACKAGES " == *" $2 "* ]]
        """
    ),
    "dpkg-query": textwrap.dedent(
        """\
        package="${@: -1}"
        [[ " $FAKE_INSTALLED " == *" $package "* ]]
        """
    ),
    "uname": 'printf "%s\\n" "$FAKE_RUNNING_KERNEL"',
    "systemctl": 'printf "systemctl %s\\n" "$*" >>"$CALLS"',
}


def render(role: str) -> str:
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES)),
        trim_blocks=True,
        undefined=jinja2.StrictUndefined,
    )
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    return environment.get_template("apt-full-upgrade.inc.j2").render(awg_node_role=role)


def run(role: str, **environment: str) -> list[str]:
    bash = shutil.which("bash")
    if bash is None or os.name == "nt":
        raise unittest.SkipTest("нужен bash на Linux")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in FAKES.items():
            path = bin_dir / name
            path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
            path.chmod(0o755)
        calls = root / "calls"
        calls.touch()
        script = root / "upgrade.sh"
        script.write_text(
            "set -Eeuo pipefail\n" + render(role) + "\nawg_full_upgrade\n",
            encoding="utf-8",
        )
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "CALLS": str(calls),
            "FAKE_RUNNING_KERNEL": "6.8.0-149-generic",
            "FAKE_KNOWN_PACKAGES": "linux-image-virtual linux-headers-virtual",
            "FAKE_INSTALLED": "amneziawg amneziawg-dkms amneziawg-tools",
            "FAKE_ALREADY_HELD": "",
            **environment,
        }
        result = subprocess.run(
            [bash, str(script)], capture_output=True, text=True, env=env, check=True
        )
        return calls.read_text(encoding="utf-8").splitlines() + [
            "STDERR " + line for line in result.stderr.splitlines()
        ]


def apt_get(calls: list[str]) -> list[str]:
    return [call for call in calls if call.startswith("apt-get ")]


class FullUpgradeTests(unittest.TestCase):
    def test_entry_order_and_kernel_with_headers(self) -> None:
        calls = run("entry")
        commands = apt_get(calls)
        self.assertEqual(len(commands), 4, calls)
        self.assertTrue(commands[0].endswith(" -q update"), commands)
        self.assertTrue(commands[1].endswith(" -y upgrade"), commands)
        self.assertTrue(
            commands[2].endswith(" -y install linux-image-virtual linux-headers-virtual"),
            commands,
        )
        self.assertTrue(commands[3].endswith(" -y autoremove"), commands)
        for command in commands[1:]:
            self.assertIn("Dpkg::Options::=--force-confold", command)
            self.assertIn("Dpkg::Options::=--force-confdef", command)

    def test_entry_reapplies_policy_routing_after_packages(self) -> None:
        # needrestart после обновления libc перезапускал networkd, а он удалял правило
        # fwmark -> таблица EXIT: трафик клиентов уходил с ENTRY без гео.
        calls = run("entry")
        autoremove = next(i for i, call in enumerate(calls) if call.endswith(" -y autoremove"))
        reload = calls.index("systemctl reload awg-entry-routing.service")
        self.assertLess(autoremove, reload)
        for role in ("exit", "front"):
            self.assertFalse(
                [call for call in run(role) if call.startswith("systemctl ")], role
            )

    def test_amneziawg_is_held_only_during_upgrade(self) -> None:
        calls = run("exit")
        hold = calls.index("apt-mark hold amneziawg")
        upgrade = next(i for i, call in enumerate(calls) if call.endswith(" -y upgrade"))
        unhold = calls.index("apt-mark unhold amneziawg amneziawg-dkms amneziawg-tools")
        self.assertLess(hold, upgrade)
        self.assertLess(upgrade, unhold)
        # sing-box не установлен - его не удерживаем.
        self.assertNotIn("apt-mark hold sing-box", calls)

    def test_existing_hold_is_kept(self) -> None:
        calls = run("entry", FAKE_ALREADY_HELD="amneziawg-dkms")
        self.assertNotIn("apt-mark hold amneziawg-dkms", calls)
        self.assertIn("apt-mark unhold amneziawg amneziawg-tools", calls)

    def test_front_kernel_without_headers_and_no_holds(self) -> None:
        calls = run("front")
        self.assertIn(
            True,
            [call.endswith(" -y install linux-image-virtual") for call in apt_get(calls)],
            calls,
        )
        self.assertFalse([call for call in calls if call.startswith("apt-mark hold")])

    def test_other_flavour_uses_own_metapackage(self) -> None:
        calls = run(
            "front",
            FAKE_RUNNING_KERNEL="6.8.0-1020-kvm",
            FAKE_KNOWN_PACKAGES="linux-image-kvm",
        )
        self.assertIn(
            True, [call.endswith(" -y install linux-image-kvm") for call in apt_get(calls)]
        )

    def test_missing_metapackage_skips_kernel_but_finishes(self) -> None:
        calls = run("entry", FAKE_KNOWN_PACKAGES="")
        self.assertFalse([call for call in apt_get(calls) if " install " in call])
        self.assertTrue(apt_get(calls)[-1].endswith(" -y autoremove"))
        self.assertIn(
            "STDERR Метапакет linux-image-virtual не найден в репозиториях; "
            "новое ядро не устанавливается.",
            calls,
        )


if __name__ == "__main__":
    unittest.main()

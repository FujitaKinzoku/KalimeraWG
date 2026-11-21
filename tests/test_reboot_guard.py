"""Предохранители перезагрузки: сервер не перезагружается, если может не подняться.

Программа kalimera-reboot-guard запускается целиком в bash с подставными
командами и своим каталогом /boot. Проверяется каждая причина, по которой сервер
не загрузился бы или не вернулся в каскад, и то, что исправный сервер проходит
проверку без единого замечания.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import jinja2

ROOT = Path(__file__).parents[1]
GUARD = ROOT / "roles" / "operations" / "templates" / "reboot-guard.sh.j2"
RUNNING = "6.8.0-90-generic"
NEWER = "6.8.0-100-generic"

# Каждая подставная команда записывает вызов; ответ задаётся файлом в каталоге теста.
FAKES = {
    "uname": f'printf "{RUNNING}\\n"',
    "systemctl": (
        'printf \'systemctl %s\\n\' "$*" >>"$FAKE_DIR/calls.log"\n'
        'case "$1" in\n'
        '    is-active) if grep -Fxq -- "${*: -1}" "$FAKE_DIR/busy-units" 2>/dev/null; then echo activating; else echo inactive; exit 3; fi ;;\n'
        '    is-enabled) [[ ! -e "$FAKE_DIR/unlock-disabled" ]] ;;\n'
        "esac\n"
    ),
    "pgrep": '[[ -e "$FAKE_DIR/dpkg-running" && "${*: -1}" == dpkg ]]',
    "dpkg": '[[ ! -e "$FAKE_DIR/dpkg-broken" ]] || printf "The following packages are only half configured:\\n linux-image\\n"',
    "lsinitramfs": '[[ ! -e "$FAKE_DIR/initrd-broken" ]]',
    "grub-script-check": '[[ ! -e "$FAKE_DIR/grub-broken" ]]',
    "modinfo": '[[ -e "$FAKE_DIR/module-$2" ]]',
    "df": (
        "printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n"
        "/dev/vda1 100 0 0 %s%% /\\n' \"$(cat \"$FAKE_DIR/disk\" 2>/dev/null || echo 40)\""
    ),
    "sshd": '[[ ! -e "$FAKE_DIR/sshd-broken" ]]',
    "secretctl": (
        'printf \'secretctl %s\\n\' "$*" >>"$FAKE_DIR/calls.log"\n'
        '[[ ! -e "$FAKE_DIR/secretctl-$1-fails" ]]\n'
    ),
    # Сборка модуля AmneziaWG под установленные ядра.
    "kernel-guard": (
        'printf \'kernel-guard\\n\' >>"$FAKE_DIR/calls.log"\n'
        '[[ -e "$FAKE_DIR/build-fails" ]] || for image in "$FAKE_DIR"/boot/vmlinuz-*; do : >"$FAKE_DIR/module-${image##*/vmlinuz-}"; done\n'
    ),
}


class GuardCase(unittest.TestCase):
    role = "entry"

    def setUp(self) -> None:
        self.bash = shutil.which("bash")
        if self.bash is None or os.name == "nt":
            self.skipTest("нужен bash на Linux")
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.boot = self.dir / "boot"
        self.modules = self.dir / "modules"
        for directory in (self.bin, self.boot / "grub", self.modules):
            directory.mkdir(parents=True)
        for name, body in FAKES.items():
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8")
            path.chmod(0o755)
        self.kernel(RUNNING)
        self.grub(RUNNING)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def flag(self, name: str, text: str = "") -> None:
        (self.dir / name).write_text(text, encoding="utf-8")

    def kernel(self, version: str, *, module: bool = True) -> None:
        """Установить ядро целиком: образ, initramfs, модули и модуль AmneziaWG."""
        (self.boot / f"vmlinuz-{version}").write_text("kernel", encoding="utf-8")
        (self.boot / f"initrd.img-{version}").write_text("initrd", encoding="utf-8")
        (self.modules / version).mkdir(exist_ok=True)
        (self.modules / version / "modules.dep").write_text("dep", encoding="utf-8")
        if module:
            self.flag(f"module-{version}")

    def grub(self, *versions: str) -> None:
        (self.boot / "grub" / "grub.cfg").write_text(
            "".join(f"linux /boot/vmlinuz-{version} root=/dev/vda1\n" for version in versions), encoding="utf-8"
        )

    def new_kernel(self, **options) -> None:
        self.kernel(NEWER, **options)
        self.grub(NEWER, RUNNING)
        self.flag("reboot-required")

    def script(self, role: str | None = None, **variables) -> Path:
        environment = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
        environment.filters["quote"] = lambda value: shlex.quote(str(value))
        environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
        values = {
            "awg_node_role": role or self.role,
            "runtime_secrets_enabled": True,
            "runtime_secrets_ctl_path": str(self.bin / "secretctl"),
            "awg_kernel_guard_path": str(self.bin / "kernel-guard"),
            "kalimera_deploy_marker_path": str(self.dir / "deploy.active"),
            "awg_reboot_required_path": str(self.dir / "reboot-required"),
            "awg_reboot_guard_boot_dir": str(self.boot),
            "awg_reboot_guard_modules_dir": str(self.modules),
            # Возраст ядра и время работы сервера в большинстве тестов не мешают.
            "awg_auto_reboot_kernel_min_age_hours": 0,
            "awg_auto_reboot_min_uptime_seconds": 0,
            **variables,
        }
        text = environment.from_string(GUARD.read_text(encoding="utf-8")).render(**values)
        path = self.dir / "kalimera-reboot-guard"
        path.write_text(text.replace("[[ $EUID -eq 0 ]] ||", "true ||", 1), encoding="utf-8")
        return path

    def guard(self, mode: str = "check", role: str | None = None, **variables) -> tuple[int, list[list[str]]]:
        env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "FAKE_DIR": str(self.dir)}
        result = subprocess.run(
            [self.bash, str(self.script(role, **variables)), mode], capture_output=True, text=True, env=env, timeout=60
        )
        self.assertEqual(result.stderr, "")
        rows = [line.split("\t") for line in result.stdout.splitlines()]
        for row in rows:
            self.assertEqual(len(row), 3, row)
        return result.returncode, rows

    def by_status(self, rows: list[list[str]], status: str) -> list[str]:
        return [row[1] for row in rows if row[0] == status]

    def calls(self, prefix: str) -> list[str]:
        path = self.dir / "calls.log"
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        return [line for line in lines if line.startswith(prefix)]


class HealthyServerTests(GuardCase):
    def test_healthy_server_without_updates_needs_nothing(self) -> None:
        code, rows = self.guard()
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0], ["NEED", "no", ""])
        self.assertEqual({row[0] for row in rows[1:]}, {"OK"})

    def test_new_kernel_installed_completely_may_be_booted(self) -> None:
        self.new_kernel()
        self.flag("reboot-required.pkgs", "linux-image-6.8.0-100-generic\nlinux-base\n")
        code, rows = self.guard()
        self.assertEqual(code, 0, rows)
        self.assertEqual(rows[0], ["NEED", "yes", "linux-base, linux-image-6.8.0-100-generic"])
        self.assertIn(f"после перезагрузки загрузится ядро {NEWER}", self.by_status(rows, "OK"))
        self.assertIn(f"модуль AmneziaWG собран для ядра {NEWER}", self.by_status(rows, "OK"))
        self.assertIn("хранилище секретов откроется после перезагрузки", self.by_status(rows, "OK"))

    def test_check_changes_nothing(self) -> None:
        self.new_kernel()
        self.guard("check")
        self.assertEqual(self.calls("kernel-guard"), [])
        self.assertEqual(self.calls("secretctl"), ["secretctl check"])

    def test_front_has_no_amneziawg_module_to_check(self) -> None:
        self.new_kernel(module=False)
        code, rows = self.guard(role="front")
        self.assertEqual(code, 0, rows)
        self.assertFalse([row for row in rows if "AmneziaWG" in row[1]])

    def test_rendered_script_passes_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("нужен shellcheck")
        for role in ("entry", "exit", "front"):
            with self.subTest(role=role):
                result = subprocess.run([shellcheck, str(self.script(role))], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class BootSafetyTests(GuardCase):
    """Каждая причина, по которой сервер не загрузился бы или не вернулся в каскад."""

    def assert_blocks(self, label: str, mode: str = "check") -> list[list[str]]:
        code, rows = self.guard(mode)
        self.assertEqual(code, 1, rows)
        self.assertIn(label, self.by_status(rows, "FAIL"))
        return rows

    def test_missing_amneziawg_module_for_the_new_kernel(self) -> None:
        # Каскад не поднялся бы: ни один интерфейс AWG не запустится без модуля.
        self.new_kernel(module=False)
        self.assert_blocks(f"модуль AmneziaWG не собран для ядра {NEWER}")

    def test_prepare_builds_the_module_before_deciding(self) -> None:
        self.new_kernel(module=False)
        code, rows = self.guard("prepare")
        self.assertEqual(code, 0, rows)
        self.assertEqual(self.calls("kernel-guard"), ["kernel-guard"])

    def test_module_that_cannot_be_built_blocks_the_reboot(self) -> None:
        self.new_kernel(module=False)
        self.flag("build-fails")
        self.assert_blocks(f"модуль AmneziaWG не собран для ядра {NEWER}", mode="prepare")

    def test_interrupted_package_installation(self) -> None:
        self.new_kernel()
        self.flag("dpkg-broken")
        self.assert_blocks("установка пакетов не завершена")

    def test_missing_initramfs(self) -> None:
        # Типичное следствие заполненного диска: ядро установлено, initramfs нет.
        self.new_kernel()
        (self.boot / f"initrd.img-{NEWER}").unlink()
        self.assert_blocks(f"initramfs ядра {NEWER} отсутствует или пуст")

    def test_empty_initramfs(self) -> None:
        self.new_kernel()
        (self.boot / f"initrd.img-{NEWER}").write_text("", encoding="utf-8")
        self.assert_blocks(f"initramfs ядра {NEWER} отсутствует или пуст")

    def test_damaged_initramfs(self) -> None:
        self.new_kernel()
        self.flag("initrd-broken")
        self.assert_blocks(f"initramfs ядра {NEWER} повреждён")

    def test_empty_kernel_image(self) -> None:
        self.new_kernel()
        (self.boot / f"vmlinuz-{NEWER}").write_text("", encoding="utf-8")
        self.assert_blocks(f"образ ядра {NEWER} отсутствует или пуст")

    def test_missing_kernel_modules(self) -> None:
        self.new_kernel()
        (self.modules / NEWER / "modules.dep").unlink()
        self.assert_blocks(f"модули ядра {NEWER} не установлены")

    def test_kernel_missing_from_the_boot_menu(self) -> None:
        self.new_kernel()
        self.grub(RUNNING)
        self.assert_blocks(f"ядро {NEWER} не внесено в меню загрузчика")

    def test_damaged_boot_menu(self) -> None:
        self.new_kernel()
        self.flag("grub-broken")
        self.assert_blocks("меню загрузчика GRUB повреждено")

    def test_full_disk(self) -> None:
        self.flag("disk", "97\n")
        self.assert_blocks("корневой раздел почти заполнен")

    def test_broken_ssh_configuration(self) -> None:
        # sshd не запустился бы: сервер недоступен, доля ключа соседям не отдаётся.
        self.flag("sshd-broken")
        self.assert_blocks("конфигурация SSH содержит ошибку")

    def test_secret_store_that_would_not_open(self) -> None:
        self.flag("secretctl-check-fails")
        self.assert_blocks("хранилище секретов не откроется после перезагрузки")

    def test_secret_store_unlock_disabled_at_boot(self) -> None:
        self.flag("unlock-disabled")
        self.assert_blocks("открытие хранилища секретов при загрузке выключено")

    def test_prepare_saves_secrets_before_the_reboot(self) -> None:
        # Изменения в RAM после последнего сохранения пропали бы при перезагрузке.
        code, rows = self.guard("prepare")
        self.assertEqual(code, 0, rows)
        self.assertEqual(self.calls("secretctl"), ["secretctl seal", "secretctl check"])

    def test_secrets_that_cannot_be_saved_block_the_reboot(self) -> None:
        self.flag("secretctl-seal-fails")
        rows = self.assert_blocks("секреты не сохранены в зашифрованный пакет", mode="prepare")
        self.assertNotIn("хранилище секретов откроется после перезагрузки", self.by_status(rows, "OK"))

    def test_without_secret_store_nothing_is_checked_there(self) -> None:
        self.flag("secretctl-check-fails")
        code, rows = self.guard(runtime_secrets_enabled=False)
        self.assertEqual(code, 0, rows)
        self.assertEqual(self.calls("secretctl"), [])


class WaitAndHoldTests(GuardCase):
    def test_running_package_installation_means_wait(self) -> None:
        self.flag("dpkg-running")
        code, rows = self.guard()
        self.assertEqual(code, 3, rows)
        self.assertEqual(self.by_status(rows, "WAIT"), ["идёт установка пакетов"])

    def test_nightly_maintenance_means_wait(self) -> None:
        self.flag("busy-units", "awg-maintenance.service\n")
        code, rows = self.guard()
        self.assertEqual(code, 3, rows)
        self.assertEqual([row[2] for row in rows if row[0] == "WAIT"], ["awg-maintenance.service"])

    def test_running_deploy_means_wait(self) -> None:
        self.flag("deploy.active")
        code, rows = self.guard()
        self.assertEqual(code, 3, rows)
        self.assertEqual(self.by_status(rows, "WAIT"), ["идёт kalimera-deploy"])

    def test_fresh_kernel_is_held_back_from_the_automatic_reboot(self) -> None:
        # Ошибку в свежем ядре обычно находят за несколько дней: без присмотра
        # сервер не должен быть первым, кто в него загрузится.
        self.new_kernel()
        code, rows = self.guard(awg_auto_reboot_kernel_min_age_hours=72)
        self.assertEqual(code, 3, rows)
        self.assertEqual(self.by_status(rows, "HOLD"), [f"ядро {NEWER} установлено недавно"])
        self.assertEqual(self.by_status(rows, "FAIL"), [])

    def test_kernel_age_does_not_matter_without_a_new_kernel(self) -> None:
        # Перезагрузку требует обновление библиотек: ядро остаётся прежним.
        self.flag("reboot-required")
        code, rows = self.guard(awg_auto_reboot_kernel_min_age_hours=72)
        self.assertEqual(code, 0, rows)

    def test_freshly_booted_server_is_not_rebooted_again(self) -> None:
        code, rows = self.guard(awg_auto_reboot_min_uptime_seconds=10**9)
        self.assertEqual(code, 3, rows)
        self.assertEqual(self.by_status(rows, "HOLD"), ["сервер загружен недавно"])

    def test_failure_outweighs_hold(self) -> None:
        self.new_kernel(module=False)
        code, _rows = self.guard(awg_auto_reboot_kernel_min_age_hours=72)
        self.assertEqual(code, 1)


class LayoutTests(GuardCase):
    def test_backup_copies_are_not_kernels(self) -> None:
        (self.boot / "vmlinuz-6.8.0-200-generic.old").write_text("old", encoding="utf-8")
        (self.boot / "vmlinuz-6.8.0-300-generic.dpkg-tmp").write_text("tmp", encoding="utf-8")
        code, rows = self.guard()
        self.assertEqual(code, 0, rows)
        self.assertIn(f"после перезагрузки останется ядро {RUNNING}", self.by_status(rows, "OK"))

    def test_version_order_is_numeric(self) -> None:
        # 6.8.0-100 новее 6.8.0-90, хотя по алфавиту стоит раньше.
        self.new_kernel()
        _code, rows = self.guard()
        self.assertIn(f"после перезагрузки загрузится ядро {NEWER}", self.by_status(rows, "OK"))

    def test_kernel_booted_by_the_hosting_is_not_checked(self) -> None:
        for path in self.boot.glob("vmlinuz-*"):
            path.unlink()
        code, rows = self.guard()
        self.assertEqual(code, 0, rows)
        self.assertIn("ядро загружает хостинг: файлы ядра не проверяются", self.by_status(rows, "OK"))
        # Модуль AmneziaWG проверяется и там: без него каскад не поднимется.
        self.assertIn(f"модуль AmneziaWG собран для ядра {RUNNING}", self.by_status(rows, "OK"))

    def test_server_without_initramfs_at_all_is_not_blocked(self) -> None:
        for path in self.boot.glob("initrd.img-*"):
            path.unlink()
        code, rows = self.guard()
        self.assertEqual(code, 0, rows)

    def test_boot_menu_not_used_by_the_running_kernel_is_ignored(self) -> None:
        self.new_kernel()
        self.grub("5.15.0-1-generic")
        self.flag("grub-broken")
        code, rows = self.guard()
        self.assertEqual(code, 0, rows)


if __name__ == "__main__":
    unittest.main()

"""Отказоустойчивость самого сервера: panic ядра, сторож зависания, нехватка памяти.

Шаблоны рендерятся Jinja2, программа применения приоритета запускается в bash с
подставным systemctl и каталогами вместо /proc и /sys/fs/cgroup: root и настоящие
службы не нужны.
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
import yaml

ROOT = Path(__file__).parents[1]
OPERATIONS = ROOT / "roles" / "operations"
SYSCTL = ROOT / "roles" / "security" / "templates" / "sysctl.conf.j2"
SECURITY_DEFAULTS = ROOT / "roles" / "security" / "defaults" / "main.yml"
HEALTH = ROOT / "roles" / "health" / "templates" / "awg-health.sh.j2"
SELF_HEAL = ROOT / "roles" / "health" / "templates" / "awg-self-heal.sh.j2"
WATCHDOG_UNIT = OPERATIONS / "templates" / "kalimera-watchdog.service.j2"
WATCHDOG_DROPIN = OPERATIONS / "templates" / "kalimera-watchdog.conf.j2"
OOM_DROPIN = OPERATIONS / "templates" / "kalimera-oom.conf.j2"
OOM_APPLY = OPERATIONS / "files" / "kalimera-oom-apply.sh"
INTEGRITY = OPERATIONS / "templates" / "awg-managed-integrity.sh.j2"
DEFAULTS = OPERATIONS / "defaults" / "main.yml"
TASKS = OPERATIONS / "tasks" / "main.yml"
RESILIENCE_TASKS = OPERATIONS / "tasks" / "resilience.yml"


def render(template: Path, **variables) -> str:
    environment = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    return environment.from_string(template.read_text(encoding="utf-8")).render(**variables)


class KernelPanicTests(unittest.TestCase):
    def test_kernel_reboots_after_a_panic(self) -> None:
        # Значение Ubuntu по умолчанию 0: после panic сервер висит до ручного сброса.
        defaults = yaml.safe_load(SECURITY_DEFAULTS.read_text(encoding="utf-8"))
        self.assertEqual(defaults["security_kernel_panic_reboot_seconds"], 10)
        text = render(SYSCTL, security_disable_ipv6=True, security_kernel_panic_reboot_seconds=10)
        self.assertIn("\nkernel.panic = 10\n", text)

    def test_oops_is_left_to_the_kernel_default(self) -> None:
        # panic_on_oops превратил бы повторяющуюся ошибку модуля в бесконечную
        # перезагрузку: сервер с остановленным туннелем хотя бы доступен по SSH.
        text = render(SYSCTL, security_disable_ipv6=True, security_kernel_panic_reboot_seconds=10)
        self.assertNotIn("panic_on_oops", text)

    def test_health_checks_the_value_and_self_heal_reapplies_it(self) -> None:
        health = HEALTH.read_text(encoding="utf-8")
        self.assertIn(
            "check_value 'ядро перезагружается после panic' \"$(sysctl -n kernel.panic)\" "
            "{{ security_kernel_panic_reboot_seconds | default(10) | int }} WARN",
            health,
        )
        # Проверка стоит до блока ролей ENTRY и EXIT: она нужна и на FRONT.
        self.assertLess(
            health.index("'ядро перезагружается после panic'"),
            health.index("check 'модуль AmneziaWG' modprobe -n amneziawg"),
        )
        self.assertIn("'ответы на ICMP echo отключены'|'ядро перезагружается после panic')", SELF_HEAL.read_text(encoding="utf-8"))


class WatchdogTests(unittest.TestCase):
    def test_module_is_loaded_by_name_only_where_it_exists(self) -> None:
        unit = WATCHDOG_UNIT.read_text(encoding="utf-8")
        # Нет модуля в ядре - служба пропускается, а не завершается ошибкой:
        # неисправный модуль systemd попал бы в отчёт как замечание.
        self.assertIn("ConditionPathExistsGlob=/lib/modules/%v/kernel/drivers/watchdog/softdog.ko*\n", unit)
        # Сторож гипервизора не заменяется программным.
        self.assertIn("ExecStart=/bin/sh -c '[ -e /dev/watchdog0 ] || exec /sbin/modprobe softdog'\n", unit)
        self.assertIn("Before=sysinit.target\n", unit)
        self.assertIn("RemainAfterExit=yes\n", unit)

    def test_manager_setting_covers_work_and_reboot(self) -> None:
        text = render(WATCHDOG_DROPIN, awg_watchdog_runtime_seconds=120, awg_watchdog_reboot_seconds=600)
        self.assertIn("[Manager]\nRuntimeWatchdogSec=120s\nRebootWatchdogSec=600s\n", text)

    def test_role_installs_enables_and_arms_the_watchdog(self) -> None:
        main = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        self.assertTrue([task for task in main if task.get("ansible.builtin.import_tasks") == "resilience.yml"])
        tasks = yaml.safe_load(RESILIENCE_TASKS.read_text(encoding="utf-8"))
        names = [task["name"] for task in tasks]
        self.assertIn("Включение программного сторожа ядра", names)
        rearm = next(task for task in tasks if task["name"].startswith("Взведение сторожа зависания"))
        self.assertEqual(rearm["ansible.builtin.systemd_service"], {"daemon_reexec": True})
        # Диспетчер перезапускается, только когда устройство есть и не взведено.
        self.assertIn("(operations_watchdog_state.stdout | default('') | trim) == 'inactive'", rearm["when"])
        defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        self.assertTrue(defaults["awg_watchdog_enabled"])
        self.assertGreaterEqual(defaults["awg_watchdog_runtime_seconds"], 60)


class OomProtectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bash = shutil.which("bash")
        if self.bash is None or os.name == "nt":
            self.skipTest("нужен bash на Linux")
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.cgroup = self.dir / "cgroup"
        self.proc = self.dir / "proc"
        # Подставной systemctl: путь группы службы из файла с её именем.
        tool = self.bin / "systemctl"
        tool.write_text(
            "#!/usr/bin/env bash\n"
            f'cat {shlex.quote(str(self.dir))}/"group-${{*: -1}}" 2>/dev/null || true\n',
            encoding="utf-8",
        )
        tool.chmod(0o755)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def service(self, unit: str, processes: dict[int, int]) -> None:
        """Работающая служба: номера процессов и их текущий приоритет."""
        group = f"/system.slice/{unit}"
        (self.dir / f"group-{unit}").write_text(group + "\n", encoding="utf-8")
        directory = self.cgroup / group.lstrip("/")
        directory.mkdir(parents=True)
        (directory / "cgroup.procs").write_text("".join(f"{pid}\n" for pid in processes), encoding="utf-8")
        for pid, value in processes.items():
            (self.proc / str(pid)).mkdir(parents=True)
            (self.proc / str(pid) / "oom_score_adj").write_text(f"{value}\n", encoding="utf-8")

    def apply(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "KALIMERA_CGROUP_ROOT": str(self.cgroup),
            "KALIMERA_PROC_ROOT": str(self.proc),
        }
        return subprocess.run(
            [self.bash, str(OOM_APPLY), *arguments], capture_output=True, text=True, env=env, timeout=30
        )

    def value(self, pid: int) -> str:
        return (self.proc / str(pid) / "oom_score_adj").read_text(encoding="utf-8").strip()

    def test_running_services_get_the_priority_without_a_restart(self) -> None:
        self.service("unbound.service", {101: 0, 102: 0})
        self.service("sing-box.service", {201: 0})
        result = self.apply("-500", "unbound.service", "sing-box.service")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "3\n")
        self.assertEqual([self.value(pid) for pid in (101, 102, 201)], ["-500", "-500", "-500"])

    def test_second_run_changes_nothing(self) -> None:
        self.service("unbound.service", {101: -500})
        result = self.apply("-500", "unbound.service")
        self.assertEqual((result.returncode, result.stdout), (0, "0\n"))

    def test_absent_service_and_finished_process_are_skipped(self) -> None:
        # Службы на сервере нет (RU-прокси выключен), процесс успел завершиться.
        self.service("unbound.service", {101: 0, 102: 0})
        shutil.rmtree(self.proc / "102")
        result = self.apply("-500", "sing-box.service", "unbound.service")
        self.assertEqual((result.returncode, result.stdout), (0, "1\n"))
        self.assertEqual(self.value(101), "-500")

    def test_wrong_arguments_are_rejected(self) -> None:
        for arguments in ((), ("-500",), ("много", "unbound.service"), ("-2000", "unbound.service")):
            with self.subTest(arguments=arguments):
                result = self.apply(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Использование", result.stderr)

    def test_program_passes_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("нужен shellcheck")
        result = subprocess.run([shellcheck, str(OOM_APPLY)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_role_protects_its_own_traffic_services(self) -> None:
        defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8"))
        units = defaults["awg_oom_protected_units_by_role"]
        self.assertEqual(set(units), {"entry", "exit", "front"})
        self.assertIn("unbound.service", units["entry"])
        self.assertIn("dnsmasq.service", units["entry"])
        self.assertIn("unbound.service", units["exit"])
        self.assertIn("nginx.service", units["front"])
        # Приоритет только понижает шанс завершения: разовые задания не трогаются.
        self.assertLess(defaults["awg_oom_score_adjust"], 0)
        self.assertEqual(render(OOM_DROPIN, awg_oom_score_adjust=-500).splitlines()[-2:], ["[Service]", "OOMScoreAdjust=-500"])

    def test_new_files_are_under_integrity_control(self) -> None:
        text = render(
            INTEGRITY,
            awg_managed_integrity_manifest="/var/lib/awg-iac/security/managed-files.sha256",
            awg_node_role="front",
            awg_oom_protected_units=["xray.service", "nginx.service"],
        )
        for path in (
            "/etc/systemd/system/kalimera-watchdog.service",
            "/etc/systemd/system.conf.d/90-kalimera-watchdog.conf",
            "/usr/local/libexec/kalimera-oom-apply",
            "/etc/systemd/system/xray.service.d/90-kalimera-oom.conf",
            "/etc/systemd/system/nginx.service.d/90-kalimera-oom.conf",
        ):
            self.assertIn(f"\n{path}\n", text)


if __name__ == "__main__":
    unittest.main()

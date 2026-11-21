"""Ночное обслуживание оставляет причину сбоя и не падает от разовой неудачи.

Повод: на рабочем каскаде awg-maintenance.service дважды завершалась с ошибкой, и
оба раза причину установить не удалось. Журнал systemd хранится в RAM и к утру был
вытеснен, а итоговый аудит запускался в тихом режиме и не печатал, какая проверка
не прошла. При повторном запуске обслуживание проходило.

Шаблон запускается целиком в bash с подставными apt, systemctl, аудитом и sleep.
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

# Подставные команды записывают вызовы; коды возврата задаются переменными среды.
FAKES = {
    "apt-get": textwrap.dedent(
        """\
        printf 'apt-get %s\\n' "$*" >>"$CALLS"
        [[ " $* " != *" upgrade "* ]] || exit "${FAKE_UPGRADE_RC:-0}"
        """
    ),
    "apt-mark": textwrap.dedent(
        """\
        printf 'apt-mark %s\\n' "$*" >>"$CALLS"
        """
    ),
    "apt-cache": "exit 0\n",
    "dpkg-query": "exit 0\n",
    "uname": 'printf "6.8.0-151-generic\\n"\n',
    "systemctl": 'printf "systemctl %s\\n" "$*" >>"$CALLS"\n',
    "sleep": 'printf "sleep %s\\n" "$*" >>"$CALLS"\n',
    "kernel-guard": textwrap.dedent(
        """\
        printf 'kernel-guard\\n' >>"$CALLS"
        exit "${FAKE_GUARD_RC:-0}"
        """
    ),
    "kalimera-updates": 'printf "kalimera-updates\\n" >>"$CALLS"\n',
    # Аудит: FAKE_AUDIT_RESULTS - коды возврата по попыткам, последний повторяется.
    "server-audit": textwrap.dedent(
        """\
        printf 'server-audit %s\\n' "$*" >>"$CALLS"
        count="$(grep -c '^server-audit ' "$CALLS")"
        read -r -a results <<<"${FAKE_AUDIT_RESULTS:-0}"
        index=$(( count - 1 ))
        (( index < ${#results[@]} )) || index=$(( ${#results[@]} - 1 ))
        rc="${results[$index]}"
        if (( rc != 0 )); then
            printf 'FAIL строгая проверка роли сервера: основной DNS по UDP\\n'
            (( rc < 2 )) || printf 'FAIL нет неисправных модулей systemd\\n'
        fi
        exit "$rc"
        """
    ),
}


def render(role: str, state: Path, bin_dir: Path, lock: Path) -> str:
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES)), trim_blocks=True, keep_trailing_newline=True
    )
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    text = environment.get_template("maintenance.sh.j2").render(
        awg_node_role=role,
        awg_maintenance_state_path=str(state),
        awg_server_audit_path=str(bin_dir / "server-audit"),
        kalimera_updates_path=str(bin_dir / "kalimera-updates"),
    )
    text = text.replace("[[ $EUID -eq 0 ]] ||", "true ||", 1)
    text = text.replace("/usr/local/sbin/awg-kernel-guard", str(bin_dir / "kernel-guard"))
    return text.replace("/run/awg-apt-maintenance.lock", str(lock))


class MaintenanceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.bash = shutil.which("bash")
        if self.bash is None or os.name == "nt":
            self.skipTest("нужен bash на Linux")
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        for name, body in FAKES.items():
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
            path.chmod(0o755)
        self.calls = self.dir / "calls"
        self.calls.touch()
        self.state = self.dir / "maintenance.state"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def script(self, role: str = "entry") -> Path:
        path = self.dir / "maintenance"
        path.write_text(render(role, self.state, self.bin, self.dir / "lock"), encoding="utf-8")
        return path

    def run_maintenance(self, *arguments: str, role: str = "entry", **environment: str):
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "CALLS": str(self.calls),
            **environment,
        }
        return subprocess.run(
            [self.bash, str(self.script(role)), *arguments], capture_output=True, text=True, env=env, timeout=60
        )

    def called(self, prefix: str) -> list[str]:
        return [line for line in self.calls.read_text(encoding="utf-8").splitlines() if line.startswith(prefix)]

    def state_fields(self) -> list[str]:
        return self.state.read_text(encoding="utf-8").rstrip("\n").split("\t")


class ScheduledRunTests(MaintenanceCase):
    def test_successful_run_is_recorded(self) -> None:
        result = self.run_maintenance("--scheduled")
        self.assertEqual(result.returncode, 0, result.stderr)
        status, when, stage, details = self.state_fields()
        self.assertEqual((status, stage, details), ("OK", "итоговый аудит", ""))
        self.assertRegex(when, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$")
        self.assertEqual(self.called("server-audit"), ["server-audit --quiet"])
        self.assertFalse(self.called("sleep"))
        # Удержание пакетов AmneziaWG снимает тот же обработчик выхода.
        self.assertTrue(self.called("apt-mark unhold"))

    def test_one_failed_audit_right_after_the_upgrade_is_not_a_failure(self) -> None:
        # Обновление могло только что перезапустить службу: проверка повторяется.
        result = self.run_maintenance("--scheduled", FAKE_AUDIT_RESULTS="1 0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.called("server-audit")), 2)
        self.assertEqual(self.called("sleep"), ["sleep 60"])
        self.assertEqual(self.state_fields()[0], "OK")
        self.assertEqual(self.state_fields()[3], "")
        # Неудачная попытка остаётся в журнале вместе с названием проверки.
        self.assertIn("попытка 1 из 3, не пройдено: строгая проверка роли сервера: основной DNS по UDP.", result.stderr)

    def test_persistent_audit_failure_keeps_the_reason(self) -> None:
        result = self.run_maintenance("--scheduled", FAKE_AUDIT_RESULTS="2")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(self.called("server-audit")), 3)
        self.assertEqual(self.called("sleep"), ["sleep 60", "sleep 60"])
        status, _when, stage, details = self.state_fields()
        self.assertEqual(status, "FAIL")
        self.assertEqual(stage, "итоговый аудит")
        self.assertEqual(
            details, "строгая проверка роли сервера: основной DNS по UDP; нет неисправных модулей systemd"
        )
        self.assertIn("Обслуживание остановлено на этапе «итоговый аудит»", result.stderr)
        self.assertIn("код 2", result.stderr)

    def test_package_failure_names_its_stage_and_releases_the_hold(self) -> None:
        result = self.run_maintenance("--scheduled", FAKE_UPGRADE_RC="100")
        self.assertEqual(result.returncode, 100)
        status, _when, stage, details = self.state_fields()
        self.assertEqual((status, stage, details), ("FAIL", "обновление пакетов Ubuntu", ""))
        self.assertTrue(self.called("apt-mark unhold"))
        self.assertFalse(self.called("server-audit"))

    def test_kernel_guard_failure_names_its_stage(self) -> None:
        result = self.run_maintenance("--scheduled", FAKE_GUARD_RC="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.state_fields()[2], "подготовка модуля AmneziaWG для установленных ядер")
        self.assertFalse(self.called("server-audit"))

    def test_front_has_no_kernel_stage(self) -> None:
        result = self.run_maintenance("--scheduled", role="front", FAKE_GUARD_RC="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.called("kernel-guard"))
        self.assertEqual(self.state_fields()[0], "OK")

    def test_new_run_replaces_the_previous_record(self) -> None:
        self.assertEqual(self.run_maintenance("--scheduled", FAKE_AUDIT_RESULTS="1").returncode, 1)
        self.assertEqual(self.state_fields()[0], "FAIL")
        self.calls.write_text("", encoding="utf-8")
        self.assertEqual(self.run_maintenance("--scheduled").returncode, 0)
        self.assertEqual(self.state_fields()[0], "OK")

    def test_manual_run_writes_no_record(self) -> None:
        result = self.run_maintenance()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.called("server-audit"), ["server-audit "])


class WiringTests(unittest.TestCase):
    def test_quiet_audit_still_prints_failed_checks(self) -> None:
        # Тихий режим использует только ночное обслуживание. Раньше он скрывал и
        # непройденные проверки: в журнале не оставалось причины сбоя.
        audit = (TEMPLATES / "server-audit.sh.j2").read_text(encoding="utf-8")
        body = audit[audit.index("audit_failed() {"):audit.index("record_warn_result() {")]
        self.assertIn('    report_line FAIL "$2"\n', body)
        self.assertNotIn('[[ "$quiet" == true ]] || report_line FAIL', audit)

    def health_verdict(self, health_rc: int) -> str:
        """Запустить record_health из server-audit с подставным awg-health."""
        bash = shutil.which("bash")
        if bash is None or os.name == "nt":
            self.skipTest("нужен bash на Linux")
        audit = (TEMPLATES / "server-audit.sh.j2").read_text(encoding="utf-8")
        start = audit.index("record_health() {")
        function = audit[start:audit.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            health = root / "awg-health"
            health.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'OK\\tслужба dnsmasq\\t\\nFAIL\\tосновной DNS по UDP\\tподсказка\\n"
                "WARN\\tFail2Ban активен\\t\\n' >\"$KALIMERA_REPORT_RESULTS\"\n"
                f"exit {health_rc}\n",
                encoding="utf-8",
            )
            health.chmod(0o755)
            function = function.replace("{{ awg_health_script_path | quote }}", shlex.quote(str(health)))
            function = function.replace("/run/server-audit.health", str(root / "rows"))
            self.assertNotIn("{{", function)
            script = (
                "set -Eeuo pipefail\n"
                'audit_passed() { echo "PASS|$1"; }\n'
                'audit_failed() { echo "$1|$2"; }\n' + function + "record_health\n"
            )
            result = subprocess.run([bash, "-c", script], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(root.glob("rows*")), [])
            return result.stdout.strip()

    def test_audit_names_the_failed_health_checks(self) -> None:
        # Сбой бывает кратким: без названий проверок в строке аудита причину ночного
        # отказа нельзя было узнать, awg-health вручную уже проходил.
        self.assertEqual(
            self.health_verdict(1),
            "FAIL|строгая проверка роли сервера: основной DNS по UDP; Fail2Ban активен",
        )
        self.assertEqual(
            self.health_verdict(3),
            "WARN|строгая проверка роли сервера: только замечания (основной DNS по UDP; Fail2Ban активен)",
        )
        self.assertEqual(self.health_verdict(0), "PASS|строгая проверка роли сервера")

    def test_update_all_keeps_its_own_exit_handler(self) -> None:
        include = (TEMPLATES / "apt-full-upgrade.inc.j2").read_text(encoding="utf-8")
        self.assertIn('trap "${awg_exit_handler:-awg_release_holds}" EXIT', include)
        update_all = (TEMPLATES / "update-all.sh.j2").read_text(encoding="utf-8")
        self.assertNotIn("awg_exit_handler", update_all)

    def test_report_and_audit_read_the_same_state_file(self) -> None:
        default = "awg_maintenance_state_path | default('/run/awg-maintenance.state')"
        for path in (
            TEMPLATES / "maintenance.sh.j2",
            TEMPLATES / "server-audit.sh.j2",
            ROOT / "roles" / "cascade_check" / "templates" / "kalimera-report.sh.j2",
        ):
            self.assertIn(default, path.read_text(encoding="utf-8"), path.name)

    def test_rendered_script_passes_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        bash = shutil.which("bash")
        if shellcheck is None or bash is None or os.name == "nt":
            self.skipTest("нужен shellcheck")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for role in ("entry", "front"):
                script = root / f"maintenance-{role}"
                script.write_text(render(role, root / "state", root, root / "lock"), encoding="utf-8")
                result = subprocess.run(
                    [shellcheck, "--exclude=SC2317", str(script)], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

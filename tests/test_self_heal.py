"""Самовосстановление: действие зависит от конкретной непройденной проверки.

Программа self-heal рендерится для каждой роли и запускается целиком в bash с
подставными awg-health, systemctl и остальными командами. Проверяется, что:
действие выполняется только для подтверждённой ошибки, соответствует проверке,
идёт в правильном порядке и ограничено числом попыток; расхождение настроек и
внешние причины не «чинятся», а называются; во время deploy и обслуживания
служба ничего не меняет; таблица охватывает каждую проверку awg-health.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import jinja2
import yaml

ROOT = Path(__file__).parents[1]
HEALTH_ROLE = ROOT / "roles" / "health"
SELF_HEAL = HEALTH_ROLE / "templates" / "awg-self-heal.sh.j2"
REPORT = ROOT / "roles" / "cascade_check" / "templates" / "kalimera-report.sh.j2"
HEALTH = HEALTH_ROLE / "templates" / "awg-health.sh.j2"
UNLOCK = "kalimera-secrets-unlock.service"

FAKE_HEALTH = """#!/usr/bin/env bash
# Подставной awg-health: строки результата берутся из файла очередного вызова.
state={state}
count="$(( $(cat "$state/health-count" 2>/dev/null || echo 0) + 1 ))"
echo "$count" >"$state/health-count"
file="$state/health-$count.tsv"
[[ -e "$file" ]] || file="$state/health-last.tsv"
[[ -z "${{KALIMERA_REPORT_RESULTS:-}}" ]] || cat "$file" >"$KALIMERA_REPORT_RESULTS"
! grep -Eq '^(FAIL|WARN)' "$file"
"""

FAKE_SYSTEMCTL = """#!/usr/bin/env bash
state={state}
printf 'systemctl %s\\n' "$*" >>"$state/calls.log"
if [[ "$1" == --failed ]]; then
    cat "$state/failed-units.txt" 2>/dev/null
    exit 0
fi
if [[ "$1" == is-active ]]; then
    unit="${{@: -1}}"
    case "$unit" in
        awg-maintenance.service)
            if [[ -e "$state/maintenance-running" ]]; then echo activating; else echo inactive; fi
            exit 3
            ;;
        {unlock})
            [[ -e "$state/secrets-open" ]] || exit 3
            ;;
        awg-self-heal.timer)
            [[ -e "$state/timer-active" ]] || exit 3
            ;;
    esac
    exit 0
fi
if [[ "$1" == is-enabled ]]; then
    [[ ! -e "$state/timer-disabled" ]] || exit 1
    exit 0
fi
[[ ! -e "$state/systemctl-fails" ]] || exit 1
"""

# Вызов записывается одной строкой: текст уведомления содержит переводы строк.
FAKE_TOOL = """#!/usr/bin/env bash
arguments="$*"
printf '%s %s\\n' "$(basename "$0")" "${{arguments//$'\\n'/ | }}" >>{state}/calls.log
"""


def bash_path() -> str:
    executable = shutil.which("bash")
    if executable is None or os.name == "nt":
        raise unittest.SkipTest("нужен bash на Linux")
    return executable


def health_labels() -> list[str]:
    """Названия всех проверок awg-health, которые могут не пройти."""
    text = HEALTH.read_text(encoding="utf-8")
    labels = re.findall(r"^\s*(?:check|check_minor|check_value) +'([^']+)'", text, flags=re.MULTILINE)
    return sorted(set(labels))


class SelfHealCase(unittest.TestCase):
    role = "entry"

    def setUp(self) -> None:
        self.bash = bash_path()
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.state_dir = self.dir / "state"
        self.bin.mkdir()
        quoted = shlex.quote(str(self.dir))
        self.write_tool("awg-health", FAKE_HEALTH.format(state=quoted))
        self.write_tool("systemctl", FAKE_SYSTEMCTL.format(state=quoted, unlock=UNLOCK))
        for name in (
            "sleep", "sysctl", "ufw", "awg-kernel-guard", "ru-domain", "awg-ru-zone-update",
            "awg-mobile-firewall", "vless-user", "awg-telegram-monitor",
        ):
            self.write_tool(name, FAKE_TOOL.format(state=quoted))
        # unbound-control: list_forwards отвечает содержимым файла forwards.txt.
        self.write_tool(
            "unbound-control",
            FAKE_TOOL.format(state=quoted)
            + f'[[ "$1" != list_forwards ]] || cat {quoted}/forwards.txt 2>/dev/null\n',
        )
        # Собственные проверки службы: занятое место и синхронизация часов берутся
        # из файлов, очистка кэша пакетов освобождает место, если это задано.
        self.write_tool(
            "df",
            f"#!/usr/bin/env bash\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n"
            f"/dev/vda1 100 0 0 %s%% /\\n' \"$(cat {quoted}/disk.txt 2>/dev/null || echo 40)\"\n",
        )
        self.write_tool(
            "timedatectl", f"#!/usr/bin/env bash\ncat {quoted}/clock.txt 2>/dev/null || echo yes\n"
        )
        self.write_tool(
            "apt-get",
            FAKE_TOOL.format(state=quoted)
            + f"[[ ! -e {quoted}/clean-frees-space ]] || echo 40 >{quoted}/disk.txt\n",
        )
        (self.dir / "calls.log").write_text("", encoding="utf-8")
        self.health("last")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_tool(self, name: str, text: str) -> None:
        path = self.bin / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def health(self, call: int | str, *failed: str, status: str = "FAIL") -> None:
        """Задать результат awg-health для вызова с номером call ("last" - для остальных)."""
        rows = ["OK\tзапуск от root\t"] + [f"{status}\t{label}\tподсказка" for label in failed]
        (self.dir / f"health-{call}.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")

    def script(self, role: str | None = None, **variables) -> Path:
        environment = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
        environment.filters["quote"] = lambda value: shlex.quote(str(value))
        environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
        context = {
            "awg_node_role": role or self.role,
            "awg_health_script_path": str(self.bin / "awg-health"),
            "awg_self_heal_state_dir": str(self.state_dir),
            "awg_self_heal_manual_off_flag": str(self.dir / "manual-off"),
            "kalimera_deploy_marker_path": str(self.dir / "deploy.active"),
            "awg_telegram_monitor_path": str(self.bin / "awg-telegram-monitor"),
            "runtime_secrets_enabled": True,
            "runtime_secrets_service_name": UNLOCK,
            "entry_legacy_client_available": True,
            "entry_mobile_client_available": True,
            "entry_client_interface": "awg0",
            "entry_exit_interface": "awg3",
            "exit_awg_interface": "awg3",
            **variables,
        }
        text = environment.from_string(SELF_HEAL.read_text(encoding="utf-8")).render(**context)
        text = text.replace("[[ $EUID -eq 0 ]] ||", "true ||", 1)
        text = text.replace("/usr/local/sbin/", f"{self.bin}/")
        path = self.dir / "self-heal"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)
        return path

    def run_heal(self, *arguments: str, role: str | None = None, **variables):
        env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"}
        return subprocess.run(
            [self.bash, str(self.script(role, **variables)), *arguments],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    def calls(self, prefix: str = "") -> list[str]:
        lines = (self.dir / "calls.log").read_text(encoding="utf-8").splitlines()
        return [line for line in lines if line.startswith(prefix)]

    def changes(self) -> list[str]:
        """Вызовы, которые что-то меняют: без опросов состояния и пауз."""
        return [
            line
            for line in self.calls()
            if not line.startswith(
                ("systemctl is-active", "systemctl is-enabled", "systemctl --failed", "sleep ", "awg-telegram-monitor")
            )
            and not line.startswith("systemctl reset-failed")
        ]

    def state(self) -> list[str]:
        """Поля состояния; пустое поле записано в файле как "-"."""
        fields = (self.state_dir / "state").read_text(encoding="utf-8").rstrip("\n").split("\t")
        self.assertEqual(len(fields), 4, fields)
        self.assertNotIn("", fields)
        return ["" if field == "-" else field for field in fields]

    def report_row(self, **variables) -> list[str]:
        """Строка cascade-check о самовосстановлении.

        kalimera-report вызывает настоящую программу self-heal --report, поэтому
        проверяется вся цепочка: журнал восстановлений, итог и разбор строки.
        """
        environment = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
        environment.filters["quote"] = lambda value: shlex.quote(str(value))
        environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
        report = self.dir / "kalimera-report"
        report.write_text(
            environment.from_string(REPORT.read_text(encoding="utf-8")).render(
                awg_node_role="entry", awg_self_heal_path=str(self.script(**variables))
            ),
            encoding="utf-8",
        )
        env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"}
        result = subprocess.run(
            [self.bash, "-c", f"source {shlex.quote(str(report))}\ncheck_self_heal\n"],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = result.stdout.rstrip("\n").split("\t")
        self.assertEqual(len(fields), 6, fields)
        return fields

    def health_runs(self) -> int:
        return int((self.dir / "health-count").read_text(encoding="utf-8"))


class CycleTests(SelfHealCase):
    def test_healthy_server_is_left_alone(self) -> None:
        result = self.run_heal("--scheduled")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()[0], "OK")
        self.assertEqual(self.changes(), [])
        self.assertEqual(self.calls("sleep"), [])

    def test_single_failure_that_passes_by_itself_triggers_nothing(self) -> None:
        # Действие выполняется только для проверки, не прошедшей дважды подряд.
        self.health(1, "служба dnsmasq")
        result = self.run_heal("--scheduled")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.changes(), [])
        self.assertEqual(self.calls("sleep"), ["sleep 20"])
        self.assertEqual(self.state()[0], "OK")
        history = (self.state_dir / "history").read_text(encoding="utf-8")
        self.assertIn("разовый сбой, прошёл сам: служба dnsmasq", history)

    def test_confirmed_failure_gets_its_own_action_and_is_verified(self) -> None:
        self.health(1, "служба dnsmasq")
        self.health(2, "служба dnsmasq")
        result = self.run_heal("--scheduled")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.changes(), ["systemctl restart dnsmasq.service"])
        self.assertEqual(self.health_runs(), 3)
        status, _when, repaired, unresolved = self.state()
        self.assertEqual(status, "REPAIRED")
        self.assertEqual(repaired, "служба dnsmasq (перезапуск dnsmasq)")
        self.assertEqual(unresolved, "")
        notified = self.calls("awg-telegram-monitor")
        self.assertEqual(len(notified), 1)
        self.assertIn("--notify AWG ENTRY: самовосстановление", notified[0])

    def test_actions_follow_the_dependency_order(self) -> None:
        # Сначала хранилище секретов, затем интерфейс, затем пиры и маршрутизация.
        failed = ("служба маршрутизации", "служба клиентского AWG", "пороговое хранилище 2-of-N открыто и аутентифицировано")
        self.health(1, *failed)
        self.health(2, *failed)
        result = self.run_heal("--scheduled")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.changes(),
            [
                f"systemctl start {UNLOCK}",
                "systemctl restart awg-quick@awg0.service",
                "systemctl restart awg-local-peer-apply.service",
                "systemctl reload awg-entry-routing.service",
            ],
        )

    def test_open_secret_store_is_never_restarted(self) -> None:
        # Перезапуск службы открытия остановил бы все зависящие от неё службы.
        (self.dir / "secrets-open").write_text("", encoding="utf-8")
        self.health("last", "пороговое хранилище 2-of-N открыто и аутентифицировано")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), [])
        self.assertEqual(self.state()[0], "UNRESOLVED")
        self.assertIn("действие к этому состоянию не применимо", self.state()[3])

    def test_closed_secret_store_blocks_dependent_repairs_without_spending_attempts(self) -> None:
        # После загрузки без второго сервера хранилище закрыто, и зависящие от него
        # службы не запустятся. Их попытки не расходуются: когда хранилище
        # откроется, службы должны запуститься в том же цикле, а не через час.
        failed = ("пороговое хранилище 2-of-N открыто и аутентифицировано", "служба клиентского AWG")
        self.health("last", *failed)
        (self.dir / "systemctl-fails").write_text("", encoding="utf-8")
        for _ in range(4):
            self.run_heal("--scheduled")
        self.assertEqual(self.changes(), [f"systemctl start {UNLOCK}"] * 4)
        self.assertIn("служба клиентского AWG - ждёт открытия хранилища секретов", self.state()[3])
        attempts = (self.state_dir / "attempts").read_text(encoding="utf-8")
        self.assertNotIn("awg_client", attempts)
        # Второй сервер вернулся: хранилище открывается, интерфейс запускается сразу.
        (self.dir / "systemctl-fails").unlink()
        (self.dir / "calls.log").write_text("", encoding="utf-8")
        self.run_heal("--scheduled")
        self.assertEqual(
            self.changes()[:2], [f"systemctl start {UNLOCK}", "systemctl restart awg-quick@awg0.service"]
        )

    def test_interface_restart_reapplies_routing(self) -> None:
        self.health(1, "свежий handshake ENTRY–EXIT")
        self.health(2, "свежий handshake ENTRY–EXIT")
        self.run_heal("--scheduled")
        self.assertEqual(
            self.changes(),
            ["systemctl restart awg-quick@awg3.service", "systemctl reload awg-entry-routing.service"],
        )

    def test_empty_network_set_is_refilled(self) -> None:
        self.health(1, "ipset российских сетей")
        self.health(2, "ipset российских сетей")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), ["awg-ru-zone-update ", "systemctl reload awg-entry-routing.service"])

    def test_unanswering_resolver_keeps_its_cache(self) -> None:
        # Служба работает, но не отвечает: сбрасывается состояние вышестоящих
        # серверов. Перезапуск стёр бы кэш и при их настоящем отказе навредил бы.
        self.health(1, "основной DNS по UDP")
        self.health(2, "основной DNS по UDP")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), ["unbound-control flush_infra all"])

    def test_stopped_resolver_is_restarted(self) -> None:
        self.health(1, "служба Unbound")
        self.health(2, "служба Unbound")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), ["systemctl restart unbound.service"])

    def test_russian_zones_are_reloaded_only_when_missing(self) -> None:
        label = "российские имена разрешает российский DoT с ENTRY"
        self.health(1, label)
        self.health(2, label)
        self.run_heal("--scheduled")
        self.assertEqual(
            self.changes(),
            ["ru-domain sync", "unbound-control list_forwards", "systemctl restart unbound.service"],
        )
        # Зоны загружены, не отвечает сам российский DoT: кэш остальных имён остаётся.
        (self.dir / "calls.log").write_text("", encoding="utf-8")
        (self.dir / "health-count").unlink()
        (self.dir / "forwards.txt").write_text(". IN forward 195.72.60.66\nru. IN forward 77.88.8.8\n", encoding="utf-8")
        self.run_heal("--scheduled")
        self.assertEqual(
            self.changes(),
            ["ru-domain sync", "unbound-control list_forwards", "unbound-control flush_infra all"],
        )

    def test_configuration_drift_is_named_not_fixed(self) -> None:
        self.health("last", "UFW соответствует последней управляемой политике", status="WARN")
        result = self.run_heal("--scheduled")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.changes(), [])
        status, _when, _repaired, unresolved = self.state()
        self.assertEqual(status, "UNRESOLVED")
        self.assertIn("расхождение настроек с выпуском: на ENTRY kalimera-deploy --resume", unresolved)

    def test_external_cause_is_named_not_fixed(self) -> None:
        self.health("last", "прослушивание российского DoH")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), [])
        self.assertIn("причина вне сервера: SOCKS5-прокси", self.state()[3])

    def test_manual_run_reports_and_fails_on_unresolved(self) -> None:
        self.health("last", "служба dnsmasq")
        result = self.run_heal("run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Не устранено: служба dnsmasq", result.stdout)
        self.assertIn("проверка всё ещё не проходит", result.stdout)

    def test_action_is_not_repeated_endlessly(self) -> None:
        self.health("last", "служба dnsmasq")
        for _ in range(4):
            self.assertEqual(self.run_heal("--scheduled").returncode, 0)
        self.assertEqual(self.changes(), ["systemctl restart dnsmasq.service"] * 3)
        self.assertIn("попытки на этот час исчерпаны", self.state()[3])

    def test_persistent_failure_is_announced_once(self) -> None:
        self.health("last", "UFW соответствует последней управляемой политике", status="WARN")
        self.run_heal("--scheduled")
        self.run_heal("--scheduled")
        self.assertEqual(len(self.calls("awg-telegram-monitor")), 1)

    def test_failed_action_is_reported(self) -> None:
        (self.dir / "systemctl-fails").write_text("", encoding="utf-8")
        self.health("last", "служба dnsmasq")
        self.run_heal("--scheduled")
        self.assertIn("действие «перезапуск dnsmasq» завершилось ошибкой", self.state()[3])


class GuardTests(SelfHealCase):
    def test_nothing_changes_during_deploy(self) -> None:
        (self.dir / "deploy.active").write_text("", encoding="utf-8")
        self.health("last", "служба dnsmasq")
        result = self.run_heal("--scheduled")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.dir / "health-count").exists())
        self.assertEqual(self.state()[0], "SKIPPED")
        self.assertEqual(self.state()[3], "идёт kalimera-deploy")

    def test_forgotten_deploy_mark_expires(self) -> None:
        marker = self.dir / "deploy.active"
        marker.write_text("", encoding="utf-8")
        old = time.time() - 4 * 3600
        os.utime(marker, (old, old))
        self.run_heal("--scheduled")
        self.assertEqual(self.state()[0], "OK")

    def test_nothing_changes_during_maintenance(self) -> None:
        (self.dir / "maintenance-running").write_text("", encoding="utf-8")
        self.health("last", "служба dnsmasq")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), [])
        self.assertEqual(self.state()[3], "идёт ночное обслуживание")

    def test_switching_off_survives_the_timer(self) -> None:
        result = self.run_heal("off")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.dir / "manual-off").exists())
        self.assertIn("systemctl disable --now awg-self-heal.timer", self.calls())
        self.health("last", "служба dnsmasq")
        self.run_heal("--scheduled")
        self.assertFalse((self.dir / "health-count").exists())
        self.assertIn("выключено вручную", self.run_heal("status").stdout)
        self.assertEqual(self.run_heal("on").returncode, 0)
        self.assertFalse((self.dir / "manual-off").exists())
        self.assertIn("systemctl enable --now awg-self-heal.timer", self.calls())

    def test_unresolved_error_is_never_shown_as_repaired(self) -> None:
        # Найдено на рабочем каскаде: поле «восстановлено» было пустым, read склеивал
        # соседние табуляции, и следующее поле читалось на его месте. Неустранённая
        # ошибка показывалась как «восстановлено», а причина паузы пропадала.
        self.health("last", "UFW соответствует последней управляемой политике", status="WARN")
        self.run_heal("--scheduled")
        raw = (self.state_dir / "state").read_text(encoding="utf-8")
        self.assertNotIn("\t\t", raw)
        output = self.run_heal("status").stdout
        self.assertIn("не устранено: UFW соответствует последней управляемой политике", output)
        self.assertNotIn("  восстановлено:", output)
        self.assertNotIn("Восстановлено за 7 дней:", output)
        self.assertIn("Итог: за 7 дней сбоев 1, восстановлено 0, не восстановлено 1.", output)
        segment, status, label, value, hint, _ms = self.report_row()
        self.assertEqual(
            (segment, status, label),
            ("ENTRY", "WARN", "самовосстановление: за 7 дней сбоев 1, восстановлено 0, не восстановлено 1"),
        )
        # Неустранённая ошибка названа вместе с причиной.
        self.assertEqual(
            value,
            "UFW соответствует последней управляемой политике - расхождение настроек с выпуском: "
            "на ENTRY kalimera-deploy --resume",
        )
        self.assertEqual(hint, "подробности: self-heal status")

    def test_report_names_the_reason_of_a_pause(self) -> None:
        (self.dir / "deploy.active").write_text("", encoding="utf-8")
        self.run_heal("--scheduled")
        _segment, status, label, value, _hint, _ms = self.report_row()
        self.assertEqual((status, label, value), ("OK", "самовосстановление приостановлено", "идёт kalimera-deploy"))
        self.assertIn("пропущен: идёт kalimera-deploy", self.run_heal("status").stdout)

    def test_finished_deploy_is_not_reported_as_a_pause(self) -> None:
        # Найдено на рабочем каскаде: до пяти минут после обновления отчёт писал
        # «приостановлено», хотя deploy уже закончился.
        marker = self.dir / "deploy.active"
        marker.write_text("", encoding="utf-8")
        self.run_heal("--scheduled")
        marker.unlink()
        _segment, status, label, value, _hint, _ms = self.report_row()
        self.assertEqual((status, label, value), ("OK", "самовосстановление: за 7 дней сбоев не было", ""))

    def test_report_counts_failures_and_repairs(self) -> None:
        # Пример из запроса: «сбоев 2, восстановлено 2, статус OK».
        failed = ("Fail2Ban активен", "строгая политика Fail2Ban применяется")
        self.health(1, *failed)
        self.health(2, *failed)
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), ["systemctl restart fail2ban.service"])
        _segment, status, label, value, hint, _ms = self.report_row()
        self.assertEqual((status, label), ("OK", "самовосстановление: за 7 дней сбоев 2, восстановлено 2"))
        self.assertEqual(
            value,
            "Fail2Ban активен (перезапуск Fail2Ban); строгая политика Fail2Ban применяется (перезапуск Fail2Ban)",
        )
        self.assertEqual(hint, "")
        self.assertIn("Итог: за 7 дней сбоев 2, восстановлено 2.", self.run_heal("status").stdout)

    def test_lasting_error_is_one_failure_however_long_it_lasts(self) -> None:
        self.health("last", "UFW соответствует последней управляемой политике", status="WARN")
        for _ in range(3):
            self.run_heal("--scheduled")
        _segment, status, label, _value, _hint, _ms = self.report_row()
        self.assertEqual(
            (status, label), ("WARN", "самовосстановление: за 7 дней сбоев 1, восстановлено 0, не восстановлено 1")
        )

    def test_partly_repaired_cycle_names_only_what_is_left(self) -> None:
        failed = ("служба dnsmasq", "UFW соответствует последней управляемой политике")
        self.health(1, *failed)
        self.health(2, *failed)
        self.health("last", "UFW соответствует последней управляемой политике")
        self.run_heal("--scheduled")
        _segment, status, label, value, _hint, _ms = self.report_row()
        self.assertEqual(
            (status, label), ("WARN", "самовосстановление: за 7 дней сбоев 2, восстановлено 1, не восстановлено 1")
        )
        self.assertTrue(value.startswith("UFW соответствует последней управляемой политике - "), value)
        self.assertNotIn("dnsmasq", value)

    def test_error_fixed_by_a_later_cycle_counts_as_repaired(self) -> None:
        # Служба стартует дольше паузы: проверка ещё не проходит, а к следующему
        # циклу проходит. Восстановление засчитывается выполненному действию.
        self.health(1, "служба dnsmasq")
        self.health(2, "служба dnsmasq")
        self.health(3, "служба dnsmasq")
        self.run_heal("--scheduled")
        self.assertEqual(self.report_row()[2], "самовосстановление: за 7 дней сбоев 1, восстановлено 0, не восстановлено 1")
        self.run_heal("--scheduled")
        _segment, status, label, value, _hint, _ms = self.report_row()
        self.assertEqual((status, label), ("OK", "самовосстановление: за 7 дней сбоев 1, восстановлено 1"))
        self.assertEqual(value, "служба dnsmasq (перезапуск dnsmasq)")

    def test_error_gone_without_an_action_is_not_claimed_as_repaired(self) -> None:
        # Расхождение настроек устранил deploy, а не служба.
        self.health(1, "UFW соответствует последней управляемой политике")
        self.health(2, "UFW соответствует последней управляемой политике")
        self.run_heal("--scheduled")
        self.run_heal("--scheduled")
        _segment, status, label, _value, _hint, _ms = self.report_row()
        self.assertEqual(
            (status, label),
            ("OK", "самовосстановление: за 7 дней сбоев 1, восстановлено 0, прошло без действия службы 1"),
        )

    def test_report_covers_the_last_week_only(self) -> None:
        self.run_heal("--scheduled")
        now = int(time.time())
        (self.state_dir / "events").write_text(
            f"{now - 9 * 86400}\x1fREPAIRED\x1fслужба dnsmasq\x1fперезапуск dnsmasq\n"
            f"{now - 2 * 86400}\x1fREPAIRED\x1fслужба Unbound\x1fперезапуск Unbound\n",
            encoding="utf-8",
        )
        _segment, _status, label, value, _hint, _ms = self.report_row()
        self.assertEqual(label, "самовосстановление: за 7 дней сбоев 1, восстановлено 1")
        self.assertEqual(value, "служба Unbound (перезапуск Unbound)")

    def test_period_is_named_in_correct_russian(self) -> None:
        self.run_heal("--scheduled")
        expected = {1: "за сутки", 3: "за 3 дня", 7: "за 7 дней", 21: "за 21 день", 30: "за 30 дней"}
        for days, text in expected.items():
            with self.subTest(days=days):
                label = self.report_row(awg_self_heal_summary_days=days)[2]
                self.assertEqual(label, f"самовосстановление: {text} сбоев не было")

    def test_report_before_the_first_cycle(self) -> None:
        self.assertEqual(
            self.report_row()[2], "самовосстановление: запусков после загрузки сервера ещё не было"
        )

    def test_status_shows_the_last_result(self) -> None:
        self.health(1, "служба dnsmasq")
        self.health(2, "служба dnsmasq")
        self.run_heal("--scheduled")
        (self.dir / "timer-active").write_text("", encoding="utf-8")
        output = self.run_heal("status").stdout
        self.assertIn("Самовосстановление: включено.", output)
        self.assertIn("восстановлено: служба dnsmasq (перезапуск dnsmasq)", output)
        self.assertIn("выполнено: перезапуск dnsmasq", output)

    # Найдено на рабочем каскаде: итог «сбоев 15, восстановлено 4, прошло без
    # действия службы 11» не называл, что это были за сбои; журнал последних
    # событий вмещал десять строк.

    def test_status_lists_every_failure_of_the_period_with_its_time(self) -> None:
        self.run_heal("--scheduled")
        now = int(time.time())

        def stamp(epoch: int) -> str:
            return time.strftime("%Y-%m-%d %H:%M", time.gmtime(epoch))

        (self.state_dir / "events").write_text(
            # Запись старше недели в список не входит.
            f"{now - 9 * 86400}\x1fCLEARED\x1fслужба Unbound\x1f\x1f{now - 9 * 86400 - 60}\n"
            f"{now - 3600}\x1fREPAIRED\x1fFail2Ban активен\x1fперезапуск Fail2Ban\x1f{now - 3600 - 20}\n"
            f"{now - 1800}\x1fCLEARED\x1fпрослушивание российского DoH\x1f\x1f{now - 1800 - 900}\n"
            # Запись прежнего формата, без времени появления.
            f"{now - 600}\x1fCLEARED\x1fсвежий handshake ENTRY–EXIT\x1f\n",
            encoding="utf-8",
        )
        output = self.run_heal("status").stdout
        self.assertIn("Итог: за 7 дней сбоев 3, восстановлено 1, прошло без действия службы 2.", output)
        self.assertIn(
            "Сбои за 7 дней после загрузки сервера, время UTC:\n"
            f"  {stamp(now - 3600)}  восстановлено службой: Fail2Ban активен (перезапуск Fail2Ban); "
            "держалось меньше минуты\n"
            f"  {stamp(now - 1800)}  прошло без действия службы: прослушивание российского DoH; "
            "держалось около 15 мин\n"
            f"  {stamp(now - 600)}  прошло без действия службы: свежий handshake ENTRY–EXIT\n",
            output,
        )
        self.assertNotIn("служба Unbound", output)
        # В cascade-check прошедшие без действия службы тоже названы по имени.
        _segment, status, label, value, _hint, _ms = self.report_row()
        self.assertEqual(
            (status, label),
            ("OK", "самовосстановление: за 7 дней сбоев 3, восстановлено 1, прошло без действия службы 2"),
        )
        self.assertEqual(
            value,
            "Fail2Ban активен (перезапуск Fail2Ban); "
            "прослушивание российского DoH (прошло без действия службы); "
            "свежий handshake ENTRY–EXIT (прошло без действия службы)",
        )

    def test_failure_records_when_it_was_noticed(self) -> None:
        # Ошибка держится два цикла и проходит без действия службы: длительность
        # считается с первого цикла, а не с последнего.
        self.health("last", "UFW соответствует последней управляемой политике")
        self.run_heal("--scheduled")
        first_seen = int((self.state_dir / "open").read_text(encoding="utf-8").split("\x1f")[0])
        self.health("last")
        self.run_heal("--scheduled")
        fields = (self.state_dir / "events").read_text(encoding="utf-8").rstrip("\n").split("\x1f")
        self.assertEqual(fields[1:4], ["CLEARED", "UFW соответствует последней управляемой политике", ""])
        self.assertEqual(int(fields[4]), first_seen)
        self.assertLessEqual(int(fields[4]), int(fields[0]))

    def test_failure_repaired_in_the_same_cycle_is_timed_from_the_cycle_start(self) -> None:
        self.health(1, "служба dnsmasq")
        self.health(2, "служба dnsmasq")
        started = int(time.time())
        self.run_heal("--scheduled")
        fields = (self.state_dir / "events").read_text(encoding="utf-8").rstrip("\n").split("\x1f")
        self.assertEqual(fields[1:4], ["REPAIRED", "служба dnsmasq", "перезапуск dnsmasq"])
        self.assertGreaterEqual(int(fields[4]), started)
        self.assertLessEqual(int(fields[4]), int(fields[0]))


class OwnProbeTests(SelfHealCase):
    """Проверки самой службы: место на диске и часы. В awg-health их нет."""

    def test_full_disk_gets_the_package_cache_cleaned(self) -> None:
        (self.dir / "disk.txt").write_text("93\n", encoding="utf-8")
        (self.dir / "clean-frees-space").write_text("", encoding="utf-8")
        result = self.run_heal("run")
        self.assertEqual(self.changes(), ["apt-get clean"])
        self.assertIn("Восстановлено: свободное место на корневом разделе (очистка кэша пакетов)", result.stdout)

    def test_disk_still_full_after_cleaning_is_named(self) -> None:
        (self.dir / "disk.txt").write_text("96\n", encoding="utf-8")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), ["apt-get clean"])
        self.assertIn(
            "свободное место на корневом разделе - действие «очистка кэша пакетов» выполнено, "
            "проверка всё ещё не проходит",
            self.state()[3],
        )

    def test_disk_below_the_limit_is_left_alone(self) -> None:
        (self.dir / "disk.txt").write_text("89\n", encoding="utf-8")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), [])
        self.assertEqual(self.state()[0], "OK")

    def test_lost_clock_sync_restarts_the_time_service(self) -> None:
        self.run_heal("--scheduled")  # часы синхронизированы: служба это запоминает
        (self.dir / "clock.txt").write_text("no\n", encoding="utf-8")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), ["systemctl restart systemd-timesyncd.service"])
        (self.dir / "clock.txt").write_text("yes\n", encoding="utf-8")
        self.run_heal("--scheduled")
        _segment, status, label, value, _hint, _ms = self.report_row()
        self.assertEqual((status, label), ("OK", "самовосстановление: за 7 дней сбоев 1, восстановлено 1"))
        self.assertEqual(value, "системные часы синхронизированы (перезапуск службы синхронизации времени)")

    def test_clock_that_never_synced_is_not_an_error(self) -> None:
        # NTP закрыт хостингом, время ведёт гипервизор: замечание висело бы всегда.
        (self.dir / "clock.txt").write_text("no\n", encoding="utf-8")
        self.run_heal("--scheduled")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), [])
        self.assertEqual(self.state()[0], "OK")

    def test_server_without_a_time_service_is_not_checked(self) -> None:
        self.run_heal("--scheduled")
        (self.dir / "clock.txt").write_text("no\n", encoding="utf-8")
        (self.dir / "timer-disabled").write_text("", encoding="utf-8")  # is-enabled: ни одной службы
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), [])

    def test_own_probes_are_not_awg_health_checks(self) -> None:
        # Deploy требует awg-health --strict без замечаний: новая проверка там могла
        # бы остановить обновление каскада ложным срабатыванием.
        labels = health_labels()
        self.assertNotIn("свободное место на корневом разделе", labels)
        self.assertNotIn("системные часы синхронизированы", labels)
        # Таблица действий и проверки используют одни и те же названия.
        text = SELF_HEAL.read_text(encoding="utf-8")
        for label in ("свободное место на корневом разделе", "системные часы синхронизированы"):
            self.assertEqual(text.count(f"'{label}'"), 2, label)


class FailedUnitTests(SelfHealCase):
    def failed_units(self, *units: str) -> None:
        (self.dir / "failed-units.txt").write_text(
            "".join(f"{unit} loaded failed failed описание\n" for unit in units), encoding="utf-8"
        )

    def test_failed_maintenance_is_started_again_once(self) -> None:
        self.failed_units("awg-maintenance.service")
        self.run_heal("--scheduled")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), ["systemctl start --no-block awg-maintenance.service"])
        self.assertIn("модуль systemd awg-maintenance.service", self.state()[3])

    def test_periodic_job_is_started_again(self) -> None:
        self.failed_units("awg-ru-zone-update.service")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), ["systemctl start --no-block awg-ru-zone-update.service"])

    def test_unknown_failed_unit_is_only_reported(self) -> None:
        self.failed_units("something-else.service")
        self.run_heal("--scheduled")
        self.assertEqual(self.changes(), [])
        self.assertIn("не исправляется автоматически", self.state()[3])
        # Команда для поиска причины называет сам модуль, а не «ИМЯ».
        self.assertIn("sudo journalctl -u something-else.service -b --no-pager", self.state()[3])
        self.assertNotIn("ИМЯ", self.state()[3])

    def test_job_fixed_by_its_rerun_counts_as_repaired(self) -> None:
        # Повторный запуск идёт в фоне: его итог виден только в следующем цикле.
        self.failed_units("awg-ru-zone-update.service")
        self.run_heal("--scheduled")
        self.assertEqual(self.report_row()[1], "WARN")
        self.failed_units()
        self.run_heal("--scheduled")
        _segment, status, label, value, _hint, _ms = self.report_row()
        self.assertEqual((status, label), ("OK", "самовосстановление: за 7 дней сбоев 1, восстановлено 1"))
        self.assertIn("модуль systemd awg-ru-zone-update.service (", value)

    def test_own_and_audit_units_are_ignored(self) -> None:
        self.failed_units("awg-server-audit.service", "awg-self-heal.service")
        self.run_heal("--scheduled")
        self.assertEqual(self.state()[0], "OK")


class RoleTests(SelfHealCase):
    def test_exit_restarts_its_tunnel_without_entry_follow_ups(self) -> None:
        self.health(1, "ограниченный NAT EXIT сервера")
        self.health(2, "ограниченный NAT EXIT сервера")
        self.run_heal("--scheduled", role="exit")
        self.assertEqual(self.changes(), ["systemctl restart awg-quick@awg3.service"])

    def test_front_restarts_xray_and_resyncs_users(self) -> None:
        failed = ("реестр VLESS-пользователей согласован с Xray", "служба Xray-core FRONT-релея")
        self.health(1, *failed)
        self.health(2, *failed)
        self.run_heal("--scheduled", role="front")
        self.assertEqual(self.changes(), ["systemctl restart xray.service", "vless-user sync"])

    def test_action_of_another_role_is_not_executed(self) -> None:
        self.health("last", "служба Xray-core FRONT-релея")
        self.run_heal("--scheduled", role="exit")
        self.assertEqual(self.changes(), [])

    def test_userspace_transit_restarts_its_own_service(self) -> None:
        self.health(1, "служба AWG 3+ до EXIT сервера")
        self.health(2, "служба AWG 3+ до EXIT сервера")
        self.run_heal("--scheduled", awg3_transit_enabled=True)
        self.assertEqual(self.changes()[0], "systemctl restart awg3-transit.service")


class TableTests(SelfHealCase):
    def classify(self, labels: list[str]) -> dict[str, str]:
        text = self.script().read_text(encoding="utf-8")
        start = text.index("classify() {")
        end = text.index("# Порядок выполнения")
        titles = text[text.index("action_title() {"):text.index("restart_unit() {")]
        order = text[text.index("readonly -a action_order=("):text.index("action_title() {")]
        body = (
            "set -Eeuo pipefail\nreadonly unit_prefix='модуль systemd '\n" + text[start:end] + order + titles
            + 'while IFS= read -r label; do\n'
            '    classify "$label"\n'
            '    printf \'%s\\t%s\\t%s\\t%s\\n\' "$label" "$plan_action" "$plan_reason" '
            '"$([[ -z "$plan_action" ]] || action_title "$plan_action")"\n'
            "done\n"
            'printf "ORDER\\t%s\\n" "${action_order[*]}"\n'
        )
        result = subprocess.run(
            [self.bash, "-c", body], input="\n".join(labels) + "\n", capture_output=True, text=True, timeout=30
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line.split("\t") for line in result.stdout.splitlines()]
        self.order = next(row[1] for row in rows if row[0] == "ORDER").split()
        return {row[0]: "\t".join(row[1:]) for row in rows if row[0] != "ORDER"}

    def test_every_health_check_is_classified(self) -> None:
        labels = health_labels()
        self.assertGreater(len(labels), 120)
        table = self.classify(labels)
        unknown = [label for label, plan in table.items() if "действие не задано" in plan]
        self.assertEqual(unknown, [], "проверки awg-health без строки в таблице self-heal")
        for label, plan in table.items():
            action, reason, title = plan.split("\t")
            with self.subTest(label=label):
                # Ровно одно из двух: действие либо причина, по которой его нет.
                self.assertNotEqual(bool(action), bool(reason))
                if action:
                    self.assertIn(action, self.order)
                    self.assertNotEqual(title, action, "у действия нет названия")
                else:
                    self.assertRegex(reason, r"^(deploy|external:.+|manual:.+)$")

    def test_security_and_release_drift_have_no_automatic_action(self) -> None:
        table = self.classify(
            [
                "UFW соответствует последней управляемой политике",
                "клиенты AWG изолированы друг от друга",
                "systemd journal хранится только в RAM",
                "защищённые службы получают конфигурацию через systemd credentials",
                "MTU клиентского интерфейса согласован с каскадом",
            ]
        )
        for label, plan in table.items():
            self.assertEqual(plan.split("\t")[:2], ["", "deploy"], label)

    def test_rendered_scripts_pass_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("нужен shellcheck")
        for role, extra in (("entry", {}), ("entry", {"awg3_transit_enabled": True}), ("exit", {}), ("front", {})):
            script = self.script(role, **extra)
            result = subprocess.run([shellcheck, "--exclude=SC2317", str(script)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, f"{role}: {result.stdout}{result.stderr}")


class WiringTests(unittest.TestCase):
    def test_role_installs_and_enables_the_timer(self) -> None:
        tasks = yaml.safe_load((HEALTH_ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
        names = [task["name"] for task in tasks]
        timer = names.index("Включение: таймер самовосстановления")
        # Таймер включается до строгой проверки: она требует его активности.
        self.assertLess(timer, names.index("Настройка: проверка состояния - этап 4"))
        defaults = yaml.safe_load((HEALTH_ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
        self.assertIs(defaults["awg_self_heal_enabled"], True)
        self.assertEqual(defaults["awg_self_heal_path"], "/usr/local/sbin/self-heal")

    def test_command_is_exposed_and_tracked(self) -> None:
        gateway = (ROOT / "roles/security/templates/kalimera-admin-command.sh.j2").read_text(encoding="utf-8")
        self.assertIn("|self-heal|", gateway)
        tools = (ROOT / "roles/terminal/templates/kalimera-shell-tools.sh.j2").read_text(encoding="utf-8")
        self.assertIn('function self-heal { _kalimera_admin self-heal "$@"; }', tools)
        manifest = (ROOT / "roles/operations/templates/awg-managed-integrity.sh.j2").read_text(encoding="utf-8")
        self.assertIn("/etc/systemd/system/awg-self-heal.timer", manifest)
        self.assertIn("awg_self_heal_path | default('/usr/local/sbin/self-heal')", manifest)

    def test_administrator_reaches_the_program_through_the_gateway(self) -> None:
        # На рабочем каскаде «self-heal run» от администратора ответила Permission
        # denied в сеансе, открытом до обновления: функции команд читаются при
        # входе. Здесь та же цепочка в новом сеансе: функция, sudo, шлюз, программа.
        bash = bash_path()
        if os.geteuid() == 0:
            self.skipTest("функции команд создаются только для обычного пользователя")
        environment = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
        environment.filters["quote"] = lambda value: shlex.quote(str(value))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            sbin = directory / "sbin"
            sbin.mkdir()
            program = sbin / "self-heal"
            program.write_text('#!/bin/sh\necho "программа self-heal: $*"\n', encoding="utf-8")
            program.chmod(0o755)
            gateway = directory / "kalimera-admin-command"
            text = (ROOT / "roles/security/templates/kalimera-admin-command.sh.j2").read_text(encoding="utf-8")
            text = environment.from_string(text).render(awg_node_role="exit")
            text = text.replace("[[ $EUID -eq 0 ]] ||", "true ||", 1).replace("/usr/local/sbin/", f"{sbin}/")
            gateway.write_text(text, encoding="utf-8")
            gateway.chmod(0o755)
            sudo = directory / "sudo"
            sudo.write_text('#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n', encoding="utf-8")
            sudo.chmod(0o755)
            tools = directory / "kalimera-shell-tools.sh"
            text = (ROOT / "roles/terminal/templates/kalimera-shell-tools.sh.j2").read_text(encoding="utf-8")
            text = environment.from_string(text).render(awg_node_role="exit")
            tools.write_text(text.replace("/usr/local/libexec/kalimera-admin-command", str(gateway)), encoding="utf-8")
            result = subprocess.run(
                [bash, "--norc", "-i", "-c", f"source {shlex.quote(str(tools))}\nself-heal status\n"],
                capture_output=True,
                text=True,
                env={**os.environ, "PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"},
                stdin=subprocess.DEVNULL,
                timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("программа self-heal: status", result.stdout)

    def test_deploy_marks_itself_and_cleans_up(self) -> None:
        site = (ROOT / "playbooks" / "site.yml").read_text(encoding="utf-8")
        self.assertLess(
            site.index("Отметка идущего deploy для службы самовосстановления"),
            site.index("Проверка системного DNS до изменения состояния серверов"),
        )
        self.assertGreater(
            site.index("Снятие отметки идущего deploy"),
            site.index("Создание манифеста после полного применения ролей"),
        )
        cleanup = (ROOT / "playbooks" / "cleanup.yml").read_text(encoding="utf-8")
        self.assertIn("Снятие отметки идущего deploy", cleanup)

    def test_health_checks_the_timer_unless_switched_off(self) -> None:
        health = HEALTH.read_text(encoding="utf-8")
        self.assertIn("check_minor 'таймер самовосстановления' systemctl is-active --quiet", health)
        self.assertIn("check_passed 'самовосстановление выключено администратором'", health)

    def test_telegram_accepts_a_ready_message(self) -> None:
        monitor = (ROOT / "roles/operations/templates/telegram-monitor.sh.j2").read_text(encoding="utf-8")
        notify = monitor.index('if [[ -n "$notify_text" ]]; then')
        # Готовое сообщение уходит до общей блокировки и без запуска аудита.
        self.assertLess(notify, monitor.index('exec 9>"$STATE_DIR/lock"'))
        self.assertIn("[IP]", monitor[notify:monitor.index("install -d -m 0700", notify)])


if __name__ == "__main__":
    unittest.main()

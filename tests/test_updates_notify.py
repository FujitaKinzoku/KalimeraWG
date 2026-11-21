"""kalimera-updates по расписанию: уведомления Telegram и срок регистрации домена.

Сформированный шаблон запускается в bash с подставными apt, curl и программой
отправки уведомлений. Проверяется, что о новой версии компонента сообщается один
раз и с командой установки, что срок домена запрашивается у реестра без имён
поддоменов и что недоступный реестр не превращается в ошибку.
"""

from __future__ import annotations

import datetime
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import jinja2

ROOT = Path(__file__).parents[1]
TEMPLATE = ROOT / "roles" / "operations" / "templates" / "kalimera-updates.sh.j2"
SERVICE = ROOT / "roles" / "operations" / "templates" / "kalimera-updates.service.j2"

FAKES = {
    "uname": 'printf "6.8.0-149-generic\\n"',
    "apt-get": "exit 0",
    "apt-cache": (
        'case "$1" in\n'
        "    depends) printf '%s\\n  Depends: linux-image-6.8.0-149-generic\\n' \"$2\" ;;\n"
        "    policy) printf '%s:\\n  Installed: 1.0-1\\n  Candidate: %s\\n' \"$2\" \"$(cat \"$FAKE_DIR/awg-candidate\")\" ;;\n"
        "esac\n"
    ),
    "dpkg-query": (
        'case "$2" in\n'
        "    *Status*) printf 'ii ' ;;\n"
        "    *Version*) printf '1.0-1' ;;\n"
        "esac\n"
    ),
    # Адрес - последний аргумент: список IANA, запрос о домене или выпуски Xray.
    "curl": (
        'url="${*: -1}"\n'
        'case "$url" in\n'
        '    *bootstrap*) cat "$FAKE_DIR/bootstrap.json" 2>/dev/null || exit 6 ;;\n'
        "    */domain/*)\n"
        '        name="${url##*/domain/}"\n'
        '        printf \'%s\\n\' "$name" >>"$FAKE_DIR/rdap-queries.log"\n'
        '        cat "$FAKE_DIR/rdap-$name.json" 2>/dev/null || exit 22\n'
        "        ;;\n"
        "    *) exit 6 ;;\n"
        "esac\n"
    ),
    "xray": 'printf "Xray 26.10.31 (Xray, Penetrates Everything.)\\n"',
    # Текущее время сдвигается на заданное число суток: так проверяется, что
    # напоминание о сроке домена повторяется по порогам, а не каждый день.
    "date": (
        'if [[ "$*" == "+%s" ]]; then\n'
        '    echo $(( $(/bin/date +%s) + 86400 * $(cat "$FAKE_DIR/days-passed" 2>/dev/null || echo 0) ))\n'
        "else\n"
        '    exec /bin/date "$@"\n'
        "fi\n"
    ),
    # Сообщение записывается одной строкой; код возврата задаётся файлом.
    "notifier": (
        'text="$2"\n'
        'printf \'%s\\n\' "${text//$\'\\n\'/ | }" >>"$FAKE_DIR/sent.log"\n'
        'exit "$(cat "$FAKE_DIR/notifier-code" 2>/dev/null || echo 0)"\n'
    ),
}


class UpdatesCase(unittest.TestCase):
    role = "entry"

    def setUp(self) -> None:
        self.bash = shutil.which("bash")
        if self.bash is None or os.name == "nt" or shutil.which("flock") is None:
            self.skipTest("нужны bash и flock на Linux")
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        for name, body in FAKES.items():
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
            path.chmod(0o755)
        (self.dir / "awg-candidate").write_text("1.0-1\n", encoding="utf-8")
        self.notified = self.dir / "notified"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def script(self, role: str | None = None) -> Path:
        environment = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
        environment.filters["quote"] = lambda value: shlex.quote(str(value))
        text = environment.from_string(TEMPLATE.read_text(encoding="utf-8")).render(
            awg_node_role=role or self.role,
            kalimera_updates_state_dir=str(self.dir / "state"),
            kalimera_updates_apt_lock_path=str(self.dir / "apt.lock"),
            kalimera_updates_xray_releases_api="https://api.github.invalid/latest",
            kalimera_updates_rdap_bootstrap="https://bootstrap.invalid/dns.json",
            front_xray_binary_path=str(self.bin / "xray"),
            front_origin_domain="origin.example.uk",
            front_cdn_domain="www.example.uk",
            awg_telegram_monitor_path=str(self.bin / "notifier"),
            awg_telegram_monitor_state_dir=str(self.notified),
        )
        path = self.dir / "kalimera-updates"
        path.write_text(text.replace("[[ $EUID -eq 0 ]] ||", "true ||", 1), encoding="utf-8")
        return path

    def run_updates(self, *arguments: str, role: str | None = None) -> str:
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "FAKE_DIR": str(self.dir),
            "KALIMERA_REPORT_STYLE": "plain",
        }
        result = subprocess.run(
            [self.bash, str(self.script(role)), *arguments], capture_output=True, text=True, env=env, timeout=60
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def sent(self) -> list[str]:
        path = self.dir / "sent.log"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def state(self) -> str:
        return (self.dir / "state" / "state").read_text(encoding="utf-8")


class ComponentNotifyTests(UpdatesCase):
    def new_amneziawg(self, version: str = "1.1-1") -> None:
        (self.dir / "awg-candidate").write_text(f"{version}\n", encoding="utf-8")

    def test_new_version_is_announced_once_with_the_command(self) -> None:
        self.new_amneziawg()
        self.run_updates("--scheduled")
        self.run_updates("--scheduled")
        self.assertEqual(len(self.sent()), 1, self.sent())
        message = self.sent()[0]
        self.assertTrue(message.startswith("AWG ENTRY: доступно обновление компонентов | доступен AmneziaWG: "), message)
        self.assertIn("amneziawg-dkms 1.0-1 → 1.1-1", message)
        self.assertIn("→ на ENTRY: kalimera-deploy --resume --update-amneziawg", message)

    def test_next_version_is_announced_again(self) -> None:
        self.new_amneziawg("1.1-1")
        self.run_updates("--scheduled")
        self.new_amneziawg("1.2-1")
        self.run_updates("--scheduled")
        self.assertEqual(len(self.sent()), 2, self.sent())
        self.assertIn("1.0-1 → 1.2-1", self.sent()[1])

    def test_installed_update_clears_the_mark(self) -> None:
        self.new_amneziawg()
        self.run_updates("--scheduled")
        self.assertTrue((self.notified / "updates-notified").exists())
        self.new_amneziawg("1.0-1")
        self.run_updates("--scheduled")
        self.assertFalse((self.notified / "updates-notified").exists())
        self.assertEqual(len(self.sent()), 1)

    def test_exit_stays_silent_about_amneziawg(self) -> None:
        # Тот же репозиторий и та же команда с ENTRY: второе сообщение было бы повтором.
        self.new_amneziawg()
        self.run_updates("--scheduled", role="exit")
        self.assertEqual(self.sent(), [])
        self.assertIn("UPD\tamneziawg\t", self.state())

    def test_manual_check_sends_nothing(self) -> None:
        self.new_amneziawg()
        output = self.run_updates()
        self.assertIn("UPD  доступен AmneziaWG", output)
        self.assertEqual(self.sent(), [])

    def test_undelivered_message_is_retried(self) -> None:
        # Telegram ещё не настроен (код 3): отметка не ставится, и сообщение уйдёт,
        # когда уведомления включат.
        self.new_amneziawg()
        (self.dir / "notifier-code").write_text("3\n", encoding="utf-8")
        self.run_updates("--scheduled")
        self.assertFalse((self.notified / "updates-notified").exists())
        (self.dir / "notifier-code").write_text("0\n", encoding="utf-8")
        self.run_updates("--scheduled")
        self.assertTrue((self.notified / "updates-notified").exists())
        self.assertEqual(len(self.sent()), 2)

    def test_new_kernel_is_not_announced(self) -> None:
        # Ядро ставит ночное обслуживание, перезагрузку выполняет cascade-reboot.
        text = TEMPLATE.read_text(encoding="utf-8")
        body = text[text.index("notify_news() {"):text.index("\n}\n", text.index("notify_news() {"))]
        self.assertNotIn("kernel", body)

    def test_timer_runs_the_scheduled_mode(self) -> None:
        self.assertIn("ExecStart={{ kalimera_updates_path }} --scheduled\n", SERVICE.read_text(encoding="utf-8"))


class DomainExpiryTests(UpdatesCase):
    role = "front"

    def setUp(self) -> None:
        super().setUp()
        (self.dir / "bootstrap.json").write_text(
            json.dumps({"services": [[["com", "net"], ["https://rdap.com.invalid/"]], [["uk"], ["https://rdap.uk.invalid/uk/"]]]}),
            encoding="utf-8",
        )

    def expires_in(self, days: int) -> str:
        date = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days, hours=1)).date()
        (self.dir / "rdap-example.uk.json").write_text(
            json.dumps(
                {
                    "ldhName": "example.uk",
                    "events": [
                        {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                        {"eventAction": "expiration", "eventDate": f"{date.isoformat()}T12:00:00Z"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        return date.isoformat()

    def test_near_expiry_is_a_warning_with_a_notification(self) -> None:
        date = self.expires_in(20)
        output = self.run_updates("--scheduled")
        # Дни считаются до начала даты окончания: 19 или 20 в зависимости от часа.
        self.assertRegex(output, rf"WARN регистрация домена example\.uk истекает {date} \(через (19|20) дн\.\)")
        self.assertIn("продлите домен у регистратора", output)
        # Домен origin и домен CDN - одна регистрация: одна строка и одно сообщение.
        self.assertEqual(self.state().count("WARN\tdomain\t"), 1)
        self.assertEqual(len(self.sent()), 1, self.sent())
        self.assertTrue(self.sent()[0].startswith("AWG FRONT: заканчивается регистрация домена | "), self.sent()[0])

    def days_pass(self, days: int) -> None:
        (self.dir / "days-passed").write_text(f"{days}\n", encoding="utf-8")
        self.run_updates("--scheduled")

    def test_reminder_repeats_at_thresholds_not_daily(self) -> None:
        self.expires_in(20)
        self.days_pass(0)
        self.days_pass(1)
        self.assertEqual(len(self.sent()), 1, self.sent())  # порог 30 дней
        self.days_pass(6)
        self.days_pass(7)
        self.assertEqual(len(self.sent()), 2, self.sent())  # порог 14 дней
        self.days_pass(17)
        self.assertEqual(len(self.sent()), 3, self.sent())  # порог 3 дня

    def test_subdomain_names_are_not_sent_to_the_registry(self) -> None:
        self.expires_in(200)
        self.run_updates("--scheduled")
        queries = set((self.dir / "rdap-queries.log").read_text(encoding="utf-8").split())
        self.assertEqual(queries, {"example.uk"})

    def test_distant_expiry_is_ok_and_silent(self) -> None:
        date = self.expires_in(200)
        output = self.run_updates("--scheduled")
        self.assertIn(f"OK   домен example.uk зарегистрирован до {date}", output)
        self.assertEqual(self.sent(), [])

    def test_expired_domain_is_named(self) -> None:
        date = self.expires_in(-3)
        self.assertIn(f"WARN регистрация домена example.uk истекла {date}", self.run_updates())

    def test_silent_registry_is_not_an_error(self) -> None:
        # Реестр не ответил: срок не определён, но это не замечание и не тревога.
        output = self.run_updates("--scheduled")
        self.assertIn("INFO срок регистрации домена origin.example.uk не определён", output)
        self.assertNotIn("WARN", output)
        self.assertEqual(self.sent(), [])

    def test_zone_without_rdap_is_not_an_error(self) -> None:
        (self.dir / "bootstrap.json").write_text(json.dumps({"services": []}), encoding="utf-8")
        output = self.run_updates("--scheduled")
        self.assertIn("INFO срок регистрации домена origin.example.uk не определён", output)
        self.assertFalse((self.dir / "rdap-queries.log").exists())

    def test_broken_answers_do_not_stop_the_check(self) -> None:
        (self.dir / "bootstrap.json").write_text("<html>blocked</html>", encoding="utf-8")
        self.assertIn("INFO срок регистрации домена", self.run_updates())
        (self.dir / "bootstrap.json").write_text(
            json.dumps({"services": [[["uk"], ["https://rdap.uk.invalid/uk/"]]]}), encoding="utf-8"
        )
        (self.dir / "rdap-example.uk.json").write_text('{"events": "нет"}', encoding="utf-8")
        self.assertIn("INFO срок регистрации домена", self.run_updates())

    def test_impossible_date_does_not_break_the_whole_check(self) -> None:
        (self.dir / "rdap-example.uk.json").write_text(
            json.dumps({"events": [{"eventAction": "expiration", "eventDate": "2026-13-45T00:00:00Z"}]}),
            encoding="utf-8",
        )
        output = self.run_updates("--scheduled")
        self.assertIn("INFO срок регистрации домена example.uk не определён: реестр вернул непонятную дату", output)
        self.assertIn("OK   ядро", output)  # остальные проверки выполнены и записаны
        self.assertEqual(self.sent(), [])

    def test_entry_does_not_ask_about_domains(self) -> None:
        # Запрос с ENTRY раскрыл бы реестру его адрес рядом с именем домена.
        self.expires_in(5)
        self.run_updates("--scheduled", role="entry")
        self.assertNotIn("domain", self.state())
        self.assertFalse((self.dir / "rdap-queries.log").exists())


if __name__ == "__main__":
    unittest.main()

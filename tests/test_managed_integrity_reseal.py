"""Манифест целостности после команд, которые сами меняют управляемые файлы.

dot-switch переписывает 90-awg-dot.conf, а этот файл входит в манифест
awg-managed-integrity. Обе программы рендерятся Jinja2 с рабочими путями, затем
/etc, /run, /root, /usr/local и /var/lib переносятся во временный каталог, и в
bash выполняется seal -> команда -> check. unbound-checkconf, systemctl, dig и
kalimera-secretctl подменяются скриптами, поэтому root, сеть и настоящий Unbound
не нужны. jq и flock нужны настоящие.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import jinja2

ROOT = Path(__file__).parents[1]
TEMPLATES = ROOT / "roles" / "operations" / "templates"
INTEGRITY = TEMPLATES / "awg-managed-integrity.sh.j2"
DOT_SWITCH = TEMPLATES / "dot-switch.sh.j2"
REALITY_SWITCH = TEMPLATES / "reality-dest-switch.sh.j2"

MANIFEST = "/var/lib/awg-iac/security/managed-files.sha256"
INTEGRITY_PATH = "/usr/local/sbin/awg-managed-integrity"
SECRETCTL_PATH = "/usr/local/sbin/kalimera-secretctl"
DOT_CONF = "/etc/unbound/unbound.conf.d/90-awg-dot.conf"
SSHD_CONF = "/etc/ssh/sshd_config.d/00-awg-managed.conf"
FRONT_BACKEND = "/etc/sing-box/front-backend.json"
SING_BOX = "/etc/sing-box/config.json"

DEFAULT_DOT = (
    {"address": "162.254.86.13", "tls_name": "vno01.dnscry.pt"},
    {"address": "185.95.218.43", "tls_name": "dns.digitale-gesellschaft.ch"},
)
DEFAULT_FORWARDERS = [f"{item['address']}@853#{item['tls_name']}" for item in DEFAULT_DOT]

# Политика без журналов стоит в том же файле, что и серверы DoT: из-за неё файл
# и входит в манифест. dot-switch меняет только строки forward-addr.
BASE_CONF = (
    "server:\n"
    "    port: 5353\n"
    "    verbosity: 0\n"
    "    log-queries: no\n"
    "\n"
    "forward-zone:\n"
    '    name: "."\n'
    "    forward-tls-upstream: yes\n"
    + "".join(f"    forward-addr: {server}\n" for server in DEFAULT_FORWARDERS)
)

FAKE_TOOL = """#!/usr/bin/env bash
# Подставная команда: записывает вызов и падает, если есть файл ИМЯ-fails.
state={state}
name="$(basename "$0")"
printf '%s %s\\n' "$name" "$*" >>"$state/calls.log"
[[ ! -e "$state/$name-fails" ]] || exit 1
[[ "$name" != dig ]] || echo 93.184.216.34
"""

# Манифест проверяется, но не записывается: так выглядит сбой seal на сервере.
UNSEALABLE_INTEGRITY = """#!/usr/bin/env bash
[[ "$1" == check ]] && exit 0
echo 'нет места для манифеста' >&2
exit 1
"""

ROOT_CHECK = "[[ $EUID -eq 0 ]] ||"
SYSTEM_PATH = re.compile(r"(?<![\w./-])/(etc|run|root|usr/local|var/lib)/")
NOT_RESEALED = "манифест целостности не обновлён"
SEAL_FAILED = "не удалось обновить манифест целостности"


def render(template: Path, **variables) -> str:
    environment = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    return environment.from_string(template.read_text(encoding="utf-8")).render(**variables)


def sandbox(text: str, root: Path) -> str:
    """Переносит системные пути отрендеренной программы во временный каталог."""
    return SYSTEM_PATH.sub(lambda match: f"{root}/{match.group(1)}/", text)


def without_root_check(text: str) -> str:
    """Тест работает от обычного пользователя: проверка root заменяется."""
    if ROOT_CHECK not in text:
        raise AssertionError("в программе нет проверки запуска от root")
    return text.replace(ROOT_CHECK, "true ||", 1)


def bash_path() -> str:
    executable = shutil.which("bash")
    if executable is None or os.name == "nt":
        raise unittest.SkipTest("нужен bash на Linux")
    return executable


def integrity_text(**overrides) -> str:
    variables = {
        "awg_managed_integrity_manifest": MANIFEST,
        "awg_node_role": "entry",
        "runtime_secrets_enabled": False,
        "front_backend_enabled": False,
        "awg3_transit_enabled": False,
    }
    variables.update(overrides)
    return render(INTEGRITY, **variables)


def managed_paths(**overrides) -> list[str]:
    """Пути из списка управляемых файлов отрендеренного awg-managed-integrity."""
    text = integrity_text(**overrides)
    start = text.index("done <<'EOF'\n") + len("done <<'EOF'\n")
    return text[start:text.index("\nEOF\n", start)].split("\n")


def dot_switch_text(**overrides) -> str:
    variables = {
        "entry_dns_dot_override_path": "/etc/awg/dot-override.json",
        "entry_dns_default_port": 5353,
        "entry_dns_dot_upstreams_resolved": list(DEFAULT_DOT),
        "runtime_secrets_enabled": False,
    }
    variables.update(overrides)
    return render(DOT_SWITCH, **variables)


def reality_switch_text(**overrides) -> str:
    variables = {
        "front_backend_enabled": True,
        "sing_box_config_path": SING_BOX,
        "sing_box_service_name": "sing-box.service",
        "sing_box_reality_dest_override_path": "/etc/awg/reality-dest-override.json",
        "reality_fallback_port": 8444,
        "reality_fallback_dest": "yandex.ru",
        "reality_fallback_dest_port": 443,
        "runtime_secrets_enabled": False,
    }
    variables.update(overrides)
    return render(REALITY_SWITCH, **variables)


class SandboxCase(unittest.TestCase):
    """Временный каталог вместо корня сервера с подставными командами."""

    def setUp(self) -> None:
        self.bash = bash_path()
        for tool in ("jq", "flock", "sha256sum"):
            if shutil.which(tool) is None:
                self.skipTest(f"нужен {tool}")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # Путь подставляется в программы без кавычек, как рабочие пути на сервере.
        if not re.fullmatch(r"[\w./-]+", str(self.root)):
            self.skipTest("нужен временный каталог без пробелов и спецсимволов")
        self.state = self.root / "state"
        self.fakebin = self.root / "bin"
        for directory in (self.state, self.fakebin, self.path("/run")):
            directory.mkdir(parents=True)
        self.calls = self.state / "calls.log"
        self.calls.write_text("", encoding="utf-8")
        fake = FAKE_TOOL.format(state=shlex.quote(str(self.state)))
        for name in ("unbound-checkconf", "systemctl", "dig"):
            self.install(self.fakebin / name, fake)
        self.install(self.path(SECRETCTL_PATH), fake)
        self.manifest = self.path(MANIFEST)
        self.integrity_program = self.path(INTEGRITY_PATH)
        self.install_integrity()
        # Управляемый файл, который проверяемые команды не трогают.
        self.unrelated = self.write(SSHD_CONF, "PasswordAuthentication no\n")

    def path(self, system_path: str) -> Path:
        return Path(f"{self.root}{system_path}")

    def write(self, system_path: str, text: str) -> Path:
        target = self.path(system_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def install(self, target: Path, text: str) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        target.chmod(0o755)

    def install_integrity(self, **overrides) -> None:
        self.install(self.integrity_program, sandbox(integrity_text(**overrides), self.root))

    def run_program(self, program: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "PATH": f"{self.fakebin}{os.pathsep}{os.environ['PATH']}"}
        return subprocess.run(
            [self.bash, str(program), *arguments],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    def seal(self) -> bytes:
        result = self.run_program(self.integrity_program, "seal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_manifest_valid()
        return self.manifest.read_bytes()

    def check(self) -> subprocess.CompletedProcess[str]:
        return self.run_program(self.integrity_program, "check")

    def assert_manifest_valid(self) -> None:
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def flag(self, name: str, present: bool = True) -> None:
        marker = self.state / name
        if present:
            marker.write_text("", encoding="utf-8")
        else:
            marker.unlink(missing_ok=True)

    def logged_calls(self) -> list[str]:
        return self.calls.read_text(encoding="utf-8").splitlines()


class DotSwitchManifestTests(SandboxCase):
    def setUp(self) -> None:
        super().setUp()
        self.config = self.write(DOT_CONF, BASE_CONF)
        self.override = self.path("/etc/awg/dot-override.json")
        self.program = self.path("/usr/local/sbin/dot-switch")
        self.install_switch()

    def install_switch(self, **overrides) -> None:
        text = without_root_check(dot_switch_text(**overrides))
        self.install(self.program, sandbox(text, self.root))

    def switch(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self.run_program(self.program, *arguments)

    def forwarders(self) -> list[str]:
        return [
            line.split()[1]
            for line in self.config.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("forward-addr:")
        ]

    def test_custom_servers_keep_the_manifest_valid(self) -> None:
        self.assertIn(str(self.config), self.seal().decode("utf-8"))
        result = self.switch("custom", "9.9.9.9,149.112.112.112", "dns.quad9.net")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Upstream-серверы DoT проверены и применены.\n")
        self.assertNotIn("ВНИМАНИЕ", result.stderr)
        self.assertEqual(
            self.forwarders(), ["9.9.9.9@853#dns.quad9.net", "149.112.112.112@853#dns.quad9.net"]
        )
        self.assertTrue(self.override.is_file())
        self.assert_manifest_valid()

    def test_pairs_and_reset_keep_the_manifest_valid(self) -> None:
        self.seal()
        result = self.switch("custom", "1.1.1.1:one.one.one.one,9.9.9.9:dns.quad9.net")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.forwarders(), ["1.1.1.1@853#one.one.one.one", "9.9.9.9@853#dns.quad9.net"])
        self.assert_manifest_valid()
        result = self.switch("reset")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.forwarders(), DEFAULT_FORWARDERS)
        self.assertFalse(self.override.exists())
        self.assert_manifest_valid()

    def test_other_changed_file_keeps_the_audit_failing(self) -> None:
        sealed = self.seal()
        self.unrelated.write_text("PasswordAuthentication yes\n", encoding="utf-8")
        result = self.switch("custom", "9.9.9.9", "dns.quad9.net")
        # Смена DoT выполняется, но манифест остаётся прежним.
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.forwarders(), ["9.9.9.9@853#dns.quad9.net"])
        self.assertIn(NOT_RESEALED, result.stderr)
        self.assertIn("sudo awg-managed-integrity check", result.stderr)
        self.assertEqual(self.manifest.read_bytes(), sealed)
        verdict = self.check()
        self.assertEqual(verdict.returncode, 1)
        self.assertIn(str(self.unrelated), verdict.stdout)

    def test_manual_edit_of_the_dot_file_is_not_sealed(self) -> None:
        sealed = self.seal()
        self.config.write_text(
            BASE_CONF.replace("log-queries: no", "log-queries: yes"), encoding="utf-8"
        )
        result = self.switch("custom", "9.9.9.9", "dns.quad9.net")
        self.assertEqual(result.returncode, 0, result.stderr)
        # dot-switch меняет только forward-addr: ручная правка остаётся в файле.
        self.assertIn("log-queries: yes", self.config.read_text(encoding="utf-8"))
        self.assertIn(NOT_RESEALED, result.stderr)
        self.assertEqual(self.manifest.read_bytes(), sealed)
        verdict = self.check()
        self.assertEqual(verdict.returncode, 1)
        self.assertIn(str(self.config), verdict.stdout)

    def test_missing_manifest_is_not_created(self) -> None:
        result = self.switch("custom", "9.9.9.9", "dns.quad9.net")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(NOT_RESEALED, result.stderr)
        self.assertFalse(self.manifest.exists())
        self.assertEqual(self.check().returncode, 1)

    def test_rolled_back_change_leaves_the_manifest_valid(self) -> None:
        sealed = self.seal()
        for tool, rolled_back in (
            ("unbound-checkconf", False),
            ("systemctl", True),
            ("dig", True),
        ):
            with self.subTest(tool=tool):
                self.flag(f"{tool}-fails")
                result = self.switch("custom", "9.9.9.9", "dns.quad9.net")
                self.flag(f"{tool}-fails", present=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual("Изменение DoT отменено" in result.stderr, rolled_back, result.stderr)
                self.assertNotIn("проверены и применены", result.stdout)
                self.assertEqual(self.config.read_text(encoding="utf-8"), BASE_CONF)
                self.assertFalse(self.override.exists())
                self.assertEqual(self.manifest.read_bytes(), sealed)
                self.assert_manifest_valid()

    def test_runtime_secrets_are_sealed_before_the_manifest(self) -> None:
        self.install_switch(runtime_secrets_enabled=True)
        sealed = self.seal()
        result = self.switch("custom", "9.9.9.9", "dns.quad9.net")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kalimera-secretctl seal", self.logged_calls())
        self.assertNotEqual(self.manifest.read_bytes(), sealed)
        self.assert_manifest_valid()

    def test_failed_secret_seal_rolls_back_before_the_manifest_changes(self) -> None:
        self.install_switch(runtime_secrets_enabled=True)
        sealed = self.seal()
        self.flag("kalimera-secretctl-fails")
        result = self.switch("custom", "9.9.9.9", "dns.quad9.net")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Изменение DoT отменено", result.stderr)
        self.assertEqual(self.config.read_text(encoding="utf-8"), BASE_CONF)
        self.assertEqual(self.manifest.read_bytes(), sealed)
        self.assert_manifest_valid()

    def test_failed_manifest_update_does_not_undo_the_switch(self) -> None:
        self.install(self.integrity_program, UNSEALABLE_INTEGRITY)
        result = self.switch("custom", "9.9.9.9", "dns.quad9.net")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Upstream-серверы DoT проверены и применены.\n")
        self.assertIn(SEAL_FAILED, result.stderr)
        self.assertNotIn("Изменение DoT отменено", result.stderr)
        self.assertEqual(self.forwarders(), ["9.9.9.9@853#dns.quad9.net"])
        self.assertEqual(self.logged_calls().count("systemctl restart unbound.service"), 1)

    def test_status_and_rejected_arguments_leave_the_manifest_alone(self) -> None:
        sealed = self.seal()
        before = self.manifest.stat().st_mtime_ns
        for arguments, code in (
            (("status",), 0),
            (("custom", "not-an-address", "dns.quad9.net"), 1),
            (("custom", "9.9.9.9", "bad..name"), 2),
            (("unknown",), 2),
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.switch(*arguments).returncode, code)
                self.assertEqual(self.manifest.read_bytes(), sealed)
                self.assertEqual(self.manifest.stat().st_mtime_ns, before)
        self.assertEqual(self.logged_calls(), [])


class RealityDestSwitchManifestTests(SandboxCase):
    """reality-dest-switch не меняет файлы манифеста, поэтому манифест не трогает."""

    BACKEND = (
        '{"inbounds": [{"tag": "front-reality-in", "tls": {"server_name": "yandex.ru", '
        '"reality": {"handshake": {"server": "yandex.ru", "server_port": 443}}}}]}\n'
    )

    def setUp(self) -> None:
        super().setUp()
        self.install_integrity(front_backend_enabled=True)
        self.config = self.write(FRONT_BACKEND, self.BACKEND)
        self.program = self.path("/usr/local/sbin/reality-dest-switch")
        self.install(self.program, sandbox(without_root_check(reality_switch_text()), self.root))

    def test_front_backend_configuration_is_sealed_and_never_rewritten(self) -> None:
        sealed = self.seal()
        self.assertIn(str(self.config), sealed.decode("utf-8"))
        for arguments in (("set", "vk.ru"), ("set", "vk.ru", "8443"), ("reset",)):
            with self.subTest(arguments=arguments):
                result = self.run_program(self.program, *arguments)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("dest меняется только через production inventory", result.stderr)
                self.assertEqual(self.config.read_text(encoding="utf-8"), self.BACKEND)
                self.assertEqual(self.manifest.read_bytes(), sealed)
                self.assert_manifest_valid()
        # До проб TLS, перезапуска службы и записи файлов дело не доходит.
        self.assertEqual(self.logged_calls(), [])
        self.assertFalse(self.path("/root/config-backups").exists())


class ManifestWiringTests(unittest.TestCase):
    """Проверки по тексту шаблонов: bash, jq и временный корень не нужны."""

    def test_dot_switch_rewrites_a_sealed_file(self) -> None:
        self.assertIn(DOT_CONF, managed_paths())
        self.assertIn(f"readonly config={DOT_CONF}\n", dot_switch_text())

    def test_server_audit_reports_the_same_check_as_a_failure(self) -> None:
        # Код возврата check, который проверяют тесты выше, server-audit и вслед за
        # ним cascade-check показывают как FAIL.
        audit = (TEMPLATES / "server-audit.sh.j2").read_text(encoding="utf-8")
        self.assertIn(
            "record 'целостность управляемых файлов подтверждена' "
            "{{ awg_managed_integrity_path | quote }} check\n",
            audit,
        )

    def test_manifest_is_checked_under_the_lock_and_sealed_after_commit(self) -> None:
        text = dot_switch_text(runtime_secrets_enabled=True)
        self.assertIn(f"readonly integrity={INTEGRITY_PATH}\n", text)
        check = text.index('"$integrity" check')
        seal = text.index('"$integrity" seal')
        self.assertLess(text.index("flock 9"), check)
        self.assertLess(check, text.index('cp -a "$config" "$config_backup"'))
        # Сначала проверенное изменение и runtime-секреты, потом манифест.
        committed = text.rindex("\ncommitted=false\n")
        self.assertLess(text.index('"$secretctl" seal'), committed)
        self.assertLess(committed, seal)
        # Откат возвращает прежний файл, поэтому манифест в нём не трогается.
        cleanup = text[text.index("cleanup() {"):text.index("trap cleanup EXIT")]
        self.assertNotIn("$integrity", cleanup)

    def test_reality_switch_refuses_before_any_write_of_the_sealed_file(self) -> None:
        text = reality_switch_text()
        self.assertIn(f"readonly config={FRONT_BACKEND}\n", text)
        self.assertIn(FRONT_BACKEND, managed_paths(front_backend_enabled=True))
        refusal = text.index("dest меняется только через production inventory")
        for write in ('cp -a "$config" "$config_backup"', 'install -m 0600 "$tmp" "$config"'):
            self.assertLess(text.index("exit 2\nfi\n", refusal), text.index(write))

    def test_reality_switch_without_front_backend_rewrites_an_unsealed_file(self) -> None:
        text = reality_switch_text(front_backend_enabled=False)
        self.assertIn(f"readonly config={SING_BOX}\n", text)
        self.assertNotIn("production inventory", text)
        for front_backend in (False, True):
            self.assertNotIn(SING_BOX, managed_paths(front_backend_enabled=front_backend))
        self.assertNotIn(FRONT_BACKEND, managed_paths(front_backend_enabled=False))

    def test_rendered_programs_pass_shellcheck(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None or os.name == "nt":
            self.skipTest("нужен shellcheck")
        with tempfile.TemporaryDirectory() as temporary:
            programs = []
            # dot-switch проверяется с runtime-секретами, как в tests/render-shell.yml:
            # без них переменная secretctl не используется (SC2034).
            for name, text in (
                ("dot-switch", dot_switch_text(runtime_secrets_enabled=True)),
                ("awg-managed-integrity", integrity_text(front_backend_enabled=True)),
            ):
                program = Path(temporary) / name
                program.write_text(text, encoding="utf-8")
                programs.append(str(program))
            result = subprocess.run(
                [shellcheck, "--exclude=SC2317", *programs], capture_output=True, text=True
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class SealedConfigurationUsageTests(unittest.TestCase):
    """Какие шаблоны роли operations упоминают управляемые файлы настроек.

    Если программа их только читает, манифест не устаревает. Программа, которая
    их переписывает, после проверенного изменения обязана обновить манифест, как
    dot-switch. Новая строка в этом списке означает, что это нужно решить.
    Поиск идёт по тексту шаблонов: путь, собранный из частей, он не увидит.
    """

    def sealed_configuration(self) -> set[str]:
        secrets = {
            "runtime_secrets_enabled": True,
            "runtime_secrets_ctl_path": SECRETCTL_PATH,
            "runtime_secrets_service_name": "kalimera-secrets-unlock.service",
        }
        transit = {
            "awg3_transit_enabled": True,
            "awg3_transit_setup_path": "/usr/local/sbin/awg3-transit-setup",
            "awg3_transit_service_name": "awg3-transit.service",
        }
        paths: set[str] = set()
        for role in ("entry", "exit", "front"):
            paths.update(
                managed_paths(awg_node_role=role, front_backend_enabled=True, **secrets, **transit)
            )
        # Программы из sbin и libexec другие программы запускают, а не переписывают.
        return {path for path in paths if not path.startswith(("/usr/local/sbin/", "/usr/local/libexec/"))}

    def test_only_known_programs_mention_sealed_configuration(self) -> None:
        sealed = self.sealed_configuration()
        self.assertIn(DOT_CONF, sealed)
        self.assertIn(FRONT_BACKEND, sealed)
        mentions = {}
        for template in sorted(TEMPLATES.iterdir()):
            if template == INTEGRITY:
                continue
            text = template.read_text(encoding="utf-8")
            found = {path for path in sealed if path in text}
            if found:
                mentions[template.name] = found
        self.assertEqual(
            mentions,
            {
                # Только читает.
                "dns-status.sh.j2": {DOT_CONF},
                # Переписывает и обновляет манифест.
                "dot-switch.sh.j2": {DOT_CONF},
                # set и reset при отдельном FRONT backend запрещены.
                "reality-dest-switch.sh.j2": {FRONT_BACKEND},
                # Только читает.
                "server-audit.sh.j2": {
                    "/etc/fail2ban/fail2ban.local",
                    "/etc/fail2ban/jail.d/zz-awg-sshd.local",
                    FRONT_BACKEND,
                    "/usr/local/etc/xray/config.base.json",
                    "/usr/local/etc/xray/config.json",
                    "/usr/local/etc/xray/users.json",
                    "/usr/local/etc/xray/client-settings.json",
                },
            },
            "шаблон упоминает управляемый файл: если программа его переписывает, "
            "после проверенного изменения нужен awg-managed-integrity seal, как в dot-switch",
        )


if __name__ == "__main__":
    unittest.main()

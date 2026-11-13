"""kalimera-updates: новые версии ядра, AmneziaWG и Xray показываются как UPD.

Сформированный шаблон запускается в bash с подставными uname, apt-get,
apt-cache, dpkg-query, curl и xray. Найденное обновление - строка UPD с командой, а не
предупреждение; недоступность GitHub - INFO, а не ошибка.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import jinja2

ROOT = Path(__file__).parents[1]
TEMPLATE = ROOT / "roles" / "operations" / "templates" / "kalimera-updates.sh.j2"

FAKES = {
    "uname": 'printf "%s\\n" "$FAKE_RUNNING_KERNEL"',
    "apt-get": textwrap.dedent(
        """\
        [[ " $* " == *" update "* ]] || exit 64
        printf 'Hit:1 http://archive.example.invalid/ubuntu noble InRelease\\n'
        [[ -z "$FAKE_APT_STDERR" ]] || printf '%s\\n' "$FAKE_APT_STDERR" >&2
        exit "${FAKE_APT_RC:-0}"
        """
    ),
    # FAKE_PADDING дописывает длинную таблицу версий, как у настоящего
    # apt-cache policy: читатель, вышедший раньше конца, вызвал бы SIGPIPE.
    "apt-cache": textwrap.dedent(
        """\
        pad() {
            [[ -z "$FAKE_PADDING" ]] ||
                yes '     500 http://mirror.example.invalid/ubuntu noble/main amd64 Packages' |
                head -n "$FAKE_PADDING"
        }
        case "$1" in
            depends)
                [[ -n "$FAKE_LATEST_KERNEL" ]] || exit 0
                printf '%s\\n  Depends: linux-image-%s\\n' "$2" "$FAKE_LATEST_KERNEL"
                pad
                ;;
            policy)
                printf '%s:\\n  Installed: %s\\n  Candidate: %s\\n  Version table:\\n' "$2" "$FAKE_AWG_INSTALLED" "$FAKE_AWG_CANDIDATE"
                pad
                ;;
        esac
        """
    ),
    "dpkg-query": textwrap.dedent(
        """\
        # Вызов: dpkg-query -W -f=ФОРМАТ ПАКЕТ
        format="$2"; package="$3"
        case "$format" in
            *Status*)
                [[ "$package" == "linux-image-$FAKE_INSTALLED_KERNEL" ]] || exit 1
                printf 'ii '
                ;;
            *Version*)
                [[ -n "$FAKE_AWG_INSTALLED" ]] || exit 1
                printf '%s' "$FAKE_AWG_INSTALLED"
                ;;
        esac
        """
    ),
    "curl": '[[ -n "$FAKE_XRAY_LATEST" ]] || exit 6; printf \'{"tag_name": "%s"}\' "$FAKE_XRAY_LATEST"',
    "xray": 'printf "Xray %s (Xray, Penetrates Everything.)\\n" "$FAKE_XRAY_INSTALLED"',
}


def render(role: str, state_dir: Path, xray: Path, lock: Path) -> str:
    environment = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    text = environment.from_string(TEMPLATE.read_text(encoding="utf-8")).render(
        awg_node_role=role,
        kalimera_updates_state_dir=str(state_dir),
        kalimera_updates_apt_lock_path=str(lock),
        kalimera_updates_xray_releases_api="https://api.github.invalid/latest",
        front_xray_binary_path=str(xray),
    )
    # Тест идёт не от root; остальная логика скрипта не меняется.
    return text.replace("[[ $EUID -eq 0 ]] ||", "true ||", 1)


def run(role: str, *args: str, **environment: str) -> str:
    bash = shutil.which("bash")
    if (
        bash is None
        or shutil.which("dpkg") is None
        or shutil.which("jq") is None
        or shutil.which("flock") is None
    ):
        raise unittest.SkipTest("нужны bash, dpkg, jq и flock (Ubuntu)")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in FAKES.items():
            path = bin_dir / name
            path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
            path.chmod(0o755)
        script = root / "kalimera-updates"
        script.write_text(
            render(role, root / "state", bin_dir / "xray", root / "apt.lock"), encoding="utf-8"
        )
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "FAKE_RUNNING_KERNEL": "6.8.0-149-generic",
            "FAKE_LATEST_KERNEL": "6.8.0-149-generic",
            "FAKE_INSTALLED_KERNEL": "6.8.0-149-generic",
            "FAKE_AWG_INSTALLED": "1.0.20251101-1",
            "FAKE_AWG_CANDIDATE": "1.0.20251101-1",
            "FAKE_XRAY_INSTALLED": "26.10.31",
            "FAKE_XRAY_LATEST": "v26.10.31",
            "FAKE_APT_STDERR": "",
            "FAKE_PADDING": "",
            **environment,
        }
        # restore_signals по умолчанию: SIGPIPE у дочерних процессов штатный,
        # как в интерактивном SSH-сеансе.
        result = subprocess.run(
            [bash, str(script), *args], capture_output=True, text=True, env=env, check=True
        )
        state = (root / "state" / "state").read_text(encoding="utf-8")
        assert oct((root / "state" / "state").stat().st_mode & 0o777) == "0o600", "state not 0600"
        return result.stdout + "\n#STATE\n" + state


class KernelTests(unittest.TestCase):
    def test_current_kernel_is_ok(self) -> None:
        output = run("entry")
        self.assertIn("OK   ядро 6.8.0-149-generic актуально", output)
        self.assertNotIn("UPD", output.split("#STATE")[0])

    def test_new_kernel_available(self) -> None:
        output = run(
            "front",
            FAKE_RUNNING_KERNEL="6.8.0-134-generic",
            FAKE_INSTALLED_KERNEL="6.8.0-134-generic",
        )
        self.assertIn("UPD  доступно ядро 6.8.0-149-generic, работает 6.8.0-134-generic", output)
        self.assertIn("→ kalimera-updates install kernel", output)

    def test_installed_kernel_needs_reboot_with_guard_on_entry(self) -> None:
        output = run("entry", FAKE_RUNNING_KERNEL="6.8.0-134-generic")
        self.assertIn("UPD  ядро 6.8.0-149-generic установлено, работает 6.8.0-134-generic", output)
        self.assertIn("awg-kernel-guard && sudo reboot", output)

    def test_installed_kernel_needs_plain_reboot_on_front(self) -> None:
        output = run("front", FAKE_RUNNING_KERNEL="6.8.0-134-generic")
        self.assertIn("→ sudo reboot", output)
        self.assertNotIn("awg-kernel-guard", output)

    def test_unknown_metapackage_is_info(self) -> None:
        output = run("exit", FAKE_LATEST_KERNEL="")
        self.assertIn("INFO ядро 6.8.0-149-generic; новые версии не определены", output)


class AmneziaWGTests(unittest.TestCase):
    def test_new_package_points_to_update_amneziawg(self) -> None:
        output = run("exit", FAKE_AWG_CANDIDATE="1.0.20251201-1")
        self.assertIn("UPD  доступен AmneziaWG: amneziawg-dkms 1.0.20251101-1 → 1.0.20251201-1", output)
        self.assertIn("kalimera-deploy --resume --update-amneziawg", output)

    def test_current_package_is_ok(self) -> None:
        self.assertIn("OK   AmneziaWG 1.0.20251101-1 актуален", run("entry"))

    def test_front_does_not_check_amneziawg(self) -> None:
        self.assertNotIn("AmneziaWG", run("front"))


class XrayTests(unittest.TestCase):
    def test_new_release_points_to_update_xray(self) -> None:
        output = run("front", FAKE_XRAY_LATEST="v26.11.9")
        self.assertIn("UPD  доступен Xray 26.11.9, работает 26.10.31", output)
        self.assertIn("kalimera-deploy --resume --update-xray", output)

    def test_current_release_is_ok(self) -> None:
        self.assertIn("OK   Xray 26.10.31 актуален", run("front"))

    def test_github_unreachable_is_info_not_failure(self) -> None:
        output = run("front", FAKE_XRAY_LATEST="")
        self.assertIn("INFO Xray 26.10.31; новые версии не проверены", output)

    def test_entry_does_not_check_xray(self) -> None:
        self.assertNotIn("Xray", run("entry"))


class SummaryTests(unittest.TestCase):
    def test_counts_updates(self) -> None:
        output = run(
            "entry",
            FAKE_RUNNING_KERNEL="6.8.0-134-generic",
            FAKE_INSTALLED_KERNEL="6.8.0-134-generic",
            FAKE_AWG_CANDIDATE="1.0.20251201-1",
        )
        self.assertIn("Доступно обновлений: 2;", output)
        state = output.split("#STATE\n", 1)[1]
        self.assertEqual(sum(line.startswith("UPD\t") for line in state.splitlines()), 2)

    def test_terminal_shows_yellow_box_with_commands(self) -> None:
        output = run(
            "entry",
            KALIMERA_REPORT_STYLE="fancy",
            FAKE_AWG_CANDIDATE="1.0.20251201-1",
        ).split("#STATE")[0]
        self.assertIn("\x1b[36mUPD  доступен AmneziaWG", output)
        self.assertIn("\x1b[1;33m┌", output)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
        self.assertIn("WARN  kalimera-updates entry: доступно обновлений: 1", plain)
        self.assertIn("→ на ENTRY: kalimera-deploy --resume", plain)
        self.assertNotIn("Доступно обновлений: 1;", plain)

    def test_terminal_shows_green_box_when_current(self) -> None:
        output = run("exit", KALIMERA_REPORT_STYLE="fancy").split("#STATE")[0]
        self.assertIn("\x1b[32mOK   ядро", output)
        self.assertIn("\x1b[1;32m┌", output)
        self.assertIn("kalimera-updates exit: всё актуально", output)

    def test_unreachable_repository_makes_box_yellow(self) -> None:
        output = run(
            "entry",
            KALIMERA_REPORT_STYLE="fancy",
            FAKE_APT_STDERR="W: Failed to fetch http://mirror.example.invalid/ubuntu/dists/noble/InRelease",
        ).split("#STATE")[0]
        self.assertIn("\x1b[1;33m┌", output)
        self.assertIn("проверка неполная", output)


class CommandTests(unittest.TestCase):
    def test_long_apt_cache_output_does_not_fail_with_sigpipe(self) -> None:
        # На ENTRY и EXIT команда завершалась с кодом 141: awk выходил после
        # строки Candidate, а apt-cache policy ещё писал таблицу версий.
        output = run(
            "entry",
            FAKE_PADDING="200000",
            FAKE_AWG_CANDIDATE="1.0.20251201-1",
        )
        self.assertIn("UPD  доступен AmneziaWG", output)
        self.assertIn("OK   ядро 6.8.0-149-generic актуально", output)

    def test_check_is_alias_of_plain_command(self) -> None:
        self.assertIn("OK   AmneziaWG 1.0.20251101-1 актуален", run("exit", "check"))

    def test_unreachable_repository_is_info(self) -> None:
        output = run(
            "entry",
            FAKE_APT_STDERR=(
                "W: Failed to fetch http://pa2.clouds.archive.ubuntu.com/ubuntu/dists/noble/InRelease"
                "  Temporary failure resolving 'pa2.clouds.archive.ubuntu.com'\n"
                "W: Failed to fetch https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/noble/InRelease"
                "  connection timed out"
            ),
        )
        self.assertIn(
            "INFO не ответили репозитории: pa2.clouds.archive.ubuntu.com, "
            "ppa.launchpadcontent.net; результат может быть устаревшим",
            output,
        )
        self.assertIn("Доступно обновлений: 0;", output)

    def test_apt_update_failure_is_info_not_failure(self) -> None:
        output = run("front", FAKE_APT_STDERR="E: The repository is not signed.", FAKE_APT_RC="100")
        self.assertIn("INFO apt-get update завершился с ошибкой", output)


if __name__ == "__main__":
    unittest.main()

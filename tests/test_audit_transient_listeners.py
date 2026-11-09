"""server-audit не принимает короткоживущий исходящий сокет за слушателя.

Исходящий UDP-запрос на мгновение держит сокет на случайном порту, и
`ss -lntu` показывает его как UNCONN 0.0.0.0:порт. Аудит предупреждает только
о портах, которые видны в двух снимках подряд, и печатает их.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import jinja2

TEMPLATE = (
    Path(__file__).parents[1]
    / "roles"
    / "operations"
    / "templates"
    / "server-audit.sh.j2"
)
START = "# Внешние сокеты вне ожидаемого списка"
END = "systemd_config_last_value() {"

KNOWN = textwrap.dedent(
    """\
    udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:*
    udp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:*
    udp UNCONN 0 0 0.0.0.0:39745 0.0.0.0:*
    udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*
    tcp LISTEN 0 4096 0.0.0.0:56777 0.0.0.0:*
    tcp LISTEN 0 4096 *:443 *:*
    """
)


def listener_functions() -> str:
    text = TEMPLATE.read_text(encoding="utf-8")
    snippet = text[text.index(START) : text.index(END)]
    environment = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    return environment.from_string(snippet).render(
        awg_node_role="entry",
        front_backend_enabled=True,
        reality_fallback_port=443,
        ssh_listen_port=56777,
        ansible_port=56777,
        entry_awg0_listen_port=443,
        entry_mobile_client_listen_port=8443,
        entry_legacy_client_listen_port=39744,
        awg3_transit_listen_port=39745,
    )


def run_check(first: str, second: str) -> tuple[int, str]:
    bash = shutil.which("bash")
    if bash is None:
        raise unittest.SkipTest("bash недоступен")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "1").write_text(first, encoding="utf-8")
        (root / "2").write_text(second, encoding="utf-8")
        (root / "counter").write_text("0", encoding="utf-8")
        # ss вызывается внутри $(...), поэтому счётчик снимков хранится в файле.
        script = textwrap.dedent(
            f"""\
            set -Eeuo pipefail
            ss() {{
                local snapshot
                snapshot=$(( $(cat "{root.as_posix()}/counter") + 1 ))
                printf '%s' "$snapshot" >"{root.as_posix()}/counter"
                cat "{root.as_posix()}/$snapshot"
            }}
            """
        )
        script += listener_functions()
        script += textwrap.dedent(
            """\
            if known_public_listeners_only; then status=0; else status=1; fi
            printf 'status=%s\\n' "$status"
            printf 'ports=%s\\n' "$(paste -sd ' ' <<<"$unexpected_listeners")"
            """
        )
        script_path = root / "check.sh"
        script_path.write_text(script, encoding="utf-8", newline="\n")
        result = subprocess.run(
            [bash, script_path.as_posix()],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env={**os.environ, "SERVER_AUDIT_LISTENER_RECHECK_SECONDS": "0"},
            check=True,
        )
    lines = dict(line.split("=", 1) for line in result.stdout.splitlines())
    return int(lines["status"]), lines["ports"]


class TransientListenerTests(unittest.TestCase):
    def test_only_known_listeners_pass(self) -> None:
        self.assertEqual(run_check(KNOWN, KNOWN), (0, ""))

    def test_transient_udp_socket_is_ignored(self) -> None:
        transient = KNOWN + "udp UNCONN 0 0 0.0.0.0:53260 0.0.0.0:*\n"
        self.assertEqual(run_check(transient, KNOWN), (0, ""))

    def test_different_transient_ports_are_ignored(self) -> None:
        first = KNOWN + "udp UNCONN 0 0 0.0.0.0:53260 0.0.0.0:*\n"
        second = KNOWN + "udp UNCONN 0 0 0.0.0.0:41268 0.0.0.0:*\n"
        self.assertEqual(run_check(first, second), (0, ""))

    def test_persistent_unknown_listener_is_reported(self) -> None:
        persistent = (
            KNOWN
            + "tcp LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*\n"
            + "udp UNCONN 0 0 [::]:5353 [::]:*\n"
        )
        self.assertEqual(run_check(persistent, persistent), (1, "tcp/8080 udp/5353"))

    def test_private_addresses_are_not_checked(self) -> None:
        private = KNOWN + "tcp LISTEN 0 4096 10.0.0.5:9100 0.0.0.0:*\n"
        self.assertEqual(run_check(private, private), (0, ""))


if __name__ == "__main__":
    unittest.main()

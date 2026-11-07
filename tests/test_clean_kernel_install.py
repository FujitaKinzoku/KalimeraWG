"""Чистая установка на kernel-движке: юнита awg3-transit.service на серверах нет.

Существующие каскады этого не проявляют: файл юнита остался у них с периода
userspace-движка, а роль awg3_transit его только отключает. Поэтому проверять
такие шаблоны через --resume бесполезно, нужен рендер под чистый сервер.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

import jinja2


REPO = Path(__file__).parents[1]
INTEGRITY = REPO / "roles" / "operations" / "templates" / "awg-managed-integrity.sh.j2"
HEALTH = REPO / "roles" / "health" / "templates" / "awg-health.sh.j2"


def environment() -> jinja2.Environment:
    env = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
    env.filters["bool"] = lambda value: str(value).lower() in {"1", "true", "yes", "on"}
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    return env


def render_integrity(manifest: str, **overrides: object) -> str:
    context = {
        "awg_managed_integrity_manifest": manifest,
        "awg_node_role": "exit",
        "awg3_transit_enabled": False,
        "runtime_secrets_enabled": False,
    }
    context.update(overrides)
    return environment().from_string(INTEGRITY.read_text(encoding="utf-8")).render(context)


def render_credentials_check(**overrides: object) -> str:
    source = HEALTH.read_text(encoding="utf-8")
    match = re.search(
        r"runtime_secret_dependencies_are_loaded\(\) \{\n(.*?\{% endif %\}\n)\}\n",
        source,
        re.DOTALL,
    )
    assert match is not None
    context = {
        "awg_node_role": "entry",
        "awg3_transit_enabled": False,
        "front_backend_enabled": False,
        "runtime_secrets_service_name": "kalimera-secrets-unlock.service",
    }
    context.update(overrides)
    return environment().from_string(match.group(1)).render(context)


class CleanKernelInstallTests(unittest.TestCase):
    def test_transit_unit_is_not_managed_on_kernel_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rendered = render_integrity(str(Path(directory) / "manifest"))
        self.assertNotIn("awg3-transit.service", rendered)

    def test_missing_managed_file_does_not_set_loop_status(self) -> None:
        source = INTEGRITY.read_text(encoding="utf-8")
        self.assertNotIn('[[ -f "$path" ]] && printf', source)

    @unittest.skipIf(os.name == "nt", "seal запускается настоящим bash на Linux")
    def test_seal_succeeds_when_last_managed_file_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "state" / "manifest"
            script = Path(directory) / "integrity"
            script.write_text(render_integrity(str(manifest)), encoding="utf-8")
            result = subprocess.run(
                ["bash", str(script), "seal"],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_credentials_check_skips_transit_unit_on_kernel_engine(self) -> None:
        for overrides in (
            {"awg_node_role": "entry"},
            {"awg_node_role": "entry", "front_backend_enabled": True},
            {"awg_node_role": "exit"},
        ):
            with self.subTest(overrides=overrides):
                rendered = render_credentials_check(**overrides)
                self.assertNotIn("awg3-transit.service", rendered)
                self.assertNotIn("&&\n\n", rendered)
                self.assertFalse(rendered.rstrip().endswith("&&"))

    def test_credentials_check_keeps_transit_unit_on_userspace_engine(self) -> None:
        for overrides in (
            {"awg_node_role": "entry"},
            {"awg_node_role": "entry", "front_backend_enabled": True},
            {"awg_node_role": "exit"},
        ):
            with self.subTest(overrides=overrides):
                rendered = render_credentials_check(awg3_transit_enabled=True, **overrides)
                self.assertIn("awg3-transit.service", rendered)


if __name__ == "__main__":
    unittest.main()

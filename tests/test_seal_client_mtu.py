"""Согласованный MTU клиентских конфигов сохраняется в runtime-пакет.

На локальном ENTRY каталог клиентов управляющего компьютера лежит в tmpfs
runtime-секретов. MTU записывается в него после последнего seal в playbook,
поэтому deploy обязан сделать seal сам: иначе после перезагрузки ENTRY в
сохранённом конфиге снова окажется прежний MTU.
"""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "lib" / "interactive_deploy.py"
SPEC = importlib.util.spec_from_file_location("interactive_deploy_seal", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_production(root: Path, entry_vars: dict) -> Path:
    production = root / "production"
    (production / "group_vars" / "all").mkdir(parents=True)
    MODULE.yaml_write(production / "group_vars" / "entry.yml", entry_vars)
    MODULE.yaml_write(
        production / "group_vars" / "all" / "main.yml",
        {"runtime_secrets_ctl_path": "/usr/local/sbin/kalimera-secretctl"},
    )
    return production


class SealLocalControllerStateTests(unittest.TestCase):
    def test_local_controller_seals_runtime_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = write_production(
                Path(temporary),
                {
                    "runtime_secrets_controller_client_state_path": (
                        "/root/.local/share/awg-iac/production/clients"
                    )
                },
            )
            with mock.patch.object(MODULE.subprocess, "run") as run:
                MODULE.seal_local_controller_state(production)
        run.assert_called_once()
        self.assertEqual(
            run.call_args.args[0], ["/usr/local/sbin/kalimera-secretctl", "seal"]
        )
        self.assertTrue(run.call_args.kwargs.get("check"))

    def test_remote_controller_does_not_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = write_production(Path(temporary), {})
            with mock.patch.object(MODULE.subprocess, "run") as run:
                MODULE.seal_local_controller_state(production)
        run.assert_not_called()

    def test_missing_entry_vars_do_not_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary) / "production"
            (production / "group_vars" / "all").mkdir(parents=True)
            with mock.patch.object(MODULE.subprocess, "run") as run:
                MODULE.seal_local_controller_state(production)
        run.assert_not_called()

    def test_seal_failure_stops_deploy_with_instruction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = write_production(
                Path(temporary),
                {"runtime_secrets_controller_client_state_path": "/clients"},
            )
            error = subprocess.CalledProcessError(1, ["kalimera-secretctl", "seal"])
            with mock.patch.object(MODULE.subprocess, "run", side_effect=error):
                with self.assertRaises(SystemExit) as raised:
                    MODULE.seal_local_controller_state(production)
        self.assertIn("kalimera-secretctl seal", str(raised.exception))


class SealOrderTests(unittest.TestCase):
    """Seal идёт после каждой правки MTU и до завершения deploy."""

    def calls_in_main(self) -> list[str]:
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        main = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        calls = [
            node
            for node in ast.walk(main)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        calls.sort(key=lambda node: (node.lineno, node.col_offset))
        return [node.func.id for node in calls]

    def test_every_mtu_edit_is_followed_by_seal_before_cleanup(self) -> None:
        names = self.calls_in_main()
        edits = [
            index
            for index, name in enumerate(names)
            if name in ("update_client_config_mtu", "update_saved_client_configs_mtu")
        ]
        self.assertEqual(len(edits), 2, "ожидались правки MTU в resume и в установке")
        for index in edits:
            following = names[index + 1 :]
            self.assertIn("seal_local_controller_state", following)
            self.assertIn("cleanup_deployment", following)
            self.assertLess(
                following.index("seal_local_controller_state"),
                following.index("cleanup_deployment"),
            )
            self.assertNotIn(
                "update_client_config_mtu",
                following[: following.index("seal_local_controller_state")],
            )


if __name__ == "__main__":
    unittest.main()

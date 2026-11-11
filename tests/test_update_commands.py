"""Обновления компонентов: Xray-core с GitHub и пакеты AmneziaWG без смены клиентов."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "scripts" / "lib" / "interactive_deploy.py"
SPEC = importlib.util.spec_from_file_location("interactive_deploy_updates", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

AMD64 = "a" * 64
ARM64 = "b" * 64


def release(tag: str = "v26.11.9", *, digest: bool = True, prerelease: bool = False) -> dict:
    base = f"https://github.com/XTLS/Xray-core/releases/download/{tag}/"
    assets = []
    for name, checksum in (("Xray-linux-64.zip", AMD64), ("Xray-linux-arm64-v8a.zip", ARM64)):
        asset = {"name": name, "browser_download_url": base + name}
        if digest:
            asset["digest"] = f"sha256:{checksum}"
        assets.append(asset)
    assets.append({"name": "Xray-windows-64.zip", "browser_download_url": base + "Xray-windows-64.zip"})
    return {"tag_name": tag, "prerelease": prerelease, "draft": False, "assets": assets}


def fake_http(payload: dict, dgst: dict[str, str] | None = None):
    def get(url: str, *, accept: str = "") -> bytes:
        if url == MODULE.XRAY_RELEASES_API:
            return json.dumps(payload).encode()
        for name, checksum in (dgst or {}).items():
            if url.endswith(name + ".dgst"):
                return f"MD5= 0\nSHA2-256= {checksum}\n".encode()
        raise OSError(f"unexpected url {url}")

    return get


class LatestXrayReleaseTests(unittest.TestCase):
    def test_uses_github_digest(self) -> None:
        with mock.patch.object(MODULE, "_http_get", side_effect=fake_http(release())):
            result = MODULE.latest_xray_release()
        self.assertEqual(result["front_xray_version"], "v26.11.9")
        packages = result["front_xray_packages"]
        self.assertEqual(packages["x86_64"]["checksum"], f"sha256:{AMD64}")
        self.assertEqual(packages["aarch64"]["checksum"], f"sha256:{ARM64}")
        self.assertTrue(packages["x86_64"]["url"].endswith("/v26.11.9/Xray-linux-64.zip"))

    def test_falls_back_to_dgst_file(self) -> None:
        dgst = {"Xray-linux-64.zip": AMD64, "Xray-linux-arm64-v8a.zip": ARM64}
        with mock.patch.object(
            MODULE, "_http_get", side_effect=fake_http(release(digest=False), dgst)
        ):
            result = MODULE.latest_xray_release()
        self.assertEqual(result["front_xray_packages"]["aarch64"]["checksum"], f"sha256:{ARM64}")

    def test_rejects_prerelease(self) -> None:
        with mock.patch.object(
            MODULE, "_http_get", side_effect=fake_http(release(prerelease=True))
        ):
            with self.assertRaises(SystemExit):
                MODULE.latest_xray_release()

    def test_rejects_missing_checksum(self) -> None:
        with mock.patch.object(MODULE, "_http_get", side_effect=fake_http(release(digest=False))):
            with self.assertRaises(SystemExit):
                MODULE.latest_xray_release()

    def test_rejects_foreign_download_url(self) -> None:
        payload = release()
        payload["assets"][0]["browser_download_url"] = "https://example.invalid/Xray-linux-64.zip"
        with mock.patch.object(MODULE, "_http_get", side_effect=fake_http(payload)):
            with self.assertRaises(SystemExit):
                MODULE.latest_xray_release()


class XrayOverrideTests(unittest.TestCase):
    def production(self, root: Path, front_vars: dict) -> Path:
        production = root / "production"
        (production / "group_vars").mkdir(parents=True)
        MODULE.yaml_write(production / "group_vars" / "front.yml", front_vars)
        return production

    def test_override_dropped_when_release_catches_up(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = self.production(
                Path(temporary),
                {"front_origin_domain": "o.example", "front_xray_version": "v26.10.31",
                 "front_xray_packages": {"x86_64": {}}},
            )
            MODULE.drop_stale_xray_override(ROOT, production)
            front_vars = MODULE.load_yaml(production / "group_vars" / "front.yml")
        self.assertNotIn("front_xray_version", front_vars)
        self.assertNotIn("front_xray_packages", front_vars)
        self.assertEqual(front_vars["front_origin_domain"], "o.example")

    def test_newer_override_kept(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = self.production(
                Path(temporary),
                {"front_xray_version": "v99.1.1", "front_xray_packages": {"x86_64": {}}},
            )
            MODULE.drop_stale_xray_override(ROOT, production)
            front_vars = MODULE.load_yaml(production / "group_vars" / "front.yml")
        self.assertEqual(front_vars["front_xray_version"], "v99.1.1")

    def test_no_update_when_latest_is_not_newer(self) -> None:
        current = MODULE.default_xray_version(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            production = self.production(Path(temporary), {"front_origin_domain": "o.example"})
            with mock.patch.object(MODULE, "_http_get", side_effect=fake_http(release(current))):
                self.assertIsNone(MODULE.newer_xray_release(ROOT, production))

    def test_newer_release_applied_to_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = self.production(Path(temporary), {"front_origin_domain": "o.example"})
            with mock.patch.object(MODULE, "_http_get", side_effect=fake_http(release("v99.1.1"))):
                found = MODULE.newer_xray_release(ROOT, production)
            self.assertIsNotNone(found)
            self.assertEqual(found["previous_version"], MODULE.default_xray_version(ROOT))
            MODULE.apply_xray_release(production, found)
            front_vars = MODULE.load_yaml(production / "group_vars" / "front.yml")
        self.assertEqual(front_vars["front_xray_version"], "v99.1.1")
        self.assertEqual(front_vars["front_xray_packages"]["x86_64"]["checksum"], f"sha256:{AMD64}")
        self.assertNotIn("previous_version", front_vars)

    def test_missing_front_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary) / "production"
            (production / "group_vars").mkdir(parents=True)
            with self.assertRaises(SystemExit):
                MODULE.newer_xray_release(ROOT, production)


class AmneziaWGPackageUpdateTests(unittest.TestCase):
    def test_only_packages_are_unpinned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            production = Path(temporary) / "production"
            (production / "group_vars" / "all").mkdir(parents=True)
            all_path = production / "group_vars" / "all" / "main.yml"
            entry_path = production / "group_vars" / "entry.yml"
            MODULE.yaml_write(all_path, {
                "awg_package_version_mode": "pinned",
                "awg_package_versions": {"amneziawg": "1"},
                "security_admin_user": "kalimera",
            })
            entry_before = {"entry_awg0_obfuscation": {"jc": 5}, "entry_sing_box_version": "1.13.19"}
            MODULE.yaml_write(entry_path, entry_before)
            MODULE.prepare_amneziawg_update(production)
            all_vars = MODULE.load_yaml(all_path)
            entry_after = MODULE.load_yaml(entry_path)
        self.assertEqual(all_vars["awg_package_version_mode"], "candidate")
        self.assertNotIn("awg_package_versions", all_vars)
        self.assertEqual(all_vars["security_admin_user"], "kalimera")
        # Профили клиентов не перевыпускаются: старые конфиги продолжают работать.
        self.assertEqual(entry_after, entry_before)


class UpdateArgumentTests(unittest.TestCase):
    def run_main(self, *arguments: str) -> int:
        argv = ["deploy", "--repo-root", str(ROOT), *arguments]
        with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit) as raised:
            MODULE.main()
        return raised.exception.code

    def test_update_requires_resume(self) -> None:
        self.assertEqual(self.run_main("--update-xray"), 2)
        self.assertEqual(self.run_main("--update-amneziawg"), 2)

    def test_only_one_update_per_run(self) -> None:
        self.assertEqual(self.run_main("--resume", "--update-xray", "--update-amneziawg"), 2)
        self.assertEqual(self.run_main("--resume", "--update-components", "--update-xray"), 2)

    def test_update_cannot_be_combined_with_front_operation(self) -> None:
        self.assertEqual(self.run_main("--resume", "--update-xray", "--replace-front"), 2)


class AllowlistTests(unittest.TestCase):
    def test_admin_wrapper_allows_update_commands(self) -> None:
        wrapper = (ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2").read_text(
            encoding="utf-8"
        )
        self.assertIn("'--resume --update-amneziawg'", wrapper)
        self.assertIn("'--resume --update-xray'", wrapper)
        self.assertIn("|kalimera-updates)", wrapper)

    def test_shell_tool_and_integrity_cover_updates_command(self) -> None:
        tools = (ROOT / "roles" / "terminal" / "templates" / "kalimera-shell-tools.sh.j2").read_text(
            encoding="utf-8"
        )
        integrity = (
            ROOT / "roles" / "operations" / "templates" / "awg-managed-integrity.sh.j2"
        ).read_text(encoding="utf-8")
        self.assertIn("function kalimera-updates", tools)
        self.assertIn("kalimera_updates_path", integrity)
        self.assertIn("/etc/systemd/system/kalimera-updates.timer", integrity)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Описание runtime-хранилища должно доносить права доступа до secretctl.

apply_runtime_access() раздаёт группе sing-box узкий доступ внутрь tmpfs по
полям access_group/traverse_paths/read_paths. Цикл вывода в шаблоне когда-то
печатал только source и target, из-за чего эти три ключа молча терялись, права
не раздавались, и kalimera-front-backend после каждой перезагрузки падал на
чтении ru-domains.json. Баг повторялся на четырёх каскадах.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jinja2
import yaml


REPO = Path(__file__).parents[1]
TEMPLATE = REPO / "roles" / "runtime_secrets" / "templates" / "config.json.j2"

BASE_CONTEXT = {
    "runtime_secrets_cluster_id": "cluster",
    "runtime_secrets_threshold": 2,
    "runtime_secrets_total_shares": 5,
    "vault_runtime_secret_key_sha256": "0" * 64,
    "runtime_secrets_runtime_root": "/run/kalimera-secrets",
    "runtime_secrets_bundle_path": "/etc/kalimera-secrets/bundle",
    "runtime_secrets_local_share_path": "/etc/kalimera-secrets/local.share",
    "runtime_secrets_exchange_identity_path": "/etc/kalimera-secrets/share-exchange",
    "runtime_secrets_known_hosts_path": "/etc/kalimera-secrets/known_hosts",
    "runtime_secrets_peer_timeout_seconds": 180,
    "runtime_secrets_peer_inventory_hosts": [],
    "runtime_secrets_ssh_user": "kalimera",
    "hostvars": {},
    "runtime_secrets_controller_vault_password_path": "",
    "runtime_secrets_controller_ssh_private_key_path": "",
}


def render(**overrides: object) -> dict:
    """Отрендерить шаблон окружением, повторяющим Ansible по trim_blocks."""
    environment = jinja2.Environment(trim_blocks=True, autoescape=False)
    environment.filters["bool"] = lambda value: str(value).strip().lower() in {
        "true",
        "yes",
        "on",
        "1",
    }
    environment.filters["to_json"] = lambda value, **_: json.dumps(value)
    context = dict(BASE_CONTEXT)
    context.update(overrides)
    rendered = environment.from_string(
        TEMPLATE.read_text(encoding="utf-8")
    ).render(**context)
    return json.loads(rendered)


def sing_box_mapping(document: dict) -> dict:
    return next(m for m in document["mappings"] if m.get("target") == "sing-box")


class RuntimeSecretsConfigTests(unittest.TestCase):
    def test_front_backend_mapping_carries_access_fields(self) -> None:
        mapping = sing_box_mapping(render(front_backend_enabled=True))
        self.assertEqual(mapping["access_group"], "sing-box")
        self.assertEqual(mapping["traverse_paths"], [".", "reality"])
        self.assertEqual(mapping["read_paths"], ["reality/rules"])

    def test_access_fields_are_absent_without_front_backend(self) -> None:
        mapping = sing_box_mapping(render(front_backend_enabled=False))
        self.assertNotIn("access_group", mapping)
        self.assertNotIn("traverse_paths", mapping)
        self.assertNotIn("read_paths", mapping)

    def test_rendered_document_is_valid_json_in_both_modes(self) -> None:
        for flag in (True, False):
            with self.subTest(front_backend_enabled=flag):
                document = render(front_backend_enabled=flag)
                self.assertEqual(document["version"], 1)
                targets = [m["target"] for m in document["mappings"]]
                self.assertIn("sing-box", targets)
                self.assertEqual(len(targets), len(set(targets)))

    def test_emitter_does_not_enumerate_mapping_fields_by_name(self) -> None:
        # Именно перечисление по именам и теряло права; маппинг должен
        # выводиться целиком.
        body = TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("{{ mapping | to_json }}", body)
        self.assertNotIn('{"source": {{ mapping.source', body)


class ListPersistenceTests(unittest.TestCase):
    """Списки доменов, адресов и портов лежат в tmpfs и требуют seal.

    При загрузке сервера tmpfs собирается из зашифрованного пакета. Команды
    ru-domain, se-domain, entry-domain, proxy-domain, proxy-address и
    ru-direct-ports пакет не обновляли: изменение действовало до перезагрузки
    ENTRY и молча пропадало. Поведение команд проверяют test_selective_proxy и
    test_command_messages; здесь связь между путями списков и хранилищем.
    """

    def defaults(self, role: str) -> dict:
        return yaml.safe_load(
            (REPO / "roles" / role / "defaults" / "main.yml").read_text(encoding="utf-8")
        )

    def test_list_files_live_inside_the_runtime_store(self) -> None:
        sources = [mapping["source"] for mapping in render(front_backend_enabled=True)["mappings"]]
        self.assertIn("/etc/awg", sources)
        policy_dir = self.defaults("operations")["awg_domain_policy_dir"]
        ports_file = self.defaults("entry_routing")["entry_ru_direct_tcp_ports_file"]
        self.assertTrue(policy_dir.startswith("/etc/awg/"), policy_dir)
        self.assertTrue(ports_file.startswith("/etc/awg/"), ports_file)
        self.assertIn("awg_domain_policy_dir", self.defaults("entry_routing")["entry_ru_proxy_address_file"])

    def test_every_list_command_saves_its_change(self) -> None:
        templates = REPO / "roles" / "operations" / "templates"
        for name in ("domain-admin.sh.j2", "proxy-address.sh.j2", "ru-direct-ports.sh.j2"):
            with self.subTest(command=name):
                body = (templates / name).read_text(encoding="utf-8")
                self.assertIn("persist_lists() {", body)
                self.assertIn(" seal >/dev/null", body)
                self.assertIn("/run/kalimera-lists.seal-pending", body)
                self.assertIn("sudo kalimera-secretctl seal", body)

    def test_any_successful_seal_clears_the_pending_mark(self) -> None:
        body = (REPO / "roles/runtime_secrets/templates/secretctl.py.j2").read_text(encoding="utf-8")
        branch = body[body.index('elif args.action == "seal":'):body.index('elif args.action == "link":')]
        self.assertIn('"kalimera-lists.seal-pending").unlink(missing_ok=True)', branch)

    def test_recovery_share_number_starts_at_one(self) -> None:
        # Ноль Python принял бы как отсчёт с конца и сохранил бы другую долю.
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "share.txt"
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO / "scripts" / "export-runtime-recovery-share.py"),
                    "--repo-root", str(REPO),
                    "--vault-password-file", str(Path(temporary) / "absent.pass"),
                    "--output", str(output),
                    "--share-index", "0",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Номер доли начинается с 1", result.stderr)
            self.assertFalse(output.exists())


class MtuProbeTests(unittest.TestCase):
    def test_one_lost_packet_does_not_lower_the_cascade_mtu(self) -> None:
        # Раньше каждый размер проверялся одним пакетом: единственная потеря во время
        # deploy занижала MTU межсерверного канала и клиентов до следующего запуска.
        site = (REPO / "playbooks" / "site.yml").read_text(encoding="utf-8")
        probe = site[site.index("Определение максимального двустороннего IPv4 PMTU"):]
        probe = probe[:probe.index("register: awg_mtu_outer_probe")]
        self.assertIn('ping -4 -c 3 -i 0.2 -W 1 -M do -s "$1" "$peer"', probe)
        self.assertNotIn("ping -4 -c 1 ", probe)
        self.assertEqual(probe.count('fits "$'), 2)


if __name__ == "__main__":
    unittest.main()

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
import unittest
from pathlib import Path

import jinja2


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


if __name__ == "__main__":
    unittest.main()

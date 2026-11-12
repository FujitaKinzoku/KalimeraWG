"""Профиль VLESS с резервным каскадом: vless-user auto.

Два независимых каскада: основной - CDN этого FRONT (прямой путь только у
FRONT без CDN), резервный - экспорт другого каскада. Поведение балансировщика выбрано по исходникам Xray-core
(app/router/strategy_leastload.go, app/observatory/burst): резерв внутри
балансировщика с огромной ценой, fallbackTag - основной путь, исключение
узла по доле провалов. Здесь проверяется, что профиль собирается именно так
и что неподходящий резерв отклоняется до записи файла.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

# Менеджер импортирует fcntl и pwd; для сборки профиля они не нужны.
sys.modules.setdefault("fcntl", types.ModuleType("fcntl"))
sys.modules.setdefault("pwd", types.ModuleType("pwd"))

sys.path.insert(0, str(Path(__file__).parent))
import test_front_xhttp_uplink as uplink  # noqa: E402


def manager() -> dict:
    rendered = uplink.render(uplink.MANAGER_TEMPLATE, uplink.context())
    namespace: dict = {"__name__": "vless_user_auto_under_test"}
    exec(compile(rendered, "vless-user", "exec"), namespace)
    return namespace


RECORD = {"name": "phone", "id": str(uuid.UUID(int=3)), "mode": "cdn"}


class AutoProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ns = manager()
        self.settings = uplink.client_settings()
        reserve_settings = uplink.client_settings(
            front_direct_domain="origin2.example.invalid",
            front_cdn_domain="edge2.example.invalid",
            front_xhttp_disguise_session_cookie="JSESSIONID",
            front_xhttp_disguise_session_table="HEX",
        )
        self.reserve_export = self.ns["client_config"](
            {"name": "phone", "id": str(uuid.UUID(int=4)), "mode": "cdn"}, reserve_settings
        )

    def load(self, payload: object, settings: dict | None = None) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reserve.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return self.ns["load_reserve_outbound"](str(path), settings or self.settings)

    def rejected(self, payload: object, settings: dict | None = None) -> str:
        with contextlib.redirect_stderr(io.StringIO()) as message:
            with self.assertRaises(SystemExit) as raised:
                self.load(payload, settings)
        self.assertEqual(raised.exception.code, 2)
        return message.getvalue()

    def test_two_cascades_through_cdn_without_direct_path(self) -> None:
        # На FRONT включены оба режима, но в профиль попадает только CDN:
        # оба каскада работают через CDN, прямой путь не нужен.
        profile = self.ns["auto_config"](RECORD, self.settings, self.load(self.reserve_export))
        tags = [item["tag"] for item in profile["outbounds"]]
        self.assertEqual(tags, ["kalimera-main", "kalimera-reserve", "direct", "block"])
        addresses = [item["settings"]["vnext"][0]["address"] for item in profile["outbounds"][:2]]
        self.assertEqual(addresses, ["edge.example.invalid", "edge2.example.invalid"])
        self.assertEqual(profile["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"], RECORD["id"])
        self.assertEqual(profile["outbounds"][1]["settings"]["vnext"][0]["users"][0]["id"], str(uuid.UUID(int=4)))

    def test_balancer_prefers_main_cascade(self) -> None:
        profile = self.ns["auto_config"](RECORD, self.settings, self.load(self.reserve_export))
        balancer = profile["routing"]["balancers"][0]
        self.assertEqual(balancer["selector"], ["kalimera-main", "kalimera-reserve"])
        # Без результатов наблюдателя (сразу после запуска) - основной путь,
        # а не резервный каскад с другим IP.
        self.assertEqual(balancer["fallbackTag"], "kalimera-main")
        strategy = balancer["strategy"]
        self.assertEqual(strategy["type"], "leastLoad")
        settings = strategy["settings"]
        self.assertEqual(settings["expected"], 1)
        self.assertEqual(settings["tolerance"], 0.5)
        # Медленный ответ не повод уходить на другой IP: только провалы.
        self.assertNotIn("maxRTT", settings)
        costs = {item["match"]: item["value"] for item in settings["costs"]}
        # Xray умножает разброс RTT на корень из цены: резерв в 10 000 раз
        # дороже основного (у основного цена 1).
        self.assertEqual(costs, {"kalimera-reserve": 100000000})
        self.assertFalse(any(item["regexp"] for item in settings["costs"]))

    def test_observatory_needs_majority_of_failures(self) -> None:
        profile = self.ns["auto_config"](RECORD, self.settings, self.load(self.reserve_export))
        observatory = profile["burstObservatory"]
        self.assertEqual(observatory["subjectSelector"], ["kalimera-main", "kalimera-reserve"])
        ping = observatory["pingConfig"]
        self.assertEqual((ping["interval"], ping["sampling"], ping["timeout"]), ("10s", 4, "5s"))
        # Проверка сети напрямую: при полном отсутствии сети провал не
        # засчитывается, и после метро основной путь не исключён.
        self.assertEqual(ping["connectivity"], "https://ya.ru/")
        rules = profile["routing"]["rules"]
        self.assertEqual(rules[0], {"domain": ["full:ya.ru"], "outboundTag": "direct", "type": "field"})
        self.assertEqual(rules[-1]["balancerTag"], "kalimera-auto")
        self.assertEqual(rules[-1]["network"], "tcp,udp")

    def test_front_without_cdn_uses_direct_path(self) -> None:
        direct_only = uplink.client_settings(front_access_modes=["direct"])
        reserve = self.load(self.reserve_export, direct_only)
        profile = self.ns["auto_config"](RECORD, direct_only, reserve)
        self.assertEqual([item["tag"] for item in profile["outbounds"][:2]], ["kalimera-main", "kalimera-reserve"])
        self.assertEqual(profile["outbounds"][0]["settings"]["vnext"][0]["address"], "origin.example.invalid")

    def test_reserve_from_same_front_is_rejected(self) -> None:
        own = self.ns["client_config"](RECORD, self.settings)
        self.assertIn("Резерв должен быть другим каскадом", self.rejected(own))

    def test_profile_with_reserve_is_not_accepted_as_reserve(self) -> None:
        nested = self.ns["auto_config"](RECORD, self.settings, self.load(self.reserve_export))
        other_settings = uplink.client_settings(
            front_direct_domain="origin3.example.invalid", front_cdn_domain="edge3.example.invalid"
        )
        self.assertIn("outbound 'proxy'", self.rejected(nested, other_settings))

    def test_non_json_and_broken_reserve_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reserve.json"
            path.write_text("vless://not-json", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()) as message, self.assertRaises(SystemExit):
                self.ns["load_reserve_outbound"](str(path), self.settings)
        self.assertIn("не JSON", message.getvalue())
        broken = json.loads(json.dumps(self.reserve_export))
        del broken["outbounds"][0]["settings"]["vnext"][0]["users"]
        self.assertIn("повреждён", self.rejected(broken))

    def test_stale_get_body_reserve_is_rejected(self) -> None:
        stale = json.loads(json.dumps(self.reserve_export))
        xhttp = stale["outbounds"][0]["streamSettings"]["xhttpSettings"]
        for level in (xhttp, xhttp["extra"]):
            level["uplinkDataPlacement"] = "body"
        self.assertIn("устарел", self.rejected(stale))

    def test_reserve_mangled_into_markdown_link_is_rejected(self) -> None:
        # Так выглядел реальный резерв после копирования через заметки:
        # Xray профиль принимал, но резерв не отвечал и переключения не было.
        link = "[edge2.example.invalid](https://edge2.example.invalid)"
        for field in ("address", "serverName", "host"):
            mangled = json.loads(json.dumps(self.reserve_export))
            stream = mangled["outbounds"][0]["streamSettings"]
            if field == "address":
                mangled["outbounds"][0]["settings"]["vnext"][0]["address"] = link
            elif field == "serverName":
                stream["tlsSettings"]["serverName"] = link
            else:
                stream["xhttpSettings"]["host"] = link
            with self.subTest(field=field):
                self.assertIn("испорчен при копировании", self.rejected(mangled))

    def test_reserve_can_be_read_from_stdin(self) -> None:
        payload = json.dumps(self.reserve_export).encode("utf-8")
        fake_stdin = types.SimpleNamespace(buffer=io.BytesIO(payload))
        with mock.patch.object(sys, "stdin", fake_stdin):
            reserve = self.ns["load_reserve_outbound"]("-", self.settings)
        self.assertEqual(reserve["tag"], "kalimera-reserve")

    def test_single_profile_is_unchanged(self) -> None:
        exported = self.ns["client_config"](RECORD, self.settings)
        self.assertEqual([item["tag"] for item in exported["outbounds"]], ["proxy", "direct", "block"])
        self.assertEqual(exported["routing"]["rules"], [{"network": "tcp,udp", "outboundTag": "proxy", "type": "field"}])
        self.assertNotIn("burstObservatory", exported)
        self.assertEqual(exported["remarks"], "Kalimera-FRONT-disguiseV3")


if __name__ == "__main__":
    unittest.main()

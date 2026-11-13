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
            return self.ns["load_reserve_outbound"](str(path), settings or self.settings, "kalimera-reserve-1")

    def rejected(self, payload: object, settings: dict | None = None) -> str:
        with contextlib.redirect_stderr(io.StringIO()) as message:
            with self.assertRaises(SystemExit) as raised:
                self.load(payload, settings)
        self.assertEqual(raised.exception.code, 2)
        return message.getvalue()

    def test_two_cascades_through_cdn_without_direct_path(self) -> None:
        # На FRONT включены оба режима, но в профиль попадает только CDN:
        # оба каскада работают через CDN, прямой путь не нужен.
        profile = self.ns["auto_config"](RECORD, self.settings, [self.load(self.reserve_export)])
        tags = [item["tag"] for item in profile["outbounds"]]
        self.assertEqual(tags, ["kalimera-main", "kalimera-reserve-1", "direct", "block"])
        addresses = [item["settings"]["vnext"][0]["address"] for item in profile["outbounds"][:2]]
        self.assertEqual(addresses, ["edge.example.invalid", "edge2.example.invalid"])
        self.assertEqual(profile["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"], RECORD["id"])
        self.assertEqual(profile["outbounds"][1]["settings"]["vnext"][0]["users"][0]["id"], str(uuid.UUID(int=4)))

    def test_balancer_prefers_main_cascade(self) -> None:
        profile = self.ns["auto_config"](RECORD, self.settings, [self.load(self.reserve_export)])
        balancer = profile["routing"]["balancers"][0]
        self.assertEqual(balancer["selector"], ["kalimera-main", "kalimera-reserve-1"])
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
        self.assertEqual(costs, {"^kalimera-reserve-1$": 100000000})
        # Якоря: совпадение по подстроке отдало бы reserve-1 цену reserve-10.
        self.assertTrue(all(item["regexp"] for item in settings["costs"]))

    def test_observatory_needs_majority_of_failures(self) -> None:
        profile = self.ns["auto_config"](RECORD, self.settings, [self.load(self.reserve_export)])
        observatory = profile["burstObservatory"]
        self.assertEqual(observatory["subjectSelector"], ["kalimera-main", "kalimera-reserve-1"])
        ping = observatory["pingConfig"]
        self.assertEqual((ping["interval"], ping["sampling"], ping["timeout"]), ("10s", 4, "5s"))
        # Без проверки сети напрямую: на телефоне её DNS идёт через упавший
        # основной каскад, провалы не записывались, и резерв не включался.
        self.assertNotIn("connectivity", ping)
        rules = profile["routing"]["rules"]
        self.assertEqual(rules, [{"network": "tcp,udp", "balancerTag": "kalimera-auto", "type": "field"}])

    def test_cascade_names_resolved_by_xray_outside_tunnel(self) -> None:
        # Системный DNS телефона идёт в туннель, то есть через основной
        # каскад: при его отказе имя резерва не разрешалось, и проверки
        # резерва проваливались. Xray разрешает имена сам по TCP напрямую.
        profile = self.ns["auto_config"](RECORD, self.settings, [self.load(self.reserve_export)])
        for outbound in profile["outbounds"][:2]:
            self.assertEqual(outbound["streamSettings"]["sockopt"], {"domainStrategy": "UseIPv4"})
        servers = profile["dns"]["servers"]
        self.assertTrue(servers)
        self.assertTrue(all(server.startswith("tcp+local://") for server in servers))
        # Обычный профиль и выгрузка резерва не меняются.
        single = self.ns["client_config"](RECORD, self.settings)
        self.assertNotIn("sockopt", single["outbounds"][0]["streamSettings"])
        self.assertFalse(any("://" in server for server in single["dns"]["servers"]))
        self.assertNotIn("sockopt", self.reserve_export["outbounds"][0]["streamSettings"])

    def test_front_without_cdn_uses_direct_path(self) -> None:
        direct_only = uplink.client_settings(front_access_modes=["direct"])
        reserve = self.load(self.reserve_export, direct_only)
        profile = self.ns["auto_config"](RECORD, direct_only, [reserve])
        self.assertEqual([item["tag"] for item in profile["outbounds"][:2]], ["kalimera-main", "kalimera-reserve-1"])
        self.assertEqual(profile["outbounds"][0]["settings"]["vnext"][0]["address"], "origin.example.invalid")

    def test_reserve_from_same_front_is_rejected(self) -> None:
        own = self.ns["client_config"](RECORD, self.settings)
        self.assertIn("Резерв должен быть другим каскадом", self.rejected(own))

    def test_profile_with_reserve_is_not_accepted_as_reserve(self) -> None:
        nested = self.ns["auto_config"](RECORD, self.settings, [self.load(self.reserve_export)])
        other_settings = uplink.client_settings(
            front_direct_domain="origin3.example.invalid", front_cdn_domain="edge3.example.invalid"
        )
        self.assertIn("outbound 'proxy'", self.rejected(nested, other_settings))

    def test_non_json_and_broken_reserve_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "reserve.json"
            path.write_text("vless://not-json", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()) as message, self.assertRaises(SystemExit):
                self.ns["load_reserve_outbound"](str(path), self.settings, "kalimera-reserve-1")
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
            reserve = self.ns["load_reserve_outbound"]("-", self.settings, "kalimera-reserve-1")
        self.assertEqual(reserve["tag"], "kalimera-reserve-1")

    def reserve_files(self, count: int, temporary: str) -> list:
        paths = []
        for position in range(1, count + 1):
            settings = uplink.client_settings(
                front_direct_domain=f"origin-r{position}.example.invalid",
                front_cdn_domain=f"edge-r{position}.example.invalid",
            )
            export = self.ns["client_config"](
                {"name": "phone", "id": str(uuid.UUID(int=10 + position)), "mode": "cdn"}, settings
            )
            path = Path(temporary) / f"r{position}.json"
            path.write_text(json.dumps(export), encoding="utf-8")
            paths.append(str(path))
        return paths

    def test_several_reserves_keep_their_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            reserves = self.ns["load_reserves"](self.reserve_files(3, temporary), self.settings)
        profile = self.ns["auto_config"](RECORD, self.settings, reserves)
        tags = ["kalimera-main", "kalimera-reserve-1", "kalimera-reserve-2", "kalimera-reserve-3"]
        self.assertEqual([item["tag"] for item in profile["outbounds"][:4]], tags)
        self.assertEqual(
            [item["settings"]["vnext"][0]["address"] for item in profile["outbounds"][1:4]],
            ["edge-r1.example.invalid", "edge-r2.example.invalid", "edge-r3.example.invalid"],
        )
        self.assertEqual(profile["burstObservatory"]["subjectSelector"], tags)
        balancer = profile["routing"]["balancers"][0]
        self.assertEqual(balancer["selector"], tags)
        self.assertEqual(balancer["fallbackTag"], "kalimera-main")
        costs = balancer["strategy"]["settings"]["costs"]
        self.assertEqual([item["match"] for item in costs], [f"^{tag}$" for tag in tags[1:]])
        values = [item["value"] for item in costs]
        self.assertEqual(values[0], 100000000)
        self.assertEqual(values, sorted(values))
        for item in profile["outbounds"][:4]:
            self.assertEqual(item["streamSettings"]["sockopt"], {"domainStrategy": "UseIPv4"})

    def test_cost_multipliers_never_overflow_xray_duration(self) -> None:
        # Разброс живого пути до 2,5 с; Xray умножает его на корень из цены и
        # переводит в int64 наносекунд. Переполнение поставило бы резерв
        # впереди основного каскада.
        for count in range(1, 6):
            values = [item["value"] for item in self.ns["reserve_costs"](count)]
            factors = [value ** 0.5 for value in values]
            self.assertAlmostEqual(factors[0], 10000)
            self.assertLess(max(factors) * 2.5e9, 2 ** 63 - 1)
            for left, right in zip(factors, factors[1:]):
                self.assertGreaterEqual(right / left, 20)

    def test_reserve_list_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            files = self.reserve_files(6, temporary)
            with contextlib.redirect_stderr(io.StringIO()) as message, self.assertRaises(SystemExit):
                self.ns["load_reserves"](files, self.settings)
            self.assertIn("не больше 5", message.getvalue())
            with contextlib.redirect_stderr(io.StringIO()) as message, self.assertRaises(SystemExit):
                self.ns["load_reserves"]([files[0], files[0]], self.settings)
            self.assertIn("дважды", message.getvalue())
        with contextlib.redirect_stderr(io.StringIO()) as message, self.assertRaises(SystemExit):
            self.ns["load_reserves"](["-", "-"], self.settings)
        self.assertIn("stdin", message.getvalue())

    def test_single_profile_is_unchanged(self) -> None:
        exported = self.ns["client_config"](RECORD, self.settings)
        self.assertEqual([item["tag"] for item in exported["outbounds"]], ["proxy", "direct", "block"])
        self.assertEqual(exported["routing"]["rules"], [{"network": "tcp,udp", "outboundTag": "proxy", "type": "field"}])
        self.assertNotIn("burstObservatory", exported)
        self.assertEqual(exported["remarks"], "Kalimera-FRONT-disguiseV3")


if __name__ == "__main__":
    unittest.main()

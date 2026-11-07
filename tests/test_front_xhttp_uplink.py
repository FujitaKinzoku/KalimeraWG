#!/usr/bin/env python3
"""Аплинк XHTTP через CDN обязан уходить GET-запросом без тела.

Yandex Cloud CDN отвечает 413 на любой GET, HEAD или OPTIONS с телом (выпуск
документации от 30.09.2026), а POST у него по умолчанию выключен. Профиль
FRONT клал аплинк packet-up в тело GET-запроса (uplinkDataPlacement: body), и
CDN-доступ пропал целиком, хотя напрямую цепочка работала. Тесты рендерят
настоящие шаблоны сервера и клиента и проверяют действующие поля так, как их
читает Xray-core v26.7.28: при наличии extra конфигурация целиком заменяется
им, снаружи остаются только host, path и mode
(infra/conf/transport_method.go, SplitHTTPConfig.Build).
"""
from __future__ import annotations

import base64
import contextlib
import io
import itertools
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

import jinja2
import yaml


REPO = Path(__file__).resolve().parents[1]
FRONT = REPO / "roles" / "front"
SERVER_TEMPLATE = FRONT / "templates" / "xray-config.json.j2"
CLIENT_TEMPLATE = FRONT / "templates" / "vless-client-settings.json.j2"
MANAGER_TEMPLATE = FRONT / "templates" / "vless-user.py.j2"
NGINX_TEMPLATE = FRONT / "templates" / "nginx-front.conf.j2"
HEALTH_TEMPLATE = REPO / "roles" / "health" / "templates" / "awg-health.sh.j2"

MODES = ("packet-up", "stream-up", "stream-one", "auto")
# transport/internet/splithttp/config.go, PredefinedTable (Xray-core v26.7.28).
# Имя вне этого списка Xray молча берёт как сам алфавит: "Base36" давал id
# сессии только из символов B, a, s, e, 3 и 6.
PREDEFINED_SESSION_ID_TABLES = {
    "ALPHABET",
    "Alphabet",
    "BASE36",
    "Base62",
    "HEX",
    "alphabet",
    "base36",
    "hex",
    "number",
}
# Одиночный заголовок такого размера прошёл Yandex Cloud CDN живой пробой.
CDN_VERIFIED_HEADER_BYTES = 6000
# nginx: large_client_header_buffers 4 8k по умолчанию - предел одного поля
# и для HTTP/1.1, и для HTTP/2.
NGINX_FIELD_LIMIT = 8 * 1024
# Запас на остальные заголовки запроса (браузерные, CDN, nginx, cookie).
OTHER_HEADERS_BUDGET = 4096
# Заголовки с подчёркиванием nginx по умолчанию молча выбрасывает.
HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
# Заголовки, которые Xray-core v26.7.28 без явного User-Agent добавляет к
# каждому пакету (common/utils/browser.go, applyMasqueradedHeaders для
# chrome/fetch) плюс Accept-Encoding, который ставит HTTP/2-транспорт Go
# (golang.org/x/net/http2). Проба health обязана нести их же, иначе она
# меньше настоящего пакета.
XRAY_FETCH_HEADERS = {
    "Sec-CH-UA",
    "Sec-CH-UA-Mobile",
    "Sec-CH-UA-Platform",
    "DNT",
    "User-Agent",
    "Accept-Language",
    "Sec-Fetch-Mode",
    "Sec-Fetch-Dest",
    "Sec-Fetch-Site",
    "Priority",
    "Cache-Control",
    "Pragma",
    "Accept",
    "Accept-Encoding",
}
# Запас нагрузки пробы health сверх наибольшего пакета клиента, байт.
PROBE_EXTRA_BYTES = 48
# Встроенный предел пакета на сервере Xray (GetNormalizedScMaxEachPostBytes).
XRAY_DEFAULT_MAX_EACH_POST_BYTES = 1_000_000


def load_defaults() -> dict:
    return yaml.safe_load((FRONT / "defaults" / "main.yml").read_text(encoding="utf-8"))


def environment() -> jinja2.Environment:
    """Окружение, повторяющее Ansible по trim_blocks; неизвестные переменные - ошибка."""
    env = jinja2.Environment(
        trim_blocks=True,
        autoescape=False,
        undefined=jinja2.StrictUndefined,
    )
    env.filters["bool"] = lambda value: str(value).strip().lower() in {
        "true",
        "yes",
        "on",
        "1",
    }
    env.filters["to_json"] = lambda value, **_: json.dumps(value)
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    return env


def context(mode: str = "packet-up", disguise: bool = True, **overrides: object) -> dict:
    values = load_defaults()
    values.update(
        front_xhttp_mode=mode,
        front_xhttp_disguise_enabled=disguise,
        front_xhttp_path="/verified-allowlist-path",
        front_access_modes=["direct", "cdn"],
        front_direct_domain="origin.example.invalid",
        front_cdn_domain="edge.example.invalid",
        front_vless_encryption_enabled=True,
        front_vless_encryption="mlkem768x25519plus.native.0rtt.fixture",
        front_vless_decryption="mlkem768x25519plus.native.600s.fixture",
        front_entry_address="198.51.100.10",
        front_entry_reality_port=443,
        front_entry_reality_dest="example.com",
        front_entry_reality_public_key="fixture-public-key",
        front_entry_reality_short_id="0011223344556677",
        front_entry_reality_client_uuid=str(uuid.UUID(int=1)),
        front_entry_reality_front_client_uuid=str(uuid.UUID(int=2)),
    )
    values.update(overrides)
    return values


def render(template: Path, values: dict) -> str:
    return environment().from_string(template.read_text(encoding="utf-8")).render(**values)


def client_settings(mode: str = "packet-up", disguise: bool = True, **overrides: object) -> dict:
    return json.loads(render(CLIENT_TEMPLATE, context(mode, disguise, **overrides)))


def server_xhttp(mode: str = "packet-up", disguise: bool = True, **overrides: object) -> dict:
    config = json.loads(render(SERVER_TEMPLATE, context(mode, disguise, **overrides)))
    return config["inbounds"][0]["streamSettings"]["xhttpSettings"]


def effective(xhttp: dict) -> dict:
    """Поля, которые Xray-core действительно применит (SplitHTTPConfig.Build)."""
    extra = xhttp.get("extra")
    if extra is None:
        return dict(xhttp)
    merged = dict(extra)
    for key in ("host", "path", "mode"):
        merged.pop(key, None)
        if key in xhttp:
            merged[key] = xhttp[key]
    return merged


def client_method(xhttp: dict) -> str:
    return str(xhttp.get("uplinkHTTPMethod") or "POST").upper()


def client_sends_body(xhttp: dict) -> bool:
    # config.go, FillPacketRequest: body и auto (пустое значение Build
    # превращает в auto) клиент кладёт в тело запроса.
    return (xhttp.get("uplinkDataPlacement") or "auto") in ("body", "auto")


def range_bounds(value: object) -> tuple[int, int]:
    if isinstance(value, int):
        return value, value
    low, _, high = str(value).partition("-")
    return int(low), int(high or low)


def xray_header_chunks(payload: bytes, chunk_size: int, key: str) -> dict[str, str]:
    """Повторяет GetRequestHeaderWithPayload из config.go для заданного куска."""
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return {
        f"{key}-{index}": encoded[offset : offset + chunk_size]
        for index, offset in enumerate(range(0, len(encoded), chunk_size))
    }


def render_cdn_health_block(**overrides: object) -> str:
    """Рендерит ветвь CDN раздела FRONT шаблона health (до парного endif)."""
    source = HEALTH_TEMPLATE.read_text(encoding="utf-8")
    start = source.index("{% if 'cdn' in front_access_modes %}\ncheck 'TLS endpoint CDN")
    depth = 0
    end = None
    for match in re.finditer(r"\{%-?\s*(if|endif)\b[^%]*%\}", source[start:]):
        depth += 1 if match.group(1) == "if" else -1
        if depth == 0:
            end = start + match.end()
            break
    if end is None:
        raise AssertionError("не найден парный endif ветви CDN в шаблоне health")
    values: dict = {
        "front_access_modes": ["direct", "cdn"],
        "front_cdn_domain": "edge.example.invalid",
        "front_origin_domain": "origin.example.invalid",
        "front_xhttp_mode": "packet-up",
    }
    values.update(overrides)
    return environment().from_string(source[start:end]).render(**values)


class RenderedUplinkTests(unittest.TestCase):
    def test_no_rendered_profile_sends_get_with_body(self) -> None:
        for mode, disguise in itertools.product(MODES, (True, False)):
            client = client_settings(mode, disguise)["xhttp"]
            server = server_xhttp(mode, disguise)
            levels = {
                "client": client,
                "client.extra": client.get("extra"),
                "server": server,
                "server.extra": server.get("extra"),
            }
            for name, level in levels.items():
                if level is None:
                    continue
                with self.subTest(mode=mode, disguise=disguise, level=name):
                    if str(level.get("uplinkHTTPMethod") or "").upper() == "GET":
                        self.assertNotEqual(level.get("uplinkDataPlacement"), "body")
                        if name.startswith("client"):
                            self.assertIn(
                                level.get("uplinkDataPlacement"), ("header", "cookie")
                            )
            with self.subTest(mode=mode, disguise=disguise, level="effective client"):
                active = effective(client)
                self.assertFalse(
                    client_method(active) == "GET" and client_sends_body(active),
                    "клиент Xray отправил бы GET с телом - CDN ответит 413",
                )

    def test_default_packet_up_profile_moves_uplink_into_headers(self) -> None:
        defaults = load_defaults()
        for disguise in (True, False):
            with self.subTest(disguise=disguise):
                client = client_settings("packet-up", disguise)["xhttp"]
                active = effective(client)
                self.assertEqual(client_method(active), "GET")
                self.assertEqual(active["uplinkDataPlacement"], "header")
                self.assertEqual(active["uplinkDataKey"], defaults["front_xhttp_uplink_data_key"])
                # Без явного значения Xray кладёт до 1 000 000 байт в один запрос.
                self.assertIn("scMaxEachPostBytes", active)
                self.assertIn("uplinkChunkSize", active)
                self.assertIn("scMinPostsIntervalMs", active)
                if disguise:
                    # Поля снаружи extra мертвы, но обязаны совпадать с действующими.
                    for key in (
                        "uplinkHTTPMethod",
                        "uplinkDataPlacement",
                        "uplinkDataKey",
                        "uplinkChunkSize",
                        "scMaxEachPostBytes",
                        "scMinPostsIntervalMs",
                    ):
                        self.assertEqual(client[key], client["extra"][key], key)

    def test_client_and_server_agree_on_uplink_placement_and_key(self) -> None:
        for mode, disguise in itertools.product(MODES, (True, False)):
            with self.subTest(mode=mode, disguise=disguise):
                client = effective(client_settings(mode, disguise)["xhttp"])
                server = effective(server_xhttp(mode, disguise))
                # Сервер читает строго свою placement (или всё сразу в auto) и
                # свой ключ; несовпадение даёт пустой пакет с ответом 200.
                self.assertIn(
                    server["uplinkDataPlacement"],
                    ("auto", client.get("uplinkDataPlacement")),
                )
                if mode == "packet-up":
                    self.assertEqual(client["uplinkDataKey"], server["uplinkDataKey"])
                else:
                    # Остальные режимы шлют аплинк потоковым POST, нагрузка в теле.
                    self.assertTrue(client_sends_body(client))
                    self.assertNotEqual(client_method(client), "GET")

    def test_uplink_key_survives_nginx_defaults(self) -> None:
        key = effective(client_settings()["xhttp"])["uplinkDataKey"]
        self.assertRegex(key, HEADER_NAME_RE)
        self.assertNotIn("_", key)
        self.assertNotEqual(key.lower(), "x-data", "встроенное имя Xray - отпечаток")

    def test_largest_packet_fits_verified_header_limits(self) -> None:
        client = effective(client_settings()["xhttp"])
        server = effective(server_xhttp())
        key = client["uplinkDataKey"]
        _, max_bytes = range_bounds(client["scMaxEachPostBytes"])
        chunk_low, chunk_high = range_bounds(client["uplinkChunkSize"])
        self.assertGreaterEqual(chunk_low, 64)
        self.assertLessEqual(chunk_high, CDN_VERIFIED_HEADER_BYTES)

        payload = os.urandom(max_bytes)
        encoded_length = math.ceil(len(payload) * 4 / 3)
        for chunk in (chunk_low, chunk_high):
            headers = xray_header_chunks(payload, chunk, key)
            self.assertEqual(sum(len(value) for value in headers.values()), encoded_length)
            joined = "".join(headers[f"{key}-{index}"] for index in range(len(headers)))
            padded = joined + "=" * (-len(joined) % 4)
            self.assertEqual(base64.urlsafe_b64decode(padded), payload)
            lines = [f"{name}: {value}\r\n" for name, value in headers.items()]
            self.assertLess(max(len(line) for line in lines), NGINX_FIELD_LIMIT)
            self.assertLessEqual(
                sum(len(line) for line in lines) + OTHER_HEADERS_BUDGET,
                server["serverMaxHeaderBytes"],
            )
        self.assertIsInstance(server["serverMaxHeaderBytes"], int)

    def test_server_reorder_queue_covers_small_get_uplink(self) -> None:
        # Мелкие GET аплинка идут до ~100 в секунду по нескольким соединениям
        # CDN; встроенные 30 пакетов очереди Xray переполнились бы от задержки
        # одного запроса на ~0,3 с и оборвали бы сессию.
        for mode in MODES:
            for disguise in (True, False):
                with self.subTest(mode=mode, disguise=disguise):
                    server = effective(server_xhttp(mode, disguise))
                    self.assertIsInstance(server["scMaxBufferedPosts"], int)
                    self.assertGreaterEqual(server["scMaxBufferedPosts"], 100)

    def test_session_id_table_is_a_predefined_xray_table(self) -> None:
        for mode in MODES:
            client = client_settings(mode, True)["xhttp"]["extra"]
            server = server_xhttp(mode, True)["extra"]
            for name, extra in (("client", client), ("server", server)):
                with self.subTest(mode=mode, side=name):
                    self.assertIn(extra["sessionIDTable"], PREDEFINED_SESSION_ID_TABLES)
                    self.assertEqual(extra["sessionIDTable"], "hex")
                    self.assertEqual(extra["sessionIDLength"], "32")

    def test_nginx_header_buffers_are_not_narrowed(self) -> None:
        nginx = NGINX_TEMPLATE.read_text(encoding="utf-8")
        # Размер пакета рассчитан на штатные large_client_header_buffers
        # 4 8k; переопределение допустимо только в сторону увеличения.
        for size in re.findall(
            r"^\s*large_client_header_buffers\s+\d+\s+(\d+)k\s*;", nginx, re.M
        ):
            self.assertGreaterEqual(int(size), 8)

    def test_probe_margin_is_accepted_by_the_server(self) -> None:
        # Проба несёт на PROBE_EXTRA_BYTES больше наибольшего пакета клиента;
        # сервер с меньшим scMaxEachPostBytes ответил бы ей 413.
        client = effective(client_settings()["xhttp"])
        server = effective(server_xhttp())
        _, client_max = range_bounds(client["scMaxEachPostBytes"])
        _, server_max = range_bounds(
            server.get("scMaxEachPostBytes", XRAY_DEFAULT_MAX_EACH_POST_BYTES)
        )
        self.assertGreaterEqual(server_max, client_max + PROBE_EXTRA_BYTES)
        health = HEALTH_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn(f'head -c "$(( bytes + {PROBE_EXTRA_BYTES} ))"', health)

    def test_health_probe_runs_only_for_cdn_in_packet_up(self) -> None:
        health = HEALTH_TEMPLATE.read_text(encoding="utf-8")
        start = health.index("{% if 'cdn' in front_access_modes %}\ncheck 'TLS endpoint CDN")
        # Функции пробы определены вне условия, чтобы ShellCheck в
        # tests/render-shell.yml проверял их и на direct-only примере.
        self.assertLess(health.index("front_uplink_probe_request() {"), start)
        self.assertLess(health.index("front_uplink_reaches_xray() {"), start)
        # URL и cookie не попадают в аргументы процессов.
        self.assertIn("--config -", health)

        active = render_cdn_health_block()
        self.assertIn("front_uplink_reaches_xray edge.example.invalid", active)
        self.assertNotIn("origin.example.invalid", active)
        explicit = render_cdn_health_block(front_replacement_state="active")
        self.assertEqual(explicit, active)
        for mode in ("stream-up", "stream-one", "auto"):
            with self.subTest(mode=mode):
                self.assertNotIn(
                    "front_uplink_reaches_xray", render_cdn_health_block(front_xhttp_mode=mode)
                )
        self.assertEqual(render_cdn_health_block(front_access_modes=["direct"]).strip(), "")

    def test_health_probe_skips_the_cdn_until_front_replacement_is_committed(self) -> None:
        # До commit замены CDN origin указывает на старый FRONT: проба через
        # CDN проверила бы чужой сервер, а старый FRONT без аплинка в
        # заголовках сорвал бы --replace-front. Проба идёт на origin нового.
        prepared = render_cdn_health_block(front_replacement_state="prepared")
        self.assertIn("front_uplink_reaches_xray origin.example.invalid", prepared)
        self.assertNotIn("front_uplink_reaches_xray edge.example.invalid", prepared)
        # TLS endpoint самого CDN по-прежнему проверяется.
        self.assertIn("front_tls_endpoint_ready edge.example.invalid", prepared)


@unittest.skipUnless(os.name == "posix", "менеджер vless-user использует fcntl и pwd")
class ManagerExportGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        values = context()
        rendered = render(MANAGER_TEMPLATE, values)
        namespace: dict = {"__name__": "vless_user_under_test"}
        exec(compile(rendered, "vless-user", "exec"), namespace)
        self.client_config = namespace["client_config"]

    def record(self, mode: str) -> dict:
        return {"name": "phone", "id": str(uuid.UUID(int=3)), "mode": mode}

    def test_current_cdn_profile_is_exported_with_header_uplink(self) -> None:
        exported = self.client_config(self.record("cdn"), client_settings())
        xhttp = exported["outbounds"][0]["streamSettings"]["xhttpSettings"]
        self.assertEqual(xhttp["host"], "edge.example.invalid")
        self.assertEqual(effective(xhttp)["uplinkDataPlacement"], "header")
        self.assertEqual(exported["remarks"], "Kalimera-FRONT-disguiseV3")

    def test_stale_get_body_settings_cannot_be_exported_for_cdn(self) -> None:
        stale = client_settings()
        for level in (stale["xhttp"], stale["xhttp"]["extra"]):
            level["uplinkDataPlacement"] = "body"
        with contextlib.redirect_stderr(io.StringIO()) as message:
            with self.assertRaises(SystemExit):
                self.client_config(self.record("cdn"), stale)
        self.assertIn("413", message.getvalue())
        # Прямой путь через nginx FRONT принимает тело в GET.
        exported = self.client_config(self.record("direct"), stale)
        address = exported["outbounds"][0]["settings"]["vnext"][0]["address"]
        self.assertEqual(address, "origin.example.invalid")


def health_probe_script(settings_path: Path) -> str:
    """Функции живой пробы аплинка из шаблона health с подставленным путём."""
    source = HEALTH_TEMPLATE.read_text(encoding="utf-8")
    start = source.index("front_uplink_probe_request() {")
    end = source.index("\n}\n", source.index("front_uplink_reaches_xray() {")) + 3
    snippet = source[start:end].replace(
        "{{ front_vless_client_settings_path | quote }}", shlex.quote(str(settings_path))
    )
    if any(marker in snippet for marker in ("{{", "{%", "{#")):
        raise AssertionError("в функциях пробы осталась необработанная разметка Jinja")
    return "set -Eeuo pipefail\n" + snippet


def curl_config_values(config: str, option: str) -> list[str]:
    """Значения строк option = "..." конфигурации curl после разбора кавычек.

    Повторяет src/tool_parsecfg.c (unslashquote): внутри кавычек обратная
    косая черта берёт следующий символ буквально (\\t, \\n, \\r и \\v -
    управляющие символы), строка обязана закончиться закрывающей кавычкой.
    """
    special = {"t": "\t", "n": "\n", "r": "\r", "v": "\v"}
    prefix = f'{option} = "'
    values = []
    for line in config.splitlines():
        if not line.startswith(prefix):
            continue
        text = line[len(prefix) :]
        out = []
        index = 0
        while index < len(text) and text[index] != '"':
            if text[index] == "\\" and index + 1 < len(text):
                index += 1
                out.append(special.get(text[index], text[index]))
            else:
                out.append(text[index])
            index += 1
        if text[index:] != '"':
            raise AssertionError(f"кавычки строки конфигурации curl нарушены: {line!r}")
        values.append("".join(out))
    return values


# Поддельный curl: читает конфигурацию из stdin, как настоящий с --config -,
# сохраняет её и отвечает так, как ответили бы CDN и Xray-core. Режимы
# повторяют возможные поломки по дороге: CDN или nginx выбросили все
# заголовки аплинка, только последний кусок или обрезали его.
FAKE_CURL = r"""#!/usr/bin/env python3
import json, os, re, sys
config = sys.stdin.read()
with open(os.environ["FAKE_CURL_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(config) + "\n")
mode = os.environ.get("FAKE_CURL_MODE", "honest")
chunks = {
    int(index): value
    for index, value in re.findall(
        r'^header = "X-Client-State-(\d+): ([^"\\]*)"$', config, re.M
    )
}
if mode == "strip":
    chunks = {}
elif mode == "drop-last" and chunks:
    del chunks[max(chunks)]
elif mode == "truncate-last" and chunks:
    chunks[max(chunks)] = chunks[max(chunks)][:-10]
# splithttp/hub.go: куски <ключ>-0, <ключ>-1, ... склеиваются до первого
# отсутствующего и декодируются как base64 RawURLEncoding.
joined, index = "", 0
while index in chunks:
    joined += chunks[index]
    index += 1
if "data-binary" in config:
    status = "413"
elif not re.fullmatch(r"[A-Za-z0-9_-]*", joined) or len(joined) % 4 == 1:
    status = "400"
else:
    status = "200"
sys.stdout.write(status)
"""


@unittest.skipUnless(
    os.name == "posix" and shutil.which("bash") and shutil.which("jq"),
    "живая проба аплинка требует bash и jq",
)
class HealthProbeTests(unittest.TestCase):
    def run_probe(
        self,
        settings: dict,
        mode: str = "honest",
        domain: str = "edge.example.invalid",
    ) -> tuple[int, list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings_path = root / "client-settings.json"
            settings_path.write_text(json.dumps(settings), encoding="utf-8")
            bin_dir = root / "bin"
            bin_dir.mkdir()
            curl = bin_dir / "curl"
            curl.write_text(f"#!{sys.executable}\n" + FAKE_CURL.split("\n", 1)[1], encoding="utf-8")
            curl.chmod(0o755)
            script = root / "probe.sh"
            script.write_text(health_probe_script(settings_path), encoding="utf-8")
            log = root / "curl.log"
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f"source {shlex.quote(str(script))}; "
                    f"front_uplink_reaches_xray {shlex.quote(domain)}",
                ],
                env={
                    **os.environ,
                    "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                    "FAKE_CURL_LOG": str(log),
                    "FAKE_CURL_MODE": mode,
                },
                capture_output=True,
                text=True,
                check=False,
            )
            configs = (
                [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
                if log.exists()
                else []
            )
            return result.returncode, configs

    def test_probe_sends_bodyless_get_shaped_like_the_client(self) -> None:
        settings = client_settings()
        status, configs = self.run_probe(settings)
        self.assertEqual(status, 0)
        self.assertEqual(len(configs), 2, "валидная и невалидная проба")
        valid, invalid = configs
        for config in configs:
            self.assertNotIn("data-binary", config)
            self.assertNotIn("request =", config)
        (url,) = curl_config_values(valid, "url")
        self.assertRegex(
            url,
            r"^https://edge\.example\.invalid/verified-allowlist-path/[0-9a-f]{16}\?chunk=0$",
        )
        active = effective(settings["xhttp"])
        _, padding_high = range_bounds(active["xPaddingBytes"])
        (cookie,) = curl_config_values(valid, "cookie")
        self.assertRegex(cookie, r"(^|; )PHPESSID=[0-9a-f]{32}(;|$)")
        # Наибольший допустимый паддинг: проба не меньше настоящего пакета.
        self.assertRegex(cookie, rf"(^|; )mc_token=X{{{padding_high}}}(;|$)")

        headers = dict(header.split(": ", 1) for header in curl_config_values(valid, "header"))
        # Те же заголовки браузера, что Xray-core добавляет к каждому пакету.
        self.assertLessEqual(XRAY_FETCH_HEADERS, set(headers))
        version = re.fullmatch(
            r"Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit/537\.36 "
            r"\(KHTML, like Gecko\) Chrome/(\d+)\.0\.0\.0 Safari/537\.36",
            headers["User-Agent"],
        ).group(1)
        # common/utils/browser.go, ChromeVersion без случайного сдвига.
        today = int(time.time()) // 86400
        self.assertEqual(int(version), 144 + (today - 20466 - 35) // 35)
        self.assertIn(f'"Chromium";v="{version}"', headers["Sec-CH-UA"])
        self.assertEqual(headers["Sec-CH-UA-Platform"], '"Windows"')

        uplink = {name: value for name, value in headers.items() if name.startswith("X-Client-State-")}
        _, max_bytes = range_bounds(active["scMaxEachPostBytes"])
        _, chunk_high = range_bounds(active["uplinkChunkSize"])
        probe_bytes = max_bytes + PROBE_EXTRA_BYTES
        self.assertEqual(len(uplink), math.ceil(math.ceil(probe_bytes * 4 / 3) / chunk_high))
        self.assertTrue(all(len(value) <= chunk_high for value in uplink.values()))
        joined = "".join(uplink[f"X-Client-State-{index}"] for index in range(len(uplink)))
        decoded = base64.urlsafe_b64decode(joined + "=" * (-len(joined) % 4))
        self.assertEqual(len(decoded), probe_bytes)

        broken = dict(header.split(": ", 1) for header in curl_config_values(invalid, "header"))
        broken_joined = "".join(broken[f"X-Client-State-{index}"] for index in range(len(uplink)))
        self.assertEqual(len(broken_joined), len(joined))
        # Испорчен ровно последний символ: потеря или обрезка любого куска
        # убирает его, и Xray отвечает 200 вместо 400.
        self.assertTrue(broken_joined.endswith("."))
        self.assertRegex(broken_joined[:-1], r"^[A-Za-z0-9_-]+$")

    def test_probe_goes_to_the_given_domain(self) -> None:
        # Пока замена FRONT не подтверждена, health передаёт origin-домен.
        status, configs = self.run_probe(client_settings(), domain="origin.example.invalid")
        self.assertEqual(status, 0)
        self.assertEqual(len(configs), 2)
        for config in configs:
            (url,) = curl_config_values(config, "url")
            self.assertTrue(url.startswith("https://origin.example.invalid/verified-allowlist-path/"))

    def test_probe_refuses_malformed_domain(self) -> None:
        status, configs = self.run_probe(client_settings(), domain='edge.example.invalid"x')
        self.assertNotEqual(status, 0)
        self.assertEqual(configs, [])

    def test_probe_fails_on_get_body_profile_like_the_outage(self) -> None:
        stale = client_settings()
        for level in (stale["xhttp"], stale["xhttp"]["extra"]):
            level["uplinkDataPlacement"] = "body"
        status, configs = self.run_probe(stale)
        self.assertNotEqual(status, 0)
        self.assertIn('request = "GET"', configs[0])
        self.assertIn("data-binary", configs[0])

    def test_probe_fails_when_headers_are_stripped_on_the_way(self) -> None:
        status, configs = self.run_probe(client_settings(), mode="strip")
        self.assertNotEqual(status, 0)
        self.assertEqual(len(configs), 2)

    def test_probe_fails_when_a_later_header_chunk_is_lost(self) -> None:
        # Первый кусок в 3000 символов декодируется сам по себе, поэтому
        # испорченный символ в начале пропустил бы такую потерю.
        for mode in ("drop-last", "truncate-last"):
            with self.subTest(mode=mode):
                status, configs = self.run_probe(client_settings(), mode=mode)
                self.assertNotEqual(status, 0)
                self.assertEqual(len(configs), 2)


if __name__ == "__main__":
    unittest.main()

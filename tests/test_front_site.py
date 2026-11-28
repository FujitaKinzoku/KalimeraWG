"""Сайт в корне FRONT: сборщик, настройки установщика, Nginx и проверки.

Без сайта FRONT отвечал 404 на всё, кроме пути XHTTP, и домен с настоящим
сертификатом выглядел заглушкой. Сборщик проверяется как программа (одинаковые
настройки дают один и тот же сайт, разные - разные, все ссылки ведут на
существующие файлы, путь XHTTP сайту недоступен), а конфигурация Nginx - на
настоящем nginx, когда он есть в окружении: страницы, сжатие, кэш, своя
страница 404 и нетронутый путь XHTTP.
"""

from __future__ import annotations

import gzip
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ElementTree
import zlib
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

import jinja2
import yaml

ROOT = Path(__file__).parents[1]
GENERATOR_PATH = ROOT / "roles" / "front" / "files" / "kalimera-front-site.py"
DEPLOY_PATH = ROOT / "scripts" / "lib" / "interactive_deploy.py"
FRONT_DEFAULTS = ROOT / "roles" / "front" / "defaults" / "main.yml"
FRONT_TASKS = ROOT / "roles" / "front" / "tasks" / "main.yml"
NGINX_TEMPLATE = ROOT / "roles" / "front" / "templates" / "nginx-front.conf.j2"
AWG_HEALTH = ROOT / "roles" / "health" / "templates" / "awg-health.sh.j2"
SELF_HEAL = ROOT / "roles" / "health" / "templates" / "awg-self-heal.sh.j2"
INTEGRITY = ROOT / "roles" / "operations" / "templates" / "awg-managed-integrity.sh.j2"
CASCADE = ROOT / "roles" / "cascade_check" / "templates" / "cascade-check.sh.j2"
GATEWAY = ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SITE = load("kalimera_front_site", GENERATOR_PATH)
DEPLOY = load("interactive_deploy_front_site", DEPLOY_PATH)

SEEDS = tuple(hashlib.sha256(f"seed-{index}".encode()).hexdigest()[:32] for index in range(10))
XHTTP_PATH = "/verified-allowlist-path"


def config(seed: str = SEEDS[0], **overrides: object):
    raw = {
        "seed": seed,
        "created": "2026-11-28",
        "language": "ru",
        "title": "",
        "domain": "edge.example.invalid",
        "reserved": [XHTTP_PATH],
    }
    raw.update(overrides)
    return SITE.parse_config(raw)


def built(seed: str = SEEDS[0], **overrides: object) -> dict:
    return SITE.build_site(config(seed, **overrides))


class Links(HTMLParser):
    """Локальные ссылки страницы и баланс её тегов."""

    VOID = {"meta", "link", "img", "br", "hr", "input"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.targets: list[str] = []
        self.stack: list[str] = []
        self.problems: list[str] = []

    def handle_starttag(self, tag: str, attributes: list) -> None:
        for name, value in attributes:
            if name in ("href", "src") and value:
                self.targets.append(value)
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack or self.stack.pop() != tag:
            self.problems.append(f"лишний или непарный закрывающий тег {tag}")


def page_links(data: bytes) -> Links:
    parser = Links()
    parser.feed(data.decode("utf-8"))
    parser.close()
    return parser


def target_file(target: str) -> str:
    """Файл, который Nginx отдаст по локальному адресу."""
    path = target.split("#", 1)[0].split("?", 1)[0].lstrip("/")
    if path == "" or path.endswith("/"):
        return path + "index.html"
    return path


class GeneratorTests(unittest.TestCase):
    def test_same_settings_give_the_same_site(self) -> None:
        self.assertEqual(built(), built())

    def test_every_installation_gets_its_own_site(self) -> None:
        sites = [built(seed) for seed in SEEDS]
        for extension in (".css", ".js"):
            contents = [
                next(data for name, (data, _) in site.items() if name.endswith(extension))
                for site in sites
            ]
            self.assertEqual(len(set(contents)), len(sites), extension)
        self.assertEqual(len({site["index.html"][0] for site in sites}), len(sites))
        # Набор адресов тоже не общий: одинаковая карта страниц у всех установок
        # была бы приметой не хуже одинакового текста.
        self.assertGreater(len({tuple(sorted(site)) for site in sites}), len(sites) // 2)
        drawings = [data for site in sites for name, (data, _) in site.items() if name.endswith(".svg")
                    and "/" in name]
        self.assertEqual(len(set(drawings)), len(drawings))

    def test_every_local_link_leads_to_a_file(self) -> None:
        for seed in SEEDS:
            for language in ("ru", "en"):
                site = built(seed, language=language)
                for name, (data, _) in site.items():
                    if not name.endswith(".html"):
                        continue
                    parsed = page_links(data)
                    self.assertEqual(parsed.problems, [], name)
                    self.assertEqual(parsed.stack, [], name)
                    for target in parsed.targets:
                        if target.startswith("https://"):
                            self.assertTrue(target.startswith("https://edge.example.invalid/"), target)
                            target = target[len("https://edge.example.invalid"):]
                        self.assertTrue(target.startswith("/"), f"{name}: {target}")
                        self.assertIn(target_file(target), site, f"{name}: {target}")

    def test_xml_files_are_well_formed(self) -> None:
        for seed in SEEDS[:4]:
            site = built(seed)
            for name, (data, _) in site.items():
                if name.endswith((".xml", ".svg")):
                    try:
                        ElementTree.fromstring(data)
                    except ElementTree.ParseError as error:
                        self.fail(f"{name}: {error}")

    def test_sitemap_and_feed_list_the_pages(self) -> None:
        site = built()
        pages = {name for name in site if name.endswith(".html") and name != "404.html"}
        space = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        listed = {
            target_file(loc.text[len("https://edge.example.invalid"):])
            for loc in ElementTree.fromstring(site["sitemap.xml"][0]).findall("s:url/s:loc", space)
        }
        self.assertEqual(listed, pages)
        feed_name = next(name for name in site if name in ("feed.xml", "atom.xml"))
        atom = {"a": "http://www.w3.org/2005/Atom"}
        entries = ElementTree.fromstring(site[feed_name][0]).findall("a:entry", atom)
        self.assertGreaterEqual(len(entries), 18)
        for entry in entries:
            link = entry.find("a:link", atom).attrib["href"]
            self.assertIn(target_file(link[len("https://edge.example.invalid"):]), site)
        self.assertIn(b"Sitemap: https://edge.example.invalid/sitemap.xml", site["robots.txt"][0])

    def test_site_is_complete_and_moderate_in_size(self) -> None:
        for seed in SEEDS:
            site = built(seed)
            for required in ("index.html", "404.html", "robots.txt", "sitemap.xml", "favicon.ico",
                             "favicon.svg", "apple-touch-icon.png"):
                self.assertIn(required, site)
            pages = [name for name in site if name.endswith(".html")]
            drawings = [name for name in site if name.endswith(".svg") and "/" in name]
            self.assertGreaterEqual(len(pages), 25)
            self.assertTrue(18 <= len(drawings) <= 28, len(drawings))
            self.assertLess(max(len(site[name][0]) for name in drawings), 150_000)
            self.assertLess(sum(len(data) for data, _ in site.values()), 2_000_000)
            # Каталог без index.html Nginx отдал бы как 403; у страниц его нет.
            for name in pages:
                self.assertTrue(name.endswith(("index.html", ".html")))

    def test_nothing_in_the_site_names_the_cascade(self) -> None:
        words = re.compile(rb"kalimera|vless|xray|xhttp|vpn|proxy|wireguard|amnezia|tunnel", re.IGNORECASE)
        for seed in SEEDS[:5]:
            for language in ("ru", "en"):
                for name, (data, _) in built(seed, language=language).items():
                    if name.endswith((".png", ".ico")):
                        continue
                    self.assertIsNone(words.search(data), name)
                    self.assertNotIn(XHTTP_PATH.encode(), data, name)
                    self.assertNotIn(seed.encode(), data, name)
                    self.assertNotIn(seed[:8].encode(), data, name)

    def test_site_never_takes_addresses_under_the_xhttp_path(self) -> None:
        # Nginx отдаёт Xray всё, что начинается с пути XHTTP, в том числе адреса,
        # у которых путь - только начало имени каталога.
        for reserved in ("/w", "/works", "/s", "/a", "/img", "/assets/app", "/series/tiles"):
            for seed in SEEDS:
                try:
                    site = built(seed, reserved=[reserved])
                except SITE.SiteError:
                    # Обязательные адреса (/sitemap.xml, /apple-touch-icon.png)
                    # переименовать нельзя: сборщик обязан отказаться, а не
                    # собрать сайт без них.
                    self.assertTrue(
                        any(("/" + name).startswith(reserved) for name in SITE.FIXED_FILES), reserved
                    )
                    continue
                for name in site:
                    self.assertFalse(("/" + name).startswith(reserved), f"{reserved}: {name}")

    def test_xhttp_path_over_a_required_address_is_refused(self) -> None:
        for reserved in ("/index", "/favicon", "/robots.txt", "/4"):
            with self.assertRaises(SITE.SiteError):
                built(reserved=[reserved])

    def test_dates_lie_before_the_day_the_site_was_enabled(self) -> None:
        created = time.mktime(time.strptime("2026-11-28", "%Y-%m-%d"))
        for seed in SEEDS:
            site = built(seed)
            moments = [moment for _, moment in site.values()]
            self.assertLess(max(moments), created)
            self.assertGreater(max(moments), created - 20 * 86400)
            self.assertGreater(min(moments), created - 480 * 86400)
            # Страницы и рисунки датированы по-разному, а не одной минутой сборки.
            self.assertGreater(len(set(moments)), 15)

    def test_icons_are_real_images(self) -> None:
        site = built()
        png = site["apple-touch-icon.png"][0]
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        width, height, depth, kind = struct.unpack(">IIBB", png[16:26])
        self.assertEqual((width, height, depth, kind), (180, 180, 8, 6))
        length = struct.unpack(">I", png[33:37])[0]
        self.assertEqual(png[37:41], b"IDAT")
        self.assertEqual(len(zlib.decompress(png[41:41 + length])), 180 * (1 + 4 * 180))
        ico = site["favicon.ico"][0]
        reserved, kind, count = struct.unpack("<HHH", ico[:6])
        self.assertEqual((reserved, kind, count), (0, 1, 1))
        size, offset = struct.unpack("<II", ico[14:22])
        self.assertEqual(ico[offset:offset + 8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(len(ico), offset + size)

    def test_title_from_settings_is_used_and_escaped(self) -> None:
        site = built(title='Линии & <углы> "45"')
        page = site["index.html"][0].decode("utf-8")
        self.assertIn("Линии &amp; &lt;углы&gt; &quot;45&quot;", page)
        self.assertNotIn("<углы>", page)
        script = next(data for name, (data, _) in site.items() if name.endswith(".js"))
        self.assertEqual(script.count(b"*/"), 1)

    def test_languages(self) -> None:
        russian = built()["index.html"][0].decode("utf-8")
        english = built(language="en")["index.html"][0].decode("utf-8")
        self.assertIn('<html lang="ru">', russian)
        self.assertIn('<html lang="en">', english)
        self.assertIsNone(re.search("[А-Яа-я]", english))

    def test_settings_are_validated(self) -> None:
        for broken in (
            {"seed": "short"},
            {"seed": "Z" * 32},
            {"created": "28.11.2026"},
            {"language": "de"},
            {"title": "x" * 61},
            {"title": "строка\nвторая"},
            {"domain": "bad domain"},
            {"reserved": ["no-slash"]},
            {"reserved": "/path"},
        ):
            with self.assertRaises(SITE.SiteError, msg=str(broken)):
                config(**broken)

    def test_output_is_pinned_to_the_generator_revision(self) -> None:
        # Сайт уже установленного FRONT пересобирается только при смене настроек
        # или номера GENERATOR_REVISION. Правка сборщика, которая меняет его
        # вывод без смены номера, дала бы после замены FRONT другой сайт под
        # тем же доменом. Изменили вывод намеренно - увеличьте номер и обновите
        # хеши. PNG и ICO не учитываются: их байты зависят от сборки zlib.
        # Хеши совпали на Linux (glibc) и Windows (MSVC), Python 3.12.
        expected = {
            "ru": "484c41777b5f7237e306b1293fc3d5e3794310c34d18a092192d626b2e6b0c5e",
            "en": "b7f70c898b08d1e76def2cafbd67ccc98336945bf1144db3320fabe049232fa4",
        }
        self.assertEqual(SITE.GENERATOR_REVISION, 1)
        for language, pinned in expected.items():
            site = built("00112233445566778899aabbccddeeff", language=language)
            digest = hashlib.sha256()
            for name in sorted(site):
                if name.endswith((".png", ".ico")):
                    continue
                data, moment = site[name]
                digest.update(f"{name}\0{moment}\0".encode() + hashlib.sha256(data).digest())
            self.assertEqual(digest.hexdigest(), pinned, language)

    def test_random_stream_is_fixed(self) -> None:
        # Алгоритм потока менять нельзя: от него зависит каждый уже собранный
        # сайт. Значения получены от этой же реализации splitmix64.
        stream = SITE.Rng("0" * 32, "check")
        first = [stream.next() for _ in range(3)]
        again = SITE.Rng("0" * 32, "check")
        self.assertEqual(first, [again.next() for _ in range(3)])
        self.assertNotEqual(first, [SITE.Rng("0" * 32, "other").next() for _ in range(3)])
        self.assertTrue(all(0 <= value < 2 ** 64 for value in first))
        values = [SITE.Rng("1" * 32, "spread").uniform(2, 5) for _ in range(1)]
        self.assertTrue(2 <= values[0] < 5)


class BuildOnDiskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        base = Path(self.directory.name)
        self.root = base / "www" / "site"
        self.state = base / "state"
        (base / "www").mkdir()
        self.config = config()

    def test_build_is_idempotent_and_keeps_dates(self) -> None:
        self.assertTrue(SITE.build(self.config, self.root, self.state))
        before = {path: path.stat().st_mtime_ns for path in self.root.rglob("*") if path.is_file()}
        self.assertFalse(SITE.build(self.config, self.root, self.state))
        after = {path: path.stat().st_mtime_ns for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        expected = built()
        self.assertEqual({path.relative_to(self.root).as_posix() for path in before}, set(expected))
        for name, (data, moment) in expected.items():
            path = self.root / name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(int(path.stat().st_mtime), moment)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        self.assertFalse(self.root.with_name("site.new").exists())
        self.assertFalse(self.root.with_name("site.old").exists())

    def test_damage_is_seen_and_repaired(self) -> None:
        SITE.build(self.config, self.root, self.state)
        manifest = SITE.read_manifest(self.state)
        self.assertEqual(SITE.tree_problems(self.root, manifest), [])
        (self.root / "index.html").write_text("взлом", encoding="utf-8")
        (self.root / "robots.txt").unlink()
        (self.root / "extra.php").write_text("<?php", encoding="utf-8")
        problems = SITE.tree_problems(self.root, manifest)
        self.assertEqual(
            sorted(problems),
            ["изменён файл index.html", "лишний файл extra.php", "нет файла robots.txt"],
        )
        self.assertTrue(SITE.build(self.config, self.root, self.state))
        self.assertEqual(SITE.tree_problems(self.root, SITE.read_manifest(self.state)), [])
        self.assertFalse((self.root / "extra.php").exists())

    def test_changed_settings_rebuild_the_site(self) -> None:
        SITE.build(self.config, self.root, self.state)
        self.assertTrue(SITE.build(config(title="Другое название"), self.root, self.state))
        self.assertIn("Другое название", (self.root / "index.html").read_text(encoding="utf-8"))

    def test_command_line(self) -> None:
        settings = Path(self.directory.name) / "config.json"
        settings.write_text(
            json.dumps({"seed": SEEDS[1], "created": "2026-11-28", "language": "en", "title": "",
                        "domain": "edge.example.invalid", "reserved": [XHTTP_PATH]}),
            encoding="utf-8",
        )
        common = ["--root", str(self.root), "--state", str(self.state)]

        def run(*arguments: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [sys.executable, str(GENERATOR_PATH), *arguments],
                capture_output=True, text=True, encoding="utf-8", check=False,
            )

        self.assertEqual(run("verify", *common).returncode, 1)
        first = run("build", "--config", str(settings), *common)
        self.assertEqual((first.returncode, first.stdout.strip()), (0, "changed"), first.stderr)
        self.assertEqual(run("build", "--config", str(settings), *common).stdout.strip(), "unchanged")
        self.assertEqual(run("verify", "--config", str(settings), *common).returncode, 0)
        (self.root / "index.html").write_text("x", encoding="utf-8")
        damaged = run("verify", "--config", str(settings), *common)
        self.assertEqual(damaged.returncode, 1)
        self.assertIn("изменён файл index.html", damaged.stderr)
        settings.write_text(settings.read_text(encoding="utf-8").replace('"en"', '"de"'), encoding="utf-8")
        refused = run("build", "--config", str(settings), *common)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("language", refused.stderr)
        self.assertEqual(run("remove", *common).returncode, 0)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.state.exists())


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.production = Path(self.directory.name)
        self.front = self.production / "group_vars" / "front.yml"
        self.front.parent.mkdir(parents=True)

    def write(self, **values: object) -> None:
        self.front.write_text(yaml.safe_dump(values, allow_unicode=True), encoding="utf-8")

    def read(self) -> dict:
        return yaml.safe_load(self.front.read_text(encoding="utf-8"))

    def answers(self, *lines: str):
        return mock.patch("builtins.input", side_effect=list(lines))

    def test_new_settings_pass_role_and_generator_validation(self) -> None:
        tasks = FRONT_TASKS.read_text(encoding="utf-8")
        seed_pattern = re.search(r"front_site_seed is match\('([^']+)'\)", tasks).group(1)
        date_pattern = re.search(r"front_site_created \| string is match\('([^']+)'\)", tasks).group(1)
        seeds = set()
        for _ in range(50):
            values = DEPLOY.new_front_site("en", "Lines")
            self.assertEqual(set(values), set(DEPLOY.FRONT_SITE_KEYS))
            self.assertRegex(values["front_site_seed"], seed_pattern)
            self.assertRegex(values["front_site_created"], date_pattern)
            seeds.add(values["front_site_seed"])
            SITE.parse_config({
                "seed": values["front_site_seed"], "created": values["front_site_created"],
                "language": values["front_site_language"], "title": values["front_site_title"],
                "domain": "edge.example.invalid", "reserved": [XHTTP_PATH],
            })
        self.assertEqual(len(seeds), 50)

    def test_enable_writes_settings_and_keeps_the_rest(self) -> None:
        self.write(front_enabled=True, front_xhttp_path="/kept", front_origin_domain="o.example.invalid")
        with self.answers("", "Малые формы"), mock.patch("builtins.print"):
            self.assertTrue(DEPLOY.enable_front_site(self.production))
        values = self.read()
        self.assertEqual(values["front_xhttp_path"], "/kept")
        self.assertIs(values["front_site_enabled"], True)
        self.assertEqual(values["front_site_language"], "ru")
        self.assertEqual(values["front_site_title"], "Малые формы")
        self.assertRegex(values["front_site_seed"], r"^[0-9a-f]{32}$")
        # Дата читается из YAML строкой, а не объектом даты.
        self.assertIsInstance(values["front_site_created"], str)
        with mock.patch("builtins.print") as printed:
            self.assertFalse(DEPLOY.enable_front_site(self.production))
        self.assertIn("уже включён", printed.call_args[0][0])

    def test_disable_keeps_the_seed_and_enable_can_return_the_same_site(self) -> None:
        self.write(front_enabled=True)
        with self.answers("en", ""), mock.patch("builtins.print"):
            DEPLOY.enable_front_site(self.production)
        first = self.read()
        with mock.patch("builtins.print"):
            self.assertTrue(DEPLOY.disable_front_site(self.production))
            self.assertFalse(DEPLOY.disable_front_site(self.production))
        disabled = self.read()
        self.assertNotIn("front_site_enabled", disabled)
        self.assertEqual(disabled["front_site_seed"], first["front_site_seed"])
        with self.answers(""), mock.patch("builtins.print"):
            DEPLOY.enable_front_site(self.production)
        self.assertEqual(self.read(), first)
        with mock.patch("builtins.print"):
            DEPLOY.disable_front_site(self.production)
        with self.answers("n", "ru", ""), mock.patch("builtins.print"):
            DEPLOY.enable_front_site(self.production)
        self.assertNotEqual(self.read()["front_site_seed"], first["front_site_seed"])

    def test_enable_needs_a_front(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            DEPLOY.enable_front_site(self.production / "missing")
        self.assertIn("FRONT", str(raised.exception))
        self.write(front_enabled=False)
        with self.assertRaises(SystemExit):
            DEPLOY.enable_front_site(self.production)

    def test_bad_answers_are_refused(self) -> None:
        self.write(front_enabled=True)
        with self.answers("de"), mock.patch("builtins.print"), self.assertRaises(SystemExit):
            DEPLOY.enable_front_site(self.production)
        with self.answers("ru", "x" * 61), mock.patch("builtins.print"), self.assertRaises(SystemExit):
            DEPLOY.enable_front_site(self.production)
        self.assertNotIn("front_site_seed", self.read())

    def test_flags_are_wired(self) -> None:
        source = DEPLOY_PATH.read_text(encoding="utf-8")
        gateway = GATEWAY.read_text(encoding="utf-8")
        for flag in ("--enable-front-site", "--disable-front-site"):
            self.assertIn(f'("{flag}", args.{flag[2:].replace("-", "_")}),', source)
            self.assertIn(f"'--resume {flag}'|", gateway)
            self.assertIn(f"{flag},", gateway)
        self.assertIn("**front_site,", source)


def render(template: Path, **variables: object) -> str:
    environment = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    return environment.from_string(template.read_text(encoding="utf-8")).render(**variables)


def nginx_config(site: bool, **overrides: object) -> str:
    values = {
        "front_cert_present": True,
        "front_xhttp_listen_port": 8080,
        "front_origin_domain": "origin.example.invalid",
        "front_origin_cert_path": "/etc/letsencrypt/live/origin.example.invalid/fullchain.pem",
        "front_origin_key_path": "/etc/letsencrypt/live/origin.example.invalid/privkey.pem",
        "front_xhttp_path": XHTTP_PATH,
    }
    if site:
        values.update(front_site_active=True, front_site_root="/var/www/kalimera-site")
    values.update(overrides)
    return render(NGINX_TEMPLATE, **values)


class NginxTemplateTests(unittest.TestCase):
    def test_without_the_site_the_configuration_is_unchanged(self) -> None:
        # Существующие каскады получают прежний файл байт в байт: и без
        # переменной вовсе, и с явным false. Хеши сняты с шаблона до появления
        # сайта (коммит 28db9cc) при тех же значениях: полный файл и заготовка
        # для получения сертификата.
        current = nginx_config(False)
        self.assertEqual(current, nginx_config(False, front_site_active=False))
        self.assertEqual(current, nginx_config(False, front_site_active="False"))
        self.assertIn("    location / {\n        return 404;\n    }\n}\n", current)
        self.assertNotIn("front_site", current)
        self.assertNotIn("root ", current.replace("root /var/www/html;", ""))
        self.assertEqual(
            hashlib.sha256(current.encode("utf-8")).hexdigest(),
            "af8a359ed37a3e930b219d8bdf109993016ff60b690892fb203d0def53768fde",
        )
        for site in (False, True):
            stage = nginx_config(site, front_cert_present=False)
            self.assertEqual(
                hashlib.sha256(stage.encode("utf-8")).hexdigest(),
                "036c32a0f3d6e6dedde7249cc28c728fa603a867017b10f61a7369249059105b",
            )

    def test_acme_stage_has_no_site(self) -> None:
        text = nginx_config(True, front_cert_present=False)
        self.assertNotIn("front_site_expires", text)
        self.assertNotIn("kalimera-site", text)
        self.assertIn("return 404;", text)

    def test_site_is_served_without_regex_locations(self) -> None:
        text = nginx_config(True)
        self.assertIn("    root /var/www/kalimera-site;\n", text)
        self.assertIn("        try_files $uri $uri/ =404;\n", text)
        self.assertIn("    error_page 404 /404.html;\n", text)
        self.assertNotIn("return 404;", text)
        # Регулярные location nginx проверяет раньше обычных: появись такой,
        # он мог бы перехватить запросы пути XHTTP.
        self.assertIsNone(re.search(r"location\s+~", text))
        locations = re.findall(r"^\s*location\s+(.+?)\s*\{", text, re.MULTILINE)
        self.assertEqual(
            locations, ["/.well-known/acme-challenge/", "/", XHTTP_PATH, "= /404.html", "/"]
        )
        # Путь XHTTP настроен как прежде.
        start = text.index(f"location {XHTTP_PATH} {{")
        block = text[start:text.index("\n    }\n", start)]
        without = nginx_config(False)
        start = without.index(f"location {XHTTP_PATH} {{")
        self.assertEqual(block, without[start:without.index("\n    }\n", start)])


class WiringTests(unittest.TestCase):
    def test_role_defaults_keep_the_site_off(self) -> None:
        defaults = yaml.safe_load(FRONT_DEFAULTS.read_text(encoding="utf-8"))
        self.assertIs(defaults["front_site_enabled"], False)
        self.assertEqual(defaults["front_site_seed"], "")
        self.assertEqual(defaults["front_site_domain"], "{{ front_client_domain }}")
        self.assertNotEqual(defaults["front_site_root"], "/var/www/html")

    def test_role_builds_before_nginx_and_removes_after_it(self) -> None:
        tasks = yaml.safe_load(FRONT_TASKS.read_text(encoding="utf-8"))
        names = [task["name"] for task in tasks]
        build = names.index("Сборка: сайт FRONT")
        nginx = names.index("Установка: полная конфигурация Nginx (с TLS-блоком)")
        applied = names.index("Применение: конфигурация FRONT-релея")
        removal = names.index("Удаление: сайт FRONT при отключении")
        self.assertLess(names.index("Проверка: каталоги сайта FRONT"), build)
        self.assertLess(build, nginx)
        self.assertLess(nginx, applied)
        self.assertLess(applied, removal)
        # Пути удаляемых каталогов проверяются и при выключенном сайте.
        self.assertNotIn("when", tasks[names.index("Проверка: каталоги сайта FRONT")])
        self.assertEqual(tasks[removal]["when"], "not (front_site_active | bool)")
        settings = tasks[names.index("Установка: настройки сайта FRONT")]
        self.assertEqual(settings["vars"]["front_site_settings"]["reserved"], ["{{ front_xhttp_path }}"])
        self.assertEqual(settings["ansible.builtin.copy"]["mode"], "0600")

    def test_role_path_patterns_accept_defaults_and_refuse_dangerous_values(self) -> None:
        defaults = yaml.safe_load(FRONT_DEFAULTS.read_text(encoding="utf-8"))
        tasks = FRONT_TASKS.read_text(encoding="utf-8")
        for key, dangerous in (
            ("front_site_root", ("/", "/var/www", "/var/www/a/b", "/etc", "/var/www/..")),
            ("front_site_state_dir", ("/", "/var/lib", "/var/lib/dpkg", "/var/lib/kalimera-x/..")),
            ("front_site_config_path", ("/etc/passwd", "/etc/nginx/nginx.conf", "/etc/kalimera-x")),
            ("front_site_command_path", ("/usr/local/libexec", "/usr/bin/python3")),
        ):
            pattern = re.search(rf"{key} is match\('([^']+)'\)", tasks).group(1)
            self.assertRegex(defaults[key], pattern)
            for value in dangerous:
                self.assertIsNone(re.match(pattern, value), f"{key}: {value}")

    def test_health_checks_exist_only_with_the_site(self) -> None:
        text = AWG_HEALTH.read_text(encoding="utf-8")
        self.assertEqual(text.count("{% if front_site_enabled | default(false) | bool %}"), 2)
        self.assertIn("check_minor 'сайт FRONT собран и не изменён' front_site_is_intact", text)
        self.assertIn("check 'Nginx отдаёт главную страницу сайта FRONT' front_site_is_served", text)
        # Проба идёт на локальный Nginx: от DNS, CDN и сети результат не зависит.
        self.assertIn("--resolve {{ (front_origin_domain ~ ':443:127.0.0.1') | quote }}", text)

    def test_self_heal_knows_both_checks(self) -> None:
        text = SELF_HEAL.read_text(encoding="utf-8")
        self.assertIn("'Nginx отдаёт главную страницу сайта FRONT')\n            plan_action=nginx ;;", text)
        self.assertIn("'сайт FRONT собран и не изменён')\n            plan_action=front_site ;;", text)
        self.assertIn("front_site) echo 'пересборка сайта FRONT' ;;", text)
        self.assertRegex(text, r"front_backend xray vless_sync front_site nginx certbot")
        self.assertIn("front_site)\n", text)

    def test_integrity_and_cascade_check(self) -> None:
        integrity = INTEGRITY.read_text(encoding="utf-8")
        self.assertIn("{{ front_site_command_path | default('/usr/local/libexec/kalimera-front-site') }}", integrity)
        self.assertIn("{{ front_site_config_path | default('/etc/kalimera-front-site/config.json') }}", integrity)
        cascade = CASCADE.read_text(encoding="utf-8")
        self.assertIn("emit_row CDN OK 'сайт FRONT через CDN' 'главная страница отдаётся'", cascade)
        self.assertIn("emit_row CDN WARN 'сайт FRONT через CDN'", cascade)


class AnsibleExpressionTests(unittest.TestCase):
    """Выражения роли вычисляет настоящий шаблонизатор Ansible."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from ansible.parsing.dataloader import DataLoader
            from ansible.template import Templar
        except ImportError as error:
            raise unittest.SkipTest(f"нужен ansible-core: {error}") from error
        try:
            from ansible.template import trust_as_template
        except ImportError:
            def trust_as_template(value):
                return value
        cls.trust = staticmethod(trust_as_template)
        cls.templar_class, cls.loader_class = Templar, DataLoader
        cls.defaults = yaml.safe_load(FRONT_DEFAULTS.read_text(encoding="utf-8"))
        cls.tasks = {task["name"]: task for task in yaml.safe_load(FRONT_TASKS.read_text(encoding="utf-8"))}

    def trusted(self, value):
        if isinstance(value, str):
            return self.trust(value)
        if isinstance(value, dict):
            return {key: self.trusted(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.trusted(item) for item in value]
        return value

    def evaluate(self, expression: str, **variables: object):
        names = {key: self.trusted(value) for key, value in self.defaults.items() if key.startswith("front_")}
        names.update({key: self.trusted(value) for key, value in variables.items()})
        templar = self.templar_class(loader=self.loader_class(), variables=names)
        return templar.template(self.trust(expression))

    def test_site_is_active_only_together_with_the_front(self) -> None:
        for relay, site, expected in (
            (True, True, True), (True, False, False), (False, True, False), (False, False, False),
            ("true", "true", True), (True, "false", False),
        ):
            value = self.evaluate(
                "{{ front_site_active | bool }}", front_relay_enabled=relay, front_site_enabled=site
            )
            self.assertIs(value, expected, (relay, site))

    def test_settings_file_is_what_the_generator_reads(self) -> None:
        import datetime

        task = self.tasks["Установка: настройки сайта FRONT"]
        for created in ("2026-11-28", datetime.date(2026, 11, 28)):
            text = self.evaluate(
                task["ansible.builtin.copy"]["content"],
                front_site_settings=task["vars"]["front_site_settings"],
                front_site_seed="ab" * 16,
                # Без кавычек в inventory YAML читает дату объектом, а не строкой.
                front_site_created=created,
                front_site_language="en",
                front_site_title='Линии & "углы"',
                front_client_domain="edge.example.invalid",
                front_origin_domain="origin.example.invalid",
                front_xhttp_path=XHTTP_PATH,
            )
            self.assertTrue(text.endswith("\n"))
            raw = json.loads(text)
            self.assertEqual(raw, {
                "seed": "ab" * 16, "created": "2026-11-28", "language": "en",
                "title": 'Линии & "углы"', "domain": "edge.example.invalid", "reserved": [XHTTP_PATH],
            })
            parsed = SITE.parse_config(raw)
            # Страницы называют имя, по которому подключаются клиенты, а не origin.
            self.assertEqual(parsed.domain, "edge.example.invalid")

    def test_path_assertions_hold_for_defaults_and_fail_for_dangerous_values(self) -> None:
        conditions = self.tasks["Проверка: каталоги сайта FRONT"]["ansible.builtin.assert"]["that"]
        self.assertTrue(all(self.evaluate("{{ " + condition + " }}") for condition in conditions))
        for key, value in (
            ("front_site_root", "/"), ("front_site_root", "/var/www/html"), ("front_site_root", "/var/www"),
            ("front_site_state_dir", "/var/lib"), ("front_site_config_path", "/etc/passwd"),
            ("front_site_command_path", "/usr/bin/python3"),
        ):
            results = [self.evaluate("{{ " + condition + " }}", **{key: value}) for condition in conditions]
            self.assertIn(False, results, f"{key}={value}")

    def test_incomplete_settings_fail_the_deploy(self) -> None:
        conditions = self.tasks["Проверка: настройки сайта FRONT"]["ansible.builtin.assert"]["that"]
        good = dict(front_site_seed="cd" * 16, front_site_created="2026-11-28", front_site_language="ru",
                    front_site_title="", front_client_domain="edge.example.invalid",
                    front_origin_domain="origin.example.invalid")
        self.assertTrue(all(self.evaluate("{{ " + condition + " }}", **good) for condition in conditions))
        for key, value in (("front_site_seed", ""), ("front_site_seed", "xyz"), ("front_site_created", ""),
                           ("front_site_language", "de"), ("front_site_title", "x" * 61)):
            results = [
                self.evaluate("{{ " + condition + " }}", **{**good, key: value}) for condition in conditions
            ]
            self.assertIn(False, results, f"{key}={value}")


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Backend(http.server.BaseHTTPRequestHandler):
    """Вместо Xray: отвечает на любой запрос и показывает, что до него дошло."""

    def do_GET(self) -> None:  # noqa: N802 - имя задано http.server
        body = json.dumps({"path": self.path, "state": self.headers.get("X-Client-State-0", "")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *arguments: object) -> None:
        return


class RealNginxTests(unittest.TestCase):
    """Конфигурация роли на настоящем nginx: то, что увидит проверяющий."""

    @classmethod
    def setUpClass(cls) -> None:
        binary = os.environ.get("KALIMERA_TEST_NGINX") or shutil.which("nginx") or "/usr/sbin/nginx"
        mime = os.environ.get("KALIMERA_TEST_NGINX_MIME") or "/etc/nginx/mime.types"
        openssl = shutil.which("openssl")
        if os.name == "nt" or not os.access(binary, os.X_OK) or not Path(mime).is_file() or not openssl:
            raise unittest.SkipTest("нужны nginx, его mime.types и openssl")
        cls.binary, cls.mime = binary, mime
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.base = Path(cls.directory.name)
        subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=origin.example.invalid",
             "-keyout", str(cls.base / "key.pem"), "-out", str(cls.base / "cert.pem")],
            check=True, capture_output=True,
        )
        cls.backend_port = free_port()
        cls.backend = http.server.ThreadingHTTPServer(("127.0.0.1", cls.backend_port), Backend)
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.backend.server_close)
        cls.addClassCleanup(cls.backend.shutdown)
        cls.site_config = config(reserved=[XHTTP_PATH])
        cls.site = SITE.build_site(cls.site_config)
        (cls.base / "www").mkdir()
        SITE.build(cls.site_config, cls.base / "www" / "site", cls.base / "state")

    def start(self, site: bool) -> tuple[int, int]:
        """Запустить nginx с конфигурацией роли; вернуть порты HTTPS и HTTP."""
        tls_port, plain_port = free_port(), free_port()
        work = Path(tempfile.mkdtemp(dir=self.base))
        text = nginx_config(
            site,
            front_xhttp_listen_port=self.backend_port,
            front_origin_cert_path=str(self.base / "cert.pem"),
            front_origin_key_path=str(self.base / "key.pem"),
            front_site_root=str(self.base / "www" / "site"),
        )
        # Только адреса прослушивания: непривилегированный процесс не откроет
        # 80 и 443. Остальной текст - ровно тот, что получает сервер.
        text = text.replace("listen 443 ssl http2;", f"listen 127.0.0.1:{tls_port} ssl http2;")
        text = text.replace("listen 80;", f"listen 127.0.0.1:{plain_port};")
        text = text.replace("    listen [::]:443 ssl http2;\n", "").replace("    listen [::]:80;\n", "")
        (work / "site.conf").write_text(text, encoding="utf-8")
        (work / "nginx.conf").write_text(
            "daemon off;\nmaster_process off;\n"
            f"pid {work}/nginx.pid;\nerror_log {work}/error.log;\n"
            "events { worker_connections 64; }\n"
            "http {\n"
            f"    include {self.mime};\n    default_type application/octet-stream;\n"
            f"    client_body_temp_path {work}/body;\n    proxy_temp_path {work}/proxy;\n"
            f"    fastcgi_temp_path {work}/fastcgi;\n    uwsgi_temp_path {work}/uwsgi;\n"
            f"    scgi_temp_path {work}/scgi;\n"
            f"    include {work}/site.conf;\n"
            "}\n",
            encoding="utf-8",
        )
        command = [self.binary, "-p", str(work), "-c", str(work / "nginx.conf")]
        check = subprocess.run([*command, "-t"], capture_output=True, text=True, check=False)
        self.assertEqual(check.returncode, 0, check.stderr)
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(process.wait)
        self.addCleanup(process.terminate)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", tls_port), timeout=0.5).close()
                return tls_port, plain_port
            except OSError:
                if process.poll() is not None:
                    log = (work / "error.log").read_text(encoding="utf-8", errors="replace")
                    self.fail(f"nginx завершился: {log}")
                time.sleep(0.1)
        self.fail("nginx не начал принимать соединения")

    def fetch(self, port: int, path: str, method: str = "GET", headers: dict | None = None, tls: bool = True):
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=context)
        else:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            connection.request(method, path, headers={"Host": "origin.example.invalid", **(headers or {})})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_probe_sees_a_working_site(self) -> None:
        port, plain = self.start(site=True)
        index = self.site["index.html"][0]

        status, headers, body = self.fetch(port, "/")
        self.assertEqual(status, 200)
        self.assertEqual(body, index)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "max-age=600")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("ETag", headers)
        self.assertIn("Last-Modified", headers)
        # Дата страницы - дата последнего листа, а не минута сборки.
        self.assertEqual(
            time.strptime(headers["Last-Modified"], "%a, %d %b %Y %H:%M:%S GMT")[:6],
            time.gmtime(self.site["index.html"][1])[:6],
        )

        status, headers, body = self.fetch(port, "/", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(headers["Content-Encoding"], "gzip")
        self.assertEqual(headers["Vary"], "Accept-Encoding")
        self.assertEqual(gzip.decompress(body), index)

        status, headers, body = self.fetch(port, "/", method="HEAD")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(int(headers["Content-Length"]), len(index))

        etag = self.fetch(port, "/")[1]["ETag"]
        self.assertEqual(self.fetch(port, "/", headers={"If-None-Match": etag})[0], 304)

        # Каждый файл сайта отдаётся целиком и со своим типом.
        kinds = {".html": "text/html; charset=utf-8", ".css": "text/css",
                 ".js": "application/javascript; charset=utf-8",
                 ".svg": "image/svg+xml", ".xml": "text/xml; charset=utf-8", ".txt": "text/plain; charset=utf-8",
                 ".png": "image/png", ".ico": "image/x-icon"}
        for name, (data, _) in self.site.items():
            if name == "404.html":
                continue
            status, headers, body = self.fetch(port, "/" + name)
            self.assertEqual((status, body), (200, data), name)
            self.assertEqual(headers["Content-Type"], kinds[Path(name).suffix], name)
        style = next(name for name in self.site if name.endswith(".css"))
        self.assertEqual(self.fetch(port, "/" + style)[1]["Cache-Control"], "max-age=2592000")
        drawing = next(name for name in self.site if name.endswith(".svg") and "/" in name)
        status, headers, body = self.fetch(port, "/" + drawing, headers={"Accept-Encoding": "gzip"})
        self.assertEqual(headers.get("Content-Encoding"), "gzip")
        self.assertEqual(gzip.decompress(body), self.site[drawing][0])

        # Страницы открываются по тем адресам, которые стоят в ссылках.
        for target in page_links(index).targets:
            if target.startswith("/"):
                self.assertEqual(self.fetch(port, target)[0], 200, target)

        # Несуществующий адрес: своя страница 404, а не заглушка nginx.
        missing = self.site["404.html"][0]
        for path in ("/no-such-page", "/wp-login.php", "/.env", "/404.html", "/a/b/c/"):
            status, headers, body = self.fetch(port, path)
            self.assertEqual((status, body), (404, missing), path)
            self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")

        # Каталог без завершающей косой черты - перенаправление, как у обычного сайта.
        folder = next((name.split("/")[0] for name in self.site if name.count("/") == 1
                       and name.endswith("/index.html")), None)
        if folder:
            status, headers, _ = self.fetch(port, "/" + folder)
            self.assertEqual(status, 301)
            self.assertTrue(headers["Location"].endswith(f"/{folder}/"), headers["Location"])

        self.assertEqual(self.fetch(port, "/", method="POST")[0], 405)

        status, headers, _ = self.fetch(plain, "/some/page", tls=False)
        self.assertEqual(status, 301)
        self.assertEqual(headers["Location"], "https://origin.example.invalid/some/page")

    def test_xhttp_path_still_reaches_the_backend(self) -> None:
        for site in (True, False):
            port, _ = self.start(site=site)
            payload = "A" * 2900
            status, headers, body = self.fetch(
                port, f"{XHTTP_PATH}/0?x=1", headers={"X-Client-State-0": payload, "Accept-Encoding": "gzip"}
            )
            self.assertEqual(status, 200, site)
            answer = json.loads(body)
            self.assertEqual(answer, {"path": f"{XHTTP_PATH}/0?x=1", "state": payload})
            # Ответ Xray не получает заголовков сайта и не сжимается.
            self.assertNotIn("Cache-Control", headers)
            self.assertNotIn("X-Content-Type-Options", headers)
            self.assertNotIn("Content-Encoding", headers)
            self.assertEqual(headers["Content-Type"], "application/octet-stream")

    def test_without_the_site_the_answer_is_the_old_404(self) -> None:
        port, _ = self.start(site=False)
        status, headers, body = self.fetch(port, "/")
        self.assertEqual(status, 404)
        self.assertIn(b"<center>nginx", body)

    def test_alpn_offers_http2(self) -> None:
        port, _ = self.start(site=True)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname="origin.example.invalid") as secured:
                self.assertEqual(secured.selected_alpn_protocol(), "h2")


if __name__ == "__main__":
    unittest.main()

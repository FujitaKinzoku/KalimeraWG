"""I1 межсерверного канала в форме ответа DNS.

I1 - пакет-приманка, который отправитель шлёт перед каждым рукопожатием.
Прежний I1 канала ENTRY-EXIT имел форму QUIC версии 1 длиной 1200-1252 байта и
подходил под правило, которым в 2022 году блокировали весь QUIC за границу: UDP,
первый пакет не короче 1001 байта, версия QUIC 1. Новый - короткий ответ DNS,
как у официального приложения AmneziaVPN, но свой у каждой установки.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "scripts" / "lib" / "interactive_deploy.py"
SPEC = importlib.util.spec_from_file_location("interactive_deploy_transit_signature", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

GATEWAY = ROOT / "roles" / "security" / "templates" / "kalimera-admin-command.sh.j2"
# Значение defaultSpecialJunk1 из исходников официального клиента AmneziaVPN
# (client/core/utils/constants/protocolConstants.h): ответ DNS на 44 байта.
OFFICIAL_CLIENT_I1 = (
    "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001"
    "c00c000100010000105a00044d583737>"
)


def render(signature: str) -> bytes:
    """Собрать пакет так, как это делает отправитель: <b> дословно, <r> случайно."""
    packet = b""
    for kind, value in re.findall(r"<(r|b) ([0-9a-fx]+)>", signature):
        packet += os.urandom(int(value)) if kind == "r" else bytes.fromhex(value[2:])
    return packet


def parse_dns(packet: bytes) -> dict:
    """Строгий разбор сообщения DNS с одним вопросом и записями A.

    Любое отклонение от формата - исключение: лишние байты, обрезанная запись,
    указатель не на имя из вопроса.
    """
    if len(packet) < 12:
        raise ValueError("короче заголовка")
    counts = [int.from_bytes(packet[offset:offset + 2], "big") for offset in range(4, 12, 2)]
    position = 12
    labels = []
    while True:
        length = packet[position]
        position += 1
        if length == 0:
            break
        if length > 63:
            raise ValueError("недопустимая метка")
        labels.append(packet[position:position + length].decode("ascii"))
        position += length
    question = packet[position:position + 4]
    position += 4
    answers = []
    for _ in range(counts[1]):
        record = packet[position:position + 16]
        if len(record) != 16 or record[:2] != b"\xc0\x0c":
            raise ValueError("запись не ссылается на имя из вопроса")
        if record[2:6] != b"\x00\x01\x00\x01" or record[10:12] != b"\x00\x04":
            raise ValueError("запись не типа A")
        answers.append((int.from_bytes(record[6:10], "big"), tuple(record[12:16])))
        position += 16
    if position != len(packet):
        raise ValueError("лишние байты после записей")
    return {
        "flags": int.from_bytes(packet[2:4], "big"),
        "counts": counts,
        "name": ".".join(labels),
        "question": question,
        "answers": answers,
    }


def matches_broad_quic_rule(packet: bytes) -> bool:
    """Правило 2022 года: пакет не короче 1001 байта с версией QUIC 1."""
    return len(packet) >= 1001 and packet[1:5] == b"\x00\x00\x00\x01"


def quic_profile() -> dict:
    """Профиль канала прежнего вида: I1 в форме QUIC, как у установленных каскадов."""
    profile = MODULE.awg3_transit_obfuscation()
    profile["i1"] = MODULE.transit_signature("quic")
    MODULE.validate_awg_obfuscation(profile)
    return profile


class GeneratorTests(unittest.TestCase):
    def test_signature_is_a_wellformed_dns_response(self) -> None:
        sizes = set()
        for _ in range(300):
            signature = MODULE.awg_dns_response_signature()
            packet = render(signature)
            self.assertEqual(len(packet), MODULE.awg_cps_signature_size(signature))
            message = parse_dns(packet)
            # Ответ рекурсивного резолвера без ошибки, один вопрос.
            self.assertEqual(message["flags"], 0x8180)
            self.assertEqual(message["counts"][0], 1)
            self.assertIn(message["counts"][1], (1, 2, 3))
            self.assertEqual(message["counts"][2:], [0, 0])
            self.assertEqual(message["question"], b"\x00\x01\x00\x01")
            name = message["name"]
            prefix, _, rest = name.partition(".")
            self.assertTrue(
                name in MODULE.AWG_DNS_SIGNATURE_NAMES
                or (prefix in MODULE.AWG_DNS_SIGNATURE_PREFIXES and rest in MODULE.AWG_DNS_SIGNATURE_NAMES),
                name,
            )
            # Записи одного набора: общий срок жизни и одна сеть /24.
            self.assertEqual(len({ttl for ttl, _ in message["answers"]}), 1)
            self.assertTrue(20 <= message["answers"][0][0] <= 600)
            self.assertEqual(len({address[:3] for _, address in message["answers"]}), 1)
            self.assertIn(message["answers"][0][1][0], MODULE.AWG_DNS_SIGNATURE_FIRST_OCTETS)
            sizes.add(len(packet))
        self.assertGreaterEqual(min(sizes), 39)
        self.assertLessEqual(max(sizes), MODULE.AWG_DNS_SIGNATURE_MAX_SIZE)
        self.assertGreater(len(sizes), 10)

    def test_names_fit_dns_and_the_size_limit(self) -> None:
        longest = 0
        for name in MODULE.AWG_DNS_SIGNATURE_NAMES:
            self.assertRegex(name, r"^[a-z0-9-]+\.[a-z]+$")
            for prefix in ("",) + MODULE.AWG_DNS_SIGNATURE_PREFIXES:
                full = f"{prefix}.{name}" if prefix else name
                longest = max(longest, sum(len(label) + 1 for label in full.split(".")) + 1)
        # Номер запроса, заголовок, имя, тип и класс вопроса, три записи.
        self.assertLessEqual(2 + 10 + longest + 4 + 3 * 16, MODULE.AWG_DNS_SIGNATURE_MAX_SIZE)
        self.assertEqual(len(set(MODULE.AWG_DNS_SIGNATURE_NAMES)), len(MODULE.AWG_DNS_SIGNATURE_NAMES))
        for octet in MODULE.AWG_DNS_SIGNATURE_FIRST_OCTETS:
            # Не частные, не служебные и не групповые сети.
            self.assertNotIn(octet, (0, 10, 100, 127, 169, 172, 192, 198, 203))
            self.assertLess(octet, 224)

    def test_dns_signature_cannot_match_the_broad_quic_rule(self) -> None:
        for _ in range(200):
            signature = MODULE.awg_dns_response_signature()
            # Байты на месте версии QUIC: второй байт номера запроса и флаги
            # 0x8180 с началом счётчика вопросов. Флаги в подписи постоянны.
            self.assertTrue(signature.startswith("<r 2><b 0x81800001"), signature)
            self.assertLess(MODULE.awg_cps_signature_size(signature), 1001)
            self.assertFalse(matches_broad_quic_rule(render(signature)))
        # Прежний I1 под это правило подходит: ради этого он и заменён.
        for _ in range(20):
            self.assertTrue(matches_broad_quic_rule(render(MODULE.transit_signature("quic"))))

    def test_signature_uses_only_tags_every_implementation_parses(self) -> None:
        # <b 0x...> и <r N> разбирают и модуль ядра (junk.c), и amneziawg-go.
        for _ in range(100):
            signature = MODULE.awg_dns_response_signature()
            self.assertRegex(signature, r"^(?:<r [0-9]+>|<b 0x(?:[0-9a-f]{2})+>)+$")

    def test_signatures_differ_between_installations(self) -> None:
        signatures = {MODULE.awg_dns_response_signature() for _ in range(200)}
        self.assertGreater(len(signatures), 190)
        self.assertNotIn(OFFICIAL_CLIENT_I1, signatures)

    def test_two_sends_of_one_signature_differ(self) -> None:
        signature = MODULE.awg_dns_response_signature()
        packets = {render(signature) for _ in range(20)}
        self.assertGreater(len(packets), 15)
        self.assertEqual(len({len(packet) for packet in packets}), 1)
        self.assertEqual(len({parse_dns(packet)["name"] for packet in packets}), 1)

    def test_kind_of_a_signature(self) -> None:
        self.assertEqual(MODULE.awg_signature_kind(MODULE.awg_dns_response_signature()), "dns")
        self.assertEqual(MODULE.awg_signature_kind(OFFICIAL_CLIENT_I1), "dns")
        self.assertEqual(MODULE.awg_signature_kind(MODULE.awg_quic_initial_signature()), "quic")
        self.assertEqual(MODULE.awg_signature_kind(MODULE.transit_signature("quic")), "quic")
        for other in ("", None, "<r 40>", "<b 0x4a><r 90>"):
            self.assertEqual(MODULE.awg_signature_kind(other), "other")
        with self.assertRaises(SystemExit), mock.patch("builtins.print"):
            MODULE.transit_signature("stun")

    def test_official_client_signature_is_what_the_comment_says(self) -> None:
        message = parse_dns(render(OFFICIAL_CLIENT_I1))
        self.assertEqual(len(render(OFFICIAL_CLIENT_I1)), 44)
        self.assertEqual(message["name"], "icloud.com")
        self.assertEqual(message["counts"], [1, 1, 0, 0])

    def test_only_the_transit_profile_gets_the_dns_signature(self) -> None:
        for _ in range(20):
            transit = MODULE.awg3_transit_obfuscation()
            self.assertEqual(MODULE.awg_signature_kind(transit["i1"]), "dns")
            # awg-health требует на канале все пять пакетов: I2-I5 остаются.
            self.assertTrue(all(transit[f"i{index}"] for index in range(2, 6)))
        # Клиентские профили идут внутри страны и не меняются.
        for build in (MODULE.awg_server_obfuscation, MODULE.awg_mobile_awg3_obfuscation):
            profile = build()
            self.assertEqual(MODULE.awg_signature_kind(profile["i1"]), "quic", build.__name__)
            self.assertTrue(1200 <= MODULE.awg_cps_signature_size(profile["i1"]) <= 1252)

    def test_new_path_takes_the_kind_of_the_primary_one(self) -> None:
        dns_primary = MODULE.awg3_transit_obfuscation()
        standby = MODULE.standby_transit_profile(dns_primary)
        self.assertEqual(MODULE.awg_signature_kind(standby["i1"]), "dns")
        self.assertNotEqual(standby["i1"], dns_primary["i1"])
        # Владелец вернул QUIC-подобный I1: новый путь получает такой же.
        quic_primary = quic_profile()
        standby = MODULE.standby_transit_profile(quic_primary)
        self.assertEqual(MODULE.awg_signature_kind(standby["i1"]), "quic")
        self.assertEqual(standby["s4"], quic_primary["s4"])

    def test_replacing_the_signature_keeps_the_rest_of_the_profile(self) -> None:
        before = quic_profile()
        signature = MODULE.transit_signature("dns")
        after = MODULE.awg_profile_with_signature(before, signature)
        self.assertEqual(after["i1"], signature)
        self.assertEqual(
            {key: value for key, value in after.items() if key != "i1"},
            {key: value for key, value in before.items() if key != "i1"},
        )
        self.assertEqual(MODULE.awg_signature_kind(before["i1"]), "quic")


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.production = Path(self.directory.name)
        (self.production / "group_vars" / "all").mkdir(parents=True)
        self.transit = quic_profile()
        self.standby = quic_profile()
        self.mobile = MODULE.awg_mobile_awg3_obfuscation()
        self.keenetic = MODULE.awg_server_obfuscation()

    def write(self, standby: bool = True) -> None:
        entry = {
            "entry_awg0_obfuscation": self.keenetic,
            "entry_awg1_obfuscation": dict(self.transit),
            "awg3_transit_obfuscation": dict(self.transit),
            "entry_mobile_awg_obfuscation": dict(self.mobile),
        }
        hosts = {"all": {"children": {"exit": {"hosts": {"exit-managed": {"ansible_host": "192.0.2.20"}}}}}}
        if standby:
            entry["entry_standby_exit_obfuscation"] = dict(self.standby)
            hosts["all"]["children"]["exit"]["hosts"][MODULE.STANDBY_EXIT_HOST] = {
                "ansible_host": "198.51.100.7",
                "exit_awg_obfuscation": dict(self.standby),
                "awg3_transit_obfuscation": dict(self.standby),
            }
        documents = {
            "hosts.yml": hosts,
            "group_vars/all/main.yml": {"awg3_random_trailers": True},
            "group_vars/entry.yml": entry,
            "group_vars/exit.yml": {
                "exit_awg_obfuscation": dict(self.transit),
                "awg3_transit_obfuscation": dict(self.transit),
            },
        }
        for name, document in documents.items():
            (self.production / name).write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    def read(self, name: str) -> dict:
        return yaml.safe_load((self.production / name).read_text(encoding="utf-8"))

    def snapshot(self) -> dict[str, bytes]:
        return {name: (self.production / name).read_bytes() for name in
                ("hosts.yml", "group_vars/all/main.yml", "group_vars/entry.yml", "group_vars/exit.yml")}

    def run_command(self, dns: bool, answer: str = "y") -> bool:
        with mock.patch("builtins.input", return_value=answer), mock.patch("builtins.print"):
            return MODULE.set_transit_signature(self.production, dns)

    def test_enable_changes_the_first_packet_on_both_ends_of_every_link(self) -> None:
        self.write()
        self.assertEqual(MODULE.transit_signature_state(self.production), {"primary": "quic", "standby": "quic"})
        all_before = (self.production / "group_vars" / "all" / "main.yml").read_bytes()
        self.assertTrue(self.run_command(True))
        entry, exit_vars, hosts = self.read("group_vars/entry.yml"), self.read("group_vars/exit.yml"), self.read("hosts.yml")
        standby_host = hosts["all"]["children"]["exit"]["hosts"][MODULE.STANDBY_EXIT_HOST]

        primary = entry["entry_awg1_obfuscation"]
        self.assertEqual(MODULE.awg_signature_kind(primary["i1"]), "dns")
        parse_dns(render(primary["i1"]))
        for copy in (entry["awg3_transit_obfuscation"], exit_vars["exit_awg_obfuscation"],
                     exit_vars["awg3_transit_obfuscation"]):
            self.assertEqual(copy, primary)
        standby = entry["entry_standby_exit_obfuscation"]
        self.assertEqual(MODULE.awg_signature_kind(standby["i1"]), "dns")
        self.assertEqual(standby_host["exit_awg_obfuscation"], standby)
        self.assertEqual(standby_host["awg3_transit_obfuscation"], standby)
        self.assertNotEqual(standby["i1"], primary["i1"])

        # Меняется только I1: ключи, H, S, I2-I5 прежние, перевыпуск не нужен.
        for after, before in ((primary, self.transit), (standby, self.standby)):
            self.assertEqual(
                {key: value for key, value in after.items() if key != "i1"},
                {key: value for key, value in before.items() if key != "i1"},
            )
        # Клиентские профили и общие настройки не тронуты.
        self.assertEqual(entry["entry_awg0_obfuscation"], self.keenetic)
        self.assertEqual(entry["entry_mobile_awg_obfuscation"], self.mobile)
        self.assertEqual((self.production / "group_vars" / "all" / "main.yml").read_bytes(), all_before)
        self.assertEqual(MODULE.transit_signature_state(self.production), {"primary": "dns", "standby": "dns"})

    def test_repeat_and_return_to_quic(self) -> None:
        self.write()
        self.run_command(True)
        enabled = self.snapshot()
        self.assertFalse(self.run_command(True))
        self.assertEqual(self.snapshot(), enabled)

        self.assertTrue(self.run_command(False))
        entry = self.read("group_vars/entry.yml")
        for key in ("entry_awg1_obfuscation", "entry_standby_exit_obfuscation"):
            self.assertEqual(MODULE.awg_signature_kind(entry[key]["i1"]), "quic")
            self.assertTrue(1200 <= MODULE.awg_cps_signature_size(entry[key]["i1"]) <= 1252)
        self.assertEqual(self.read("group_vars/exit.yml")["exit_awg_obfuscation"], entry["entry_awg1_obfuscation"])
        self.assertFalse(self.run_command(False))

    def test_path_left_behind_is_brought_to_the_same_kind(self) -> None:
        # Резервный EXIT подключён позже и получил другой вид: команда не
        # отвечает «уже включено», пока хоть один путь отличается.
        self.transit["i1"] = MODULE.transit_signature("dns")
        self.write()
        self.assertEqual(MODULE.transit_signature_state(self.production), {"primary": "dns", "standby": "quic"})
        self.assertTrue(self.run_command(True))
        self.assertEqual(MODULE.transit_signature_state(self.production), {"primary": "dns", "standby": "dns"})

    def test_cascade_without_standby(self) -> None:
        self.write(standby=False)
        self.assertTrue(self.run_command(True))
        entry = self.read("group_vars/entry.yml")
        self.assertEqual(MODULE.awg_signature_kind(entry["entry_awg1_obfuscation"]["i1"]), "dns")
        self.assertNotIn("entry_standby_exit_obfuscation", entry)
        self.assertEqual(MODULE.transit_signature_state(self.production), {"primary": "dns"})
        self.assertFalse(self.run_command(True))

    def test_nothing_changes_without_confirmation(self) -> None:
        self.write()
        before = self.snapshot()
        with self.assertRaises(SystemExit):
            self.run_command(True, answer="")
        self.assertEqual(self.snapshot(), before)

    def test_incomplete_inventory_stops_before_any_write(self) -> None:
        self.write()
        entry = self.read("group_vars/entry.yml")
        del entry["entry_standby_exit_obfuscation"]
        (self.production / "group_vars" / "entry.yml").write_text(yaml.safe_dump(entry), encoding="utf-8")
        before = self.snapshot()
        with self.assertRaises(SystemExit):
            self.run_command(True)
        self.assertEqual(self.snapshot(), before)

        self.write()
        (self.production / "group_vars" / "exit.yml").write_text("{}\n", encoding="utf-8")
        before = self.snapshot()
        with self.assertRaises(SystemExit):
            self.run_command(True)
        self.assertEqual(self.snapshot(), before)

    def test_warning_says_what_is_and_is_not_touched(self) -> None:
        self.write()
        with mock.patch("builtins.input", return_value="y"), mock.patch("builtins.print") as printed:
            MODULE.set_transit_signature(self.production, True)
        text = "\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
        self.assertIn("ответа DNS", text)
        self.assertIn("перезапустится", text)
        self.assertIn("не затрагиваются", text)


class WiringTests(unittest.TestCase):
    def test_flags_are_wired(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        gateway = GATEWAY.read_text(encoding="utf-8")
        for flag in ("--enable-dns-signature", "--disable-dns-signature"):
            self.assertIn(f'("{flag}", args.{flag[2:].replace("-", "_")}),', source)
            self.assertIn(f"'--resume {flag}'|", gateway)
            self.assertIn(f"{flag},", gateway)
        self.assertIn("set_transit_signature(production, True)", source)
        self.assertIn("set_transit_signature(production, False)", source)

    def test_templates_print_the_signature_as_it_is(self) -> None:
        for path, variable in (
            (ROOT / "roles" / "entry" / "templates" / "awg1.conf.j2", "entry_awg1_obfuscation"),
            (ROOT / "roles" / "entry" / "templates" / "awg-standby.conf.j2", "entry_standby_exit_obfuscation"),
            (ROOT / "roles" / "exit" / "templates" / "awg0.conf.j2", "exit_awg_obfuscation"),
        ):
            self.assertIn(f"I1 = {{{{ {variable}.i1 }}}}", path.read_text(encoding="utf-8"), path.name)


if __name__ == "__main__":
    unittest.main()

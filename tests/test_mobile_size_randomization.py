"""Mobile/AWG3+ без рандомизации размера и проверка полноты его профиля.

С включёнными ContentPaddingAddition и RandomTrailers mobile терял около 5%
пакетов при 0% у профиля balanced с того же клиента. showconf не печатает
ContentPaddingAddition со значением 0, поэтому awg-health не должен требовать
это поле, когда рандомизация выключена, иначе исправный каскад получит FAIL.
"""

from __future__ import annotations

import re
import shlex
import unittest
from pathlib import Path

import jinja2
import yaml


REPO = Path(__file__).parents[1]
HEALTH = REPO / "roles" / "health" / "templates" / "awg-health.sh.j2"
MOBILE_DEFAULTS = REPO / "roles" / "awg3_mobile" / "defaults" / "main.yml"
DEPLOY = REPO / "scripts" / "lib" / "interactive_deploy.py"


def render_mobile_check(**overrides: object) -> str:
    source = HEALTH.read_text(encoding="utf-8")
    match = re.search(
        r"(\{% if awg_node_role == 'entry' and entry_mobile_client_available"
        r".*?mobile_awg31_profile_is_complete\(\) \{.*?\n\}\n\{% endif %\}\n)",
        source,
        re.DOTALL,
    )
    assert match is not None
    env = jinja2.Environment(trim_blocks=True, undefined=jinja2.StrictUndefined)
    env.filters["bool"] = lambda value: str(value).lower() in {"1", "true", "yes", "on"}
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    context = {
        "awg_node_role": "entry",
        "entry_mobile_client_available": True,
        "awg3_mobile_tools_binary_path": "/usr/bin/awg",
        "entry_mobile_client_interface": "awg-mobile",
    }
    context.update(overrides)
    return env.from_string(match.group(1)).render(context)


def field_list(rendered: str) -> list[str]:
    match = re.search(r"for field in ([^;]+); do", rendered)
    assert match is not None
    return match.group(1).split()


class MobileSizeRandomizationTests(unittest.TestCase):
    def test_role_defaults_disable_both_size_fields(self) -> None:
        defaults = yaml.safe_load(MOBILE_DEFAULTS.read_text(encoding="utf-8"))
        self.assertEqual(defaults["awg3_mobile_content_padding_addition"], "0")
        self.assertFalse(defaults["awg3_mobile_random_trailers"])

    def test_fresh_install_writes_the_same_values(self) -> None:
        source = DEPLOY.read_text(encoding="utf-8")
        block = source[source.index("AWG3_MOBILE_FEATURE_DEFAULTS = {"):]
        block = block[: block.index("}") + 1]
        self.assertIn('"content_padding_addition": "0"', block)
        self.assertIn('"random_trailers": False', block)

    def test_health_skips_padding_field_when_it_is_zero(self) -> None:
        for value in ("0", "0-0"):
            with self.subTest(value=value):
                fields = field_list(
                    render_mobile_check(awg3_mobile_content_padding_addition=value)
                )
                self.assertNotIn("ContentPaddingAddition", fields)
                for required in ("HeaderProtectionKey", "RandomTrailers", "I1", "I5"):
                    self.assertIn(required, fields)

    def test_health_requires_padding_field_when_enabled(self) -> None:
        fields = field_list(
            render_mobile_check(awg3_mobile_content_padding_addition="8-32")
        )
        self.assertIn("ContentPaddingAddition", fields)

    def test_health_defaults_to_disabled_padding(self) -> None:
        self.assertNotIn("ContentPaddingAddition", field_list(render_mobile_check()))


if __name__ == "__main__":
    unittest.main()

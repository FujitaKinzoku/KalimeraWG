"""SSH-политика: AllowUsers не склеивается со следующей директивой.

Ansible рендерит шаблоны с trim_blocks=True. Условие {% if %} в конце строки
AllowUsers съедало перевод строки, и sshd получал
"AllowUsers kalimera rootBanner none": root отклонялся на первом этапе
установки, как только истекал ControlPersist-сеанс Ansible.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import jinja2

TEMPLATE = (
    Path(__file__).parents[1] / "roles" / "security" / "templates" / "sshd-awg.conf.j2"
)


def ternary(value, true_value, false_value):
    return true_value if value else false_value


def render(**overrides) -> list[str]:
    environment = jinja2.Environment(
        trim_blocks=True, undefined=jinja2.StrictUndefined, keep_trailing_newline=True
    )
    environment.filters["ternary"] = ternary
    environment.filters["bool"] = lambda value: str(value).lower() in ("true", "yes", "1")
    variables = {
        "security_ssh_host_key_paths": ["/etc/ssh/ssh_host_ed25519_key"],
        "ssh_listen_port": 56777,
        "security_allow_ssh_port_change": False,
        "ansible_port": 56777,
        "ssh_password_authentication": False,
        "security_manage_admin_account": True,
        "security_finalize_admin_access": False,
        "security_admin_user": "kalimera",
        "ansible_user": "root",
        "ssh_root_login": "prohibit-password",
    }
    variables.update(overrides)
    text = environment.from_string(TEMPLATE.read_text(encoding="utf-8")).render(
        **variables
    )
    return text.splitlines()


def allow_users(lines: list[str]) -> list[str]:
    matches = [line for line in lines if line.startswith("AllowUsers")]
    assert len(matches) == 1, matches
    return matches[0].split()[1:]


class SshdAllowUsersTests(unittest.TestCase):
    def test_bootstrap_as_root_keeps_root_and_banner_separate(self) -> None:
        lines = render()
        self.assertEqual(allow_users(lines), ["kalimera", "root"])
        self.assertIn("Banner none", lines)

    def test_bootstrap_as_other_user_adds_that_user(self) -> None:
        lines = render(ansible_user="ubuntu")
        self.assertEqual(allow_users(lines), ["kalimera", "root", "ubuntu"])
        self.assertIn("Banner none", lines)

    def test_resume_as_admin_does_not_duplicate_admin(self) -> None:
        lines = render(ansible_user="kalimera")
        self.assertEqual(allow_users(lines), ["kalimera", "root"])
        self.assertIn("Banner none", lines)

    def test_final_policy_allows_only_admin(self) -> None:
        lines = render(ansible_user="kalimera", security_finalize_admin_access=True)
        self.assertEqual(allow_users(lines), ["kalimera"])
        self.assertIn("PermitRootLogin no", lines)
        self.assertIn("Banner none", lines)

    def test_every_directive_is_on_its_own_line(self) -> None:
        # Значения директив не содержат стыка "строчная+Заглавная"; он
        # появляется, только когда к значению приклеилась следующая директива.
        for user in ("root", "ubuntu", "kalimera"):
            for line in render(ansible_user=user):
                for token in line.split()[1:]:
                    self.assertNotRegex(token, r"[a-z][A-Z]", line)


if __name__ == "__main__":
    unittest.main()

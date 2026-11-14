"""Откат обновления AmneziaWG не зависит от того, отдаёт ли PPA прежнюю версию.

До установки новых пакетов роль берёт предыдущие пакеты из локального
хранилища или из кэша apt, а в PPA обращается только за недостающими. Полный
набор проверяется до изменения системы. После успешной установки и проверки
модуля установленные пакеты попадают в хранилище, откуда берутся при следующем
обновлении.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
ROLE = ROOT / "roles" / "amneziawg"

TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))

STORE_PREPARE = "Подготовка локального хранилища пакетов AmneziaWG"
LOCAL_LOOKUP = "Поиск локальных копий установленных пакетов AmneziaWG"
PPA_FALLBACK = "Загрузка из PPA предыдущих пакетов AmneziaWG, которых нет локально"
COPY_PREVIOUS = "Копирование локальных копий предыдущих пакетов AmneziaWG для отката"
PREVIOUS_LOOKUP = "Поиск предыдущих пакетов AmneziaWG для отката"
PREVIOUS_CHECK = "Проверка, что предыдущие пакеты AmneziaWG готовы для отката"
INSTALL = "Установка выбранных версий пакетов AmneziaWG"
MODPROBE = "Проверка доступности модуля ядра AmneziaWG"
STORE_LOOKUP = "Поиск установленных пакетов AmneziaWG для локального хранилища"
STORE_COPY = "Сохранение установленных пакетов AmneziaWG в локальном хранилище"

REFRESH_ONLY = (
    STORE_PREPARE,
    LOCAL_LOOKUP,
    PPA_FALLBACK,
    COPY_PREVIOUS,
    PREVIOUS_LOOKUP,
    PREVIOUS_CHECK,
    STORE_LOOKUP,
    STORE_COPY,
)


def task_index(name: str) -> int:
    names = [task.get("name") for task in TASKS]
    if names.count(name) != 1:
        raise AssertionError(f"задача не найдена однозначно: {name}")
    return names.index(name)


def task_body(name: str) -> dict:
    return TASKS[task_index(name)]


class AmneziawgRollbackCopiesTests(unittest.TestCase):
    def test_unconditional_ppa_download_is_gone(self) -> None:
        names = [task.get("name") for task in TASKS]
        self.assertNotIn("Предварительная загрузка предыдущих пакетов для гарантированного отката", names)

    def test_local_copies_are_searched_before_ppa_and_checked_before_install(self) -> None:
        self.assertLess(task_index(LOCAL_LOOKUP), task_index(PPA_FALLBACK))
        self.assertLess(task_index(PPA_FALLBACK), task_index(COPY_PREVIOUS))
        self.assertLess(task_index(COPY_PREVIOUS), task_index(PREVIOUS_LOOKUP))
        self.assertLess(task_index(PREVIOUS_LOOKUP), task_index(PREVIOUS_CHECK))
        self.assertLess(task_index(PREVIOUS_CHECK), task_index(INSTALL))

    def test_local_lookup_covers_store_and_apt_cache_with_apt_file_names(self) -> None:
        lookup = task_body(LOCAL_LOOKUP)["ansible.builtin.find"]
        self.assertIn("{{ amneziawg_package_store_dir }}", lookup["paths"])
        self.assertIn("/var/cache/apt/archives", lookup["paths"])
        # Версия в имени файла apt записывается с %3a вместо двоеточия эпохи.
        self.assertIn("replace(':', '%3a')", lookup["patterns"])

    def test_ppa_is_used_only_for_packages_without_local_copy(self) -> None:
        task = task_body(PPA_FALLBACK)
        self.assertIn("rejectattr('matched', 'gt', 0)", task["ansible.builtin.command"]["argv"])
        self.assertIn("length > 0", str(task["when"]))

    def test_previous_package_set_is_verified_before_any_change(self) -> None:
        check = task_body(PREVIOUS_CHECK)["ansible.builtin.assert"]["that"]
        self.assertTrue(
            any("amneziawg_package_names | length" in condition for condition in check),
            check,
        )
        self.assertLess(task_index(PREVIOUS_CHECK), task_index(INSTALL))

    def test_store_is_filled_only_after_successful_install_and_module_check(self) -> None:
        self.assertGreater(task_index(STORE_COPY), task_index(INSTALL))
        self.assertGreater(task_index(STORE_COPY), task_index(MODPROBE))
        self.assertGreater(task_index(STORE_LOOKUP), task_index(MODPROBE))
        dest = task_body(STORE_COPY)["ansible.builtin.copy"]["dest"]
        self.assertIn("amneziawg_package_store_dir", dest)

    def test_store_lives_outside_the_directory_that_refresh_clears(self) -> None:
        store = DEFAULTS["amneziawg_package_store_dir"]
        self.assertTrue(store.startswith("/var/lib/awg-iac/"), store)
        self.assertFalse(store.startswith("/var/cache/awg-iac/"), store)

    def test_refresh_only_tasks_do_not_run_on_normal_deploy(self) -> None:
        for name in REFRESH_ONLY:
            with self.subTest(task=name):
                self.assertIn("awg_package_refresh", str(task_body(name).get("when")))


if __name__ == "__main__":
    unittest.main()

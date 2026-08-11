#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
destination="$repo_root/inventory/production"

command -v ansible-vault >/dev/null 2>&1 || {
    printf 'Требуется ansible-vault. Сначала установите ansible-core.\n' >&2
    exit 1
}

if [[ -e "$destination" ]]; then
    printf 'Отказ от перезаписи существующего файла %s\n' "$destination" >&2
    exit 1
fi

cp -R "$repo_root/inventory/example" "$destination"
mkdir -p "$destination/group_vars/all"

printf 'Создан локальный inventory, исключённый из Git: %s\n' "$destination"
printf 'Сначала отредактируйте hosts.yml и несекретные group_vars.\n'
printf 'Затем создайте зашифрованные переменные через редактор ansible-vault:\n'
printf '  ansible-vault create %q\n' "$destination/group_vars/all/vault.yml"
printf 'Используйте secrets.example.yml только как справочник имён полей; не копируйте реальные секреты в чат или логи.\n'

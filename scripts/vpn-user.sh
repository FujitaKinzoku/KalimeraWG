#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf 'Использование: %s {edit|validate} --vault-password-file /path/outside/repo [vault.yml]\n' "$0" >&2
}

[[ $# -ge 3 && "$2" == --vault-password-file ]] || { usage; exit 2; }
action="$1"
password_file="$3"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vault_file="${4:-$repo_root/inventory/production/group_vars/all/vault.yml}"

[[ "$action" == edit || "$action" == validate ]] || { usage; exit 2; }
for command in ansible-vault python3 realpath; do
    command -v "$command" >/dev/null 2>&1 || { printf 'Требуется команда %s\n' "$command" >&2; exit 1; }
done
[[ -f "$password_file" && -f "$vault_file" ]] || {
    printf 'Не найден зашифрованный Vault или файл пароля.\n' >&2
    exit 1
}

repo_real="$(realpath "$repo_root")"
password_real="$(realpath "$password_file")"
[[ "$password_real" != "$repo_real"/* ]] || {
    printf 'Файл пароля Vault должен находиться за пределами репозитория.\n' >&2
    exit 1
}
[[ -z "$(find "$password_real" -perm /077 -print -quit)" ]] || {
    printf 'Файл пароля Vault не должен быть доступен группе или другим пользователям.\n' >&2
    exit 1
}
head -n 1 "$vault_file" | grep -Eq '^[$]ANSIBLE_VAULT;' || {
    printf 'Отказ от использования незашифрованного Vault.\n' >&2
    exit 1
}

validate_vault() {
    ansible-vault view "$vault_file" --vault-password-file "$password_real" |
        python3 "$repo_root/scripts/lib/validate_vault_peers.py"
}

if [[ "$action" == edit ]]; then
    ansible-vault edit "$vault_file" --vault-password-file "$password_real"
fi
validate_vault
printf 'Зашифрованная модель пиров корректна. Ключи и клиентские конфигурации не выводились.\n'

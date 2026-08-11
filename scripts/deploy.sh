#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf 'Использование: %s --vault-password-file /path/outside/repo --confirm APPLY\n' "$0" >&2
}

vault_password_file=""
confirmation=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vault-password-file) vault_password_file="${2:-}"; shift 2 ;;
        --confirm) confirmation="${2:-}"; shift 2 ;;
        *) usage; exit 2 ;;
    esac
done

[[ "$confirmation" == APPLY && -n "$vault_password_file" ]] || { usage; exit 2; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
inventory="$repo_root/inventory/production/hosts.yml"
vault_file="$repo_root/inventory/production/group_vars/all/vault.yml"

for command in ansible-playbook ansible-inventory; do
    command -v "$command" >/dev/null 2>&1 || { printf 'Требуется команда %s\n' "$command" >&2; exit 1; }
done
[[ -f "$inventory" && -f "$vault_file" && -f "$vault_password_file" ]] || {
    printf 'Не найден production inventory, зашифрованный Vault или файл пароля.\n' >&2
    exit 1
}
head -n 1 "$vault_file" | grep -Eq '^[$]ANSIBLE_VAULT;' || {
    printf 'Отказ от использования незашифрованного Vault: %s\n' "$vault_file" >&2
    exit 1
}

repo_real="$(realpath "$repo_root")"
password_real="$(realpath "$vault_password_file")"
[[ "$password_real" != "$repo_real"/* ]] || {
    printf 'Файл пароля Vault должен находиться за пределами репозитория.\n' >&2
    exit 1
}

cd "$repo_root"
cleanup_needed=true
cleanup() {
    [[ "$cleanup_needed" == true ]] || return 0
    ansible-playbook -i "$inventory" playbooks/cleanup.yml \
        --vault-password-file "$password_real" >/dev/null 2>&1 || true
}
trap cleanup EXIT

./scripts/validate.sh
ansible-inventory -i "$inventory" \
    --vault-password-file "$password_real" --list >/dev/null
ansible-playbook -i "$inventory" playbooks/audit.yml --vault-password-file "$password_real"
ansible-playbook -i "$inventory" playbooks/site.yml --vault-password-file "$password_real" \
    -e awg_adoption_mode=apply
ansible-playbook -i "$inventory" playbooks/verify.yml --vault-password-file "$password_real"
cleanup_needed=false

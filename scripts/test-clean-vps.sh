#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf 'Использование: %s --inventory inventory/test/hosts.yml --vault-password-file /secure/path --confirm DISPOSABLE\n' "$0" >&2
}

inventory=""
password_file=""
confirmation=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --inventory) inventory="${2:-}"; shift 2 ;;
        --vault-password-file) password_file="${2:-}"; shift 2 ;;
        --confirm) confirmation="${2:-}"; shift 2 ;;
        *) usage; exit 2 ;;
    esac
done
[[ "$confirmation" == DISPOSABLE && -n "$inventory" && -n "$password_file" ]] || {
    usage
    exit 2
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
inventory_real="$(realpath "$inventory")"
password_real="$(realpath "$password_file")"
repo_real="$(realpath "$repo_root")"
vault_file="$(dirname "$inventory_real")/group_vars/all/vault.yml"
second_run="$(mktemp)"
cleanup() {
    rm -f -- "$second_run"
    ansible-playbook -i "$inventory_real" playbooks/cleanup.yml \
        --vault-password-file "$password_real" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ "$inventory_real" == "$repo_real/inventory/test/"* ]] || {
    printf 'Inventory должен находиться внутри исключённого каталога inventory/test/.\n' >&2
    exit 1
}
[[ "$password_real" != "$repo_real"/* ]] || {
    printf 'Файл пароля Vault должен находиться за пределами репозитория.\n' >&2
    exit 1
}
if [[ ! -f "$vault_file" ]] || ! head -n 1 "$vault_file" | grep -Eq '^[$]ANSIBLE_VAULT;'; then
    printf 'Не найден зашифрованный тестовый Vault.\n' >&2
    exit 1
fi
[[ -z "$(find "$password_real" -perm /077 -print -quit)" ]] || {
    printf 'Файл пароля Vault не должен быть доступен группе или другим пользователям.\n' >&2
    exit 1
}
for command in ansible ansible-inventory ansible-playbook; do
    command -v "$command" >/dev/null 2>&1 || { printf 'Требуется команда %s\n' "$command" >&2; exit 1; }
done

cd "$repo_root"
export ANSIBLE_NOCOLOR=1
common_args=(
    -i "$inventory_real"
    --vault-password-file "$password_real"
    -e awg_adoption_mode=apply
)

./scripts/validate.sh
ansible-inventory -i "$inventory_real" \
    --vault-password-file "$password_real" --list >/dev/null
ansible-playbook "${common_args[@]}" playbooks/site.yml
ansible-playbook "${common_args[@]}" playbooks/verify.yml

if ! ansible-playbook "${common_args[@]}" playbooks/site.yml >"$second_run"; then
    printf 'Повторное развёртывание завершилось ошибкой. Безопасно проверьте вывод управляющего узла.\n' >&2
    exit 1
fi
if grep -Eq '^[^[:space:]][^:]*[[:space:]]+:[[:space:]]+ok=.*changed=[1-9][0-9]*' "$second_run"; then
    printf 'Проверка идемпотентности не пройдена: повторный deploy сообщил об изменениях.\n' >&2
    grep -E '^[^[:space:]][^:]*[[:space:]]+:[[:space:]]+ok=' "$second_run" >&2
    exit 1
fi
printf 'Проверка идемпотентности пройдена: повторный deploy дал changed=0.\n'

ansible all -i "$inventory_real" --vault-password-file "$password_real" \
    -e awg_test_environment=true -b -m ansible.builtin.reboot \
    -a 'reboot_timeout=600 post_reboot_delay=10'
ansible-playbook "${common_args[@]}" playbooks/verify.yml

printf 'Проверяется прямая RU-маршрутизация при выключенных прокси-службах.\n'
ansible-playbook "${common_args[@]}" -e entry_ru_proxy_enabled=false playbooks/site.yml
ansible-playbook "${common_args[@]}" -e entry_ru_proxy_enabled=false playbooks/verify.yml

printf 'Восстанавливается и проверяется настроенный режим RU-прокси.\n'
ansible-playbook "${common_args[@]}" -e entry_ru_proxy_enabled=true playbooks/site.yml
ansible-playbook "${common_args[@]}" -e entry_ru_proxy_enabled=true playbooks/verify.yml

ansible-playbook "${common_args[@]}" -e awg_test_environment=true playbooks/test-failover.yml
ansible-playbook "${common_args[@]}" playbooks/verify.yml

ansible-playbook "${common_args[@]}" -e awg_test_environment=true playbooks/test-prepare-rollback.yml
ansible-playbook "${common_args[@]}" playbooks/rollback-exit.yml \
    -e rollback_component=awg3 \
    -e rollback_file=/root/config-backups/exit/awg3/acceptance-awg3.conf
ansible-playbook "${common_args[@]}" playbooks/rollback-entry.yml \
    -e rollback_component=awg3 \
    -e rollback_file=/root/config-backups/entry/awg3/acceptance-awg3.conf
ansible exit -i "$inventory_real" --vault-password-file "$password_real" -b -m ansible.builtin.command \
    -a 'cmp --silent /etc/amnezia/amneziawg-v3/awg3.conf /root/config-backups/exit/awg3/acceptance-awg3.conf'
ansible entry -i "$inventory_real" --vault-password-file "$password_real" -b -m ansible.builtin.command \
    -a 'cmp --silent /etc/amnezia/amneziawg-v3/awg3.conf /root/config-backups/entry/awg3/acceptance-awg3.conf'
ansible-playbook "${common_args[@]}" playbooks/verify.yml

printf 'Приёмка чистых VPS пройдена: развёртывание, идемпотентность, перезагрузка, прямой и прокси-режимы, переключение при отказе, восстановление и откат.\n'

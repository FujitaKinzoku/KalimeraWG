#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || {
    echo 'Запустите скрипт от root.' >&2
    exit 1
}

readonly -a RU_DOMAINS=(
    2ip.io
    2ip.ru
    api.ipify.org
    checkip.amazonaws.com
    icanhazip.com
    ifconfig.me
    ip-api.com
    ipinfo.io
    okex.com
    okx.com
    whoer.net
)

readonly -a ENTRY_DOMAINS=(
    online.sberbank.ru
    sberbank.ru
)

readonly -a RU_DIRECT_PORTS=(
    22
    143
    465
    587
    993
    995
    4244
    5222
    5223
    5228
    5242
    7777
    8883
    53535
    56777
)

usage() {
    cat <<'EOF'
Использование: apply-policy-profile.sh [--merge|--replace]

  --merge    добавить недостающие значения, сохранив существующие (по умолчанию)
  --replace  заменить доменные списки и прямые RU-порты готовым профилем
EOF
}

mode=merge
case "${1:-}" in
    ''|--merge) mode=merge ;;
    --replace) mode=replace ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { usage >&2; exit 2; }

for required_command in \
    ru-domain se-domain entry-domain ru-direct-ports awg-health; do
    command -v "$required_command" >/dev/null 2>&1 || {
        echo "Не найдена команда $required_command. Сначала завершите установку KalimeraWG." >&2
        exit 1
    }
done

snapshot_dir="$(mktemp -d /run/awg-policy-profile.XXXXXX)"
readonly snapshot_dir
cleanup() {
    rm -f -- \
        "$snapshot_dir/ru-domain" \
        "$snapshot_dir/se-domain" \
        "$snapshot_dir/entry-domain" \
        "$snapshot_dir/ru-direct-ports"
    rmdir -- "$snapshot_dir" 2>/dev/null || true
}
trap cleanup EXIT

ru-domain list >"$snapshot_dir/ru-domain"
se-domain list >"$snapshot_dir/se-domain"
entry-domain list >"$snapshot_dir/entry-domain"
ru-direct-ports list >"$snapshot_dir/ru-direct-ports"

contains_value() {
    local command_name=$1
    local expected=$2
    local value

    while IFS= read -r value; do
        [[ $value == "$expected" ]] && return 0
    done < <("$command_name" list)
    return 1
}

add_missing_values() {
    local command_name=$1
    shift
    local value

    for value in "$@"; do
        if contains_value "$command_name" "$value"; then
            printf 'Уже настроено: %s → %s\n' "$value" "$command_name"
        else
            "$command_name" add "$value" --defer || return
        fi
    done
}

restore_snapshot() {
    local command_name value
    local restore_failed=false

    echo 'Возврат предыдущей политики...'
    for command_name in ru-domain se-domain entry-domain; do
        "$command_name" clear --defer >/dev/null || restore_failed=true
    done
    ru-direct-ports clear --defer >/dev/null || restore_failed=true

    for command_name in ru-domain se-domain entry-domain ru-direct-ports; do
        while IFS= read -r value; do
            [[ -z $value ]] || "$command_name" add "$value" --defer >/dev/null || restore_failed=true
        done <"$snapshot_dir/$command_name"
    done

    ru-domain sync >/dev/null 2>&1 || restore_failed=true
    ru-direct-ports apply >/dev/null 2>&1 || restore_failed=true

    if [[ $restore_failed == true ]]; then
        echo 'Автоматический возврат выполнен не полностью. Проверьте dnsmasq и маршрутизацию.' >&2
        return 1
    fi
    echo 'Предыдущая политика восстановлена.'
}

apply_profile() {
    if [[ $mode == replace ]]; then
        echo 'Подготовка полной замены пользовательской политики...'
        ru-domain clear --defer || return
        se-domain clear --defer || return
        entry-domain clear --defer || return
        ru-direct-ports clear --defer || return
    fi

    echo 'Подготовка RU-доменов...'
    add_missing_values ru-domain "${RU_DOMAINS[@]}" || return

    echo 'Подготовка доменов прямого маршрута через ENTRY...'
    add_missing_values entry-domain "${ENTRY_DOMAINS[@]}" || return

    echo 'Подготовка TCP-портов в обход RU-прокси...'
    add_missing_values ru-direct-ports "${RU_DIRECT_PORTS[@]}" || return

    echo 'Однократное применение DNS-политики и маршрутизации...'
    ru-domain sync || return
    ru-direct-ports apply || return
}

if apply_profile; then
    :
else
    profile_rc=$?
    echo 'Профиль не применён. Диагностика dnsmasq:' >&2
    systemctl status dnsmasq.service --no-pager --full 2>/dev/null | tail -n 20 >&2 || true
    restore_snapshot || true
    exit "$profile_rc"
fi

printf '\n--- ru-domain ---\n'
ru-domain list
printf '\n--- se-domain ---\n'
se-domain list
printf '\n--- entry-domain ---\n'
entry-domain list
printf '\n--- ru-direct-ports ---\n'
ru-direct-ports list

printf '\n--- итоговая проверка ---\n'
awg-health --strict

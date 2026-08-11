#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf 'Использование: %s DOMAIN {ru|se|entry|exit|direct|default} [каталог доменов]\n' "$0" >&2
}

[[ $# -ge 2 && $# -le 3 ]] || { usage; exit 2; }
domain="$1"
policy="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
domain_directory="${3:-$repo_root/inventory/production/domains}"

[[ -d "$domain_directory" ]] || {
    printf 'Не найден каталог доменов: %s\n' "$domain_directory" >&2
    exit 1
}

python3 "$repo_root/scripts/lib/domain_route.py" \
    --directory "$domain_directory" --domain "$domain" --policy "$policy"

printf 'Проверьте diff, затем примените ENTRY через защищённый сценарий deploy.\n'

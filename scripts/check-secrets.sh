#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

findings="$(mktemp)"
trap 'rm -f "$findings"' EXIT

tracked_or_candidate_files() {
    find . -type f \
        ! -path './.git/*' \
        ! -path './work/*' \
        ! -path './outputs/*' \
        ! -path './inventory/production/*' \
        ! -name '*.tar' \
        ! -name '*.tar.gz' \
        ! -name '*.tgz' \
        -print0
}

while IFS= read -r -d '' file; do
    [[ "$file" == "./scripts/check-secrets.sh" ]] && continue

    case "$file" in
        *.key|*.pem|*.p12|*.pfx|*.pcap|*.pcapng|*.log|*.backup|*.bak)
            printf 'запрещённый файл: %s\n' "$file" >>"$findings"
            continue
            ;;
        *.jpg|*.jpeg|*.png|*.gif|*.webp|*.ico)
            continue
            ;;
    esac

    grep -Ein -- \
        'BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY|[0-9]{6,12}:[A-Za-z0-9_-]{25,}|https?://[^/@[:space:]]+:[^/@[:space:]]+@|(^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{43}=([^A-Za-z0-9+/]|$)' \
        "$file" 2>/dev/null |
        grep -Fv 'REPLACE_ONLY_INSIDE_ENCRYPTED_VAULT' |
        sed "s#^#$file:#" >>"$findings" || true
done < <(tracked_or_candidate_files)

if [[ -s "$findings" ]]; then
    printf 'Обнаружены данные, похожие на секреты:\n' >&2
    cat "$findings" >&2
    exit 1
fi

printf 'Проверка секретов пройдена.\n'

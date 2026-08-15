#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

findings="$(mktemp)"
file_list="$(mktemp)"
trap 'rm -f "$findings" "$file_list"' EXIT

tracked_or_candidate_files() {
    # Игнорируем локальные runtime-файлы штатными правилами Git, но обязательно
    # проверяем любой файл, который уже отслеживается даже после принудительного
    # `git add -f inventory/production/...`.
    git ls-files -z --cached --others --exclude-standard
}

if ! tracked_or_candidate_files >"$file_list"; then
    printf '%s\n' 'Не удалось получить проверяемый список файлов Git.' >&2
    exit 1
fi

while IFS= read -r -d '' file; do
    file="./${file#./}"
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
        'BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY|[0-9]{6,12}:[A-Za-z0-9_-]{25,}|github_pat_[A-Za-z0-9_]{40,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}[.][A-Za-z0-9_-]{10,}[.][A-Za-z0-9_-]{10,}|https?://[^/@[:space:]]+:[^/@[:space:]]+@|(^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{43}=([^A-Za-z0-9+/]|$)' \
        "$file" 2>/dev/null |
        grep -Fv 'REPLACE_ONLY_INSIDE_ENCRYPTED_VAULT' |
        sed "s#^#$file:#" >>"$findings" || true
done <"$file_list"

if [[ -s "$findings" ]]; then
    printf 'Обнаружены данные, похожие на секреты:\n' >&2
    cat "$findings" >&2
    exit 1
fi

printf 'Проверка секретов пройдена.\n'

#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf 'Использование: %s --vault-password-file /secure/pass --client-secrets-file /secure/client.env\n' "$0" >&2
}

password_file=""
client_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vault-password-file) password_file="${2:-}"; shift 2 ;;
        --client-secrets-file) client_file="${2:-}"; shift 2 ;;
        *) usage; exit 2 ;;
    esac
done
[[ -n "$password_file" && -n "$client_file" ]] || { usage; exit 2; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "$repo_root/scripts/lib/create_test_vault.py" \
    --repo-root "$repo_root" \
    --vault-password-file "$password_file" \
    --client-secrets-file "$client_file"

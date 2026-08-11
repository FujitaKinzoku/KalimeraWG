#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY_URL="https://github.com/FujitaKinzoku/KalimeraWG.git"
readonly REPOSITORY_BRANCH="main"
readonly INSTALL_DIR="${KALIMERA_DIR:-/root/KalimeraWG}"

fail() {
    printf 'Ошибка: %s\n' "$*" >&2
    exit 1
}

(( EUID == 0 )) || fail 'запустите установку от root'

[[ -r /etc/os-release ]] || fail 'не удалось определить операционную систему'
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] ||
    fail 'требуется чистая Ubuntu 24.04 LTS'

if [[ -e "$INSTALL_DIR" ]]; then
    fail "каталог $INSTALL_DIR уже существует; используйте находящийся в нём ./deploy --resume"
fi

printf '%s\n' 'Установка Git и сертификатов...'
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=5 -o DPkg::Lock::Timeout=600 update
apt-get -o Acquire::Retries=5 -o DPkg::Lock::Timeout=600 \
    install -y --no-install-recommends git ca-certificates

printf '%s\n' 'Загрузка KalimeraWG...'
git clone --depth 1 --branch "$REPOSITORY_BRANCH" "$REPOSITORY_URL" "$INSTALL_DIR"
chmod 0755 "$INSTALL_DIR/deploy"

printf '%s\n' 'Запуск интерактивного развёртывания...'
cd "$INSTALL_DIR"
exec ./deploy

#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY_URL="https://github.com/FujitaKinzoku/KalimeraWG.git"
readonly REPOSITORY_REF="${KALIMERA_VERSION:-v2.0.1}"
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
git clone --depth 1 --branch "$REPOSITORY_REF" "$REPOSITORY_URL" "$INSTALL_DIR"

installed_version="$(tr -d '[:space:]' < "$INSTALL_DIR/VERSION")"
expected_version="${REPOSITORY_REF#v}"
[[ "$installed_version" == "$expected_version" ]] ||
    fail "версия файлов $installed_version не совпадает с выбранным выпуском $REPOSITORY_REF"

chmod 0755 "$INSTALL_DIR/deploy"

printf 'Запуск KalimeraWG v%s...\n' "$installed_version"
cd "$INSTALL_DIR"
exec ./deploy

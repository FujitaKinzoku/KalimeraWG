#!/usr/bin/env bash
# Применяет приоритет при нехватке памяти к уже работающим службам каскада.
# Настройка systemd OOMScoreAdjust действует с запуска службы, а перезапускать
# ради неё DNS и прокси незачем. Печатает число процессов, у которых приоритет
# изменён.
#
# Использование: kalimera-oom-apply ЗНАЧЕНИЕ СЛУЖБА...
set -Eeuo pipefail

if (( $# < 2 )) || [[ ! "$1" =~ ^-?[0-9]+$ ]] || (( $1 < -1000 || $1 > 1000 )); then
    echo 'Использование: kalimera-oom-apply ЗНАЧЕНИЕ СЛУЖБА...' >&2
    exit 2
fi
readonly adjust="$1"
shift

cgroup_root="${KALIMERA_CGROUP_ROOT:-/sys/fs/cgroup}"
proc_root="${KALIMERA_PROC_ROOT:-/proc}"

changed=0
for unit in "$@"; do
    group="$(systemctl show --property=ControlGroup --value "$unit" 2>/dev/null || true)"
    [[ -n "$group" && -r "$cgroup_root$group/cgroup.procs" ]] || continue
    while IFS= read -r pid; do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        current="$(cat "$proc_root/$pid/oom_score_adj" 2>/dev/null || true)"
        [[ -n "$current" && "$current" != "$adjust" ]] || continue
        # Процесс мог завершиться между чтением списка и записью.
        if printf '%s\n' "$adjust" >"$proc_root/$pid/oom_score_adj" 2>/dev/null; then
            changed=$((changed + 1))
        fi
    done <"$cgroup_root$group/cgroup.procs"
done
printf '%d\n' "$changed"

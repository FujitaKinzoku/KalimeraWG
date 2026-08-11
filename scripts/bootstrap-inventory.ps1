param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $repoRoot 'inventory\production'

if (-not (Get-Command ansible-vault -ErrorAction SilentlyContinue)) {
    throw 'Требуется ansible-vault. Установите ansible-core в WSL или на управляющем компьютере.'
}
if (Test-Path -LiteralPath $destination) {
    throw "Отказ от перезаписи существующего каталога $destination"
}

Copy-Item -Recurse -LiteralPath (Join-Path $repoRoot 'inventory\example') -Destination $destination
New-Item -ItemType Directory -Force -Path (Join-Path $destination 'group_vars\all') | Out-Null

Write-Output "Создан локальный inventory, исключённый из Git: $destination"
Write-Output 'Сначала отредактируйте hosts.yml и несекретные group_vars.'
Write-Output 'Затем создайте зашифрованные переменные командой:'
Write-Output "  ansible-vault create `"$destination\group_vars\all\vault.yml`""
Write-Output 'Используйте secrets.example.yml только как справочник имён полей; никогда не вставляйте реальные секреты в чат или журналы.'

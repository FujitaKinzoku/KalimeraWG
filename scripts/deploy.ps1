param(
    [Parameter(Mandatory = $true)]
    [string]$VaultPasswordFile,
    [Parameter(Mandatory = $true)]
    [ValidateSet('APPLY')]
    [string]$Confirm
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$inventory = Join-Path $repoRoot 'inventory\production\hosts.yml'
$vaultFile = Join-Path $repoRoot 'inventory\production\group_vars\all\vault.yml'
$passwordPath = [IO.Path]::GetFullPath($VaultPasswordFile)
$repoPath = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\') + '\'

foreach ($command in @('ansible-playbook', 'ansible-inventory')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Требуется команда $command. Если она недоступна в Windows, запускайте развёртывание из WSL/Linux."
    }
}
foreach ($path in @($inventory, $vaultFile, $passwordPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Отсутствует обязательный файл: $path"
    }
}
if ($passwordPath.StartsWith($repoPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Файл пароля Vault должен находиться за пределами репозитория.'
}
if ((Get-Content -LiteralPath $vaultFile -TotalCount 1) -notmatch '^\$ANSIBLE_VAULT;') {
    throw "Отказ от использования незашифрованного файла Vault: $vaultFile"
}

Push-Location $repoRoot
try {
    & "$PSScriptRoot\validate.ps1"
    if ($LASTEXITCODE -ne 0) { throw 'Проверка репозитория не пройдена.' }
    & ansible-inventory -i $inventory --vault-password-file $passwordPath --list | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Проверка production inventory не пройдена.' }
    & ansible-playbook -i $inventory playbooks/audit.yml --vault-password-file $passwordPath
    if ($LASTEXITCODE -ne 0) { throw 'Аудит не пройден; развёртывание не запускалось.' }
    & ansible-playbook -i $inventory playbooks/site.yml --vault-password-file $passwordPath `
        -e awg_adoption_mode=apply
    if ($LASTEXITCODE -ne 0) { throw 'Развёртывание завершилось с ошибкой.' }
    & ansible-playbook -i $inventory playbooks/verify.yml --vault-password-file $passwordPath
    if ($LASTEXITCODE -ne 0) { throw 'Проверка после развёртывания не пройдена.' }
}
finally {
    if ((Test-Path -LiteralPath $inventory -PathType Leaf) -and
        (Test-Path -LiteralPath $passwordPath -PathType Leaf) -and
        (Get-Command ansible-playbook -ErrorAction SilentlyContinue)) {
        & ansible-playbook -i $inventory playbooks/cleanup.yml --vault-password-file $passwordPath *> $null
    }
    Pop-Location
}

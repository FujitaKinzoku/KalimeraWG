$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

& "$PSScriptRoot/check-secrets.ps1"

$ansible = Get-Command ansible-playbook -ErrorAction SilentlyContinue
if (-not $ansible) {
    Write-Warning 'ansible-playbook не установлен; проверки синтаксиса пропущены.'
    exit 0
}

foreach ($playbook in @(
    'playbooks/audit.yml',
    'playbooks/site.yml',
    'playbooks/entry.yml',
    'playbooks/exit.yml',
    'playbooks/verify.yml',
    'playbooks/finalize-monitoring.yml',
    'playbooks/rollback-entry.yml',
    'playbooks/rollback-exit.yml',
    'playbooks/test-failover.yml',
    'playbooks/test-prepare-rollback.yml',
    'playbooks/cleanup.yml',
    'tests/render-shell.yml',
    'tests/check-sing-box.yml',
    'tests/check-ansible-filters.yml'
)) {
    & ansible-playbook --syntax-check $playbook
    if ($LASTEXITCODE -ne 0) {
        throw "Проверка синтаксиса Ansible не пройдена: $playbook"
    }
}

& python -m compileall -q scripts tests
if ($LASTEXITCODE -ne 0) { throw 'Проверка синтаксиса Python не пройдена.' }
& python -m unittest discover -s tests -p 'test_*.py'
if ($LASTEXITCODE -ne 0) { throw 'Unit-тесты Python не пройдены.' }

Write-Output 'Проверка репозитория пройдена.'

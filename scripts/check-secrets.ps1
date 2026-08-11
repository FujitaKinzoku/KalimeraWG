$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$repoPrefix = $repoRoot.TrimEnd('\') + '\'
$forbiddenExtensions = @('.key', '.pem', '.p12', '.pfx', '.pcap', '.pcapng', '.log', '.bak')
$binaryImageExtensions = @('.jpg', '.jpeg', '.png', '.gif', '.webp', '.ico')
$secretPattern = 'BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY|[0-9]{6,12}:[A-Za-z0-9_-]{25,}|https?://[^/@\s]+:[^/@\s]+@|(^|[^A-Za-z0-9+/])[A-Za-z0-9+/]{43}=([^A-Za-z0-9+/]|$)'
$findings = [System.Collections.Generic.List[string]]::new()

$files = Get-ChildItem -LiteralPath $repoRoot -Recurse -File | Where-Object {
    $relative = $_.FullName.Substring($repoPrefix.Length).Replace('\', '/')
    $relative -notmatch '^(\.git|work|outputs|inventory/production)/' -and
    $relative -ne 'scripts/check-secrets.ps1' -and
    $relative -ne 'scripts/check-secrets.sh' -and
    $_.Name -notmatch '\.(tar|tar\.gz|tgz)$'
}

foreach ($file in $files) {
    $relative = $file.FullName.Substring($repoPrefix.Length).Replace('\', '/')

    if ($forbiddenExtensions -contains $file.Extension.ToLowerInvariant() -or $file.Name -match '\.backup(?:\.|$)') {
        $findings.Add("запрещённый файл: $relative")
        continue
    }

    if ($binaryImageExtensions -contains $file.Extension.ToLowerInvariant()) {
        continue
    }

    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue) {
        $lineNumber++
        if ($line -match $secretPattern -and $line -notmatch 'REPLACE_ONLY_INSIDE_ENCRYPTED_VAULT') {
            $findings.Add("${relative}:${lineNumber}: возможные секретные данные")
        }
    }
}

if ($findings.Count -gt 0) {
    $findings | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'Проверка секретов пройдена.'

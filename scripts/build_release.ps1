param(
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Dist = Join-Path $Root 'dist'

$plugin = Get-Content -Raw -LiteralPath (Join-Path $Root 'plugin.json') | ConvertFrom-Json
$codexPlugin = Get-Content -Raw -LiteralPath (Join-Path $Root '.codex-plugin\plugin.json') | ConvertFrom-Json
$serverText = Get-Content -Raw -LiteralPath (Join-Path $Root 'server\src_guarded_mcp.py')
$match = [regex]::Match($serverText, 'SERVER_VERSION\s*=\s*"([^"]+)"')
if (-not $match.Success) { throw 'Unable to read SERVER_VERSION' }
$serverVersion = $match.Groups[1].Value
if ($plugin.version -ne $codexPlugin.version -or $plugin.version -ne $serverVersion) {
    throw "Version mismatch: plugin=$($plugin.version), codex-plugin=$($codexPlugin.version), server=$serverVersion"
}

if (-not $SkipTests) {
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed; release build aborted.' }
}

New-Item -ItemType Directory -Path $Dist -Force | Out-Null
$targets = @(
    (Join-Path $Dist 'src-guarded-workflow'),
    (Join-Path $Dist 'src-guarded-workflow-migration'),
    (Join-Path $Dist 'src-guarded-workflow-migration.zip'),
    (Join-Path $Dist 'src-guarded-workflow-portable.zip')
)
foreach ($target in $targets) {
    if (Test-Path -LiteralPath $target) {
        $resolved = (Resolve-Path -LiteralPath $target).Path
        if (-not $resolved.StartsWith($Dist + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove outside dist: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

$pluginTarget = Join-Path $Dist 'src-guarded-workflow'
New-Item -ItemType Directory -Path $pluginTarget -Force | Out-Null
$items = @(
    'plugin.json', 'mcp.json', '.codex-plugin', 'skills', 'scripts', 'server', 'schemas',
    'templates', 'config', 'knowledge', 'requirements.txt', 'README.md', 'CHANGELOG.md',
    'AGENTS.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md'
)
foreach ($item in $items) {
    $from = Join-Path $Root $item
    if (Test-Path -LiteralPath $from) {
        Copy-Item -LiteralPath $from -Destination $pluginTarget -Recurse -Force
    }
}

$migration = Join-Path $Dist 'src-guarded-workflow-migration'
New-Item -ItemType Directory -Path $migration -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $Root '.agents') -Destination $migration -Recurse -Force
$migrationPlugin = Join-Path $migration 'src-workflow'
New-Item -ItemType Directory -Path $migrationPlugin -Force | Out-Null
Copy-Item -Path (Join-Path $pluginTarget '*') -Destination $migrationPlugin -Recurse -Force
foreach ($file in @('install.ps1', 'install.sh', 'README.md')) {
    Copy-Item -LiteralPath (Join-Path $Root "migration\$file") -Destination $migration -Force
}

Compress-Archive -Path (Join-Path $pluginTarget '*') -DestinationPath (Join-Path $Dist 'src-guarded-workflow-portable.zip') -Force
Compress-Archive -Path (Join-Path $migration '*') -DestinationPath (Join-Path $Dist 'src-guarded-workflow-migration.zip') -Force

Write-Output "Built src-guarded-workflow $($plugin.version)"
Write-Output (Join-Path $Dist 'src-guarded-workflow-portable.zip')
Write-Output (Join-Path $Dist 'src-guarded-workflow-migration.zip')

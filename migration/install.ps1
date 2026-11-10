param(
    [switch]$SkipDependencies
)

$ErrorActionPreference = 'Stop'
$BundleRoot = (Resolve-Path $PSScriptRoot).Path
$PluginRoot = Join-Path $BundleRoot 'src-workflow'

if (-not (Test-Path -LiteralPath (Join-Path $PluginRoot 'plugin.json'))) {
    throw "Migration bundle is incomplete: $PluginRoot"
}

$MarketplacePath = Join-Path $BundleRoot '.agents\plugins\marketplace.json'
if (Test-Path -LiteralPath $MarketplacePath) {
    $market = Get-Content -Raw -LiteralPath $MarketplacePath | ConvertFrom-Json
    foreach ($plugin in @($market.plugins)) {
        if ($plugin.name -eq 'src-guarded-workflow') {
            .source.path = './src-workflow'
        }
    }
    $market | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $MarketplacePath -Encoding utf8
}
if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
    throw 'Codex CLI is not installed or not in PATH.'
}

$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) { $Python = Get-Command py -ErrorAction SilentlyContinue }
if (-not $Python) { throw 'Python 3 is required.' }

$McpPath = Join-Path $PluginRoot 'mcp.json'
$mcp = Get-Content -Raw -LiteralPath $McpPath | ConvertFrom-Json
$mcp.mcpServers.srcGuardedWorkflow.command = $Python.Source
$mcp | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $McpPath -Encoding utf8

if (-not $SkipDependencies) {
    & $Python.Source -m pip install -r (Join-Path $PluginRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
}

$MarketplaceRoot = ($BundleRoot -replace '\\', '/')
& codex plugin marketplace add $MarketplaceRoot --json
if ($LASTEXITCODE -ne 0) {
    Write-Warning 'Marketplace may already be registered; continuing to plugin install.'
}

& codex plugin add 'src-guarded-workflow@codex-local' --json
if ($LASTEXITCODE -ne 0) { throw 'Plugin installation failed.' }

Write-Output 'Migration complete.'
Write-Output 'Restart the Codex desktop app, then start a new chat and provide the SRC program, authorized asset, and authorization confirmation.'

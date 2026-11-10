param(
    [switch]$Force,
    [switch]$SkipDependencies,
    [string]$DestinationRoot = $env:USERPROFILE
)

$ErrorActionPreference = 'Stop'
$Source = (Resolve-Path $PSScriptRoot).Path
$HomeRoot = $DestinationRoot
$SkillTarget = Join-Path $HomeRoot '.agents\skills\src-bug-bounty'
$PluginTarget = Join-Path $HomeRoot '.agents\plugins\src-guarded-workflow'
$MarketplacePath = Join-Path $HomeRoot '.agents\plugins\marketplace.json'
$MarketplaceRoot = Join-Path $HomeRoot '.agents\plugins'

if ((Test-Path $SkillTarget) -and -not $Force) {
    throw "Skill target already exists: $SkillTarget. Use -Force to update."
}
if ((Test-Path $PluginTarget) -and -not $Force) {
    throw "Plugin target already exists: $PluginTarget. Use -Force to update."
}

New-Item -ItemType Directory -Path $MarketplaceRoot -Force | Out-Null
New-Item -ItemType Directory -Path $SkillTarget -Force | Out-Null
New-Item -ItemType Directory -Path $PluginTarget -Force | Out-Null

Copy-Item -LiteralPath (Join-Path $Source 'skills\src-bug-bounty\SKILL.md') -Destination $SkillTarget -Force
Copy-Item -LiteralPath (Join-Path $Source 'skills\src-bug-bounty\references') -Destination $SkillTarget -Recurse -Force

$items = @('plugin.json', 'mcp.json', '.codex-plugin', 'skills', 'scripts', 'server', 'schemas', 'templates', 'config', 'knowledge', 'requirements.txt', 'README.md', 'CHANGELOG.md', 'AGENTS.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md')
foreach ($item in $items) {
    $from = Join-Path $Source $item
    if (Test-Path $from) {
        Copy-Item -LiteralPath $from -Destination $PluginTarget -Recurse -Force
    }
}

$entry = [ordered]@{
    name = 'src-guarded-workflow'
    source = [ordered]@{ source = 'local'; path = './.agents/plugins/src-guarded-workflow' }
    policy = [ordered]@{ installation = 'AVAILABLE'; authentication = 'ON_INSTALL' }
    category = 'Security'
}

if (Test-Path $MarketplacePath) {
    $market = Get-Content -Raw -LiteralPath $MarketplacePath | ConvertFrom-Json
    $plugins = @($market.plugins | Where-Object { $_.name -ne $entry.name })
    $plugins += [pscustomobject]$entry
    $market | Add-Member -NotePropertyName plugins -NotePropertyValue $plugins -Force
} else {
    $market = [pscustomobject][ordered]@{
        name = 'codex-local'
        plugins = @([pscustomobject]$entry)
    }
}

$market | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $MarketplacePath -Encoding utf8

if (-not $SkipDependencies) {
    $requirements = Join-Path $PluginTarget 'requirements.txt'
    python -m pip install -r $requirements
}

Write-Output "Installed skill: $SkillTarget"
Write-Output "Installed plugin: $PluginTarget"
Write-Output "Marketplace: $MarketplacePath"
Write-Output "Restart the Codex desktop app, then enable src-guarded-workflow from the local marketplace."



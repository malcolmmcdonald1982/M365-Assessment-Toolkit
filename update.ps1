<#
.SYNOPSIS
    M365 Assessment Toolkit - Updater
.DESCRIPTION
    Downloads and applies the latest version from GitHub.
    Preserves all saved sessions, reports and output files.

    Usage:
        irm https://raw.githubusercontent.com/malcolmmcdonald1982/m365-assessment-toolkit/main/update.ps1 | iex
#>

[CmdletBinding()]
param(
    [string]$InstallPath  = "C:\M365 Assessment Toolkit",
    [string]$RepoUrl      = "https://github.com/malcolmmcdonald1982/m365-assessment-toolkit",
    [string]$RawBaseUrl   = "https://raw.githubusercontent.com/malcolmmcdonald1982/m365-assessment-toolkit/main",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

function Write-Header { param($t) Write-Host "`n$t" -ForegroundColor Cyan }
function Write-OK     { param($t) Write-Host "  [OK]  $t" -ForegroundColor Green }
function Write-Warn   { param($t) Write-Host "  [!!]  $t" -ForegroundColor Yellow }
function Write-Fail   { param($t) Write-Host "  [XX]  $t" -ForegroundColor Red }
function Write-Step   { param($t) Write-Host "  -->   $t" -ForegroundColor White }

Clear-Host
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  M365 Assessment Toolkit - Updater" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# Check install exists
if (-not (Test-Path $InstallPath)) {
    Write-Fail "Install path not found: $InstallPath"
    Write-Fail "Run install.ps1 first."
    exit 1
}

# Check current version
$LocalVersion  = "unknown"
$RemoteVersion = "unknown"
$LocalVerFile  = Join-Path $InstallPath "VERSION"
if (Test-Path $LocalVerFile) {
    $LocalVersion = (Get-Content $LocalVerFile -Raw).Trim()
    Write-OK "Current version: $LocalVersion"
}

# Fetch remote version
Write-Header "Checking for updates..."
try {
    $RemoteVersion = (Invoke-RestMethod "$RawBaseUrl/VERSION" -ErrorAction Stop).Trim()
    Write-OK "Latest version: $RemoteVersion"
} catch {
    Write-Warn "Could not reach GitHub to check for updates."
    Write-Warn "Check your internet connection."
    if (-not $Force) { exit 1 }
}

if ($LocalVersion -eq $RemoteVersion -and -not $Force) {
    Write-OK "Already up to date (v$LocalVersion). Use -Force to reinstall."
    exit 0
}

Write-Header "Downloading update v$RemoteVersion..."

# Files to update (never touch output/, reports/, or session files)
$UpdateFiles = @(
    "backend.py",
    "index.html",
    "generate-report.js",
    "package.json",
    "scripts/Get-IdentityMetrics.ps1",
    "scripts/Get-SecurityMetrics.ps1",
    "scripts/Get-ExchangeMetrics.ps1",
    "scripts/Get-TeamsMetrics.ps1",
    "scripts/Get-SharePointMetrics.ps1",
    "scripts/Get-IntuneMetrics.ps1",
    "scripts/Test-AppRegistrationPermissions.ps1",
    "remediation/Remediate-LegacyAuth.ps1",    "remediation/Rollback-LegacyAuth.ps1",
    "remediation/Remediate-MailboxAudit.ps1",  "remediation/Rollback-MailboxAudit.ps1",
    "remediation/Remediate-ExternalForwarding.ps1", "remediation/Rollback-ExternalForwarding.ps1",
    "remediation/Remediate-AntiPhish.ps1",     "remediation/Rollback-AntiPhish.ps1",
    "remediation/Remediate-MFAFatigue.ps1",    "remediation/Rollback-MFAFatigue.ps1",
    "remediation/Remediate-WeakAuth.ps1",      "remediation/Rollback-WeakAuth.ps1",
    "remediation/Remediate-UserConsent.ps1",   "remediation/Rollback-UserConsent.ps1",
    "remediation/Remediate-TeamsConsumer.ps1", "remediation/Rollback-TeamsConsumer.ps1",
    "remediation/Remediate-SPOLegacyAuth.ps1", "remediation/Rollback-SPOLegacyAuth.ps1"
)

$Updated = 0
$Failed  = 0
foreach ($RelPath in $UpdateFiles) {
    $RemoteUrl = "$RawBaseUrl/$($RelPath.Replace('\','/'))"
    $LocalPath = Join-Path $InstallPath $RelPath
    try {
        Invoke-WebRequest -Uri $RemoteUrl -OutFile $LocalPath -ErrorAction Stop
        Write-OK "Updated: $RelPath"
        $Updated++
    } catch {
        Write-Warn "Could not update: $RelPath"
        $Failed++
    }
}

# Update VERSION file
"$RemoteVersion" | Out-File -FilePath $LocalVerFile -Encoding ASCII -Force

# Re-run npm install for any new dependencies
Write-Header "Updating npm packages..."
Push-Location $InstallPath
try {
    & npm install --quiet 2>&1 | Out-Null
    Write-OK "npm packages updated"
} catch {
    Write-Warn "npm update failed"
}
Pop-Location

Write-Host "`n======================================================" -ForegroundColor Cyan
Write-OK "Updated to v$RemoteVersion ($Updated files, $Failed skipped)"
Write-Host "  Restart the tool to apply the update." -ForegroundColor White
Write-Host "  Your saved sessions and reports are untouched." -ForegroundColor White
Write-Host "======================================================`n" -ForegroundColor Cyan


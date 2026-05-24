#Requires -Version 5.1
<#
.SYNOPSIS
    build-release.ps1 — M365 Assessment Toolkit
    Packages the release files into a zip ready to attach to a GitHub release.
.USAGE
    .\build-release.ps1
    Output: C:\AssetTool\release\M365-Assessment-Toolkit-v<version>.zip
#>

$ErrorActionPreference = "Stop"

# Read version
$Version = (Get-Content "$PSScriptRoot\VERSION" -Raw).Trim()
$ZipName = "M365-Assessment-Toolkit-v$Version.zip"
$ReleaseDir = "$PSScriptRoot\release"
$ZipPath = "$ReleaseDir\$ZipName"

# Files and folders to include
$Include = @(
    "backend.py",
    "index.html",
    "generate-report.js",
    "package.json",
    "requirements.txt",
    "install.ps1",
    "update.ps1",
    "uninstall.ps1",
    "VERSION",
    "CHANGELOG.md",
    "README.md",
    "LICENSE",
    "scripts",
    "remediation",
    "docs"
)

# Create release folder if it doesn't exist
if (-not (Test-Path $ReleaseDir)) {
    New-Item -ItemType Directory -Path $ReleaseDir | Out-Null
}

# Remove existing zip if present
if (Test-Path $ZipPath) {
    Remove-Item $ZipPath -Force
}

# Build a temp staging folder
$TempDir = "$env:TEMP\M365-Assessment-Toolkit-v$Version"
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -ItemType Directory -Path $TempDir | Out-Null

foreach ($item in $Include) {
    $Source = "$PSScriptRoot\$item"
    if (Test-Path $Source) {
        Copy-Item $Source "$TempDir\$item" -Recurse
    } else {
        Write-Host "  SKIP (not found): $item" -ForegroundColor Yellow
    }
}

# Zip it
Compress-Archive -Path "$TempDir\*" -DestinationPath $ZipPath

# Clean up temp
Remove-Item $TempDir -Recurse -Force

Write-Host ""
Write-Host "Release zip built successfully:" -ForegroundColor Green
Write-Host "  $ZipPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next step: attach this file to the v$Version release on GitHub." -ForegroundColor Gray

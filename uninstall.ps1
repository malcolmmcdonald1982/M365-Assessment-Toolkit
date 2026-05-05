<#
.SYNOPSIS
    M365 Assessment Toolkit - Uninstaller
.DESCRIPTION
    Cleanly removes the M365 Assessment Toolkit.
    Optionally preserves saved sessions and reports.
#>

[CmdletBinding()]
param(
    [string]$InstallPath  = "C:\M365 Assessment Toolkit",
    [switch]$KeepData,
    [switch]$Force
)

function Write-Header { param($t) Write-Host "`n$t" -ForegroundColor Cyan }
function Write-OK     { param($t) Write-Host "  [OK]  $t" -ForegroundColor Green }
function Write-Warn   { param($t) Write-Host "  [!!]  $t" -ForegroundColor Yellow }
function Write-Step   { param($t) Write-Host "  -->   $t" -ForegroundColor White }
function Write-Blank   { Write-Host "" }

Clear-Host
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  M365 Assessment Toolkit - Uninstaller" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

if (-not (Test-Path $InstallPath)) {
    Write-Warn "Install path not found: $InstallPath"
    Write-Warn "Nothing to uninstall."
    exit 0
}

if (-not $Force) {
    Write-Host "`n  This will remove the M365 Assessment Toolkit from:" -ForegroundColor Yellow
    Write-Host "  $InstallPath" -ForegroundColor White
    Write-Blank
    Write-Host "  The following will be REMOVED:" -ForegroundColor Red
    Write-Host "    - All tool files (backend.py, index.html, scripts, remediation)" -ForegroundColor White
    Write-Host "    - Desktop shortcut" -ForegroundColor White

    $SessionCount = (Get-ChildItem "$InstallPath\output" -Filter "Session_*.json" -ErrorAction SilentlyContinue).Count
    $ReportCount  = (Get-ChildItem "$InstallPath\reports" -Filter "*.docx" -ErrorAction SilentlyContinue).Count

    if ($SessionCount -gt 0 -or $ReportCount -gt 0) {
        Write-Host "`n  DATA FOUND:" -ForegroundColor Yellow
        Write-Host "    - $SessionCount saved assessment session(s)" -ForegroundColor White
        Write-Host "    - $ReportCount report file(s)" -ForegroundColor White
        Write-Blank
        $KeepDataAnswer = Read-Host "  Keep your saved sessions and reports? (Y/N)"
        $KeepData = ($KeepDataAnswer -eq "Y" -or $KeepDataAnswer -eq "y")
    }

    Write-Blank
    $Confirm = Read-Host "  Proceed with uninstall? (Y/N)"
    if ($Confirm -ne "Y" -and $Confirm -ne "y") {
        Write-Host "`n  Uninstall cancelled.`n" -ForegroundColor Yellow
        exit 0
    }
}

Write-Header "Removing tool files..."

# Stop any running backend processes first
Write-Step "Stopping any running M365 Assessment Toolkit processes..."
try {
    $PythonProcs = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*backend.py*" -or $_.MainWindowTitle -like "*M365*"
    }
    if ($PythonProcs) {
        $PythonProcs | Stop-Process -Force
        Start-Sleep -Seconds 2
        Write-OK "Backend process stopped"
    }
    # Also check for any python processes with backend in path
    $AllPython = Get-Process -Name "python","python3" -ErrorAction SilentlyContinue
    foreach ($Proc in $AllPython) {
        try {
            $CmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.Id)").CommandLine
            if ($CmdLine -like "*$InstallPath*") {
                Stop-Process -Id $Proc.Id -Force
                Write-OK "Stopped process: $($Proc.Id)"
            }
        } catch {}
    }
} catch {
    Write-Warn "Could not check for running processes - close the tool manually if open"
    Start-Sleep -Seconds 3
}

if ($KeepData) {
    # Backup data folders
    $BackupPath = "$env:USERPROFILE\Documents\M365 Assessment Toolkit Backup"
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    Write-Step "Backing up data to: $BackupPath"
    Copy-Item -Path "$InstallPath\output"  -Destination "$BackupPath\output"  -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -Path "$InstallPath\reports" -Destination "$BackupPath\reports" -Recurse -Force -ErrorAction SilentlyContinue
    Write-OK "Data backed up"
}

# Remove install folder
try {
    Remove-Item -Path $InstallPath -Recurse -Force
    Write-OK "Removed: $InstallPath"
} catch {
    Write-Warn "Could not fully remove $InstallPath : $_"
}

# Remove desktop shortcut
$ShortcutPath = "$env:USERPROFILE\Desktop\M365 Assessment Toolkit.lnk"
if (Test-Path $ShortcutPath) {
    Remove-Item -Path $ShortcutPath -Force
    Write-OK "Removed desktop shortcut"
}

Write-Host "`n======================================================" -ForegroundColor Cyan
Write-OK "M365 Assessment Toolkit uninstalled"
if ($KeepData) {
    Write-Host "  Your data has been saved to:" -ForegroundColor White
    Write-Host "  $BackupPath" -ForegroundColor White
}
Write-Host "======================================================`n" -ForegroundColor Cyan


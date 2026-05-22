#Requires -Version 5.1
<#
.SYNOPSIS
    M365 Assessment Toolkit - Installer
    https://github.com/malcolmmcdonald1982/m365-assessment-toolkit

.DESCRIPTION
    Installs the M365 Assessment Toolkit and all prerequisites.
    Run this script as Administrator for best results.

    Usage (one-line install):
        irm https://raw.githubusercontent.com/malcolmmcdonald1982/m365-assessment-toolkit/main/install.ps1 | iex

    Or download and run locally:
        .\install.ps1
#>

[CmdletBinding()]
param(
    [string]$InstallPath = "C:\M365 Assessment Toolkit",
    [switch]$SkipPrereqs,
    [switch]$Silent
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$VERSION               = "1.1.0"

function Write-Header { param($t) Write-Host "" ; Write-Host $t -ForegroundColor Cyan }
function Write-OK      { param($t) Write-Host "  [OK]  $t" -ForegroundColor Green }
function Write-Warn    { param($t) Write-Host "  [!!]  $t" -ForegroundColor Yellow }
function Write-Fail    { param($t) Write-Host "  [XX]  $t" -ForegroundColor Red }
function Write-Step    { param($t) Write-Host "  -->   $t" -ForegroundColor White }
function Write-Blank   { Write-Host "" }

Clear-Host
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  M365 Assessment Toolkit  v$VERSION" -ForegroundColor Cyan
Write-Host "  Installer" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Blank

# Admin check
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Warn "Not running as Administrator."
    Write-Warn "Some prerequisites may fail to install without admin rights."
    Write-Warn "For best results, right-click PowerShell and Run as Administrator."
    Write-Blank
    $Continue = Read-Host "Continue anyway? (Y/N)"
    if ($Continue -ne "Y" -and $Continue -ne "y") { exit 0 }
}

$Errors   = 0
$Warnings = 0

# Step 1: Python
Write-Header "Step 1 of 6 - Python 3.11+"
try {
    $PyVer = & python --version 2>&1
    if ($PyVer -match "Python (\d+)\.(\d+)") {
        $Major = [int]$Matches[1]; $Minor = [int]$Matches[2]
        if ($Major -ge 3 -and $Minor -ge 11) {
            Write-OK "Python $Major.$Minor found"
        } else {
            throw "Python version too old: $PyVer"
        }
    } else { throw "Python not found" }
} catch {
    Write-Warn "Python 3.11+ not found. Attempting to install via winget..."
    try {
        winget install --id Python.Python.3.11 --silent --accept-source-agreements --accept-package-agreements
        Write-OK "Python installed via winget"
        $MachinePath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
        $UserPath    = [System.Environment]::GetEnvironmentVariable("PATH", "User")
        $env:PATH    = $MachinePath + ";" + $UserPath
    } catch {
        Write-Fail "Could not auto-install Python."
        Write-Fail "Please install Python 3.11+ from https://python.org/downloads"
        Write-Fail "Ensure 'Add Python to PATH' is checked during installation."
        $Errors++
    }
}

# Step 2: Python packages
Write-Blank
Write-Header "Step 2 of 6 - Python packages (Flask)"
try {
    $FlaskCheck = & python -m pip show flask 2>&1
    if ($FlaskCheck -match "Name: flask") {
        Write-OK "Flask already installed"
    } else {
        throw "Flask not found"
    }
} catch {
    Write-Step "Installing Flask and flask-cors..."
    try {
        & python -m pip install flask flask-cors --quiet 2>&1 | Out-Null
        Write-OK "Flask and flask-cors installed"
    } catch {
        Write-Fail "Could not install Python packages: $_"
        $Errors++
    }
}

# Step 3: Node.js
Write-Blank
Write-Header "Step 3 of 6 - Node.js 18+"
try {
    $NodeVer = & node --version 2>&1
    if ($NodeVer -match "v(\d+)") {
        $NodeMajor = [int]$Matches[1]
        if ($NodeMajor -ge 18) {
            Write-OK "Node.js $NodeVer found"
        } else {
            throw "Node.js version too old: $NodeVer"
        }
    } else { throw "Node.js not found" }
} catch {
    Write-Warn "Node.js 18+ not found. Attempting to install via winget..."
    try {
        winget install --id OpenJS.NodeJS.LTS --silent --accept-source-agreements --accept-package-agreements
        $MachinePath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
        $UserPath    = [System.Environment]::GetEnvironmentVariable("PATH", "User")
        $env:PATH    = $MachinePath + ";" + $UserPath
        Write-OK "Node.js installed via winget"
    } catch {
        Write-Fail "Could not auto-install Node.js."
        Write-Fail "Please install Node.js LTS from https://nodejs.org"
        $Errors++
    }
}

# Step 4: npm packages
Write-Blank
Write-Header "Step 4 of 6 - npm packages (docx report generator)"

# Step 5: PowerShell modules
Write-Blank
Write-Header "Step 5 of 6 - PowerShell Modules"

$PSModules = @(
    @{ Name="Microsoft.Graph";                        Desc="Microsoft 365 / Entra ID" },
    @{ Name="ExchangeOnlineManagement";               Desc="Exchange Online" },
    @{ Name="MicrosoftTeams";                         Desc="Microsoft Teams" },
    @{ Name="Microsoft.Online.SharePoint.PowerShell"; Desc="SharePoint Online" }
)

try {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
} catch {}

foreach ($Mod in $PSModules) {
    $Installed = Get-Module -ListAvailable -Name $Mod.Name | Sort-Object Version -Descending | Select-Object -First 1
    if ($Installed) {
        Write-OK "$($Mod.Name) v$($Installed.Version) - $($Mod.Desc)"
    } else {
        Write-Step "Installing $($Mod.Name) ($($Mod.Desc))..."
        try {
            Install-Module -Name $Mod.Name -Force -AllowClobber -Scope CurrentUser -Repository PSGallery -ErrorAction Stop
            Write-OK "$($Mod.Name) installed"
        } catch {
            Write-Warn "Could not auto-install $($Mod.Name): $_"
            Write-Warn "Run manually: Install-Module $($Mod.Name) -Scope CurrentUser"
            $Warnings++
        }
    }
}

# Step 6: Copy tool files
Write-Blank
Write-Header "Step 6 of 6 - Installing Tool Files"

$Folders = @(
    $InstallPath,
    "$InstallPath\scripts",
    "$InstallPath\remediation",
    "$InstallPath\output",
    "$InstallPath\reports"
)
foreach ($Folder in $Folders) {
    if (-not (Test-Path $Folder)) {
        New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        Write-OK "Created: $Folder"
    } else {
        Write-OK "Exists:  $Folder"
    }
}

$RepoBase = "https://raw.githubusercontent.com/malcolmmcdonald1982/M365-Assessment-Toolkit/main"

$SourcePath = $PSScriptRoot
if (-not $SourcePath) {
    try {
        $def = $MyInvocation.MyCommand.Definition
        if ($def -and (Test-Path (Split-Path -Parent $def) -ErrorAction SilentlyContinue)) {
            $SourcePath = Split-Path -Parent $def
        }
    } catch {}
}

$UseGitHub = $true
if ($SourcePath) {
    try { $UseGitHub = -not (Test-Path (Join-Path $SourcePath "backend.py") -ErrorAction SilentlyContinue) } catch {}
}

if ($UseGitHub) {
    Write-Step "Downloading tool files from GitHub..."

    $CoreFiles = @("backend.py","index.html","generate-report.js","package.json","sample-data.json","sample-report.docx")
    foreach ($File in $CoreFiles) {
        try {
            Invoke-WebRequest -Uri "$RepoBase/$File" -OutFile (Join-Path $InstallPath $File) -UseBasicParsing
            Write-OK "Downloaded: $File"
        } catch {
            Write-Warn "Could not download: $File"
            $Warnings++
        }
    }

    $AssessScripts = @(
        "Get-IdentityMetrics.ps1","Get-SecurityMetrics.ps1","Get-ExchangeMetrics.ps1",
        "Get-TeamsMetrics.ps1","Get-SharePointMetrics.ps1","Get-IntuneMetrics.ps1",
        "Test-AppRegistrationPermissions.ps1"
    )
    foreach ($Script in $AssessScripts) {
        try {
            Invoke-WebRequest -Uri "$RepoBase/scripts/$Script" -OutFile (Join-Path $InstallPath "scripts\$Script") -UseBasicParsing
            Write-OK "Downloaded: scripts\$Script"
        } catch {
            Write-Warn "Could not download: scripts\$Script"
            $Warnings++
        }
    }

    $RemScripts = @(
        "Remediate-LegacyAuth.ps1","Rollback-LegacyAuth.ps1",
        "Remediate-MailboxAudit.ps1","Rollback-MailboxAudit.ps1",
        "Remediate-ExternalForwarding.ps1","Rollback-ExternalForwarding.ps1",
        "Remediate-AntiPhish.ps1","Rollback-AntiPhish.ps1",
        "Remediate-MFAFatigue.ps1","Rollback-MFAFatigue.ps1",
        "Remediate-WeakAuth.ps1","Rollback-WeakAuth.ps1",
        "Remediate-UserConsent.ps1","Rollback-UserConsent.ps1",
        "Remediate-TeamsConsumer.ps1","Rollback-TeamsConsumer.ps1",
        "Remediate-SPOLegacyAuth.ps1","Rollback-SPOLegacyAuth.ps1"
    )
    foreach ($Script in $RemScripts) {
        try {
            Invoke-WebRequest -Uri "$RepoBase/remediation/$Script" -OutFile (Join-Path $InstallPath "remediation\$Script") -UseBasicParsing
            Write-OK "Downloaded: remediation\$Script"
        } catch {
            Write-Warn "Could not download: remediation\$Script"
        }
    }
} else {
    Write-Step "Copying tool files from local source: $SourcePath"

    $CoreFiles = @("backend.py","index.html","generate-report.js","package.json","sample-data.json","sample-report.docx")
    foreach ($File in $CoreFiles) {
        $Src = Join-Path $SourcePath $File
        $Dst = Join-Path $InstallPath $File
        if (Test-Path $Src) {
            Copy-Item -Path $Src -Destination $Dst -Force
            Write-OK "Copied: $File"
        }
    }

    $AssessScripts = @(
        "Get-IdentityMetrics.ps1","Get-SecurityMetrics.ps1","Get-ExchangeMetrics.ps1",
        "Get-TeamsMetrics.ps1","Get-SharePointMetrics.ps1","Get-IntuneMetrics.ps1",
        "Test-AppRegistrationPermissions.ps1"
    )
    foreach ($Script in $AssessScripts) {
        $Src = Join-Path $SourcePath "scripts\$Script"
        $Dst = Join-Path $InstallPath "scripts\$Script"
        if (Test-Path $Src) {
            Copy-Item -Path $Src -Destination $Dst -Force
            Write-OK "Copied: scripts\$Script"
        }
    }

    $RemScripts = @(
        "Remediate-LegacyAuth.ps1","Rollback-LegacyAuth.ps1",
        "Remediate-MailboxAudit.ps1","Rollback-MailboxAudit.ps1",
        "Remediate-ExternalForwarding.ps1","Rollback-ExternalForwarding.ps1",
        "Remediate-AntiPhish.ps1","Rollback-AntiPhish.ps1",
        "Remediate-MFAFatigue.ps1","Rollback-MFAFatigue.ps1",
        "Remediate-WeakAuth.ps1","Rollback-WeakAuth.ps1",
        "Remediate-UserConsent.ps1","Rollback-UserConsent.ps1",
        "Remediate-TeamsConsumer.ps1","Rollback-TeamsConsumer.ps1",
        "Remediate-SPOLegacyAuth.ps1","Rollback-SPOLegacyAuth.ps1"
    )
    foreach ($Script in $RemScripts) {
        $Src = Join-Path $SourcePath "remediation\$Script"
        $Dst = Join-Path $InstallPath "remediation\$Script"
        if (Test-Path $Src) {
            Copy-Item -Path $Src -Destination $Dst -Force
            Write-OK "Copied: remediation\$Script"
        }
    }
}

# npm install
Push-Location $InstallPath
try {
    if (Test-Path "package.json") {
        Write-Step "Running npm install..."
        & npm install --quiet 2>&1 | Out-Null
        Write-OK "npm packages installed"
    }
} catch {
    Write-Warn "npm install failed - report generation may not work"
}
Pop-Location

# Desktop shortcut
Write-Step "Creating desktop shortcut..."
try {
    $BatPath = Join-Path $InstallPath "Start-Tool.bat"
    $BatLines = @(
        "@echo off",
        "title M365 Assessment Toolkit",
        "echo.",
        "echo   Starting M365 Assessment Toolkit...",
        "echo   The tool will open automatically in your browser.",
        "echo.",
        "cd /d `"$InstallPath`"",
        "python backend.py",
        "pause"
    )
    $BatLines | Out-File -FilePath $BatPath -Encoding ASCII -Force

    $WshShell  = New-Object -ComObject WScript.Shell
    $Shortcut  = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\M365 Assessment Toolkit.lnk")
    $Shortcut.TargetPath       = $BatPath
    $Shortcut.WorkingDirectory = $InstallPath
    $Shortcut.Description      = "M365 Assessment Toolkit"
    $Shortcut.IconLocation     = "shell32.dll,13"
    $Shortcut.Save()
    Write-OK "Desktop shortcut created"
} catch {
    Write-Warn "Could not create desktop shortcut: $_"
    $Warnings++
}

# Output folder README
@"
M365 Assessment Toolkit - Output Folder
========================================
Session files (Session_*.json) are saved here automatically after each assessment.
Remediation logs (RemediationLog_*.json) are saved here after remediation.
Snapshot files (Snapshot_*.json) are saved before each remediation change.
Do not delete session files if you want to reload previous assessments.
"@ | Out-File -FilePath "$InstallPath\output\README.txt" -Encoding UTF8 -Force

# Summary
Write-Blank
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Installation Complete" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Blank

if ($Errors -eq 0 -and $Warnings -eq 0) {
    Write-Host "  All prerequisites installed successfully." -ForegroundColor Green
} elseif ($Errors -eq 0) {
    Write-Host "  Installed with $Warnings warning(s) - check output above." -ForegroundColor Yellow
} else {
    Write-Host "  Installed with $Errors error(s) - check output above." -ForegroundColor Red
}

Write-Blank
Write-Host "  Install location: $InstallPath" -ForegroundColor White
Write-Host "  To start: Double-click the desktop shortcut" -ForegroundColor White
Write-Host "            Or run: python `"$InstallPath\backend.py`"" -ForegroundColor White
Write-Host "  Opens automatically at http://localhost:5000" -ForegroundColor White
Write-Blank
Write-Host "======================================================" -ForegroundColor Cyan
Write-Blank

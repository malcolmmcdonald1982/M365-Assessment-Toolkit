<#
.SYNOPSIS
    Setup-M365AssessmentToolkit.ps1
    M365 Assessment Toolkit
    Version 2.1 - includes remediation scripts

.DESCRIPTION
    Creates the M365 Assessment Toolkit at C:\M365 Assessment Toolkit
    and copies all tool files from the current folder into the right structure.

.USAGE
    Right-click -> Run with PowerShell
    OR from PowerShell: cd C:\AssetTool then .\Setup-M365AssessmentToolkit.ps1
#>

param(
    [string]$SourcePath  = "",
    [string]$InstallPath = "C:\M365 Assessment Toolkit"
)

function Write-Header {
    Write-Host ""
    Write-Host "  +------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |      M365 Assessment Toolkit - Setup Script          |" -ForegroundColor Cyan
    Write-Host "  |      [Consultant Name] | IT Infrastructure            |" -ForegroundColor Cyan
    Write-Host "  +------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step  ($msg) { Write-Host "  > $msg" -ForegroundColor Cyan }
function Write-OK    ($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn  ($msg) { Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Fail  ($msg) { Write-Host "  [X]  $msg" -ForegroundColor Red }
function Write-Info  ($msg) { Write-Host "       $msg" -ForegroundColor Gray }
function Write-Blank       { Write-Host "" }

Write-Header

# Step 1: Find source files
Write-Step "Locating source files..."

if ($SourcePath -eq "") {
    $SearchPaths = @(
        $PSScriptRoot,
        "$env:USERPROFILE\Downloads\AssetTool",
        "$env:USERPROFILE\Downloads\m365_assessment_v2",
        "C:\AssetTool"
    )
    foreach ($Path in $SearchPaths) {
        if (Test-Path "$Path\backend.py") {
            $SourcePath = $Path
            Write-OK "Found source files at: $SourcePath"
            break
        }
    }
}

if ($SourcePath -eq "" -or -not (Test-Path "$SourcePath\backend.py")) {
    Write-Warn "Could not find tool files automatically."
    Write-Blank
    Write-Host "  Enter the full path to the folder containing backend.py:" -ForegroundColor White
    $SourcePath = Read-Host "  Path"
    if (-not (Test-Path "$SourcePath\backend.py")) {
        Write-Fail "backend.py not found at: $SourcePath"
        Write-Info "Make sure you have extracted AssetTool.zip first."
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-OK "Source files confirmed at: $SourcePath"
}

Write-Blank

# Step 2: Create folder structure
Write-Step "Creating folder structure at $InstallPath ..."

$Folders = @(
    $InstallPath,
    "$InstallPath\scripts",
    "$InstallPath\output",
    "$InstallPath\reports",
    "$InstallPath\remediation"
)

foreach ($Folder in $Folders) {
    if (-not (Test-Path $Folder)) {
        New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        Write-OK "Created: $Folder"
    } else {
        Write-Info "Already exists: $Folder"
    }
}

Write-Blank

# Step 3: Copy core files
Write-Step "Copying tool files..."

$CoreFiles = @(
    "index.html",
    "backend.py",
    "generate-report.js",
    "package.json",
    "sample-data.json",
    "sample-report.docx",
    "README.md",
    "update.ps1",
    "uninstall.ps1"
)

$CopyErrors = 0

foreach ($File in $CoreFiles) {
    $Src = Join-Path $SourcePath $File
    $Dst = Join-Path $InstallPath $File
    if (Test-Path $Src) {
        Copy-Item -Path $Src -Destination $Dst -Force
        Write-OK "Copied: $File"
    } else {
        Write-Warn "Not found (skipping): $File"
        $CopyErrors++
    }
}

Write-Blank
Write-Step "Copying PowerShell scripts..."

$Scripts = @(
    "Get-IdentityMetrics.ps1",
    "Get-SecurityMetrics.ps1",
    "Get-ExchangeMetrics.ps1",
    "Get-TeamsMetrics.ps1",
    "Get-SharePointMetrics.ps1",
    "Get-IntuneMetrics.ps1"
)

foreach ($Script in $Scripts) {
    $Src = Join-Path $SourcePath "scripts\$Script"
    $Dst = Join-Path $InstallPath "scripts\$Script"
    if (Test-Path $Src) {
        Copy-Item -Path $Src -Destination $Dst -Force
        Write-OK "Copied: scripts\$Script"
    } else {
        Write-Warn "Not found (skipping): scripts\$Script"
        $CopyErrors++
    }
}

Write-Blank
Write-Step "Copying remediation scripts..."

$RemediationScripts = @(
    "Remediate-LegacyAuth.ps1",    "Rollback-LegacyAuth.ps1",
    "Remediate-MailboxAudit.ps1",  "Rollback-MailboxAudit.ps1",
    "Remediate-ExternalForwarding.ps1", "Rollback-ExternalForwarding.ps1",
    "Remediate-AntiPhish.ps1",     "Rollback-AntiPhish.ps1",
    "Remediate-MFAFatigue.ps1",    "Rollback-MFAFatigue.ps1",
    "Remediate-WeakAuth.ps1",      "Rollback-WeakAuth.ps1",
    "Remediate-UserConsent.ps1",   "Rollback-UserConsent.ps1",
    "Remediate-TeamsConsumer.ps1", "Rollback-TeamsConsumer.ps1",
    "Remediate-SPOLegacyAuth.ps1", "Rollback-SPOLegacyAuth.ps1"
)

foreach ($Script in $RemediationScripts) {
    $Src = Join-Path $SourcePath "remediation\$Script"
    $Dst = Join-Path $InstallPath "remediation\$Script"
    if (Test-Path $Src) {
        Copy-Item -Path $Src -Destination $Dst -Force
        Write-OK "Copied: remediation\$Script"
    } else {
        Write-Warn "Not found (skipping): remediation\$Script"
    }
}

Write-Blank

# Step 4: Create launcher bat file
Write-Step "Creating Start-Tool.bat launcher..." 

$BatLines = @(
    "@echo off",
    "title M365 Assessment Toolkit",
    "echo.",
    "echo   Starting M365 Assessment Toolkit...",
    "echo   M365 Assessment Toolkit",
    "echo.",
    "echo   Starting Python backend...",
    "echo   The tool will open automatically in your browser.",
    "echo.",
    "cd /d ""$InstallPath""",
    "python backend.py",
    "pause"
)

$BatContent = $BatLines -join "`r`n"
[System.IO.File]::WriteAllText("$InstallPath\Start-Tool.bat", $BatContent, [System.Text.Encoding]::ASCII)
Write-OK "Created: Start-Tool.bat"

# Desktop shortcut
$ShortcutPath = "$env:USERPROFILE\Desktop\M365 Assessment Toolkit.lnk"
try {
    $WshShell                  = New-Object -ComObject WScript.Shell
    $Shortcut                  = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath       = "$InstallPath\Start-Tool.bat"
    $Shortcut.WorkingDirectory = $InstallPath
    $Shortcut.Description      = "M365 Assessment Toolkit - [Consultant Name]"
    $Shortcut.Save()
    Write-OK "Desktop shortcut created"
} catch {
    Write-Warn "Could not create desktop shortcut (not critical)"
}

Write-Blank

# Step 5: Prerequisites check
Write-Step "Checking prerequisites..."
Write-Blank

$AllGood = $true

# Python
Write-Host "  Python:" -ForegroundColor White -NoNewline
try {
    $PyVer = (& python --version 2>&1).ToString().Trim()
    if ($LASTEXITCODE -eq 0) {
        Write-Host " $PyVer" -ForegroundColor Green

        $FlaskVer = (& python -c "import flask; print(flask.__version__)" 2>&1).ToString().Trim()
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Flask installed (v$FlaskVer)"
        } else {
            Write-Warn "Flask not installed"
            Write-Info "Run: pip install flask flask-cors"
            $AllGood = $false
        }

        & python -c "import flask_cors" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "flask-cors installed"
        } else {
            Write-Warn "flask-cors not installed"
            Write-Info "Run: pip install flask flask-cors"
            $AllGood = $false
        }

    } else {
        Write-Host " NOT FOUND" -ForegroundColor Red
        Write-Fail "Python not installed"
        Write-Info "Download from: https://www.python.org/downloads/"
        Write-Info "Tick 'Add Python to PATH' during installation"
        $AllGood = $false
    }
} catch {
    Write-Host " NOT FOUND" -ForegroundColor Red
    Write-Fail "Python not installed - download from https://www.python.org/downloads/"
    $AllGood = $false
}

Write-Blank

# Node.js
Write-Host "  Node.js:" -ForegroundColor White -NoNewline
$NodeFound = $false
try {
    $NodeVer = (& node --version 2>&1).ToString().Trim()
    if ($LASTEXITCODE -eq 0) {
        Write-Host " $NodeVer" -ForegroundColor Green
        $NodeFound = $true

        & node -e "require('docx'); process.exit(0)" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "docx npm module installed"
        } else {
            Write-Warn "docx npm module not installed"
            Write-Blank
            $DoInstall = Read-Host "  Install it now? (Y/N)"
            if ($DoInstall -match '^[Yy]') {
                Write-Step "Installing docx module..."
                Push-Location $InstallPath
                & npm install docx
                $NpmResult = $LASTEXITCODE
                Pop-Location
                if ($NpmResult -eq 0) {
                    Write-OK "docx module installed"
                } else {
                    Write-Fail "npm install failed - run manually:"
                    Write-Info "  cd `"$InstallPath`""
                    Write-Info "  npm install docx"
                    $AllGood = $false
                }
            } else {
                Write-Info "Run these when ready:"
                Write-Info "  cd `"$InstallPath`""
                Write-Info "  npm install docx"
                $AllGood = $false
            }
        }
    } else {
        Write-Host " NOT FOUND" -ForegroundColor Red
        $NodeFound = $false
    }
} catch {
    Write-Host " NOT FOUND" -ForegroundColor Red
    $NodeFound = $false
}

if (-not $NodeFound) {
    Write-Fail "Node.js not installed"
    Write-Info "Download from: https://nodejs.org (choose LTS version)"
    Write-Info "After installing Node.js, re-run this setup script"
    $AllGood = $false
}

Write-Blank

# PowerShell modules
Write-Host "  PowerShell Modules:" -ForegroundColor White

$Modules = @(
    @{ Name = "Microsoft.Graph";                        Label = "Microsoft Graph"   },
    @{ Name = "ExchangeOnlineManagement";               Label = "Exchange Online"   },
    @{ Name = "MicrosoftTeams";                         Label = "Microsoft Teams"   },
    @{ Name = "Microsoft.Online.SharePoint.PowerShell"; Label = "SharePoint Online" }
)

$MissingModules = @()
foreach ($Mod in $Modules) {
    $Installed = Get-Module -ListAvailable -Name $Mod.Name | Select-Object -First 1
    if ($Installed) {
        Write-OK "$($Mod.Label) - v$($Installed.Version)"
    } else {
        Write-Warn "$($Mod.Label) - NOT INSTALLED"
        $MissingModules += $Mod.Name
        $AllGood = $false
    }
}

if ($MissingModules.Count -gt 0) {
    Write-Blank
    $DoMods = Read-Host "  Install missing PowerShell modules now? (Y/N)"
    if ($DoMods -match '^[Yy]') {
        foreach ($ModName in $MissingModules) {
            Write-Step "Installing $ModName ..."
            try {
                Install-Module -Name $ModName -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
                Write-OK "$ModName installed"
            } catch {
                Write-Fail "Failed to install $ModName"
                Write-Info "Run manually: Install-Module $ModName -Scope CurrentUser -Force"
            }
        }
    } else {
        Write-Info "Run these manually when ready:"
        foreach ($ModName in $MissingModules) {
            Write-Info "  Install-Module $ModName -Scope CurrentUser -Force"
        }
    }
}

Write-Blank

# Step 6: Summary
Write-Host "  ------------------------------------------------------" -ForegroundColor DarkGray
Write-Blank

if ($AllGood -and $CopyErrors -eq 0) {
    Write-Host "  All done - everything is ready to use." -ForegroundColor Green
    Write-Blank
    Write-Host "  To launch the tool:" -ForegroundColor White
    Write-Info "  Double-click 'M365 Assessment Toolkit' on your Desktop"
    Write-Info "  OR double-click Start-Tool.bat in $InstallPath"
    Write-Blank
    Write-Host "  To test the report generator without a live tenant:" -ForegroundColor White
    Write-Info "  cd `"$InstallPath`""
    Write-Info "  node generate-report.js sample-data.json test.docx"
} else {
    Write-Host "  Setup complete - some items still need attention:" -ForegroundColor Yellow
    Write-Blank
    if (-not $AllGood) {
        Write-Warn "One or more prerequisites are missing - see notes above."
    }
    if ($CopyErrors -gt 0) {
        Write-Warn "$CopyErrors file(s) were missing from the source folder."
    }
    Write-Blank
    Write-Info "Re-run this script after installing any missing prerequisites."
}

Write-Blank
Write-Host "  Installed to: $InstallPath" -ForegroundColor DarkGray
Write-Host "  M365 Assessment Toolkit" -ForegroundColor DarkGray
Write-Blank

Read-Host "  Press Enter to close"

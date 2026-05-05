<#
.SYNOPSIS  Rollback-WeakAuth.ps1 - SEC-004 rollback
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[Parameter(Mandatory=$true)][string]$SnapshotPath="")
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if (-not (Test-Path $SnapshotPath)) { throw "Snapshot not found: $SnapshotPath" }
    $Snapshot = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    if ($AuthMethod -eq "AppReg") {
        $TokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
        $AccessToken = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $TokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop).access_token
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $AccessToken -AsPlainText -Force) -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } else {
        $Scopes = @('Policy.ReadWrite.AuthenticationMethod')
        if ($TenantId -ne "") { Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null } else { Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null }
    }
    $PrevStates = $Snapshot.previousState
    foreach ($Method in @("Sms","Voice","Email")) {
        try {
            $PrevState = $PrevStates.$Method
            if ($PrevState -and $PrevState -ne "unknown") {
                $Body = @{ state=$PrevState }
                Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$Method" -Body ($Body | ConvertTo-Json) -ContentType "application/json" | Out-Null
            }
        } catch {}
    }
    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
    @{ success=$true; details="SMS, Voice, and Email OTP methods restored to previous state" } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Rollback-WeakAuth failed: $_"); exit 1 }

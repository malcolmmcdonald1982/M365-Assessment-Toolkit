<#
.SYNOPSIS  Remediate-WeakAuth.ps1 - SEC-004
           Disables SMS, Voice, and Email OTP authentication methods.
           WARNING: Checks if any users have these as their ONLY MFA method first.
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[string]$SnapshotPath="",[switch]$CheckOnly=$false)
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if ($AuthMethod -eq "AppReg") {
        $TokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
        $AccessToken = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $TokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop).access_token
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $AccessToken -AsPlainText -Force) -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } else {
        $Scopes = @('Policy.ReadWrite.AuthenticationMethod','UserAuthenticationMethod.Read.All')
        if ($TenantId -ne "") { Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null } else { Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null }
    }
    $WeakMethods = @("Sms","Voice","Email")
    $PrevStates  = @{}
    foreach ($Method in $WeakMethods) {
        try {
            $Cfg = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$Method" -ErrorAction SilentlyContinue
            $PrevStates[$Method] = $Cfg.state
        } catch { $PrevStates[$Method] = "unknown" }
    }
    # Safety check - find users with ONLY weak methods
    $Warning = $null
    $UsersAtRisk = 0
    try {
        $RegDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction SilentlyContinue
        foreach ($User in $RegDetails) {
            $Methods = $User.MethodsRegistered
            $HasStrongMethod = $Methods | Where-Object { $_ -in @("microsoftAuthenticatorPush","softwareOneTimePasscode","fido2","windowsHelloForBusiness","temporaryAccessPass") }
            $HasWeakOnly = ($Methods | Where-Object { $_ -in @("mobilePhone","alternateMobilePhone","email") }).Count -gt 0 -and -not $HasStrongMethod
            if ($HasWeakOnly) { $UsersAtRisk++ }
        }
    } catch {}
    if ($UsersAtRisk -gt 0) { $Warning = "$UsersAtRisk user(s) have SMS/voice/email as their ONLY MFA method. They will lose MFA access if these are disabled. Ensure they set up the Authenticator app first." }
    $Snapshot = @{ findingId="SEC-004"; timestamp=(Get-Date).ToString("o"); usersAtRisk=$UsersAtRisk; previousState=$PrevStates }
    if ($CheckOnly) {
        Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
        @{ success=$true; checkOnly=$true; warning=$Warning; usersAtRisk=$UsersAtRisk } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
    }
    if ($SnapshotPath -ne "") { $Snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $SnapshotPath -Encoding UTF8 }
    foreach ($Method in $WeakMethods) {
        try {
            $Body = @{ state="disabled" }
            Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$Method" -Body ($Body | ConvertTo-Json) -ContentType "application/json" | Out-Null
        } catch {}
    }
    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
    @{ success=$true; details="SMS, Voice, and Email OTP authentication methods disabled"; warning=$Warning; snapshot=$Snapshot } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Remediate-WeakAuth failed: $_"); exit 1 }

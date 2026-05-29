<#
.SYNOPSIS  Remediate-UserConsent.ps1 - SEC-005
           Restricts users from consenting to OAuth apps without admin approval.
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[string]$SnapshotPath="",[switch]$CheckOnly=$false)
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if ($AuthMethod -eq "AppReg") {
        $TokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
        $AccessToken = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $TokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop).access_token
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $AccessToken -AsPlainText -Force) -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } else {
        $Scopes = @('Policy.ReadWrite.Authorization')
        if ($TenantId -ne "") { Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null } else { Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null }
    }
    $AuthPolicy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    $PrevPolicies = $AuthPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
    $Snapshot = @{ findingId="SEC-005"; timestamp=(Get-Date).ToString("o"); previousState=@{ permissionGrantPolicies=$PrevPolicies } }
    if ($CheckOnly) {
        Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
        $IsUnrestricted = $PrevPolicies -contains "ManagePermissionGrantsForSelf.microsoft-user-default-low"
        @{ success=$true; checkOnly=$true; alreadyRemediated=(-not $IsUnrestricted) } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
    }
    if ($SnapshotPath -ne "") { $Snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $SnapshotPath -Encoding UTF8 }
    # Remove user consent permission - set to empty array (admin consent required)
    $Body = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } }
    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" -Body ($Body | ConvertTo-Json -Depth 5) -ContentType "application/json" | Out-Null
    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
    @{ success=$true; details="User consent to apps restricted - admin approval now required"; snapshot=$Snapshot } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Remediate-UserConsent failed: $_"); exit 1 }

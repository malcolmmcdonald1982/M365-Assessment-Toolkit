<#
.SYNOPSIS  Rollback-LegacyAuth.ps1
           Malcolm McDonald - IT Infrastructure Consultant
.DESCRIPTION
    Rolls back CA-002 remediation.
    Reads snapshot and removes the CA policy created by Remediate-LegacyAuth.ps1.
    Only removes the policy if it was created by this tool.
    Outputs JSON: { success, details }
#>
param(
    [Parameter(Mandatory=$false)] [string]$AuthMethod   = "Interactive",
    [Parameter(Mandatory=$false)] [string]$TenantId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientSecret = "",
    [Parameter(Mandatory=$true)]  [string]$SnapshotPath = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"

$POLICY_NAME = "MM-Assessment - Block Legacy Authentication"

try {
    # Load snapshot
    if (-not (Test-Path $SnapshotPath)) {
        throw "Snapshot file not found: $SnapshotPath"
    }
    $Snapshot = Get-Content $SnapshotPath -Raw | ConvertFrom-Json

    # If policy existed before our change, we should not remove it
    if ($Snapshot.policyExisted -eq $true) {
        @{
            success = $true
            details = "Policy existed before remediation - not removed to preserve original state"
        } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }
        exit 0
    }

    # Authenticate
    if ($AuthMethod -eq "AppReg") {
        $TokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
        $AccessToken = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $TokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop).access_token
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $AccessToken -AsPlainText -Force) -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } else {
        $Scopes = @('Policy.ReadWrite.ConditionalAccess')
        if ($TenantId -ne "") {
            Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        } else {
            Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
    }

    # Find and remove our policy by name (safer than by ID in case of tenant changes)
    $Policies  = Get-MgIdentityConditionalAccessPolicy -All -WarningAction SilentlyContinue
    $OurPolicy = $Policies | Where-Object { $_.DisplayName -eq $POLICY_NAME }

    if ($null -eq $OurPolicy) {
        Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
        @{
            success = $true
            details = "Policy not found - may have already been removed"
        } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }
        exit 0
    }

    Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $OurPolicy.Id
    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null

    @{
        success = $true
        details = "CA policy removed: $POLICY_NAME. Legacy authentication is no longer blocked."
    } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }
    exit 0

} catch {
    [Console]::Error.WriteLine("Rollback-LegacyAuth failed: $_")
    exit 1
}

<#
.SYNOPSIS  Rollback-ExternalForwarding.ps1 - EXO-001 rollback
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[Parameter(Mandatory=$true)][string]$SnapshotPath="")
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if (-not (Test-Path $SnapshotPath)) { throw "Snapshot not found: $SnapshotPath" }
    $Snapshot    = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    $RestoreMode = $Snapshot.previousState.autoForwardingMode
    $PolicyName  = $Snapshot.policyName
    if ($TenantId -ne "") { Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false | Out-Null } else { Connect-ExchangeOnline -ShowBanner:$false | Out-Null }
    Set-HostedOutboundSpamFilterPolicy -Identity $PolicyName -AutoForwardingMode $RestoreMode
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    @{ success=$true; details="Auto-forwarding mode restored to: $RestoreMode" } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Rollback-ExternalForwarding failed: $_"); exit 1 }

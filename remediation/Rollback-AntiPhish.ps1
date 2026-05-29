<#
.SYNOPSIS  Rollback-AntiPhish.ps1 - EXO-003 rollback
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[Parameter(Mandatory=$true)][string]$SnapshotPath="")
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if (-not (Test-Path $SnapshotPath)) { throw "Snapshot not found: $SnapshotPath" }
    $Snapshot  = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    $RestoreVal = $Snapshot.previousState.enableMailboxIntelligence
    $PolicyName = $Snapshot.policyName
    if ($TenantId -ne "") { Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false | Out-Null } else { Connect-ExchangeOnline -ShowBanner:$false | Out-Null }
    Set-AntiPhishPolicy -Identity $PolicyName -EnableMailboxIntelligence $RestoreVal
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    @{ success=$true; details="Mailbox intelligence restored to: $RestoreVal" } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Rollback-AntiPhish failed: $_"); exit 1 }

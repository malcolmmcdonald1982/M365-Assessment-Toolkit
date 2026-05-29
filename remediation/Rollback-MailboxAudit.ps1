<#
.SYNOPSIS  Rollback-MailboxAudit.ps1 - EXO-002 rollback
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[Parameter(Mandatory=$true)][string]$SnapshotPath="")
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if (-not (Test-Path $SnapshotPath)) { throw "Snapshot not found: $SnapshotPath" }
    $Snapshot = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    $RestoreValue = $Snapshot.previousState.auditDisabled
    if ($TenantId -ne "") { Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false | Out-Null } else { Connect-ExchangeOnline -ShowBanner:$false | Out-Null }
    Set-OrganizationConfig -AuditDisabled $RestoreValue
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    $State = if ($RestoreValue) { "disabled" } else { "enabled" }
    @{ success=$true; details="Mailbox auditing restored to: $State" } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Rollback-MailboxAudit failed: $_"); exit 1 }

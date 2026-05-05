<#
.SYNOPSIS  Remediate-MailboxAudit.ps1 - EXO-002
           Enables organisation-wide mailbox auditing.
#>
param(
    [string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[string]$SnapshotPath="",[switch]$CheckOnly=$false
)
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if ($TenantId -ne "") { Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false | Out-Null } else { Connect-ExchangeOnline -ShowBanner:$false | Out-Null }
    $OrgConfig  = Get-OrganizationConfig
    $WasDisabled = $OrgConfig.AuditDisabled
    $Snapshot = @{ findingId="EXO-002"; timestamp=(Get-Date).ToString("o"); previousState=@{ auditDisabled=$WasDisabled } }
    if ($CheckOnly) {
        Disconnect-ExchangeOnline -Confirm:$false | Out-Null
        @{ success=$true; checkOnly=$true; alreadyRemediated=(-not $WasDisabled) } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
    }
    if ($SnapshotPath -ne "") { $Snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $SnapshotPath -Encoding UTF8 }
    Set-OrganizationConfig -AuditDisabled $false
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    @{ success=$true; details="Organisation-wide mailbox auditing enabled"; snapshot=$Snapshot } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Remediate-MailboxAudit failed: $_"); exit 1 }

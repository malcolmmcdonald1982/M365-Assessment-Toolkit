<#
.SYNOPSIS  Remediate-AntiPhish.ps1 - EXO-003
           Enables mailbox intelligence in anti-phishing policy.
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[string]$SnapshotPath="",[switch]$CheckOnly=$false)
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if ($TenantId -ne "") { Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false | Out-Null } else { Connect-ExchangeOnline -ShowBanner:$false | Out-Null }
    $Policy  = Get-AntiPhishPolicy | Select-Object -First 1
    $PrevVal = $Policy.EnableMailboxIntelligence
    $Snapshot = @{ findingId="EXO-003"; timestamp=(Get-Date).ToString("o"); policyName=$Policy.Name; previousState=@{ enableMailboxIntelligence=$PrevVal } }
    if ($CheckOnly) {
        Disconnect-ExchangeOnline -Confirm:$false | Out-Null
        @{ success=$true; checkOnly=$true; alreadyRemediated=$PrevVal } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
    }
    if ($SnapshotPath -ne "") { $Snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $SnapshotPath -Encoding UTF8 }
    Set-AntiPhishPolicy -Identity $Policy.Name -EnableMailboxIntelligence $true -EnableMailboxIntelligenceProtection $true
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    @{ success=$true; details="Mailbox intelligence enabled on: $($Policy.Name)"; snapshot=$Snapshot } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Remediate-AntiPhish failed: $_"); exit 1 }

<#
.SYNOPSIS  Remediate-ExternalForwarding.ps1 - EXO-001
           Blocks automatic forwarding to external recipients.
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[string]$SnapshotPath="",[switch]$CheckOnly=$false)
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if ($TenantId -ne "") { Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false | Out-Null } else { Connect-ExchangeOnline -ShowBanner:$false | Out-Null }
    $Policy = Get-HostedOutboundSpamFilterPolicy -Identity Default -ErrorAction SilentlyContinue
    if (-not $Policy) { $Policy = Get-HostedOutboundSpamFilterPolicy | Select-Object -First 1 }
    $PrevMode = $Policy.AutoForwardingMode
    $Snapshot = @{ findingId="EXO-001"; timestamp=(Get-Date).ToString("o"); policyName=$Policy.Name; previousState=@{ autoForwardingMode=$PrevMode.ToString() } }
    if ($CheckOnly) {
        Disconnect-ExchangeOnline -Confirm:$false | Out-Null
        @{ success=$true; checkOnly=$true; alreadyRemediated=($PrevMode -eq "Off") } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
    }
    if ($SnapshotPath -ne "") { $Snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $SnapshotPath -Encoding UTF8 }
    Set-HostedOutboundSpamFilterPolicy -Identity $Policy.Name -AutoForwardingMode Off
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    @{ success=$true; details="External auto-forwarding blocked on policy: $($Policy.Name)"; snapshot=$Snapshot } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Remediate-ExternalForwarding failed: $_"); exit 1 }

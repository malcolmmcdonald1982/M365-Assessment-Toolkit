<#
.SYNOPSIS  Remediate-TeamsConsumer.ps1 - TEAMS-002
           Blocks Teams consumer/personal account access.
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[string]$SnapshotPath="",[switch]$CheckOnly=$false)
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if ($TenantId -ne "") { Connect-MicrosoftTeams -TenantId $TenantId | Out-Null } else { Connect-MicrosoftTeams | Out-Null }
    $Policy  = Get-CsExternalAccessPolicy -Identity Global
    $PrevVal = $Policy.EnableTeamsConsumerAccess
    $Snapshot = @{ findingId="TEAMS-002"; timestamp=(Get-Date).ToString("o"); previousState=@{ enableTeamsConsumerAccess=$PrevVal } }
    if ($CheckOnly) {
        Disconnect-MicrosoftTeams | Out-Null
        @{ success=$true; checkOnly=$true; alreadyRemediated=(-not $PrevVal) } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
    }
    if ($SnapshotPath -ne "") { $Snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $SnapshotPath -Encoding UTF8 }
    Set-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerAccess $false
    Disconnect-MicrosoftTeams | Out-Null
    @{ success=$true; details="Teams consumer/personal account access disabled"; snapshot=$Snapshot } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Remediate-TeamsConsumer failed: $_"); exit 1 }

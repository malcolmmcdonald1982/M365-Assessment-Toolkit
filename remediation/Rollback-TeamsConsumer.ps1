<#
.SYNOPSIS  Rollback-TeamsConsumer.ps1 - TEAMS-002 rollback
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[Parameter(Mandatory=$true)][string]$SnapshotPath="")
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if (-not (Test-Path $SnapshotPath)) { throw "Snapshot not found: $SnapshotPath" }
    $Snapshot  = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    $RestoreVal = $Snapshot.previousState.enableTeamsConsumerAccess
    if ($TenantId -ne "") { Connect-MicrosoftTeams -TenantId $TenantId | Out-Null } else { Connect-MicrosoftTeams | Out-Null }
    Set-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerAccess $RestoreVal
    Disconnect-MicrosoftTeams | Out-Null
    @{ success=$true; details="Teams consumer access restored to: $RestoreVal" } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Rollback-TeamsConsumer failed: $_"); exit 1 }

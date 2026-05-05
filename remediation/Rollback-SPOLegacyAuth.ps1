<#
.SYNOPSIS  Rollback-SPOLegacyAuth.ps1 - SPO-002 rollback
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[Parameter(Mandatory=$true)][string]$SnapshotPath="",[string]$SpAdminUrl="")
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if (-not (Test-Path $SnapshotPath)) { throw "Snapshot not found: $SnapshotPath" }
    $Snapshot   = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    $RestoreVal = $Snapshot.previousState.legacyAuthEnabled
    if ($SpAdminUrl -eq "") {
        $Scopes = @('Organization.Read.All')
        if ($TenantId -ne "") { Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null } else { Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null }
        $Org = Get-MgOrganization; $Domain = ($Org.VerifiedDomains | Where-Object { $_.IsInitial }).Name
        $SpAdminUrl = "https://$($Domain.Split('.')[0])-admin.sharepoint.com"
        Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
    }
    Connect-SPOService -Url $SpAdminUrl | Out-Null
    Set-SPOTenant -LegacyAuthProtocolsEnabled $RestoreVal
    Disconnect-SPOService | Out-Null
    @{ success=$true; details="SharePoint legacy auth restored to: $RestoreVal" } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Rollback-SPOLegacyAuth failed: $_"); exit 1 }

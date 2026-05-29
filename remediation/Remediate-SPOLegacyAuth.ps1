<#
.SYNOPSIS  Remediate-SPOLegacyAuth.ps1 - SPO-002
           Disables legacy authentication in SharePoint Online.
#>
param([string]$AuthMethod="Interactive",[string]$TenantId="",[string]$ClientId="",[string]$ClientSecret="",[string]$SnapshotPath="",[switch]$CheckOnly=$false,[string]$SpAdminUrl="")
$ErrorActionPreference="Stop";$ProgressPreference="SilentlyContinue";$WarningPreference="SilentlyContinue"
try {
    if ($SpAdminUrl -eq "") {
        $Scopes = @('Organization.Read.All')
        if ($TenantId -ne "") { Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null } else { Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null }
        $Org = Get-MgOrganization; $Domain = ($Org.VerifiedDomains | Where-Object { $_.IsInitial }).Name
        $SpAdminUrl = "https://$($Domain.Split('.')[0])-admin.sharepoint.com"
        Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
    }
    Connect-SPOService -Url $SpAdminUrl | Out-Null
    $Tenant  = Get-SPOTenant
    $PrevVal = $Tenant.LegacyAuthProtocolsEnabled
    $Snapshot = @{ findingId="SPO-002"; timestamp=(Get-Date).ToString("o"); previousState=@{ legacyAuthEnabled=$PrevVal } }
    if ($CheckOnly) {
        Disconnect-SPOService | Out-Null
        @{ success=$true; checkOnly=$true; alreadyRemediated=(-not $PrevVal) } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
    }
    if ($SnapshotPath -ne "") { $Snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $SnapshotPath -Encoding UTF8 }
    Set-SPOTenant -LegacyAuthProtocolsEnabled $false
    Disconnect-SPOService | Out-Null
    @{ success=$true; details="SharePoint legacy authentication disabled"; snapshot=$Snapshot } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }; exit 0
} catch { [Console]::Error.WriteLine("Remediate-SPOLegacyAuth failed: $_"); exit 1 }

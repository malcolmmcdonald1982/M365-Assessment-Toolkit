<#
.SYNOPSIS  Get-SharePointMetrics.ps1 - M365 Assessment Tool
           Malcolm McDonald | IT Infrastructure Consultant
.DESCRIPTION
    Collects SharePoint Online tenant security metrics.
    Always uses interactive login.
    Outputs JSON to stdout. Exit 0 = success.
.NOTES
    SpAdminUrl format: https://yourtenant-admin.sharepoint.com
    If SpAdminUrl is not supplied, the script will attempt to
    derive it from the connected tenant automatically.
#>
param(
    [Parameter(Mandatory=$false)] [string]$AuthMethod   = "Interactive",
    [Parameter(Mandatory=$false)] [string]$TenantId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientSecret = "",
    [Parameter(Mandatory=$false)] [string]$SpAdminUrl   = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"

# If no SPO admin URL supplied, try to derive it from Graph
if ($SpAdminUrl -eq "") {
    try {
        $Scopes = @('Organization.Read.All')
        if ($TenantId -ne "") {
            Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        } else {
            Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
        $OrgDetails = Get-MgOrganization
        $Domain     = ($OrgDetails.VerifiedDomains | Where-Object { $_.IsInitial -eq $true }).Name
        if ($Domain) {
            $TenantName = $Domain.Split('.')[0]
            $SpAdminUrl = "https://$TenantName-admin.sharepoint.com"
        }
        Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
    } catch {
        [Console]::Error.WriteLine("Get-SharePointMetrics failed: Could not determine SPO admin URL. Please enter it in the SharePoint Admin URL field.")
        exit 1
    }
}

if ($SpAdminUrl -eq "") {
    [Console]::Error.WriteLine("Get-SharePointMetrics failed: SharePoint Admin URL is required.")
    exit 1
}

try {
    Connect-SPOService -Url $SpAdminUrl | Out-Null

    $SharingLevel      = "Unknown"
    $LegacyAuthEnabled = $false
    try {
        $Tenant            = Get-SPOTenant
        $SharingLevel      = $Tenant.SharingCapability.ToString()
        $LegacyAuthEnabled = [bool]$Tenant.LegacyAuthProtocolsEnabled
    } catch {}

    Disconnect-SPOService | Out-Null

    $result = @{
        spo_sharing_level = $SharingLevel
        spo_legacy_auth   = $LegacyAuthEnabled
    } | ConvertTo-Json -Compress

    [Console]::Out.WriteLine($result)
    exit 0

} catch {
    [Console]::Error.WriteLine("Get-SharePointMetrics failed: $_")
    exit 1
}

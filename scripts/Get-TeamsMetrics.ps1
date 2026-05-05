<#
.SYNOPSIS  Get-TeamsMetrics.ps1 — M365 Assessment Tool
           Malcolm McDonald | IT Infrastructure Consultant
.DESCRIPTION
    Collects Microsoft Teams tenant security metrics.
    Always uses interactive login — MicrosoftTeams module
    does not support app-only client credential auth via PowerShell.
    Outputs JSON to stdout. Exit 0 = success.
.NOTES
    Module required: MicrosoftTeams
    Install: Install-Module MicrosoftTeams -Scope CurrentUser

    Permissions needed (delegated):
      Teams Administrator or Global Reader role
#>
param(
    [Parameter(Mandatory=$false)] [string]$AuthMethod   = "Interactive",
    [Parameter(Mandatory=$false)] [string]$TenantId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientSecret = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

try {
    # ── Connect to Teams (always interactive) ─────────────────
    if ($TenantId -ne "") {
        Connect-MicrosoftTeams -TenantId $TenantId | Out-Null
    } else {
        Connect-MicrosoftTeams | Out-Null
    }

    # ── External Access ───────────────────────────────────────
    # Check if external access is restricted (not open to all domains)
    $ExternalAccessRestricted = $false
    $ConsumerAccessBlocked    = $false
    try {
        $ExtPolicy = Get-CsExternalAccessPolicy -Identity Global
        # If AllowedDomains set or federation is off, it's restricted
        $ExternalAccessRestricted = (-not $ExtPolicy.EnableFederationAccess -or
                                     $ExtPolicy.EnableFederationAccess -eq $false)
        $ConsumerAccessBlocked    = (-not $ExtPolicy.EnableTeamsConsumerAccess -or
                                     $ExtPolicy.EnableTeamsConsumerAccess -eq $false)
    } catch {}

    # ── Teams Client Config ───────────────────────────────────
    $EmailIntoChannelEnabled = $false
    try {
        $ClientConfig = Get-CsTeamsClientConfiguration -Identity Global
        $EmailIntoChannelEnabled = [bool]$ClientConfig.AllowEmailIntoChannel
    } catch {}

    Disconnect-MicrosoftTeams | Out-Null

    # ── Output JSON ────────────────────────────────────────────
    @{
        teams_external_access_restricted = $ExternalAccessRestricted
        teams_consumer_access_blocked    = $ConsumerAccessBlocked
        teams_email_into_channel         = $EmailIntoChannelEnabled
    } | ConvertTo-Json -Compress | Write-Output

    exit 0

} catch {
    Write-Error "Get-TeamsMetrics failed: $_"
    exit 1
}

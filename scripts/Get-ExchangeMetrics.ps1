<#
.SYNOPSIS  Get-ExchangeMetrics.ps1 — M365 Assessment Tool
           Malcolm McDonald | IT Infrastructure Consultant
.DESCRIPTION
    Collects Exchange Online security metrics.
    Always uses interactive login — Exchange Online Management
    does not support app-only client credential auth via PowerShell.
    Outputs JSON to stdout. Exit 0 = success.
.NOTES
    Module required: ExchangeOnlineManagement
    Install: Install-Module ExchangeOnlineManagement -Scope CurrentUser

    Permissions needed (delegated, via interactive login):
      Exchange Administrator or Global Reader role
#>
param(
    [Parameter(Mandatory=$false)] [string]$AuthMethod   = "Interactive",
    [Parameter(Mandatory=$false)] [string]$TenantId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientSecret = ""
    # Note: ClientId/ClientSecret not used — Exchange always prompts interactively
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

try {
    # ── Connect to Exchange Online (always interactive) ────────
    if ($TenantId -ne "") {
        Connect-ExchangeOnline -ShowBanner:$false -Organization $TenantId | Out-Null
    } else {
        Connect-ExchangeOnline -ShowBanner:$false | Out-Null
    }

    # ── External Auto-Forwarding ───────────────────────────────
    $ExternalForwardingBlocked = $false
    try {
        $OutboundPolicies = Get-HostedOutboundSpamFilterPolicy
        foreach ($Policy in $OutboundPolicies) {
            if ($Policy.AutoForwardingMode -eq "Off") {
                $ExternalForwardingBlocked = $true
                break
            }
        }
        # Also check transport rules blocking forwarding
        if (-not $ExternalForwardingBlocked) {
            $Rules = Get-TransportRule | Where-Object {
                $_.State -eq "Enabled" -and
                ($_.Description -match "forward" -or $_.RedirectMessageTo -or $_.BlindCopyTo)
            }
            # If there's a rule set to reject or block auto-forward, count it
            $BlockRules = Get-TransportRule | Where-Object {
                $_.State -eq "Enabled" -and $_.RejectMessageReasonText -match "forward"
            }
            if ($BlockRules.Count -gt 0) { $ExternalForwardingBlocked = $true }
        }
    } catch {}

    # ── Mailbox Audit ─────────────────────────────────────────
    $MailboxAuditPct = 0
    try {
        $OrgConfig = Get-OrganizationConfig
        if ($OrgConfig.AuditDisabled -eq $false) {
            # Org-wide auditing enabled = all mailboxes covered
            $MailboxAuditPct = 100
        } else {
            # Check per-mailbox
            $Mailboxes      = Get-Mailbox -ResultSize 500 | Select-Object AuditEnabled
            $AuditEnabled   = ($Mailboxes | Where-Object { $_.AuditEnabled -eq $true }).Count
            $MailboxAuditPct = if ($Mailboxes.Count -gt 0) {
                [math]::Round(($AuditEnabled / $Mailboxes.Count) * 100, 1)
            } else { 0 }
        }
    } catch {}

    # ── Anti-Phishing ─────────────────────────────────────────
    $AntiphishIntelEnabled = $false
    try {
        $AntiPhish = Get-AntiPhishPolicy | Select-Object -First 1
        if ($AntiPhish) {
            $AntiphishIntelEnabled = [bool]$AntiPhish.EnableMailboxIntelligence
        }
    } catch {}

    Disconnect-ExchangeOnline -Confirm:$false | Out-Null

    # ── Output JSON ────────────────────────────────────────────
    @{
        external_forwarding_blocked      = $ExternalForwardingBlocked
        mailbox_audit_enabled_percentage = $MailboxAuditPct
        antiphish_intelligence_enabled   = $AntiphishIntelEnabled
    } | ConvertTo-Json -Compress | Write-Output

    exit 0

} catch {
    Write-Error "Get-ExchangeMetrics failed: $_"
    exit 1
}

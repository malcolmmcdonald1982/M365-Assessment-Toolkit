"""
M365 Assessment Tool — Python Backend v2
M365 Assessment Toolkit

Run with: python backend.py
Requires:  pip install flask flask-cors
Requires:  Node.js + npm install docx (run once in tool folder)

Supports two authentication methods:
  - Interactive:        Browser popup per workload (no setup required)
  - App Registration:  Tenant ID + Client ID + Client Secret (unattended)

Exchange Online, Teams, and SharePoint always use interactive login
regardless of auth method — these workloads do not support app-only
client credential auth via PowerShell in the same way as Graph.
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import subprocess, json, os, datetime, csv, io
import urllib.request, urllib.parse, urllib.error

app = Flask(__name__)
CORS(app)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")
OUTPUT_DIR  = os.path.join(BASE_DIR, "output")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
for d in [SCRIPTS_DIR, OUTPUT_DIR, REPORTS_DIR]:
    os.makedirs(d, exist_ok=True)


# ─────────────────────────────────────────────────────────────
#  FINDINGS LIBRARY
# ─────────────────────────────────────────────────────────────
def build_findings_library():
    return [
        # Identity
        {"id":"ID-001","title":"Low MFA Coverage","module":"identity","metric":"mfa_percentage","severity":"critical",
         "threshold": lambda v: isinstance(v,(int,float)) and v < 95,
         "description":"Fewer than 95% of licensed users have MFA registered. This significantly increases account compromise risk.",
         "recommendation":"Enable MFA for all users via Conditional Access. Consider enabling Security Defaults if no CA policies exist."},

        {"id":"ID-002","title":"Excessive Global Administrators","module":"identity","metric":"global_admin_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 3,
         "description":"More than 3 Global Administrators detected. Global Admin is the highest-privilege role and should be minimised.",
         "recommendation":"Reduce Global Admins to 2–3 break-glass accounts. Use least-privilege roles for day-to-day admin tasks."},

        {"id":"ID-003","title":"No Privileged Identity Management","module":"identity","metric":"pim_enabled","severity":"high",
         "threshold": lambda v: v is False,
         "description":"PIM is not in use. Permanent role assignments expand the attack surface unnecessarily.",
         "recommendation":"Enable Entra PIM and convert permanent admin role assignments to eligible (just-in-time) assignments."},

        {"id":"ID-004","title":"High Guest User Count","module":"identity","metric":"guest_user_count","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 50,
         "description":"A large number of guest accounts exist in the tenant. Unreviewed guests represent a data exposure risk.",
         "recommendation":"Implement an access review policy for guest accounts. Remove guests who no longer require access."},

        {"id":"ID-005","title":"Unused Licences","module":"identity","metric":"unassigned_licence_percentage","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 20,
         "description":"More than 20% of purchased licences are unassigned, representing unnecessary cost.",
         "recommendation":"Audit unassigned licences and remove from the subscription where no longer required."},

        # Security & CA
        {"id":"SEC-001","title":"Low Secure Score","module":"security","metric":"secure_score_percentage","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v < 50,
         "description":"Microsoft Secure Score is below 50%, indicating significant security controls are missing.",
         "recommendation":"Review the Secure Score dashboard in Defender portal. Prioritise high-impact, low-effort recommendations first."},

        {"id":"SEC-002","title":"Security Defaults Disabled — No CA Policies","module":"security","metric":"security_defaults_enabled","severity":"critical",
         "threshold": lambda v, m: v is False and m.get("ca_enabled_policy_count", 0) == 0,
         "description":"Security Defaults are disabled and no compensating Conditional Access policies may be in place.",
         "recommendation":"Either re-enable Security Defaults or implement an equivalent baseline CA policy set covering MFA and legacy auth blocking."},

        {"id":"CA-001","title":"No Conditional Access Policies Enabled","module":"security","metric":"ca_enabled_policy_count","severity":"critical",
         "threshold": lambda v: isinstance(v,(int,float)) and v == 0,
         "description":"No enabled Conditional Access policies found. Access to M365 is not context-aware.",
         "recommendation":"Deploy baseline CA policies: MFA for all users, MFA for admins, block legacy auth, require compliant devices."},

        {"id":"CA-002","title":"Legacy Authentication Not Blocked","module":"security","metric":"legacy_auth_blocked","severity":"critical",
         "threshold": lambda v: v is False,
         "description":"Legacy authentication protocols are not blocked. These bypass MFA and are heavily exploited.",
         "recommendation":"Create a CA policy to block all legacy authentication. Audit dependencies before enforcing."},

        # Exchange
        {"id":"EXO-001","title":"Auto-Forwarding Allowed to External","module":"exchange","metric":"external_forwarding_blocked","severity":"high",
         "threshold": lambda v: v is False,
         "description":"Automatic email forwarding to external recipients is not blocked. This is a common data exfiltration vector.",
         "recommendation":"Set AutoForwardingMode to 'Automatic' block in the outbound spam filter policy, or create a transport rule to block external auto-forwarding."},

        {"id":"EXO-002","title":"Mailbox Auditing Disabled","module":"exchange","metric":"mailbox_audit_enabled_percentage","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v < 90,
         "description":"Mailbox auditing is not enabled for all mailboxes. Audit logs are essential for forensic investigation.",
         "recommendation":"Enable mailbox auditing organisation-wide using Set-OrganizationConfig -AuditDisabled $false."},

        {"id":"EXO-003","title":"Anti-Phishing Intelligence Disabled","module":"exchange","metric":"antiphish_intelligence_enabled","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"Mailbox intelligence in anti-phishing policies is not enabled, reducing protection against targeted attacks.",
         "recommendation":"Enable mailbox intelligence and impersonation protection in the anti-phishing policy."},

        # Teams
        {"id":"TEAMS-001","title":"Unrestricted External Access","module":"teams","metric":"teams_external_access_restricted","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"Teams external access (federation) is not restricted. Users can communicate with any external Teams tenant.",
         "recommendation":"Restrict Teams external access to approved domains only, or disable it if not required."},

        {"id":"TEAMS-002","title":"Teams Consumer Access Enabled","module":"teams","metric":"teams_consumer_access_blocked","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"Users can communicate with Teams personal/consumer accounts, increasing data leakage risk.",
         "recommendation":"Disable Teams consumer access unless there is a specific business requirement."},

        # SharePoint
        {"id":"SPO-001","title":"SharePoint Sharing Set to Anyone","module":"sharepoint","metric":"spo_sharing_level","severity":"critical",
         "threshold": lambda v: v == "ExternalUserAndGuestSharing",
         "description":"SharePoint/OneDrive external sharing is set to Anyone, allowing unauthenticated link sharing.",
         "recommendation":"Restrict sharing to 'New and existing guests' (ExternalUserSharingOnly) at minimum. Review per site collection."},

        {"id":"SPO-002","title":"Legacy Authentication Enabled in SharePoint","module":"sharepoint","metric":"spo_legacy_auth","severity":"high",
         "threshold": lambda v: v is True,
         "description":"Legacy authentication protocols are enabled in SharePoint, bypassing modern auth controls.",
         "recommendation":"Disable LegacyAuthProtocolsEnabled in SharePoint tenant settings."},


        # Over-Permissioned Apps
        {"id":"APP-001","title":"High-Privilege OAuth Apps Detected","module":"security","metric":"high_privilege_app_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more third-party OAuth applications have been granted high-privilege permissions across the tenant. These apps have persistent access to data even after users log out, and are a common persistence mechanism used by attackers following account compromise.",
         "recommendation":"Review all OAuth app permissions in Entra ID under Enterprise Applications. Remove or restrict apps that have unnecessary Graph permissions such as Mail.ReadWrite, Files.ReadWrite.All, or Directory.ReadWrite.All. Enable admin consent workflow to prevent users granting app permissions without approval."},

        # Alerting and Monitoring
        {"id":"MON-001","title":"No Active Defender Alert Policies","module":"security","metric":"defender_alert_policy_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v == 0,
         "description":"No Microsoft Defender alert policies are active. Without alerting, security incidents such as mass file downloads, impossible travel sign-ins, or malware detections will not be flagged to administrators in real time.",
         "recommendation":"Enable Microsoft Defender for Office 365 and configure alert policies for high-severity events including suspicious inbox rules, mass file deletion, impossible travel, and malware detected. Ensure alerts are routed to a monitored mailbox or SIEM."},

        {"id":"SEC-003","title":"MFA Fatigue Protection Not Enabled","module":"security","metric":"mfa_number_matching_enabled","severity":"high",
         "threshold": lambda v: v is False,
         "description":"Microsoft Authenticator number matching and additional context (sign-in location and app name) are not enabled. Without these, users are vulnerable to MFA fatigue attacks where an attacker repeatedly sends push notifications until the user approves one.",
         "recommendation":"Enable number matching and additional context in the Authenticator app settings under Entra ID Authentication Methods. This ensures users see the number displayed on screen before approving, making accidental approvals impossible."},

        {"id":"SEC-004","title":"Weak MFA Methods Enabled","module":"security","metric":"weak_auth_methods_enabled","severity":"medium",
         "threshold": lambda v: v is True,
         "description":"One or more weak authentication methods (SMS text, voice call, or email OTP) are enabled in the tenant. These methods can be intercepted via SIM swapping, call forwarding, or phishing, and are significantly less secure than the Microsoft Authenticator app or FIDO2 keys.",
         "recommendation":"Disable SMS, voice call, and email OTP authentication methods in Entra ID under Authentication Methods policies. Migrate users to Microsoft Authenticator app with number matching, or FIDO2 security keys for highest assurance."},

        {"id":"SEC-005","title":"Users Can Consent to Apps Without Admin Approval","module":"security","metric":"user_consent_unrestricted","severity":"high",
         "threshold": lambda v: v is True,
         "description":"Users are permitted to grant OAuth application permissions to access company data without administrator approval. This allows malicious or over-permissioned apps to gain access to email, files, and other sensitive data simply by convincing a user to click Accept.",
         "recommendation":"Restrict user consent to apps in Entra ID under Enterprise Applications > Consent and Permissions. Set to admin consent required, and enable the admin consent workflow so users can request access through an approved process."},
        # Intune
        {"id":"MDM-001","title":"Low Device Compliance","module":"intune","metric":"intune_compliance_percentage","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v < 80,
         "description":"Fewer than 80% of managed devices are compliant. Non-compliant devices may lack encryption or current patches.",
         "recommendation":"Review non-compliant devices in Intune portal. Identify common failures and remediate. Consider blocking non-compliant device access to M365."},

        {"id":"MDM-002","title":"No Compliance Policies Configured","module":"intune","metric":"intune_compliance_policy_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v == 0,
         "description":"No Intune device compliance policies are in place. Devices cannot be evaluated for compliance.",
         "recommendation":"Create compliance policies for each device platform (Windows, iOS, Android) covering OS version, encryption, and antivirus requirements."},

        # New v1.2 findings
        {"id":"ID-006","title":"Risky Users Not Reviewed","module":"identity","metric":"risky_users_count","severity":"high",
         "threshold": lambda v: isinstance(v,(int,float)) and v > 0,
         "description":"One or more users are flagged as high or medium risk by Entra ID Identity Protection and have not been remediated or dismissed. Risky users indicate potential compromised accounts.",
         "recommendation":"Review risky users in Entra ID > Protection > Risky users. Require password reset or MFA re-registration for at-risk accounts. Investigate the risk events behind each flagged user."},

        {"id":"ID-007","title":"No Emergency Access Account Detected","module":"identity","metric":"emergency_access_exists","severity":"high",
         "threshold": lambda v: v is False,
         "description":"No break-glass (emergency access) account was detected. Without an emergency access account, a misconfigured Conditional Access policy or MFA outage could lock administrators out of the tenant.",
         "recommendation":"Create at least two emergency access accounts. Exclude them from all CA policies. Store credentials securely offline. Monitor for any sign-in activity on these accounts as an indicator of compromise."},

        {"id":"SEC-006","title":"No Microsoft Sentinel Connected","module":"security","metric":"sentinel_connected","severity":"medium",
         "threshold": lambda v: v is False,
         "description":"Microsoft Sentinel does not appear to be connected or generating security alerts. Without a SIEM, threats across M365 services may not be correlated or retained for investigation.",
         "recommendation":"Deploy Microsoft Sentinel and connect the Microsoft 365 Defender data connector. Configure analytics rules for high-priority scenarios and set up a regular alert review process."},

        {"id":"EXO-004","title":"DMARC Not Configured","module":"exchange","metric":"dmarc_configured","severity":"high",
         "threshold": lambda v: v is False,
         "description":"DMARC is not configured on the primary domain. Without DMARC, attackers can spoof your domain in phishing emails, impersonating your organisation to external recipients.",
         "recommendation":"Publish a DMARC TXT record at _dmarc.yourdomain.com. Start with p=none for monitoring, then progress to p=quarantine and p=reject once SPF and DKIM are confirmed working."},

        {"id":"EXO-005","title":"SPF or DKIM Not Configured","module":"exchange","metric":"spf_dkim_configured","severity":"high",
         "threshold": lambda v: v is False,
         "description":"SPF or DKIM email authentication is not fully configured on the primary domain. Without both controls, outbound emails may be rejected by recipients and the domain can be spoofed.",
         "recommendation":"Ensure an SPF TXT record exists for your domain. Enable DKIM signing in Exchange Online Admin > Email authentication. Both must pass before DMARC enforcement is safe to enable."},

        {"id":"MDM-003","title":"No Windows Update Ring Configured","module":"intune","metric":"update_ring_count","severity":"medium",
         "threshold": lambda v: isinstance(v,(int,float)) and v == 0,
         "description":"No Windows Update for Business rings are configured in Intune. Without update rings, Windows devices may receive patches inconsistently or too late, leaving known vulnerabilities unpatched.",
         "recommendation":"Create at least one Windows Update ring in Intune targeting Windows devices. Consider a Pilot ring and a Production ring with a deferral period to catch problematic updates before broad rollout."},

        {"id":"MDM-004","title":"BitLocker Not Enforced","module":"intune","metric":"bitlocker_enforced","severity":"high",
         "threshold": lambda v: v is False,
         "description":"BitLocker disk encryption does not appear to be required by Intune compliance or configuration policies. Devices without encryption expose all data if lost or stolen.",
         "recommendation":"Create an Intune device configuration profile enabling BitLocker on Windows devices. Add a compliance policy condition requiring device encryption, and block non-compliant devices from accessing M365."},
    ]

FINDINGS_LIBRARY = build_findings_library()

METRIC_DISPLAY = {
    "mfa_percentage":                  {"label":"MFA Coverage",                    "format":"{}%",   "desc":"Percentage of users with MFA registered"},
    "global_admin_count":              {"label":"Global Administrators",           "format":"{}",    "desc":"Number of users with Global Admin role"},
    "pim_enabled":                     {"label":"Just-in-Time Admin Access (PIM)", "format":"{}",    "desc":"Whether Privileged Identity Management is active"},
    "guest_user_count":                {"label":"Guest Accounts",                  "format":"{}",    "desc":"Number of external guest users in the tenant"},
    "unassigned_licence_percentage":   {"label":"Unused Licences",                 "format":"{}%",   "desc":"Percentage of purchased licences not assigned"},
    "secure_score_percentage":         {"label":"Microsoft Secure Score",          "format":"{}%",   "desc":"Microsofts own security configuration score"},
    "security_defaults_enabled":       {"label":"Security Defaults Enabled",       "format":"{}",    "desc":"Whether Microsoft baseline security defaults are on"},
    "ca_enabled_policy_count":         {"label":"Conditional Access Policies",     "format":"{}",    "desc":"Number of active Conditional Access policies"},
    "legacy_auth_blocked":             {"label":"Legacy Authentication Blocked",   "format":"{}",    "desc":"Whether old-style auth protocols are blocked"},
    "external_forwarding_blocked":     {"label":"External Email Forwarding Blocked","format":"{}",   "desc":"Whether auto-forwarding to external addresses is blocked"},
    "mailbox_audit_enabled_percentage":{"label":"Mailbox Audit Coverage",          "format":"{}%",   "desc":"Percentage of mailboxes with audit logging enabled"},
    "antiphish_intelligence_enabled":  {"label":"Anti-Phishing Intelligence",      "format":"{}",    "desc":"Whether mailbox intelligence protects against impersonation"},
    "teams_external_access_restricted":{"label":"Teams External Access Restricted","format":"{}",    "desc":"Whether Teams federation is restricted to approved domains"},
    "teams_consumer_access_blocked":   {"label":"Teams Consumer Access Blocked",   "format":"{}",    "desc":"Whether personal Teams accounts are blocked"},
    "spo_sharing_level":               {"label":"SharePoint External Sharing",     "format":"{}",    "desc":"External sharing setting for SharePoint and OneDrive"},
    "spo_legacy_auth":                 {"label":"SharePoint Legacy Auth Enabled",  "format":"{}",    "desc":"Whether old authentication is enabled in SharePoint"},
    "intune_compliance_percentage":    {"label":"Device Compliance Rate",          "format":"{}%",   "desc":"Percentage of managed devices meeting compliance policy"},
    "intune_compliance_policy_count":  {"label":"Device Compliance Policies",      "format":"{}",    "desc":"Number of Intune compliance policies configured"},
    "intune_config_policy_count":      {"label":"Device Config Policies",          "format":"{}",    "desc":"Number of Intune device configuration profiles"},
    "high_privilege_app_count":        {"label":"High-Privilege OAuth Apps",       "format":"{}",    "desc":"Apps with dangerous tenant-wide permissions"},
    "defender_alert_policy_count":     {"label":"Defender Alert Policies",         "format":"{}",    "desc":"Number of active Microsoft Defender alert policies"},
    "mfa_number_matching_enabled":     {"label":"MFA Fatigue Protection",          "format":"{}",    "desc":"Whether Authenticator number matching is enabled"},
    "weak_auth_methods_enabled":       {"label":"Weak MFA Methods Active",         "format":"{}",    "desc":"Whether SMS, voice, or email OTP auth is enabled"},
    "user_consent_unrestricted":       {"label":"Users Can Consent to Apps",       "format":"{}",    "desc":"Whether users can grant app permissions without admin approval"},
    "teams_email_into_channel":        {"label":"Teams Email-to-Channel",          "format":"{}",    "desc":"Whether external emails can be sent into Teams channels"},
    "risky_users_count":               {"label":"Risky Users (High/Medium)",       "format":"{}",    "desc":"Users flagged as high or medium risk by Identity Protection"},
    "emergency_access_exists":         {"label":"Emergency Access Account",        "format":"{}",    "desc":"Whether a break-glass account is detectable in the tenant"},
    "sentinel_connected":              {"label":"Microsoft Sentinel Connected",    "format":"{}",    "desc":"Whether Sentinel appears to be active and generating alerts"},
    "dmarc_configured":                {"label":"DMARC Configured",               "format":"{}",    "desc":"Whether a DMARC record exists for the primary domain"},
    "spf_dkim_configured":             {"label":"SPF and DKIM Configured",        "format":"{}",    "desc":"Whether SPF and DKIM are both set up for the primary domain"},
    "update_ring_count":               {"label":"Windows Update Rings",            "format":"{}",    "desc":"Number of Windows Update for Business rings in Intune"},
    "bitlocker_enforced":              {"label":"BitLocker Enforced",              "format":"{}",    "desc":"Whether BitLocker is required by Intune policies"},
}


# ─────────────────────────────────────────────────────────────
#  SCRIPT RUNNER
# ─────────────────────────────────────────────────────────────

# Map module names → script filenames
MODULE_SCRIPTS = {
    "identity":   "Get-IdentityMetrics.ps1",
    "security":   "Get-SecurityMetrics.ps1",
    "exchange":   "Get-ExchangeMetrics.ps1",
    "teams":      "Get-TeamsMetrics.ps1",
    "sharepoint": "Get-SharePointMetrics.ps1",
    "intune":     "Get-IntuneMetrics.ps1",
}

# Modules that ALWAYS use interactive login (no app-only support)
INTERACTIVE_ONLY_MODULES = {"exchange", "teams", "sharepoint"}


def build_ps_args(module, auth):
    """Build the PowerShell parameter list for a given module and auth config."""
    auth_method = auth.get("authMethod", "interactive")
    environment = auth.get("environment", "commercial").lower()
    args = []

    # Government cloud endpoint overrides
    # GCC uses the same endpoints as Commercial — no change needed
    # GCCH uses graph.microsoft.us / login.microsoftonline.us
    # DoD uses dod-graph.microsoft.us / login.microsoftonline.us
    if environment == "gcch":
        graph_endpoint = "https://graph.microsoft.us"
        login_endpoint = "https://login.microsoftonline.us"
    elif environment == "dod":
        graph_endpoint = "https://dod-graph.microsoft.us"
        login_endpoint = "https://login.microsoftonline.us"
    else:
        # Commercial and GCC both use standard endpoints
        graph_endpoint = "https://graph.microsoft.com"
        login_endpoint = "https://login.microsoftonline.com"

    if auth_method == "appreg" and module not in INTERACTIVE_ONLY_MODULES:
        args += ["-AuthMethod", "AppReg"]
        args += ["-TenantId", auth.get("tenantId", "")]
        args += ["-ClientId", auth.get("clientId", "")]
        args += ["-ClientSecret", auth.get("clientSecret", "")]
        args += ["-GraphEndpoint", graph_endpoint]
        args += ["-LoginEndpoint", login_endpoint]
    elif auth_method == "certificate" and module not in INTERACTIVE_ONLY_MODULES:
        args += ["-AuthMethod", "Certificate"]
        args += ["-TenantId", auth.get("tenantId", "")]
        args += ["-ClientId", auth.get("clientId", "")]
        args += ["-CertThumbprint", auth.get("certThumbprint", "")]
        args += ["-GraphEndpoint", graph_endpoint]
        args += ["-LoginEndpoint", login_endpoint]
    else:
        # Interactive auth (also fallback for cert/appreg on interactive-only modules)
        args += ["-AuthMethod", "Interactive"]
        tenant_id = auth.get("tenantId", "")
        if tenant_id:
            args += ["-TenantId", tenant_id]

    # Pass environment to all modules so Exchange/Teams/SPO can switch endpoints
    args += ["-Environment", environment]

    # SharePoint admin URL for SPO module
    if module == "sharepoint":
        args += ["-SpAdminUrl", auth.get("spAdminUrl", "")]

    return args


def run_script(script_name, ps_args):
    """
    Execute a PowerShell script and return parsed JSON output.
    App Registration: runs silently, captures stdout directly.
    Interactive: runs allowing popup windows, filters WARNING lines before JSON parsing.
    """
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(script_path):
        return None, f"Script not found: {script_name}"

    # Do NOT use -NonInteractive - it blocks login popups for interactive auth
    cmd = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", script_path
    ] + ps_args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        stdout = result.stdout.strip()

        # Filter WARNING and INFO lines - find the JSON output line
        json_line = None
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                json_line = line
                break

        # If script failed and no JSON found, return error
        if result.returncode != 0 and not json_line:
            err = result.stderr.strip() or stdout[:300] or f"Script exited with code {result.returncode}"
            return None, err

        if not json_line:
            err = result.stderr.strip() or "Script produced no JSON output"
            return None, err

        data = json.loads(json_line)
        return data, None

    except subprocess.TimeoutExpired:
        return None, "Script timed out after 300 seconds"
    except json.JSONDecodeError as e:
        stderr = result.stderr.strip() if result else ""
        return None, f"Invalid JSON from script: {e}. stderr: {stderr[:300]}"
    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────────────────────────
#  EVALUATION & SCORING
# ─────────────────────────────────────────────────────────────

def evaluate_findings(all_metrics):
    triggered = []
    for f in FINDINGS_LIBRARY:
        metric = f["metric"]
        if metric not in all_metrics:
            continue
        value = all_metrics[metric]
        try:
            try:
                triggered_flag = f["threshold"](value, all_metrics)
            except TypeError:
                triggered_flag = f["threshold"](value)
            if triggered_flag:
                triggered.append({
                    "id": f["id"], "title": f["title"], "module": f["module"],
                    "metric": metric, "severity": f["severity"],
                    "description": f["description"], "recommendation": f["recommendation"],
                    "observed_value": value
                })
        except Exception:
            pass
    return triggered


def calculate_score(findings):
    """
    Score out of 100. Deductions per finding with caps per severity band
    so a tenant with many findings still gets a meaningful score.
      Critical: -8 each, max -32  (4+ critical = worst band)
      High:     -5 each, max -20
      Medium:   -3 each, max -12
      Low:      -1 each, max -4
    Floor: 10 (even the worst tenant shows a number)
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in counts:
            counts[sev] += 1

    penalty = (
        min(counts["critical"] * 8, 32) +
        min(counts["high"]     * 5, 20) +
        min(counts["medium"]   * 3, 12) +
        min(counts["low"]      * 1,  4)
    )
    return max(10, 100 - penalty)


def format_metric(key, value):
    config = METRIC_DISPLAY.get(key, {"label": key, "format": "{}"})
    try:
        display = config["format"].format(value)
    except Exception:
        display = str(value)

    status = "good"
    if isinstance(value, bool):
        # For flags where True = good
        good_when_true = {"pim_enabled", "security_defaults_enabled", "legacy_auth_blocked",
                          "external_forwarding_blocked", "antiphish_intelligence_enabled",
                          "teams_external_access_restricted", "teams_consumer_access_blocked",
                          "mfa_number_matching_enabled"}
        # Flags where True = bad
        bad_when_true_extra = {"weak_auth_methods_enabled", "user_consent_unrestricted", "teams_email_into_channel"}
        # For flags where False = good
        bad_when_true = {"spo_legacy_auth"}
        if key in bad_when_true or key in bad_when_true_extra:
            status = "bad" if value else "good"
        else:
            status = "good" if value else "bad"
    elif isinstance(value, (int, float)):
        percentage_good_high = {"mfa_percentage", "secure_score_percentage",
                                 "mailbox_audit_enabled_percentage", "intune_compliance_percentage"}
        percentage_good_low  = {"unassigned_licence_percentage"}
        count_good_low       = {"global_admin_count", "guest_user_count"}
        count_good_high      = {"ca_enabled_policy_count", "intune_compliance_policy_count", "defender_alert_policy_count", "intune_config_policy_count"}
        count_good_zero      = {"high_privilege_app_count", "risky_users_count"}
        count_good_nonzero   = {"update_ring_count"}

        if key in percentage_good_high:
            status = "good" if value >= 90 else ("warn" if value >= 70 else "bad")
        elif key in percentage_good_low:
            status = "good" if value <= 10 else ("warn" if value <= 20 else "bad")
        elif key in count_good_low:
            status = "good" if value <= 2 else ("warn" if value <= 4 else "bad")
        elif key in count_good_high:
            status = "good" if value >= 3 else ("warn" if value >= 1 else "bad")
        elif key in count_good_zero:
            status = "good" if value == 0 else ("warn" if value <= 2 else "bad")
        elif key in count_good_nonzero:
            status = "good" if value >= 1 else "bad"
    elif isinstance(value, str):
        bad_values = {"ExternalUserAndGuestSharing", "anyone"}
        warn_values = {"ExternalUserSharingOnly", "new_and_existing"}
        if value in bad_values: status = "bad"
        elif value in warn_values: status = "warn"

    # Convert True/False to friendly labels
    if isinstance(value, bool):
        friendly_map = {
            "pim_enabled": ("Active", "Not Active"),
            "security_defaults_enabled": ("Enabled", "Disabled"),
            "legacy_auth_blocked": ("Blocked", "Not Blocked"),
            "external_forwarding_blocked": ("Blocked", "Not Blocked"),
            "antiphish_intelligence_enabled": ("Enabled", "Disabled"),
            "teams_external_access_restricted": ("Restricted", "Open"),
            "teams_consumer_access_blocked": ("Blocked", "Allowed"),
            "spo_legacy_auth": ("Enabled", "Disabled"),
            "mfa_number_matching_enabled": ("Enabled", "Disabled"),
            "weak_auth_methods_enabled": ("Yes - Review", "No"),
            "user_consent_unrestricted": ("Yes - Review", "Restricted"),
            "teams_email_into_channel": ("Allowed", "Blocked"),
            "emergency_access_exists": ("Detected", "Not Detected"),
            "sentinel_connected": ("Connected", "Not Connected"),
            "dmarc_configured": ("Configured", "Not Configured"),
            "spf_dkim_configured": ("Configured", "Not Configured"),
            "bitlocker_enforced": ("Enforced", "Not Enforced"),
        }
        if key in friendly_map:
            display = friendly_map[key][0] if value else friendly_map[key][1]

    # SharePoint sharing level friendly labels
    spo_labels = {
        "ExternalUserAndGuestSharing": "Anyone (Unrestricted)",
        "ExternalUserSharingOnly": "New and Existing Guests",
        "ExistingExternalUserSharingOnly": "Existing Guests Only",
        "Disabled": "No External Sharing",
        "Unknown": "Could not retrieve",
    }
    if key == "spo_sharing_level":
        display = spo_labels.get(str(value), str(value))

    desc = config.get("desc", "")
    return {"label": config["label"], "value": display, "status": status, "sub": desc}


def save_csvs(client_name, all_metrics, findings):
    date_str = datetime.date.today().strftime("%Y%m%d")
    safe = client_name.replace(" ", "_")
    with open(os.path.join(OUTPUT_DIR, f"TenantMetrics_{safe}_{date_str}.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["Metric","Value"])
        for k, v in all_metrics.items(): w.writerow([k, v])
    fields = ["id","title","module","metric","severity","observed_value","recommendation"]
    with open(os.path.join(OUTPUT_DIR, f"TriggeredFindings_{safe}_{date_str}.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for fi in findings: w.writerow({k: fi.get(k,"") for k in fields})


def save_session(session_data):
    """Save full assessment session as JSON for later reload."""
    client_name = session_data.get("orgName", session_data.get("clientName", "Unknown"))
    assess_date = session_data.get("assessDate", datetime.date.today().isoformat())
    safe = client_name.replace(" ", "_").replace("/", "-")
    date_str = assess_date.replace("-", "")
    # Add timestamp to avoid overwriting same-day runs
    timestamp = datetime.datetime.now().strftime("%H%M%S")
    filename = f"Session_{safe}_{date_str}_{timestamp}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(session_data, f, ensure_ascii=False, indent=2)
    return filename


# ─────────────────────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────────────────────

@app.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "online", "version": "1.2.0",
                    "findings_loaded": len(FINDINGS_LIBRARY), "scripts_dir": SCRIPTS_DIR})


@app.route("/run", methods=["POST"])
def run_assessment():
    body          = request.get_json()
    client_name   = body.get("orgName", body.get("clientName", "Unknown"))
    modules       = body.get("modules", [])
    auth          = {k: body.get(k,"") for k in
                     ["authMethod","tenantId","clientId","clientSecret","certThumbprint","spAdminUrl","environment"]}

    log = []
    all_metrics = {}

    def L(msg, t="info"):
        log.append({"message": msg, "type": t})
        print(f"[{t.upper()}] {msg}", flush=True)

    L(f"Assessment started — {client_name}")
    L(f"Auth method: {auth['authMethod']}")

    for module in modules:
        script = MODULE_SCRIPTS.get(module)
        if not script:
            L(f"Unknown module: {module}", "warn"); continue

        is_interactive_only = module in INTERACTIVE_ONLY_MODULES
        if auth["authMethod"] == "interactive" or is_interactive_only:
            effective_auth = "interactive"
        elif auth["authMethod"] == "certificate":
            effective_auth = "certificate"
        else:
            effective_auth = "appreg"

        if is_interactive_only and auth["authMethod"] == "appreg":
            L(f"{module}: App Reg not supported for this workload — using interactive login", "warn")

        L(f"Running: {script} [{effective_auth}]")
        ps_args = build_ps_args(module, auth)
        metrics, error = run_script(script, ps_args)

        if error:
            L(f"{module} failed: {error}", "error")
        elif metrics:
            all_metrics.update(metrics)
            L(f"{module} complete — {len(metrics)} metrics collected", "success")
        else:
            L(f"{module} returned no data", "warn")

    findings = evaluate_findings(all_metrics)
    score    = calculate_score(findings)
    display_metrics = [format_metric(k, v) for k, v in all_metrics.items()]

    L(f"Findings: {len(findings)} triggered")
    L(f"Score: {score}/100")

    try:
        save_csvs(client_name, all_metrics, findings)
        L("CSVs saved to /output", "success")
    except Exception as e:
        L(f"CSV save failed: {e}", "warn")

    assess_date = datetime.date.today().isoformat()
    # Check if a remediation log exists for this client
    safe_client = client_name.replace(" ", "_").replace("/", "-")
    rem_log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe_client}.json")
    rem_log = []
    if os.path.exists(rem_log_path):
        try:
            with open(rem_log_path, "r", encoding="utf-8") as f:
                rem_log = json.load(f)
        except Exception:
            pass

    session = {
        "orgName": client_name, "clientName": client_name,
        "authMethod": auth["authMethod"],
        "assessDate": assess_date,
        "score": score,
        "metrics": display_metrics,
        "findings": findings,
        "rawMetrics": all_metrics,
        "modulesRun": len(modules),
        "log": log,
        "savedAt": datetime.datetime.now().isoformat(),
        "toolVersion": "1.2.0",
        "remediationLog": rem_log,
    }

    try:
        saved_file = save_session(session)
        L(f"Session saved: {saved_file}", "success")
        session["savedFile"] = saved_file
    except Exception as e:
        L(f"Session save failed: {e}", "warn")

    return jsonify(session)


@app.route("/report", methods=["POST"])
def report_meta():
    body = request.get_json()
    return jsonify({"status":"ready","modulesRun": body.get("modulesRun",0),
                    "findingsCount": len(body.get("findings",[]))})


@app.route("/download", methods=["POST"])
def download_report():
    """
    Generate a professional colour-coded .docx report using the Node.js generator.
    Requires Node.js and: npm install docx  (run once in the tool folder)
    """
    body        = request.get_json()
    client_name = body.get("orgName", body.get("clientName", "Organisation"))
    assess_date = body.get("assessDate", str(datetime.date.today()))

    safe_name   = client_name.replace(" ", "_").replace("/", "-")
    filename    = f"M365_Assessment_{safe_name}_{assess_date.replace('-', '')}.docx"
    report_path = os.path.join(REPORTS_DIR, filename)
    json_path   = os.path.join(REPORTS_DIR, f"_tmp_{safe_name}.json")
    generator   = os.path.join(BASE_DIR, "generate-report.js")

    if not os.path.exists(generator):
        return jsonify({"error": "generate-report.js not found. Place it in the same folder as backend.py."}), 500

    # Write assessment data to a temp JSON file for the Node script
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(body, f, ensure_ascii=False)

    try:
        result = subprocess.run(
            ["node", generator, json_path, report_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            error_detail = result.stderr.strip() or result.stdout.strip()
            return jsonify({"error": f"Report generator failed: {error_detail}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Node.js not found. Install from https://nodejs.org"}), 500
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

    if not os.path.exists(report_path):
        return jsonify({"error": "Report file was not created — check Node.js and docx module are installed."}), 500

    return send_file(
        report_path,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename
    )






@app.route("/download-remediation", methods=["POST"])
def download_remediation_report():
    """
    Generate a separate Remediation Report document.
    Only available when a remediation log exists for the client.
    """
    body        = request.get_json()
    client_name = body.get("orgName", body.get("clientName", "Organisation"))
    assess_date = body.get("assessDate", str(datetime.date.today()))
    rem_date    = datetime.date.today().isoformat()

    safe_name   = client_name.replace(" ", "_").replace("/", "-")
    filename    = f"M365_RemediationReport_{safe_name}_{rem_date.replace('-','')}.docx"
    report_path = os.path.join(REPORTS_DIR, filename)
    json_path   = os.path.join(REPORTS_DIR, f"_tmp_rem_{safe_name}.json")
    generator   = os.path.join(BASE_DIR, "generate-report.js")

    print(f"[REMEDIATION REPORT] Organisation: {client_name}, Safe: {safe_name}", flush=True)
    print(f"[REMEDIATION REPORT] Generator: {generator} exists={os.path.exists(generator)}", flush=True)

    if not os.path.exists(generator):
        return jsonify({"error": "generate-report.js not found"}), 500

    # Always load from file — file is source of truth and includes rollbacks
    # that may have happened after the frontend cached the session data
    log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe_name}.json")
    print(f"[REMEDIATION REPORT] Log path: {log_path} exists={os.path.exists(log_path)}", flush=True)
    rem_log = []
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                rem_log = json.load(f)
        except Exception as e:
            print(f"[REMEDIATION REPORT] Log read error: {e}", flush=True)
    # Fall back to body if file missing
    if not rem_log:
        rem_log = body.get("remediationLog", [])

    print(f"[REMEDIATION REPORT] Log entries: {len(rem_log)}", flush=True)

    if not rem_log:
        return jsonify({"error": "No remediation log found for this client. Complete at least one remediation before generating this report."}), 400

    # Calculate after-remediation score
    remediatedIds = {e["findingId"] for e in rem_log if e.get("action") == "remediate" and e.get("success")}
    rolledBackIds = {e["findingId"] for e in rem_log if e.get("action") == "rollback" and e.get("success")}
    netFixed      = remediatedIds - rolledBackIds
    openFindings  = [f for f in body.get("findings", []) if f["id"] not in netFixed]
    score_after   = calculate_score(openFindings)

    # Build data payload for remediation report
    report_data = {
        **body,
        "remediationLog": rem_log,
        "remediationDate": rem_date,
        "scoreAfter": score_after,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False)

    try:
        result = subprocess.run(
            ["node", generator, json_path, report_path, "remediation"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return jsonify({"error": f"Report generator failed: {result.stderr.strip()}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Node.js not found"}), 500
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

    if not os.path.exists(report_path):
        return jsonify({"error": "Report file was not created"}), 500

    return send_file(
        report_path,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name=filename
    )

@app.route("/download-pdf", methods=["POST"])
def download_pdf():
    """
    Generate a PDF report by first creating the .docx then converting via LibreOffice.
    Falls back to generating a clean HTML-based PDF using weasyprint if available.
    """
    body        = request.get_json()
    client_name = body.get("orgName", body.get("clientName", "Organisation"))
    assess_date = body.get("assessDate", str(datetime.date.today()))

    safe_name   = client_name.replace(" ", "_").replace("/", "-")
    docx_name   = f"M365_Assessment_{safe_name}_{assess_date.replace('-','')}.docx"
    pdf_name    = f"M365_Assessment_{safe_name}_{assess_date.replace('-','')}.pdf"
    docx_path   = os.path.join(REPORTS_DIR, docx_name)
    pdf_path    = os.path.join(REPORTS_DIR, pdf_name)
    json_path   = os.path.join(REPORTS_DIR, f"_tmp_{safe_name}.json")
    generator   = os.path.join(BASE_DIR, "generate-report.js")

    if not os.path.exists(generator):
        return jsonify({"error": "generate-report.js not found"}), 500

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(body, f, ensure_ascii=False)

    try:
        # Step 1: Generate the docx
        result = subprocess.run(
            ["node", generator, json_path, docx_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return jsonify({"error": f"Report generator failed: {result.stderr.strip()}"}), 500

        # Step 2: Try LibreOffice conversion
        lo_paths = [
            r"C:\Program Files\LibreOffice\program\soffice.exe",
            r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
            "soffice",
        ]
        lo_exe = None
        for p in lo_paths:
            if os.path.exists(p) or p == "soffice":
                try:
                    subprocess.run([p, "--version"], capture_output=True, timeout=5)
                    lo_exe = p
                    break
                except Exception:
                    continue

        if lo_exe:
            conv = subprocess.run(
                [lo_exe, "--headless", "--convert-to", "pdf", "--outdir", REPORTS_DIR, docx_path],
                capture_output=True, text=True, timeout=120
            )
            if conv.returncode == 0 and os.path.exists(pdf_path):
                return send_file(pdf_path, mimetype="application/pdf",
                                 as_attachment=True, download_name=pdf_name)

        # Step 3: Fallback - generate HTML-based PDF report
        html_pdf = generate_html_pdf(body, assess_date)
        return send_file(
            io.BytesIO(html_pdf.encode("utf-8")),
            mimetype="text/html",
            as_attachment=True,
            download_name=f"M365_Assessment_{safe_name}_{assess_date.replace('-','')}.html"
        )

    except FileNotFoundError:
        return jsonify({"error": "Node.js not found"}), 500
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)


def generate_html_pdf(data, assess_date):
    """Generate a clean, print-ready HTML report as PDF fallback."""
    findings  = data.get("findings", [])
    score     = data.get("score", 0)
    client          = data.get("orgName", data.get("clientName", "Organisation"))
    consultant_name  = data.get("consultantName", "[Consultant Name]")
    consultant_role  = data.get("consultantRole",  "[Role]")
    consultant_email = data.get("consultantEmail", "[Email]")
    metrics   = data.get("metrics", [])

    sev_colours = {"critical":"#C0392B","high":"#D35400","medium":"#D4AC0D","low":"#27AE60"}
    score_colour = "#27AE60" if score >= 70 else "#D4AC0D" if score >= 50 else "#C0392B"

    counts = {s: len([f for f in findings if f["severity"]==s]) for s in ["critical","high","medium","low"]}

    order = {"critical":0,"high":1,"medium":2,"low":3}
    sorted_findings = sorted(findings, key=lambda x: order.get(x["severity"],9))

    findings_html = ""
    for f in sorted_findings:
        col = sev_colours.get(f["severity"], "#666")
        findings_html += f"""
        <div class="finding">
          <div class="finding-header" style="border-left: 6px solid {col}; padding-left: 12px;">
            <span class="badge" style="background:{col}">{f["severity"].upper()}</span>
            <span class="finding-id">{f["id"]}</span>
            <strong>{f["title"]}</strong>
          </div>
          <table class="finding-table">
            <tr><td class="ft-label">What this means</td><td>{f["description"]}</td></tr>
            <tr><td class="ft-label">Recommendation</td><td>{f["recommendation"]}</td></tr>
            <tr><td class="ft-label">Observed value</td><td>{f.get("observed_value","")}</td></tr>
          </table>
        </div>"""

    metrics_html = ""
    for m in metrics:
        col = "#27AE60" if m["status"]=="good" else "#D4AC0D" if m["status"]=="warn" else "#C0392B"
        metrics_html += f'<tr><td>{m["label"]}</td><td style="font-weight:bold;color:{col}">{m["value"]}</td></tr>'

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>M365 Assessment - {client}</title>
<style>
  @media print {{ @page {{ margin: 2cm; }} .no-print {{ display:none; }} }}
  body {{ font-family: Arial, sans-serif; font-size: 11pt; color: #212529; margin: 0; padding: 20px; }}
  h1 {{ color: #1B2A4A; font-size: 22pt; border-bottom: 3px solid #1B2A4A; padding-bottom: 8px; }}
  h2 {{ color: #2E4A7A; font-size: 15pt; border-bottom: 1px solid #DEE2E6; padding-bottom: 4px; margin-top: 30px; }}
  .cover {{ text-align:center; padding: 60px 0; border-bottom: 2px solid #1B2A4A; margin-bottom: 30px; }}
  .cover h1 {{ font-size: 28pt; border: none; }}
  .cover p {{ color: #6c757d; font-size: 12pt; }}
  .score-box {{ background: {score_colour}22; border: 3px solid {score_colour}; border-radius: 10px;
                text-align: center; padding: 20px; margin: 20px 0; }}
  .score-num {{ font-size: 48pt; font-weight: bold; color: {score_colour}; }}
  .counts {{ display: flex; gap: 10px; margin: 20px 0; }}
  .count-box {{ flex: 1; text-align: center; padding: 15px; border-radius: 6px; }}
  .count-num {{ font-size: 28pt; font-weight: bold; }}
  .finding {{ margin-bottom: 20px; border: 1px solid #DEE2E6; border-radius: 6px; overflow: hidden; }}
  .finding-header {{ padding: 10px 12px; background: #f8f9fa; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .badge {{ color: white; padding: 2px 8px; border-radius: 3px; font-size: 9pt; font-weight: bold; }}
  .finding-id {{ font-size: 9pt; color: #6c757d; font-family: monospace; }}
  .finding-table {{ width: 100%; border-collapse: collapse; }}
  .finding-table td {{ padding: 8px 12px; border-top: 1px solid #DEE2E6; vertical-align: top; font-size: 10pt; }}
  .ft-label {{ width: 140px; color: #495057; font-weight: bold; background: #f8f9fa; }}
  .metrics-table {{ width: 100%; border-collapse: collapse; }}
  .metrics-table th {{ background: #1B2A4A; color: white; padding: 8px 12px; text-align: left; }}
  .metrics-table td {{ padding: 7px 12px; border-bottom: 1px solid #DEE2E6; font-size: 10pt; }}
  .metrics-table tr:nth-child(even) td {{ background: #f8f9fa; }}
  .notice {{ background: #EBF5FB; border-left: 5px solid #2E4A7A; padding: 12px 16px; margin: 20px 0; font-size: 10pt; line-height: 1.6; }}
  footer {{ margin-top: 40px; padding-top: 10px; border-top: 1px solid #DEE2E6; color: #6c757d; font-size: 9pt; text-align: center; }}
  .no-print {{ text-align:center; margin-bottom: 20px; }}
  .print-btn {{ background: #1B2A4A; color: white; border: none; padding: 10px 24px; border-radius: 6px; font-size: 12pt; cursor: pointer; }}
</style>
</head><body>
<div class="no-print"><button class="print-btn" onclick="window.print()">Print / Save as PDF</button></div>
<div class="cover">
  <h1>Microsoft 365 Health Assessment</h1>
  <p style="font-size:18pt;font-weight:bold;color:#2E4A7A">{client}</p>
  <p>Assessment Date: {assess_date}</p>
  <p>Prepared by {consultant_name} &nbsp;|&nbsp; {consultant_role}</p>
  <p style="color:#C0392B;font-weight:bold">CONFIDENTIAL</p>
</div>

<h2>1. Executive Summary</h2>
<div class="score-box">
  <div class="score-num">{score}/100</div>
  <div>Overall Security Score</div>
</div>
<div class="counts">
  <div class="count-box" style="background:#FDECEA;border:2px solid #C0392B"><div class="count-num" style="color:#C0392B">{counts["critical"]}</div><div>Critical</div></div>
  <div class="count-box" style="background:#FEF0E7;border:2px solid #D35400"><div class="count-num" style="color:#D35400">{counts["high"]}</div><div>High</div></div>
  <div class="count-box" style="background:#FEFAE7;border:2px solid #D4AC0D"><div class="count-num" style="color:#D4AC0D">{counts["medium"]}</div><div>Medium</div></div>
  <div class="count-box" style="background:#EAF7EE;border:2px solid #27AE60"><div class="count-num" style="color:#27AE60">{counts["low"]}</div><div>Low</div></div>
</div>
<div class="notice">
  <strong>Beyond Microsoft Secure Score:</strong> Microsoft Secure Score measures configuration compliance - whether recommended settings are turned on.
  This assessment evaluates real attack paths. A tenant can achieve a high Secure Score and still be vulnerable to business email compromise, OAuth app abuse, and lateral movement.
  Each finding below represents a genuine risk that an attacker could exploit.
</div>

<h2>2. Findings</h2>
{findings_html}

<h2>3. Metrics Summary</h2>
<table class="metrics-table">
  <tr><th>Metric</th><th>Value</th></tr>
  {metrics_html}
</table>

<footer>{consultant_name} &nbsp;|&nbsp; {consultant_role} &nbsp;|&nbsp; {consultant_email}</footer>
</body></html>"""




# =================================================================
#  APP REGISTRATION PERMISSION CHECKER
# =================================================================

# Required permissions per module (Graph Application permissions)
MODULE_REQUIRED_PERMISSIONS = {
    "identity": [
        "User.Read.All",
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "AuditLog.Read.All",
        "Organization.Read.All",
        "Policy.Read.All",
    ],
    "security": [
        "Policy.Read.All",
        "SecurityEvents.Read.All",
        "Organization.Read.All",
        "Application.Read.All",
    ],
    "intune": [
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All",
    ],
    # Exchange, Teams, SharePoint always use interactive - no app reg check needed
    "exchange":   [],
    "teams":      [],
    "sharepoint": [],
}

INTERACTIVE_ONLY_MODULES_SET = {"exchange", "teams", "sharepoint"}




@app.route("/test-connection", methods=["POST"])
def test_connection():
    """Quick connection test - validates credentials without running a full assessment."""
    body          = request.get_json()
    auth_method   = body.get("authMethod", "interactive").strip().lower()
    tenant_id     = body.get("tenantId", "").strip()
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()

    if auth_method == "appreg":
        if not all([tenant_id, client_id, client_secret]):
            return jsonify({"connected": False, "error": "Tenant ID, Client ID and Client Secret are all required"})

        try:
            token_url  = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            token_data = urllib.parse.urlencode({
                "grant_type": "client_credentials", "client_id": client_id,
                "client_secret": client_secret, "scope": "https://graph.microsoft.com/.default",
            }).encode("utf-8")
            req = urllib.request.Request(token_url, data=token_data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=10) as resp:
                token_resp = json.loads(resp.read().decode("utf-8"))
            access_token = token_resp.get("access_token")
            if not access_token:
                return jsonify({"connected": False, "error": "No access token returned. Check credentials."})
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
                err_desc = err_body.get("error_description", str(e))[:120]
            except Exception:
                err_desc = str(e)
            return jsonify({"connected": False, "error": f"Authentication failed: {err_desc}"})
        except Exception as e:
            return jsonify({"connected": False, "error": f"Connection failed: {str(e)[:120]}"})

        # Get org info to confirm access
        try:
            org_req = urllib.request.Request("https://graph.microsoft.com/v1.0/organization?$select=displayName,verifiedDomains")
            org_req.add_header("Authorization", f"Bearer {access_token}")
            with urllib.request.urlopen(org_req, timeout=10) as resp:
                org_data = json.loads(resp.read().decode("utf-8"))
            org    = org_data.get("value", [{}])[0]
            name   = org.get("displayName", "Unknown")
            domain = next((d.get("name","") for d in org.get("verifiedDomains",[]) if d.get("isInitial")), "")
            return jsonify({"connected": True, "tenantName": name, "domain": domain,
                            "authMode": "App Registration", "message": f"Connected to {name} ({domain})"})
        except Exception:
            return jsonify({"connected": True, "message": "Connected - token obtained successfully", "authMode": "App Registration"})
    else:
        return jsonify({"connected": True, "message": "Interactive login will be prompted when assessment runs", "authMode": "Interactive"})

@app.route("/check-permissions", methods=["POST"])
def check_permissions():
    """
    Verify an App Registration has the required Graph permissions
    for the selected assessment modules.
    Calls the Graph API to get the service principal's app roles
    and compares against required permissions.
    """
    body          = request.get_json()
    tenant_id     = body.get("tenantId", "").strip()
    client_id     = body.get("clientId", "").strip()
    client_secret = body.get("clientSecret", "").strip()
    modules       = body.get("modules", list(MODULE_REQUIRED_PERMISSIONS.keys()))

    if not tenant_id or not client_id or not client_secret:
        return jsonify({"error": "Tenant ID, Client ID and Client Secret are required"}), 400

    # Get an access token using client credentials
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = urllib.parse.urlencode({
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "https://graph.microsoft.com/.default",
    }).encode("utf-8")

    try:
        req = urllib.request.Request(token_url, data=token_data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=15) as resp:
            token_resp = json.loads(resp.read().decode("utf-8"))
        access_token = token_resp.get("access_token")
        if not access_token:
            return jsonify({"error": "Could not obtain access token. Check Tenant ID, Client ID and Secret."}), 401
    except urllib.error.HTTPError as e:
        err_body = json.loads(e.read().decode("utf-8"))
        err_desc = err_body.get("error_description", str(e))
        return jsonify({"error": f"Authentication failed: {err_desc[:200]}"}), 401
    except Exception as e:
        return jsonify({"error": f"Token request failed: {str(e)}"}), 500

    # Get the service principal for this app registration
    try:
        sp_url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{client_id}'&$select=id,displayName,appRoles"
        req2   = urllib.request.Request(sp_url)
        req2.add_header("Authorization", f"Bearer {access_token}")
        req2.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req2, timeout=15) as resp:
            sp_data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return jsonify({"error": f"Could not query service principal: {str(e)}"}), 500

    # Get granted app role assignments (what permissions have been granted + consented)
    granted_permissions = set()
    try:
        sp_list = sp_data.get("value", [])
        if sp_list:
            sp_id = sp_list[0]["id"]
            # Get app role assignments for this SP
            roles_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
            req3 = urllib.request.Request(roles_url)
            req3.add_header("Authorization", f"Bearer {access_token}")
            with urllib.request.urlopen(req3, timeout=15) as resp:
                roles_data = json.loads(resp.read().decode("utf-8"))

            # For each role assignment, get the permission name from the resource SP
            resource_sps = {}
            for assignment in roles_data.get("value", []):
                resource_id   = assignment.get("resourceId")
                app_role_id   = assignment.get("appRoleId")
                if not resource_id or not app_role_id:
                    continue
                # Cache resource SP lookups
                if resource_id not in resource_sps:
                    try:
                        rsp_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{resource_id}?$select=appRoles,displayName"
                        req4 = urllib.request.Request(rsp_url)
                        req4.add_header("Authorization", f"Bearer {access_token}")
                        with urllib.request.urlopen(req4, timeout=15) as resp:
                            resource_sps[resource_id] = json.loads(resp.read().decode("utf-8"))
                    except Exception:
                        resource_sps[resource_id] = {}

                rsp     = resource_sps.get(resource_id, {})
                sp_name = rsp.get("displayName", "")
                if sp_name == "Microsoft Graph":
                    for role in rsp.get("appRoles", []):
                        if role.get("id") == app_role_id:
                            granted_permissions.add(role.get("value", ""))
                            break
    except Exception as e:
        return jsonify({"error": f"Could not retrieve permissions: {str(e)}"}), 500

    # Check each module
    results = {}
    all_ok  = True

    for module in modules:
        if module in INTERACTIVE_ONLY_MODULES_SET:
            results[module] = {
                "status":  "interactive",
                "message": "This module always uses interactive login — App Registration not required.",
                "missing": [],
                "granted": [],
            }
            continue

        required = MODULE_REQUIRED_PERMISSIONS.get(module, [])
        missing  = [p for p in required if p not in granted_permissions]
        present  = [p for p in required if p in granted_permissions]

        if missing:
            all_ok = False
            results[module] = {
                "status":  "missing",
                "message": f"{len(missing)} permission(s) missing. Grant them in Entra ID and re-run admin consent.",
                "missing": missing,
                "granted": present,
            }
        else:
            results[module] = {
                "status":  "ok",
                "message": "All required permissions granted.",
                "missing": [],
                "granted": present,
            }

    # Build missing list and fix instructions
    all_missing = []
    for mod_result in results.values():
        all_missing.extend(mod_result.get("missing", []))
    all_missing = list(set(all_missing))

    fix_instructions = []
    if all_missing:
        fix_instructions.append(f"Go to Entra ID > App registrations > {client_id} > API permissions")
        fix_instructions.append("Click: Add a permission > Microsoft Graph > Application permissions")
        for perm in sorted(all_missing):
            fix_instructions.append(f"Add: {perm}")
        fix_instructions.append("Click: Grant admin consent for your organisation")

    # Normalise module results for frontend compatibility
    norm_modules = {}
    for mod, res in results.items():
        norm_modules[mod] = {
            "status":   res.get("status", "ok"),
            "present":  res.get("granted", []),
            "missing":  res.get("missing", []),
            "authMode": "Interactive" if res.get("status") == "interactive" else "AppRegistration",
            "note":     res.get("message", ""),
        }

    return jsonify({
        "success":         True,
        "allGranted":      all_ok,
        "allOk":           all_ok,
        "grantedCount":    len(granted_permissions),
        "grantedPerms":    sorted(list(granted_permissions)),
        "modules":         norm_modules,
        "missingAll":      all_missing,
        "fixInstructions": fix_instructions,
        "tenantId":        tenant_id,
        "clientId":        client_id,
    })






@app.route("/sessions/<filename>", methods=["GET"])
def load_session(filename):
    """
    Load a specific saved assessment session.
    Also scans the output folder for any snapshot files for this client
    and returns remediation state so rollback works after reload.
    """
    if not filename.startswith("Session_") or not filename.endswith(".json"):
        return jsonify({"error": "Invalid session file"}), 400
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Session file not found"}), 404
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        client_name = data.get("clientName", "")
        safe        = client_name.replace(" ", "_").replace("/", "-")

        # Scan for snapshot files for this client and restore remediation state
        remediation_state = {}
        try:
            for fname in os.listdir(OUTPUT_DIR):
                if fname.startswith(f"Snapshot_{safe}_") and fname.endswith(".json"):
                    snap_path = os.path.join(OUTPUT_DIR, fname)
                    try:
                        with open(snap_path, "r", encoding="utf-8") as sf:
                            snap = json.load(sf)
                        finding_id = snap.get("findingId")
                        if finding_id:
                            # Most recent snapshot wins
                            existing = remediation_state.get(finding_id, {})
                            if snap.get("timestamp", "") >= existing.get("timestamp", ""):
                                remediation_state[finding_id] = {
                                    "status": "done",
                                    "snapshotFile": fname,
                                    "timestamp": snap.get("timestamp", ""),
                                    "previousState": snap.get("previousState", {}),
                                }
                    except Exception:
                        pass
        except Exception:
            pass

        # Also load remediation log to mark any rolled-back items
        log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe}.json")
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as lf:
                    log = json.load(lf)
                # Process log entries in order - last action wins per finding
                for entry in log:
                    fid = entry.get("findingId")
                    if not fid: continue
                    action = entry.get("action")
                    if action == "rollback" and entry.get("success"):
                        if fid in remediation_state:
                            remediation_state[fid]["status"] = "rolled"
                    elif action == "remediate" and entry.get("success"):
                        snap_file = entry.get("snapshotFile")
                        if fid not in remediation_state and snap_file:
                            remediation_state[fid] = {
                                "status": "done",
                                "snapshotFile": snap_file,
                                "timestamp": entry.get("timestamp", ""),
                            }
                data["remediationLog"] = log
            except Exception:
                pass

        data["remediationState"] = remediation_state
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sessions/<filename>", methods=["DELETE"])
def delete_session(filename):
    """Delete a saved session file."""
    if not filename.startswith("Session_") or not filename.endswith(".json"):
        return jsonify({"error": "Invalid session file"}), 400
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Session not found"}), 404
    try:
        os.remove(filepath)
        return jsonify({"deleted": filename})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sessions", methods=["GET"])
def list_sessions():
    """List all saved assessment sessions, newest first."""
    sessions = []
    try:
        files = sorted(
            [f for f in os.listdir(OUTPUT_DIR) if f.startswith("Session_") and f.endswith(".json")],
            reverse=True
        )
        for fname in files:
            filepath = os.path.join(OUTPUT_DIR, fname)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                sessions.append({
                    "filename":     fname,
                    "clientName":   data.get("clientName", data.get("orgName", "Unknown")),
                    "assessDate":   data.get("assessDate", ""),
                    "score":        data.get("score", 0),
                    "findingsCount": len(data.get("findings", [])),
                    "modulesRun":   data.get("modulesRun", 0),
                    "savedAt":      data.get("savedAt", ""),
                    "toolVersion":  data.get("toolVersion", ""),
                })
            except Exception:
                pass
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"sessions": sessions})








# =================================================================
#  PHASE 4 - MULTI-ASSESSMENT COMPARISON
# =================================================================

@app.route("/compare", methods=["POST"])
def compare_assessments():
    """
    Compare two saved assessment sessions.
    Returns a structured comparison including score delta,
    resolved findings, new findings, still open, and trend data.
    """
    body    = request.get_json()
    file_a  = body.get("sessionA", "")
    file_b  = body.get("sessionB", "")

    if not file_a or not file_b:
        return jsonify({"error": "Two session files required"}), 400

    # Load both sessions
    def load_sess(filename):
        if not filename.startswith("Session_") or not filename.endswith(".json"):
            return None, "Invalid session file"
        path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(path):
            return None, f"Session not found: {filename}"
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f), None
        except Exception as e:
            return None, str(e)

    sess_a, err_a = load_sess(file_a)
    sess_b, err_b = load_sess(file_b)

    if err_a: return jsonify({"error": f"Session A: {err_a}"}), 400
    if err_b: return jsonify({"error": f"Session B: {err_b}"}), 400

    # Ensure A is the earlier session
    date_a = sess_a.get("assessDate", "")
    date_b = sess_b.get("assessDate", "")
    if date_a > date_b:
        sess_a, sess_b = sess_b, sess_a
        file_a, file_b = file_b, file_a

    findings_a = {f["id"]: f for f in sess_a.get("findings", [])}
    findings_b = {f["id"]: f for f in sess_b.get("findings", [])}

    ids_a = set(findings_a.keys())
    ids_b = set(findings_b.keys())

    # Resolved: was in A, not in B
    resolved = [findings_a[fid] for fid in (ids_a - ids_b)]
    # New: in B but not in A
    new_findings = [findings_b[fid] for fid in (ids_b - ids_a)]
    # Still open: in both
    still_open = [findings_b[fid] for fid in (ids_a & ids_b)]
    # Improved severity: same finding but lower severity in B
    improved = []
    for fid in (ids_a & ids_b):
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sev_a = sev_order.get(findings_a[fid].get("severity", "low"), 3)
        sev_b = sev_order.get(findings_b[fid].get("severity", "low"), 3)
        if sev_b < sev_a:
            improved.append({
                **findings_b[fid],
                "previousSeverity": findings_a[fid].get("severity"),
            })

    score_a = sess_a.get("score", 0)
    score_b = sess_b.get("score", 0)
    score_delta = score_b - score_a

    # Metric comparison
    metrics_a = {m["sub"]: m for m in sess_a.get("metrics", [])}
    metrics_b = {m["sub"]: m for m in sess_b.get("metrics", [])}
    metric_changes = []
    for key in set(list(metrics_a.keys()) + list(metrics_b.keys())):
        ma = metrics_a.get(key)
        mb = metrics_b.get(key)
        if ma and mb and ma.get("value") != mb.get("value"):
            metric_changes.append({
                "label":    mb.get("label", key),
                "before":   ma.get("value", "-"),
                "after":    mb.get("value", "-"),
                "statusA":  ma.get("status", ""),
                "statusB":  mb.get("status", ""),
            })

    # Severity counts for both
    def sev_counts(findings_dict):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings_dict.values():
            s = f.get("severity", "low")
            if s in counts: counts[s] += 1
        return counts

    return jsonify({
        "sessionA": {
            "filename":   file_a,
            "orgName":    sess_a.get("orgName", sess_a.get("clientName", "Unknown")),
            "assessDate": sess_a.get("assessDate", ""),
            "score":      score_a,
            "findingCount": len(ids_a),
            "sevCounts":  sev_counts(findings_a),
        },
        "sessionB": {
            "filename":   file_b,
            "orgName":    sess_b.get("orgName", sess_b.get("clientName", "Unknown")),
            "assessDate": sess_b.get("assessDate", ""),
            "score":      score_b,
            "findingCount": len(ids_b),
            "sevCounts":  sev_counts(findings_b),
        },
        "scoreDelta":    score_delta,
        "resolved":      resolved,
        "newFindings":   new_findings,
        "stillOpen":     still_open,
        "improved":      improved,
        "metricChanges": metric_changes,
        "summary": {
            "resolvedCount": len(resolved),
            "newCount":      len(new_findings),
            "stillOpenCount": len(still_open),
            "improvedCount": len(improved),
            "overallTrend":  "improved" if score_delta > 0 else "declined" if score_delta < 0 else "unchanged",
        }
    })


@app.route("/compare/report", methods=["POST"])
def comparison_report():
    """Generate a Word comparison report from two sessions."""
    body      = request.get_json()
    comp_data = body.get("comparisonData", {})
    generator = os.path.join(BASE_DIR, "generate-report.js")

    if not os.path.exists(generator):
        return jsonify({"error": "generate-report.js not found"}), 500

    org_name  = comp_data.get("sessionA", {}).get("orgName", "Organisation")
    safe_name = org_name.replace(" ", "_").replace("/", "-")
    date_str  = datetime.date.today().strftime("%Y%m%d")
    filename  = f"M365_Comparison_{safe_name}_{date_str}.docx"
    rep_path  = os.path.join(REPORTS_DIR, filename)
    json_path = os.path.join(REPORTS_DIR, f"_tmp_compare_{safe_name}.json")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(comp_data, f, ensure_ascii=False)

    try:
        result = subprocess.run(
            ["node", generator, json_path, rep_path, "comparison"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return jsonify({"error": f"Report failed: {result.stderr.strip()}"}), 500
    except FileNotFoundError:
        return jsonify({"error": "Node.js not found"}), 500
    finally:
        if os.path.exists(json_path):
            os.remove(json_path)

    if not os.path.exists(rep_path):
        return jsonify({"error": "Report file not created"}), 500

    return send_file(rep_path,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True, download_name=filename)

# =================================================================
#  SIMULATOR - Attack Chain Engine
# =================================================================

ATTACK_CHAINS = [
    {
        "id": "BEC",
        "name": "Business Email Compromise",
        "description": "Attacker bypasses MFA via SIM swapping, authenticates using legacy protocols, then silently forwards emails to an external address to intercept financial communications.",
        "requires": ["SEC-004", "CA-002", "EXO-001"],
        "severity": "critical",
        "steps": [
            "Attacker identifies a target user with SMS-based MFA",
            "SIM swap attack transfers the victim's phone number to attacker",
            "Attacker authenticates via legacy protocol (bypasses Conditional Access)",
            "Silent forwarding rule created — all emails copied to attacker",
            "Financial emails, invoices, and credentials intercepted indefinitely"
        ],
        "impact": "Invoice fraud, credential theft, financial loss. Average BEC loss: $125,000 per incident.",
        "broken_by": "Fixing any one of: SEC-004 (remove weak MFA), CA-002 (block legacy auth), EXO-001 (block forwarding)"
    },
    {
        "id": "ATO",
        "name": "Account Takeover",
        "description": "Without MFA enforcement or Conditional Access policies, a phishing attack or credential stuffing can result in full account compromise with no controls to detect or prevent it.",
        "requires": ["ID-001", "CA-001", "SEC-002"],
        "severity": "critical",
        "steps": [
            "Attacker sends phishing email to obtain credentials",
            "No MFA enforced — attacker signs in with username and password only",
            "No Conditional Access — sign-in from unknown location not challenged",
            "Full access to email, files, Teams, and SharePoint",
            "Attacker moves laterally to other accounts using harvested credentials"
        ],
        "impact": "Full account compromise, data breach, lateral movement to other systems.",
        "broken_by": "Fixing any one of: ID-001 (enforce MFA), CA-001 (deploy CA policies), SEC-002 (enable security defaults)"
    },
    {
        "id": "PRIV",
        "name": "Privilege Escalation",
        "description": "With too many permanent Global Administrators and no just-in-time access controls, compromising any one admin account gives an attacker unrestricted tenant-wide control.",
        "requires": ["ID-002", "ID-003"],
        "severity": "critical",
        "steps": [
            "Attacker targets one of the many permanent Global Admin accounts",
            "Account compromised via phishing, credential stuffing, or password spray",
            "No PIM in place — attacker has immediate permanent Global Admin access",
            "Attacker creates backdoor admin accounts and disables security controls",
            "Full tenant control established — MFA disabled, audit logs cleared"
        ],
        "impact": "Complete tenant takeover. Attacker can access all data, disable security, create persistent backdoors.",
        "broken_by": "Both required: ID-002 (reduce Global Admins) AND ID-003 (enable PIM for just-in-time access)"
    },
    {
        "id": "OAUTH",
        "name": "OAuth App Abuse",
        "description": "Users can be tricked into granting a malicious third-party app access to their email, files, and directory data. The app retains access permanently, even after the user's password is reset.",
        "requires": ["SEC-005", "APP-001"],
        "severity": "high",
        "steps": [
            "Attacker creates a convincing OAuth app requesting Mail.Read and Files.ReadWrite permissions",
            "Phishing email directs user to consent page — user clicks Accept",
            "App has persistent access to mailbox and files — survives password resets",
            "Attacker exfiltrates emails and documents continuously via Graph API",
            "Access persists until app is manually revoked by an administrator"
        ],
        "impact": "Persistent data exfiltration. Access survives MFA resets and password changes.",
        "broken_by": "Both help: SEC-005 (restrict user consent) AND APP-001 (review existing high-privilege apps)"
    },
    {
        "id": "EXFIL",
        "name": "Data Exfiltration",
        "description": "A combination of open SharePoint sharing, unblocked email forwarding, and no alerting creates multiple unmonitored channels for data to leave the organisation without detection.",
        "requires": ["SPO-001", "EXO-001", "MON-001"],
        "severity": "high",
        "steps": [
            "Attacker or malicious insider identifies sensitive SharePoint sites",
            "Files shared via Anyone links — no authentication required to access",
            "Email forwarding configured to send copies to external address",
            "No Defender alerts configured — exfiltration goes undetected",
            "Data leaves the organisation through multiple channels simultaneously"
        ],
        "impact": "Undetected bulk data theft. Regulatory breach risk (GDPR). No forensic trail.",
        "broken_by": "Fixing any one significantly reduces risk: SPO-001 (restrict sharing), EXO-001 (block forwarding), MON-001 (enable alerting)"
    },
    {
        "id": "RANSOM",
        "name": "Ransomware Deployment",
        "description": "Legacy authentication bypasses MFA, allowing access from an unmanaged and unpatched device. Once inside, ransomware is deployed across SharePoint, OneDrive, and connected file shares.",
        "requires": ["CA-002", "MDM-001", "MDM-002"],
        "severity": "critical",
        "steps": [
            "Attacker authenticates via legacy protocol — bypasses MFA and Conditional Access",
            "Access granted from unmanaged device with no compliance check",
            "No compliance policies to detect missing patches or disabled antivirus",
            "Ransomware payload deployed to OneDrive — version sync spreads to SharePoint",
            "Files encrypted across the tenant — backups potentially compromised"
        ],
        "impact": "Full file encryption across M365. Average ransomware recovery cost: $1.85M. Operational shutdown.",
        "broken_by": "CA-002 is critical (block legacy auth). MDM-001 and MDM-002 add defence in depth."
    },
    {
        "id": "PERSIST",
        "name": "Invisible Persistence",
        "description": "An attacker who gains access establishes multiple persistence mechanisms — rogue apps, email forwarding rules, and backdoor accounts — while generating no alerts. The compromise can go undetected for months.",
        "requires": ["APP-001", "MON-001", "EXO-001"],
        "severity": "high",
        "steps": [
            "Initial access gained via any vector (phishing, legacy auth, weak MFA)",
            "Rogue OAuth app registered with high-privilege permissions as backdoor",
            "Silent email forwarding rules created on key mailboxes",
            "No alert policies — no notifications sent to administrators",
            "Attacker maintains persistent access and intelligence for months undetected"
        ],
        "impact": "Long-term undetected compromise. Average dwell time without alerting: 197 days.",
        "broken_by": "MON-001 is most critical (enable alerting). APP-001 and EXO-001 remove persistence mechanisms."
    },
]


@app.route("/simulator/chains", methods=["POST"])
def simulate_chains():
    """
    Evaluate attack chains against a set of open finding IDs.
    Returns which chains are active, broken, and partially mitigated.
    """
    body            = request.get_json()
    open_finding_ids = set(body.get("openFindings", []))
    all_finding_ids  = set(body.get("allFindings", []))

    results = []
    for chain in ATTACK_CHAINS:
        required     = set(chain["requires"])
        active_reqs  = required & open_finding_ids
        fixed_reqs   = required - open_finding_ids

        if len(active_reqs) == len(required):
            status = "active"      # All requirements open - chain fully active
        elif len(active_reqs) == 0:
            status = "broken"      # All requirements fixed - chain broken
        else:
            status = "partial"     # Some fixed, some still open - partially mitigated

        # Score contribution - how much does fixing this chain improve security
        score_impact = len(active_reqs) * {"critical": 15, "high": 10}.get(chain["severity"], 5)

        results.append({
            "id":           chain["id"],
            "name":         chain["name"],
            "description":  chain["description"],
            "severity":     chain["severity"],
            "status":       status,
            "requires":     chain["requires"],
            "activeReqs":   list(active_reqs),
            "fixedReqs":    list(fixed_reqs),
            "steps":        chain["steps"],
            "impact":       chain["impact"],
            "broken_by":    chain["broken_by"],
            "scoreImpact":  score_impact,
        })

    # Calculate simulated score
    open_findings_list = body.get("openFindingsData", [])
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in open_findings_list:
        sev = f.get("severity", "low")
        if sev in counts:
            counts[sev] += 1

    sim_score = max(10, 100 - (
        min(counts["critical"] * 8, 32) +
        min(counts["high"]     * 5, 20) +
        min(counts["medium"]   * 3, 12) +
        min(counts["low"]      * 1,  4)
    ))

    active_chains  = [r for r in results if r["status"] == "active"]
    broken_chains  = [r for r in results if r["status"] == "broken"]
    partial_chains = [r for r in results if r["status"] == "partial"]

    return jsonify({
        "chains":        results,
        "simScore":      sim_score,
        "activeCount":   len(active_chains),
        "brokenCount":   len(broken_chains),
        "partialCount":  len(partial_chains),
        "criticalChains": len([c for c in active_chains if c["severity"] == "critical"]),
    })

# =================================================================
#  REMEDIATION ROUTES
# =================================================================

REMEDIATION_DIR = os.path.join(BASE_DIR, "remediation")

# Maps finding ID to its remediation and rollback scripts
REMEDIATION_MAP = {
    "CA-002": {
        "script": "Remediate-LegacyAuth.ps1", "rollback": "Rollback-LegacyAuth.ps1",
        "tier": 1, "auth": ["graph"],
        "manual_fix": "Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess\n# Create CA policy blocking legacy auth in Entra ID:\n# Entra ID > Protection > Conditional Access > New Policy\n# Conditions: Client apps = Exchange ActiveSync + Other clients\n# Grant: Block access",
        "manual_rollback": "# Go to Entra ID > Protection > Conditional Access\n# Find policy named: MM-Assessment - Block Legacy Authentication\n# Delete or disable the policy",
    },
    "EXO-001": {
        "script": "Remediate-ExternalForwarding.ps1", "rollback": "Rollback-ExternalForwarding.ps1",
        "tier": 1, "auth": ["exchange"],
        "manual_fix": "Connect-ExchangeOnline\nSet-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off\nDisconnect-ExchangeOnline -Confirm:$false",
        "manual_rollback": "Connect-ExchangeOnline\nSet-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Automatic\nDisconnect-ExchangeOnline -Confirm:$false",
    },
    "EXO-002": {
        "script": "Remediate-MailboxAudit.ps1", "rollback": "Rollback-MailboxAudit.ps1",
        "tier": 1, "auth": ["exchange"],
        "manual_fix": "Connect-ExchangeOnline\nSet-OrganizationConfig -AuditDisabled $false\nDisconnect-ExchangeOnline -Confirm:$false",
        "manual_rollback": "Connect-ExchangeOnline\nSet-OrganizationConfig -AuditDisabled $true\nDisconnect-ExchangeOnline -Confirm:$false",
    },
    "EXO-003": {
        "script": "Remediate-AntiPhish.ps1", "rollback": "Rollback-AntiPhish.ps1",
        "tier": 1, "auth": ["exchange"],
        "manual_fix": "Connect-ExchangeOnline\n$Policy = Get-AntiPhishPolicy | Select-Object -First 1\nSet-AntiPhishPolicy -Identity $Policy.Name -EnableMailboxIntelligence $true -EnableMailboxIntelligenceProtection $true\nDisconnect-ExchangeOnline -Confirm:$false",
        "manual_rollback": "Connect-ExchangeOnline\n$Policy = Get-AntiPhishPolicy | Select-Object -First 1\nSet-AntiPhishPolicy -Identity $Policy.Name -EnableMailboxIntelligence $false\nDisconnect-ExchangeOnline -Confirm:$false",
    },
    "SEC-003": {
        "script": "Remediate-MFAFatigue.ps1", "rollback": "Rollback-MFAFatigue.ps1",
        "tier": 1, "auth": ["graph"],
        "manual_fix": "# Entra ID > Protection > Authentication Methods > Microsoft Authenticator\n# Enable: Require number matching\n# Enable: Show additional context in notifications",
        "manual_rollback": "# Entra ID > Protection > Authentication Methods > Microsoft Authenticator\n# Disable: Require number matching\n# Disable: Show additional context in notifications",
    },
    "SEC-004": {
        "script": "Remediate-WeakAuth.ps1", "rollback": "Rollback-WeakAuth.ps1",
        "tier": 1, "auth": ["graph"],
        "manual_fix": "# Entra ID > Protection > Authentication Methods\n# Select SMS > Disable\n# Select Voice call > Disable\n# Select Email OTP > Disable",
        "manual_rollback": "# Entra ID > Protection > Authentication Methods\n# Re-enable SMS, Voice call, or Email OTP as required",
    },
    "SEC-005": {
        "script": "Remediate-UserConsent.ps1", "rollback": "Rollback-UserConsent.ps1",
        "tier": 1, "auth": ["graph"],
        "manual_fix": "# Entra ID > Enterprise Applications > Consent and Permissions > User consent settings\n# Set: Do not allow user consent\n# Enable: Admin consent request workflow",
        "manual_rollback": "# Entra ID > Enterprise Applications > Consent and Permissions > User consent settings\n# Restore to: Allow user consent for apps from verified publishers",
    },
    "TEAMS-002": {
        "script": "Remediate-TeamsConsumer.ps1", "rollback": "Rollback-TeamsConsumer.ps1",
        "tier": 1, "auth": ["teams"],
        "manual_fix": "Connect-MicrosoftTeams\nSet-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerAccess $false\nDisconnect-MicrosoftTeams",
        "manual_rollback": "Connect-MicrosoftTeams\nSet-CsExternalAccessPolicy -Identity Global -EnableTeamsConsumerAccess $true\nDisconnect-MicrosoftTeams",
    },
    "SPO-002": {
        "script": "Remediate-SPOLegacyAuth.ps1", "rollback": "Rollback-SPOLegacyAuth.ps1",
        "tier": 1, "auth": ["sharepoint"],
        "manual_fix": "Connect-SPOService -Url https://yourtenant-admin.sharepoint.com\nSet-SPOTenant -LegacyAuthProtocolsEnabled $false\nDisconnect-SPOService",
        "manual_rollback": "Connect-SPOService -Url https://yourtenant-admin.sharepoint.com\nSet-SPOTenant -LegacyAuthProtocolsEnabled $true\nDisconnect-SPOService",
    },
}

# Tier 2 findings - guided only, no auto-fix script
TIER2_GUIDANCE = {
    "ID-001":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods", "steps": ["Go to Entra ID > Protection > Authentication Methods", "Enable Microsoft Authenticator for all users", "Set registration campaign to nudge users without MFA to register", "Set a deadline of 14 days for registration"]},
    "ID-002":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles", "steps": ["Go to Entra ID > Roles and administrators > Global Administrator", "Review each Global Admin account", "Remove the Global Admin role from accounts that do not need it", "Assign least-privilege roles instead (e.g. Exchange Admin, Intune Admin)", "Keep a maximum of 2-3 break-glass accounts with Global Admin"]},
    "ID-003":  {"portal": "https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart", "steps": ["Go to Entra ID > Identity Governance > Privileged Identity Management", "Click Entra roles", "Add eligible assignments for admin roles", "Remove permanent assignments and convert to eligible", "Configure approval workflow and MFA on activation"]},
    "CA-001":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies", "steps": ["Go to Entra ID > Protection > Conditional Access", "Create policy: Require MFA for all users", "Create policy: Require MFA for admin roles", "Create policy: Block legacy authentication", "Create policy: Require compliant device for M365 apps", "Set all policies to Report-only first, then Enabled after review"]},
    "ID-004":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/UsersManagementMenuBlade/~/AllUsers", "steps": ["Go to Entra ID > Users > All Users", "Filter by User type = Guest", "Review each guest account", "Remove guests who no longer need access", "Set up Access Reviews under Identity Governance to automate this going forward"]},
    "SPO-001": {"portal": "https://admin.microsoft.com/sharepoint", "steps": ["Go to SharePoint Admin Centre > Policies > Sharing", "Change the top-level sharing setting from Anyone to New and existing guests", "Review site-level sharing settings for sensitive sites", "Enable expiry on Anyone links (recommended: 30 days)"]},
    "APP-001": {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview", "steps": ["Go to Entra ID > Enterprise Applications > All Applications", "Filter by Application type = Enterprise Applications", "Review each app's permissions under Permissions", "Remove or restrict apps with Directory.ReadWrite.All or Mail.ReadWrite.All", "Enable admin consent workflow under User settings > Admin consent requests"]},
    "MON-001": {"portal": "https://security.microsoft.com/alertpolicies", "steps": ["Go to Microsoft Defender > Policies > Alert Policies", "Enable high-severity alert policies: Malware detected, Suspicious email forwarding, Mass file download", "Set alert notification email to a monitored mailbox", "Review existing alerts under Incidents and Alerts"]},
    "MDM-001": {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/overview", "steps": ["Go to Intune > Devices > Monitor > Device compliance", "Review non-compliant devices", "Identify common compliance failures (BitLocker, OS version, antivirus)", "Remediate devices or create exceptions where appropriate", "Consider blocking non-compliant devices via Conditional Access"]},
    "MDM-002": {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/compliancePolicies", "steps": ["Go to Intune > Devices > Compliance policies", "Create a Windows compliance policy requiring: BitLocker enabled, Minimum OS version, Antivirus enabled, Defender enabled", "Create equivalent policies for iOS and Android if managed", "Assign policies to All Users or All Devices"]},
    "SEC-001": {"portal": "https://security.microsoft.com/securescore", "steps": ["Go to Microsoft Defender > Secure Score", "Review improvement actions sorted by Points available", "Prioritise actions with High impact and Low implementation effort", "Assign actions to responsible team members", "Review score weekly"]},
    "SEC-002": {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/TenantPropertiesBlade", "steps": ["Go to Entra ID > Properties > Manage security defaults", "If not using Conditional Access: enable Security Defaults", "If using Conditional Access: ensure CA policies cover all scenarios Security Defaults would cover (MFA for all, block legacy auth)", "Do not enable Security Defaults if you have existing CA policies - they conflict"]},
    "TEAMS-001": {"portal": "https://admin.teams.microsoft.com/company-wide-settings/external-communications", "steps": ["Go to Teams Admin Centre > Users > External access", "Change from Open federation to Allowed domains only", "Add any approved partner domains to the allowed list", "Remove unknown or unused domains"]},
    "ID-006":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RiskyUsersV2Blade", "steps": ["Go to Entra ID > Protection > Risky users", "Filter by Risk level: High, then Medium", "For high risk: select user > Block sign-in > Require password reset", "For medium risk: select user > Require users to re-register MFA", "Investigate the risk events behind each flagged user under Risk history", "Dismiss false positives after investigation"]},
    "ID-007":  {"portal": "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/UsersManagementMenuBlade/~/AllUsers", "steps": ["Create two dedicated emergency access accounts with long random passwords", "Exclude both accounts from all Conditional Access policies", "Store credentials in a physically secure location (e.g. safe, sealed envelope)", "Do NOT register MFA on break-glass accounts — if MFA fails, you cannot use them", "Set up an alert for any sign-in on these accounts", "Test the accounts annually to verify they work", "See: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"]},
    "SEC-006": {"portal": "https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/MainMenuBlade", "steps": ["Go to Azure Portal > Microsoft Sentinel", "If not deployed: Create a Sentinel workspace in your subscription", "Add the Microsoft 365 Defender data connector", "Add the Azure Active Directory data connector", "Enable the Microsoft Sentinel analytics rules relevant to your environment", "Configure a daily review process for Sentinel incidents"]},
    "EXO-004": {"portal": "https://admin.microsoft.com/Adminportal/Home#/Domains", "steps": ["Identify your primary domain in Microsoft 365 Admin > Settings > Domains", "Log into your DNS provider and add a TXT record", "Name: _dmarc.yourdomain.com", "Value: v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com", "Wait for DNS propagation (up to 48 hours)", "Monitor reports for 2-4 weeks, then change p=none to p=quarantine", "Once confident, move to p=reject for full enforcement"]},
    "EXO-005": {"portal": "https://admin.exchange.microsoft.com/#/dkim", "steps": ["Go to Exchange Admin Centre > Email authentication > DKIM", "Select your domain and click Enable", "If not yet set up: follow the DNS record instructions provided", "For SPF: ensure your domain has a TXT record starting with v=spf1 include:spf.protection.outlook.com", "Add any other authorised senders (e.g. marketing platforms) to the SPF record", "Verify both records with MXToolbox before enabling DMARC enforcement"]},
    "MDM-003": {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/PatchManagementBlade/~/overview", "steps": ["Go to Intune > Devices > Windows > Update rings for Windows 10 and later", "Click Create profile", "Name it e.g. Pilot Ring — set quality update deferral to 3 days", "Create a second Production Ring with quality deferral of 7 days, feature deferral of 30 days", "Assign Pilot Ring to a test group, Production Ring to all Windows devices", "Monitor Windows Update compliance under Reports > Windows Updates"]},
    "MDM-004": {"portal": "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/compliancePolicies", "steps": ["Go to Intune > Devices > Compliance policies > Create policy > Windows 10+", "Enable: Require BitLocker", "Also go to Intune > Devices > Configuration > Create > Windows > Templates > Endpoint Protection", "Configure BitLocker Drive Encryption settings", "Assign both policies to All Devices or Windows device groups", "Monitor encryption status under Intune > Devices > Monitor > Encryption report"]},
}


def run_remediation_script(script_name, ps_args, timeout=180):
    """Run a remediation PowerShell script and return parsed JSON output."""
    script_path = os.path.join(REMEDIATION_DIR, script_name)
    if not os.path.exists(script_path):
        return None, f"Script not found: {script_name}"
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
           "-File", script_path] + ps_args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return None, (result.stderr.strip() or f"Script exited with code {result.returncode}")
        if not result.stdout.strip():
            return None, "Script produced no output"
        data = json.loads(result.stdout.strip())
        return data, None
    except subprocess.TimeoutExpired:
        return None, f"Script timed out after {timeout} seconds"
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON output: {e}. Output: {result.stdout[:300]}"
    except Exception as e:
        return None, str(e)


def save_remediation_log(client_name, finding_id, action, result, snapshot_file=None):
    """Append an entry to the remediation log for this client."""
    safe = client_name.replace(" ", "_").replace("/", "-")
    log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe}.json")
    
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "findingId": finding_id,
        "action": action,  # "remediate", "rollback", "check"
        "success": result.get("success", False),
        "details": result.get("details", ""),
        "warning": result.get("warning", None),
        "snapshotFile": snapshot_file,
    }
    
    log = []
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                log = json.load(f)
        except Exception:
            log = []
    
    log.append(entry)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(log, f, ensure_ascii=False, indent=2)
    return log_path


@app.route("/remediate/check/<finding_id>", methods=["POST"])
def remediate_check(finding_id):
    """Run pre-remediation safety check for a finding without making changes."""
    if finding_id not in REMEDIATION_MAP:
        return jsonify({"error": f"No remediation available for {finding_id}", "tier": 2,
                        "guidance": TIER2_GUIDANCE.get(finding_id, {})}), 200
    
    body    = request.get_json()
    auth    = {k: body.get(k, "") for k in ["authMethod","tenantId","clientId","clientSecret","certThumbprint","spAdminUrl","environment"]}
    mapping = REMEDIATION_MAP[finding_id]
    
    ps_args = build_ps_args_remediation(auth) + ["-CheckOnly"]
    if auth.get("spAdminUrl") and finding_id in {"SPO-001", "SPO-002"}:
        ps_args += ["-SpAdminUrl", auth["spAdminUrl"]]
    
    result, error = run_remediation_script(mapping["script"], ps_args)
    if error:
        return jsonify({"error": error}), 500
    
    return jsonify(result)


@app.route("/remediate/run/<finding_id>", methods=["POST"])
def remediate_run(finding_id):
    """Execute remediation for a finding, saving a snapshot first."""
    if finding_id not in REMEDIATION_MAP:
        return jsonify({"error": f"No auto-remediation for {finding_id}. Use guided remediation.",
                        "tier": 2, "guidance": TIER2_GUIDANCE.get(finding_id, {})}), 200
    
    body        = request.get_json()
    client_name = body.get("orgName", body.get("clientName", "Unknown"))
    auth        = {k: body.get(k, "") for k in ["authMethod","tenantId","clientId","clientSecret","certThumbprint","spAdminUrl","environment"]}
    mapping     = REMEDIATION_MAP[finding_id]
    
    # Create snapshot file path
    safe          = client_name.replace(" ", "_").replace("/", "-")
    timestamp     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    snapshot_name = f"Snapshot_{safe}_{finding_id}_{timestamp}.json"
    snapshot_path = os.path.join(OUTPUT_DIR, snapshot_name)
    
    ps_args = build_ps_args_remediation(auth) + ["-SnapshotPath", snapshot_path]
    if auth.get("spAdminUrl") and finding_id in {"SPO-001", "SPO-002"}:
        ps_args += ["-SpAdminUrl", auth["spAdminUrl"]]
    
    result, error = run_remediation_script(mapping["script"], ps_args)
    if error:
        save_remediation_log(client_name, finding_id, "remediate", {"success": False, "details": error})
        return jsonify({"error": error}), 500
    
    result["snapshotFile"] = snapshot_name
    save_remediation_log(client_name, finding_id, "remediate", result, snapshot_name)
    return jsonify(result)


@app.route("/remediate/rollback/<finding_id>", methods=["POST"])
def remediate_rollback(finding_id):
    """Roll back a previously remediated finding using its snapshot."""
    if finding_id not in REMEDIATION_MAP:
        return jsonify({"error": f"No rollback available for {finding_id}"}), 400
    
    body          = request.get_json()
    client_name   = body.get("orgName", body.get("clientName", "Unknown"))
    snapshot_name = body.get("snapshotFile", "")
    auth          = {k: body.get(k, "") for k in ["authMethod","tenantId","clientId","clientSecret","certThumbprint","spAdminUrl","environment"]}
    mapping       = REMEDIATION_MAP[finding_id]
    
    if not snapshot_name:
        return jsonify({"error": "No snapshot file specified for rollback"}), 400
    
    snapshot_path = os.path.join(OUTPUT_DIR, snapshot_name)
    if not os.path.exists(snapshot_path):
        return jsonify({"error": f"Snapshot file not found: {snapshot_name}"}), 404
    
    ps_args = build_ps_args_remediation(auth) + ["-SnapshotPath", snapshot_path]
    if auth.get("spAdminUrl") and finding_id in {"SPO-001", "SPO-002"}:
        ps_args += ["-SpAdminUrl", auth["spAdminUrl"]]
    
    result, error = run_remediation_script(mapping["rollback"], ps_args)
    if error:
        save_remediation_log(client_name, finding_id, "rollback", {"success": False, "details": error})
        return jsonify({"error": error}), 500
    
    save_remediation_log(client_name, finding_id, "rollback", result, snapshot_name)
    return jsonify(result)



@app.route("/remediate/commands/<finding_id>", methods=["GET"])
def get_manual_commands(finding_id):
    """Return manual PowerShell commands for a finding."""
    if finding_id in REMEDIATION_MAP:
        mapping = REMEDIATION_MAP[finding_id]
        return jsonify({
            "findingId": finding_id,
            "tier": mapping.get("tier", 1),
            "manual_fix": mapping.get("manual_fix", "No manual command available"),
            "manual_rollback": mapping.get("manual_rollback", "No manual rollback available"),
        })
    return jsonify({"error": "No commands found"}), 404

@app.route("/remediate/guidance/<finding_id>", methods=["GET"])
def remediate_guidance(finding_id):
    """Return Tier 2 guided remediation steps for a finding."""
    if finding_id in TIER2_GUIDANCE:
        return jsonify({"tier": 2, "findingId": finding_id, "guidance": TIER2_GUIDANCE[finding_id]})
    elif finding_id in REMEDIATION_MAP:
        return jsonify({"tier": 1, "findingId": finding_id, "message": "Use /remediate/run for auto-fix"})
    return jsonify({"error": "No guidance available"}), 404


@app.route("/remediate/log/<client_name>", methods=["GET"])
def get_remediation_log(client_name):
    """Return the remediation log for a client."""
    safe     = client_name.replace(" ", "_").replace("/", "-")
    log_path = os.path.join(OUTPUT_DIR, f"RemediationLog_{safe}.json")
    if not os.path.exists(log_path):
        return jsonify({"log": []})
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            log = json.load(f)
        return jsonify({"log": log})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def build_ps_args_remediation(auth):
    """Build PS args for remediation scripts - same pattern as assessment."""
    args = []
    if auth.get("authMethod") == "appreg":
        args += ["-AuthMethod", "AppReg",
                 "-TenantId", auth.get("tenantId", ""),
                 "-ClientId", auth.get("clientId", ""),
                 "-ClientSecret", auth.get("clientSecret", "")]
    else:
        args += ["-AuthMethod", "Interactive"]
        if auth.get("tenantId"):
            args += ["-TenantId", auth["tenantId"]]
    return args

# =================================================================
#  INVESTIGATION SCRIPTS
#  Ready-to-run PowerShell scripts returned per finding so the
#  consultant can dig deeper without leaving the tool.
# =================================================================

INVESTIGATION_SCRIPTS = {

    "ID-001": {
        "title": "Who is missing MFA?",
        "description": "Lists every enabled user without a registered MFA method and exports to CSV.",
        "script": r"""# ID-001 — Users Without MFA
# Requires: Microsoft.Graph module
# Permissions: User.Read.All, UserAuthenticationMethod.Read.All

Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All" -NoWelcome

$users = Get-MgUser -All -Filter "accountEnabled eq true" `
         -Property Id,DisplayName,UserPrincipalName | Sort-Object UserPrincipalName

$noMFA  = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($user in $users) {
    $i++
    Write-Progress -Activity "Checking MFA" -Status $user.UserPrincipalName `
                   -PercentComplete ($i / $users.Count * 100)
    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
    $hasMFA  = ($methods | Where-Object {
        $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod'
    }).Count -gt 0
    if (-not $hasMFA) {
        $noMFA.Add([PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName       = $user.DisplayName
        })
    }
}
Write-Progress -Completed -Activity "Checking MFA"

$csv = "NoMFA_Users_$(Get-Date -Format yyyyMMdd).csv"
$noMFA | Export-Csv $csv -NoTypeInformation
$noMFA | Format-Table -AutoSize
Write-Host "$($noMFA.Count) of $($users.Count) users have no MFA. Exported: $csv" -ForegroundColor Yellow
Disconnect-MgGraph"""
    },

    "ID-002": {
        "title": "Global Administrator details",
        "description": "Lists every Global Admin with last sign-in date to identify stale or excessive accounts.",
        "script": r"""# ID-002 — Global Administrator Audit
# Requires: Microsoft.Graph module
# Permissions: Directory.Read.All, AuditLog.Read.All

Connect-MgGraph -Scopes "Directory.Read.All", "AuditLog.Read.All" -NoWelcome

$gaRole   = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
$members  = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All
$report   = [System.Collections.Generic.List[object]]::new()

foreach ($m in $members) {
    $user   = Get-MgUser -UserId $m.Id `
              -Property DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime `
              -ErrorAction SilentlyContinue
    if (-not $user) { continue }
    $signIn = (Get-MgAuditLogSignIn -Filter "userId eq '$($m.Id)'" -Top 1 |
               Select-Object -First 1).CreatedDateTime
    $report.Add([PSCustomObject]@{
        UserPrincipalName = $user.UserPrincipalName
        DisplayName       = $user.DisplayName
        AccountEnabled    = $user.AccountEnabled
        AccountCreated    = $user.CreatedDateTime
        LastSignIn        = $signIn ?? 'No record'
    })
}

$csv = "GlobalAdmins_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
$col = if ($report.Count -gt 3) { 'Red' } else { 'Green' }
Write-Host "$($report.Count) Global Administrators found. Target: 2-3. Exported: $csv" -ForegroundColor $col
Disconnect-MgGraph"""
    },

    "ID-003": {
        "title": "Permanent privileged role assignments",
        "description": "Lists all permanent (non-PIM-eligible) admin role assignments across the tenant.",
        "script": r"""# ID-003 — Permanent Role Assignment Audit
# Requires: Microsoft.Graph module
# Permissions: RoleManagement.Read.Directory, Directory.Read.All

Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "Directory.Read.All" -NoWelcome

$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All `
               -ExpandProperty Principal,RoleDefinition

$report = $assignments | Where-Object { $_.Principal } | ForEach-Object {
    $upn = $_.Principal.AdditionalProperties['userPrincipalName'] `
        ?? $_.Principal.AdditionalProperties['displayName'] `
        ?? $_.PrincipalId
    [PSCustomObject]@{
        Principal    = $upn
        Role         = $_.RoleDefinition.DisplayName
        Assignment   = 'Permanent (not PIM-eligible)'
        CreatedDate  = $_.CreatedDateTime
    }
} | Sort-Object Role, Principal

$csv = "PermanentRoles_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
Write-Host "$($report.Count) permanent assignments. Use PIM to convert high-risk roles to eligible. Exported: $csv" -ForegroundColor Yellow
Disconnect-MgGraph"""
    },

    "ID-004": {
        "title": "Guest user inventory",
        "description": "Lists all guest accounts with invite date and last sign-in to identify stale access.",
        "script": r"""# ID-004 — Guest User Review
# Requires: Microsoft.Graph module
# Permissions: User.Read.All, AuditLog.Read.All

Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome

$guests = Get-MgUser -Filter "userType eq 'Guest'" -All `
          -Property Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime

$report = [System.Collections.Generic.List[object]]::new()
foreach ($g in $guests) {
    $signIn = (Get-MgAuditLogSignIn -Filter "userId eq '$($g.Id)'" -Top 1 |
               Select-Object -First 1).CreatedDateTime
    $days   = if ($signIn) { [math]::Round(((Get-Date) - [datetime]$signIn).TotalDays) } else { $null }
    $report.Add([PSCustomObject]@{
        UserPrincipalName = $g.UserPrincipalName
        DisplayName       = $g.DisplayName
        AccountEnabled    = $g.AccountEnabled
        InvitedDate       = $g.CreatedDateTime
        LastSignIn        = $signIn ?? 'Never'
        DaysSinceSignIn   = $days   ?? 'Never'
    })
}

$csv = "GuestUsers_$(Get-Date -Format yyyyMMdd).csv"
$report | Sort-Object DaysSinceSignIn -Descending | Export-Csv $csv -NoTypeInformation
$report | Sort-Object DaysSinceSignIn -Descending | Format-Table -AutoSize
$stale = ($report | Where-Object { $_.DaysSinceSignIn -is [int] -and $_.DaysSinceSignIn -gt 90 }).Count
Write-Host "$($report.Count) guests — $stale inactive 90+ days. Exported: $csv" -ForegroundColor Yellow
Disconnect-MgGraph"""
    },

    "ID-005": {
        "title": "Licence allocation breakdown",
        "description": "Shows assigned vs. unassigned licence counts per SKU so unused licences can be identified and removed.",
        "script": r"""# ID-005 — Licence Usage Breakdown
# Requires: Microsoft.Graph module
# Permissions: Organization.Read.All

Connect-MgGraph -Scopes "Organization.Read.All" -NoWelcome

$skus   = Get-MgSubscribedSku -All
$report = $skus | Where-Object { $_.PrepaidUnits.Enabled -gt 0 } | ForEach-Object {
    $pct = [math]::Round($_.ConsumedUnits / $_.PrepaidUnits.Enabled * 100, 1)
    [PSCustomObject]@{
        SKU              = $_.SkuPartNumber
        Total            = $_.PrepaidUnits.Enabled
        Assigned         = $_.ConsumedUnits
        Unassigned       = $_.PrepaidUnits.Enabled - $_.ConsumedUnits
        UtilisationPct   = "$pct%"
    }
} | Sort-Object Unassigned -Descending

$csv = "LicenceUsage_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
$total = ($report | Measure-Object Unassigned -Sum).Sum
Write-Host "$total total unassigned licences across $($report.Count) SKUs. Exported: $csv" -ForegroundColor Yellow
Disconnect-MgGraph"""
    },

    "APP-001": {
        "title": "High-privilege OAuth application inventory",
        "description": "Lists third-party apps with tenant-wide Graph permissions that could be used for persistent access.",
        "script": r"""# APP-001 — High-Privilege OAuth App Review
# Requires: Microsoft.Graph module
# Permissions: Application.Read.All, Directory.Read.All

Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All" -NoWelcome

# Permissions considered high-risk for tenant-wide app access
$highRisk = @(
    'Mail.ReadWrite.All','Files.ReadWrite.All','Directory.ReadWrite.All',
    'User.ReadWrite.All','RoleManagement.ReadWrite.Directory',
    'Mail.Read.All','Calendars.ReadWrite.All','Notes.ReadWrite.All',
    'MailboxSettings.ReadWrite','TeamSettings.ReadWrite.All'
)

# Get the Microsoft Graph service principal to resolve role names
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Build role ID → name lookup
$roleMap = @{}
$graphSP.AppRoles | ForEach-Object { $roleMap[$_.Id.ToString()] = $_.Value }

# Check all non-Microsoft service principals
$sps = Get-MgServicePrincipal -All -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
$report = [System.Collections.Generic.List[object]]::new()

foreach ($sp in $sps) {
    $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue |
                   Where-Object { $_.ResourceId -eq $graphSP.Id }
    $dangerous   = $assignments | Where-Object { $highRisk -contains $roleMap[$_.AppRoleId.ToString()] }
    if ($dangerous) {
        $report.Add([PSCustomObject]@{
            AppName     = $sp.DisplayName
            AppId       = $sp.AppId
            Publisher   = $sp.PublisherName ?? 'Unknown'
            Permissions = ($dangerous | ForEach-Object { $roleMap[$_.AppRoleId.ToString()] }) -join ', '
            Created     = $sp.CreatedDateTime
        })
    }
}

$csv = "HighPrivApps_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize -Wrap
Write-Host "$($report.Count) apps with high-privilege permissions. Review each in Entra ID > Enterprise Applications > Permissions. Exported: $csv" -ForegroundColor Red
Disconnect-MgGraph"""
    },

    "MON-001": {
        "title": "Defender alert policy status",
        "description": "Shows all Microsoft Defender for Office 365 alert policies and which are disabled.",
        "script": r"""# MON-001 — Defender Alert Policy Review
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$policies = Get-ProtectionAlert | Select-Object Name, IsEnabled, Severity, Category, NotifyUser
$enabled  = $policies | Where-Object { $_.IsEnabled }
$disabled = $policies | Where-Object { -not $_.IsEnabled }

Write-Host "`nEnabled  alert policies: $($enabled.Count)" -ForegroundColor Green
Write-Host "Disabled alert policies: $($disabled.Count)" -ForegroundColor $(if($disabled.Count -gt 0){'Yellow'}else{'Green'})

if ($disabled) {
    Write-Host "`nDisabled policies (consider enabling):" -ForegroundColor Yellow
    $disabled | Format-Table Name, Severity, Category -AutoSize
}

$csv = "AlertPolicies_$(Get-Date -Format yyyyMMdd).csv"
$policies | Export-Csv $csv -NoTypeInformation
Write-Host "Full policy list exported: $csv" -ForegroundColor Cyan
Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "EXO-001": {
        "title": "Active forwarding rules inventory",
        "description": "Finds mailbox-level forwarding and inbox rules that redirect mail externally.",
        "script": r"""# EXO-001 — External Forwarding Rule Discovery
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$report = [System.Collections.Generic.List[object]]::new()

# 1. Mailbox-level ForwardingAddress / ForwardingSmtpAddress
Write-Host "Checking mailbox forwarding settings..." -ForegroundColor Cyan
$fwdMailboxes = Get-Mailbox -ResultSize Unlimited |
                Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress }
foreach ($mbx in $fwdMailboxes) {
    $report.Add([PSCustomObject]@{
        Mailbox         = $mbx.UserPrincipalName
        ForwardTo       = $mbx.ForwardingAddress ?? $mbx.ForwardingSmtpAddress
        KeepCopy        = $mbx.DeliverToMailboxAndForward
        Type            = 'Mailbox Forwarding'
    })
}

# 2. Inbox rules with forwarding or redirect actions
Write-Host "Scanning inbox rules for forwarding actions..." -ForegroundColor Cyan
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    $rules = Get-InboxRule -Mailbox $_.Identity -ErrorAction SilentlyContinue |
             Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo }
    foreach ($rule in $rules) {
        $dest = ($rule.ForwardTo + $rule.ForwardAsAttachmentTo + $rule.RedirectTo) -join '; '
        $report.Add([PSCustomObject]@{
            Mailbox   = $_.UserPrincipalName
            ForwardTo = $dest
            KeepCopy  = -not [bool]$rule.RedirectTo
            Type      = "Inbox Rule: $($rule.Name)"
        })
    }
}

if ($report.Count -eq 0) {
    Write-Host "No forwarding rules found." -ForegroundColor Green
} else {
    $report | Format-Table -AutoSize
    $csv = "ForwardingRules_$(Get-Date -Format yyyyMMdd).csv"
    $report | Export-Csv $csv -NoTypeInformation
    Write-Host "$($report.Count) forwarding rule(s) found. Exported: $csv" -ForegroundColor Red
}
Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "MDM-001": {
        "title": "Non-compliant device list",
        "description": "Lists all Intune-managed devices that are not compliant, with last sync date and OS version.",
        "script": r"""# MDM-001 — Non-Compliant Device Inventory
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementManagedDevices.Read.All

Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -NoWelcome

$all     = Get-MgDeviceManagementManagedDevice -All `
           -Property DeviceName,UserPrincipalName,ComplianceState,OperatingSystem,OsVersion,LastSyncDateTime,ManagementState
$nonComp = $all | Where-Object { $_.ComplianceState -ne 'compliant' }

$report = $nonComp | ForEach-Object {
    [PSCustomObject]@{
        DeviceName      = $_.DeviceName
        User            = $_.UserPrincipalName
        OS              = "$($_.OperatingSystem) $($_.OsVersion)"
        ComplianceState = $_.ComplianceState
        ManagementState = $_.ManagementState
        LastSync        = $_.LastSyncDateTime
        DaysSinceSync   = if ($_.LastSyncDateTime) {
                              [math]::Round(((Get-Date) - [datetime]$_.LastSyncDateTime).TotalDays)
                          } else { 'Never' }
    }
} | Sort-Object ComplianceState, OS

$csv = "NonCompliantDevices_$(Get-Date -Format yyyyMMdd).csv"
$report | Export-Csv $csv -NoTypeInformation
$report | Format-Table -AutoSize
$col = if ($nonComp.Count -gt 0) { 'Red' } else { 'Green' }
Write-Host "$($nonComp.Count) non-compliant of $($all.Count) total managed devices. Exported: $csv" -ForegroundColor $col
Disconnect-MgGraph"""
    },

    "SEC-001": {
        "title": "Secure Score breakdown",
        "description": "Shows your current Secure Score, percentage, and top improvement actions ranked by points available.",
        "script": r"""# SEC-001 — Secure Score Breakdown
# Requires: Microsoft.Graph module
# Permissions: SecurityEvents.Read.All

Connect-MgGraph -Scopes "SecurityEvents.Read.All" -NoWelcome

$latest = Get-MgSecuritySecureScore -Top 1 | Select-Object -First 1
$pct    = [math]::Round(($latest.CurrentScore / $latest.MaxScore) * 100, 1)
$col    = if ($pct -lt 50) { 'Red' } elseif ($pct -lt 75) { 'Yellow' } else { 'Green' }

Write-Host "`nCurrent Secure Score: $($latest.CurrentScore) / $($latest.MaxScore) ($pct%)" -ForegroundColor $col
Write-Host "Score Date: $($latest.CreatedDateTime)" -ForegroundColor Cyan

Write-Host "`nTop improvement actions by points available:" -ForegroundColor Cyan
$actions = Get-MgSecuritySecureScoreControlProfile -All |
           Sort-Object MaxScore -Descending |
           Select-Object -First 20

$actions | Select-Object Title, MaxScore, @{N='Category';E={$_.ControlCategory}} |
           Format-Table -AutoSize

$csv = "SecureScore_$(Get-Date -Format yyyyMMdd).csv"
$actions | Export-Csv $csv -NoTypeInformation
Write-Host "Full action list exported: $csv" -ForegroundColor Cyan
Disconnect-MgGraph"""
    },

    "SEC-002": {
        "title": "Security defaults and CA policy status",
        "description": "Shows whether Security Defaults are enabled and whether Conditional Access policies are covering the same ground.",
        "script": r"""# SEC-002 — Security Defaults vs Conditional Access
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

$defaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
$col      = if ($defaults.IsEnabled) { 'Green' } else { 'Red' }
Write-Host "`nSecurity Defaults: $(if($defaults.IsEnabled){'ENABLED'}else{'DISABLED'})" -ForegroundColor $col

$all     = Get-MgIdentityConditionalAccessPolicy -All
$enabled = $all | Where-Object { $_.State -eq 'enabled' }
$report  = $all | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }

Write-Host "`nConditional Access: $($all.Count) total | $($enabled.Count) enforced | $($report.Count) report-only" -ForegroundColor Cyan

if (-not $defaults.IsEnabled -and $enabled.Count -eq 0) {
    Write-Host "`nCRITICAL: Security Defaults disabled AND no CA policies enforced." -ForegroundColor Red
    Write-Host "The tenant has no baseline MFA enforcement." -ForegroundColor Red
} elseif (-not $defaults.IsEnabled) {
    Write-Host "`nRelying on $($enabled.Count) Conditional Access policy/policies." -ForegroundColor Yellow
    Write-Host "Verify CA policies cover: MFA for all users, block legacy auth, require compliant device." -ForegroundColor Yellow
} else {
    Write-Host "`nSecurity Defaults active. Note: conflicts with custom CA policies if both are enabled." -ForegroundColor Green
}

Write-Host "`nEnabled CA Policies:" -ForegroundColor Cyan
$enabled | Select-Object DisplayName, State | Format-Table -AutoSize
Disconnect-MgGraph"""
    },

    "SEC-003": {
        "title": "MFA number matching status",
        "description": "Checks whether number matching (MFA fatigue protection) is enabled in the Microsoft Authenticator policy.",
        "script": r"""# SEC-003 — MFA Fatigue Protection (Number Matching)
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

$msAuth = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
          -AuthenticationMethodConfigurationId "MicrosoftAuthenticator"

Write-Host "`nMicrosoft Authenticator: $($msAuth.State)" -ForegroundColor $(if($msAuth.State -eq 'enabled'){'Green'}else{'Red'})

$props = $msAuth.AdditionalProperties
if ($props.featureSettings) {
    $nm  = $props.featureSettings.numberMatchingRequiredState
    $ctx = $props.featureSettings.displayAppInformationRequiredState
    Write-Host "Number Matching:    $(if($nm.state -eq 'enabled'){'ENABLED'}else{'DISABLED'})" `
               -ForegroundColor $(if($nm.state -eq 'enabled'){'Green'}else{'Red'})
    Write-Host "Additional Context: $(if($ctx.state -eq 'enabled'){'ENABLED'}else{'DISABLED'})" `
               -ForegroundColor $(if($ctx.state -eq 'enabled'){'Green'}else{'Red'})
} else {
    Write-Host "Could not read feature settings. Check Entra ID > Authentication Methods > Microsoft Authenticator." -ForegroundColor Yellow
}

Write-Host "`nNumber matching prevents MFA fatigue attacks (push bombing)." -ForegroundColor Cyan
Write-Host "Enable at: Entra ID > Protection > Authentication Methods > Microsoft Authenticator > Configure" -ForegroundColor White
Disconnect-MgGraph"""
    },

    "SEC-004": {
        "title": "Enabled authentication methods",
        "description": "Lists all enabled authentication methods in the tenant, flagging weak options such as SMS and voice call.",
        "script": r"""# SEC-004 — Authentication Method Inventory
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

$weak   = @('Sms','Voice','Email')
$strong = @('MicrosoftAuthenticator','Fido2','WindowsHelloForBusiness','SoftwareOath','TemporaryAccessPass')

$policy = Get-MgPolicyAuthenticationMethodPolicy
Write-Host "`nAuthentication Method Status:" -ForegroundColor Cyan

foreach ($method in $policy.AuthenticationMethodConfigurations) {
    $isWeak   = $weak   -contains $method.Id
    $isStrong = $strong -contains $method.Id
    $tag      = if ($isWeak) { '  [WEAK — consider disabling]' } elseif ($isStrong) { '  [Strong]' } else { '' }
    $col      = if ($method.State -eq 'enabled' -and $isWeak) { 'Red' } `
                elseif ($method.State -eq 'enabled' -and $isStrong) { 'Green' } `
                else { 'Gray' }
    Write-Host "  $($method.Id.PadRight(32)) $($method.State)$tag" -ForegroundColor $col
}

Write-Host "`nSMS and Voice are vulnerable to SIM swapping and SS7 interception." -ForegroundColor Yellow
Write-Host "Disable weak methods once Authenticator or FIDO2 is fully deployed." -ForegroundColor Cyan
Disconnect-MgGraph"""
    },

    "SEC-005": {
        "title": "User app consent configuration",
        "description": "Shows whether users can consent to OAuth applications without admin approval, and lists existing user-level grants.",
        "script": r"""# SEC-005 — User App Consent Policy
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All, Directory.Read.All

Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All" -NoWelcome

$authPolicy  = Get-MgPolicyAuthorizationPolicy | Select-Object -First 1
$grantPolicies = $authPolicy.PermissionGrantPolicyIdsAssignedToDefaultUserRole

Write-Host "`nUser Consent Policy:" -ForegroundColor Cyan
Write-Host "  Permission grant policies: $($grantPolicies -join ', ')" -ForegroundColor White

if ($grantPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {
    Write-Host "`n  WARNING: Users can consent to any OAuth app requesting any permission." -ForegroundColor Red
    Write-Host "  This enables illicit consent grant (OAuth phishing) attacks." -ForegroundColor Red
} elseif ($grantPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-low') {
    Write-Host "`n  Users can consent to low-risk permissions only." -ForegroundColor Yellow
    Write-Host "  Consider requiring admin approval for all third-party apps." -ForegroundColor Yellow
} elseif (-not $grantPolicies) {
    Write-Host "`n  Users cannot consent to apps — admin approval required. Good." -ForegroundColor Green
}

Write-Host "`nUser-level OAuth permission grants in tenant:" -ForegroundColor Cyan
$grants = Get-MgOauth2PermissionGrant -All | Where-Object { $_.ConsentType -eq 'Principal' }
Write-Host "  $($grants.Count) user-level OAuth grant(s) found" -ForegroundColor $(if($grants.Count -gt 0){'Yellow'}else{'Green'})

if ($grants.Count -gt 0) {
    $csv = "OAuthUserGrants_$(Get-Date -Format yyyyMMdd).csv"
    $grants | Select-Object ClientId, ConsentType, PrincipalId, Scope | Export-Csv $csv -NoTypeInformation
    Write-Host "  Exported: $csv" -ForegroundColor Cyan
    Write-Host "  Review each grant in Entra ID > Enterprise Applications > Permissions" -ForegroundColor White
}
Disconnect-MgGraph"""
    },

    "CA-001": {
        "title": "Conditional Access policy inventory",
        "description": "Lists all Conditional Access policies by state — enforced, report-only, and disabled — to identify coverage gaps.",
        "script": r"""# CA-001 — Conditional Access Policy Inventory
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All

Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome

$all        = Get-MgIdentityConditionalAccessPolicy -All
$enabled    = $all | Where-Object { $_.State -eq 'enabled' }
$reportOnly = $all | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }
$disabled   = $all | Where-Object { $_.State -eq 'disabled' }

Write-Host "`nConditional Access Policy Summary:" -ForegroundColor Cyan
Write-Host "  Total:        $($all.Count)" -ForegroundColor White
Write-Host "  Enforced:     $($enabled.Count)" -ForegroundColor $(if($enabled.Count -gt 0){'Green'}else{'Red'})
Write-Host "  Report-only:  $($reportOnly.Count)" -ForegroundColor Yellow
Write-Host "  Disabled:     $($disabled.Count)" -ForegroundColor Gray

if ($enabled.Count -eq 0) {
    Write-Host "`n  CRITICAL: No policies are enforced. Users are not protected by Conditional Access." -ForegroundColor Red
}

Write-Host "`nEnforced Policies:" -ForegroundColor Green
if ($enabled) { $enabled | Select-Object DisplayName, State, ModifiedDateTime | Format-Table -AutoSize }
else { Write-Host "  None" -ForegroundColor Red }

Write-Host "`nReport-Only Policies (not yet enforced):" -ForegroundColor Yellow
if ($reportOnly) { $reportOnly | Select-Object DisplayName | Format-Table -AutoSize }
else { Write-Host "  None" -ForegroundColor Gray }

$csv = "CAPolicies_$(Get-Date -Format yyyyMMdd).csv"
$all | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime | Export-Csv $csv -NoTypeInformation
Write-Host "Full policy list exported: $csv" -ForegroundColor Cyan
Disconnect-MgGraph"""
    },

    "CA-002": {
        "title": "Legacy authentication sign-in activity",
        "description": "Checks for a CA policy blocking legacy auth and shows recent sign-ins using legacy protocols from sign-in logs.",
        "script": r"""# CA-002 — Legacy Authentication Check
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All, AuditLog.Read.All

Connect-MgGraph -Scopes "Policy.Read.All", "AuditLog.Read.All" -NoWelcome

# Check for CA policy blocking legacy auth
$allPolicies  = Get-MgIdentityConditionalAccessPolicy -All
$legacyBlock  = $allPolicies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -and
    $_.Conditions.ClientAppTypes -contains 'other' -and
    $_.GrantControls.BuiltInControls -contains 'block'
}

if ($legacyBlock) {
    Write-Host "`nLegacy authentication is BLOCKED by CA policy:" -ForegroundColor Green
    $legacyBlock | Select-Object DisplayName, State | Format-Table -AutoSize
} else {
    Write-Host "`nWARNING: No CA policy found blocking legacy authentication." -ForegroundColor Red
    Write-Host "Legacy auth bypasses MFA — a primary vector for password spray attacks." -ForegroundColor Red
}

# Check sign-in logs for legacy protocol usage (last 7 days)
Write-Host "`nChecking sign-in logs for legacy protocol usage (last 7 days)..." -ForegroundColor Cyan
$signIns = Get-MgAuditLogSignIn `
           -Filter "clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'" `
           -Top 100 -ErrorAction SilentlyContinue

if ($signIns) {
    $grouped = $signIns | Group-Object ClientAppUsed | Sort-Object Count -Descending
    Write-Host "`nLegacy protocol usage breakdown:" -ForegroundColor Yellow
    $grouped | Select-Object Name, Count | Format-Table -AutoSize
    $csv = "LegacyAuthSignIns_$(Get-Date -Format yyyyMMdd).csv"
    $signIns | Select-Object UserPrincipalName, ClientAppUsed, AppDisplayName, CreatedDateTime, IpAddress |
               Export-Csv $csv -NoTypeInformation
    Write-Host "Sign-in details exported: $csv" -ForegroundColor Cyan
} else {
    Write-Host "No legacy authentication sign-ins found." -ForegroundColor Green
}
Disconnect-MgGraph"""
    },

    "EXO-002": {
        "title": "Mailbox audit configuration",
        "description": "Checks org-level audit status and lists any mailboxes with auditing explicitly disabled.",
        "script": r"""# EXO-002 — Mailbox Audit Status
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$orgConfig = Get-OrganizationConfig | Select-Object AuditDisabled
Write-Host "`nOrganisation-level auditing: $(if(-not $orgConfig.AuditDisabled){'ENABLED'}else{'DISABLED'})" `
           -ForegroundColor $(if(-not $orgConfig.AuditDisabled){'Green'}else{'Red'})

$disabled = Get-Mailbox -ResultSize Unlimited -Filter "AuditEnabled -eq `$false" |
            Select-Object UserPrincipalName, DisplayName, RecipientTypeDetails

if ($disabled.Count -eq 0) {
    Write-Host "All mailboxes have auditing enabled." -ForegroundColor Green
} else {
    Write-Host "`n$($disabled.Count) mailbox(es) with auditing explicitly disabled:" -ForegroundColor Red
    $disabled | Format-Table -AutoSize
    $csv = "AuditDisabledMailboxes_$(Get-Date -Format yyyyMMdd).csv"
    $disabled | Export-Csv $csv -NoTypeInformation
    Write-Host "Exported: $csv" -ForegroundColor Cyan
}

# Show audit actions on a sample mailbox
$sample = Get-Mailbox -ResultSize 1 -RecipientTypeDetails UserMailbox
if ($sample) {
    Write-Host "`nSample mailbox audit actions ($($sample.UserPrincipalName)):" -ForegroundColor Cyan
    $audit = Get-Mailbox -Identity $sample.UserPrincipalName |
             Select-Object AuditEnabled, AuditOwner, AuditDelegate, AuditAdmin
    Write-Host "  Enabled:   $($audit.AuditEnabled)"
    Write-Host "  Owner:     $($audit.AuditOwner -join ', ')"
    Write-Host "  Delegate:  $($audit.AuditDelegate -join ', ')"
    Write-Host "  Admin:     $($audit.AuditAdmin -join ', ')"
}
Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "EXO-003": {
        "title": "Anti-phishing policy review",
        "description": "Shows spoof intelligence, mailbox intelligence, and impersonation protection settings across all anti-phishing policies.",
        "script": r"""# EXO-003 — Anti-Phishing Policy Review
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$policies = Get-AntiPhishPolicy | Sort-Object IsDefault -Descending

foreach ($policy in $policies) {
    $label = if ($policy.IsDefault) { ' [Default]' } else { '' }
    Write-Host "`nPolicy: $($policy.Name)$label" -ForegroundColor Cyan
    Write-Host "  Enabled:                  $($policy.Enabled)" `
               -ForegroundColor $(if($policy.Enabled){'Green'}else{'Red'})
    Write-Host "  Spoof Intelligence:       $($policy.EnableSpoofIntelligence)" `
               -ForegroundColor $(if($policy.EnableSpoofIntelligence){'Green'}else{'Red'})
    Write-Host "  Mailbox Intelligence:     $($policy.EnableMailboxIntelligence)" `
               -ForegroundColor $(if($policy.EnableMailboxIntelligence){'Green'}else{'Red'})
    Write-Host "  Honour DMARC Policy:      $($policy.HonorDmarcPolicy)" `
               -ForegroundColor $(if($policy.HonorDmarcPolicy){'Green'}else{'Yellow'})
    Write-Host "  User Impersonation:       $($policy.EnableTargetedUserProtection)" `
               -ForegroundColor $(if($policy.EnableTargetedUserProtection){'Green'}else{'Yellow'})
    Write-Host "  Domain Impersonation:     $($policy.EnableTargetedDomainsProtection)" `
               -ForegroundColor $(if($policy.EnableTargetedDomainsProtection){'Green'}else{'Yellow'})
    Write-Host "  Phish Threshold Level:    $($policy.PhishThresholdLevel)  (1=Standard 2=Aggressive 3=More 4=Most)"
}

$csv = "AntiPhishPolicies_$(Get-Date -Format yyyyMMdd).csv"
$policies | Select-Object Name, Enabled, EnableSpoofIntelligence, HonorDmarcPolicy,
            EnableMailboxIntelligence, EnableTargetedUserProtection, PhishThresholdLevel |
            Export-Csv $csv -NoTypeInformation
Write-Host "`nFull policy export: $csv" -ForegroundColor Cyan
Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "TEAMS-001": {
        "title": "Teams external access configuration",
        "description": "Shows federation settings and whether external Teams users can communicate freely or only via an allowed domain list.",
        "script": r"""# TEAMS-001 — Teams External Access Review
# Requires: MicrosoftTeams module

Connect-MicrosoftTeams

$config = Get-CsTenantFederationConfiguration

Write-Host "`nTeams External Access Settings:" -ForegroundColor Cyan
Write-Host "  AllowFederatedUsers:       $($config.AllowFederatedUsers)" `
           -ForegroundColor $(if($config.AllowFederatedUsers){'Yellow'}else{'Green'})
Write-Host "  AllowPublicUsers:          $($config.AllowPublicUsers)" `
           -ForegroundColor $(if($config.AllowPublicUsers){'Yellow'}else{'Green'})
Write-Host "  AllowTeamsConsumer:        $($config.AllowTeamsConsumer)" `
           -ForegroundColor $(if($config.AllowTeamsConsumer){'Red'}else{'Green'})

if ($config.AllowFederatedUsers) {
    $allowed = Get-CsAllowedDomain
    $blocked = Get-CsBlockedDomain
    if ($allowed.Count -gt 0) {
        Write-Host "`n  Allowed domains list (restricted federation — good):" -ForegroundColor Green
        $allowed | Select-Object Domain | Format-Table -AutoSize
    } else {
        Write-Host "`n  Open federation — any external Teams tenant can contact your users." -ForegroundColor Red
        Write-Host "  Recommendation: Restrict to an allowed domain list of approved partners." -ForegroundColor Yellow
    }
    if ($blocked.Count -gt 0) {
        Write-Host "  Explicitly blocked domains: $($blocked.Count)" -ForegroundColor Yellow
    }
}

$csv = "TeamsFederation_$(Get-Date -Format yyyyMMdd).csv"
[PSCustomObject]@{
    AllowFederatedUsers = $config.AllowFederatedUsers
    AllowPublicUsers    = $config.AllowPublicUsers
    AllowTeamsConsumer  = $config.AllowTeamsConsumer
    AllowedDomains      = (Get-CsAllowedDomain).Count
    BlockedDomains      = (Get-CsBlockedDomain).Count
} | Export-Csv $csv -NoTypeInformation
Write-Host "`nConfiguration exported: $csv" -ForegroundColor Cyan
Disconnect-MicrosoftTeams"""
    },

    "TEAMS-002": {
        "title": "Teams consumer access status",
        "description": "Checks whether personal Microsoft accounts (Teams personal/Skype) can communicate with your tenant users.",
        "script": r"""# TEAMS-002 — Teams Consumer (Personal Account) Access
# Requires: MicrosoftTeams module

Connect-MicrosoftTeams

$config = Get-CsTenantFederationConfiguration

Write-Host "`nTeams Consumer Access Settings:" -ForegroundColor Cyan
Write-Host "  AllowTeamsConsumer:        $($config.AllowTeamsConsumer)" `
           -ForegroundColor $(if($config.AllowTeamsConsumer){'Red'}else{'Green'})
Write-Host "  AllowTeamsConsumerInbound: $($config.AllowTeamsConsumerInbound)" `
           -ForegroundColor $(if($config.AllowTeamsConsumerInbound){'Red'}else{'Green'})

if ($config.AllowTeamsConsumer -or $config.AllowTeamsConsumerInbound) {
    Write-Host "`n  WARNING: Personal Microsoft accounts can communicate with your users." -ForegroundColor Red
    Write-Host "  Files and chats can be shared with unmanaged, unaudited accounts." -ForegroundColor Red
    Write-Host "`n  To disable:" -ForegroundColor Yellow
    Write-Host "  Set-CsTenantFederationConfiguration -AllowTeamsConsumer `$false -AllowTeamsConsumerInbound `$false" -ForegroundColor White
} else {
    Write-Host "`n  Teams consumer access is blocked. Good." -ForegroundColor Green
}

$meetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global
Write-Host "`n  Anonymous meeting join: $($meetingPolicy.AllowAnonymousUsersToJoinMeeting)" `
           -ForegroundColor $(if($meetingPolicy.AllowAnonymousUsersToJoinMeeting){'Yellow'}else{'Green'})
Disconnect-MicrosoftTeams"""
    },

    "SPO-001": {
        "title": "SharePoint sharing level and anonymous links",
        "description": "Checks the tenant-level sharing setting and identifies sites with Anyone (anonymous) link sharing enabled.",
        "script": r"""# SPO-001 — SharePoint Sharing Level Audit
# Requires: Microsoft.Online.SharePoint.PowerShell module

$spAdminUrl = Read-Host "Enter your SharePoint Admin URL (e.g. https://contoso-admin.sharepoint.com)"
Connect-SPOService -Url $spAdminUrl

$tenant = Get-SPOTenant
$level  = $tenant.SharingCapability

$levelDesc = switch ($level) {
    'Disabled'                       { 'Sharing disabled — most restrictive' }
    'ExistingExternalUserSharingOnly'{ 'Existing external users only' }
    'ExternalUserSharingOnly'        { 'New and existing guests (sign-in required)' }
    'ExternalUserAndGuestSharing'    { 'Anyone — anonymous links ALLOWED' }
    default                          { $level }
}
$col = if ($level -eq 'ExternalUserAndGuestSharing') { 'Red' } `
       elseif ($level -eq 'ExternalUserSharingOnly') { 'Yellow' } else { 'Green' }

Write-Host "`nTenant Sharing Level: $level" -ForegroundColor $col
Write-Host "  $levelDesc" -ForegroundColor $col
Write-Host "  Anyone link expiry: $($tenant.RequireAnonymousLinksExpireInDays) days (0 = no expiry)" `
           -ForegroundColor $(if($tenant.RequireAnonymousLinksExpireInDays -eq 0 -and $level -eq 'ExternalUserAndGuestSharing'){'Red'}else{'Green'})
Write-Host "  Default link type: $($tenant.DefaultSharingLinkType)" -ForegroundColor Cyan

Write-Host "`nChecking sites with Anyone link sharing enabled..." -ForegroundColor Cyan
$sites = Get-SPOSite -Limit All -IncludePersonalSite $false |
         Where-Object { $_.SharingCapability -eq 'ExternalUserAndGuestSharing' }

if ($sites.Count -gt 0) {
    Write-Host "$($sites.Count) site(s) allow anonymous links:" -ForegroundColor Red
    $sites | Select-Object Url, SharingCapability | Format-Table -AutoSize
    $csv = "SPOAnonymousSites_$(Get-Date -Format yyyyMMdd).csv"
    $sites | Export-Csv $csv -NoTypeInformation
    Write-Host "Exported: $csv" -ForegroundColor Cyan
} else {
    Write-Host "No sites with anonymous link sharing found." -ForegroundColor Green
}
Disconnect-SPOService"""
    },

    "SPO-002": {
        "title": "SharePoint legacy authentication status",
        "description": "Shows whether legacy authentication protocols are enabled in SharePoint, allowing connections that bypass MFA.",
        "script": r"""# SPO-002 — SharePoint Legacy Authentication
# Requires: Microsoft.Online.SharePoint.PowerShell module

$spAdminUrl = Read-Host "Enter your SharePoint Admin URL (e.g. https://contoso-admin.sharepoint.com)"
Connect-SPOService -Url $spAdminUrl

$tenant = Get-SPOTenant

Write-Host "`nSharePoint Legacy Authentication:" -ForegroundColor Cyan
Write-Host "  LegacyAuthProtocolsEnabled: $($tenant.LegacyAuthProtocolsEnabled)" `
           -ForegroundColor $(if($tenant.LegacyAuthProtocolsEnabled){'Red'}else{'Green'})
Write-Host "  BrowserSSOEnabled:          $($tenant.BrowserSSOEnabled)" `
           -ForegroundColor $(if($tenant.BrowserSSOEnabled){'Green'}else{'Yellow'})
Write-Host "  ConditionalAccessPolicy:    $($tenant.ConditionalAccessPolicy)" -ForegroundColor Cyan

if ($tenant.LegacyAuthProtocolsEnabled) {
    Write-Host "`n  WARNING: Legacy authentication is enabled." -ForegroundColor Red
    Write-Host "  Basic auth connections can bypass MFA and Conditional Access." -ForegroundColor Red
    Write-Host "`n  To disable:" -ForegroundColor Yellow
    Write-Host "  Set-SPOTenant -LegacyAuthProtocolsEnabled `$false" -ForegroundColor White
} else {
    Write-Host "`n  Legacy authentication is disabled. Good." -ForegroundColor Green
}

Write-Host "`nAdditional settings:" -ForegroundColor Cyan
Write-Host "  EmailAttestationRequired:              $($tenant.EmailAttestationRequired)"
Write-Host "  AllowDownloadingNonWebViewableFiles:   $($tenant.AllowDownloadingNonWebViewableFiles)"
Disconnect-SPOService"""
    },

    "MDM-002": {
        "title": "Intune compliance policy inventory",
        "description": "Lists all Intune compliance policies, shows platform coverage, and identifies any policies with no assignments.",
        "script": r"""# MDM-002 — Intune Compliance Policy Inventory
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementConfiguration.Read.All

Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome

$policies = Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction SilentlyContinue

if (-not $policies -or $policies.Count -eq 0) {
    Write-Host "`nCRITICAL: No Intune compliance policies found." -ForegroundColor Red
    Write-Host "Without compliance policies, device health cannot be enforced and" -ForegroundColor Red
    Write-Host "Conditional Access cannot block non-compliant devices from accessing resources." -ForegroundColor Red
    Write-Host "`nCreate compliance policies at: https://intune.microsoft.com > Devices > Compliance" -ForegroundColor Yellow
} else {
    Write-Host "`nIntune Compliance Policies: $($policies.Count) found" -ForegroundColor Green

    Write-Host "`nPlatform coverage:" -ForegroundColor Cyan
    $policies | Group-Object {
        $_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.','' -replace 'CompliancePolicy',''
    } | Select-Object Name, Count | Format-Table -AutoSize

    # Check for unassigned policies
    Write-Host "Checking assignments..." -ForegroundColor Cyan
    $unassigned = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $policies) {
        $assignments = Get-MgDeviceManagementDeviceCompliancePolicyAssignment `
                       -DeviceCompliancePolicyId $p.Id -ErrorAction SilentlyContinue
        if (-not $assignments) { $unassigned.Add($p) }
    }

    if ($unassigned.Count -gt 0) {
        Write-Host "`n$($unassigned.Count) policy/policies exist but are NOT assigned to any users or devices:" -ForegroundColor Yellow
        $unassigned | Select-Object DisplayName | Format-Table -AutoSize
    } else {
        Write-Host "All compliance policies are assigned." -ForegroundColor Green
    }

    $csv = "CompliancePolicies_$(Get-Date -Format yyyyMMdd).csv"
    $policies | Select-Object DisplayName, CreatedDateTime, LastModifiedDateTime | Export-Csv $csv -NoTypeInformation
    Write-Host "`nFull list exported: $csv" -ForegroundColor Cyan
}
Disconnect-MgGraph"""
    },

    "ID-006": {
        "title": "Risky user details",
        "description": "Lists all high and medium risk users from Entra ID Identity Protection with their risk level, state, and last update.",
        "script": r"""# ID-006 — Risky User Review
# Requires: Microsoft.Graph module
# Permissions: IdentityRiskyUser.Read.All

Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All" -NoWelcome

$riskyUsers = Get-MgRiskyUser -All -Filter "riskState ne 'remediated' and riskState ne 'dismissed'" |
              Where-Object { $_.RiskLevel -in @('high','medium') } |
              Sort-Object RiskLevel, RiskLastUpdatedDateTime -Descending

if ($riskyUsers.Count -eq 0) {
    Write-Host "`nNo high or medium risk users found. Good." -ForegroundColor Green
} else {
    Write-Host "`n$($riskyUsers.Count) risky user(s) requiring attention:" -ForegroundColor Red
    $riskyUsers | Select-Object UserPrincipalName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime |
                  Format-Table -AutoSize

    $csv = "RiskyUsers_$(Get-Date -Format yyyyMMdd).csv"
    $riskyUsers | Select-Object UserPrincipalName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime |
                  Export-Csv $csv -NoTypeInformation
    Write-Host "Exported: $csv" -ForegroundColor Cyan
    Write-Host "`nRecommended actions:" -ForegroundColor Yellow
    Write-Host "  - High risk: block sign-in and require password reset immediately" -ForegroundColor White
    Write-Host "  - Medium risk: require MFA re-registration and password change" -ForegroundColor White
    Write-Host "  - Dismiss false positives in Entra ID > Protection > Risky users" -ForegroundColor White
}
Disconnect-MgGraph"""
    },

    "ID-007": {
        "title": "Emergency access account detection",
        "description": "Attempts to identify break-glass accounts by looking for Global Admins excluded from all enabled Conditional Access policies.",
        "script": r"""# ID-007 — Emergency Access Account Detection
# Requires: Microsoft.Graph module
# Permissions: Policy.Read.All, Directory.Read.All

Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All" -NoWelcome

# Get all Global Admins
$gaRole   = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
$gaMembers = @{}
if ($gaRole) {
    Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All | ForEach-Object {
        $gaMembers[$_.Id] = $_.AdditionalProperties['userPrincipalName'] ?? $_.Id
    }
}

# Get all enabled CA policies and their excluded users
$policies       = Get-MgIdentityConditionalAccessPolicy -All | Where-Object { $_.State -eq 'enabled' }
$exclusionCount = @{}
foreach ($p in $policies) {
    foreach ($uid in $p.Conditions.Users.ExcludeUsers) {
        $exclusionCount[$uid] = ($exclusionCount[$uid] ?? 0) + 1
    }
}

# Find Global Admins excluded from ALL enabled CA policies
$totalPolicies   = $policies.Count
$breakGlassFound = [System.Collections.Generic.List[object]]::new()

foreach ($uid in $gaMembers.Keys) {
    $exCount = $exclusionCount[$uid] ?? 0
    if ($totalPolicies -gt 0 -and $exCount -eq $totalPolicies) {
        $breakGlassFound.Add([PSCustomObject]@{
            UserPrincipalName = $gaMembers[$uid]
            UserId            = $uid
            ExcludedFromPolicies = $exCount
            TotalPolicies        = $totalPolicies
            Assessment = 'Likely break-glass account'
        })
    }
}

Write-Host "`nGlobal Administrators: $($gaMembers.Count)" -ForegroundColor Cyan
Write-Host "Enabled CA Policies:   $totalPolicies" -ForegroundColor Cyan

if ($breakGlassFound.Count -gt 0) {
    Write-Host "`nPotential emergency access account(s) detected:" -ForegroundColor Green
    $breakGlassFound | Format-Table -AutoSize
    Write-Host "Verify these accounts have credentials stored securely offline." -ForegroundColor Yellow
} else {
    Write-Host "`nNo account found that is excluded from ALL CA policies." -ForegroundColor Red
    Write-Host "Consider creating a dedicated emergency access account excluded from all CA policies." -ForegroundColor Yellow
    Write-Host "See: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access" -ForegroundColor White
}
Disconnect-MgGraph"""
    },

    "SEC-006": {
        "title": "Microsoft Sentinel connection status",
        "description": "Checks for Sentinel alert activity via the Microsoft Security Graph API as a proxy for whether Sentinel is connected.",
        "script": r"""# SEC-006 — Microsoft Sentinel Connection Check
# Requires: Microsoft.Graph module
# Permissions: SecurityEvents.Read.All

Connect-MgGraph -Scopes "SecurityEvents.Read.All" -NoWelcome

Write-Host "`nChecking for Microsoft Sentinel alert activity..." -ForegroundColor Cyan

try {
    # Check for Sentinel alerts via Security API
    $sentinelAlerts = Get-MgSecurityAlert -All -ErrorAction Stop |
                      Where-Object { $_.VendorInformation.Provider -match 'Sentinel|Azure Sentinel' }

    if ($sentinelAlerts.Count -gt 0) {
        Write-Host "Microsoft Sentinel alerts found: $($sentinelAlerts.Count)" -ForegroundColor Green
        Write-Host "Sentinel appears to be connected and generating alerts.`n" -ForegroundColor Green
        $sentinelAlerts | Select-Object Title, Severity, Status, CreatedDateTime |
                          Sort-Object CreatedDateTime -Descending |
                          Select-Object -First 10 |
                          Format-Table -AutoSize
    } else {
        Write-Host "No Sentinel alerts found via Security Graph API." -ForegroundColor Yellow
        Write-Host "This may indicate Sentinel is not connected, or no alerts have been generated." -ForegroundColor Yellow
        Write-Host "`nTo verify directly, check:" -ForegroundColor Cyan
        Write-Host "  Azure Portal > Microsoft Sentinel > Overview" -ForegroundColor White
        Write-Host "  https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/MainMenuBlade" -ForegroundColor White
    }

    # Also check all security alert providers for context
    $allProviders = Get-MgSecurityAlert -All -ErrorAction SilentlyContinue |
                    Group-Object { $_.VendorInformation.Provider } |
                    Sort-Object Count -Descending
    if ($allProviders) {
        Write-Host "`nSecurity alert providers currently active:" -ForegroundColor Cyan
        $allProviders | Select-Object Name, Count | Format-Table -AutoSize
    }
} catch {
    Write-Host "Could not query Security alerts: $_" -ForegroundColor Red
    Write-Host "Check permissions: SecurityEvents.Read.All is required." -ForegroundColor Yellow
}
Disconnect-MgGraph"""
    },

    "EXO-004": {
        "title": "DMARC DNS record check",
        "description": "Performs a DNS lookup for the DMARC TXT record on your primary domain and shows the current policy.",
        "script": r"""# EXO-004 — DMARC Configuration Check
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

# Get primary accepted domain
$primaryDomain = (Get-AcceptedDomain | Where-Object { $_.Default -eq $true }).DomainName
Write-Host "`nPrimary domain: $primaryDomain" -ForegroundColor Cyan

# Check DMARC
Write-Host "`nDMARC Record:" -ForegroundColor Cyan
try {
    $dmarc = Resolve-DnsName -Name "_dmarc.$primaryDomain" -Type TXT -ErrorAction Stop
    $dmarcRecord = ($dmarc | Where-Object { $_.Strings -match 'v=DMARC1' }).Strings -join ''
    if ($dmarcRecord) {
        Write-Host "  FOUND: $dmarcRecord" -ForegroundColor Green
        if ($dmarcRecord -match 'p=none')      { Write-Host "  Policy: none (monitoring only — not enforced)" -ForegroundColor Yellow }
        elseif ($dmarcRecord -match 'p=quarantine') { Write-Host "  Policy: quarantine (failing emails go to spam)" -ForegroundColor Yellow }
        elseif ($dmarcRecord -match 'p=reject') { Write-Host "  Policy: reject (failing emails blocked — strongest)" -ForegroundColor Green }
    } else {
        Write-Host "  TXT record found but no DMARC record present." -ForegroundColor Red
    }
} catch {
    Write-Host "  NOT FOUND — no DMARC record at _dmarc.$primaryDomain" -ForegroundColor Red
    Write-Host "  Attackers can spoof @$primaryDomain in phishing emails." -ForegroundColor Red
}

# Check SPF while we're here
Write-Host "`nSPF Record:" -ForegroundColor Cyan
try {
    $spf = Resolve-DnsName -Name $primaryDomain -Type TXT -ErrorAction Stop
    $spfRecord = ($spf | Where-Object { $_.Strings -match 'v=spf1' }).Strings -join ''
    if ($spfRecord) {
        Write-Host "  FOUND: $spfRecord" -ForegroundColor Green
    } else {
        Write-Host "  NOT FOUND — no SPF record on $primaryDomain" -ForegroundColor Red
    }
} catch {
    Write-Host "  Could not resolve DNS for $primaryDomain" -ForegroundColor Red
}

# DKIM
Write-Host "`nDKIM Signing Status:" -ForegroundColor Cyan
$dkim = Get-DkimSigningConfig -ErrorAction SilentlyContinue
$dkim | Select-Object Domain, Enabled, Status | Format-Table -AutoSize

Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "EXO-005": {
        "title": "SPF and DKIM configuration",
        "description": "Checks SPF DNS record on the primary domain and DKIM signing configuration in Exchange Online.",
        "script": r"""# EXO-005 — SPF and DKIM Configuration Check
# Requires: ExchangeOnlineManagement module

Connect-ExchangeOnline -ShowBanner:$false

$primaryDomain = (Get-AcceptedDomain | Where-Object { $_.Default -eq $true }).DomainName
Write-Host "`nPrimary domain: $primaryDomain" -ForegroundColor Cyan

# SPF check
Write-Host "`nSPF Record:" -ForegroundColor Cyan
try {
    $spf = Resolve-DnsName -Name $primaryDomain -Type TXT -ErrorAction Stop
    $spfRecord = ($spf | Where-Object { $_.Strings -match 'v=spf1' }).Strings -join ''
    if ($spfRecord) {
        Write-Host "  FOUND: $spfRecord" -ForegroundColor Green
        if ($spfRecord -match '~all') { Write-Host "  Qualifier: ~all (SoftFail — not rejected, marked as suspicious)" -ForegroundColor Yellow }
        elseif ($spfRecord -match '-all') { Write-Host "  Qualifier: -all (HardFail — failing mail rejected)" -ForegroundColor Green }
        elseif ($spfRecord -match '\+all') { Write-Host "  WARNING: +all allows any server to send as your domain" -ForegroundColor Red }
    } else {
        Write-Host "  NOT FOUND — no SPF record on $primaryDomain" -ForegroundColor Red
        Write-Host "  Outbound email may be rejected by recipient servers." -ForegroundColor Red
    }
} catch {
    Write-Host "  Could not resolve DNS for $primaryDomain" -ForegroundColor Red
}

# DKIM check
Write-Host "`nDKIM Signing Configuration:" -ForegroundColor Cyan
$dkimConfigs = Get-DkimSigningConfig -ErrorAction SilentlyContinue

if (-not $dkimConfigs) {
    Write-Host "  No DKIM signing configurations found." -ForegroundColor Red
} else {
    foreach ($d in $dkimConfigs) {
        $col = if ($d.Enabled) { 'Green' } else { 'Red' }
        Write-Host "  $($d.Domain.PadRight(50)) Enabled: $($d.Enabled)  Status: $($d.Status)" -ForegroundColor $col
    }
    $disabled = $dkimConfigs | Where-Object { -not $_.Enabled }
    if ($disabled) {
        Write-Host "`n  To enable DKIM for a domain:" -ForegroundColor Yellow
        Write-Host "  Set-DkimSigningConfig -Identity domain.com -Enabled `$true" -ForegroundColor White
        Write-Host "  Or: New-DkimSigningConfig -DomainName domain.com -Enabled `$true" -ForegroundColor White
    }
}

# All accepted domains summary
Write-Host "`nAll accepted domains:" -ForegroundColor Cyan
Get-AcceptedDomain | Select-Object DomainName, Default, DomainType | Format-Table -AutoSize

Disconnect-ExchangeOnline -Confirm:$false"""
    },

    "MDM-003": {
        "title": "Windows Update ring inventory",
        "description": "Lists all Windows Update for Business rings configured in Intune with their deferral periods.",
        "script": r"""# MDM-003 — Windows Update Ring Inventory
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementConfiguration.Read.All

Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome

$allConfigs   = Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction SilentlyContinue
$updateRings  = $allConfigs | Where-Object {
    $_.AdditionalProperties['@odata.type'] -like '*windowsUpdateForBusiness*'
}

if (-not $updateRings -or $updateRings.Count -eq 0) {
    Write-Host "`nNo Windows Update rings found in Intune." -ForegroundColor Red
    Write-Host "Without update rings, Windows devices may not receive patches consistently." -ForegroundColor Red
    Write-Host "`nCreate update rings at: Intune > Devices > Windows > Update rings for Windows 10 and later" -ForegroundColor Yellow
} else {
    Write-Host "`nWindows Update Rings: $($updateRings.Count) found" -ForegroundColor Green

    foreach ($ring in $updateRings) {
        $props = $ring.AdditionalProperties
        Write-Host "`nRing: $($ring.DisplayName)" -ForegroundColor Cyan
        Write-Host "  Quality update deferral:  $($props['qualityUpdatesDeferralPeriodInDays'] ?? 'Not set') days"
        Write-Host "  Feature update deferral:  $($props['featureUpdatesDeferralPeriodInDays'] ?? 'Not set') days"
        Write-Host "  Automatic update behavior: $($props['automaticUpdateMode'] ?? 'Not set')"
        Write-Host "  Created: $($ring.CreatedDateTime)"
    }

    # Check assignments
    Write-Host "`nChecking ring assignments..." -ForegroundColor Cyan
    $unassigned = [System.Collections.Generic.List[object]]::new()
    foreach ($ring in $updateRings) {
        $assignments = Get-MgDeviceManagementDeviceConfigurationAssignment `
                       -DeviceConfigurationId $ring.Id -ErrorAction SilentlyContinue
        if (-not $assignments) { $unassigned.Add($ring) }
    }
    if ($unassigned.Count -gt 0) {
        Write-Host "$($unassigned.Count) ring(s) are not assigned to any users or devices:" -ForegroundColor Yellow
        $unassigned | Select-Object DisplayName | Format-Table -AutoSize
    } else {
        Write-Host "All rings are assigned." -ForegroundColor Green
    }
}
Disconnect-MgGraph"""
    },

    "MDM-004": {
        "title": "BitLocker enforcement check",
        "description": "Looks for BitLocker requirements in Intune compliance policies and device configuration profiles.",
        "script": r"""# MDM-004 — BitLocker Enforcement Check
# Requires: Microsoft.Graph module
# Permissions: DeviceManagementConfiguration.Read.All

Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome

Write-Host "`nChecking Intune compliance policies for BitLocker requirement..." -ForegroundColor Cyan
$compPolicies    = Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction SilentlyContinue
$bitlockerCompPolicies = $compPolicies | Where-Object {
    $_.AdditionalProperties['storageRequireDeviceEncryption'] -eq $true -or
    $_.AdditionalProperties['bitLockerEnabled'] -eq $true
}

if ($bitlockerCompPolicies) {
    Write-Host "  BitLocker required in compliance policy/policies:" -ForegroundColor Green
    $bitlockerCompPolicies | Select-Object DisplayName | Format-Table -AutoSize
} else {
    Write-Host "  No compliance policy found requiring BitLocker/device encryption." -ForegroundColor Red
}

Write-Host "`nChecking device configuration profiles for BitLocker settings..." -ForegroundColor Cyan
$configProfiles    = Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction SilentlyContinue
$bitlockerConfigs  = $configProfiles | Where-Object {
    $_.AdditionalProperties['@odata.type'] -like '*bitLocker*' -or
    $_.AdditionalProperties['bitLockerFixedDrivePolicy'] -or
    $_.AdditionalProperties['bitLockerSystemDrivePolicy'] -or
    $_.DisplayName -match 'bitlocker|encryption|encrypt'
}

if ($bitlockerConfigs) {
    Write-Host "  BitLocker configuration profile(s) found:" -ForegroundColor Green
    $bitlockerConfigs | Select-Object DisplayName, @{N='Type';E={$_.AdditionalProperties['@odata.type']}} |
                        Format-Table -AutoSize
} else {
    Write-Host "  No BitLocker configuration profiles found." -ForegroundColor Red
}

if (-not $bitlockerCompPolicies -and -not $bitlockerConfigs) {
    Write-Host "`nCRITICAL: BitLocker is not enforced via any Intune policy." -ForegroundColor Red
    Write-Host "Devices that are lost or stolen will have unencrypted data." -ForegroundColor Red
    Write-Host "`nTo fix:" -ForegroundColor Yellow
    Write-Host "  1. Intune > Devices > Compliance policies > Create > Windows 10+ > Require BitLocker" -ForegroundColor White
    Write-Host "  2. Intune > Devices > Configuration > Create > Windows > BitLocker (Endpoint Protection)" -ForegroundColor White
}

Disconnect-MgGraph"""
    },
}


@app.route("/investigate/<finding_id>", methods=["GET"])
def get_investigation_script(finding_id):
    """Return a ready-to-run PowerShell investigation script for a finding."""
    data = INVESTIGATION_SCRIPTS.get(finding_id)
    if not data:
        return jsonify({"error": f"No investigation script for {finding_id}"}), 404
    return jsonify({
        "findingId":   finding_id,
        "title":       data["title"],
        "description": data["description"],
        "script":      data["script"],
    })


@app.route("/findings-library", methods=["GET"])
def get_findings_library():
    return jsonify([{k: v for k, v in f.items() if k != "threshold"} for f in FINDINGS_LIBRARY])


@app.route("/")
def serve_index():
    """Serve the frontend HTML file - avoids file:// CORS issues."""
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html"}
    return "index.html not found", 404


if __name__ == "__main__":
    import webbrowser, threading

    print("=" * 60)
    print("  M365 Assessment Tool - Backend v2")
    print("  M365 Assessment Toolkit")
    print("=" * 60)
    print(f"  Auth modes:      Interactive Login + App Registration")
    print(f"  Scripts folder:  {SCRIPTS_DIR}")
    print(f"  Output folder:   {OUTPUT_DIR}")
    print(f"  Reports folder:  {REPORTS_DIR}")
    print(f"  Findings loaded: {len(FINDINGS_LIBRARY)}")
    print("=" * 60)
    print("  Opening tool at http://localhost:5000")
    print("  Keep this window open while using the tool.")
    print()

    # Open browser automatically after a short delay
    def open_browser():
        import time
        time.sleep(1.5)
        webbrowser.open("http://localhost:5000")

    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False)

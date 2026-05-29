<#
.SYNOPSIS  Get-SecurityMetrics.ps1 - M365 Assessment Tool
           Malcolm McDonald | IT Infrastructure Consultant
.DESCRIPTION
    Collects security metrics from Microsoft Graph including:
    - Secure Score
    - Security Defaults
    - Conditional Access (count + legacy auth block)
    - Over-permissioned OAuth apps
    - Defender alert policies
    - MFA fatigue protection (number matching)
    - Weak authentication methods (SMS/voice/email OTP)
    - User consent to apps policy
    Supports Interactive Login and App Registration auth.
    Outputs JSON to stdout. Exit 0 = success.
#>
param(
    [Parameter(Mandatory=$false)] [string]$AuthMethod     = "Interactive",
    [Parameter(Mandatory=$false)] [string]$TenantId       = "",
    [Parameter(Mandatory=$false)] [string]$ClientId       = "",
    [Parameter(Mandatory=$false)] [string]$ClientSecret   = "",
    [Parameter(Mandatory=$false)] [string]$CertThumbprint = "",
    [Parameter(Mandatory=$false)] [string]$GraphEndpoint  = "https://graph.microsoft.com",
    [Parameter(Mandatory=$false)] [string]$LoginEndpoint  = "https://login.microsoftonline.com",
    [Parameter(Mandatory=$false)] [string]$Environment    = "commercial"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"
$InformationPreference = "SilentlyContinue"

# High-privilege permissions that flag an app as over-permissioned
$HighPrivilegePerms = @(
    "Mail.ReadWrite", "Mail.ReadWrite.All",
    "Files.ReadWrite.All", "Directory.ReadWrite.All",
    "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "full_access_as_app", "Exchange.ManageAsApp",
    "Sites.FullControl.All", "MailboxSettings.ReadWrite",
    "Application.ReadWrite.All"
)

try {
    # ── Authenticate ──────────────────────────────────────────
    if ($AuthMethod -eq "AppReg") {
        # App Registration — client credentials via REST token
        $TokenBody = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = "$GraphEndpoint/.default"
        }
        $TokenResponse = Invoke-RestMethod -Uri "$LoginEndpoint/$TenantId/oauth2/v2.0/token" `
            -Method POST -Body $TokenBody -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction Stop
        $AccessToken = $TokenResponse.access_token
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $AccessToken -AsPlainText -Force) -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } elseif ($AuthMethod -eq "Certificate") {
        # Certificate auth — certificate must be installed in the local certificate store
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertThumbprint `
            -Environment $(if ($GraphEndpoint -match 'microsoft.us') { 'USGov' } else { 'Global' }) `
            -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } else {
        # Interactive auth — browser popup
        $Scopes = @(
            'Policy.Read.All',
            'SecurityEvents.Read.All',
            'Organization.Read.All',
            'Application.Read.All'
        )
        $ConnectArgs = @{ Scopes = $Scopes; NoWelcome = $true; WarningAction = 'SilentlyContinue' }
        if ($TenantId -ne "") { $ConnectArgs['TenantId'] = $TenantId }
        if ($GraphEndpoint -match 'microsoft.us') { $ConnectArgs['Environment'] = 'USGov' }
        Connect-MgGraph @ConnectArgs | Out-Null
    }

    # ── Secure Score ───────────────────────────────────────────
    $SecureScorePct = 0
    try {
        $ScoreData = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/secureScores?`$top=1"
        if ($ScoreData.value -and $ScoreData.value.Count -gt 0) {
            $Latest = $ScoreData.value[0]
            if ($Latest.maxScore -gt 0) {
                $SecureScorePct = [math]::Round(($Latest.currentScore / $Latest.maxScore) * 100, 1)
            }
        }
    } catch {}

    # ── Security Defaults ─────────────────────────────────────
    $SecurityDefaultsEnabled = $false
    try {
        $Defaults                = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy"
        $SecurityDefaultsEnabled = [bool]$Defaults.isEnabled
    } catch {}

    # ── Conditional Access ────────────────────────────────────
    $CAEnabledCount    = 0
    $LegacyAuthBlocked = $false
    try {
        $CAPolicies      = Get-MgIdentityConditionalAccessPolicy -All -WarningAction SilentlyContinue
        $EnabledPolicies = $CAPolicies | Where-Object { $_.State -eq "enabled" }
        $CAEnabledCount  = $EnabledPolicies.Count
        foreach ($Policy in $EnabledPolicies) {
            $ClientApps = $Policy.Conditions.ClientAppTypes
            if ($ClientApps -and ($ClientApps -contains "exchangeActiveSync" -or $ClientApps -contains "other")) {
                $Controls = $Policy.GrantControls.BuiltInControls
                if ($Controls -contains "block") { $LegacyAuthBlocked = $true; break }
            }
        }
    } catch {}

    # ── Over-Permissioned OAuth Apps ──────────────────────────
    $HighPrivAppCount = 0
    try {
        $SPData = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&`$select=id,displayName&`$top=999"
        foreach ($SP in $SPData.value) {
            try {
                $AppRoles    = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($SP.id)/appRoleAssignments"
                $FoundHighPriv = $false
                foreach ($Role in $AppRoles.value) {
                    if ($FoundHighPriv) { break }
                    try {
                        $ResourceSP = Invoke-MgGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($Role.resourceId)?`$select=appRoles"
                        $RoleDef = $ResourceSP.appRoles | Where-Object { $_.id -eq $Role.appRoleId }
                        if ($RoleDef -and ($HighPrivilegePerms -contains $RoleDef.value)) {
                            $HighPrivAppCount++
                            $FoundHighPriv = $true
                        }
                    } catch {}
                }
            } catch {}
        }
    } catch {}

    # ── Defender Alert Policies ───────────────────────────────
    $DefenderAlertPolicyCount = 0
    try {
        $AlertPolicies = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/security/alertPolicies" -ErrorAction SilentlyContinue
        if ($AlertPolicies -and $AlertPolicies.value) {
            $DefenderAlertPolicyCount = ($AlertPolicies.value | Where-Object { $_.isEnabled -eq $true }).Count
        }
    } catch {
        try {
            $Alerts = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2?`$top=1" -ErrorAction SilentlyContinue
            if ($Alerts -and $Alerts.value) { $DefenderAlertPolicyCount = 1 }
        } catch {}
    }

    # ── MFA Fatigue Protection (Number Matching) ──────────────
    # Checks if Authenticator app is configured to show number + location context
    $NumberMatchingEnabled = $false
    try {
        $AuthConfig = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator"
        $Features = $AuthConfig.featureSettings
        $NumberMatch = $Features.displayAppInformationRequiredState.state -eq "enabled"
        $LocationCtx = $Features.displayLocationInformationRequiredState.state -eq "enabled"
        $NumberMatchingEnabled = ($NumberMatch -and $LocationCtx)
    } catch {}

    # ── Weak Authentication Methods ───────────────────────────
    # Checks if SMS, voice call, or email OTP are enabled
    $WeakAuthMethodsEnabled = $false
    try {
        $WeakMethods = @("Sms", "Voice", "Email")
        foreach ($Method in $WeakMethods) {
            $MethodConfig = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$Method" `
                -ErrorAction SilentlyContinue
            if ($MethodConfig -and $MethodConfig.state -eq "enabled") {
                $WeakAuthMethodsEnabled = $true
                break
            }
        }
    } catch {}

    # ── User Consent to Apps ──────────────────────────────────
    # Checks if users can grant OAuth app permissions without admin approval
    $UserConsentUnrestricted = $false
    try {
        $AuthPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        $GrantPolicies = $AuthPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
        # If this contains the default low-risk policy, users can consent to apps themselves
        if ($GrantPolicies -and $GrantPolicies -contains "ManagePermissionGrantsForSelf.microsoft-user-default-low") {
            $UserConsentUnrestricted = $true
        }
    } catch {}

    # Microsoft Sentinel — check for Sentinel alert activity via Security API
    $SentinelConnected = $false
    try {
        $SecurityAlerts = Get-MgSecurityAlert -All -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $SentinelConnected = ($SecurityAlerts | Where-Object {
            $_.VendorInformation.Provider -match 'Sentinel|Azure Sentinel'
        }).Count -gt 0
    } catch {}

    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null

    # ── Output JSON ────────────────────────────────────────────
    $result = @{
        secure_score_percentage     = $SecureScorePct
        security_defaults_enabled   = $SecurityDefaultsEnabled
        ca_enabled_policy_count     = $CAEnabledCount
        legacy_auth_blocked         = $LegacyAuthBlocked
        high_privilege_app_count    = $HighPrivAppCount
        defender_alert_policy_count = $DefenderAlertPolicyCount
        mfa_number_matching_enabled = $NumberMatchingEnabled
        weak_auth_methods_enabled   = $WeakAuthMethodsEnabled
        user_consent_unrestricted   = $UserConsentUnrestricted
        sentinel_connected          = $SentinelConnected
    } | ConvertTo-Json -Compress

    [Console]::Out.WriteLine($result)
    exit 0

} catch {
    [Console]::Error.WriteLine("Get-SecurityMetrics failed: $_")
    exit 1
}

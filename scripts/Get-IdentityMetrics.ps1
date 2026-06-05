<#
.SYNOPSIS  Get-IdentityMetrics.ps1 - M365 Assessment Tool
           Malcolm McDonald | IT Infrastructure Consultant
.DESCRIPTION
    Collects identity metrics from Microsoft Graph.
    Supports Interactive Login, App Registration, and Certificate auth.
    Outputs JSON to stdout. Exit 0 = success.
.NOTES
    Graph permissions required (Application or Delegated):
      User.Read.All, Directory.Read.All, RoleManagement.Read.Directory,
      AuditLog.Read.All, Organization.Read.All
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

try {
    # Authenticate
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
        $Scopes = @('User.Read.All','Directory.Read.All','RoleManagement.Read.Directory',
                    'AuditLog.Read.All','Organization.Read.All','Policy.Read.All',
                    'IdentityRiskyUser.Read.All')
        $ConnectArgs = @{ Scopes = $Scopes; NoWelcome = $true; WarningAction = 'SilentlyContinue' }
        if ($TenantId -ne "") { $ConnectArgs['TenantId'] = $TenantId }
        if ($GraphEndpoint -match 'microsoft.us') { $ConnectArgs['Environment'] = 'USGov' }
        Connect-MgGraph @ConnectArgs | Out-Null
    }

    # ─── Entra ID Deep Findings — shared lookup tables ────────────────────────

    # High-privilege Graph application permission classification
    $HighPrivPermissions = @{
        'Directory.ReadWrite.All'                = 'Critical'
        'RoleManagement.ReadWrite.Directory'     = 'Critical'
        'User.ReadWrite.All'                     = 'Critical'
        'Group.ReadWrite.All'                    = 'Critical'
        'Application.ReadWrite.All'              = 'Critical'
        'Mail.ReadWrite'                         = 'Critical'
        'Mail.Send'                              = 'Critical'
        'Files.ReadWrite.All'                    = 'Critical'
        'Sites.FullControl.All'                  = 'Critical'
        'Sites.ReadWrite.All'                    = 'Critical'
        'UserAuthenticationMethod.ReadWrite.All' = 'Critical'
        'Policy.ReadWrite.ConditionalAccess'     = 'Critical'
        'Domain.ReadWrite.All'                   = 'Critical'
        'Mail.Read'                              = 'High'
        'Mail.ReadBasic.All'                     = 'High'
        'Files.Read.All'                         = 'High'
        'Directory.Read.All'                     = 'High'
        'RoleManagement.Read.Directory'          = 'High'
        'AuditLog.Read.All'                      = 'High'
        'IdentityRiskyUser.Read.All'             = 'High'
        'SecurityEvents.ReadWrite.All'           = 'High'
        'Organization.ReadWrite.All'             = 'High'
    }

    # Collect ObjectIds of principals that hold high-privilege directory roles
    $PrivSPIds = @{}
    $PrivRoleNames = @(
        'Global Administrator', 'Privileged Role Administrator',
        'Application Administrator', 'Cloud Application Administrator',
        'Exchange Administrator', 'SharePoint Administrator',
        'Security Administrator', 'Conditional Access Administrator',
        'User Administrator', 'Hybrid Identity Administrator'
    )
    try {
        # One bulk call instead of 10 filtered round-trips
        $AllDirRoles = Get-MgDirectoryRole -All -ErrorAction SilentlyContinue
        foreach ($role in ($AllDirRoles | Where-Object { $PrivRoleNames -contains $_.DisplayName })) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                if (-not $PrivSPIds.ContainsKey($m.Id)) { $PrivSPIds[$m.Id] = $role.DisplayName }
            }
        }
    } catch {}

    # Default values — overwritten by query blocks below; stay 0 on any error
    $HighPrivAppRegCount    = 0
    $ExpiredCredCount       = 0
    $ExpiringCred30dCount   = 0
    $ExpiringCred90dCount   = 0
    $NeverExpireCredCount   = 0
    $UnownedAppRegCount     = 0
    $MultitenantAppRegCount = 0
    $ImplicitGrantAppCount  = 0
    $PrivSPCount            = 0
    $PrivMICount            = 0

    # Users
    $AllUsers      = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,AssignedLicenses -Filter "accountEnabled eq true"
    $LicensedUsers = ($AllUsers | Where-Object { $_.AssignedLicenses.Count -gt 0 })
    $GuestUsers    = ($AllUsers | Where-Object { $_.UserType -eq "Guest" }).Count

    # MFA Registration
    $MFAEnabled = 0
    try {
        $AuthDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
        $MFAEnabled  = ($AuthDetails | Where-Object { $_.IsMfaRegistered -eq $true }).Count
        $MFABase     = $AuthDetails.Count
    } catch {
        $MFABase = $LicensedUsers.Count
        foreach ($User in $LicensedUsers) {
            try {
                $Methods = Get-MgUserAuthenticationMethod -UserId $User.Id
                $NonPwd  = $Methods | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' }
                if ($NonPwd.Count -gt 0) { $MFAEnabled++ }
            } catch {}
        }
    }
    $MFAPercentage = if ($MFABase -gt 0) { [math]::Round(($MFAEnabled / $MFABase) * 100, 1) } else { 0 }

    # Global Admin Count
    $GlobalAdminCount = 0
    try {
        $GARole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
        if ($GARole) {
            $GlobalAdminCount = (Get-MgDirectoryRoleMember -DirectoryRoleId $GARole.Id -All).Count
        }
    } catch {}

    # PIM
    $PIMEnabled = $false
    try {
        $Eligible   = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $PIMEnabled = ($null -ne $Eligible -and $Eligible.Count -gt 0)
    } catch {}

    # Licences
    $UnassignedPct = 0
    try {
        $SKUs           = Get-MgSubscribedSku
        $TotalPurchased = ($SKUs | Measure-Object -Property @{E={$_.PrepaidUnits.Enabled}} -Sum).Sum
        $TotalConsumed  = ($SKUs | Measure-Object -Property ConsumedUnits -Sum).Sum
        if ($TotalPurchased -gt 0) {
            $UnassignedPct = [math]::Round((($TotalPurchased - $TotalConsumed) / $TotalPurchased) * 100, 1)
        }
    } catch {}

    # Risky Users (Identity Protection)
    $RiskyUsersCount = 0
    try {
        $RiskyUsers      = Get-MgRiskyUser -All -Filter "riskState ne 'remediated' and riskState ne 'dismissed'" `
                           -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $RiskyUsersCount = ($RiskyUsers | Where-Object { $_.RiskLevel -in @('high','medium') }).Count
    } catch {}

    # Emergency Access Account Detection
    # Heuristic: a Global Admin excluded from ALL enabled CA policies is likely a break-glass account
    $EmergencyAccessExists = $false
    try {
        $CAPolicies    = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
                         Where-Object { $_.State -eq 'enabled' }
        $GARole        = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction SilentlyContinue
        $GAMemberIds   = @{}
        if ($GARole) {
            Get-MgDirectoryRoleMember -DirectoryRoleId $GARole.Id -All -ErrorAction SilentlyContinue |
            ForEach-Object { $GAMemberIds[$_.Id] = $true }
        }
        if ($CAPolicies.Count -gt 0 -and $GAMemberIds.Count -gt 0) {
            $ExclusionCount = @{}
            foreach ($p in $CAPolicies) {
                foreach ($uid in $p.Conditions.Users.ExcludeUsers) {
                    if ($ExclusionCount.ContainsKey($uid)) {
                        $ExclusionCount[$uid]++
                    } else {
                        $ExclusionCount[$uid] = 1
                    }
                }
            }
            foreach ($uid in $GAMemberIds.Keys) {
                $uidCount = if ($ExclusionCount.ContainsKey($uid)) { $ExclusionCount[$uid] } else { 0 }
                if ($uidCount -eq $CAPolicies.Count) {
                    $EmergencyAccessExists = $true
                    break
                }
            }
        }
    } catch {}

    # ─── US1: App Registration Risk Review ──────────────────────────────────
    try {
        $Now  = Get-Date

        # Get Microsoft Graph service principal and build AppRoleId → permission-name map
        $GraphSP      = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" `
                        -ErrorAction SilentlyContinue
        $GraphRoleMap = @{}
        if ($GraphSP) {
            foreach ($ar in $GraphSP.AppRoles) { $GraphRoleMap[$ar.Id] = $ar.Value }

            # One call retrieves all app role assignments granted to Graph — no N+1
            $AllGraphAssignments = Get-MgServicePrincipalAppRoleAssignedTo `
                                   -ServicePrincipalId $GraphSP.Id -All -ErrorAction SilentlyContinue
            $HighPrivPrincipalIds = @{}
            foreach ($a in $AllGraphAssignments) {
                $pName = $GraphRoleMap[$a.AppRoleId]
                if ($pName -and $HighPrivPermissions.ContainsKey($pName)) {
                    $HighPrivPrincipalIds[$a.PrincipalId] = $true
                }
            }
            $HighPrivAppRegCount = $HighPrivPrincipalIds.Count
        }

        # Get all app registrations — credential health, implicit grant, multi-tenant
        $AllApps     = Get-MgApplication -All `
                       -Property Id,AppId,DisplayName,PasswordCredentials,KeyCredentials,Web,SignInAudience `
                       -ErrorAction SilentlyContinue
        $RiskyAppIds = [System.Collections.Generic.List[string]]::new()

        foreach ($App in $AllApps) {
            $IsRisky = $false

            # Credential checks (password secrets + certificates)
            $AllCreds = @($App.PasswordCredentials) + @($App.KeyCredentials)
            foreach ($Cred in $AllCreds) {
                if ($null -eq $Cred) { continue }
                if ($null -eq $Cred.EndDateTime) {
                    $NeverExpireCredCount++; $IsRisky = $true
                } elseif ($Cred.EndDateTime -lt $Now) {
                    $ExpiredCredCount++; $IsRisky = $true
                } elseif ($Cred.EndDateTime -lt $Now.AddDays(30)) {
                    $ExpiringCred30dCount++; $IsRisky = $true
                } elseif ($Cred.EndDateTime -lt $Now.AddDays(90)) {
                    $ExpiringCred90dCount++; $IsRisky = $true
                }
            }

            # Implicit grant flow check
            if ($App.Web -and $App.Web.ImplicitGrantSettings) {
                if ($App.Web.ImplicitGrantSettings.EnableIdTokenIssuance -eq $true -or
                    $App.Web.ImplicitGrantSettings.EnableAccessTokenIssuance -eq $true) {
                    $ImplicitGrantAppCount++; $IsRisky = $true
                }
            }

            # Multi-tenant check
            if ($App.SignInAudience -and $App.SignInAudience -ne 'AzureADMyOrg') {
                $MultitenantAppRegCount++; $IsRisky = $true
            }

            if ($IsRisky) { $RiskyAppIds.Add($App.Id) }
        }

        # Owner check — capped at 25 already-risky apps to avoid N×API-call blowout
        foreach ($AppId in ($RiskyAppIds | Select-Object -First 25)) {
            try {
                $Owners = Get-MgApplicationOwner -ApplicationId $AppId -ErrorAction SilentlyContinue
                if ($null -eq $Owners -or $Owners.Count -eq 0) { $UnownedAppRegCount++ }
            } catch {}
        }
    } catch {}

    # ─── US2 + US3: Privileged SP / Managed Identity check ──────────────────
    # $PrivSPIds already has the answer — look up only those IDs rather than
    # enumerating every service principal in the tenant.
    try {
        foreach ($spId in $PrivSPIds.Keys) {
            try {
                $sp = Get-MgServicePrincipal -ServicePrincipalId $spId `
                      -Property ServicePrincipalType -ErrorAction SilentlyContinue
                if ($null -eq $sp) { continue }
                switch ($sp.ServicePrincipalType) {
                    'Application'     { $PrivSPCount++ }
                    'ManagedIdentity' { $PrivMICount++ }
                }
            } catch {}
        }
    } catch {}

    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null

    # Output JSON - write directly to stdout
    $result = @{
        mfa_percentage                = $MFAPercentage
        global_admin_count            = $GlobalAdminCount
        pim_enabled                   = $PIMEnabled
        guest_user_count              = $GuestUsers
        unassigned_licence_percentage = $UnassignedPct
        risky_users_count             = $RiskyUsersCount
        emergency_access_exists       = $EmergencyAccessExists
        high_priv_app_reg_count       = $HighPrivAppRegCount
        expired_cred_count            = $ExpiredCredCount
        expiring_cred_30d_count       = $ExpiringCred30dCount
        expiring_cred_90d_count       = $ExpiringCred90dCount
        never_expire_cred_count       = $NeverExpireCredCount
        unowned_app_reg_count         = $UnownedAppRegCount
        multitenant_app_reg_count     = $MultitenantAppRegCount
        implicit_grant_app_count      = $ImplicitGrantAppCount
        priv_service_principal_count  = $PrivSPCount
        priv_managed_identity_count   = $PrivMICount
    } | ConvertTo-Json -Compress

    [Console]::Out.WriteLine($result)
    exit 0

} catch {
    [Console]::Error.WriteLine("Get-IdentityMetrics failed: $_")
    exit 1
}

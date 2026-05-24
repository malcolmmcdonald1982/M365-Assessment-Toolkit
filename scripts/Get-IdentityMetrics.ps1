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
    } | ConvertTo-Json -Compress

    [Console]::Out.WriteLine($result)
    exit 0

} catch {
    [Console]::Error.WriteLine("Get-IdentityMetrics failed: $_")
    exit 1
}

<#
.SYNOPSIS  Get-IdentityMetrics.ps1 - M365 Assessment Tool
           Malcolm McDonald | IT Infrastructure Consultant
.DESCRIPTION
    Collects identity metrics from Microsoft Graph.
    Supports Interactive Login and App Registration auth.
    Outputs JSON to stdout. Exit 0 = success.
.NOTES
    Graph permissions required (Application or Delegated):
      User.Read.All, Directory.Read.All, RoleManagement.Read.Directory,
      AuditLog.Read.All, Organization.Read.All
#>
param(
    [Parameter(Mandatory=$false)] [string]$AuthMethod   = "Interactive",
    [Parameter(Mandatory=$false)] [string]$TenantId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientSecret = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"
$InformationPreference = "SilentlyContinue"

try {
    # Authenticate
    if ($AuthMethod -eq "AppReg") {
        # Get token via REST - works with any module version, no Az.Accounts needed
        $TokenBody = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = "https://graph.microsoft.com/.default"
        }
        $TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -Method POST -Body $TokenBody -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction Stop
        $AccessToken = $TokenResponse.access_token
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $AccessToken -AsPlainText -Force) -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } else {
        $Scopes = @('User.Read.All','Directory.Read.All','RoleManagement.Read.Directory',
                    'AuditLog.Read.All','Organization.Read.All','Policy.Read.All')
        if ($TenantId -ne "") {
            Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        } else {
            Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
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

    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null

    # Output JSON - write directly to stdout
    $result = @{
        mfa_percentage                = $MFAPercentage
        global_admin_count            = $GlobalAdminCount
        pim_enabled                   = $PIMEnabled
        guest_user_count              = $GuestUsers
        unassigned_licence_percentage = $UnassignedPct
    } | ConvertTo-Json -Compress

    [Console]::Out.WriteLine($result)
    exit 0

} catch {
    [Console]::Error.WriteLine("Get-IdentityMetrics failed: $_")
    exit 1
}

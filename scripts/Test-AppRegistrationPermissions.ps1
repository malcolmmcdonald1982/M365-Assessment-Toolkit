<#
.SYNOPSIS  Test-AppRegistrationPermissions.ps1
           Malcolm McDonald - IT Infrastructure Consultant
.DESCRIPTION
    Validates that an App Registration has all required permissions
    for the M365 Assessment Toolkit before running the assessment.
    Tests each module's required permissions and reports exactly
    what is present, missing, and whether admin consent is granted.
    Outputs JSON: { success, modules: { identity, security, intune }, missing, allGranted }
#>
param(
    [Parameter(Mandatory=$true)]  [string]$TenantId     = "",
    [Parameter(Mandatory=$true)]  [string]$ClientId     = "",
    [Parameter(Mandatory=$true)]  [string]$ClientSecret = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"

# Required permissions per module
$RequiredPermissions = @{
    "Identity & MFA" = @(
        "User.Read.All",
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "UserAuthenticationMethod.Read.All",
        "Reports.Read.All"
    )
    "Security & CA" = @(
        "Policy.Read.All",
        "SecurityEvents.Read.All",
        "Organization.Read.All",
        "Application.Read.All"
    )
    "Intune / Devices" = @(
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All"
    )
}

# Permissions that require interactive login (cannot use App Reg)
$InteractiveOnly = @{
    "Exchange Online" = "Connect-ExchangeOnline does not support app-only auth via PS module"
    "Teams"           = "Connect-MicrosoftTeams does not support app-only auth via PS module"
    "SharePoint"      = "Connect-SPOService does not support app-only auth via PS module"
}

try {
    # Connect with App Registration
    $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
    $Credential   = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $Credential -NoWelcome -WarningAction SilentlyContinue | Out-Null

    # Get the service principal for this app
    $SP = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
    if (-not $SP) {
        Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
        @{ success = $false; error = "App Registration not found in this tenant. Ensure the app is registered in tenant: $TenantId" } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }
        exit 0
    }

    # Get all app role assignments for this service principal
    $AppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -All -ErrorAction SilentlyContinue

    # Get all service principals to resolve permission names
    $GrantedPermissions = @()
    foreach ($Role in $AppRoles) {
        try {
            $ResourceSP = Get-MgServicePrincipal -ServicePrincipalId $Role.ResourceId -ErrorAction SilentlyContinue
            if ($ResourceSP) {
                $RoleDef = $ResourceSP.AppRoles | Where-Object { $_.Id -eq $Role.AppRoleId }
                if ($RoleDef) {
                    $GrantedPermissions += $RoleDef.Value
                }
            }
        } catch {}
    }

    # Check each module
    $ModuleResults = @{}
    $AllMissing    = @()
    $AllGranted    = $true

    foreach ($Module in $RequiredPermissions.Keys) {
        $Required = $RequiredPermissions[$Module]
        $Present  = @()
        $Missing  = @()

        foreach ($Perm in $Required) {
            if ($GrantedPermissions -contains $Perm) {
                $Present += $Perm
            } else {
                $Missing += $Perm
                $AllMissing += $Perm
                $AllGranted = $false
            }
        }

        $ModuleResults[$Module] = @{
            status   = if ($Missing.Count -eq 0) { "ok" } else { "missing" }
            present  = $Present
            missing  = $Missing
            authMode = "AppRegistration"
        }
    }

    # Add interactive-only modules
    foreach ($Module in $InteractiveOnly.Keys) {
        $ModuleResults[$Module] = @{
            status   = "interactive"
            present  = @()
            missing  = @()
            authMode = "Interactive"
            note     = $InteractiveOnly[$Module]
        }
    }

    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null

    # Build fix instructions for missing permissions
    $FixInstructions = @()
    if ($AllMissing.Count -gt 0) {
        $FixInstructions += "Go to Entra ID > App registrations > $ClientId > API permissions"
        $FixInstructions += "Click Add a permission > Microsoft Graph > Application permissions"
        foreach ($Perm in $AllMissing) {
            $FixInstructions += "Add: $Perm"
        }
        $FixInstructions += "Click Grant admin consent"
    }

    @{
        success          = $true
        appId            = $ClientId
        tenantId         = $TenantId
        allGranted       = $AllGranted
        grantedCount     = $GrantedPermissions.Count
        modules          = $ModuleResults
        missingAll       = $AllMissing
        fixInstructions  = $FixInstructions
        grantedPerms     = $GrantedPermissions
    } | ConvertTo-Json -Depth 10 -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }
    exit 0

} catch {
    [Console]::Error.WriteLine("Test-AppRegistrationPermissions failed: $_")
    exit 1
}

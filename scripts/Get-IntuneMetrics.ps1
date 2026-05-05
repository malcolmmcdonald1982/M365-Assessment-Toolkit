<#
.SYNOPSIS  Get-IntuneMetrics.ps1 - M365 Assessment Tool
           Malcolm McDonald | IT Infrastructure Consultant
.DESCRIPTION
    Collects Microsoft Intune device compliance and policy metrics.
    Supports Interactive Login and App Registration auth.
    Outputs JSON to stdout. Exit 0 = success.
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
        $Scopes = @('DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All')
        if ($TenantId -ne "") {
            Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        } else {
            Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
    }

    # Device Compliance
    $CompliancePct = 0
    try {
        $Devices   = Get-MgDeviceManagementManagedDevice -All -Property ComplianceState,DeviceName -WarningAction SilentlyContinue
        $Total     = $Devices.Count
        $Compliant = ($Devices | Where-Object { $_.ComplianceState -eq "compliant" }).Count
        $CompliancePct = if ($Total -gt 0) { [math]::Round(($Compliant / $Total) * 100, 1) } else { 0 }
    } catch {}

    # Compliance Policies
    $CompliancePolicyCount = 0
    try {
        $Policies              = Get-MgDeviceManagementDeviceCompliancePolicy -All -WarningAction SilentlyContinue
        $CompliancePolicyCount = $Policies.Count
    } catch {}

    # Config Policies
    $ConfigPolicyCount = 0
    try {
        $ConfigPolicies    = Get-MgDeviceManagementDeviceConfiguration -All -WarningAction SilentlyContinue
        $ConfigPolicyCount = $ConfigPolicies.Count
    } catch {}

    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null

    $result = @{
        intune_compliance_percentage   = $CompliancePct
        intune_compliance_policy_count = $CompliancePolicyCount
        intune_config_policy_count     = $ConfigPolicyCount
    } | ConvertTo-Json -Compress

    [Console]::Out.WriteLine($result)
    exit 0

} catch {
    [Console]::Error.WriteLine("Get-IntuneMetrics failed: $_")
    exit 1
}

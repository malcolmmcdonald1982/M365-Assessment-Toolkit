<#
.SYNOPSIS  Get-IntuneMetrics.ps1 - M365 Assessment Tool
           Malcolm McDonald | IT Infrastructure Consultant
.DESCRIPTION
    Collects Microsoft Intune device compliance and policy metrics.
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
        $Scopes = @('DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All')
        $ConnectArgs = @{ Scopes = $Scopes; NoWelcome = $true; WarningAction = 'SilentlyContinue' }
        if ($TenantId -ne "") { $ConnectArgs['TenantId'] = $TenantId }
        if ($GraphEndpoint -match 'microsoft.us') { $ConnectArgs['Environment'] = 'USGov' }
        Connect-MgGraph @ConnectArgs | Out-Null
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

    # Windows Update Rings
    $UpdateRingCount = 0
    try {
        $UpdateRings     = Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                           Where-Object { $_.AdditionalProperties['@odata.type'] -like '*windowsUpdateForBusiness*' }
        $UpdateRingCount = $UpdateRings.Count
    } catch {}

    # BitLocker Enforced — check compliance policies and config profiles
    $BitLockerEnforced = $false
    try {
        $CompPoliciesAll = Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $BitLockerComp   = $CompPoliciesAll | Where-Object {
            $_.AdditionalProperties['storageRequireDeviceEncryption'] -eq $true -or
            $_.AdditionalProperties['bitLockerEnabled'] -eq $true
        }
        if (-not $BitLockerComp) {
            $ConfigProfilesAll = Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            $BitLockerConfig   = $ConfigProfilesAll | Where-Object {
                $_.AdditionalProperties['@odata.type'] -like '*bitLocker*' -or
                $_.AdditionalProperties['bitLockerFixedDrivePolicy'] -or
                $_.AdditionalProperties['bitLockerSystemDrivePolicy'] -or
                $_.DisplayName -match 'bitlocker|encryption'
            }
            $BitLockerEnforced = $BitLockerConfig.Count -gt 0
        } else {
            $BitLockerEnforced = $true
        }
    } catch {}

    # Mobile Device Compliance Policy (iOS / Android)
    $MobileCompliancePolicyExists = $false
    try {
        $MobilePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All -WarningAction SilentlyContinue |
            Where-Object {
                $_.AdditionalProperties['@odata.type'] -like '*ios*' -or
                $_.AdditionalProperties['@odata.type'] -like '*android*' -or
                $_.AdditionalProperties['@odata.type'] -like '*Android*'
            }
        $MobileCompliancePolicyExists = ($MobilePolicies.Count -gt 0)
    } catch {}

    # Defender for Endpoint — Mobile Threat Defence connector
    $DefenderMdeIntegrationEnabled = $false
    try {
        $MtdConnectors = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/deviceManagement/mobileThreatDefenseConnectors" `
            -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($MtdConnectors -and $MtdConnectors.value) {
            $DefenderConnector = $MtdConnectors.value | Where-Object {
                $_.id -match 'microsoftdefender|windowsdefenderatp' -or
                ($_.AdditionalProperties -and
                 $_.AdditionalProperties['@odata.type'] -match 'defender')
            }
            if (-not $DefenderConnector) {
                # Fallback: any connector with an active platform enabled
                $DefenderConnector = $MtdConnectors.value
            }
            $DefenderMdeIntegrationEnabled = ($DefenderConnector | Where-Object {
                $_.androidEnabled -eq $true -or
                $_.iosEnabled -eq $true -or
                $_.windowsEnabled -eq $true
            }).Count -gt 0
        }
    } catch {}

    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null

    $result = @{
        intune_compliance_percentage      = $CompliancePct
        intune_compliance_policy_count    = $CompliancePolicyCount
        intune_config_policy_count        = $ConfigPolicyCount
        update_ring_count                 = $UpdateRingCount
        bitlocker_enforced                = $BitLockerEnforced
        mobile_compliance_policy_exists   = $MobileCompliancePolicyExists
        defender_mde_integration_enabled  = $DefenderMdeIntegrationEnabled
    } | ConvertTo-Json -Compress

    [Console]::Out.WriteLine($result)
    exit 0

} catch {
    [Console]::Error.WriteLine("Get-IntuneMetrics failed: $_")
    exit 1
}

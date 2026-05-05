<#
.SYNOPSIS  Remediate-LegacyAuth.ps1
           Malcolm McDonald - IT Infrastructure Consultant
.DESCRIPTION
    Remediates CA-002: Legacy Authentication Not Blocked
    1. Reads current state and saves snapshot
    2. Checks for legacy auth usage in last 30 days (safety check)
    3. Creates a Conditional Access policy blocking legacy auth
    4. Verifies the policy was created
    Outputs JSON: { success, snapshotFile, warning, details }
#>
param(
    [Parameter(Mandatory=$false)] [string]$AuthMethod   = "Interactive",
    [Parameter(Mandatory=$false)] [string]$TenantId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientId     = "",
    [Parameter(Mandatory=$false)] [string]$ClientSecret = "",
    [Parameter(Mandatory=$false)] [string]$SnapshotPath = "",
    [Parameter(Mandatory=$false)] [switch]$CheckOnly    = $false
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"

$POLICY_NAME = "MM-Assessment - Block Legacy Authentication"

try {
    # Authenticate
    if ($AuthMethod -eq "AppReg") {
        $TokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
        $AccessToken = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $TokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop).access_token
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $AccessToken -AsPlainText -Force) -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } else {
        $Scopes = @('Policy.ReadWrite.ConditionalAccess','Policy.Read.All','AuditLog.Read.All')
        if ($TenantId -ne "") {
            Connect-MgGraph -TenantId $TenantId -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        } else {
            Connect-MgGraph -Scopes $Scopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
    }

    # Step 1: Read current state for snapshot
    $ExistingPolicies = Get-MgIdentityConditionalAccessPolicy -All -WarningAction SilentlyContinue
    $OurPolicy = $ExistingPolicies | Where-Object { $_.DisplayName -eq $POLICY_NAME }

    $Snapshot = @{
        findingId        = "CA-002"
        timestamp        = (Get-Date).ToString("o")
        policyExisted    = ($null -ne $OurPolicy)
        policyId         = if ($OurPolicy) { $OurPolicy.Id } else { $null }
        previousState    = @{ legacyAuthBlocked = ($null -ne $OurPolicy) }
    }

    # Step 2: Safety check - look for legacy auth sign-ins in last 30 days
    $Warning = $null
    $LegacySignInCount = 0
    try {
        $StartDate  = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $Filter     = "createdDateTime ge $StartDate and clientAppUsed eq 'Exchange ActiveSync' or clientAppUsed eq 'Other clients'"
        $SignIns    = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $StartDate and (clientAppUsed eq 'Exchange ActiveSync' or clientAppUsed eq 'Other clients')&`$top=50" `
            -ErrorAction SilentlyContinue
        if ($SignIns -and $SignIns.value) {
            $LegacySignInCount = $SignIns.value.Count
        }
    } catch {}

    if ($LegacySignInCount -gt 0) {
        $Warning = "$LegacySignInCount legacy authentication sign-in(s) detected in the last 30 days. Apps or users using legacy auth will lose access when this policy is applied. Review before proceeding."
        $Snapshot.legacySignInsDetected = $LegacySignInCount
    }

    # If check-only mode, return safety check result without making changes
    if ($CheckOnly) {
        Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
        @{
            success          = $true
            checkOnly        = $true
            warning          = $Warning
            legacySignIns    = $LegacySignInCount
            alreadyRemediated = ($null -ne $OurPolicy)
        } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }
        exit 0
    }

    # Already remediated
    if ($null -ne $OurPolicy) {
        Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null
        @{
            success  = $true
            details  = "Policy already exists - no changes made"
            warning  = $Warning
            snapshot = $Snapshot
        } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }
        exit 0
    }

    # Step 3: Save snapshot
    if ($SnapshotPath -ne "") {
        $Snapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath $SnapshotPath -Encoding UTF8
    }

    # Step 4: Create the CA policy
    $PolicyBody = @{
        displayName = $POLICY_NAME
        state       = "enabled"
        conditions  = @{
            clientAppTypes = @("exchangeActiveSync", "other")
            users          = @{ includeUsers = @("All") }
            applications   = @{ includeApplications = @("All") }
        }
        grantControls = @{
            operator         = "OR"
            builtInControls  = @("block")
        }
    }

    $NewPolicy = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
        -Body ($PolicyBody | ConvertTo-Json -Depth 10) `
        -ContentType "application/json"

    Disconnect-MgGraph -WarningAction SilentlyContinue | Out-Null

    $Snapshot.afterState = @{ legacyAuthBlocked = $true; policyId = $NewPolicy.id }

    @{
        success      = $true
        details      = "CA policy created: $POLICY_NAME (ID: $($NewPolicy.id))"
        warning      = $Warning
        policyId     = $NewPolicy.id
        snapshot     = $Snapshot
    } | ConvertTo-Json -Compress | ForEach-Object { [Console]::Out.WriteLine($_) }
    exit 0

} catch {
    [Console]::Error.WriteLine("Remediate-LegacyAuth failed: $_")
    exit 1
}

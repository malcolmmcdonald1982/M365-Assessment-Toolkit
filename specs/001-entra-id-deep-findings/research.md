# Research: Entra ID Deep Findings

**Feature**: 001-entra-id-deep-findings
**Date**: 2026-05-29

## 1. Graph API Endpoints & PowerShell Cmdlets

### Decision
Use Microsoft.Graph PowerShell SDK v7.x cmdlets (already installed) with the `-All`
flag for automatic pagination. No direct `Invoke-RestMethod` calls needed.

| Entity | Cmdlet | Key Properties |
|--------|--------|----------------|
| App registrations | `Get-MgApplication -All` | `Id`, `AppId`, `DisplayName`, `PasswordCredentials`, `KeyCredentials`, `Owners`, `SignInAudience`, `Web` |
| Service principals (all) | `Get-MgServicePrincipal -All` | `Id`, `AppId`, `DisplayName`, `ServicePrincipalType` |
| Managed identities | `Get-MgServicePrincipal -Filter "servicePrincipalType eq 'ManagedIdentity'" -All` | Same as above |
| Directory roles | `Get-MgDirectoryRole -All` | `Id`, `DisplayName` |
| Role members | `Get-MgDirectoryRoleMember -DirectoryRoleId $id -All` | `Id` (ObjectId of member) |
| App role assignments (SP) | `Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $id -All` | `AppRoleId`, `ResourceId` |
| Graph SP (for permission lookup) | `Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"` | `AppRoles` |

### Rationale
Using SDK cmdlets instead of raw REST calls avoids manual token management, provides
automatic retry, and keeps the code consistent with the existing scripts.

### Alternative Considered
Direct `Invoke-RestMethod` against `https://graph.microsoft.com/v1.0/applications` —
rejected because the existing scripts all use SDK cmdlets and it would require manual
bearer token forwarding.

---

## 2. High-Privilege Graph Application Permissions

### Decision
The following application permissions (app roles, not delegated) are classified as
High or Critical risk when granted to an app registration:

**Critical** (write access to identity, auth, or all data):
- `Directory.ReadWrite.All`
- `RoleManagement.ReadWrite.Directory`
- `User.ReadWrite.All`
- `Group.ReadWrite.All`
- `Application.ReadWrite.All`
- `Mail.ReadWrite`
- `Mail.Send`
- `Files.ReadWrite.All`
- `Sites.FullControl.All`
- `Sites.ReadWrite.All`
- `UserAuthenticationMethod.ReadWrite.All`
- `Policy.ReadWrite.ConditionalAccess`
- `Domain.ReadWrite.All`

**High** (broad read access that enables reconnaissance or exfiltration):
- `Mail.Read`
- `Mail.ReadBasic.All`
- `Files.Read.All`
- `Directory.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`
- `IdentityRiskyUser.Read.All`
- `SecurityEvents.ReadWrite.All`
- `Organization.ReadWrite.All`

### Rationale
Critical permissions allow an attacker with control of the app registration credentials
to make destructive writes. High permissions allow persistent read-access for
exfiltration or reconnaissance. This list is drawn from Microsoft's own sensitivity
classifications and known attack tooling that targets these specific permissions.

### Implementation Note
Store as a hardcoded PowerShell hashtable (`$HighPrivPermissions`) with value "Critical"
or "High" per permission. Check against the `Value` property of each `AppRole` returned
by the Graph service principal's `AppRoles` collection.

### Alternative Considered
Dynamic fetch from Microsoft's Graph permission metadata API — rejected for this version
as it adds network complexity and latency. A static list is auditable and version-controlled.

---

## 3. Never-Expiring Credentials

### Decision
A credential (client secret or certificate) is considered "never expiring" when its
`endDateTime` property is `$null`. This is possible in tenants where secrets were created
via the API without specifying an expiry, or in very old app registrations.

Detection:
```powershell
$cred.EndDateTime -eq $null
```

### Rationale
Microsoft's portal enforces maximum 2-year expiry for new secrets, but the Graph API
allows `null` endDateTime. Legacy app registrations (especially those created via older
AAD module or Azure classic portal) commonly have null expiry dates.

---

## 4. Implicit Grant Flow Detection

### Decision
Detect via the `Web.ImplicitGrantSettings` property on the `Application` object:

```powershell
$app.Web.ImplicitGrantSettings.EnableIdTokenIssuance -eq $true
# OR
$app.Web.ImplicitGrantSettings.EnableAccessTokenIssuance -eq $true
```

The `Get-MgApplication` cmdlet returns the `Web` navigation property automatically when
`-Property Web` is included or when the full object is returned with `-All`.

### Rationale
Implicit grant enables tokens to be returned directly in browser redirect URLs (URL
fragment), making them susceptible to token leakage via browser history, referrer headers,
and cross-site scripting. Microsoft recommends disabling implicit grant for all apps.

---

## 5. Managed Identities vs Regular Service Principals

### Decision
Filter service principals by type:

```powershell
# Managed identities only
Get-MgServicePrincipal -Filter "servicePrincipalType eq 'ManagedIdentity'" -All

# Application-type service principals (regular apps)
Get-MgServicePrincipal -Filter "servicePrincipalType eq 'Application'" -All
```

`servicePrincipalType` values: `Application`, `ManagedIdentity`, `Legacy`, `SocialIdp`

### Rationale
The `servicePrincipalType` property unambiguously differentiates managed identities from
application service principals. No heuristics needed.

---

## 6. Efficient Directory Role Lookups

### Decision
Enumerate all high-privilege directory roles once, collect member object IDs into a
hashtable keyed by ObjectId, then check each service principal/managed identity against
the hashtable. Avoids O(n×m) API calls.

```powershell
$HighPrivRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "User Administrator",
    "Hybrid Identity Administrator"
)

$PrivSPIds = @{}  # ObjectId -> RoleName

foreach ($roleName in $HighPrivRoles) {
    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
    if ($role) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
        foreach ($m in $members) {
            if (-not $PrivSPIds.ContainsKey($m.Id)) {
                $PrivSPIds[$m.Id] = $roleName
            }
        }
    }
}
```

### Rationale
Fetching role members by role (10 roles × 1 API call each = max 10 calls) is far more
efficient than checking each service principal's role assignments individually
(potentially 100s of SP × N calls each).

---

## 7. App Registration Owner Detection

### Decision
Use `Get-MgApplicationOwner -ApplicationId $app.Id` to retrieve owners. An app
with zero owners triggers the unowned finding.

Note: The `Owners` property is NOT returned by `Get-MgApplication -All` — a separate
call per app is required. To avoid performance issues, batch owner lookups only after
the initial app list is retrieved.

### Performance Consideration
For 500 app registrations, 500 separate owner API calls could add significant latency.
Mitigate by using a try/catch with `-ErrorAction SilentlyContinue` and applying a
maximum cap: if the tenant has more than 200 app registrations, only check ownership
for apps that already have other risk indicators (high privilege, expiring creds, etc.).
Document this behaviour in quickstart.md.

---

## 8. Performance Estimate

For a tenant with 500 app registrations and 100 service principals:

| Query | Est. Time |
|-------|-----------|
| `Get-MgApplication -All` (500 apps) | ~5–15s |
| Per-app credential check (no extra calls) | ~0s (data in app object) |
| Per-app owner check (500 calls) | ~30–90s |
| `Get-MgServicePrincipal` (ManagedIdentity filter) | ~3–8s |
| Directory role lookups (10 roles × members) | ~5–15s |
| **Total new queries estimate** | **~45–130s** |
| Existing identity queries | ~30–60s |
| **Combined estimate** | **~75–190s** |

Well within the 300-second timeout. The owner-check batching approach (only checking
ownership for already-flagged apps) reduces the worst-case estimate further.

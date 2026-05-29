# Feature Specification: Entra ID Deep Findings

**Feature Branch**: `001-entra-id-deep-findings`

**Created**: 2026-05-29

**Status**: Draft

**Input**: User description: "Add deeper Entra ID security findings covering app registrations, managed identities and service principals"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - App Registration Risk Review (Priority: P1)

An IT consultant runs an assessment against a client tenant and sees a dedicated set of
findings covering risky app registrations. They can identify which apps hold high-privilege
permissions, which have credentials about to expire or already expired, and which lack an
owner — all without manually querying Entra ID.

**Why this priority**: App registrations are a common initial-access vector. High-privilege
apps with unmanaged credentials represent immediate, concrete risk that clients can act on
quickly. This delivers the most direct remediation value.

**Independent Test**: Can be fully tested by running the Identity module against a tenant
with at least one app registration and verifying that finding cards appear in the dashboard
with severity, description, and investigation script populated.

**Acceptance Scenarios**:

1. **Given** a tenant with an app registration holding `RoleManagement.Read.Directory`
   or higher Graph application permissions, **When** the Identity module assessment runs,
   **Then** a finding appears categorised as High or Critical with the app registration
   name, permission list, and remediation guidance.

2. **Given** a tenant with an app registration whose client secret or certificate expires
   within 30 days, **When** the Identity module assessment runs, **Then** a finding
   appears showing the app name, credential type, and days until expiry.

3. **Given** a tenant with an app registration whose credentials are set to never expire,
   **When** the Identity module assessment runs, **Then** a finding appears identifying
   the app and explaining the risk.

4. **Given** a tenant with an app registration that has no owner assigned, **When** the
   Identity module assessment runs, **Then** a finding appears identifying the unowned app.

5. **Given** a tenant with no risky app registrations, **When** the assessment runs,
   **Then** all app registration findings show as Passed with no false positives.

---

### User Story 2 - Service Principal Privilege Review (Priority: P2)

A security assessor can identify service principals (enterprise applications and
first-party service accounts) that have been assigned high-privilege directory roles
or broad Graph permissions, understanding the attack path implication of each.

**Why this priority**: Service principals assigned to privileged roles are a persistence
and lateral-movement risk that is frequently missed in manual reviews. This directly
extends the attack simulation capability.

**Independent Test**: Can be fully tested by running the Identity module against a tenant
where at least one service principal holds a directory role, and verifying a finding card
appears with role name, service principal name, and attack path context.

**Acceptance Scenarios**:

1. **Given** a service principal assigned to the Global Administrator, Privileged Role
   Administrator, or Application Administrator directory role, **When** the assessment
   runs, **Then** a Critical finding appears naming the service principal and the assigned
   role.

2. **Given** a service principal with no privileged role assignments, **When** the
   assessment runs, **Then** no false-positive findings are raised for that principal.

3. **Given** that service principal findings exist, **When** the attack simulation runs,
   **Then** those findings are correctly incorporated into the relevant attack chain.

---

### User Story 3 - Managed Identity Inventory & Privilege Review (Priority: P3)

An administrator can see an inventory of managed identities in the tenant and identify
any that have been assigned high-privilege directory roles, helping them enforce least
privilege for workload identities.

**Why this priority**: Managed identities are increasingly used for automation and are
sometimes granted excessive roles. This rounds out the workload identity coverage and
supports the least-privilege principle.

**Independent Test**: Can be fully tested by running the Identity module against a tenant
with at least one managed identity and verifying that the finding card correctly reflects
its privilege level.

**Acceptance Scenarios**:

1. **Given** a managed identity assigned a high-privilege directory role, **When** the
   assessment runs, **Then** a finding appears identifying the identity name, type
   (system-assigned or user-assigned), and assigned role.

2. **Given** managed identities with no elevated role assignments, **When** the assessment
   runs, **Then** no finding is raised (or a Passed status is shown).

---

### Edge Cases

- What happens when a tenant has more than 500 app registrations? The assessment MUST
  paginate results and not silently miss registrations beyond the first page.
- What happens when the assessment account lacks `Application.Read.All` permission?
  The module MUST surface a clear permission error rather than returning empty results.
- What happens when an app registration has multiple credentials, some expiring and some
  not? The finding MUST reflect the worst-case credential (soonest expiry or already
  expired).
- What happens when a service principal is a first-party Microsoft application assigned
  a high-privilege role? The finding MUST still surface it — the assessor decides
  whether it is expected.
- What happens if the tenant has zero app registrations? All related findings MUST show
  as Passed or Not Applicable — no errors or empty cards.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The assessment MUST identify app registrations with application-level Graph
  permissions classified as High or Critical risk (e.g., `RoleManagement.Read.Directory`,
  `Directory.ReadWrite.All`, `User.ReadWrite.All`, `Mail.ReadWrite`).
- **FR-002**: The assessment MUST identify app registrations with credentials (client
  secrets or certificates) expiring within 30 days.
- **FR-003**: The assessment MUST identify app registrations with credentials expiring
  within 90 days (separate lower-severity finding from FR-002).
- **FR-004**: The assessment MUST identify app registrations with credentials already
  expired.
- **FR-005**: The assessment MUST identify app registrations with credentials configured
  to never expire.
- **FR-006**: The assessment MUST identify app registrations with no owner assigned.
- **FR-007**: The assessment MUST identify multi-tenant app registrations registered in
  the tenant.
- **FR-008**: The assessment MUST identify app registrations with implicit grant flow
  enabled (ID token issuance or access token issuance).
- **FR-009**: The assessment MUST identify service principals assigned to high-privilege
  directory roles (at minimum: Global Administrator, Privileged Role Administrator,
  Application Administrator, Cloud Application Administrator, Exchange Administrator,
  SharePoint Administrator).
- **FR-010**: The assessment MUST identify managed identities (system-assigned and
  user-assigned) assigned to high-privilege directory roles.
- **FR-011**: Each finding MUST include: severity rating, short description, detailed
  explanation, attack path context, and remediation guidance consistent with the existing
  finding card format.
- **FR-012**: Each finding MUST include an inline PowerShell investigation script that
  the assessor can run to retrieve the raw detail behind the finding.
- **FR-013**: All new findings MUST appear in the Assessment Report generated by the
  report command, using the same formatting as existing findings.
- **FR-014**: New findings MUST integrate with the attack simulation module — relevant
  findings MUST be linked to the attack chains they enable.
- **FR-015**: New findings MUST contribute to the tenant risk score using severity
  weights consistent with the existing scoring model.
- **FR-016**: The assessment MUST paginate all API queries to handle tenants with more
  than 100 app registrations or service principals without missing results.
- **FR-017**: When the assessment account lacks the required permissions to run these
  checks, the module MUST surface a clear, actionable error message rather than silently
  returning empty or incomplete results.

### Key Entities

- **App Registration**: Display name, application ID, created date, credential set
  (type, expiry date, never-expires flag), owner list (present/absent), permission
  grants (type, value, risk classification), multi-tenant flag, implicit grant settings.
- **Service Principal**: Display name, object ID, service principal type
  (Application, ManagedIdentity, Legacy), assigned directory roles, permission grants.
- **Managed Identity**: Display name, object ID, managed identity type
  (SystemAssigned / UserAssigned), resource association, assigned directory roles.
- **Finding**: Finding ID, module tag, title, severity, description, attack path
  context, remediation guidance, investigation script, pass/fail status, affected
  resource name(s).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An assessor can identify all app registrations with expiring credentials
  without manually querying Entra ID — 100% of expiring credentials surfaced per
  assessment run.
- **SC-002**: All new finding cards display correctly within the existing assessment
  dashboard with no layout regressions in other modules.
- **SC-003**: The Identity module assessment (including new findings) completes within
  3 minutes for a typical tenant with up to 500 app registrations.
- **SC-004**: Attack simulation correctly reflects new service principal and managed
  identity findings — no attack chain that relies on these findings shows as blocked
  when the finding is present.
- **SC-005**: Generated Assessment Reports include all new findings at the same detail
  level as existing findings — no blank or truncated finding sections.
- **SC-006**: Zero false negatives for the critical app registration permission findings
  (FR-001) when tested against a known-configuration tenant.
- **SC-007**: Assessors report that new findings provide actionable, non-duplicate value
  beyond the existing 7 Identity & MFA findings.

## Assumptions

- The existing Graph API permissions already granted for App Registration and Certificate
  auth (`Application.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`)
  are sufficient to retrieve app registration, service principal, and managed identity
  data — no additional permissions need to be added to the documented minimum set.
- New findings will be added to the existing Identity & MFA module (ENTRA tag) rather
  than creating a separate module, keeping the module count at 6.
- The 30-day expiry warning threshold is the default; it is not user-configurable in
  this version.
- The risk classification for Graph permissions (FR-001) will be defined as a static
  lookup list maintained within the assessment scripts, not fetched dynamically.
- Exchange, Teams, and SharePoint modules are out of scope for this feature — it is
  limited to Entra ID workload identities only.
- The feature targets tenants with up to 500 app registrations for the stated
  performance goal; pagination support (FR-016) ensures correctness beyond that limit
  even if assessment duration increases.
- Remediation scripts are out of scope for this version — findings will surface risk
  and provide manual guidance only, consistent with how some existing findings work.

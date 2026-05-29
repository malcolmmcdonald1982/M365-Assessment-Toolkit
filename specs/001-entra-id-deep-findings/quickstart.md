# Quickstart: Testing Entra ID Deep Findings

**Feature**: 001-entra-id-deep-findings
**Date**: 2026-05-29

## Prerequisites

- M365 Assessment Toolkit installed and running (`http://localhost:5000`)
- Access to an M365 tenant with Global Reader permissions (minimum)
- To test all findings: access to a tenant with known-configuration app registrations

---

## Setting Up a Test Tenant

For meaningful end-to-end testing, set up the following in your test tenant before
running the assessment:

### Trigger ENTRA-001 (High-Privilege App Registrations)
1. Go to Entra ID > App registrations > New registration
2. After creating, go to API permissions > Add a permission > Microsoft Graph > Application
3. Add `Directory.ReadWrite.All` or `Mail.ReadWrite`
4. Click Grant admin consent
5. The app registration should now trigger ENTRA-001

### Trigger ENTRA-002 (Expired Credentials)
1. Find an existing app registration or create one
2. Go to Certificates & secrets > New client secret
3. Set expiry to a past date (not possible via UI — use the `Update-MgApplicationPassword`
   Graph API call with a past date, or wait for an existing secret to expire)
4. Alternatively: use an app registration that already has an expired secret

### Trigger ENTRA-003 (Expiring Within 30 Days)
1. Create or find an app registration
2. Add a client secret with an expiry date 20 days from today

### Trigger ENTRA-005 (Never-Expiring Credentials)
1. Only possible on older app registrations — check existing apps in the tenant

### Trigger ENTRA-006 (Unowned App Registrations)
1. Create a new app registration as a service account or via API with no owner
2. Verify the app has no owner in Entra ID > App registrations > [App] > Owners

### Trigger ENTRA-007 (Multi-Tenant)
1. Create an app registration and set Supported account types to
   "Accounts in any organizational directory"
2. `SignInAudience` will be `AzureADMultipleOrgs` or `AzureADandPersonalMicrosoftAccount`

### Trigger ENTRA-008 (Implicit Grant)
1. Go to an app registration > Authentication > Implicit grant and hybrid flows
2. Check "ID tokens" or "Access tokens"

### Trigger ENTRA-009 (Privileged Service Principals)
1. Go to Entra ID > Roles and administrators
2. Find "Application Administrator" or "Cloud Application Administrator"
3. Add an enterprise application (service principal) as a member

### Trigger ENTRA-010 (Privileged Managed Identities)
1. Assign a managed identity the "Global Administrator" role via Entra ID > Roles
2. This should be rare in production — use a dev/test tenant

---

## Running the Assessment

1. Open the tool at `http://localhost:5000`
2. Select **Interactive** authentication (or App Reg/Certificate if configured)
3. Ensure **Identity & MFA** is checked in the module list
4. Click **Run Assessment**
5. Sign in when the browser popup appears

---

## Verifying New Findings

After the assessment completes:

1. **Check the dashboard** — new ENTRA-xxx finding cards should appear in the Findings
   panel sorted by severity (Critical → High → Medium)

2. **Check the investigation scripts** — click the "Investigate" button on each ENTRA
   finding card. The script panel should expand and show a PowerShell script. Click
   "Copy" to copy it and run it in a PowerShell window against the same tenant.

3. **Check the score** — with ENTRA-001 and ENTRA-009 triggered, the score should
   decrease by at least 16 points (8 per critical finding, capped at -32 total critical).

4. **Check attack simulation** — click "Attack Simulation" tab. The `APP-TAKEOVER`
   chain should appear as active if both ENTRA-001 and ENTRA-002 are triggered.
   The `SP-PERSIST` chain should appear if ENTRA-009 is triggered.

5. **Check the Assessment Report** — click Download Report. Open the generated Word
   document and verify all ENTRA-xxx findings appear in the findings section with
   description and recommendation text.

---

## Verifying a Clean Tenant (No False Positives)

Run against a well-managed tenant with:
- No app registrations with high-privilege permissions
- All credentials with defined future expiry dates
- All app registrations with at least one owner
- No multi-tenant apps
- No implicit grant flows enabled
- No service principals or managed identities in privileged roles

Expected result: All 10 ENTRA-xxx findings show as Passed (not triggered). The score
should not be affected by these findings.

---

## Performance Check

On a tenant with ~500 app registrations:
- The Identity & MFA module should complete within 3 minutes
- Check the Run Log panel for timing information
- If the module times out (300-second limit), report this as a performance regression

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| ENTRA-xxx findings not appearing | Identity module not included in run | Ensure Identity & MFA is checked |
| All ENTRA findings show 0 with no errors | `Application.Read.All` permission missing | Verify app registration has this permission and admin consent granted |
| "Investigate" button not visible on ENTRA findings | `INVESTIGATE_IDS` set not updated in `index.html` | Check that the frontend change was applied |
| Module times out | Tenant has very large number of app registrations | Contact developer; pagination optimisation may be needed |
| Script returns permission error | Account lacks `RoleManagement.Read.Directory` | Grant this permission and re-run |

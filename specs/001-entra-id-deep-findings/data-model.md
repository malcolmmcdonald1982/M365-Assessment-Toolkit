# Data Model: Entra ID Deep Findings

**Feature**: 001-entra-id-deep-findings
**Date**: 2026-05-29

## Overview

The data model for this feature consists of new metric keys added to the JSON output
of `Get-IdentityMetrics.ps1`, and the corresponding finding definitions in `backend.py`.
No persistent storage schema changes are required — findings flow through the existing
in-memory pipeline.

---

## Metric Keys (PowerShell → Backend)

These keys are new additions to the JSON object output by `Get-IdentityMetrics.ps1`.
They are merged into `all_metrics` by the `/run` endpoint alongside existing identity
metrics.

| Key | Type | Description | Threshold Direction |
|-----|------|-------------|---------------------|
| `high_priv_app_reg_count` | `int` | Count of app registrations holding Critical or High risk Graph application permissions | > 0 = finding triggered |
| `expiring_cred_30d_count` | `int` | Count of app registrations with ≥1 credential expiring within 30 days | > 0 = finding triggered |
| `expiring_cred_90d_count` | `int` | Count of app registrations with ≥1 credential expiring within 31–90 days | > 0 = finding triggered |
| `expired_cred_count` | `int` | Count of app registrations with ≥1 already-expired credential | > 0 = finding triggered |
| `never_expire_cred_count` | `int` | Count of app registrations with ≥1 credential where `endDateTime` is null | > 0 = finding triggered |
| `unowned_app_reg_count` | `int` | Count of app registrations with zero owners | > 0 = finding triggered |
| `multitenant_app_reg_count` | `int` | Count of app registrations with `SignInAudience` not equal to `AzureADMyOrg` | > 0 = finding triggered |
| `implicit_grant_app_count` | `int` | Count of app registrations with implicit ID or access token issuance enabled | > 0 = finding triggered |
| `priv_service_principal_count` | `int` | Count of non-managed-identity service principals assigned to high-privilege directory roles | > 0 = finding triggered |
| `priv_managed_identity_count` | `int` | Count of managed identities assigned to high-privilege directory roles | > 0 = finding triggered |

### Key Design Rules

- All keys return `int`, never `null` or absent — default to `0` on error or no data.
- Values are counts, not lists — the investigation script provides the detail.
- `expiring_cred_90d_count` counts apps in the 31–90 day window ONLY (apps in the
  ≤30 day window are captured by `expiring_cred_30d_count` separately).
- For `unowned_app_reg_count`: only checked for apps that have at least one other risk
  indicator if tenant has >200 app registrations (see research.md §7).

---

## Finding Definitions (backend.py additions)

Each finding follows the existing `FINDINGS_LIBRARY` dict structure:

```python
{
    "id":             "ENTRA-xxx",         # string, unique
    "title":          "...",               # short display title
    "module":         "identity",          # existing module tag
    "metric":         "<key>",             # must match a metric key above
    "severity":       "critical|high|medium|low",
    "threshold":      lambda v: v > 0,     # always int > 0 for these findings
    "description":    "...",               # shown in finding card
    "recommendation": "...",               # shown in finding card
}
```

### Finding Catalogue

| Finding ID | Metric Key | Severity | Title |
|-----------|-----------|---------|-------|
| ENTRA-001 | `high_priv_app_reg_count` | critical | High-Privilege App Registrations |
| ENTRA-002 | `expired_cred_count` | high | Expired App Registration Credentials |
| ENTRA-003 | `expiring_cred_30d_count` | high | App Registration Credentials Expiring Within 30 Days |
| ENTRA-004 | `expiring_cred_90d_count` | medium | App Registration Credentials Expiring Within 90 Days |
| ENTRA-005 | `never_expire_cred_count` | medium | App Registration Credentials Set to Never Expire |
| ENTRA-006 | `unowned_app_reg_count` | medium | Unowned App Registrations |
| ENTRA-007 | `multitenant_app_reg_count` | medium | Multi-Tenant App Registrations |
| ENTRA-008 | `implicit_grant_app_count` | medium | Implicit Grant Flow Enabled on App Registrations |
| ENTRA-009 | `priv_service_principal_count` | critical | Service Principals with High-Privilege Directory Roles |
| ENTRA-010 | `priv_managed_identity_count` | high | Managed Identities with High-Privilege Directory Roles |

---

## METRIC_DISPLAY Entries

New entries for the `METRIC_DISPLAY` dict in `backend.py`:

| Key | Label | Format | Description |
|-----|-------|--------|-------------|
| `high_priv_app_reg_count` | High-Privilege App Registrations | `{}` | Apps with Critical or High risk Graph permissions |
| `expired_cred_count` | Expired App Credentials | `{}` | App registrations with expired credentials |
| `expiring_cred_30d_count` | Credentials Expiring (≤30 days) | `{}` | App registrations with credentials expiring within 30 days |
| `expiring_cred_90d_count` | Credentials Expiring (31–90 days) | `{}` | App registrations with credentials expiring within 31–90 days |
| `never_expire_cred_count` | Never-Expiring Credentials | `{}` | App registrations with credentials set to never expire |
| `unowned_app_reg_count` | Unowned App Registrations | `{}` | App registrations with no owner assigned |
| `multitenant_app_reg_count` | Multi-Tenant App Registrations | `{}` | App registrations accessible from any Entra tenant |
| `implicit_grant_app_count` | Implicit Grant Apps | `{}` | Apps with implicit ID/access token issuance enabled |
| `priv_service_principal_count` | Privileged Service Principals | `{}` | Service principals with high-privilege directory roles |
| `priv_managed_identity_count` | Privileged Managed Identities | `{}` | Managed identities with high-privilege directory roles |

All 10 keys follow the `count_good_zero` display rule (green = 0, warn = 1–2, red = 3+).

---

## Attack Chain Additions (backend.py)

Two new entries in `ATTACK_CHAINS`:

### APP-TAKEOVER: App Registration Credential Theft
- **Requires**: `["ENTRA-001", "ENTRA-002"]` (high-priv app + expired/leaked cred)
- **Severity**: critical
- **Description**: An attacker who obtains the credential (secret or certificate) of a
  high-privilege app registration gains persistent, non-interactive tenant access that
  survives password resets and MFA changes.

### SP-PERSIST: Service Principal Backdoor
- **Requires**: `["ENTRA-009"]` (service principal with high-privilege role)
- **Severity**: high
- **Description**: A service principal with Global Administrator or Privileged Role
  Administrator represents a persistent, non-interactive backdoor. Attackers who
  compromise the associated application gain admin-level tenant access without
  triggering user-based sign-in alerts.

---

## Investigation Script Additions (backend.py)

One `INVESTIGATION_SCRIPTS` entry per finding (10 total). Each entry is a ready-to-run
PowerShell script that:
1. Connects to Microsoft Graph interactively
2. Queries the specific entity type relevant to the finding
3. Outputs a formatted table to the console
4. Exports results to a timestamped CSV file
5. Disconnects

Scripts follow the same structure as existing investigation scripts (see ID-001–ID-007
in `backend.py` for reference).

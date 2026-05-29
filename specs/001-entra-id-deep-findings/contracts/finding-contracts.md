# Contracts: Entra ID Deep Findings

**Feature**: 001-entra-id-deep-findings
**Date**: 2026-05-29

This document describes the API contracts affected by the new Entra ID deep findings.
No new endpoints are introduced — existing endpoints are extended with new finding IDs
and new metric keys.

---

## `/run` Response Extension

**Endpoint**: `POST /run`

The response payload is unchanged in shape. The new findings appear as additional
entries in the `findings` array when triggered, and the new metric keys appear in
`allMetrics`.

### New finding object shape (same as existing)

```json
{
  "id": "ENTRA-001",
  "title": "High-Privilege App Registrations",
  "module": "identity",
  "metric": "high_priv_app_reg_count",
  "severity": "critical",
  "description": "...",
  "recommendation": "...",
  "observed_value": 3
}
```

### New metric keys in `allMetrics`

All 10 new keys (see `data-model.md`) are present in `allMetrics` when the `identity`
module is included in the assessment run. All values are integers ≥ 0.

```json
{
  "high_priv_app_reg_count":      2,
  "expired_cred_count":           1,
  "expiring_cred_30d_count":      0,
  "expiring_cred_90d_count":      3,
  "never_expire_cred_count":      1,
  "unowned_app_reg_count":        4,
  "multitenant_app_reg_count":    2,
  "implicit_grant_app_count":     1,
  "priv_service_principal_count": 1,
  "priv_managed_identity_count":  0
}
```

---

## `/investigate/<finding_id>` Extensions

**Endpoint**: `GET /investigate/<finding_id>`

The existing endpoint already handles any finding ID. The following new IDs are added
to `INVESTIGATION_SCRIPTS` in `backend.py`. Requesting any other ID returns 404 as before.

| Finding ID | Script Title |
|-----------|-------------|
| `ENTRA-001` | What are the high-privilege app registrations? |
| `ENTRA-002` | Which app registrations have expired credentials? |
| `ENTRA-003` | Which app registrations have credentials expiring soon (≤30 days)? |
| `ENTRA-004` | Which app registrations have credentials expiring within 90 days? |
| `ENTRA-005` | Which app registrations have credentials set to never expire? |
| `ENTRA-006` | Which app registrations have no owner? |
| `ENTRA-007` | Which app registrations are multi-tenant? |
| `ENTRA-008` | Which app registrations have implicit grant flow enabled? |
| `ENTRA-009` | Which service principals hold high-privilege directory roles? |
| `ENTRA-010` | Which managed identities hold high-privilege directory roles? |

### Response shape (unchanged)

```json
{
  "findingId":   "ENTRA-001",
  "title":       "What are the high-privilege app registrations?",
  "description": "Lists all app registrations with Critical or High risk Graph permissions.",
  "script":      "# PowerShell script content..."
}
```

---

## `/simulator/chains` Extension

**Endpoint**: `POST /simulator/chains`

Two new chain IDs (`APP-TAKEOVER`, `SP-PERSIST`) are added to `ATTACK_CHAINS`. The
response shape is unchanged. The new chains appear in the `chains` array and are
evaluated against the submitted `openFindingIds` as normal.

### New chain IDs

| Chain ID | Name | Severity | Requires |
|---------|------|---------|---------|
| `APP-TAKEOVER` | App Registration Credential Theft | critical | `ENTRA-001`, `ENTRA-002` |
| `SP-PERSIST` | Service Principal Backdoor | high | `ENTRA-009` |

---

## Frontend Change (`index.html`)

**Not an API contract** — documented here for completeness.

The `INVESTIGATE_IDS` constant (line ~1305) must be updated to include the 10 new IDs.
This is a one-line change:

```javascript
// Before
const INVESTIGATE_IDS = new Set(['ID-001','ID-002','ID-003','ID-004','ID-005','APP-001','MON-001','EXO-001','MDM-001']);

// After
const INVESTIGATE_IDS = new Set(['ID-001','ID-002','ID-003','ID-004','ID-005','APP-001','MON-001','EXO-001','MDM-001','ENTRA-001','ENTRA-002','ENTRA-003','ENTRA-004','ENTRA-005','ENTRA-006','ENTRA-007','ENTRA-008','ENTRA-009','ENTRA-010']);
```

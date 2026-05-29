# Research: Simulator Secure Score

**Feature**: 002-simulator-secure-score
**Date**: 2026-05-29

## 1. Where Should the Impact Lookup Table Live?

### Decision
`secure_score_impact` is added as an integer field on each finding in `FINDINGS_LIBRARY`
in `backend.py`. The existing `evaluate_findings()` function includes it in each triggered
finding dict, so it flows automatically into session JSON and into the frontend's
`assessmentData.findings` array. No separate API endpoint or JS constant is needed.

### Rationale
Keeping it in `FINDINGS_LIBRARY` alongside the finding definition is the single source of
truth. The `/findings-library` endpoint (existing) will expose it automatically since it
already returns all non-threshold fields. Old sessions that lack the field default to
`secure_score_impact = 0` gracefully via `f.secure_score_impact || 0` in the frontend.

### Alternatives Considered
- **JS constant in index.html**: Simpler but creates two places to update when findings
  change (backend FINDINGS_LIBRARY and the JS table). Rejected.
- **Separate `/secure-score-impacts` endpoint**: Unnecessary indirection for a static
  lookup. Rejected.

---

## 2. Where Does the Baseline Secure Score Come From?

### Decision
The baseline is `assessmentData.allMetrics?.secure_score_percentage`, a float 0–100
already present in the session when the Security & CA module ran. If absent (Security
module not run), baseline is `null` and the frontend uses 0 as the starting point while
showing an "Estimated" label.

### Rationale
The `secure_score_percentage` metric is already collected, stored in sessions, and
available to the frontend without any new API call. The session structure already includes
`allMetrics` as a flat key-value dict.

### Verification
From `backend.py` line ~638:
```python
all_metrics.update(metrics)
...
return jsonify({..., "allMetrics": all_metrics, ...})
```
And in `index.html`, the frontend stores the full response in `assessmentData`, so
`assessmentData.allMetrics.secure_score_percentage` is accessible.

---

## 3. Secure Score Impact Values Per Finding

### Decision
Static integer values representing approximate Microsoft Secure Score point improvements.
Microsoft does not publicly document exact per-recommendation Secure Score weights; values
below are approximations based on Microsoft documentation, category groupings, and
industry guidance. Values are intentionally conservative.

| Finding ID | Title (short) | Impact (pts) | Basis |
|-----------|--------------|-------------|-------|
| ID-001 | Low MFA Coverage | 16 | MFA enforcement is typically worth 15–20 pts |
| ID-002 | Excessive Global Admins | 5 | Role reduction — moderate weight |
| ID-003 | No PIM | 10 | JIT access is a published Secure Score action |
| ID-004 | High Guest Users | 3 | Access review category — low weight |
| ID-005 | Unused Licences | 0 | Cost/hygiene — not a Secure Score item |
| SEC-001 | Low Secure Score | 0 | Meta-finding; IS the score, not a driver |
| SEC-002 | Security Defaults Disabled | 12 | Baseline protection — high weight |
| CA-001 | No CA Policies | 15 | CA baseline is heavily weighted by Microsoft |
| CA-002 | Legacy Auth Not Blocked | 10 | Blocking legacy auth is a top recommendation |
| EXO-001 | External Forwarding | 5 | Mail flow control |
| EXO-002 | Mailbox Audit Disabled | 5 | Audit/compliance category |
| EXO-003 | Anti-Phish Intelligence | 5 | Defender for Office 365 controls |
| TEAMS-001 | Unrestricted External Access | 3 | Teams security category |
| TEAMS-002 | Consumer Access Enabled | 3 | Teams security category |
| SPO-001 | SPO Sharing = Anyone | 8 | Data protection category |
| SPO-002 | SPO Legacy Auth | 5 | Identity / legacy auth |
| MDM-001 | Low Device Compliance | 5 | Intune compliance |
| MDM-002 | No Compliance Policies | 8 | Intune compliance |
| APP-001 | High-Privilege OAuth Apps | 5 | App governance |
| MON-001 | No Defender Alert Policies | 5 | Threat detection |
| SEC-003 | MFA Fatigue Protection | 5 | Authenticator hardening |
| SEC-004 | Weak MFA Methods | 8 | Authentication methods policy |
| SEC-005 | User Consent Unrestricted | 5 | App consent governance |
| ID-006 | Risky Users Not Reviewed | 5 | Identity Protection |
| ID-007 | No Emergency Access | 3 | Admin resilience |
| SEC-006 | No Sentinel | 3 | SIEM integration |
| EXO-004 | DMARC Not Configured | 5 | Email authentication |
| EXO-005 | SPF/DKIM Not Configured | 5 | Email authentication |
| MDM-003 | No Windows Update Ring | 3 | Patch management |
| MDM-004 | BitLocker Not Enforced | 8 | Device encryption |
| ENTRA-001 | High-Priv App Regs | 5 | App governance |
| ENTRA-002 | Expired App Credentials | 3 | Credential hygiene |
| ENTRA-003 | Creds Expiring ≤30d | 3 | Credential hygiene |
| ENTRA-004 | Creds Expiring 31–90d | 2 | Credential hygiene |
| ENTRA-005 | Never-Expire Creds | 3 | Credential hygiene |
| ENTRA-006 | Unowned App Regs | 2 | App governance |
| ENTRA-007 | Multi-Tenant App Regs | 2 | App governance |
| ENTRA-008 | Implicit Grant Flow | 3 | App security |
| ENTRA-009 | Priv Service Principals | 5 | Identity governance |
| ENTRA-010 | Priv Managed Identities | 3 | Identity governance |

**Total potential uplift across all findings**: ~210 points — intentionally exceeds 100
because only a subset will be triggered in any given tenant.

**Note**: Consultants should present these as directional estimates, not precise Microsoft
figures. The UI "Estimated" label handles this disclosure.

---

## 4. Existing Simulator DOM and JS State

### Decision
Extend the existing `.sim-score-banner` with three new `sim-score-block` divs. Update
`renderSimResults()` with a Secure Score calculation block.

### Key existing state variables (already in index.html)
- `simFindings` — array of triggered findings (each has `id`, `severity`, etc.;
  will have `secure_score_impact` after this change)
- `simState` — object `{ [findingId]: boolean }` — `true` = open (not fixed),
  `false` = fixed/toggled
- `assessmentData` — full session object; `assessmentData.allMetrics` contains metrics

### Calculation (pure JS, no async)
```javascript
const baseline  = Math.round(assessmentData?.allMetrics?.secure_score_percentage ?? 0);
const hasActual = assessmentData?.allMetrics?.secure_score_percentage != null;
const uplift    = simFindings
  .filter(f => simState[f.id] === false)          // fixed findings only
  .reduce((sum, f) => sum + (f.secure_score_impact || 0), 0);
const projected = Math.min(100, baseline + uplift);
const delta     = projected - baseline;
```

### Rendering target
Three new `<div class="sim-score-block">` elements appended after the existing five in
`.sim-score-banner`. IDs: `simSSBaseline`, `simSSProjected`, `simSSDelta`.
A "Estimated" sub-label beneath the value when `!hasActual`.

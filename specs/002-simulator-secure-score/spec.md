# Feature Specification: Simulator Secure Score

**Feature Branch**: `002-simulator-secure-score`

**Created**: 2026-05-29

**Status**: Draft

**Input**: User description: "Add estimated Microsoft Secure Score display to the Attack Path Simulator alongside the existing attack path score"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Dual Score Display in Simulator (Priority: P1)

An IT consultant running the attack simulation can see both the tool's existing risk score
AND an estimated Microsoft Secure Score displayed side-by-side in the simulator panel. As
they toggle findings on or off to simulate remediation, both scores update in real time —
the risk score showing attack path exposure, and the estimated Secure Score showing what the
tenant's Microsoft Secure Score would look like after those fixes are applied.

**Why this priority**: Clients frequently ask "what does this do to our Secure Score?" during
a remediation discussion. Answering that question without leaving the tool removes friction
and strengthens the consultant's narrative. This is the core value of the feature.

**Independent Test**: Run an assessment against any tenant, navigate to the Attack Simulation
tab, and verify that both the existing risk score and an estimated Secure Score are visible.
Toggle at least one finding and verify both scores update without a page reload.

**Acceptance Scenarios**:

1. **Given** an assessment has been completed with the Security module included, **When** the
   consultant opens the Attack Simulation tab, **Then** both the tool's risk score and an
   estimated Microsoft Secure Score are displayed prominently in the score summary area.

2. **Given** the simulator is showing both scores, **When** the consultant toggles a finding
   to "simulated as fixed", **Then** the estimated Secure Score increases by the finding's
   associated Secure Score impact, and the risk score updates as it does today.

3. **Given** the consultant has toggled several findings, **When** they toggle a finding back
   to "open", **Then** the estimated Secure Score decreases accordingly, always reflecting
   only the currently simulated-as-fixed findings.

4. **Given** the Security module was not run during the assessment (no actual Secure Score
   collected), **When** the simulator is opened, **Then** the estimated Secure Score still
   displays, calculated from the tool's own findings, with a clear label indicating it is
   an estimate rather than a measured value.

---

### User Story 2 - Secure Score Baseline vs Projected Comparison (Priority: P2)

When an actual Microsoft Secure Score was collected during the assessment, the simulator
displays it as the baseline alongside the projected score after simulated remediation —
allowing the consultant to show the client the gap between current and potential Secure Score
in concrete numbers.

**Why this priority**: The comparison between "where you are now" (actual) and "where you
could be" (projected) is a compelling client-facing narrative. It's more persuasive than the
projected number alone.

**Independent Test**: Run an assessment that includes the Security & CA module. Open the
simulator. Verify that the baseline Secure Score label shows the actual collected value and
the projected label shows the estimated post-remediation value.

**Acceptance Scenarios**:

1. **Given** the Security module ran and collected an actual Secure Score, **When** the
   consultant opens the simulator with no findings toggled, **Then** the display shows
   the actual Secure Score as the baseline and the same value as the current projection
   (no delta when nothing is fixed).

2. **Given** the simulator is showing the baseline Secure Score, **When** the consultant
   toggles findings representing a high-Secure-Score-impact fix, **Then** the projected
   Secure Score increases above the baseline and the point delta is shown (e.g.,
   "+18 points").

---

### Edge Cases

- What happens when the Security module was not run? The Secure Score display should still
  show an estimated value derived from the findings that were collected, with a visual
  indicator that no actual baseline was measured.
- What if all findings are toggled as fixed? The projected Secure Score MUST NOT exceed 100.
- What if no findings are triggered at all (clean tenant)? Both scores show their maximum
  values and the Secure Score impact delta shows +0.
- What if the actual Secure Score collected is higher than the projected post-remediation
  score? This can happen if the tool's findings don't fully overlap with Secure Score
  recommendations. The display MUST show this without displaying a negative delta.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The Attack Simulation tab MUST display an estimated Microsoft Secure Score
  alongside the existing tool risk score at all times when an assessment result is loaded.
- **FR-002**: The estimated Secure Score MUST update in real time as the consultant toggles
  findings on or off in the simulator — no page reload required.
- **FR-003**: Each finding in the findings library MUST have an associated estimated Secure
  Score impact value (points), representing the approximate Secure Score improvement
  achievable by remediating that finding.
- **FR-004**: The estimated Secure Score MUST be calculated as: actual baseline Secure Score
  (if available) plus the sum of Secure Score impacts for all currently simulated-as-fixed
  findings, capped at 100.
- **FR-005**: When an actual Secure Score was collected during the assessment, the display
  MUST show it as a labelled baseline value alongside the current projected value.
- **FR-006**: When no actual Secure Score was collected, the display MUST show a calculated
  estimate with a visible "Estimated" label to distinguish it from a measured value.
- **FR-007**: When findings are toggled, the display MUST show the point delta between the
  baseline and projected Secure Score (e.g., "+12 points" or "+0 points").
- **FR-008**: The Secure Score display MUST be positioned in the simulator score summary
  area, adjacent to the existing risk score, so both are visible simultaneously without
  scrolling.
- **FR-009**: The Secure Score impact values per finding MUST be based on published
  Microsoft Secure Score recommendation weights or reasonable approximations where exact
  values are not published.
- **FR-010**: The Secure Score display MUST NOT break or error if the Security module was
  not run; it MUST gracefully degrade to estimation-only mode.

### Key Entities

- **Finding Secure Score Impact**: Finding ID, estimated Secure Score point improvement
  when remediated (integer, 0–100), source basis (Microsoft published weight or
  approximation).
- **Secure Score Display State**: Baseline value (actual collected or null), projected
  value (calculated), delta (projected minus baseline), display mode (measured vs
  estimated).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Both the risk score and the estimated Secure Score are visible simultaneously
  in the Attack Simulation tab without any scrolling on a standard 1080p display.
- **SC-002**: The Secure Score projection updates within 200 milliseconds of a finding
  being toggled — no perceptible lag.
- **SC-003**: Consultants can answer "what would fixing these issues do to our Secure Score?"
  without leaving the simulator view.
- **SC-004**: The Secure Score display correctly shows 0 point delta when no findings are
  toggled and the correct cumulative delta when multiple findings are toggled simultaneously.
- **SC-005**: The Secure Score projection never displays a value above 100 or below 0,
  regardless of finding combinations.

## Assumptions

- The existing attack simulation toggle mechanism is retained unchanged; only the score
  display area is extended.
- Secure Score impact values per finding are defined as a static lookup table maintained
  in the backend. Values are approximated from Microsoft documentation where exact weights
  are not publicly disclosed; the tool does not claim these are precise.
- The "estimated" label is sufficient to communicate the approximate nature of the
  projection — no additional disclaimer modal or tooltip is required for this version.
- The baseline Secure Score used is the `secure_score_percentage` metric collected by the
  Security & CA module during the assessment (stored in the session). If that module was
  not run, the baseline is null and estimation-only mode applies.
- The feature is display-only — no new API calls to Microsoft are made to fetch or
  recalculate the Secure Score at simulation time.
- The Secure Score impact values for the 10 new ENTRA-xxx findings (from the preceding
  feature) are included in the lookup table.

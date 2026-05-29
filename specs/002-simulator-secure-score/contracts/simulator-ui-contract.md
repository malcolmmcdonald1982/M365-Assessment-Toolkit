# UI Contract: Simulator Secure Score

**Feature**: 002-simulator-secure-score
**Date**: 2026-05-29

This document defines the UI contract changes — new DOM elements, JS state, and data
flow — introduced by this feature. No new backend API endpoints are added.

---

## 1. Score Banner Extension (`index.html` lines ~791–813)

The existing `.sim-score-banner` has 5 blocks:

```
[Current Score] → [Simulated Score] [Improvement] [Active Chains] [Chains Broken]
```

This feature appends 3 more blocks (a visual separator `|` precedes them):

```
[Current Score] → [Simulated Score] [Improvement] [Active Chains] [Chains Broken] | [Secure Baseline] [Secure Projected] [Secure Uplift]
```

### New HTML (appended inside `.sim-score-banner`)

```html
<div class="sim-score-separator">|</div>

<div class="sim-score-block">
  <div class="sim-score-label">Secure Baseline</div>
  <div class="sim-score-val" id="simSSBaseline" style="color:var(--muted)">—</div>
</div>

<div class="sim-score-block">
  <div class="sim-score-label">Secure Projected</div>
  <div class="sim-score-val" id="simSSProjected" style="color:var(--success)">—</div>
  <div class="sim-score-sub" id="simSSEstLabel" style="display:none;">Estimated</div>
</div>

<div class="sim-score-block">
  <div class="sim-score-label">Secure Uplift</div>
  <div class="sim-score-val" id="simSSDelta" style="color:var(--accent)">—</div>
</div>
```

### New CSS class `.sim-score-sub`

```css
.sim-score-sub {
  font-size: 9px;
  color: var(--muted);
  font-family: var(--mono);
  text-align: center;
  margin-top: 2px;
}
```

### New CSS class `.sim-score-separator`

```css
.sim-score-separator {
  color: var(--muted);
  font-size: 1.2rem;
  align-self: center;
  padding: 0 4px;
}
```

---

## 2. `renderSimResults()` Extension (`index.html` ~line 1867)

After the existing block that updates `simScoreSim`, `simScoreDiff`, etc., add:

```javascript
// Secure Score estimation
const baseline  = Math.round(assessmentData?.allMetrics?.secure_score_percentage ?? 0);
const hasActual = assessmentData?.allMetrics?.secure_score_percentage != null;
const uplift    = simFindings
  .filter(f => simState[f.id] === false)
  .reduce((sum, f) => sum + (f.secure_score_impact || 0), 0);
const projected = Math.min(100, baseline + uplift);
const delta     = projected - baseline;

const ssCol  = projected >= 70 ? 'var(--success)' : projected >= 50 ? 'var(--warning)' : 'var(--danger)';
document.getElementById('simSSBaseline').textContent  = hasActual ? `${baseline}/100` : '—';
document.getElementById('simSSProjected').textContent = `${projected}/100`;
document.getElementById('simSSProjected').style.color = ssCol;
document.getElementById('simSSDelta').textContent     = `+${delta} pts`;
document.getElementById('simSSDelta').style.color     = delta > 0 ? 'var(--success)' : 'var(--muted)';
document.getElementById('simSSEstLabel').style.display = hasActual ? 'none' : 'block';
```

---

## 3. `initSimulator()` Initialisation (`index.html` ~line 1798)

After the existing line that sets `simScoreCurrent`, add initialisation for the new
baseline display:

```javascript
const hasActualOnInit = assessmentData?.allMetrics?.secure_score_percentage != null;
const baselineOnInit  = Math.round(assessmentData?.allMetrics?.secure_score_percentage ?? 0);
document.getElementById('simSSBaseline').textContent = hasActualOnInit ? `${baselineOnInit}/100` : '—';
document.getElementById('simSSEstLabel').style.display = hasActualOnInit ? 'none' : 'block';
```

---

## 4. `backend.py` — `evaluate_findings()` Change

Add `secure_score_impact` to the triggered finding dict:

```python
# Before
triggered.append({
    "id": f["id"], "title": f["title"], "module": f["module"],
    "metric": metric, "severity": f["severity"],
    "description": f["description"], "recommendation": f["recommendation"],
    "observed_value": value
})

# After
triggered.append({
    "id": f["id"], "title": f["title"], "module": f["module"],
    "metric": metric, "severity": f["severity"],
    "description": f["description"], "recommendation": f["recommendation"],
    "observed_value": value,
    "secure_score_impact": f.get("secure_score_impact", 0)
})
```

---

## 5. Backward Compatibility

Sessions created before this feature will have `findings` entries without
`secure_score_impact`. The frontend handles this via `f.secure_score_impact || 0` —
old sessions show `+0 pts` uplift for all findings. The baseline is still shown
correctly if `allMetrics.secure_score_percentage` is present.

---

## 6. No Changes To

- `/simulator/chains` endpoint (backend) — unchanged
- `/run` endpoint response structure — extended only (new field, no removals)
- Existing score banner elements (`simScoreCurrent`, `simScoreSim`, `simScoreDiff`,
  `simActiveChains`, `simBrokenChains`) — unchanged
- Export What-If Report (`exportSimReport`) — the new Secure Score values are visible
  in the HTML export naturally since they're in the DOM; no explicit changes needed

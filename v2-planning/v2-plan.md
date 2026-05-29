# M365 Assessment Toolkit — V2 Planning Document

## Overview

V2 targets MSPs and IT consultancies who are already using v1 for client assessments.
The core free tool stays as-is. V2 adds a Pro tier built around three pillars:
white-label reports, multi-tenant management, and scheduled automation.

---

## Pricing Model

| Tier | Price | Who it's for |
|---|---|---|
| Community (v1) | Free | Individual consultants, IT admins, community |
| Pro | £49–79/month per MSP | MSPs doing repeat client assessments |
| Consultancy Pack | £299–499 one-off | Branded installer + custom report template + 12 months updates |

---

## Feature 1 — White-Label Reports

### What it does
MSPs enter their company details once. Every Word report generated uses their branding
instead of the default M365 Assessment Toolkit header.

### What changes

**Settings screen (new tab in the UI)**
```
Company Name        [________________]
Company Logo        [Upload PNG/SVG  ]
Primary Colour      [#______] (used for report header bar)
Consultant Name     [________________]
Consultant Role     [________________]
Consultant Email    [________________]
Consultant Phone    [________________]
Footer Text         [________________]  e.g. "Registered in England No. 12345678"
```

**backend.py changes**
- New `POST /settings` route — saves branding config to `settings.json`
- New `GET /settings` route — returns current config
- `generate_html_pdf()` reads from `settings.json` instead of hardcoded defaults
- Report cover page uses uploaded logo + primary colour

**generate-report.js changes**
- Cover page: replace "M365 Assessment Toolkit" header with company name + logo
- Header/footer on every page: company name left, page number right
- Colour accent (currently blue #4f9cf9) replaced with MSP's primary colour
- Remove all "M365 Assessment Toolkit" references from body text

**File storage**
```
C:\M365 Assessment Toolkit\
└── settings\
    ├── settings.json       # branding config
    └── logo.png            # uploaded logo
```

### Technical effort: Medium (2–3 days)

---

## Feature 2 — Multi-Tenant Dashboard

### What it does
One screen shows all clients the MSP has assessed — name, score, last assessed date,
number of open findings, trend vs previous assessment. Click a client to load their session.

### What the screen looks like

```
┌─────────────────────────────────────────────────────────────────────┐
│  CLIENT PORTFOLIO                              [+ New Assessment]   │
├─────────────────────────────────────────────────────────────────────┤
│  Search clients...                    Sort: Last Assessed ▼         │
├──────────────────┬───────┬──────────────┬──────────┬───────────────┤
│  Client          │ Score │ Last Assessed│ Findings │ Trend         │
├──────────────────┼───────┼──────────────┼──────────┼───────────────┤
│  Contoso Ltd     │  42   │ 2026-05-18   │ 8 open   │ ▼ -6 pts      │
│  Fabrikam Inc    │  71   │ 2026-05-10   │ 3 open   │ ▲ +12 pts     │
│  Northwind Corp  │  55   │ 2026-04-28   │ 6 open   │ → no change   │
│  Adventure Works │  88   │ 2026-05-01   │ 1 open   │ ▲ +5 pts      │
│  Tailspin Toys   │  31   │ 2026-03-15   │ 11 open  │ ⚠ 60+ days   │
└──────────────────┴───────┴──────────────┴──────────┴───────────────┘

  5 clients  ·  Average score: 57  ·  29 open findings across portfolio
```

**Score colour coding**
- 75–100 = green
- 50–74 = amber
- 0–49 = red

**Trend indicators**
- Improved since last assessment = green arrow up
- Declined = red arrow down
- No previous assessment = dash
- Not assessed in 60+ days = amber warning

### What changes

**backend.py changes**
- `GET /sessions` already returns session list — extend to group by `clientName`
- New `GET /portfolio` route — aggregates latest session per client, calculates trend
- Session JSON needs a `clientName` field enforced at save time (currently optional)

**index.html changes**
- New `Portfolio` tab in the top navigation
- `renderPortfolio()` function — builds the table from `/portfolio` response
- Click row → calls existing `loadSession()` with that client's latest session
- Summary bar at bottom: total clients, average score, total open findings

**File storage**
No change — uses existing session JSON files in `output\`
The portfolio view is just a smarter read of what's already there.

### Technical effort: Medium (2–3 days)

---

## Feature 3 — Scheduled Assessments

### What it does
The MSP configures a schedule per client. The tool runs the assessment automatically
and emails the report when done.

### What the screen looks like

```
┌─────────────────────────────────────────────────────────────────────┐
│  SCHEDULED ASSESSMENTS                                              │
├─────────────────────────────────────────────────────────────────────┤
│  Client: Contoso Ltd                                                │
│  Frequency:  [Monthly ▼]    Day: [1st ▼]    Time: [08:00 ▼]        │
│  Auth:       [App Registration ▼]                                   │
│  Send report to: [client@contoso.com________________]               │
│  CC:             [malcolm@yourmsp.com_______________]               │
│                                                    [Save Schedule]  │
├─────────────────────────────────────────────────────────────────────┤
│  Active Schedules                                                   │
│  Contoso Ltd     · Monthly · Next run: 2026-06-01  [Edit] [Remove] │
│  Fabrikam Inc    · Weekly  · Next run: 2026-05-25  [Edit] [Remove] │
└─────────────────────────────────────────────────────────────────────┘
```

### What changes

**backend.py changes**
- New `POST /schedules` and `GET /schedules` routes
- Scheduler runs in a background thread (APScheduler library)
- On trigger: runs the relevant PowerShell assessment scripts, saves session, generates report, sends email via SMTP

**New dependency**
- `APScheduler` — Python job scheduler
- `smtplib` (stdlib) — email sending, or optionally SendGrid for reliability

**Settings needed**
- SMTP server, port, username, password (stored encrypted in settings.json)
- Or SendGrid API key for simpler setup

**Windows Task Scheduler alternative**
For simplicity in v2.0, generate a Windows Task Scheduler XML file instead of
running a Python scheduler — lower complexity, more reliable on Windows, no extra dependency.

### Technical effort: High (4–5 days) — recommend for v2.1 not v2.0

---

## V2.0 Scope (What to build first)

Keep v2.0 focused. Ship white-label + portfolio. That's the MSP value prop in two features.

| Feature | V2.0 | V2.1 |
|---|---|---|
| White-label reports | ✓ | |
| Multi-tenant portfolio dashboard | ✓ | |
| Scheduled assessments | | ✓ |
| Teams/email alerting on score drop | | ✓ |
| API/webhook integration | | ✓ |
| Custom finding thresholds per client | | ✓ |

---

## Landing Page (needed before selling)

GitHub is where developers go. MSPs need a proper page.
Minimum viable landing page:

1. **Hero** — "The M365 security assessment tool built for consultants"
2. **Screenshot** — dashboard + report side by side
3. **3 bullets** — White-label reports / Multi-client portfolio / Nothing leaves your machine
4. **Pricing table** — Community (free) / Pro (£X/month)
5. **Buy button** — Stripe checkout, delivers a licence key by email

Options for hosting: Carrd (£19/year, dead simple), Framer, or a basic HTML page on GitHub Pages.
Stripe handles payment + licence key delivery with no backend needed.

---

## Licence Key System (simple approach)

To gate Pro features without building a full auth system:

1. MSP buys via Stripe → webhook fires → generates a licence key → emails it to them
2. They enter the key in the Settings screen of the tool
3. `backend.py` validates the key against a simple hash (no internet call needed)
4. If valid, Pro features unlock

This keeps the tool fully local (no licence server to call home to) while still gating features.

---

## Recommended Build Order

1. Settings screen + branding config storage
2. White-label Word report (logo, colours, company name)
3. Enforce clientName on session save
4. Portfolio dashboard (backend route + frontend tab)
5. Licence key validation
6. Landing page + Stripe checkout
7. (v2.1) Scheduled assessments

---

## Competitive Positioning for V2 Pro

| | V2 Pro | ScubaGear | Purple Knight | Varonis |
|---|---|---|---|---|
| Price | £49–79/mo | Free | Free | £thousands/mo |
| UI | Web app | None | Desktop app | Web app |
| White-label reports | ✓ | ✗ | ✗ | ✓ |
| Multi-tenant portfolio | ✓ | ✗ | ✗ | ✓ |
| Attack path scoring | ✓ | ✗ | Partial | ✓ |
| Remediation + rollback | ✓ | ✗ | ✗ | ✓ |
| Data stays local | ✓ | ✓ | ✓ | ✗ |
| Built for MSPs | ✓ | ✗ | ✗ | ✗ |

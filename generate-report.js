/**
 * M365 Assessment Report Generator
 * M365 Assessment Toolkit
 *
 * Usage: node generate-report.js <input.json> <output.docx>
 *
 * Input JSON shape (from backend):
 * {
 *   clientName, assessDate, authMethod, score,
 *   findings: [{ id, title, module, severity, description, recommendation, observed_value }],
 *   metrics:  [{ label, value, status, sub }],
 *   rawMetrics: { metric_key: value, ... },
 *   modulesRun: number
 * }
 */

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, PageBreak, LevelFormat, ImageRun, PageNumber,
  TabStopType, TabStopLeader
} = require('docx');
const fs = require('fs');

// --- Colour palette ------------------------------------------------
// Helper - get consultant detail with fallback
function consultant(data, field, fallback) {
  return (data && data[field] && data[field].trim()) ? data[field].trim() : fallback;
}

// Helper - build logo paragraph from base64 data URL (PNG/JPG/SVG)
function buildLogoParagraph(dataUrl, opts = {}) {
  if (!dataUrl || !dataUrl.startsWith('data:')) return null;
  try {
    const [header, b64] = dataUrl.split(',');
    const imgBuffer = Buffer.from(b64, 'base64');
    const isSvg     = header.includes('svg');
    const w         = opts.width  || 220;  // pixels
    const h         = opts.height || 90;
    const align     = opts.align  || AlignmentType.CENTER;
    return new Paragraph({
      alignment: align,
      spacing: { before: opts.before ?? 0, after: opts.after ?? 240 },
      children: [new ImageRun({
        data: imgBuffer,
        transformation: { width: w, height: h },
        type: isSvg ? 'svg' : header.includes('png') ? 'png' : 'jpg',
      })],
    });
  } catch { return null; }
}

const COLOURS = {
  // Brand
  navy:        '1B2A4A',
  navyLight:   '2E4A7A',
  slate:       '4A5568',

  // Severity
  critical:    'C0392B',
  criticalBg:  'FDECEA',
  high:        'D35400',
  highBg:      'FEF0E7',
  medium:      'D4AC0D',
  mediumBg:    'FEFAE7',
  low:         '27AE60',
  lowBg:       'EAF7EE',

  // Status
  green:       '27AE60',
  greenBg:     'EAF7EE',
  amber:       'D4AC0D',
  amberBg:     'FEFAE7',
  red:         'C0392B',
  redBg:       'FDECEA',

  // Neutrals
  white:       'FFFFFF',
  offWhite:    'F8F9FA',
  lightGrey:   'F1F3F5',
  midGrey:     'DEE2E6',
  darkGrey:    '495057',
  black:       '212529',

  // Section accents
  execAccent:  '2E4A7A',
  scoreAccent: '1B2A4A',
};

// --- Border helpers ------------------------------------------------
const border  = (colour = COLOURS.midGrey, size = 4) =>
  ({ style: BorderStyle.SINGLE, size, color: colour });
const noBorder = { style: BorderStyle.NONE, size: 0, color: COLOURS.white };
const allBorders = (colour, size) => ({
  top: border(colour, size), bottom: border(colour, size),
  left: border(colour, size), right: border(colour, size)
});
const noBorders = { top: noBorder, bottom: noBorder, left: noBorder, right: noBorder };

// --- Severity config -----------------------------------------------
const SEV = {
  critical: { label: 'CRITICAL', colour: COLOURS.critical, bg: COLOURS.criticalBg, score: 15 },
  high:     { label: 'HIGH',     colour: COLOURS.high,     bg: COLOURS.highBg,     score: 10 },
  medium:   { label: 'MEDIUM',   colour: COLOURS.medium,   bg: COLOURS.mediumBg,   score: 5  },
  low:      { label: 'LOW',      colour: COLOURS.low,      bg: COLOURS.lowBg,      score: 2  },
};

// Framework labels and known library totals (findings that map to each framework)
const FW_LABELS = {
  cis:  'CIS M365 v7.0.0',
  nist: 'NIST CSF 2.0',
  iso:  'ISO 27001:2022',
  ce:   'Cyber Essentials v3.3',
  soc2: 'SOC 2 CC6/CC7',
  caf:  'NCSC CAF v4.0',
  e8:   'Essential Eight',
  nis2: 'EU NIS2 Art.21',
};
// FW_TOTALS: hardcoded fallback only — backend now injects data.fwTotals computed
// dynamically from FRAMEWORK_MAPPING, so these numbers auto-update when new findings
// are added (v1.6+). This constant is only used if fwTotals is missing from data.
const FW_TOTALS = { cis: 42, nist: 48, iso: 48, ce: 46, soc2: 48, caf: 48, e8: 34, nis2: 48 };

const STATUS_COLOUR = {
  good: COLOURS.green,
  warn: COLOURS.amber,
  bad:  COLOURS.red,
};

// --- Typography helpers --------------------------------------------
const run = (text, opts = {}) => new TextRun({
  text,
  font: 'Arial',
  size: opts.size || 22,          // 11pt default
  bold: opts.bold || false,
  italics: opts.italic || false,
  color: opts.colour || COLOURS.black,
  ...(opts.extra || {}),
});

const para = (children, opts = {}) => new Paragraph({
  children: Array.isArray(children) ? children : [children],
  alignment: opts.align || AlignmentType.LEFT,
  spacing: {
    before: opts.before !== undefined ? opts.before : 80,
    after:  opts.after  !== undefined ? opts.after  : 80,
    line:   opts.line   || 276,
  },
  ...(opts.extra || {}),
});

const heading1 = (text, colour = COLOURS.navy) => new Paragraph({
  heading: HeadingLevel.HEADING_1,
  children: [new TextRun({ text, font: 'Arial', size: 36, bold: true, color: colour })],
  spacing: { before: 360, after: 180 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: colour, space: 4 } },
});

const heading2 = (text, colour = COLOURS.navyLight) => new Paragraph({
  heading: HeadingLevel.HEADING_2,
  children: [new TextRun({ text, font: 'Arial', size: 28, bold: true, color: colour })],
  spacing: { before: 240, after: 120 },
});

const spacer = (lines = 1) => new Paragraph({
  children: [new TextRun('')],
  spacing: { before: 0, after: lines * 120 },
});

// --- Cell helpers -------------------------------------------------
const cell = (children, opts = {}) => new TableCell({
  children: Array.isArray(children) ? children : [children],
  width: opts.width ? { size: opts.width, type: WidthType.DXA } : undefined,
  shading: opts.bg ? { fill: opts.bg, type: ShadingType.CLEAR } : undefined,
  borders: opts.borders || allBorders(COLOURS.midGrey, 4),
  margins: { top: 100, bottom: 100, left: 140, right: 140 },
  verticalAlign: opts.vAlign || VerticalAlign.CENTER,
  columnSpan: opts.span,
});

// --- Page break ---------------------------------------------------
const pageBreak = () => new Paragraph({
  children: [new PageBreak()],
  spacing: { before: 0, after: 0 },
});

// -----------------------------------------------------------------
//  SECTION BUILDERS
// -----------------------------------------------------------------

/** Cover page */
function buildCoverPage(data) {
  const dateStr     = data.assessDate || new Date().toISOString().split('T')[0];
  const consultRole = consultant(data, 'consultantRole', '');

  const logoCentered = buildLogoParagraph(data.consultantLogo, { width: 220, height: 90, align: AlignmentType.CENTER, before: 0, after: 320 });

  return [
    spacer(logoCentered ? 2 : 4),
    // Company logo — centred above title
    ...(logoCentered ? [logoCentered] : []),
    // Title block
    new Paragraph({
      children: [new TextRun({
        text: 'Microsoft 365', font: 'Arial', size: 64, bold: true, color: COLOURS.navy,
      })],
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 60 },
    }),
    new Paragraph({
      children: [new TextRun({
        text: 'Health Assessment', font: 'Arial', size: 64, bold: true, color: COLOURS.navyLight,
      })],
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 480 },
    }),
    // Divider rule
    new Paragraph({
      children: [new TextRun({ text: '', font: 'Arial', size: 4 })],
      border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: COLOURS.navy, space: 1 } },
      spacing: { before: 0, after: 480 },
    }),
    // Client name
    new Paragraph({
      children: [new TextRun({ text: data.clientName, font: 'Arial', size: 48, bold: true, color: COLOURS.slate })],
      alignment: AlignmentType.CENTER,
      spacing: { before: 0, after: 160 },
    }),
    para([run(dateStr, { size: 24, colour: COLOURS.darkGrey })], { align: AlignmentType.CENTER, before: 0, after: 80 }),
    para([run(`Assessment conducted by ${consultant(data,'consultantName','[Consultant Name]')}`, { size: 22, colour: COLOURS.darkGrey })], { align: AlignmentType.CENTER, before: 0, after: 60 }),
    ...(consultRole ? [para([run(consultRole, { size: 22, colour: COLOURS.slate, italic: true })], { align: AlignmentType.CENTER, before: 0, after: 60 })] : []),
    para([run(`${consultant(data,'consultantEmail','[Email]')}`, { size: 22, colour: COLOURS.navyLight })], { align: AlignmentType.CENTER, before: 0, after: 0 }),
    spacer(2),
    // Confidentiality notice
    new Paragraph({
      children: [new TextRun({ text: 'CONFIDENTIAL — For authorised recipients only', font: 'Arial', size: 18, italic: true, color: COLOURS.slate })],
      alignment: AlignmentType.CENTER,
      border: {
        top: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey, space: 6 },
        bottom: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey, space: 6 },
      },
      spacing: { before: 120, after: 120 },
    }),
    spacer(1),
    // Version footer
    para([
      run(`Tool v${data.toolVersion || '—'}`, { size: 16, colour: COLOURS.midGrey }),
      run(`  ·  Findings library: ${data.findingsLastUpdated || '—'}`, { size: 16, colour: COLOURS.midGrey }),
      run(`  ·  CIS M365 v7.0  ·  NIST CSF 2.0  ·  ISO 27001:2022  ·  NCSC CAF v4.0`, { size: 16, colour: COLOURS.midGrey }),
    ], { align: AlignmentType.CENTER, before: 0, after: 0 }),
    pageBreak(),
  ];
}

/** Overall score banner - big coloured block */
function buildScoreBanner(score) {
  const colour = score >= 90 ? COLOURS.green : score >= 75 ? COLOURS.green : score >= 60 ? COLOURS.amber : score >= 40 ? COLOURS.orange : COLOURS.red;
  const bg     = score >= 90 ? COLOURS.greenBg : score >= 75 ? COLOURS.greenBg : score >= 60 ? COLOURS.amberBg : score >= 40 ? COLOURS.amberBg : COLOURS.redBg;
  const label  = score >= 90 ? 'Excellent' : score >= 75 ? 'Good' : score >= 60 ? 'Fair' : score >= 40 ? 'Poor' : 'Critical Risk';

  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [9360],
    rows: [new TableRow({ children: [
      new TableCell({
        children: [
          new Paragraph({
            children: [
              new TextRun({ text: `${score}`, font: 'Arial', size: 96, bold: true, color: colour }),
              new TextRun({ text: ` / 100  `, font: 'Arial', size: 48, color: colour }),
              new TextRun({ text: `- ${label}`, font: 'Arial', size: 40, bold: false, color: colour }),
            ],
            alignment: AlignmentType.CENTER,
            spacing: { before: 200, after: 200 },
          }),
        ],
        shading: { fill: bg, type: ShadingType.CLEAR },
        borders: {
          top: border(colour, 16), bottom: border(colour, 16),
          left: border(colour, 16), right: border(colour, 16),
        },
        margins: { top: 200, bottom: 200, left: 200, right: 200 },
      }),
    ]}),
  ]});
}

/** Findings summary counts table (Critical / High / Medium / Low) */
function buildFindingsCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

  const colW = 2340; // 4 equal cols in 9360
  const headerRow = new TableRow({
    children: ['Critical', 'High', 'Medium', 'Low'].map((label, i) => {
      const sev = label.toLowerCase();
      return new TableCell({
        children: [para([run(label, { bold: true, colour: COLOURS.white, size: 22 })], { align: AlignmentType.CENTER, before: 60, after: 60 })],
        width: { size: colW, type: WidthType.DXA },
        shading: { fill: SEV[sev].colour, type: ShadingType.CLEAR },
        borders: noBorders,
        margins: { top: 80, bottom: 80, left: 120, right: 120 },
      });
    }),
  });

  const countRow = new TableRow({
    children: ['critical', 'high', 'medium', 'low'].map(sev => new TableCell({
      children: [new Paragraph({
        children: [new TextRun({ text: String(counts[sev]), font: 'Arial', size: 64, bold: true, color: SEV[sev].colour })],
        alignment: AlignmentType.CENTER,
        spacing: { before: 120, after: 120 },
      })],
      width: { size: colW, type: WidthType.DXA },
      shading: { fill: SEV[sev].bg, type: ShadingType.CLEAR },
      borders: { top: border(SEV[sev].colour, 8), bottom: border(SEV[sev].colour, 4), left: noBorder, right: noBorder },
      margins: { top: 60, bottom: 60, left: 120, right: 120 },
    })),
  });

  return new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [colW, colW, colW, colW], rows: [headerRow, countRow] });
}

/** Executive summary section */
function buildExecSummary(data) {
  const findings  = data.findings || [];
  const critical  = findings.filter(f => f.severity === 'critical').length;
  const high      = findings.filter(f => f.severity === 'high').length;
  const score     = data.score || 0;
  const scoreText = score >= 90 ? 'a strong overall security posture' : score >= 75 ? 'a good overall security posture with minor gaps' : score >= 60 ? 'a number of notable gaps requiring attention' : score >= 40 ? 'significant vulnerabilities requiring prioritised remediation' : 'critical security risks requiring immediate action';

  const topFindings = findings
    .filter(f => ['critical','high'].includes(f.severity))
    .slice(0, 3);

  return [
    heading1('1. Executive Summary'),
    para([
      run(`This report presents the findings of a Microsoft 365 health assessment carried out for `),
      run(data.clientName, { bold: true }),
      run(`. The assessment covered ${data.modulesRun} workloads including identity and access management, security configuration, email security, collaboration tools, device management, and licensing.`),
    ], { before: 120, after: 160, line: 300 }),

    para([
      run(`The overall score for this tenant is `),
      run(`${score} out of 100`, { bold: true }),
      run(`, indicating ${scoreText}. A total of `),
      run(`${findings.length} findings`, { bold: true }),
      run(` were identified across all workloads assessed.`),
    ], { before: 0, after: 160, line: 300 }),

    spacer(1),
    buildFindingsCounts(findings),
    spacer(1),

    ...(critical + high > 0 ? [
      heading2('Key Risks Requiring Immediate Attention', COLOURS.critical),
      ...topFindings.map(f => new Paragraph({
        numbering: { reference: 'numbers', level: 0 },
        children: [
          run(`${f.title} - `, { bold: true }),
          run(f.description),
        ],
        spacing: { before: 80, after: 80, line: 300 },
      })),
      spacer(1),
    ] : []),

    // Positioning statement - beyond Secure Score
    new Paragraph({
      children: [new TextRun({ text: 'Beyond Microsoft Secure Score', font: 'Arial', size: 22, bold: true, color: COLOURS.navyLight })],
      spacing: { before: 240, after: 100 },
      border: { left: { style: BorderStyle.SINGLE, size: 16, color: COLOURS.navyLight, space: 8 } },
      indent: { left: 200 },
    }),
    new Paragraph({
      children: [new TextRun({
        text: 'Microsoft Secure Score measures configuration compliance - whether recommended settings are turned on. It does not evaluate whether those settings protect against real-world attack paths. A tenant can achieve a high Secure Score and still be vulnerable to business email compromise, OAuth app abuse, and lateral movement.',
        font: 'Arial', size: 22, color: COLOURS.black,
      })],
      spacing: { before: 80, after: 100, line: 300 },
      indent: { left: 200 },
    }),
    new Paragraph({
      children: [new TextRun({
        text: 'This assessment goes beyond Secure Score by evaluating real attack paths - not just configuration checkboxes. Each finding in this report represents a genuine risk that an attacker could exploit, regardless of what your Secure Score shows.',
        font: 'Arial', size: 22, bold: false, color: COLOURS.black,
      })],
      spacing: { before: 0, after: 120, line: 300 },
      indent: { left: 200 },
    }),
    para([run('Detailed findings, technical context, and prioritised recommendations are provided in the sections that follow. A full metrics appendix is included at the end of this report.')], { before: 120, after: 0, line: 300 }),
    pageBreak(),
  ];
}

/** Overall score section */
function buildScoreSection(data) {
  const score    = data.score || 0;
  const findings = data.findings || [];

  return [
    heading1('2. Overall Score'),
    para([run(`The score starts at 100 and is reduced by triggered findings: Critical (−8 each, max −32), High (−5 each, max −20), Medium (−3 each, max −12), Low (−1 each, max −4). Penalties are capped per severity band so a single category cannot dominate the score. The minimum possible score is 10. Findings marked Accepted Risk, False Positive or Not Applicable are excluded from the calculation.`)], { before: 120, after: 200, line: 300 }),
    buildScoreBanner(score),
    spacer(1),
    buildFindingsCounts(findings),
    spacer(1),

    // Score interpretation table
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [2000, 3000, 4360],
      rows: [
        new TableRow({ children: [
          cell(para([run('Score Range', { bold: true, colour: COLOURS.white })], { align: AlignmentType.CENTER }), { width: 2000, bg: COLOURS.navy, borders: noBorders }),
          cell(para([run('Rating', { bold: true, colour: COLOURS.white })], { align: AlignmentType.CENTER }), { width: 3000, bg: COLOURS.navy, borders: noBorders }),
          cell(para([run('Meaning', { bold: true, colour: COLOURS.white })]), { width: 4360, bg: COLOURS.navy, borders: noBorders }),
        ]}),
        ...([
          ['90 - 100', 'Excellent',       COLOURS.greenBg, COLOURS.green,  'Strong security posture — minimal risk exposure.'],
          ['75 - 89',  'Good',            COLOURS.greenBg, COLOURS.green,  'Well-managed risk with minor gaps to address.'],
          ['60 - 74',  'Fair',            COLOURS.amberBg, COLOURS.amber,  'Notable gaps present — a remediation plan should be agreed and acted on.'],
          ['40 - 59',  'Poor',            COLOURS.amberBg, COLOURS.orange, 'Significant vulnerabilities present — prioritise remediation immediately.'],
          ['0 - 39',   'Critical Risk',   COLOURS.redBg,   COLOURS.red,   'Immediate action required — high exposure to attack and breach risk.'],
        ].map(([range, rating, bg, colour, meaning]) =>
          new TableRow({ children: [
            cell(para([run(range, { bold: true, colour })], { align: AlignmentType.CENTER }), { width: 2000, bg }),
            cell(para([run(rating, { bold: true, colour })], { align: AlignmentType.CENTER }), { width: 3000, bg }),
            cell(para([run(meaning, { colour: COLOURS.black })]), { width: 4360 }),
          ]})
        )),
      ],
    }),
    pageBreak(),
  ];
}

/** Individual finding card */
function buildFindingCard(f, index) {
  const sev    = SEV[f.severity] || SEV.low;
  const colW1  = 1800;
  const colW2  = 7560;

  return [
    // Finding header row
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [colW1, colW2],
      rows: [
        new TableRow({ children: [
          // Severity badge cell
          new TableCell({
            children: [
              para([run(sev.label, { bold: true, colour: COLOURS.white, size: 20 })], { align: AlignmentType.CENTER, before: 60, after: 40 }),
              para([run(f.id, { colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 0, after: 60 }),
            ],
            width: { size: colW1, type: WidthType.DXA },
            shading: { fill: sev.colour, type: ShadingType.CLEAR },
            borders: noBorders,
            margins: { top: 100, bottom: 100, left: 120, right: 120 },
            verticalAlign: VerticalAlign.CENTER,
          }),
          // Title cell
          new TableCell({
            children: [
              para([run(f.title, { bold: true, colour: COLOURS.navy, size: 26 })], { before: 80, after: 60 }),
              para([run(`Module: ${f.module.charAt(0).toUpperCase() + f.module.slice(1)}  |  Observed value: ${f.observed_value}`, { colour: COLOURS.slate, size: 18 })], { before: 0, after: 80 }),
            ],
            width: { size: colW2, type: WidthType.DXA },
            shading: { fill: sev.bg, type: ShadingType.CLEAR },
            borders: { top: noBorder, bottom: noBorder, left: border(sev.colour, 16), right: noBorder },
            margins: { top: 80, bottom: 80, left: 160, right: 140 },
          }),
        ]}),
        // Description + Recommendation rows
        new TableRow({ children: [
          cell(para([run('What this means', { bold: true, colour: COLOURS.slate, size: 19 })], { align: AlignmentType.CENTER, before: 60, after: 60 }), { width: colW1, bg: COLOURS.lightGrey, borders: allBorders(COLOURS.midGrey, 4) }),
          cell(para([run(f.description, { colour: COLOURS.black, size: 22 })], { before: 80, after: 80, line: 300 }), { width: colW2 }),
        ]}),
        ...(f.severity_reason ? [new TableRow({ children: [
          cell(para([run('Why this severity', { bold: true, colour: COLOURS.slate, size: 19 })], { align: AlignmentType.CENTER, before: 60, after: 60 }), { width: colW1, bg: COLOURS.lightGrey, borders: allBorders(COLOURS.midGrey, 4) }),
          cell(para([run(f.severity_reason, { colour: COLOURS.darkGrey, size: 20, italics: true })], { before: 60, after: 60, line: 300 }), { width: colW2 }),
        ]})] : []),
        new TableRow({ children: [
          cell(para([run('Recommendation', { bold: true, colour: COLOURS.navyLight, size: 19 })], { align: AlignmentType.CENTER, before: 60, after: 60 }), { width: colW1, bg: COLOURS.offWhite, borders: allBorders(COLOURS.midGrey, 4) }),
          cell(para([run(f.recommendation, { colour: COLOURS.black, size: 22 })], { before: 80, after: 80, line: 300 }), { width: colW2 }),
        ]}),
        ...(f.effort ? [new TableRow({ children: [
          cell(para([run('Remediation effort', { bold: true, colour: COLOURS.navyLight, size: 19 })], { align: AlignmentType.CENTER, before: 60, after: 60 }), { width: colW1, bg: COLOURS.offWhite, borders: allBorders(COLOURS.midGrey, 4) }),
          cell(para([run(`${f.effort} · ~${f.effort_hours || '?'}h estimated`, { colour: COLOURS.darkGrey, size: 20 })], { before: 60, after: 60, line: 300 }), { width: colW2 }),
        ]})] : []),
      ],
    }),
    spacer(1),
  ];
}

/** Full findings section grouped by severity */
function buildFindingsSection(data) {
  const findings = data.findings || [];
  if (findings.length === 0) {
    return [
      heading1('3. Findings'),
      para([run('No findings were triggered for this tenant. The assessed configuration meets all checked thresholds.', { colour: COLOURS.green, bold: true })], { before: 120 }),
      pageBreak(),
    ];
  }

  const order = ['critical', 'high', 'medium', 'low'];
  const grouped = {};
  order.forEach(s => { grouped[s] = findings.filter(f => f.severity === s); });

  const content = [heading1('3. Findings')];

  order.forEach(sev => {
    if (grouped[sev].length === 0) return;
    const sevCfg = SEV[sev];
    content.push(
      new Paragraph({
        children: [new TextRun({ text: `${sevCfg.label}  (${grouped[sev].length})`, font: 'Arial', size: 28, bold: true, color: sevCfg.colour })],
        spacing: { before: 240, after: 160 },
        border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: sevCfg.colour, space: 4 } },
      })
    );
    grouped[sev].forEach((f, i) => content.push(...buildFindingCard(f, i)));
  });

  content.push(pageBreak());
  return content;
}

/** Prioritised recommendations table */
function buildRecommendationsSection(data) {
  const findings  = data.findings || [];
  const sorted    = [...findings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
  });

  // effort and effort_hours now come directly from finding data

  const headerRow = new TableRow({
    tableHeader: true,
    children: ['#', 'Finding', 'Severity', 'Effort', 'Recommendation'].map((h, i) => {
      const widths = [400, 2200, 1100, 900, 4760];
      return new TableCell({
        children: [para([run(h, { bold: true, colour: COLOURS.white, size: 20 })], { align: AlignmentType.CENTER, before: 80, after: 80 })],
        width: { size: widths[i], type: WidthType.DXA },
        shading: { fill: COLOURS.navy, type: ShadingType.CLEAR },
        borders: noBorders,
        margins: { top: 80, bottom: 80, left: 120, right: 120 },
      });
    }),
  });

  const dataRows = sorted.map((f, i) => {
    const sev    = SEV[f.severity] || SEV.low;
    const effort = f.effort || 'Medium';
    const effortLabel = f.effort_hours ? `${effort} (~${f.effort_hours}h)` : effort;
    const widths = [400, 2200, 1100, 900, 4760];
    const rowBg  = i % 2 === 0 ? COLOURS.white : COLOURS.offWhite;
    return new TableRow({ children: [
      cell(para([run(String(i + 1), { bold: true, colour: COLOURS.slate, size: 20 })], { align: AlignmentType.CENTER }), { width: widths[0], bg: rowBg }),
      cell(para([run(f.title, { colour: COLOURS.navy, size: 20, bold: true })]), { width: widths[1], bg: rowBg }),
      cell(new Paragraph({
        children: [new TextRun({ text: sev.label, font: 'Arial', size: 18, bold: true, color: sev.colour })],
        alignment: AlignmentType.CENTER,
        spacing: { before: 60, after: 60 },
      }), { width: widths[2], bg: sev.bg }),
      cell(para([run(effortLabel, { colour: COLOURS.darkGrey, size: 20 })], { align: AlignmentType.CENTER }), { width: widths[3], bg: rowBg }),
      cell(para([run(f.recommendation, { colour: COLOURS.black, size: 20 })], { before: 60, after: 60, line: 300 }), { width: widths[4], bg: rowBg }),
    ]});
  });

  return [
    heading1('4. Recommendations'),
    para([run(`The table below summarises all findings in priority order with recommended actions. Items marked Low effort can typically be resolved within a single working session. Medium effort items may require planning or change management approval.`)], { before: 120, after: 200, line: 300 }),
    new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [400, 2200, 1100, 900, 4760], rows: [headerRow, ...dataRows] }),
    pageBreak(),
  ];
}


/** Remediation Log section */
function buildRemediationSection(data) {
  const remLog = data.remediationLog || [];
  if (remLog.length === 0) return [];

  // Group by finding ID - get latest action per finding
  const byFinding = {};
  remLog.forEach(entry => {
    const fid = entry.findingId;
    if (!fid) return;
    if (!byFinding[fid] || entry.timestamp > byFinding[fid].latestTimestamp) {
      if (!byFinding[fid]) byFinding[fid] = { entries: [] };
      byFinding[fid].latestTimestamp = entry.timestamp;
      byFinding[fid].latestAction = entry.action;
    }
    byFinding[fid].entries.push(entry);
  });

  const remediatedIds = Object.keys(byFinding).filter(id => byFinding[id].latestAction === 'remediate');
  const rolledBackIds = Object.keys(byFinding).filter(id => byFinding[id].latestAction === 'rollback');

  const headerRow = new TableRow({
    tableHeader: true,
    children: ['Finding ID', 'Title', 'Action', 'Date / Time', 'Details'].map((h, i) => {
      const widths = [800, 2500, 1000, 1800, 3260];
      return new TableCell({
        children: [para([run(h, { bold: true, colour: COLOURS.white, size: 20 })], { before: 80, after: 80 })],
        width: { size: widths[i], type: WidthType.DXA },
        shading: { fill: COLOURS.navy, type: ShadingType.CLEAR },
        borders: noBorders,
        margins: { top: 80, bottom: 80, left: 120, right: 120 },
      });
    }),
  });

  const dataRows = remLog.map((entry, i) => {
    const isRemediate = entry.action === 'remediate';
    const isRollback  = entry.action === 'rollback';
    const actionColour = isRemediate ? COLOURS.green : isRollback ? COLOURS.amber : COLOURS.slate;
    const actionLabel  = isRemediate ? 'Remediated' : isRollback ? 'Rolled Back' : entry.action;
    const rowBg = i % 2 === 0 ? COLOURS.white : COLOURS.offWhite;
    const dateStr = entry.timestamp ? new Date(entry.timestamp).toLocaleString('en-GB') : '-';
    const widths = [800, 2500, 1000, 1800, 3260];

    // Find matching finding title
    const finding = (data.findings || []).find(f => f.id === entry.findingId);
    const title = finding ? finding.title : entry.findingId;

    return new TableRow({ children: [
      cell(para([run(entry.findingId || '-', { colour: COLOURS.navy, size: 18, bold: true })]), { width: widths[0], bg: rowBg }),
      cell(para([run(title, { colour: COLOURS.black, size: 18 })], { before: 60, after: 60, line: 280 }), { width: widths[1], bg: rowBg }),
      cell(new Paragraph({
        children: [new TextRun({ text: actionLabel, font: 'Arial', size: 18, bold: true, color: actionColour })],
        alignment: AlignmentType.CENTER,
        spacing: { before: 60, after: 60 },
      }), { width: widths[2], bg: isRemediate ? COLOURS.greenBg : isRollback ? COLOURS.amberBg : rowBg }),
      cell(para([run(dateStr, { colour: COLOURS.slate, size: 17 })], { before: 60, after: 60 }), { width: widths[3], bg: rowBg }),
      cell(para([run(entry.details || (entry.success ? 'Success' : 'Failed'), { colour: COLOURS.black, size: 17 })], { before: 60, after: 60, line: 280 }), { width: widths[4], bg: rowBg }),
    ]});
  });

  const summaryText = `${remediatedIds.length} finding(s) remediated` +
    (rolledBackIds.length > 0 ? `, ${rolledBackIds.length} rolled back` : '') +
    '. All changes were snapshotted before being applied and can be reversed.';

  return [
    heading1('5. Remediation Log'),
    para([run('The following changes were made to the tenant configuration during this engagement. Each change was preceded by a pre-remediation check and a snapshot of the previous state.')], { before: 120, after: 160, line: 300 }),
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [800, 2500, 1000, 1800, 3260],
      rows: [headerRow, ...dataRows],
    }),
    spacer(1),
    para([
      run('Summary: ', { bold: true }),
      run(summaryText, { colour: COLOURS.slate }),
    ], { before: 0, after: 0 }),
    pageBreak(),
  ];
}

/** Metrics appendix - full raw data */
function buildAppendix(data) {
  const metrics = data.metrics || [];

  const headerRow = new TableRow({
    tableHeader: true,
    children: ['Metric', 'Value', 'Status'].map((h, i) => {
      const widths = [4000, 3000, 2360];
      return new TableCell({
        children: [para([run(h, { bold: true, colour: COLOURS.white, size: 20 })], { before: 80, after: 80 })],
        width: { size: widths[i], type: WidthType.DXA },
        shading: { fill: COLOURS.slate, type: ShadingType.CLEAR },
        borders: noBorders,
        margins: { top: 80, bottom: 80, left: 120, right: 120 },
      });
    }),
  });

  const dataRows = metrics.map((m, i) => {
    const statusColour = STATUS_COLOUR[m.status] || COLOURS.slate;
    const statusLabel  = m.status === 'good' ? 'PASS' : m.status === 'warn' ? 'REVIEW' : 'FAIL';
    const statusBg     = m.status === 'good' ? COLOURS.greenBg : m.status === 'warn' ? COLOURS.amberBg : COLOURS.redBg;
    const rowBg        = i % 2 === 0 ? COLOURS.white : COLOURS.offWhite;
    const widths       = [4000, 3000, 2360];
    return new TableRow({ children: [
      cell(para([run(m.label, { colour: COLOURS.navy, size: 20 })]), { width: widths[0], bg: rowBg }),
      cell(para([run(String(m.value), { colour: COLOURS.black, size: 20, bold: true })]), { width: widths[1], bg: rowBg }),
      cell(new Paragraph({
        children: [new TextRun({ text: statusLabel, font: 'Arial', size: 18, bold: true, color: statusColour })],
        alignment: AlignmentType.CENTER,
        spacing: { before: 60, after: 60 },
      }), { width: widths[2], bg: statusBg }),
    ]});
  });

  return [
    heading1('Appendix - Full Metrics Data'),
    para([run(`This appendix contains the raw metric values collected during the assessment. These values form the basis of the findings and scoring in the main report.`)], { before: 120, after: 200, line: 300 }),
    new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [4000, 3000, 2360], rows: [headerRow, ...dataRows] }),
    spacer(2),
    para([run(`Assessment completed: ${data.assessDate || '-'}`, { colour: COLOURS.slate, size: 20 })], { before: 0, after: 60 }),
    para([run(`Authentication method: ${data.authMethod === 'appreg' ? 'App Registration' : 'Interactive Login'}`, { colour: COLOURS.slate, size: 20 })], { before: 0, after: 60 }),
    para([run(`Prepared by: M365 Assessment Toolkit  |  [consultant@email.com]`, { colour: COLOURS.slate, size: 20, italic: true })], { before: 0, after: 0 }),
  ];
}

// --- Header / Footer ----------------------------------------------
function buildHeader(clientName) {
  return new Header({
    children: [
      new Paragraph({
        children: [
          new TextRun({ text: `${clientName}  |  M365 Health Assessment  |  CONFIDENTIAL`, font: 'Arial', size: 18, color: COLOURS.slate, bold: false }),
        ],
        border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey, space: 4 } },
        spacing: { before: 0, after: 80 },
      }),
    ],
  });
}

function buildFooter(data) {
  const email = consultant(data, 'consultantEmail', '');
  const leftText = email
    ? `M365 Assessment Toolkit  |  ${email}`
    : 'M365 Assessment Toolkit';
  return new Footer({
    children: [
      new Paragraph({
        children: [
          new TextRun({ text: leftText, font: 'Arial', size: 16, color: COLOURS.slate }),
          new TextRun({ children: ['\t', 'Page ', PageNumber.CURRENT, ' of ', PageNumber.TOTAL_PAGES], font: 'Arial', size: 16, color: COLOURS.slate }),
        ],
        tabStops: [{ type: TabStopType.RIGHT, position: 9360 }],
        border: { top: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey, space: 4 } },
        spacing: { before: 80, after: 0 },
      }),
    ],
  });
}

// --- Main builder -------------------------------------------------
/** Framework compliance summary section */
function buildFrameworkSection(data) {
  const findings  = data.findings || [];
  const active    = data.activeFrameworks || Object.keys(FW_LABELS);
  if (!active.length) return [];

  // Build rows: one per active framework
  const colWidths = [2400, 1400, 1400, 1400, 2760];

  const headerRow = new TableRow({
    tableHeader: true,
    children: [
      'Framework', 'Checks in library', 'Gaps found', 'Passing', 'Status',
    ].map((label, i) => new TableCell({
      children: [para([run(label, { bold: true, colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 80, after: 80 })],
      shading: { fill: COLOURS.navy, type: ShadingType.CLEAR },
      borders: allBorders(COLOURS.navyLight, 4),
      width: { size: colWidths[i], type: WidthType.DXA },
      verticalAlign: VerticalAlign.CENTER,
      margins: { top: 60, bottom: 60, left: 120, right: 120 },
    })),
  });

  const dataRows = active.map(fw => {
    const label    = FW_LABELS[fw] || fw;
    const total    = (data.fwTotals && data.fwTotals[fw]) || FW_TOTALS[fw] || '—';
    const gaps     = findings.filter(f => f.frameworks && f.frameworks[fw]).length;
    const passing  = typeof total === 'number' ? total - gaps : '—';
    const passPct  = typeof total === 'number' ? Math.round((passing / total) * 100) : null;
    const statusTxt = passPct === null ? '—'
      : passPct >= 90 ? 'Good standing'
      : passPct >= 70 ? 'Needs attention'
      : 'Significant gaps';
    const statusCol = passPct === null ? COLOURS.slate
      : passPct >= 90 ? COLOURS.green
      : passPct >= 70 ? COLOURS.amber
      : COLOURS.red;
    const statusBg  = passPct === null ? COLOURS.lightGrey
      : passPct >= 90 ? COLOURS.greenBg
      : passPct >= 70 ? COLOURS.amberBg
      : COLOURS.redBg;

    const cells = [
      new TableCell({
        children: [para([run(label, { bold: true, size: 20 })], { before: 80, after: 80 })],
        borders: allBorders(COLOURS.midGrey, 4),
        width: { size: colWidths[0], type: WidthType.DXA },
        margins: { top: 60, bottom: 60, left: 120, right: 120 },
      }),
      new TableCell({
        children: [para([run(String(total), { size: 20 })], { align: AlignmentType.CENTER, before: 80, after: 80 })],
        borders: allBorders(COLOURS.midGrey, 4),
        width: { size: colWidths[1], type: WidthType.DXA },
        margins: { top: 60, bottom: 60, left: 80, right: 80 },
      }),
      new TableCell({
        children: [para([run(String(gaps), { bold: gaps > 0, colour: gaps > 0 ? COLOURS.red : COLOURS.green, size: 20 })],
          { align: AlignmentType.CENTER, before: 80, after: 80 })],
        borders: allBorders(COLOURS.midGrey, 4),
        width: { size: colWidths[2], type: WidthType.DXA },
        margins: { top: 60, bottom: 60, left: 80, right: 80 },
      }),
      new TableCell({
        children: [para([run(passPct !== null ? `${passing} (${passPct}%)` : '—', { size: 20 })],
          { align: AlignmentType.CENTER, before: 80, after: 80 })],
        borders: allBorders(COLOURS.midGrey, 4),
        width: { size: colWidths[3], type: WidthType.DXA },
        margins: { top: 60, bottom: 60, left: 80, right: 80 },
      }),
      new TableCell({
        children: [para([run(statusTxt, { bold: true, colour: statusCol, size: 20 })],
          { align: AlignmentType.CENTER, before: 80, after: 80 })],
        shading: { fill: statusBg, type: ShadingType.CLEAR },
        borders: allBorders(COLOURS.midGrey, 4),
        width: { size: colWidths[4], type: WidthType.DXA },
        margins: { top: 60, bottom: 60, left: 120, right: 120 },
      }),
    ];
    return new TableRow({ children: cells });
  });

  // Consolidated gap detail — one row per finding, all framework obligations in one column
  const sevOrder      = { critical: 0, high: 1, medium: 2, low: 3 };
  const gapColWidths  = [900, 1000, 4560, 2900];
  const allGapFindings = findings
    .filter(f => active.some(fw => f.frameworks && f.frameworks[fw]))
    .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

  const gapDetailSection = allGapFindings.length === 0 ? [] : (() => {
    const gapHdr = new TableRow({
      tableHeader: true,
      children: ['Severity', 'Finding ID', 'Finding & Recommendation', 'Framework Obligations'].map((h, i) =>
        new TableCell({
          children: [para([run(h, { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })],
          shading: { fill: COLOURS.navy, type: ShadingType.CLEAR },
          borders: allBorders(COLOURS.navyLight, 4),
          width: { size: gapColWidths[i], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 100, right: 100 },
        })
      ),
    });

    const gapRows = allGapFindings.map((f, idx) => {
      const sev   = SEV[f.severity] || SEV.medium;
      const rowBg = idx % 2 === 0 ? COLOURS.offWhite : COLOURS.white;

      // Each active framework this finding maps to — one paragraph per framework
      const fwParas = active
        .filter(fw => f.frameworks && f.frameworks[fw])
        .map(fw => {
          const d   = f.frameworks[fw];
          const ref = d.id ? `${FW_LABELS[fw] || fw}: ${d.id}` : (FW_LABELS[fw] || fw);
          return para([run(ref, { size: 16, colour: COLOURS.slate })], { before: 20, after: 20, line: 240 });
        });

      return new TableRow({ children: [
        new TableCell({
          children: [para([run(sev.label, { bold: true, colour: sev.colour, size: 16 })], { before: 60, after: 60 })],
          shading: { fill: sev.bg, type: ShadingType.CLEAR },
          borders: allBorders(COLOURS.midGrey, 4),
          width: { size: gapColWidths[0], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 80, right: 80 },
        }),
        new TableCell({
          children: [para([run(f.id, { size: 17, colour: COLOURS.navy, bold: true })], { before: 60, after: 60 })],
          shading: { fill: rowBg, type: ShadingType.CLEAR },
          borders: allBorders(COLOURS.midGrey, 4),
          width: { size: gapColWidths[1], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 80, right: 80 },
        }),
        new TableCell({
          children: [
            para([run(f.title, { bold: true, size: 18 })], { before: 40, after: 20 }),
            para([run(f.recommendation, { size: 17, colour: COLOURS.darkGrey })], { before: 0, after: 40, line: 260 }),
          ],
          shading: { fill: rowBg, type: ShadingType.CLEAR },
          borders: allBorders(COLOURS.midGrey, 4),
          width: { size: gapColWidths[2], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 100, right: 100 },
        }),
        new TableCell({
          children: fwParas.length ? fwParas : [para([run('—', { size: 16, colour: COLOURS.slate })], { before: 60, after: 60 })],
          shading: { fill: rowBg, type: ShadingType.CLEAR },
          borders: allBorders(COLOURS.midGrey, 4),
          width: { size: gapColWidths[3], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 100, right: 100 },
        }),
      ]});
    });

    return [
      heading2('Gap Detail'),
      para([run('Each triggered finding appears once. The Framework Obligations column lists every selected framework this finding has an obligation under, with the specific control reference. Findings are sorted by severity.')],
        { before: 80, after: 160, line: 300, colour: COLOURS.darkGrey }),
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: gapColWidths, rows: [gapHdr, ...gapRows] }),
      spacer(1),
    ];
  })();

  return [
    pageBreak(),
    heading1('5. Framework Compliance Summary'),
    para([
      run(`The table below shows compliance coverage across the frameworks selected for this engagement. ` +
        `"Gaps found" reflects triggered findings that carry an obligation under each framework. ` +
        `"Passing" is the number of library checks where no gap was identified. ` +
        `Remediating the findings in Section 3 will directly improve these figures.`),
    ], { before: 120, after: 200, line: 300 }),
    new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: colWidths, rows: [headerRow, ...dataRows] }),
    spacer(1),
    para([
      run('Note: ', { bold: true }),
      run(`Coverage percentages are based on the known number of checks in this toolkit that map to each framework. ` +
        `100% passing does not constitute a formal certification or audit.`),
    ], { before: 0, after: 200, line: 300, colour: COLOURS.slate }),
    ...gapDetailSection,
  ];
}

/** Compliance Annex — per-finding framework obligation detail */
function buildAssessmentMeta(data) {
  const toolVer     = data.toolVersion          || 'Unknown';
  const findingsVer = data.findingsLastUpdated   || 'Unknown';
  const fwVer       = 'CIS M365 v7.0.0  ·  NIST CSF 2.0  ·  ISO 27001:2022  ·  NCSC CAF v4.0';
  const modules     = data.modulesRun            || 0;
  const allMods     = ['Identity & Conditional Access','Defender & Security Centre','Exchange Online','Teams','SharePoint','Intune / Endpoint'];
  const ranMods     = (data.modules || []).map(m =>
    m === 'identity'   ? 'Identity & Conditional Access'  :
    m === 'security'   ? 'Defender & Security Centre'     :
    m === 'exchange'   ? 'Exchange Online'                :
    m === 'teams'      ? 'Teams'                          :
    m === 'sharepoint' ? 'SharePoint'                     :
    m === 'intune'     ? 'Intune / Endpoint'              : m
  );
  const notRun = allMods.filter(m => !ranMods.includes(m));

  const metaRows = [
    ['Tool version',               toolVer],
    ['Findings library updated',   findingsVer],
    ['Framework versions',         fwVer],
    ['Modules assessed',           ranMods.length > 0 ? ranMods.join(', ') : `${modules} workload(s)`],
    ['Modules not in scope',       notRun.length > 0 ? notRun.join(', ') : 'None — full assessment'],
    ['Assessment type',            'Read-only — no changes were made to the tenant'],
    ['Score methodology',          'Base 100 minus penalties: Critical −8 (max −32), High −5 (max −20), Medium −3 (max −12), Low −1 (max −4). Minimum score: 10.'],
  ];

  return [
    pageBreak(),
    heading1('Assessment Methodology & Scope'),
    para([run('This section documents the scope, methodology and tool version used for this assessment. It is intended to provide auditors and reviewers with the information needed to evaluate the validity of the findings.')], { before: 80, after: 160, line: 300 }),

    new Table({
      width: { size: 10360, type: WidthType.DXA },
      columnWidths: [2400, 7960],
      rows: [
        new TableRow({ tableHeader: true, children: [
          new TableCell({ children: [para([run('Item', { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })], shading: { fill: COLOURS.navy, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.navyLight, 4), width: { size: 2400, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 120, right: 120 } }),
          new TableCell({ children: [para([run('Detail', { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })], shading: { fill: COLOURS.navy, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.navyLight, 4), width: { size: 7960, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 120, right: 120 } }),
        ]}),
        ...metaRows.map(([label, value], idx) => new TableRow({ children: [
          new TableCell({ children: [para([run(label, { bold: true, size: 18, colour: COLOURS.navy })], { before: 50, after: 50 })], shading: { fill: idx % 2 === 0 ? COLOURS.offWhite : COLOURS.white, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: 2400, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 120, right: 80 } }),
          new TableCell({ children: [para([run(value, { size: 18, colour: COLOURS.darkGrey })], { before: 50, after: 50, line: 270 })], shading: { fill: idx % 2 === 0 ? COLOURS.offWhite : COLOURS.white, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: 7960, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 120, right: 80 } }),
        ]})),
      ],
    }),
    spacer(1),

    // Scope disclaimer
    new Table({
      width: { size: 10360, type: WidthType.DXA },
      columnWidths: [10360],
      rows: [new TableRow({ children: [
        new TableCell({
          children: [
            para([run('⚠  Scope Disclaimer', { bold: true, size: 20, colour: COLOURS.amber })], { before: 60, after: 60 }),
            para([run('This assessment covers the Microsoft 365 workloads listed above. Areas outside scope — including Azure infrastructure, on-premises Active Directory, network perimeter controls, physical security, and third-party SaaS applications — were not assessed and may present additional risks not reflected in this report.')], { before: 0, after: 60, line: 270 }),
            para([run('Findings represent the configuration state at the time of assessment. The security posture may change as configurations, user behaviour, and the threat landscape evolve. This report does not constitute a formal audit opinion. For regulatory compliance purposes, findings should be reviewed and validated by a qualified assessor.')], { before: 0, after: 60, line: 270 }),
          ],
          shading: { fill: COLOURS.amberBg, type: ShadingType.CLEAR },
          borders: { top: border(COLOURS.amber, 8), bottom: border(COLOURS.amber, 8), left: border(COLOURS.amber, 20), right: noBorder },
          width: { size: 10360, type: WidthType.DXA },
          margins: { top: 80, bottom: 80, left: 160, right: 160 },
        }),
      ] })],
    }),
    spacer(1),
  ];
}

function buildRiskExceptions(data) {
  const annotations = data.annotations || {};
  const allFindings = data.findings    || [];
  const exceptions  = allFindings.filter(f => {
    const s = annotations[f.id]?.status;
    return s && s !== 'open';
  });

  if (!exceptions.length) return [];

  const statusLabel = {
    accepted_risk:  'Accepted Risk',
    false_positive: 'False Positive',
    not_applicable: 'Not Applicable',
  };
  const statusColour = {
    accepted_risk:  COLOURS.amber,
    false_positive: COLOURS.slate,
    not_applicable: COLOURS.midGrey,
  };

  const colW = [1200, 3600, 1600, 1800, 2160]; // id, title, status, severity, reason/notes

  const headerRow = new TableRow({ tableHeader: true, children: [
    ['ID', 'Finding', 'Status', 'Severity', 'Reason / Notes'].map((h, i) =>
      new TableCell({
        children: [para([run(h, { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })],
        shading: { fill: COLOURS.navy, type: ShadingType.CLEAR },
        borders: allBorders(COLOURS.navyLight, 4),
        width: { size: colW[i], type: WidthType.DXA },
        margins: { top: 40, bottom: 40, left: 100, right: 100 },
      })
    ),
  ]});

  const dataRows = exceptions.map((f, idx) => {
    const ann    = annotations[f.id] || {};
    const sev    = SEV[f.severity]   || SEV.low;
    const rowBg  = idx % 2 === 0 ? COLOURS.offWhite : COLOURS.white;
    const stCol  = statusColour[ann.status] || COLOURS.slate;
    const reason = [ann.reason, ann.notes].filter(Boolean).join(' — ') || 'No reason recorded.';

    return new TableRow({ children: [
      new TableCell({ children: [para([run(f.id, { bold: true, size: 18, colour: COLOURS.navy })], { before: 40, after: 40 })],                                              shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: colW[0], type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 80, right: 80 } }),
      new TableCell({ children: [para([run(f.title, { size: 18 })], { before: 40, after: 40, line: 260 })],                                                                  shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: colW[1], type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 80, right: 80 } }),
      new TableCell({ children: [para([run(statusLabel[ann.status] || ann.status, { bold: true, size: 18, colour: stCol })], { before: 40, after: 40 })],                    shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: colW[2], type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 80, right: 80 } }),
      new TableCell({ children: [para([run(f.severity.charAt(0).toUpperCase()+f.severity.slice(1), { bold: true, size: 18, colour: sev.colour })], { before: 40, after: 40 })], shading: { fill: sev.bg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: colW[3], type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 80, right: 80 } }),
      new TableCell({ children: [para([run(reason, { size: 18, italics: !ann.reason })], { before: 40, after: 40, line: 260 })],                                            shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: colW[4], type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 80, right: 80 } }),
    ]});
  });

  return [
    pageBreak(),
    heading1('Risk Exceptions'),
    para([run(`The following ${exceptions.length} finding${exceptions.length > 1 ? 's have' : ' has'} been reviewed and formally excluded from the security score. Each exception requires periodic review to confirm it remains appropriate.`)], { before: 80, after: 160, line: 300 }),
    new Table({
      width: { size: 10360, type: WidthType.DXA },
      columnWidths: colW,
      rows: [headerRow, ...dataRows],
    }),
    spacer(1),
    para([run('⚠  Accepted risks do not eliminate the underlying vulnerability. Each exception should be reviewed at least annually or when business circumstances change.', { size: 18, colour: COLOURS.amber, bold: true })], { before: 60, after: 80 }),
  ];
}

function buildComplianceAnnex(data) {
  const findings = data.findings || [];
  const active   = data.activeFrameworks || Object.keys(FW_LABELS);
  if (!active.length) return [];

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const triggered = findings
    .filter(f => active.some(fw => f.frameworks && f.frameworks[fw]))
    .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

  if (!triggered.length) return [];

  // Column widths: Framework | Control | Requirement | Why it applies | Recommended action
  const colW = [1560, 1000, 2000, 2000, 2800];

  const fwTableHeader = new TableRow({
    tableHeader: true,
    children: ['Framework', 'Control', 'Requirement', 'Why it applies', 'Recommended action']
      .map((h, i) => new TableCell({
        children: [para([run(h, { bold: true, colour: COLOURS.white, size: 17 })], { before: 60, after: 60 })],
        shading: { fill: COLOURS.navyLight, type: ShadingType.CLEAR },
        borders: allBorders(COLOURS.navy, 4),
        width: { size: colW[i], type: WidthType.DXA },
        margins: { top: 40, bottom: 40, left: 80, right: 80 },
      })),
  });

  const sections = [];

  triggered.forEach((f, fi) => {
    const sev = SEV[f.severity] || SEV.low;
    const fwRows = active
      .filter(fw => f.frameworks && f.frameworks[fw])
      .map(fw => {
        const d         = f.frameworks[fw];
        const label     = FW_LABELS[fw] || fw;
        const controlId = d.id || d.pillar || '—';
        const req       = d.desc || d.title || '—';
        const rationale = d.rationale || '—';
        const action    = d.fw_rem || f.recommendation || '—';
        const isE5      = d.profile && d.profile.includes('E5');

        return new TableRow({ children: [
          new TableCell({
            children: [
              para([run(label, { bold: true, size: 17, colour: COLOURS.navy })], { before: 40, after: isE5 ? 0 : 40 }),
              ...(isE5 ? [para([run('E5 licence required', { size: 14, colour: COLOURS.amber, italics: true })], { before: 0, after: 40 })] : []),
            ],
            borders: allBorders(COLOURS.midGrey, 4),
            width: { size: colW[0], type: WidthType.DXA },
            margins: { top: 40, bottom: 40, left: 80, right: 80 },
          }),
          new TableCell({
            children: [para([run(controlId, { size: 16, colour: COLOURS.slate, bold: true })], { before: 40, after: 40 })],
            borders: allBorders(COLOURS.midGrey, 4),
            width: { size: colW[1], type: WidthType.DXA },
            margins: { top: 40, bottom: 40, left: 80, right: 80 },
          }),
          new TableCell({
            children: [para([run(req, { size: 17 })], { before: 40, after: 40, line: 260 })],
            borders: allBorders(COLOURS.midGrey, 4),
            width: { size: colW[2], type: WidthType.DXA },
            margins: { top: 40, bottom: 40, left: 80, right: 80 },
          }),
          new TableCell({
            children: [para([run(rationale, { size: 17, colour: COLOURS.darkGrey, italics: true })], { before: 40, after: 40, line: 260 })],
            borders: allBorders(COLOURS.midGrey, 4),
            width: { size: colW[3], type: WidthType.DXA },
            margins: { top: 40, bottom: 40, left: 80, right: 80 },
          }),
          new TableCell({
            children: [para([run(action, { size: 17, colour: COLOURS.black })], { before: 40, after: 40, line: 260 })],
            borders: allBorders(COLOURS.midGrey, 4),
            width: { size: colW[4], type: WidthType.DXA },
            margins: { top: 40, bottom: 40, left: 80, right: 80 },
          }),
        ]});
      });

    if (!fwRows.length) return;

    sections.push(
      // Finding header bar
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [1560, 7800],
        rows: [new TableRow({ children: [
          new TableCell({
            children: [
              para([run(sev.label, { bold: true, colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 40, after: 20 }),
              para([run(f.id,      { colour: COLOURS.white, size: 16 })],             { align: AlignmentType.CENTER, before: 0,  after: 40 }),
            ],
            shading: { fill: sev.colour, type: ShadingType.CLEAR },
            borders: noBorders,
            width: { size: 1560, type: WidthType.DXA },
            margins: { top: 60, bottom: 60, left: 100, right: 100 },
            verticalAlign: VerticalAlign.CENTER,
          }),
          new TableCell({
            children: [para([run(f.title, { bold: true, colour: COLOURS.navy, size: 22 })], { before: 80, after: 80 })],
            shading: { fill: sev.bg, type: ShadingType.CLEAR },
            borders: { top: noBorder, bottom: noBorder, left: border(sev.colour, 16), right: noBorder },
            width: { size: 7800, type: WidthType.DXA },
            margins: { top: 80, bottom: 80, left: 160, right: 100 },
          }),
        ]})],
      }),
      // Framework obligations table
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: colW,
        rows: [fwTableHeader, ...fwRows],
      }),
      spacer(fi < triggered.length - 1 ? 2 : 1),
    );
  });

  if (!sections.length) return [];

  return [
    pageBreak(),
    heading1('6. Compliance Annex — Framework Obligation Detail'),
    para([
      run(`This annex provides a per-finding breakdown of every framework obligation triggered during the assessment. ` +
        `For each finding, each selected framework is listed with its specific control reference, the requirement text, ` +
        `why the observed configuration fails that requirement, and the recommended action from that framework's perspective. ` +
        `This table can be used as evidence input for audit, certification or self-assessment submissions.`),
    ], { before: 120, after: 200, line: 300, colour: COLOURS.darkGrey }),
    ...sections,
  ];
}

/** Executive Summary — board-ready, 4-5 pages, no technical detail */
async function buildExecReport(data, outputPath) {
  const annotations   = data.annotations || {};
  const allFindings   = data.findings    || [];
  const adjScore      = data.adjustedScore || data.score || 0;
  const band          = data.scoreBand   || (adjScore >= 90 ? 'Excellent' : adjScore >= 75 ? 'Good' : adjScore >= 60 ? 'Fair' : adjScore >= 40 ? 'Poor' : 'Critical Risk');
  const bandColour    = adjScore >= 90 ? COLOURS.green : adjScore >= 75 ? COLOURS.green : adjScore >= 60 ? COLOURS.amber : adjScore >= 40 ? COLOURS.orange : COLOURS.red;
  const bandSub       = adjScore >= 90 ? 'Strong security posture — minimal risk exposure.'
                      : adjScore >= 75 ? 'Well-managed risk with minor gaps to address.'
                      : adjScore >= 60 ? 'Notable gaps present — remediation recommended.'
                      : adjScore >= 40 ? 'Significant vulnerabilities — prioritise remediation.'
                      :                  'Immediate action required — high exposure to attack.';

  const sevOrder      = { critical: 0, high: 1, medium: 2, low: 3 };
  const openFindings  = allFindings.filter(f => {
    const ann = annotations[f.id];
    return !ann || !ann.status || ann.status === 'open';
  }).sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

  const exceptions    = allFindings.filter(f => {
    const s = annotations[f.id]?.status;
    return s && s !== 'open';
  });

  const sevCounts     = { critical: 0, high: 0, medium: 0, low: 0 };
  openFindings.forEach(f => { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++; });

  const top5          = openFindings.slice(0, 5);
  const dateStr       = data.assessDate || new Date().toISOString().split('T')[0];
  const consultName   = consultant(data, 'consultantName',  'Security Consultant');
  const consultRole   = consultant(data, 'consultantRole',  '');
  const consultEmail  = consultant(data, 'consultantEmail', '');

  // Status label map
  const statusLabel   = { accepted_risk: 'Accepted Risk', false_positive: 'False Positive', not_applicable: 'Not Applicable' };

  const doc = new Document({
    styles: {
      default: { document: { run: { font: 'Arial', size: 22, color: COLOURS.black } } },
      paragraphStyles: [
        { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: 36, bold: true, font: 'Arial', color: COLOURS.navy },
          paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 0 } },
        { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: 28, bold: true, font: 'Arial', color: COLOURS.navyLight },
          paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } },
      ],
    },
    sections: [{
      properties: {
        page: { size: { width: 12240, height: 15840 }, margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 } },
      },
      headers: { default: buildHeader(data.clientName) },
      footers: { default: buildFooter(data) },
      children: [

        // ── Cover ─────────────────────────────────────────────────────────────
        ...(buildLogoParagraph(data.consultantLogo) ? [spacer(2), buildLogoParagraph(data.consultantLogo, { width: 220, height: 90, align: AlignmentType.CENTER, before: 0, after: 320 })] : [spacer(3)]),
        new Paragraph({ children: [new TextRun({ text: 'Microsoft 365', font: 'Arial', size: 64, bold: true, color: COLOURS.navy })], alignment: AlignmentType.CENTER, spacing: { before: 0, after: 60 } }),
        new Paragraph({ children: [new TextRun({ text: 'Executive Summary', font: 'Arial', size: 56, bold: true, color: COLOURS.navyLight })], alignment: AlignmentType.CENTER, spacing: { before: 0, after: 480 } }),
        new Paragraph({ children: [new TextRun({ text: '', font: 'Arial', size: 4 })], border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: COLOURS.navy, space: 1 } }, spacing: { before: 0, after: 400 } }),
        new Paragraph({ children: [new TextRun({ text: data.clientName || 'Client', font: 'Arial', size: 44, bold: true, color: COLOURS.slate })], alignment: AlignmentType.CENTER, spacing: { before: 0, after: 120 } }),
        new Paragraph({ children: [new TextRun({ text: dateStr, font: 'Arial', size: 26, color: COLOURS.slate })], alignment: AlignmentType.CENTER, spacing: { before: 0, after: 80 } }),
        new Paragraph({ children: [new TextRun({ text: `Prepared by: ${consultName}${consultRole ? ` — ${consultRole}` : ''}`, font: 'Arial', size: 22, color: COLOURS.slate })], alignment: AlignmentType.CENTER, spacing: { before: 0, after: 80 } }),
        new Paragraph({ children: [new TextRun({ text: '⚠ Confidential — Not for distribution', font: 'Arial', size: 18, bold: true, color: COLOURS.red })], alignment: AlignmentType.CENTER, spacing: { before: 200, after: 80 } }),
        para([
          run(`Tool v${data.toolVersion || '—'}  ·  Findings: ${data.findingsLastUpdated || '—'}  ·  CIS M365 v7.0  ·  NIST CSF 2.0  ·  ISO 27001:2022  ·  NCSC CAF v4.0`, { size: 16, colour: COLOURS.midGrey }),
        ], { align: AlignmentType.CENTER, before: 0, after: 0 }),
        pageBreak(),

        // ── Security Posture Score ─────────────────────────────────────────────
        heading1('1. Security Posture'),
        para([run(`This executive summary presents the findings of the Microsoft 365 security assessment conducted on ${dateStr}. The assessment evaluated ${data.modulesRun || 6} workload areas across the M365 tenant and identified ${allFindings.length} security findings requiring attention.`)], { before: 80, after: 160, line: 300 }),

        // Score banner
        new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [2400, 6960],
          rows: [new TableRow({ children: [
            new TableCell({
              children: [
                para([run(String(adjScore), { bold: true, colour: COLOURS.white, size: 96 })], { align: AlignmentType.CENTER, before: 60, after: 0 }),
                para([run('out of 100', { colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 0, after: 80 }),
              ],
              shading: { fill: bandColour, type: ShadingType.CLEAR },
              borders: noBorders,
              width: { size: 2400, type: WidthType.DXA },
              margins: { top: 120, bottom: 120, left: 120, right: 120 },
              verticalAlign: VerticalAlign.CENTER,
            }),
            new TableCell({
              children: [
                para([run(band, { bold: true, colour: bandColour, size: 40 })], { before: 80, after: 60 }),
                para([run(bandSub, { colour: COLOURS.darkGrey, size: 22 })], { before: 0, after: 60, line: 300 }),
                para([
                  run('Open findings: ', { bold: true, size: 20 }),
                  run(String(openFindings.length), { bold: true, colour: openFindings.length > 0 ? COLOURS.red : COLOURS.green, size: 20 }),
                  ...(exceptions.length > 0 ? [run(`  |  Accepted/excluded: ${exceptions.length}`, { colour: COLOURS.slate, size: 20 })] : []),
                ], { before: 0, after: 80 }),
              ],
              shading: { fill: COLOURS.offWhite, type: ShadingType.CLEAR },
              borders: { top: noBorder, bottom: noBorder, left: border(bandColour, 20), right: noBorder },
              width: { size: 6960, type: WidthType.DXA },
              margins: { top: 80, bottom: 80, left: 200, right: 140 },
            }),
          ]})],
        }),
        spacer(1),

        // Severity breakdown table
        ...(Object.values(sevCounts).some(v => v > 0) ? (() => {
          const sevRows = Object.entries(sevCounts).filter(([,n]) => n > 0).map(([sev, n]) => {
            const s = SEV[sev] || SEV.low;
            return new TableRow({ children: [
              new TableCell({ children: [para([run(sev.charAt(0).toUpperCase() + sev.slice(1), { bold: true, colour: s.colour, size: 20 })], { before: 60, after: 60 })], shading: { fill: s.bg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: 2400, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 120, right: 120 } }),
              new TableCell({ children: [para([run(String(n), { bold: true, size: 20 })], { align: AlignmentType.CENTER, before: 60, after: 60 })], borders: allBorders(COLOURS.midGrey, 4), width: { size: 6960, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 120, right: 120 } }),
            ]});
          });
          return [
            new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [2400, 6960],
              rows: [
                new TableRow({ tableHeader: true, children: [
                  new TableCell({ children: [para([run('Severity', { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })], shading: { fill: COLOURS.navy, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.navyLight, 4), width: { size: 2400, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 120, right: 120 } }),
                  new TableCell({ children: [para([run('Open Findings', { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })], shading: { fill: COLOURS.navy, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.navyLight, 4), width: { size: 6960, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 120, right: 120 } }),
                ]}),
                ...sevRows,
              ],
            }),
            spacer(1),
          ];
        })() : []),

        pageBreak(),

        // ── Key Findings ──────────────────────────────────────────────────────
        heading1('2. Key Findings'),
        para([run(openFindings.length === 0
          ? 'No open findings were identified. The assessed M365 configuration meets all checked security thresholds.'
          : `The following ${Math.min(top5.length, 5)} finding${top5.length > 1 ? 's' : ''} represent the most significant security gaps identified. Each finding is presented in plain language with the business risk and recommended action.`)],
          { before: 80, after: 160, line: 300 }),

        ...top5.flatMap((f, i) => {
          const sev = SEV[f.severity] || SEV.low;
          const riskStatement = f.severity === 'critical'
            ? 'This is a critical risk that could result in full tenant compromise or significant data breach if exploited.'
            : f.severity === 'high'
            ? 'This is a high-priority risk that materially increases the organisation\'s exposure to cyberattack.'
            : f.severity === 'medium'
            ? 'This is a medium risk that should be addressed as part of ongoing security improvement.'
            : 'This is a low-priority finding that represents a security improvement opportunity.';

          return [
            new Table({
              width: { size: 9360, type: WidthType.DXA },
              columnWidths: [1400, 7960],
              rows: [new TableRow({ children: [
                new TableCell({
                  children: [
                    para([run(sev.label, { bold: true, colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 40, after: 20 }),
                    para([run(`${i + 1} of ${top5.length}`, { colour: COLOURS.white, size: 16 })], { align: AlignmentType.CENTER, before: 0, after: 40 }),
                  ],
                  shading: { fill: sev.colour, type: ShadingType.CLEAR },
                  borders: noBorders,
                  width: { size: 1400, type: WidthType.DXA },
                  margins: { top: 80, bottom: 80, left: 80, right: 80 },
                  verticalAlign: VerticalAlign.CENTER,
                }),
                new TableCell({
                  children: [
                    para([run(f.title, { bold: true, colour: COLOURS.navy, size: 24 })], { before: 60, after: 40 }),
                    para([run(f.description, { colour: COLOURS.darkGrey, size: 20 })], { before: 0, after: 40, line: 280 }),
                    para([run('Business risk: ', { bold: true, size: 18 }), run(riskStatement, { colour: COLOURS.darkGrey, size: 18, italics: true })], { before: 0, after: 40, line: 260 }),
                    para([run('Action: ', { bold: true, size: 18, colour: COLOURS.navyLight }), run(f.recommendation, { colour: COLOURS.black, size: 18 })], { before: 0, after: 60, line: 260 }),
                  ],
                  shading: { fill: sev.bg, type: ShadingType.CLEAR },
                  borders: { top: noBorder, bottom: noBorder, left: border(sev.colour, 16), right: noBorder },
                  width: { size: 7960, type: WidthType.DXA },
                  margins: { top: 80, bottom: 80, left: 160, right: 120 },
                }),
              ]})],
            }),
            spacer(1),
          ];
        }),

        ...(openFindings.length > 5 ? [
          para([run(`Plus ${openFindings.length - 5} further finding${openFindings.length - 5 > 1 ? 's' : ''} of lower severity — see the full Assessment Report for complete detail.`, { colour: COLOURS.slate, size: 20, italics: true })], { before: 0, after: 160 }),
        ] : []),

        pageBreak(),

        // ── Recommendations ───────────────────────────────────────────────────
        heading1('3. Recommended Actions'),
        para([run('The following immediate actions are recommended, in priority order:')], { before: 80, after: 160, line: 300 }),
        ...openFindings.slice(0, 8).flatMap((f, i) => {
          const sev = SEV[f.severity] || SEV.low;
          return [
            new Table({
              width: { size: 9360, type: WidthType.DXA },
              columnWidths: [600, 8760],
              rows: [new TableRow({ children: [
                new TableCell({
                  children: [para([run(String(i + 1), { bold: true, colour: COLOURS.white, size: 28 })], { align: AlignmentType.CENTER, before: 60, after: 60 })],
                  shading: { fill: sev.colour, type: ShadingType.CLEAR },
                  borders: noBorders,
                  width: { size: 600, type: WidthType.DXA },
                  margins: { top: 80, bottom: 80, left: 60, right: 60 },
                  verticalAlign: VerticalAlign.CENTER,
                }),
                new TableCell({
                  children: [
                    para([run(f.title, { bold: true, colour: COLOURS.navy, size: 22 })], { before: 60, after: 30 }),
                    para([run(f.recommendation, { colour: COLOURS.darkGrey, size: 20 })], { before: 0, after: 60, line: 270 }),
                  ],
                  shading: { fill: sev.bg, type: ShadingType.CLEAR },
                  borders: { top: noBorder, bottom: noBorder, left: border(sev.colour, 12), right: noBorder },
                  width: { size: 8760, type: WidthType.DXA },
                  margins: { top: 60, bottom: 60, left: 160, right: 120 },
                }),
              ]})],
            }),
            spacer(1),
          ];
        }),

        // ── Risk Exceptions ───────────────────────────────────────────────────
        ...(exceptions.length > 0 ? [
          pageBreak(),
          heading1('4. Risk Exceptions'),
          para([run('The following findings have been reviewed and formally accepted or excluded. These have been removed from the security score calculation. Each exception must be reviewed periodically to confirm it remains appropriate.')], { before: 80, after: 160, line: 300 }),
          new Table({
            width: { size: 9360, type: WidthType.DXA },
            columnWidths: [1400, 2200, 2360, 3400],
            rows: [
              new TableRow({ tableHeader: true, children:
                ['Finding', 'Status', 'Severity', 'Reason'].map((h, i) => new TableCell({
                  children: [para([run(h, { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })],
                  shading: { fill: COLOURS.navy, type: ShadingType.CLEAR },
                  borders: allBorders(COLOURS.navyLight, 4),
                  width: { size: [1400,2200,2360,3400][i], type: WidthType.DXA },
                  margins: { top: 40, bottom: 40, left: 100, right: 100 },
                })),
              }),
              ...exceptions.map((f, idx) => {
                const ann = annotations[f.id] || {};
                const sev = SEV[f.severity] || SEV.low;
                const rowBg = idx % 2 === 0 ? COLOURS.offWhite : COLOURS.white;
                return new TableRow({ children: [
                  new TableCell({ children: [para([run(f.id, { bold: true, size: 18, colour: COLOURS.navy })], { before: 40, after: 40 })], shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: 1400, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 80, right: 80 } }),
                  new TableCell({ children: [para([run(statusLabel[ann.status] || ann.status, { size: 18 })], { before: 40, after: 40 })], shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: 2200, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 80, right: 80 } }),
                  new TableCell({ children: [para([run(f.severity, { bold: true, colour: sev.colour, size: 18 })], { before: 40, after: 40 })], shading: { fill: sev.bg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: 2360, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 80, right: 80 } }),
                  new TableCell({ children: [para([run(ann.reason || 'No reason provided.', { size: 18, italics: !ann.reason })], { before: 40, after: 40, line: 260 })], shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4), width: { size: 3400, type: WidthType.DXA }, margins: { top: 40, bottom: 40, left: 80, right: 80 } }),
                ]});
              }),
            ],
          }),
          spacer(1),
        ] : []),

        // ── Next Steps ────────────────────────────────────────────────────────
        ...(exceptions.length === 0 ? [pageBreak()] : []),
        heading1(`${exceptions.length > 0 ? '5' : '4'}. Next Steps`),
        para([run('To improve the security posture of this Microsoft 365 environment, we recommend the following next steps:')], { before: 80, after: 120, line: 300 }),
        para([run('1.  Review the full Assessment Report with the IT/security team — it contains technical detail, investigation scripts and remediation guidance for every finding.')], { before: 40, after: 40, line: 280 }),
        para([run('2.  Prioritise Critical and High findings — these carry the greatest risk and should be remediated first.')], { before: 40, after: 40, line: 280 }),
        para([run('3.  Use the tool\'s built-in remediation scripts for findings with Tier 1 automated fixes — each has a paired rollback script for safety.')], { before: 40, after: 40, line: 280 }),
        para([run('4.  Schedule a follow-up assessment 90 days after remediation to validate improvement and track score uplift.')], { before: 40, after: 40, line: 280 }),
        para([run('5.  Review any accepted risk exceptions periodically — business circumstances change, and previously accepted risks may need to be revisited.')], { before: 40, after: 80, line: 280 }),
        spacer(1),
        para([
          run('This report was produced using the M365 Assessment Toolkit. For the full technical report including all findings, compliance framework mapping, and remediation detail, refer to the accompanying Assessment Report.', { colour: COLOURS.slate, size: 18, italics: true }),
        ], { before: 80, after: 80, line: 280 }),
      ],
    }],
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);
  console.log(`Executive report written: ${outputPath}`);
}

async function buildReport(data, outputPath) {
  const doc = new Document({
    numbering: {
      config: [
        {
          reference: 'numbers',
          levels: [{ level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } } }],
        },
        {
          reference: 'bullets',
          levels: [{ level: 0, format: LevelFormat.BULLET, text: '*', alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } } }],
        },
      ],
    },
    styles: {
      default: { document: { run: { font: 'Arial', size: 22, color: COLOURS.black } } },
      paragraphStyles: [
        { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: 36, bold: true, font: 'Arial', color: COLOURS.navy },
          paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 0 } },
        { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: 28, bold: true, font: 'Arial', color: COLOURS.navyLight },
          paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } },
      ],
    },
    sections: [{
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 },
        },
      },
      headers: { default: buildHeader(data.clientName) },
      footers: { default: buildFooter(data) },
      children: [
        ...buildCoverPage(data),
        ...buildExecSummary(data),
        ...buildScoreSection(data),
        ...buildFindingsSection(data),
        ...buildRecommendationsSection(data),
        ...buildRiskExceptions(data),
        ...buildAssessmentMeta(data),
        ...buildFrameworkSection(data),
        ...buildComplianceAnnex(data),
        ...buildAppendix(data),
      ],
    }],
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);
  console.log(`Report written: ${outputPath}`);
}


// ================================================================
//  REMEDIATION REPORT - Separate document produced after fixes
// ================================================================

function buildRemCoverPage(data) {
  const dateStr     = data.remediationDate || data.assessDate || new Date().toISOString().split('T')[0];
  const logoCentered = buildLogoParagraph(data.consultantLogo, { width: 220, height: 90, align: AlignmentType.CENTER, before: 0, after: 320 });
  const consultRole  = consultant(data, 'consultantRole', '');
  return [
    ...(logoCentered ? [spacer(2), logoCentered] : [spacer(4)]),
    new Paragraph({
      children: [new TextRun({ text: 'Microsoft 365', font: 'Arial', size: 64, bold: true, color: COLOURS.navy })],
      alignment: AlignmentType.CENTER, spacing: { before: 0, after: 60 },
    }),
    new Paragraph({
      children: [new TextRun({ text: 'Remediation Report', font: 'Arial', size: 64, bold: true, color: COLOURS.navyLight })],
      alignment: AlignmentType.CENTER, spacing: { before: 0, after: 480 },
    }),
    new Paragraph({
      children: [new TextRun({ text: '', font: 'Arial', size: 4 })],
      border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: COLOURS.navy, space: 1 } },
      spacing: { before: 0, after: 480 },
    }),
    new Paragraph({
      children: [new TextRun({ text: data.clientName, font: 'Arial', size: 48, bold: true, color: COLOURS.slate })],
      alignment: AlignmentType.CENTER, spacing: { before: 0, after: 160 },
    }),
    para([run(`Assessment Date: ${data.assessDate}`, { size: 22, colour: COLOURS.darkGrey })], { align: AlignmentType.CENTER, before: 0, after: 60 }),
    para([run(`Remediation Date: ${dateStr}`, { size: 22, colour: COLOURS.darkGrey })], { align: AlignmentType.CENTER, before: 0, after: 60 }),
    para([run(`Prepared by ${consultant(data, 'consultantName', '[Consultant Name]')}`, { size: 22, colour: COLOURS.darkGrey })], { align: AlignmentType.CENTER, before: 0, after: 60 }),
    ...(consultRole ? [para([run(consultRole, { size: 22, colour: COLOURS.slate, italic: true })], { align: AlignmentType.CENTER, before: 0, after: 60 })] : []),
    para([run(consultant(data, 'consultantEmail', '[consultant@email.com]'), { size: 22, colour: COLOURS.navyLight })], { align: AlignmentType.CENTER, before: 0, after: 0 }),
    spacer(2),
    new Paragraph({
      children: [new TextRun({ text: 'CONFIDENTIAL — For authorised recipients only', font: 'Arial', size: 18, italic: true, color: COLOURS.slate })],
      alignment: AlignmentType.CENTER,
      border: {
        top: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey, space: 6 },
        bottom: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey, space: 6 },
      },
      spacing: { before: 120, after: 120 },
    }),
    spacer(1),
    para([
      run(`Tool v${data.toolVersion || '—'}  ·  Findings: ${data.findingsLastUpdated || '—'}  ·  CIS M365 v7.0  ·  NIST CSF 2.0  ·  ISO 27001:2022  ·  NCSC CAF v4.0`, { size: 16, colour: COLOURS.midGrey }),
    ], { align: AlignmentType.CENTER, before: 0, after: 0 }),
    pageBreak(),
  ];
}

function buildRemExecSummary(data) {
  const remLog     = data.remediationLog || [];
  const findings   = data.findings || [];
  const remCount   = remLog.filter(e => e.action === 'remediate' && e.success).length;
  const rollCount  = remLog.filter(e => e.action === 'rollback' && e.success).length;
  const netFixed   = remCount - rollCount;
  const beforeScore = data.score || 0;
  const afterScore  = data.scoreAfter || beforeScore;
  const scoreImproved = afterScore > beforeScore;

  return [
    heading1('1. Executive Summary'),
    para([
      run(`This report summarises the remediation work carried out on the Microsoft 365 tenant for `),
      run(data.clientName, { bold: true }),
      run(` following the assessment dated ${data.assessDate}. Remediation was carried out with written approval and all changes were preceded by a pre-change snapshot to enable rollback if required.`),
    ], { before: 120, after: 160, line: 300 }),

    // Before/after score comparison
    new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [4680, 4680],
      rows: [
        new TableRow({ children: [
          new TableCell({
            children: [
              para([run('Score Before Remediation', { bold: true, colour: COLOURS.white, size: 20 })], { align: AlignmentType.CENTER, before: 80, after: 40 }),
              new Paragraph({
                children: [new TextRun({ text: `${beforeScore}/100`, font: 'Arial', size: 72, bold: true,
                  color: beforeScore >= 70 ? COLOURS.green : beforeScore >= 50 ? COLOURS.amber : COLOURS.red })],
                alignment: AlignmentType.CENTER, spacing: { before: 60, after: 100 },
              }),
            ],
            shading: { fill: COLOURS.navy, type: ShadingType.CLEAR },
            borders: noBorders,
            margins: { top: 100, bottom: 100, left: 200, right: 200 },
          }),
          new TableCell({
            children: [
              para([run('Score After Remediation', { bold: true, colour: COLOURS.white, size: 20 })], { align: AlignmentType.CENTER, before: 80, after: 40 }),
              new Paragraph({
                children: [new TextRun({ text: `${afterScore}/100`, font: 'Arial', size: 72, bold: true,
                  color: afterScore >= 70 ? COLOURS.green : afterScore >= 50 ? COLOURS.amber : COLOURS.red })],
                alignment: AlignmentType.CENTER, spacing: { before: 60, after: 100 },
              }),
            ],
            shading: { fill: COLOURS.navyLight, type: ShadingType.CLEAR },
            borders: noBorders,
            margins: { top: 100, bottom: 100, left: 200, right: 200 },
          }),
        ]}),
        new TableRow({ children: [
          new TableCell({
            children: [para([run(
              scoreImproved ? `Improved by ${afterScore - beforeScore} points` : 'No change',
              { colour: scoreImproved ? COLOURS.green : COLOURS.slate, size: 20, bold: true }
            )], { align: AlignmentType.CENTER, before: 60, after: 60 })],
            columnSpan: 2,
            shading: { fill: scoreImproved ? COLOURS.greenBg : COLOURS.lightGrey, type: ShadingType.CLEAR },
            borders: noBorders,
          }),
        ]}),
      ],
    }),

    spacer(1),
    para([
      run(`${remCount} finding(s) were remediated`, { bold: true }),
      run(` during this engagement. `),
      rollCount > 0 ? run(`${rollCount} change(s) were subsequently rolled back at the organisation's request. `) : run(''),
      run(`${netFixed} net fix(es) were applied and remain in place.`),
    ], { before: 0, after: 160, line: 300 }),
    pageBreak(),
  ];
}

function buildRemChangesSection(data) {
  const remLog  = data.remediationLog || [];
  const findings = data.findings || [];
  if (remLog.length === 0) return [];

  const sev_order = { critical: 0, high: 1, medium: 2, low: 3 };

  // Build change cards
  const remediations = remLog.filter(e => e.action === 'remediate');
  const rollbacks    = remLog.filter(e => e.action === 'rollback').map(e => e.findingId);

  const cards = [];
  remediations.forEach(entry => {
    const finding   = findings.find(f => f.id === entry.findingId) || {};
    const isRolled  = rollbacks.includes(entry.findingId);
    const sev       = finding.severity || 'medium';
    const sevCfg    = SEV[sev] || SEV.medium;
    const statusCol = isRolled ? COLOURS.amber : COLOURS.green;
    const statusBg  = isRolled ? COLOURS.amberBg : COLOURS.greenBg;
    const statusLbl = isRolled ? 'ROLLED BACK' : 'FIXED';
    const dateStr   = entry.timestamp ? new Date(entry.timestamp).toLocaleString('en-GB') : '-';

    cards.push(
      new Table({
        width: { size: 9360, type: WidthType.DXA },
        columnWidths: [1800, 7560],
        rows: [
          new TableRow({ children: [
            new TableCell({
              children: [
                para([run(sevCfg.label, { bold: true, colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 40, after: 20 }),
                para([run(entry.findingId, { colour: COLOURS.white, size: 16 })], { align: AlignmentType.CENTER, before: 0, after: 40 }),
              ],
              shading: { fill: sevCfg.colour, type: ShadingType.CLEAR },
              borders: noBorders,
              margins: { top: 80, bottom: 80, left: 100, right: 100 },
              verticalAlign: VerticalAlign.CENTER,
            }),
            new TableCell({
              children: [
                para([run(finding.title || entry.findingId, { bold: true, colour: COLOURS.navy, size: 24 })], { before: 60, after: 40 }),
                para([
                  run('Status: ', { bold: true, colour: COLOURS.slate, size: 18 }),
                  run(statusLbl, { bold: true, colour: statusCol, size: 18 }),
                  run(`  |  Applied: ${dateStr}`, { colour: COLOURS.slate, size: 16 }),
                  ...(entry.approvedBy ? [run(`  |  Approved by: ${entry.approvedBy}`, { colour: COLOURS.slate, size: 16 })] : []),
                  ...(entry.changeRef  ? [run(`  |  Ref: ${entry.changeRef}`, { colour: COLOURS.slate, size: 16 })]          : []),
                ], { before: 0, after: 60 }),
              ],
              shading: { fill: statusBg, type: ShadingType.CLEAR },
              borders: { top: noBorder, bottom: noBorder, left: border(sevCfg.colour, 16), right: noBorder },
              margins: { top: 60, bottom: 60, left: 160, right: 140 },
            }),
          ]}),
          new TableRow({ children: [
            cell(para([run('What was changed', { bold: true, colour: COLOURS.slate, size: 17 })], { align: AlignmentType.CENTER, before: 60, after: 60 }), { width: 1800, bg: COLOURS.lightGrey, borders: allBorders(COLOURS.midGrey, 4) }),
            cell(para([run(entry.details || 'Change applied successfully', { colour: COLOURS.black, size: 20 })], { before: 60, after: 60, line: 280 }), { width: 7560 }),
          ]}),
          ...(entry.approvedBy || entry.changeRef ? [new TableRow({ children: [
            cell(para([run('Approval details', { bold: true, colour: COLOURS.navyLight, size: 17 })], { align: AlignmentType.CENTER, before: 60, after: 60 }), { width: 1800, bg: COLOURS.offWhite, borders: allBorders(COLOURS.midGrey, 4) }),
            cell(para([run([
              entry.approvedBy ? `Approved by: ${entry.approvedBy}` : '',
              entry.changeRef  ? `Change reference: ${entry.changeRef}` : '',
              entry.approvalDate ? `Approval date: ${entry.approvalDate}` : '',
              entry.approvalNotes ? `Notes: ${entry.approvalNotes}` : '',
            ].filter(Boolean).join('  |  '), { colour: COLOURS.black, size: 20 })], { before: 60, after: 60 }), { width: 7560 }),
          ]})] : []),
          ...(finding.recommendation ? [new TableRow({ children: [
            cell(para([run('Recommendation', { bold: true, colour: COLOURS.navyLight, size: 17 })], { align: AlignmentType.CENTER, before: 60, after: 60 }), { width: 1800, bg: COLOURS.offWhite, borders: allBorders(COLOURS.midGrey, 4) }),
            cell(para([run(finding.recommendation, { colour: COLOURS.black, size: 20 })], { before: 60, after: 60, line: 280 }), { width: 7560 }),
          ]})] : []),
          ...(isRolled ? [new TableRow({ children: [
            cell(para([run('Rollback note', { bold: true, colour: COLOURS.amber, size: 17 })], { align: AlignmentType.CENTER, before: 60, after: 60 }), { width: 1800, bg: COLOURS.amberBg, borders: allBorders(COLOURS.midGrey, 4) }),
            cell(para([run('This change was subsequently rolled back. The setting has been restored to its previous state.', { colour: COLOURS.black, size: 20 })], { before: 60, after: 60 }), { width: 7560 }),
          ]})] : []),
        ],
      }),
      spacer(1)
    );
  });

  return [
    heading1('2. Changes Made'),
    para([run('The following changes were applied to the tenant. Each was preceded by a pre-change check and a snapshot of the previous state.')], { before: 120, after: 200, line: 300 }),
    ...cards,
    pageBreak(),
  ];
}

function buildRemOpenFindings(data) {
  const remLog   = data.remediationLog || [];
  const findings = data.findings || [];
  const remediatedIds = remLog.filter(e => e.action === 'remediate' && e.success).map(e => e.findingId);
  const rolledBackIds = remLog.filter(e => e.action === 'rollback' && e.success).map(e => e.findingId);
  const netFixed = remediatedIds.filter(id => !rolledBackIds.includes(id));
  const stillOpen = findings.filter(f => !netFixed.includes(f.id));

  if (stillOpen.length === 0) {
    return [
      heading1('3. Remaining Open Findings'),
      para([run('All identified findings have been remediated. No open findings remain.', { colour: COLOURS.green, bold: true })], { before: 120 }),
      pageBreak(),
    ];
  }

  const sev_order = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...stillOpen].sort((a, b) => (sev_order[a.severity] ?? 9) - (sev_order[b.severity] ?? 9));

  const headerRow = new TableRow({
    tableHeader: true,
    children: ['ID', 'Finding', 'Severity', 'Reason Not Remediated'].map((h, i) => {
      const widths = [700, 2500, 1000, 5160];
      return new TableCell({
        children: [para([run(h, { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })],
        width: { size: widths[i], type: WidthType.DXA },
        shading: { fill: COLOURS.slate, type: ShadingType.CLEAR },
        borders: noBorders,
        margins: { top: 60, bottom: 60, left: 100, right: 100 },
      });
    }),
  });

  const dataRows = sorted.map((f, i) => {
    const sevCfg = SEV[f.severity] || SEV.low;
    const isGuided = !['CA-002','EXO-001','EXO-002','EXO-003','SEC-003','SEC-004','SEC-005','TEAMS-002','SPO-002'].includes(f.id);
    const reason = isGuided ? 'Requires manual action - see guidance in assessment report' : 'Pending client approval or scheduling';
    const widths = [700, 2500, 1000, 5160];
    const rowBg = i % 2 === 0 ? COLOURS.white : COLOURS.offWhite;
    return new TableRow({ children: [
      cell(para([run(f.id, { bold: true, colour: COLOURS.navy, size: 18 })]), { width: widths[0], bg: rowBg }),
      cell(para([run(f.title, { colour: COLOURS.black, size: 18 })], { before: 40, after: 40, line: 260 }), { width: widths[1], bg: rowBg }),
      cell(new Paragraph({
        children: [new TextRun({ text: sevCfg.label, font: 'Arial', size: 16, bold: true, color: sevCfg.colour })],
        alignment: AlignmentType.CENTER, spacing: { before: 40, after: 40 },
      }), { width: widths[2], bg: sevCfg.bg }),
      cell(para([run(reason, { colour: COLOURS.darkGrey, size: 18 })], { before: 40, after: 40 }), { width: widths[3], bg: rowBg }),
    ]});
  });

  return [
    heading1('3. Remaining Open Findings'),
    para([run(`${stillOpen.length} finding(s) were not remediated during this engagement. These remain open and should be scheduled for a future remediation session or accepted as a known risk.`)], { before: 120, after: 200, line: 300 }),
    new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [700, 2500, 1000, 5160], rows: [headerRow, ...dataRows] }),
    pageBreak(),
  ];
}

/** Framework compliance impact section for the remediation report */
function buildRemFrameworkSection(data) {
  const findings = data.findings || [];
  const active   = data.activeFrameworks || Object.keys(FW_LABELS);
  const remLog   = data.remediationLog  || [];
  if (!active.length || !findings.length) return [];

  // Determine which findings were net-remediated (remediate succeeds, not rolled back)
  const remState = {};
  remLog.forEach(e => {
    if (!e.findingId || !e.success) return;
    if (e.action === 'remediate') remState[e.findingId] = 'done';
    if (e.action === 'rollback')  remState[e.findingId] = 'rolled';
  });
  const remediatedIds = Object.entries(remState).filter(([,s]) => s === 'done').map(([id]) => id);
  if (!remediatedIds.length) return [];

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };

  // Summary table
  const sumColW = [2800, 1400, 1400, 1400, 2360];
  const sumHdr  = new TableRow({
    tableHeader: true,
    children: ['Framework', 'Total gaps', 'Closed', 'Remaining', 'Movement'].map((h, i) =>
      new TableCell({
        children: [para([run(h, { bold: true, colour: COLOURS.white, size: 18 })], { before: 80, after: 80 })],
        shading: { fill: COLOURS.navy, type: ShadingType.CLEAR },
        borders: allBorders(COLOURS.navyLight, 4),
        width: { size: sumColW[i], type: WidthType.DXA },
        margins: { top: 60, bottom: 60, left: 100, right: 100 },
      })
    ),
  });

  const sumRows = active
    .map(fw => {
      const mapped    = findings.filter(f => f.frameworks && f.frameworks[fw]);
      const closed    = mapped.filter(f => remediatedIds.includes(f.id)).length;
      const remaining = mapped.length - closed;
      const moveTxt   = closed > 0 ? `+${closed} closed` : 'No change';
      const moveCol   = closed > 0 ? COLOURS.green : COLOURS.slate;
      const moveBg    = closed > 0 ? COLOURS.greenBg : COLOURS.white;
      return { fw, mapped, closed, remaining, moveTxt, moveCol, moveBg };
    })
    .filter(r => r.mapped.length > 0)
    .map(({ fw, mapped, closed, remaining, moveTxt, moveCol, moveBg }) =>
      new TableRow({ children: [
        new TableCell({
          children: [para([run(FW_LABELS[fw] || fw, { bold: true, size: 20 })], { before: 60, after: 60 })],
          borders: allBorders(COLOURS.midGrey, 4), width: { size: sumColW[0], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 100, right: 100 },
        }),
        new TableCell({
          children: [para([run(String(mapped.length), { size: 20 })], { align: AlignmentType.CENTER, before: 60, after: 60 })],
          borders: allBorders(COLOURS.midGrey, 4), width: { size: sumColW[1], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 80, right: 80 },
        }),
        new TableCell({
          children: [para([run(String(closed), { bold: closed > 0, colour: closed > 0 ? COLOURS.green : COLOURS.slate, size: 20 })],
            { align: AlignmentType.CENTER, before: 60, after: 60 })],
          shading: { fill: closed > 0 ? COLOURS.greenBg : COLOURS.white, type: ShadingType.CLEAR },
          borders: allBorders(COLOURS.midGrey, 4), width: { size: sumColW[2], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 80, right: 80 },
        }),
        new TableCell({
          children: [para([run(String(remaining), { bold: remaining > 0, colour: remaining > 0 ? COLOURS.red : COLOURS.green, size: 20 })],
            { align: AlignmentType.CENTER, before: 60, after: 60 })],
          borders: allBorders(COLOURS.midGrey, 4), width: { size: sumColW[3], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 80, right: 80 },
        }),
        new TableCell({
          children: [para([run(moveTxt, { bold: closed > 0, colour: moveCol, size: 20 })],
            { align: AlignmentType.CENTER, before: 60, after: 60 })],
          shading: { fill: moveBg, type: ShadingType.CLEAR },
          borders: allBorders(COLOURS.midGrey, 4), width: { size: sumColW[4], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 100, right: 100 },
        }),
      ]})
    );

  if (!sumRows.length) return [];

  // Per-framework: which specific controls were closed
  const detColW = [900, 1000, 4760, 2700];
  const closedDetails = active.flatMap(fw => {
    const closed = findings
      .filter(f => f.frameworks && f.frameworks[fw] && remediatedIds.includes(f.id))
      .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
    if (!closed.length) return [];

    const detHdr = new TableRow({
      tableHeader: true,
      children: ['Severity', 'Finding ID', 'Finding', 'Control Closed'].map((h, i) =>
        new TableCell({
          children: [para([run(h, { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })],
          shading: { fill: COLOURS.navyLight, type: ShadingType.CLEAR },
          borders: allBorders(COLOURS.navyLight, 4), width: { size: detColW[i], type: WidthType.DXA },
          margins: { top: 60, bottom: 60, left: 100, right: 100 },
        })
      ),
    });

    const detRows = closed.map((f, idx) => {
      const sev    = SEV[f.severity] || SEV.medium;
      const fwData = f.frameworks[fw];
      const ctrl   = fwData ? [fwData.id, fwData.title].filter(Boolean).join(' — ') : '—';
      const rowBg  = idx % 2 === 0 ? COLOURS.offWhite : COLOURS.white;
      return new TableRow({ children: [
        new TableCell({
          children: [para([run(sev.label, { bold: true, colour: sev.colour, size: 16 })], { before: 60, after: 60 })],
          shading: { fill: sev.bg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4),
          width: { size: detColW[0], type: WidthType.DXA }, margins: { top: 60, bottom: 60, left: 80, right: 80 },
        }),
        new TableCell({
          children: [para([run(f.id, { size: 17, colour: COLOURS.navy, bold: true })], { before: 60, after: 60 })],
          shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4),
          width: { size: detColW[1], type: WidthType.DXA }, margins: { top: 60, bottom: 60, left: 80, right: 80 },
        }),
        new TableCell({
          children: [para([run(f.title, { bold: true, size: 18 })], { before: 40, after: 40 })],
          shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4),
          width: { size: detColW[2], type: WidthType.DXA }, margins: { top: 60, bottom: 60, left: 100, right: 100 },
        }),
        new TableCell({
          children: [para([run(ctrl, { size: 17, colour: COLOURS.green })], { before: 60, after: 60, line: 260 })],
          shading: { fill: rowBg, type: ShadingType.CLEAR }, borders: allBorders(COLOURS.midGrey, 4),
          width: { size: detColW[3], type: WidthType.DXA }, margins: { top: 60, bottom: 60, left: 100, right: 100 },
        }),
      ]});
    });

    return [
      heading2(`${FW_LABELS[fw] || fw} — ${closed.length} control${closed.length !== 1 ? 's' : ''} closed`),
      new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: detColW, rows: [detHdr, ...detRows] }),
      spacer(1),
    ];
  });

  return [
    pageBreak(),
    heading1('4. Framework Compliance Impact'),
    para([run(
      `The table below shows the direct compliance impact of the remediation work carried out. ` +
      `Each closed gap represents a finding that was successfully remediated and that carried ` +
      `an obligation under the listed framework. Where gaps remain, these represent findings ` +
      `that were not in scope for this remediation engagement.`
    )], { before: 120, after: 200, line: 300 }),
    new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: sumColW, rows: [sumHdr, ...sumRows] }),
    spacer(1),
    ...closedDetails,
  ];
}

async function buildRemediationReport(data, outputPath) {
  const doc = new Document({
    styles: {
      default: { document: { run: { font: 'Arial', size: 22, color: COLOURS.black } } },
      paragraphStyles: [
        { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: 36, bold: true, font: 'Arial', color: COLOURS.navy },
          paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 0 } },
        { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
          run: { size: 28, bold: true, font: 'Arial', color: COLOURS.navyLight },
          paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } },
      ],
    },
    sections: [{
      properties: {
        page: { size: { width: 12240, height: 15840 }, margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 } },
      },
      headers: { default: buildHeader(data.clientName + ' - Remediation Report') },
      footers: { default: buildFooter(data) },
      children: [
        ...buildRemCoverPage(data),
        ...buildRemExecSummary(data),
        ...buildRemChangesSection(data),
        ...buildRemOpenFindings(data),
        ...buildRemFrameworkSection(data),
      ],
    }],
  });

  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);
  console.log(`Remediation report written: ${outputPath}`);
}


// ================================================================
//  COMPARISON REPORT BUILDER
// ================================================================

function buildCompCoverPage(data) {
  var sA = data.sessionA || {}, sB = data.sessionB || {};
  return [
    spacer(4),
    new Paragraph({ children: [new TextRun({ text: 'Microsoft 365', font: 'Arial', size: 64, bold: true, color: COLOURS.navy })], alignment: AlignmentType.CENTER, spacing: { before: 0, after: 60 } }),
    new Paragraph({ children: [new TextRun({ text: 'Assessment Comparison', font: 'Arial', size: 52, bold: true, color: COLOURS.navyLight })], alignment: AlignmentType.CENTER, spacing: { before: 0, after: 480 } }),
    new Paragraph({ children: [new TextRun({ text: '', font: 'Arial', size: 4 })], border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: COLOURS.navy } }, spacing: { before: 0, after: 480 } }),
    new Paragraph({ children: [new TextRun({ text: sA.orgName || 'Organisation', font: 'Arial', size: 48, bold: true, color: COLOURS.slate })], alignment: AlignmentType.CENTER, spacing: { before: 0, after: 160 } }),
    para([run(sA.assessDate + ' vs ' + sB.assessDate, { size: 24, colour: COLOURS.darkGrey })], { align: AlignmentType.CENTER, before: 0, after: 60 }),
    para([run(`Prepared by ${consultant(sA, 'consultantName', consultant(data, 'consultantName', '[Consultant Name]'))}`, { size: 22, colour: COLOURS.darkGrey })], { align: AlignmentType.CENTER, before: 0, after: 0 }),
    spacer(2),
    new Paragraph({ children: [new TextRun({ text: 'CONFIDENTIAL - For authorised recipients only', font: 'Arial', size: 18, italic: true, color: COLOURS.slate })], alignment: AlignmentType.CENTER, border: { top: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey, space: 6 }, bottom: { style: BorderStyle.SINGLE, size: 4, color: COLOURS.midGrey, space: 6 } }, spacing: { before: 120, after: 120 } }),
    pageBreak(),
  ];
}

function buildCompSummary(data) {
  var sA = data.sessionA || {}, sB = data.sessionB || {};
  var sum = data.summary || {};
  var delta = data.scoreDelta || 0;
  var dCol = delta > 0 ? COLOURS.green : delta < 0 ? COLOURS.red : COLOURS.slate;
  var dLbl = delta > 0 ? '+' + delta + ' points' : delta + ' points';

  var scoreTable = new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [3120, 3120, 3120],
    rows: [
      new TableRow({ children: [
        new TableCell({ children: [para([run('First Assessment', { bold: true, colour: COLOURS.white, size: 20 })], { align: AlignmentType.CENTER, before: 80, after: 40 }), para([run(sA.assessDate || '', { colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 0, after: 80 })], shading: { fill: COLOURS.navy, type: ShadingType.CLEAR }, borders: noBorders, margins: { top: 80, bottom: 80, left: 120, right: 120 } }),
        new TableCell({ children: [para([run('Change', { bold: true, colour: COLOURS.white, size: 20 })], { align: AlignmentType.CENTER, before: 80, after: 80 })], shading: { fill: COLOURS.navyLight, type: ShadingType.CLEAR }, borders: noBorders }),
        new TableCell({ children: [para([run('Latest Assessment', { bold: true, colour: COLOURS.white, size: 20 })], { align: AlignmentType.CENTER, before: 80, after: 40 }), para([run(sB.assessDate || '', { colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 0, after: 80 })], shading: { fill: COLOURS.navy, type: ShadingType.CLEAR }, borders: noBorders, margins: { top: 80, bottom: 80, left: 120, right: 120 } }),
      ]}),
      new TableRow({ children: [
        new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: sA.score + '/100', font: 'Arial', size: 80, bold: true, color: sA.score >= 70 ? COLOURS.green : sA.score >= 50 ? COLOURS.amber : COLOURS.red })], alignment: AlignmentType.CENTER, spacing: { before: 120, after: 120 } })], shading: { fill: sA.score >= 70 ? COLOURS.greenBg : sA.score >= 50 ? COLOURS.amberBg : COLOURS.redBg, type: ShadingType.CLEAR }, borders: noBorders }),
        new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: dLbl, font: 'Arial', size: 60, bold: true, color: dCol })], alignment: AlignmentType.CENTER, spacing: { before: 120, after: 120 } })], shading: { fill: delta > 0 ? COLOURS.greenBg : delta < 0 ? COLOURS.redBg : COLOURS.lightGrey, type: ShadingType.CLEAR }, borders: noBorders }),
        new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: sB.score + '/100', font: 'Arial', size: 80, bold: true, color: sB.score >= 70 ? COLOURS.green : sB.score >= 50 ? COLOURS.amber : COLOURS.red })], alignment: AlignmentType.CENTER, spacing: { before: 120, after: 120 } })], shading: { fill: sB.score >= 70 ? COLOURS.greenBg : sB.score >= 50 ? COLOURS.amberBg : COLOURS.redBg, type: ShadingType.CLEAR }, borders: noBorders }),
      ]}),
      new TableRow({ children: [
        new TableCell({ children: [para([run(sA.findingCount + ' findings', { colour: COLOURS.slate, size: 20 })], { align: AlignmentType.CENTER, before: 60, after: 60 })], borders: noBorders }),
        new TableCell({ children: [para([run(delta > 0 ? 'Improved' : delta < 0 ? 'Declined' : 'Unchanged', { colour: dCol, size: 18, bold: true })], { align: AlignmentType.CENTER, before: 60, after: 60 })], borders: noBorders }),
        new TableCell({ children: [para([run(sB.findingCount + ' findings', { colour: COLOURS.slate, size: 20 })], { align: AlignmentType.CENTER, before: 60, after: 60 })], borders: noBorders }),
      ]}),
    ],
  });

  var countsTable = new Table({
    width: { size: 9360, type: WidthType.DXA }, columnWidths: [2340, 2340, 2340, 2340],
    rows: [new TableRow({ children: [
      ['Resolved', sum.resolvedCount, COLOURS.green, COLOURS.greenBg],
      ['New', sum.newCount, COLOURS.red, COLOURS.redBg],
      ['Still Open', sum.stillOpenCount, COLOURS.amber, COLOURS.amberBg],
      ['Improved', sum.improvedCount, COLOURS.accent, 'EBF5FB'],
    ].map(function(arr) {
      var h = arr[0], v = arr[1], col = arr[2], bg = arr[3];
      return new TableCell({ children: [
        para([run(h, { bold: true, colour: col, size: 20 })], { align: AlignmentType.CENTER, before: 60, after: 40 }),
        new Paragraph({ children: [new TextRun({ text: String(v || 0), font: 'Arial', size: 56, bold: true, color: col })], alignment: AlignmentType.CENTER, spacing: { before: 40, after: 80 } }),
      ], shading: { fill: bg, type: ShadingType.CLEAR }, borders: noBorders });
    }) })],
  });

  return [
    heading1('1. Executive Summary'),
    para([run('This report compares two Microsoft 365 security assessments for '), run(sA.orgName || 'the organisation', { bold: true }), run('. First: ' + sA.assessDate + '. Latest: ' + sB.assessDate + '.')], { before: 120, after: 160, line: 300 }),
    scoreTable, spacer(1), countsTable, spacer(1),
    para([run(delta > 0 ? 'Overall posture improved by ' + delta + ' points. ' + sum.resolvedCount + ' finding(s) resolved.' : delta < 0 ? 'Overall posture declined by ' + Math.abs(delta) + ' points. ' + sum.newCount + ' new finding(s) detected.' : 'Overall posture unchanged.', { colour: dCol })], { before: 0, after: 0, line: 300 }),
    pageBreak(),
  ];
}

function buildCompChanges(data) {
  var resolved = data.resolved || [], newFinds = data.newFindings || [], stillOpen = data.stillOpen || [];
  var sevOrd = { critical: 0, high: 1, medium: 2, low: 3 };
  var sections = [];

  if (resolved.length > 0) {
    sections.push(heading2('Resolved (' + resolved.length + ')', COLOURS.green));
    sections.push(para([run('These findings were present in the first assessment but are no longer triggered.')], { before: 0, after: 120, line: 300 }));
    resolved.slice().sort(function(a,b){ return (sevOrd[a.severity]||9)-(sevOrd[b.severity]||9); }).forEach(function(f) {
      sections.push(new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [800, 8560], rows: [new TableRow({ children: [
        new TableCell({ children: [para([run(f.id, { bold: true, colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 60, after: 60 })], shading: { fill: COLOURS.green, type: ShadingType.CLEAR }, borders: noBorders, margins: { top: 60, bottom: 60, left: 80, right: 80 } }),
        new TableCell({ children: [para([run('RESOLVED  ', { bold: true, colour: COLOURS.green, size: 18 }), run(f.title, { bold: true, colour: COLOURS.navy, size: 20 })], { before: 60, after: 20 }), para([run('Previously ' + f.severity + ' severity. No longer triggered in latest assessment.', { colour: COLOURS.slate, size: 18 })], { before: 0, after: 60 })], shading: { fill: COLOURS.greenBg, type: ShadingType.CLEAR }, borders: { top: noBorder, bottom: noBorder, left: border(COLOURS.green, 12), right: noBorder }, margins: { top: 60, bottom: 60, left: 140, right: 120 } }),
      ]})]}));
      sections.push(spacer(0));
    });
  }

  if (newFinds.length > 0) {
    sections.push(spacer(1));
    sections.push(heading2('New Findings (' + newFinds.length + ')', COLOURS.red));
    sections.push(para([run('These findings were not present in the first assessment and require attention.')], { before: 0, after: 120, line: 300 }));
    newFinds.slice().sort(function(a,b){ return (sevOrd[a.severity]||9)-(sevOrd[b.severity]||9); }).forEach(function(f) {
      var sev = SEV[f.severity] || SEV.low;
      sections.push(new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: [800, 8560], rows: [new TableRow({ children: [
        new TableCell({ children: [para([run(f.id, { bold: true, colour: COLOURS.white, size: 18 })], { align: AlignmentType.CENTER, before: 60, after: 60 })], shading: { fill: sev.colour, type: ShadingType.CLEAR }, borders: noBorders, margins: { top: 60, bottom: 60, left: 80, right: 80 } }),
        new TableCell({ children: [para([run('NEW  ', { bold: true, colour: sev.colour, size: 18 }), run(f.title, { bold: true, colour: COLOURS.navy, size: 20 })], { before: 60, after: 20 }), para([run(f.description, { colour: COLOURS.black, size: 18 })], { before: 0, after: 20, line: 280 }), para([run('Recommendation: ', { bold: true }), run(f.recommendation, { colour: COLOURS.black, size: 18 })], { before: 0, after: 60 })], shading: { fill: sev.bg, type: ShadingType.CLEAR }, borders: { top: noBorder, bottom: noBorder, left: border(sev.colour, 12), right: noBorder }, margins: { top: 60, bottom: 60, left: 140, right: 120 } }),
      ]})]}));
      sections.push(spacer(0));
    });
  }

  if (stillOpen.length > 0) {
    sections.push(spacer(1));
    sections.push(heading2('Still Open (' + stillOpen.length + ')', COLOURS.amber));
    sections.push(para([run('These findings remain open and should be prioritised.')], { before: 0, after: 120, line: 300 }));
    var ws = [700, 2500, 1100, 5060];
    var hdr = new TableRow({ children: ['ID','Finding','Severity','Recommendation'].map(function(h, i) {
      return new TableCell({ children: [para([run(h, { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })], width: { size: ws[i], type: WidthType.DXA }, shading: { fill: COLOURS.slate, type: ShadingType.CLEAR }, borders: noBorders, margins: { top: 60, bottom: 60, left: 100, right: 100 } });
    })});
    var drows = stillOpen.slice().sort(function(a,b){ return (sevOrd[a.severity]||9)-(sevOrd[b.severity]||9); }).map(function(f, i) {
      var sev = SEV[f.severity] || SEV.low;
      var bg = i % 2 === 0 ? COLOURS.white : COLOURS.offWhite;
      return new TableRow({ children: [
        cell(para([run(f.id, { bold: true, colour: COLOURS.navy, size: 18 })]), { width: ws[0], bg: bg }),
        cell(para([run(f.title, { colour: COLOURS.black, size: 18 })], { before: 40, after: 40, line: 260 }), { width: ws[1], bg: bg }),
        cell(new Paragraph({ children: [new TextRun({ text: sev.label, font: 'Arial', size: 16, bold: true, color: sev.colour })], alignment: AlignmentType.CENTER, spacing: { before: 40, after: 40 } }), { width: ws[2], bg: sev.bg }),
        cell(para([run(f.recommendation, { colour: COLOURS.black, size: 17 })], { before: 40, after: 40, line: 260 }), { width: ws[3], bg: bg }),
      ]});
    });
    sections.push(new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: ws, rows: [hdr].concat(drows) }));
  }

  return [heading1('2. Finding Changes')].concat(sections).concat([pageBreak()]);
}

function buildCompMetrics(data) {
  var changes = data.metricChanges || [];
  if (changes.length === 0) return [];
  var stCol = { good: COLOURS.green, warn: COLOURS.amber, bad: COLOURS.red };
  var ws = [3500, 1800, 1800, 2260];
  var hdr = new TableRow({ children: ['Metric','Before','After','Change'].map(function(h, i) {
    return new TableCell({ children: [para([run(h, { bold: true, colour: COLOURS.white, size: 18 })], { before: 60, after: 60 })], width: { size: ws[i], type: WidthType.DXA }, shading: { fill: COLOURS.navy, type: ShadingType.CLEAR }, borders: noBorders, margins: { top: 60, bottom: 60, left: 100, right: 100 } });
  })});
  var drows = changes.map(function(m, i) {
    var bg = i % 2 === 0 ? COLOURS.white : COLOURS.offWhite;
    var cB = stCol[m.statusA] || COLOURS.slate, cA = stCol[m.statusB] || COLOURS.slate;
    var imp = m.statusB === 'good' && m.statusA !== 'good', dec = m.statusB === 'bad' && m.statusA !== 'bad';
    var cL = imp ? 'Improved' : dec ? 'Declined' : 'Changed', cC = imp ? COLOURS.green : dec ? COLOURS.red : COLOURS.amber;
    return new TableRow({ children: [
      cell(para([run(m.label, { colour: COLOURS.navy, size: 18 })]), { width: ws[0], bg: bg }),
      cell(para([run(String(m.before), { colour: cB, size: 18, bold: true })], { align: AlignmentType.CENTER }), { width: ws[1], bg: bg }),
      cell(para([run(String(m.after), { colour: cA, size: 18, bold: true })], { align: AlignmentType.CENTER }), { width: ws[2], bg: bg }),
      cell(para([run(cL, { colour: cC, size: 18, bold: true })], { align: AlignmentType.CENTER }), { width: ws[3], bg: bg }),
    ]});
  });
  return [heading1('3. Metric Changes'), para([run('The following metrics changed between assessments.')], { before: 120, after: 200, line: 300 }), new Table({ width: { size: 9360, type: WidthType.DXA }, columnWidths: ws, rows: [hdr].concat(drows) }), pageBreak()];
}

async function buildComparisonReport(data, outputPath) {
  var sA = data.sessionA || {};
  var doc = new Document({
    styles: { default: { document: { run: { font: 'Arial', size: 22, color: COLOURS.black } } }, paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 36, bold: true, font: 'Arial', color: COLOURS.navy }, paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 0 } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 28, bold: true, font: 'Arial', color: COLOURS.navyLight }, paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } },
    ]},
    sections: [{ properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 } } },
      headers: { default: buildHeader((sA.orgName || 'Organisation') + ' - Assessment Comparison') },
      footers: { default: buildFooter(data) },
      children: buildCompCoverPage(data).concat(buildCompSummary(data)).concat(buildCompChanges(data)).concat(buildCompMetrics(data)),
    }],
  });
  var buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);
  console.log('Comparison report written: ' + outputPath);
}

// --- Entry point -------------------------------------------------
const [,, inputFile, outputFile, reportType] = process.argv;
if (!inputFile || !outputFile) {
  console.error('Usage: node generate-report.js <input.json> <output.docx> [assessment|remediation]');
  process.exit(1);
}

const data = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
const isRemediation = reportType === 'remediation';

const isComparison = reportType === 'comparison';

if (isRemediation) {
  buildRemediationReport(data, outputFile).catch(err => {
    console.error('Remediation report generation failed:', err);
    process.exit(1);
  });
} else if (isComparison) {
  buildComparisonReport(data, outputFile).catch(err => {
    console.error('Comparison report generation failed:', err);
    process.exit(1);
  });
} else if (reportType === 'executive') {
  buildExecReport(data, outputFile).catch(err => {
    console.error('Executive report generation failed:', err);
    process.exit(1);
  });
} else {
  buildReport(data, outputFile).catch(err => {
    console.error('Assessment report generation failed:', err);
    process.exit(1);
  });
}

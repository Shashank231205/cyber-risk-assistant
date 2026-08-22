"""Rendering the report as a self-contained web page.

The page carries its own styles and no scripts. That keeps it readable under
a restrictive content security policy, removes a class of injection risk
outright, and means the page renders identically with no network beyond the
initial request.

Every value drawn from the data is escaped. The report renders text taken from
an internal inventory and from an advisory that arrived from outside, so
neither is trusted to be free of markup.
"""

from __future__ import annotations

from html import escape

from cyber_risk.models.enums import DataQualitySeverity
from cyber_risk.models.report import RiskEntry, RiskReport

STYLES = """
:root {
  --bg: #f7f7f6; --panel: #fff; --ink: #1c1b1a; --muted: #5f5c58;
  --line: #e3e0dc; --accent: #8a3a2b; --chip: #f0ede9;
  --critical: #9a2b20; --warning: #8a6314; --info: #4a5a6a;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #191817; --panel: #211f1e; --ink: #eceae7; --muted: #a8a39d;
    --line: #35322f; --accent: #d98570; --chip: #2b2927;
    --critical: #e08a7d; --warning: #d4ad63; --info: #90a4b8;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 16px/1.65 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 860px; margin: 0 auto; padding: 40px 22px 80px; }
header { border-bottom: 2px solid var(--ink); padding-bottom: 20px; margin-bottom: 12px; }
h1 { font-size: 1.85rem; margin: 0 0 6px; letter-spacing: -0.02em; }
.sub { color: var(--muted); font-size: 0.95rem; margin: 0; }
.note {
  background: var(--chip); border-left: 3px solid var(--accent);
  padding: 12px 16px; margin: 22px 0; font-size: 0.9rem; color: var(--muted);
}
.summary { background: var(--panel); border: 1px solid var(--line);
           border-left: 4px solid var(--accent); border-radius: 10px;
           padding: 22px 24px; margin: 22px 0; }
.summary h2 { font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.09em;
              color: var(--muted); margin: 0 0 10px; }
.summary p { margin: 0; font-size: 1.02rem; }
.risk { background: var(--panel); border: 1px solid var(--line);
        border-radius: 10px; padding: 24px; margin: 22px 0; }
.risk-head { display: flex; gap: 14px; align-items: baseline;
             border-bottom: 1px solid var(--line); padding-bottom: 12px; margin-bottom: 14px; }
.rank { font-size: 1.55rem; font-weight: 700; color: var(--accent);
        font-variant-numeric: tabular-nums; }
.risk-head h2 { font-size: 1.12rem; margin: 0; flex: 1; }
.score { font-variant-numeric: tabular-nums; font-weight: 700; white-space: nowrap; }
.score small { display: block; font-weight: 400; font-size: 0.7rem;
               color: var(--muted); text-align: right; }
.narrative { margin: 0 0 18px; }
dl { display: grid; grid-template-columns: minmax(120px, auto) 1fr; gap: 6px 18px;
     margin: 0 0 18px; font-size: 0.9rem; }
dt { color: var(--muted); }
dd { margin: 0; }
.bars { margin: 0 0 18px; }
.bar-row { display: grid; grid-template-columns: minmax(130px, auto) 1fr auto;
           gap: 10px; align-items: center; font-size: 0.83rem; margin-bottom: 5px; }
.track { background: var(--chip); border-radius: 3px; height: 7px; overflow: hidden; }
.fill { background: var(--accent); height: 100%; }
.pts { color: var(--muted); font-variant-numeric: tabular-nums; }
.control { border-top: 1px solid var(--line); padding-top: 16px; }
.control h3 { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.09em;
              color: var(--muted); margin: 0 0 8px; }
.control p { margin: 0 0 8px; font-weight: 600; font-size: 0.94rem; }
blockquote { margin: 0; padding: 12px 16px; background: var(--chip);
             border-radius: 6px; font-size: 0.88rem; color: var(--muted); }
.flag { display: inline-block; font-size: 0.72rem; padding: 2px 8px; border-radius: 20px;
        background: var(--chip); color: var(--muted); margin-left: 6px; }
.gaps li { margin-bottom: 10px; font-size: 0.9rem; }
.sev { font-weight: 700; }
.sev.critical { color: var(--critical); }
.sev.warning { color: var(--warning); }
.sev.info { color: var(--info); }
footer { margin-top: 44px; padding-top: 20px; border-top: 1px solid var(--line);
         font-size: 0.82rem; color: var(--muted); }
footer ul { padding-left: 18px; margin: 8px 0 0; }
h2.section { font-size: 1.05rem; margin: 40px 0 12px; }
table { width: 100%; border-collapse: collapse; }
.scroll { overflow-x: auto; }
@media (max-width: 620px) {
  dl { grid-template-columns: 1fr; gap: 2px 0; }
  dt { margin-top: 8px; }
  .bar-row { grid-template-columns: 1fr; }
  .track { display: none; }
}
"""

SEVERITY_LABELS = {
    DataQualitySeverity.CRITICAL: "Critical",
    DataQualitySeverity.WARNING: "Warning",
    DataQualitySeverity.INFO: "Note",
}


def _risk_section(entry: RiskEntry) -> str:
    """Render one risk."""
    risk = entry.scored.risk
    breakdown = entry.scored.breakdown
    largest = max((f.contribution for f in breakdown.factors), default=1.0) or 1.0

    rows = "".join(
        f'<div class="bar-row"><span>{escape(f.name)}</span>'
        f'<span class="track"><span class="fill" style="width:{f.contribution / largest:.0%}">'
        f"</span></span>"
        f'<span class="pts">{f.contribution:.1f}</span></div>'
        for f in breakdown.ranked_factors
        if f.contribution > 0
    )

    details = [
        ("Asset", f"{risk.asset.asset_name} ({risk.asset.asset_type})"),
        (
            "Environment",
            f"{risk.asset.environment.value}, "
            f"{'internet-facing' if risk.is_internet_facing else 'internal'}",
        ),
        (
            "Finding",
            f"{entry.identifier} — severity {risk.vulnerability.cvss} of 10, "
            f"open {risk.vulnerability.days_open} days",
        ),
        ("Threat activity", entry.threat_summary),
        ("Exploitation", entry.exploitation_status),
        ("Business service", entry.service_name),
    ]
    if risk.service is not None and risk.service.business_impact:
        details.append(("Impact if lost", risk.service.business_impact))
    if risk.exposure_conflict:
        details.append(
            (
                "Data note",
                "Sources disagree on internet exposure; the asset inventory was "
                "treated as authoritative.",
            )
        )

    definitions = "".join(
        f"<dt>{escape(label)}</dt><dd>{escape(str(value))}</dd>" for label, value in details
    )

    if entry.control is not None:
        control = entry.control
        flag = '<span class="flag">indicative match</span>' if control.is_weak_match else ""
        guidance = (
            '<div class="control"><h3>Recommended control</h3>'
            f"<p>{escape(control.citation)}{flag}</p>"
            f"<blockquote>{escape(control.excerpt)}</blockquote></div>"
        )
    else:
        guidance = (
            '<div class="control"><h3>Recommended control</h3>'
            "<p>No control was retrieved for this finding.</p></div>"
        )

    return (
        '<article class="risk">'
        f'<div class="risk-head"><span class="rank">{entry.position}</span>'
        f"<h2>{escape(entry.finding_name)}</h2>"
        f'<span class="score">{entry.scored.score:.1f}<small>of 100</small></span></div>'
        f'<p class="narrative">{escape(entry.narrative)}</p>'
        f"<dl>{definitions}</dl>"
        f'<div class="bars">{rows}</div>'
        f"{guidance}"
        "</article>"
    )


def render_page(report: RiskReport) -> str:
    """Render the complete report as a self-contained HTML page."""
    provenance = report.provenance

    summary = (
        f'<section class="summary"><h2>Summary for the board</h2>'
        f"<p>{escape(report.summary)}</p></section>"
        if report.summary
        else ""
    )

    if report.is_empty:
        body = "<p>No risks could be ranked from the supplied data.</p>"
    else:
        body = "".join(_risk_section(entry) for entry in report.entries)

    if report.quality.issues:
        gaps = "".join(
            f'<li><span class="sev {issue.severity.value}">'
            f"{SEVERITY_LABELS[issue.severity]}</span> — {escape(issue.summary)} "
            f"({issue.affected_count} affected) {escape(issue.detail)}</li>"
            for issue in report.quality.ordered
        )
    else:
        gaps = "<li>No data quality issues were detected.</li>"

    gaps += (
        f"<li>{report.intelligence_set_aside} threat intelligence records were set "
        "aside as industry background with no match in this estate.</li>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Cyber Risk Briefing</title>
<style>{STYLES}</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Cyber Risk Briefing</h1>
  <p class="sub">Top {len(report.entries)} risks, selected from {report.total_findings}
  open findings across {report.total_assets} assets.</p>
</header>

<div class="note">
  Ranking is not severity ordering. Each risk is scored on internet exposure,
  active exploitation, business criticality, ransomware association and missing
  compensating controls, so a maximum-severity flaw on an isolated host ranks
  below a lesser flaw on an internet-facing payment system under active attack.
  Remediation guidance is quoted from NIST SP 800-53 Rev. 5 as retrieved, not
  recalled from a model.
</div>

{summary}

{body}

<h2 class="section">What this report could not see</h2>
<ul class="gaps">{gaps}</ul>

<footer>
  <strong>Provenance</strong>
  <ul>
    <li>Generated {escape(provenance.generated_at)}</li>
    <li>Reference data retrieved
        {escape(provenance.reference_retrieved_at or "unknown")}:
        {provenance.exploited_catalogue_entries:,} exploited vulnerability records,
        {provenance.controls_indexed:,} controls indexed</li>
    <li>Narration produced by {escape(provenance.narration_source)}</li>
  </ul>
  <p>Operates on synthetic data prepared for assessment purposes.</p>
</footer>
</div>
</body>
</html>"""

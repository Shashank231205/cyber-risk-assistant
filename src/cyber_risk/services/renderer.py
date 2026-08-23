"""Rendering the report as text a person can act on.

The brief asks for output a technical manager can read without further
processing, so the primary form is prose with a short evidence block, not a
table of identifiers and scores. The score is present because a reader is
entitled to ask why something ranks where it does, but it is never the whole
answer.

What the system could not see is rendered alongside what it found. A ranking
presented without its gaps invites the reader to assume coverage that does not
exist.
"""

from __future__ import annotations

from cyber_risk.models.enums import DataQualitySeverity
from cyber_risk.models.report import RiskEntry, RiskReport

SEVERITY_LABELS = {
    DataQualitySeverity.CRITICAL: "Critical",
    DataQualitySeverity.WARNING: "Warning",
    DataQualitySeverity.INFO: "Note",
}


def render_entry(entry: RiskEntry) -> str:
    """Render one ranked risk."""
    risk = entry.scored.risk
    lines = [
        f"## {entry.position}. {entry.finding_name}",
        "",
        entry.narrative.assessment,
        "",
    ]
    lines.extend(
        f"* **{label}.** {text}" for label, text in entry.narrative.points
    )
    lines.extend(
        [
            "",
            f"* **Asset**: {entry.asset_name} "
            f"({risk.asset.asset_type}, {risk.asset.environment.value.lower()}, "
            f"{'internet-facing' if risk.is_internet_facing else 'internal'})",
            f"* **Finding**: {entry.identifier} (severity "
            f"{risk.vulnerability.cvss} of 10, open {risk.vulnerability.days_open} days)",
            f"* **Threat activity**: {entry.threat_summary}",
            f"* **Exploitation**: {entry.exploitation_status}",
            f"* **Business service at risk**: {entry.service_name}",
        ]
    )

    if risk.exposure_conflict:
        lines.append(
            "* **Data note**: sources disagree on whether this asset is "
            "internet-facing; the asset inventory was treated as authoritative"
        )

    lines.extend(["", f"**Risk score {entry.scored.score:.1f} of 100**, from:"])
    lines.extend(
        f"  * {factor.name}: {factor.contribution:.1f} points"
        for factor in entry.scored.breakdown.ranked_factors
        if factor.contribution > 0
    )

    if entry.control is not None:
        control = entry.control
        confidence = " *(indicative match)*" if control.is_weak_match else ""
        lines.extend(
            [
                "",
                f"**Recommended control**: {control.citation}{confidence}",
                "",
                f"> {control.excerpt}",
            ]
        )
    else:
        lines.extend(["", "**Recommended control**: none retrieved for this finding."])

    return "\n".join(lines)


def render_report(report: RiskReport) -> str:
    """Render the complete report as Markdown."""
    provenance = report.provenance
    lines = [
        "# Cyber Risk Briefing",
        "",
        f"Top {len(report.entries)} risks, selected from {report.total_findings} open "
        f"findings across {report.total_assets} assets.",
        "",
        "Ranking is not severity ordering. Each risk is scored on internet "
        "exposure, active exploitation, business criticality, ransomware "
        "association and missing compensating controls, so a maximum-severity "
        "flaw on an isolated host ranks below a lesser flaw on an "
        "internet-facing payment system under active attack.",
        "",
    ]

    if report.summary.is_present:
        lines.extend(["## Summary for the board", "", report.summary.position, ""])
        lines.extend(
            f"* **{label}.** {text}" for label, text in report.summary.points
        )
        lines.append("")

    lines.extend(["---", ""])

    if report.is_empty:
        lines.append("No risks could be ranked from the supplied data.")
        return "\n".join(lines)

    lines.extend(f"{render_entry(entry)}\n\n---\n" for entry in report.entries)

    lines.extend(["", "## What this report could not see", ""])
    if report.quality.issues:
        lines.extend(
            f"* **{SEVERITY_LABELS[issue.severity]}**: {issue.summary} "
            f"({issue.affected_count} affected)"
            + (f" {issue.detail}" if issue.detail else "")
            for issue in report.quality.ordered
        )
    else:
        lines.append("* No data quality issues were detected.")

    lines.append(
        f"* {report.intelligence_set_aside} threat intelligence records were set "
        "aside as industry background with no match in this estate."
    )

    lines.extend(
        [
            "",
            "## Provenance",
            "",
            f"* Generated: {provenance.generated_at}",
            f"* Reference data retrieved: {provenance.reference_retrieved_at or 'unknown'}",
            f"* Exploited vulnerability catalogue: "
            f"{provenance.exploited_catalogue_entries:,} entries",
            f"* Control catalogue: {provenance.controls_indexed:,} controls indexed",
            f"* Narration produced by: {provenance.narration_source}",
            "* Guidance is quoted from NIST SP 800-53 Rev. 5 as retrieved, not "
            "recalled from a model.",
        ]
    )

    return "\n".join(lines)

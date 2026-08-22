"""Detection of data quality problems that would distort the ranking.

Each check answers a specific question about whether the ranking can be
trusted, and each returns a finding that travels with the report. The intent
is that a reader can see what the system could not see.
"""

from __future__ import annotations

from cyber_risk.ingestion.loaders import DataPack
from cyber_risk.models.domain import STALE_ASSET_THRESHOLD_DAYS
from cyber_risk.models.enums import DataQualitySeverity
from cyber_risk.models.quality import DataQualityIssue, DataQualityReport

#: Cap on identifiers listed against a single finding. The count is always
#: exact; the list is a sample for follow-up, not a dump of the inventory.
MAX_REFERENCES = 10


def _issue(
    code: str,
    severity: DataQualitySeverity,
    summary: str,
    references: list[str],
    detail: str = "",
) -> DataQualityIssue:
    """Build a finding with a bounded sample of references."""
    return DataQualityIssue(
        code=code,
        severity=severity,
        summary=summary,
        affected_count=len(references),
        detail=detail,
        references=tuple(sorted(references)[:MAX_REFERENCES]),
    )


def check_exposure_conflicts(pack: DataPack) -> DataQualityIssue | None:
    """Find assets whose exposure disagrees between the two sources.

    The asset inventory and the vulnerability feed both record whether a host
    is reachable from the internet. Where they disagree the ranking changes
    materially, so the conflict is surfaced rather than quietly resolved. The
    inventory is treated as authoritative because it is the system of record
    for the asset itself.
    """
    assets = pack.assets_by_id
    conflicting = [
        vulnerability.vuln_id
        for vulnerability in pack.vulnerabilities
        if (asset := assets.get(vulnerability.asset_id)) is not None
        and (vulnerability.asset_exposure.value == "Internet") != asset.internet_exposed
    ]
    if not conflicting:
        return None

    return _issue(
        "exposure_conflict",
        DataQualitySeverity.CRITICAL,
        "Asset inventory and vulnerability feed disagree on internet exposure.",
        conflicting,
        detail=(
            "Exposure is the highest weighted ranking factor. The asset inventory "
            "is treated as authoritative; these findings should be confirmed "
            "manually before the ranking is acted on."
        ),
    )


def check_orphaned_vulnerabilities(pack: DataPack) -> DataQualityIssue | None:
    """Find findings referencing an asset that is not in the inventory."""
    known = set(pack.assets_by_id)
    orphaned = [v.vuln_id for v in pack.vulnerabilities if v.asset_id not in known]
    if not orphaned:
        return None

    return _issue(
        "orphaned_vulnerability",
        DataQualitySeverity.CRITICAL,
        "Findings reference assets that are absent from the inventory.",
        orphaned,
        detail=(
            "These findings cannot be scored: without an asset there is no "
            "exposure, criticality or business service to weigh."
        ),
    )


def check_unscanned_assets(pack: DataPack) -> DataQualityIssue | None:
    """Find assets carrying no findings at all.

    An asset with no findings is indistinguishable from an asset that was
    never scanned. Reporting it as clean would overstate coverage, so it is
    reported as unknown.
    """
    scanned = {v.asset_id for v in pack.vulnerabilities}
    unscanned = [a.asset_id for a in pack.assets if a.asset_id not in scanned]
    if not unscanned:
        return None

    return _issue(
        "no_findings_recorded",
        DataQualitySeverity.WARNING,
        "Assets have no findings recorded and may simply be unscanned.",
        unscanned,
        detail=(
            "These assets cannot appear in the ranking. Absence of findings is "
            "not evidence that they are free of them."
        ),
    )


def check_unowned_assets(pack: DataPack) -> DataQualityIssue | None:
    """Find assets with no owning team."""
    unowned = [a.asset_id for a in pack.assets if not a.has_owner]
    if not unowned:
        return None

    return _issue(
        "unowned_asset",
        DataQualitySeverity.WARNING,
        "Assets have no owning team recorded.",
        unowned,
        detail="Findings on these assets have nobody assigned to remediate them.",
    )


def check_stale_assets(pack: DataPack) -> DataQualityIssue | None:
    """Find inventory records that have not been seen recently."""
    stale = [a.asset_id for a in pack.assets if a.is_stale]
    if not stale:
        return None

    return _issue(
        "stale_inventory",
        DataQualitySeverity.WARNING,
        "Inventory records have not been refreshed recently.",
        stale,
        detail=(
            f"Not seen for more than {STALE_ASSET_THRESHOLD_DAYS} days. Their "
            "exposure, controls and even existence may no longer be accurate."
        ),
    )


def check_catalogue_coverage(pack: DataPack) -> DataQualityIssue | None:
    """Report how much of the estate can be checked against the public catalogue.

    Only published CVE identifiers can be looked up. Everything else is
    unknown rather than safe, and the proportion matters to how much weight a
    reader should place on exploitation evidence.
    """
    unassessable = [
        v.vuln_id for v in pack.vulnerabilities if not v.is_catalogue_assessable
    ]
    if not unassessable:
        return None

    total = len(pack.vulnerabilities)
    percentage = round(100 * len(unassessable) / total)
    return _issue(
        "not_catalogue_assessable",
        DataQualitySeverity.WARNING,
        (
            f"{len(unassessable)} of {total} findings ({percentage}%) cannot be "
            "cross-referenced against the public exploited vulnerability catalogue."
        ),
        unassessable,
        detail=(
            "These carry locally assigned identifiers. They are ranked on the "
            "remaining evidence and are reported as not assessable, never as "
            "not exploited."
        ),
    )


def check_unmatched_intelligence(pack: DataPack) -> DataQualityIssue | None:
    """Report intelligence records that do not match anything in the estate.

    Recorded as information rather than a problem: correctly excluding
    unrelated campaigns is the system working, but the reader should know how
    much of the feed was set aside.
    """
    identifiers = {v.cve for v in pack.vulnerabilities}
    unmatched = [
        t.intel_id
        for t in pack.threat_intel
        if t.matched_cve_or_control not in identifiers
    ]
    if not unmatched:
        return None

    return _issue(
        "intelligence_not_matched",
        DataQualitySeverity.INFO,
        (
            f"{len(unmatched)} of {len(pack.threat_intel)} intelligence records "
            "do not correspond to anything in this estate."
        ),
        unmatched,
        detail=(
            "Excluded from the ranking as industry background rather than "
            "organisational risk."
        ),
    )


def check_missing_service_definitions(pack: DataPack) -> DataQualityIssue | None:
    """Find assets pointing at a business service that has no definition."""
    defined = set(pack.services_by_name)
    missing = sorted({a.business_service for a in pack.assets if a.business_service not in defined})
    if not missing:
        return None

    return _issue(
        "undefined_business_service",
        DataQualitySeverity.WARNING,
        "Assets reference business services that have no definition.",
        missing,
        detail=(
            "Business impact for these assets cannot be weighed, so their "
            "findings will rank lower than they may deserve."
        ),
    )


#: Every check, run in order for each report.
CHECKS = (
    check_exposure_conflicts,
    check_orphaned_vulnerabilities,
    check_missing_service_definitions,
    check_unscanned_assets,
    check_unowned_assets,
    check_stale_assets,
    check_catalogue_coverage,
    check_unmatched_intelligence,
)


def assess_quality(pack: DataPack) -> DataQualityReport:
    """Run every data quality check against ``pack``."""
    issues = [issue for check in CHECKS if (issue := check(pack)) is not None]
    return DataQualityReport(issues=tuple(issues))

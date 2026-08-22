"""Joining findings to assets, services and threat activity.

This is the structured half of the system. Everything here is an exact join
or filter over records with known keys, which is why it is queried rather than
embedded: the questions asked of this data have precise answers, and an
approximate nearest-neighbour match would introduce error where none needs to
exist.

Two joins are deliberately not naive:

Threat intelligence is many-to-many.
    One identifier may be referenced by several campaigns, and a campaign may
    reference identifiers this estate does not have. Every match is kept;
    every non-match is excluded from the ranking as industry background.

Exposure is contested.
    Two sources record whether a host is reachable from the internet. The
    inventory wins, and disagreement is recorded rather than resolved away.
"""

from __future__ import annotations

from collections.abc import Mapping

from cyber_risk.core.logging import get_logger
from cyber_risk.ingestion.loaders import DataPack
from cyber_risk.models.risk import CorrelatedRisk, KevEntry

logger = get_logger(__name__)


def correlate(
    pack: DataPack,
    kev_entries: Mapping[str, KevEntry] | None = None,
) -> tuple[CorrelatedRisk, ...]:
    """Join every finding to its asset, service and matching threat activity.

    Args:
        pack: The validated data pack.
        kev_entries: Public catalogue entries keyed by CVE identifier. Absent
            entries mean *not assessable*, never *not exploited*.

    Returns:
        One correlated record per finding that resolves to a known asset,
        in input order.
    """
    catalogue = kev_entries or {}
    assets = pack.assets_by_id
    services = pack.services_by_name
    intel_index = pack.intel_by_identifier

    correlated: list[CorrelatedRisk] = []
    unresolved = 0

    for vulnerability in pack.vulnerabilities:
        asset = assets.get(vulnerability.asset_id)
        if asset is None:
            # Reported by the data quality checks; it cannot be scored, because
            # without an asset there is no exposure or business context to weigh.
            unresolved += 1
            continue

        declared_internet = vulnerability.asset_exposure.value == "Internet"

        correlated.append(
            CorrelatedRisk(
                vulnerability=vulnerability,
                asset=asset,
                service=services.get(asset.business_service),
                intel=intel_index.get(vulnerability.cve, ()),
                kev=catalogue.get(vulnerability.cve)
                if vulnerability.is_catalogue_assessable
                else None,
                exposure_conflict=declared_internet != asset.internet_exposed,
            )
        )

    logger.info(
        "correlation complete",
        correlated=len(correlated),
        unresolved=unresolved,
        with_intel=sum(1 for r in correlated if r.intel),
        with_catalogue_entry=sum(1 for r in correlated if r.kev is not None),
    )
    return tuple(correlated)


def unmatched_intelligence(pack: DataPack) -> tuple[str, ...]:
    """Return identifiers of intelligence records this estate is not exposed to.

    Correctly excluding these is the system working rather than failing, but
    the count belongs in the output so a reader knows how much of the feed was
    set aside and why.
    """
    identifiers = {v.cve for v in pack.vulnerabilities}
    return tuple(
        record.intel_id
        for record in pack.threat_intel
        if record.matched_cve_or_control not in identifiers
    )

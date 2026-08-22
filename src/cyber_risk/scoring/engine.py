"""The deterministic risk model.

Scoring is a pure transform over correlated records. It performs no I/O, makes
no model calls and holds no state, so the same input always produces the same
ranking and the whole model can be exercised in tests without infrastructure.

The five factors and their ordering come from the analyst guidance in the MDR
advisory: internet exposure first, then active exploitation, then business
criticality, ransomware association, and missing compensating controls.

Technical severity is deliberately not a factor of its own. It participates
inside the exploitation factor and is capped there, because a severity score
describes how bad a flaw would be if reached, not whether anyone can reach it.
That is what makes a maximum-severity flaw on an isolated development host
rank below a lesser flaw on an internet-facing payment system under active
attack.
"""

from __future__ import annotations

from cyber_risk.config.settings import RiskWeights
from cyber_risk.models.domain import STALE_ASSET_THRESHOLD_DAYS
from cyber_risk.models.enums import DeploymentEnvironment, ExploitMaturity
from cyber_risk.models.risk import CorrelatedRisk, ScoreBreakdown, ScoredRisk, ScoreFactor

#: Share of the exploitation factor available to technical severity alone.
#: Capped so severity can raise a finding that already has other evidence but
#: cannot by itself push one to the top of the list.
CVSS_SHARE = 0.35

#: Days after which an unremediated finding with an available patch is treated
#: as a control failure rather than ordinary backlog.
REMEDIATION_SLA_DAYS = 90

#: Compliance regimes that materially raise the consequence of a breach for a
#: payments business, beyond the service's own recorded impact.
HIGH_CONSEQUENCE_REGIMES = frozenset({"PCI DSS", "GDPR", "UAE PDPL"})


def _clamp(value: float) -> float:
    """Constrain a sub-score to the 0.0-1.0 range factors are defined on."""
    return max(0.0, min(1.0, value))


def score_internet_exposure(risk: CorrelatedRisk) -> tuple[float, list[str]]:
    """Score reachability from the internet.

    Weighted highest because every campaign in the current advisory begins at
    an internet-facing asset. An unreachable flaw cannot be the first step in
    an intrusion.
    """
    evidence: list[str] = []

    if not risk.is_internet_facing:
        if risk.asset.environment is DeploymentEnvironment.PRODUCTION:
            evidence.append("Internal production asset; not directly reachable.")
            return 0.15, evidence
        evidence.append("Internal non-production asset; not directly reachable.")
        return 0.05, evidence

    score = 0.80
    evidence.append("Asset is reachable from the internet.")

    if not risk.vulnerability.auth_required:
        score += 0.20
        evidence.append("Exploitation requires no authentication.")

    if risk.exposure_conflict:
        evidence.append(
            "Sources disagree on exposure; the asset inventory was treated as "
            "authoritative."
        )

    return _clamp(score), evidence


def score_active_exploitation(risk: CorrelatedRisk) -> tuple[float, list[str]]:
    """Score how readily this finding can actually be exploited.

    Combines confirmed catalogue listing, observed campaign maturity, the
    scanner's exploit flag and technical severity. Severity is capped so it
    cannot dominate the other, more decisive evidence.
    """
    evidence: list[str] = []
    signals: list[float] = []

    if risk.kev is not None:
        signals.append(1.0)
        evidence.append(
            "Listed in the public catalogue of known exploited vulnerabilities."
        )
    elif not risk.vulnerability.is_catalogue_assessable:
        evidence.append(
            "Locally assigned identifier; exploitation status cannot be "
            "confirmed against the public catalogue."
        )

    maturity = risk.peak_exploit_maturity
    if maturity is not ExploitMaturity.NOT_APPLICABLE:
        signals.append(maturity.rank)
        evidence.append(f"Observed exploit maturity: {maturity.value.lower()}.")

    if risk.vulnerability.exploit_available:
        signals.append(0.60)
        evidence.append("A working exploit is available.")

    severity = risk.vulnerability.cvss / 10.0
    signals.append(severity * CVSS_SHARE)
    evidence.append(f"Technical severity {risk.vulnerability.cvss:.1f} of 10.")

    return _clamp(max(signals)), evidence


def score_business_criticality(risk: CorrelatedRisk) -> tuple[float, list[str]]:
    """Score what is lost if this asset is compromised."""
    evidence: list[str] = []
    score = risk.asset.criticality.rank * 0.40
    evidence.append(f"Asset criticality is {risk.asset.criticality.value.lower()}.")

    service = risk.service
    if service is None:
        evidence.append("No business service definition; business impact is unknown.")
        return _clamp(score), evidence

    score += service.revenue_impact.rank * 0.25

    if service.customer_facing:
        score += 0.15
        evidence.append(
            f"Supports {service.business_service}, a customer-facing service."
        )
    else:
        evidence.append(f"Supports {service.business_service}.")

    regimes = set(service.compliance_scope) & HIGH_CONSEQUENCE_REGIMES
    if regimes:
        score += 0.10
        evidence.append(
            f"In scope for {', '.join(sorted(regimes))}, raising breach consequence."
        )

    score += service.risk_appetite.rank * 0.10
    if service.rto_hours <= 4:
        evidence.append(
            f"Recovery objective is {service.rto_hours} hour(s); little tolerance "
            "for downtime."
        )

    return _clamp(score), evidence


def score_ransomware_association(risk: CorrelatedRisk) -> tuple[float, list[str]]:
    """Score evidence linking this finding to ransomware activity."""
    evidence: list[str] = []

    if risk.kev is not None and risk.kev.known_ransomware_campaign_use:
        evidence.append(
            "The public catalogue records use of this vulnerability in "
            "ransomware campaigns."
        )
        return 1.0, evidence

    ransomware_intel = [r for r in risk.intel if r.ransomware_association]
    if not ransomware_intel:
        return 0.0, evidence

    score = 0.60
    best_confidence = max(r.confidence.rank for r in ransomware_intel)
    score += best_confidence * 0.20

    regional = [r for r in ransomware_intel if r.target_region.lower() == "middle east"]
    if regional:
        score += 0.20
        evidence.append(
            "Ransomware activity reported against this region specifically."
        )

    actors = sorted({r.threat_actor for r in ransomware_intel if r.threat_actor})
    campaigns = sorted({r.campaign_name for r in ransomware_intel if r.campaign_name})
    if actors and campaigns:
        evidence.append(
            f"Referenced by {', '.join(actors)} in campaign "
            f"{', '.join(campaigns)} with ransomware deployment."
        )
    else:
        evidence.append("Referenced by campaign activity involving ransomware.")

    return _clamp(score), evidence


def score_missing_controls(risk: CorrelatedRisk) -> tuple[float, list[str]]:
    """Score the absence of controls that would detect or contain an intrusion."""
    evidence: list[str] = []
    score = 0.0

    if not risk.asset.edr_installed:
        score += 0.40
        evidence.append("No endpoint detection and response agent is installed.")

    if not risk.vulnerability.patch_available:
        score += 0.25
        evidence.append(
            "No vendor patch is available; containment depends on compensating "
            "controls."
        )
    elif risk.vulnerability.days_open > REMEDIATION_SLA_DAYS:
        score += 0.20
        evidence.append(
            f"A patch has been available while the finding stayed open for "
            f"{risk.vulnerability.days_open} days."
        )

    if not risk.asset.has_owner:
        score += 0.20
        evidence.append("No owning team is recorded, so remediation is unassigned.")

    if risk.asset.is_stale:
        score += 0.15
        evidence.append(
            f"Inventory record not refreshed for {risk.asset.last_seen_days} days "
            f"(threshold {STALE_ASSET_THRESHOLD_DAYS}); its controls may be "
            "inaccurate."
        )

    if not evidence:
        evidence.append("Expected compensating controls are present.")

    return _clamp(score), evidence


#: Factor name, scoring function, and the weight attribute it draws on.
FACTOR_DEFINITIONS = (
    ("Internet exposure", score_internet_exposure, "internet_exposure"),
    ("Active exploitation", score_active_exploitation, "active_exploitation"),
    ("Business criticality", score_business_criticality, "business_criticality"),
    ("Ransomware association", score_ransomware_association, "ransomware_association"),
    ("Missing controls", score_missing_controls, "missing_controls"),
)


def score_risk(risk: CorrelatedRisk, weights: RiskWeights) -> ScoredRisk:
    """Score one correlated risk, retaining the full derivation.

    Args:
        risk: The correlated finding to score.
        weights: Configured factor weights.

    Returns:
        The risk together with an auditable breakdown normalised to 0-100.
    """
    factors: list[ScoreFactor] = []
    total_weight = weights.total

    for name, scorer, attribute in FACTOR_DEFINITIONS:
        weight = float(getattr(weights, attribute))
        value, evidence = scorer(risk)
        factors.append(
            ScoreFactor(
                name=name,
                weight=weight,
                score=value,
                contribution=(value * weight / total_weight) * 100.0,
                evidence=tuple(evidence),
            )
        )

    total = sum(factor.contribution for factor in factors)
    return ScoredRisk(
        risk=risk,
        breakdown=ScoreBreakdown(total=min(100.0, total), factors=tuple(factors)),
    )


def rank_risks(
    risks: tuple[CorrelatedRisk, ...],
    weights: RiskWeights,
) -> tuple[ScoredRisk, ...]:
    """Score and order every correlated risk, highest first.

    Ordering is fully deterministic: ties fall back to technical severity and
    then to the finding identifier.
    """
    return tuple(sorted((score_risk(r, weights) for r in risks), key=lambda s: s.sort_key))


def select_top_risks(
    ranked: tuple[ScoredRisk, ...],
    limit: int,
    *,
    one_per_asset: bool = True,
) -> tuple[ScoredRisk, ...]:
    """Take the highest-scoring risks, optionally one per asset.

    Several findings on a single host frequently resolve to one action, so a
    short list that spends multiple places on the same asset tells the reader
    less than one covering the same number of distinct problems. The
    highest-scoring finding for an asset is kept and the rest are set aside.

    If limiting to one per asset cannot fill the list, the remaining places
    are filled from the highest-scoring risks that were set aside, so the
    caller always receives ``limit`` entries when that many exist.

    Args:
        ranked: Risks already ordered highest first.
        limit: How many entries to return.
        one_per_asset: Whether to prefer distinct assets.

    Returns:
        The selected risks, still ordered highest first.
    """
    if not one_per_asset:
        return ranked[:limit]

    selected: list[ScoredRisk] = []
    deferred: list[ScoredRisk] = []
    seen_assets: set[str] = set()

    for scored in ranked:
        asset_id = scored.risk.asset.asset_id
        if asset_id in seen_assets:
            deferred.append(scored)
            continue
        seen_assets.add(asset_id)
        selected.append(scored)
        if len(selected) == limit:
            return tuple(selected)

    selected.extend(deferred[: limit - len(selected)])
    return tuple(sorted(selected, key=lambda s: s.sort_key))

"""Correlated risk records and their scoring output.

A correlated risk joins one finding to the asset it sits on, the business
service that asset supports, and any threat activity referencing it. Scoring
then produces a breakdown rather than a bare number: every point in the final
score is attributable to a named factor with the evidence that raised it.

That attribution is the point. A ranking a reader cannot interrogate is a
ranking they cannot act on, and the explanation shown to a reader is
generated from these structures rather than asserted independently.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cyber_risk.models.domain import Asset, BusinessService, ThreatIntel, Vulnerability
from cyber_risk.models.enums import ExploitMaturity


class KevEntry(BaseModel):
    """A record from the public exploited vulnerability catalogue."""

    model_config = ConfigDict(frozen=True)

    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str = ""
    short_description: str = ""
    required_action: str = ""
    due_date: str = ""
    known_ransomware_campaign_use: bool = False


class CorrelatedRisk(BaseModel):
    """One finding joined to everything known about it."""

    model_config = ConfigDict(frozen=True)

    vulnerability: Vulnerability
    asset: Asset
    service: BusinessService | None = None
    intel: tuple[ThreatIntel, ...] = ()
    kev: KevEntry | None = None
    exposure_conflict: bool = False

    @property
    def risk_id(self) -> str:
        """Stable identifier for this correlated record."""
        return self.vulnerability.vuln_id

    @property
    def is_internet_facing(self) -> bool:
        """Whether the asset is reachable from the internet.

        The asset inventory is authoritative. It is the system of record for
        the asset, whereas the exposure field on a finding is a snapshot taken
        at scan time. Where they disagree the conflict is recorded so the
        reader can see the ranking rested on a contested value.
        """
        return self.asset.internet_exposed

    @property
    def ransomware_linked(self) -> bool:
        """Whether any evidence ties this finding to ransomware activity."""
        if self.kev is not None and self.kev.known_ransomware_campaign_use:
            return True
        return any(record.ransomware_association for record in self.intel)

    @property
    def peak_exploit_maturity(self) -> ExploitMaturity:
        """The most advanced exploit maturity across all matched campaigns."""
        if not self.intel:
            return ExploitMaturity.NOT_APPLICABLE
        return max((r.exploit_maturity for r in self.intel), key=lambda m: m.rank)

    @property
    def campaign_names(self) -> tuple[str, ...]:
        """Distinct campaign names referencing this finding."""
        seen = {r.campaign_name for r in self.intel if r.campaign_name}
        return tuple(sorted(seen))

    @property
    def threat_actors(self) -> tuple[str, ...]:
        """Distinct named threat actors referencing this finding."""
        seen = {
            r.threat_actor
            for r in self.intel
            if r.threat_actor and r.threat_actor.lower() != "unknown"
        }
        return tuple(sorted(seen))


class ScoreFactor(BaseModel):
    """One weighted contribution to a risk score.

    Attributes:
        name: Human-readable factor name.
        weight: Configured weight for this factor.
        score: Normalised strength of the factor, 0.0 to 1.0.
        contribution: Points this factor contributed to the final score.
        evidence: Specific observations that produced ``score``.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    weight: float = Field(ge=0.0)
    score: float = Field(ge=0.0, le=1.0)
    contribution: float = Field(ge=0.0)
    evidence: tuple[str, ...] = ()


class ScoreBreakdown(BaseModel):
    """The complete, auditable derivation of one risk score."""

    model_config = ConfigDict(frozen=True)

    total: float = Field(ge=0.0, le=100.0)
    factors: tuple[ScoreFactor, ...]

    @property
    def ranked_factors(self) -> tuple[ScoreFactor, ...]:
        """Factors ordered by how much they contributed."""
        return tuple(sorted(self.factors, key=lambda f: f.contribution, reverse=True))

    @property
    def dominant_factor(self) -> ScoreFactor | None:
        """The factor that contributed most, if any factor contributed at all."""
        ranked = [f for f in self.ranked_factors if f.contribution > 0]
        return ranked[0] if ranked else None

    @property
    def all_evidence(self) -> tuple[str, ...]:
        """Every observation gathered, ordered by factor contribution."""
        return tuple(item for factor in self.ranked_factors for item in factor.evidence)


class ScoredRisk(BaseModel):
    """A correlated risk together with its score."""

    model_config = ConfigDict(frozen=True)

    risk: CorrelatedRisk
    breakdown: ScoreBreakdown

    @property
    def score(self) -> float:
        """The final risk score, 0 to 100."""
        return self.breakdown.total

    @property
    def sort_key(self) -> tuple[float, float, str]:
        """Deterministic ordering key.

        Ties are broken first by technical severity and finally by identifier,
        so an identical input always produces an identical ordering.
        """
        return (-self.breakdown.total, -self.risk.vulnerability.cvss, self.risk.risk_id)

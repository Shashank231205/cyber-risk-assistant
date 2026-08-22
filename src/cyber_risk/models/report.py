"""The assembled risk report.

This is what a reader receives. Each entry carries the asset, the finding, the
matched threat activity, the business service at risk, why it ranks where it
does, and the control that applies, with the provenance of every external
source it drew on.

Provenance is part of the output rather than an appendix. A reader deciding
whether to act on a ranking needs to know when the reference data was
retrieved, whether the narration came from a model or from templates, and what
the system could not see.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cyber_risk.models.quality import DataQualityReport
from cyber_risk.models.risk import ScoredRisk
from cyber_risk.retrieval.retriever import RetrievedControl


class RiskEntry(BaseModel):
    """One ranked risk as presented to a reader."""

    model_config = ConfigDict(frozen=True)

    position: int = Field(ge=1)
    scored: ScoredRisk
    control: RetrievedControl | None
    narrative: str

    @property
    def asset_name(self) -> str:
        """The affected asset."""
        return self.scored.risk.asset.asset_name

    @property
    def identifier(self) -> str:
        """The finding's published or internal identifier."""
        return self.scored.risk.vulnerability.cve

    @property
    def finding_name(self) -> str:
        """The finding's descriptive name."""
        return self.scored.risk.vulnerability.vulnerability_name

    @property
    def service_name(self) -> str:
        """The business service at risk."""
        service = self.scored.risk.service
        return service.business_service if service else "Not defined"

    @property
    def threat_summary(self) -> str:
        """The matched threat activity, or an explicit statement of its absence."""
        risk = self.scored.risk
        if not risk.campaign_names:
            return "No matching campaign in the current feed"

        actors = ", ".join(risk.threat_actors) or "unattributed"
        return f"{', '.join(risk.campaign_names)} ({actors})"

    @property
    def exploitation_status(self) -> str:
        """What is known about exploitation, stated honestly."""
        risk = self.scored.risk
        if risk.kev is not None:
            if risk.kev.known_ransomware_campaign_use:
                return "Confirmed exploited, used in ransomware campaigns"
            return "Confirmed exploited in the wild"
        if not risk.vulnerability.is_catalogue_assessable:
            return "Not assessable against the public catalogue"
        return "No public catalogue entry found"


class ReportProvenance(BaseModel):
    """Where the report's inputs came from."""

    model_config = ConfigDict(frozen=True)

    generated_at: str
    reference_retrieved_at: str = ""
    exploited_catalogue_entries: int = 0
    controls_indexed: int = 0
    narration_provider: str | None = None
    weights: dict[str, float] = Field(default_factory=dict)

    @property
    def narration_source(self) -> str:
        """How the prose in this report was produced."""
        return self.narration_provider or "deterministic templates (no model used)"


class RiskReport(BaseModel):
    """The complete report."""

    model_config = ConfigDict(frozen=True)

    entries: tuple[RiskEntry, ...]
    summary: str = ""
    quality: DataQualityReport
    provenance: ReportProvenance
    total_findings: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    intelligence_set_aside: int = Field(ge=0)

    @property
    def is_empty(self) -> bool:
        """Whether the report contains no ranked risks."""
        return not self.entries

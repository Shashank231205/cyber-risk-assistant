"""Response models for the public API.

These are deliberately separate from the domain models. The API surface is a
contract with callers, and coupling it to internal types means an internal
refactor becomes a breaking change, or worse, quietly widens what is exposed.

The separation is also a disclosure boundary: fields reach a caller because
they were named here, never because they happened to exist on a domain object.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cyber_risk.models.report import RiskEntry, RiskReport


class FactorResponse(BaseModel):
    """One factor's contribution to a risk score."""

    model_config = ConfigDict(frozen=True)

    name: str
    contribution: float
    evidence: tuple[str, ...]


class ControlResponse(BaseModel):
    """Remediation guidance retrieved from the control catalogue."""

    model_config = ConfigDict(frozen=True)

    control_id: str
    title: str
    family: str
    excerpt: str
    citation: str
    similarity: float
    is_weak_match: bool


class NarrativeResponse(BaseModel):
    """The prose written for one risk."""

    model_config = ConfigDict(frozen=True)

    assessment: str
    threat: str
    impact: str
    action: str


class RiskResponse(BaseModel):
    """One ranked risk."""

    model_config = ConfigDict(frozen=True)

    position: int
    score: float
    narrative: NarrativeResponse
    asset: str
    asset_type: str
    environment: str
    internet_facing: bool
    identifier: str
    finding: str
    severity: float
    days_open: int
    business_service: str
    business_impact: str
    threat_activity: str
    exploitation_status: str
    exposure_conflict: bool
    factors: tuple[FactorResponse, ...]
    control: ControlResponse | None

    @classmethod
    def from_entry(cls, entry: RiskEntry) -> RiskResponse:
        """Project a report entry onto the public shape."""
        risk = entry.scored.risk
        control = entry.control

        return cls(
            position=entry.position,
            score=round(entry.scored.score, 1),
            narrative=NarrativeResponse(
                assessment=entry.narrative.assessment,
                threat=entry.narrative.threat,
                impact=entry.narrative.impact,
                action=entry.narrative.action,
            ),
            asset=entry.asset_name,
            asset_type=risk.asset.asset_type,
            environment=risk.asset.environment.value,
            internet_facing=risk.is_internet_facing,
            identifier=entry.identifier,
            finding=entry.finding_name,
            severity=risk.vulnerability.cvss,
            days_open=risk.vulnerability.days_open,
            business_service=entry.service_name,
            business_impact=risk.service.business_impact if risk.service else "",
            threat_activity=entry.threat_summary,
            exploitation_status=entry.exploitation_status,
            exposure_conflict=risk.exposure_conflict,
            factors=tuple(
                FactorResponse(
                    name=factor.name,
                    contribution=round(factor.contribution, 1),
                    evidence=factor.evidence,
                )
                for factor in entry.scored.breakdown.ranked_factors
                if factor.contribution > 0
            ),
            control=(
                ControlResponse(
                    control_id=control.control_id,
                    title=control.title,
                    family=control.family,
                    excerpt=control.excerpt,
                    citation=control.citation,
                    similarity=round(control.score, 3),
                    is_weak_match=control.is_weak_match,
                )
                if control is not None
                else None
            ),
        )


class QualityIssueResponse(BaseModel):
    """One data quality finding."""

    model_config = ConfigDict(frozen=True)

    code: str
    severity: str
    summary: str
    detail: str
    affected_count: int


class ProvenanceResponse(BaseModel):
    """Where the report's inputs came from."""

    model_config = ConfigDict(frozen=True)

    generated_at: str
    reference_retrieved_at: str
    exploited_catalogue_entries: int
    controls_indexed: int
    narration_source: str
    weights: dict[str, float]


class SummaryResponse(BaseModel):
    """The board-level opening of the report."""

    model_config = ConfigDict(frozen=True)

    position: str
    exposure: str
    consequence: str
    confidence: str


class ReportResponse(BaseModel):
    """The complete report."""

    model_config = ConfigDict(frozen=True)

    summary: SummaryResponse
    risks: tuple[RiskResponse, ...]
    total_findings: int
    total_assets: int
    intelligence_set_aside: int
    data_quality: tuple[QualityIssueResponse, ...]
    provenance: ProvenanceResponse

    @classmethod
    def from_report(cls, report: RiskReport) -> ReportResponse:
        """Project the report onto the public shape."""
        provenance = report.provenance
        return cls(
            summary=SummaryResponse(
                position=report.summary.position,
                exposure=report.summary.exposure,
                consequence=report.summary.consequence,
                confidence=report.summary.confidence,
            ),
            risks=tuple(RiskResponse.from_entry(entry) for entry in report.entries),
            total_findings=report.total_findings,
            total_assets=report.total_assets,
            intelligence_set_aside=report.intelligence_set_aside,
            data_quality=tuple(
                QualityIssueResponse(
                    code=issue.code,
                    severity=issue.severity.value,
                    summary=issue.summary,
                    detail=issue.detail,
                    affected_count=issue.affected_count,
                )
                for issue in report.quality.ordered
            ),
            provenance=ProvenanceResponse(
                generated_at=provenance.generated_at,
                reference_retrieved_at=provenance.reference_retrieved_at,
                exploited_catalogue_entries=provenance.exploited_catalogue_entries,
                controls_indexed=provenance.controls_indexed,
                narration_source=provenance.narration_source,
                weights=provenance.weights,
            ),
        )


class HealthResponse(BaseModel):
    """Liveness and readiness."""

    model_config = ConfigDict(frozen=True)

    status: str
    version: str
    controls_indexed: int = 0
    narration_providers: tuple[str, ...] = ()


class ErrorResponse(BaseModel):
    """An error, carrying nothing a caller should not see."""

    model_config = ConfigDict(frozen=True)

    error: str
    message: str
    request_id: str = Field(
        default="",
        description="Correlates this response with the server logs.",
    )

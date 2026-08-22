"""Data quality findings surfaced alongside the ranking.

A risk report that silently hides what it could not see is more dangerous
than one that admits its gaps: the reader assumes coverage that does not
exist. Every issue detected during ingestion and correlation is therefore
carried through to the output rather than logged and forgotten.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cyber_risk.models.enums import DataQualitySeverity


class DataQualityIssue(BaseModel):
    """A single detected problem with the input data.

    Attributes:
        code: Stable machine-readable identifier for the issue type.
        severity: How much the issue should affect confidence in the output.
        summary: One-line description safe to show a reader.
        affected_count: How many records exhibit the issue.
        detail: Optional explanation of the consequence for the ranking.
        references: Record identifiers exhibiting the issue, for follow-up.
    """

    model_config = ConfigDict(frozen=True)

    code: str
    severity: DataQualitySeverity
    summary: str
    affected_count: int = Field(ge=0)
    detail: str = ""
    references: tuple[str, ...] = ()


class DataQualityReport(BaseModel):
    """The full set of issues detected for one run."""

    model_config = ConfigDict(frozen=True)

    issues: tuple[DataQualityIssue, ...] = ()

    @property
    def has_critical(self) -> bool:
        """Whether any issue undermines confidence in the ranking itself."""
        return any(i.severity is DataQualitySeverity.CRITICAL for i in self.issues)

    def by_severity(self, severity: DataQualitySeverity) -> tuple[DataQualityIssue, ...]:
        """Return the issues at a given severity."""
        return tuple(i for i in self.issues if i.severity is severity)

    @property
    def ordered(self) -> tuple[DataQualityIssue, ...]:
        """Issues sorted most severe first, for presentation."""
        order = {
            DataQualitySeverity.CRITICAL: 0,
            DataQualitySeverity.WARNING: 1,
            DataQualitySeverity.INFO: 2,
        }
        return tuple(sorted(self.issues, key=lambda i: (order[i.severity], i.code)))

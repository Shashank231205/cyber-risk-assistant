"""The prose written for one risk.

Split into four parts rather than held as one block of text. A reader scanning
five entries wants to find the impact line without reading the assessment
again, and separate fields let each renderer lay them out in the way its
medium suits.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RiskNarrative(BaseModel):
    """What a reader is told about one risk."""

    model_config = ConfigDict(frozen=True)

    assessment: str
    threat: str = ""
    impact: str = ""
    action: str = ""

    @property
    def points(self) -> tuple[tuple[str, str], ...]:
        """The supporting lines, labelled and in reading order."""
        candidates = (
            ("Threat", self.threat),
            ("Impact", self.impact),
            ("Action", self.action),
        )
        return tuple((label, text) for label, text in candidates if text)

    def as_text(self) -> str:
        """Flatten to plain text, for contexts without structure."""
        parts = [self.assessment]
        parts.extend(f"{label}: {text}" for label, text in self.points)
        return " ".join(parts)

"""The board-level opening of the report.

Held as four fields rather than one block. A board reads the position first and
looks for the limits of the assessment last, and separate fields let each
renderer lay them out so both are found quickly.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ExecutiveSummary(BaseModel):
    """What the board is told before any detail."""

    model_config = ConfigDict(frozen=True)

    position: str = ""
    exposure: str = ""
    consequence: str = ""
    confidence: str = ""

    @property
    def is_present(self) -> bool:
        """Whether there is anything to show."""
        return bool(self.position)

    @property
    def points(self) -> tuple[tuple[str, str], ...]:
        """The supporting lines, labelled and in reading order."""
        candidates = (
            ("Exposure", self.exposure),
            ("Consequence", self.consequence),
            ("Confidence", self.confidence),
        )
        return tuple((label, text) for label, text in candidates if text)

    def as_text(self) -> str:
        """Flatten to plain text, for contexts without structure."""
        parts = [self.position]
        parts.extend(f"{label}: {text}" for label, text in self.points)
        return " ".join(part for part in parts if part)

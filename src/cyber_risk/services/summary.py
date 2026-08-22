"""The board-level summary that opens the report.

The scenario is a CISO briefing a board in 48 hours, and a board reads the
first paragraph. This produces that paragraph from aggregate figures only: no
identifier, hostname or actor name reaches it, which keeps the summary at the
altitude its audience reads at and avoids restating detail that follows.

Like the per-risk narration, this is presentation over settled facts. Every
figure is computed before the model is called, and a deterministic version is
always produced first, so the summary survives an unavailable provider.
"""

from __future__ import annotations

from pathlib import Path

from cyber_risk.core.logging import get_logger
from cyber_risk.models.quality import DataQualityReport
from cyber_risk.models.report import RiskEntry
from cyber_risk.services.llm import ProviderChain

logger = get_logger(__name__)

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "executive_summary.md"

#: Longest acceptable generated summary. A board paragraph that runs long has
#: stopped being a summary, and an over-long response usually means the model
#: has started listing detail that belongs in the risk entries.
MAX_SUMMARY_CHARS = 1200


class SummaryFigures:
    """The aggregate position, computed from the ranked entries."""

    def __init__(
        self,
        entries: tuple[RiskEntry, ...],
        quality: DataQualityReport,
        total_findings: int,
        total_assets: int,
    ) -> None:
        self.total_findings = total_findings
        self.total_assets = total_assets
        self.presented = len(entries)
        self.highest_score = max((e.scored.score for e in entries), default=0.0)
        self.internet_facing = sum(1 for e in entries if e.scored.risk.is_internet_facing)
        self.confirmed_exploited = sum(1 for e in entries if e.scored.risk.kev is not None)
        self.ransomware_linked = sum(1 for e in entries if e.scored.risk.ransomware_linked)
        self.services = tuple(
            sorted({e.service_name for e in entries if e.service_name != "Not defined"})
        )
        self.regimes = tuple(
            sorted(
                {
                    regime
                    for e in entries
                    if e.scored.risk.service is not None
                    for regime in e.scored.risk.service.compliance_scope
                }
            )
        )
        self.gaps = tuple(
            f"{issue.summary} ({issue.affected_count} affected)"
            for issue in quality.ordered
            if issue.code
            in {"no_findings_recorded", "not_catalogue_assessable", "exposure_conflict"}
        )

    def as_prompt(self) -> str:
        """Render the figures as the input block the instructions describe."""
        return "\n".join(
            [
                f"Findings reviewed: {self.total_findings}",
                f"Assets covered: {self.total_assets}",
                f"Top risks presented: {self.presented}",
                f"Highest score: {self.highest_score:.1f}",
                f"Internet-facing among the top risks: {self.internet_facing}",
                f"Confirmed exploited among the top risks: {self.confirmed_exploited}",
                f"Ransomware-linked among the top risks: {self.ransomware_linked}",
                f"Business services affected: {', '.join(self.services) or 'none identified'}",
                f"Compliance regimes affected: {', '.join(self.regimes) or 'none recorded'}",
                f"Coverage gaps: {'; '.join(self.gaps) or 'none detected'}",
            ]
        )


def deterministic_summary(figures: SummaryFigures) -> str:
    """Compose the summary without a language model."""
    if figures.presented == 0:
        return (
            f"We reviewed {figures.total_findings} open findings across "
            f"{figures.total_assets} assets and could not rank any risk from the "
            "available data."
        )

    sentences = [
        f"We reviewed {figures.total_findings} open findings across "
        f"{figures.total_assets} assets and identified {figures.presented} that "
        "warrant immediate attention."
    ]

    concentration = []
    if figures.internet_facing:
        concentration.append(
            f"{figures.internet_facing} sit on systems reachable directly from the internet"
        )
    if figures.confirmed_exploited:
        concentration.append(
            f"{figures.confirmed_exploited} exploit weaknesses confirmed to be under active attack"
        )
    if figures.ransomware_linked:
        concentration.append(f"{figures.ransomware_linked} are linked to ransomware activity")
    if concentration:
        sentences.append(f"Of these, {', and '.join(concentration)}.")

    if figures.services:
        consequence = f"They affect {', '.join(figures.services)}"
        if figures.regimes:
            consequence += (
                f", placing {' and '.join(figures.regimes)} obligations at risk "
                "if any is compromised"
            )
        sentences.append(consequence + ".")

    if figures.gaps:
        sentences.append(
            "Two limits should be noted alongside this: " + "; ".join(figures.gaps) + "."
            if len(figures.gaps) == 2
            else "The following limits apply to this assessment: "
            + "; ".join(figures.gaps)
            + "."
        )

    return " ".join(sentences)


class SummaryService:
    """Produces the paragraph that opens the report."""

    def __init__(self, chain: ProviderChain) -> None:
        self._chain = chain

    async def summarise(self, figures: SummaryFigures) -> str:
        """Return the summary, falling back to the deterministic version."""
        fallback = deterministic_summary(figures)

        if not self._chain.is_available:
            return fallback

        generated = await self._chain.generate(
            PROMPT_PATH.read_text(encoding="utf-8"), figures.as_prompt()
        )
        if generated is None:
            return fallback

        cleaned = " ".join(generated.split())
        if not cleaned or len(cleaned) > MAX_SUMMARY_CHARS:
            logger.warning("generated summary was unusable", length=len(cleaned))
            return fallback

        return cleaned

"""Assembling the risk report.

This is the orchestration layer. It owns the sequence: load, correlate,
score, select, retrieve, narrate: and nothing else: every step is
implemented elsewhere and injected here, so the pipeline can be re-ordered or
a stage replaced without touching the components.

Expensive work is done once at startup. The data pack, the reference
snapshots and the retrieval index are all loaded before the first request, and
the completed report is cached, so a reader waits for none of it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cyber_risk.config.settings import Settings
from cyber_risk.core.logging import get_logger
from cyber_risk.ingestion.loaders import DataPack
from cyber_risk.ingestion.quality_checks import assess_quality
from cyber_risk.ingestion.reference_data import (
    SnapshotManifest,
    load_kev_snapshot,
    load_manifest,
)
from cyber_risk.models.report import ReportProvenance, RiskEntry, RiskReport
from cyber_risk.models.risk import KevEntry, ScoredRisk
from cyber_risk.models.summary import ExecutiveSummary
from cyber_risk.retrieval.retriever import ControlRetriever, RetrievedControl
from cyber_risk.scoring.engine import rank_risks, select_top_risks
from cyber_risk.services.correlation import correlate, unmatched_intelligence
from cyber_risk.services.narration import NarrationService
from cyber_risk.services.summary import SummaryFigures, SummaryService

logger = get_logger(__name__)


class ReportService:
    """Produces the ranked risk report."""

    def __init__(
        self,
        settings: Settings,
        pack: DataPack,
        retriever: ControlRetriever,
        narration: NarrationService,
        summary: SummaryService | None = None,
        kev_entries: dict[str, KevEntry] | None = None,
        manifest: SnapshotManifest | None = None,
    ) -> None:
        self._settings = settings
        self._pack = pack
        self._retriever = retriever
        self._narration = narration
        self._summary = summary
        self._kev = kev_entries or {}
        self._manifest = manifest
        self._cached: RiskReport | None = None

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        retriever: ControlRetriever,
        narration: NarrationService,
        summary: SummaryService | None = None,
    ) -> ReportService:
        """Build a service by loading everything from configured locations."""
        reference_dir = settings.resolve_path(settings.data_reference_dir)
        return cls(
            settings=settings,
            pack=DataPack.load(settings.resolve_path(settings.data_raw_dir)),
            retriever=retriever,
            narration=narration,
            summary=summary,
            kev_entries=load_kev_snapshot(reference_dir),
            manifest=load_manifest(reference_dir),
        )

    async def generate(self, limit: int | None = None, *, refresh: bool = False) -> RiskReport:
        """Produce the report, reusing the cached result when possible.

        Args:
            limit: How many risks to present. Defaults to the configured count.
            refresh: Rebuild even when a cached report exists.
        """
        requested = limit or self._settings.risk_top_n
        if not refresh and self._cached is not None and len(self._cached.entries) == requested:
            return self._cached

        report = await self._build(requested)
        if requested == self._settings.risk_top_n:
            self._cached = report
        return report

    async def _build(self, limit: int) -> RiskReport:
        """Run the full pipeline."""
        correlated = correlate(self._pack, self._kev)
        ranked = rank_risks(correlated, self._settings.weights)
        selected = select_top_risks(ranked, limit)

        pairs: list[tuple[ScoredRisk, RetrievedControl | None]] = [
            (scored, self._best_control(scored)) for scored in selected
        ]
        narratives, provider = await self._narration.narrate(pairs)

        entries = tuple(
            RiskEntry(
                position=position,
                scored=scored,
                control=control,
                narrative=narrative,
            )
            for position, ((scored, control), narrative) in enumerate(
                zip(pairs, narratives, strict=True), start=1
            )
        )

        quality = assess_quality(self._pack)
        figures = SummaryFigures(
            entries, quality, len(self._pack.vulnerabilities), len(self._pack.assets)
        )
        summary = (
            await self._summary.summarise(figures)
            if self._summary is not None
            else ExecutiveSummary()
        )

        report = RiskReport(
            entries=entries,
            summary=summary,
            quality=quality,
            provenance=self._provenance(provider),
            total_findings=len(self._pack.vulnerabilities),
            total_assets=len(self._pack.assets),
            intelligence_set_aside=len(unmatched_intelligence(self._pack)),
        )

        logger.info(
            "report generated",
            entries=len(entries),
            narration=provider or "deterministic",
        )
        return report

    def _best_control(self, scored: ScoredRisk) -> RetrievedControl | None:
        """Retrieve the most applicable control, tolerating retrieval failure.

        A retrieval problem must not cost the reader the ranking, so the entry
        is presented without guidance rather than not at all.
        """
        try:
            results = self._retriever.retrieve(scored.risk, limit=1)
        except Exception as error:
            logger.warning(
                "guidance retrieval failed for one risk",
                risk_id=scored.risk.risk_id,
                reason=type(error).__name__,
            )
            return None
        return results[0] if results else None

    def _provenance(self, provider: str | None) -> ReportProvenance:
        """Record where this report's inputs came from."""
        weights = self._settings.weights
        return ReportProvenance(
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            reference_retrieved_at=self._manifest.retrieved_at if self._manifest else "",
            exploited_catalogue_entries=len(self._kev),
            controls_indexed=self._retriever.catalogue_size,
            narration_provider=provider,
            weights={
                "internet exposure": weights.internet_exposure,
                "active exploitation": weights.active_exploitation,
                "business criticality": weights.business_criticality,
                "ransomware association": weights.ransomware_association,
                "missing controls": weights.missing_controls,
            },
        )


def default_index_path(settings: Settings) -> Path:
    """Where the retrieval index is expected to live."""
    return settings.resolve_path(settings.vector_index_path)

"""Tests for narration, report assembly and rendering.

Narration is the one place a language model touches the output, so the
guarantees asserted here are about containment: what it is given, what is
accepted back, and what happens when it is unavailable.
"""

from __future__ import annotations

import pytest

from cyber_risk.config.settings import Settings
from cyber_risk.ingestion.loaders import DataPack
from cyber_risk.models.quality import DataQualityReport
from cyber_risk.models.report import ReportProvenance, RiskEntry, RiskReport
from cyber_risk.models.risk import CorrelatedRisk, KevEntry, ScoredRisk
from cyber_risk.retrieval.retriever import RetrievedControl
from cyber_risk.scoring.engine import score_risk
from cyber_risk.services.llm import ProviderChain
from cyber_risk.services.narration import (
    NarrationService,
    build_prompt,
    describe_evidence,
    deterministic_narration,
    load_system_prompt,
)
from cyber_risk.services.renderer import render_report
from cyber_risk.services.report_service import ReportService
from tests.unit.test_llm_chain import StubProvider
from tests.unit.test_scoring_engine import (
    WEIGHTS,
    make_asset,
    make_intel,
    make_service,
    make_vuln,
)

CONTROL = RetrievedControl(
    control_id="SI-2",
    title="Flaw Remediation",
    family="System and Information Integrity",
    excerpt="Identify, report, and correct system flaws.",
    score=0.80,
)


def make_scored(**overrides: object) -> ScoredRisk:
    """A scored risk with sensible defaults."""
    base: dict[str, object] = {
        "vulnerability": make_vuln(),
        "asset": make_asset(),
        "service": make_service(),
    }
    return score_risk(CorrelatedRisk(**{**base, **overrides}), WEIGHTS)


@pytest.mark.unit
class TestEvidenceBlock:
    def test_evidence_contains_the_established_facts(self) -> None:
        block = describe_evidence(make_scored(), CONTROL)

        assert "example-host" in block
        assert "CVE-2024-21762" in block
        assert "Payment Processing" in block
        assert "SI-2" in block

    def test_unassessable_finding_is_described_as_unknown(self) -> None:
        """The model must not be able to infer safety from silence."""
        block = describe_evidence(
            make_scored(vulnerability=make_vuln(cve="CTRL-SYN-001")), CONTROL
        )
        assert "not assessable" in block

    def test_absent_catalogue_entry_is_qualified(self) -> None:
        block = describe_evidence(make_scored(), CONTROL)
        assert "does not establish that it is not exploited" in block

    def test_confirmed_exploitation_is_stated(self) -> None:
        block = describe_evidence(
            make_scored(
                kev=KevEntry(cve_id="CVE-2024-21762", known_ransomware_campaign_use=True)
            ),
            CONTROL,
        )
        assert "confirmed exploited" in block
        assert "ransomware" in block

    def test_absent_campaign_is_stated_explicitly(self) -> None:
        block = describe_evidence(make_scored(intel=()), CONTROL)
        assert "no campaign in the feed" in block

    def test_weak_control_match_is_flagged_to_the_model(self) -> None:
        weak = CONTROL.model_copy(update={"is_weak_match": True})
        assert "low" in describe_evidence(make_scored(), weak)

    def test_absent_control_is_stated(self) -> None:
        assert "none retrieved" in describe_evidence(make_scored(), None)

    def test_scoring_evidence_is_included(self) -> None:
        block = describe_evidence(make_scored(), CONTROL)
        assert "Why it ranks here:" in block


@pytest.mark.unit
class TestPromptAssembly:
    def test_one_request_covers_every_risk(self) -> None:
        """Five sequential calls cost five chances to be rate limited."""
        prompt = build_prompt([(make_scored(), CONTROL)] * 3)

        assert "There are 3 risks" in prompt
        assert prompt.count("### Risk") == 3

    def test_system_prompt_forbids_invention(self) -> None:
        instructions = load_system_prompt().lower()
        assert "do not add" in instructions

    def test_system_prompt_treats_evidence_as_data(self) -> None:
        """The advisory arrives from outside, so its text is never an instruction."""
        instructions = load_system_prompt().lower()
        assert "never an instruction" in instructions


@pytest.mark.unit
class TestDeterministicNarration:
    def test_narration_needs_no_model(self) -> None:
        text = deterministic_narration(make_scored(), CONTROL)

        assert "example-host" in text
        assert "SI-2" in text
        assert len(text) > 100

    def test_unassessable_finding_is_qualified(self) -> None:
        text = deterministic_narration(
            make_scored(vulnerability=make_vuln(cve="CTRL-SYN-001")), CONTROL
        )
        assert "could not be confirmed" in text

    def test_campaign_attribution_is_included(self) -> None:
        text = deterministic_narration(make_scored(intel=(make_intel(),)), CONTROL)
        assert "Example Campaign" in text

    def test_narration_without_a_control_still_reads(self) -> None:
        assert deterministic_narration(make_scored(), None)


@pytest.mark.unit
class TestNarrationService:
    async def test_generated_text_is_used_when_well_formed(self) -> None:
        chain = ProviderChain((StubProvider("stub", "1: First risk.\n2: Second risk."),))
        service = NarrationService(chain)

        paragraphs, provider = await service.narrate(
            [(make_scored(), CONTROL), (make_scored(), CONTROL)]
        )

        assert paragraphs == ["First risk.", "Second risk."]
        assert provider == "stub"

    async def test_no_provider_falls_back_to_templates(self) -> None:
        paragraphs, provider = await NarrationService(ProviderChain(())).narrate(
            [(make_scored(), CONTROL)]
        )

        assert provider is None
        assert "example-host" in paragraphs[0]

    async def test_dead_provider_falls_back_to_templates(self) -> None:
        chain = ProviderChain((StubProvider("broken"),))
        paragraphs, provider = await NarrationService(chain).narrate([(make_scored(), CONTROL)])

        assert provider is None
        assert paragraphs[0]

    async def test_wrong_number_of_paragraphs_is_discarded(self) -> None:
        """A response that lost a risk is unusable, however fluent."""
        chain = ProviderChain((StubProvider("stub", "1: Only one paragraph."),))
        paragraphs, provider = await NarrationService(chain).narrate(
            [(make_scored(), CONTROL), (make_scored(), CONTROL)]
        )

        assert provider is None
        assert len(paragraphs) == 2

    async def test_unparseable_response_is_discarded(self) -> None:
        chain = ProviderChain((StubProvider("stub", "Here is some prose without numbering."),))
        paragraphs, provider = await NarrationService(chain).narrate([(make_scored(), CONTROL)])

        assert provider is None
        assert paragraphs[0]

    async def test_fabricated_control_reference_is_rejected(self) -> None:
        """A wrong control identifier reads as authoritative and misdirects work."""
        chain = ProviderChain((StubProvider("stub", "1: You should apply AC-17 instead."),))
        paragraphs, _ = await NarrationService(chain).narrate([(make_scored(), CONTROL)])

        assert "AC-17" not in paragraphs[0]

    async def test_supplied_control_reference_is_accepted(self) -> None:
        chain = ProviderChain((StubProvider("stub", "1: Apply SI-2 to correct the flaw."),))
        paragraphs, provider = await NarrationService(chain).narrate([(make_scored(), CONTROL)])

        assert paragraphs[0] == "Apply SI-2 to correct the flaw."
        assert provider == "stub"

    async def test_only_the_offending_paragraph_is_replaced(self) -> None:
        chain = ProviderChain(
            (StubProvider("stub", "1: Apply SI-2 correctly.\n2: Apply AC-17 wrongly."),)
        )
        paragraphs, _ = await NarrationService(chain).narrate(
            [(make_scored(), CONTROL), (make_scored(), CONTROL)]
        )

        assert paragraphs[0] == "Apply SI-2 correctly."
        assert "AC-17" not in paragraphs[1]

    async def test_no_risks_produces_no_narration(self) -> None:
        assert await NarrationService(ProviderChain(())).narrate([]) == ([], None)


@pytest.mark.unit
class TestRendering:
    def _report(self, **overrides: object) -> RiskReport:
        entry = RiskEntry(
            position=1,
            scored=make_scored(intel=(make_intel(),)),
            control=CONTROL,
            narrative="An explanatory paragraph about this risk.",
        )
        base: dict[str, object] = {
            "entries": (entry,),
            "quality": DataQualityReport(),
            "provenance": ReportProvenance(generated_at="2026-01-01 00:00 UTC"),
            "total_findings": 114,
            "total_assets": 60,
            "intelligence_set_aside": 16,
        }
        return RiskReport(**{**base, **overrides})

    def test_report_reads_as_prose_not_as_a_table(self) -> None:
        text = render_report(self._report())

        assert "An explanatory paragraph about this risk." in text
        assert "# Cyber Risk Briefing" in text

    def test_report_states_it_is_not_severity_ordering(self) -> None:
        assert "not severity ordering" in render_report(self._report())

    def test_every_required_element_is_present(self) -> None:
        """The brief requires asset, finding, intel, service and a reason."""
        text = render_report(self._report())

        assert "example-host" in text
        assert "CVE-2024-21762" in text
        assert "Example Campaign" in text
        assert "Payment Processing" in text
        assert "Risk score" in text

    def test_retrieved_control_is_attributed(self) -> None:
        text = render_report(self._report())
        assert "NIST SP 800-53 Rev. 5 SI-2" in text
        assert "Identify, report, and correct system flaws." in text

    def test_gaps_are_reported_alongside_findings(self) -> None:
        text = render_report(self._report())
        assert "What this report could not see" in text
        assert "16 threat intelligence records were set aside" in text

    def test_provenance_states_how_prose_was_produced(self) -> None:
        text = render_report(self._report())
        assert "deterministic templates" in text

    def test_score_contributions_are_itemised(self) -> None:
        """A reader is entitled to ask why something ranks where it does."""
        text = render_report(self._report())
        assert "Internet exposure:" in text

    def test_empty_report_is_stated_plainly(self) -> None:
        text = render_report(self._report(entries=()))
        assert "No risks could be ranked" in text

    def test_exposure_conflict_is_surfaced_to_the_reader(self) -> None:
        entry = RiskEntry(
            position=1,
            scored=score_risk(
                CorrelatedRisk(
                    vulnerability=make_vuln(asset_exposure="Internal"),
                    asset=make_asset(),
                    service=make_service(),
                    exposure_conflict=True,
                ),
                WEIGHTS,
            ),
            control=CONTROL,
            narrative="Paragraph.",
        )
        text = render_report(self._report(entries=(entry,)))
        assert "sources disagree" in text.lower()


@pytest.mark.unit
class TestReportService:
    class StubRetriever:
        """Returns a fixed control, or fails on demand."""

        catalogue_size = 10

        def __init__(self, fail: bool = False) -> None:
            self._fail = fail

        def retrieve(self, risk: object, limit: int | None = None) -> tuple[RetrievedControl, ...]:
            if self._fail:
                raise RuntimeError("retrieval unavailable")
            return (CONTROL,)

    def _service(self, pack: DataPack, **overrides: object) -> ReportService:
        base: dict[str, object] = {
            "settings": Settings(_env_file=None, risk_top_n=2),
            "pack": pack,
            "retriever": self.StubRetriever(),
            "narration": NarrationService(ProviderChain(())),
        }
        return ReportService(**{**base, **overrides})  # type: ignore[arg-type]

    @pytest.fixture
    def pack(self) -> DataPack:
        return DataPack(
            assets=(make_asset(), make_asset(asset_id="A-2", asset_name="second-host")),
            vulnerabilities=(make_vuln(), make_vuln(vuln_id="V-2", asset_id="A-2")),
            threat_intel=(make_intel(),),
            business_services=(make_service(business_service="Example Service"),),
            remediation_hints=(),
            threat_report="",
        )

    async def test_report_is_assembled(self, pack: DataPack) -> None:
        report = await self._service(pack).generate()

        assert len(report.entries) == 2
        assert report.total_findings == 2
        assert report.entries[0].position == 1

    async def test_entries_are_ordered_by_position(self, pack: DataPack) -> None:
        report = await self._service(pack).generate()
        assert [e.position for e in report.entries] == [1, 2]

    async def test_result_is_cached(self, pack: DataPack) -> None:
        service = self._service(pack)
        assert await service.generate() is await service.generate()

    async def test_refresh_rebuilds(self, pack: DataPack) -> None:
        service = self._service(pack)
        first = await service.generate()
        assert await service.generate(refresh=True) is not first

    async def test_retrieval_failure_does_not_lose_the_ranking(self, pack: DataPack) -> None:
        """A retrieval problem must not cost the reader the risk itself."""
        service = self._service(pack, retriever=self.StubRetriever(fail=True))
        report = await service.generate()

        assert len(report.entries) == 2
        assert all(entry.control is None for entry in report.entries)

    async def test_provenance_records_the_weights_used(self, pack: DataPack) -> None:
        report = await self._service(pack).generate()
        assert report.provenance.weights["internet exposure"] > 0

    async def test_quality_findings_travel_with_the_report(self, pack: DataPack) -> None:
        report = await self._service(pack).generate()
        assert isinstance(report.quality, DataQualityReport)

    async def test_rendered_output_is_readable(self, pack: DataPack) -> None:
        report = await self._service(pack).generate()
        assert "# Cyber Risk Briefing" in render_report(report)

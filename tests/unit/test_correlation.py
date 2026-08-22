"""Tests for joining findings to assets, services and threat activity."""

from __future__ import annotations

import pytest

from cyber_risk.ingestion.loaders import DataPack
from cyber_risk.models.domain import Asset, BusinessService, ThreatIntel, Vulnerability
from cyber_risk.models.enums import ExploitMaturity
from cyber_risk.models.risk import KevEntry
from cyber_risk.services.correlation import correlate, unmatched_intelligence
from tests.unit.test_scoring_engine import make_asset, make_intel, make_service, make_vuln


def make_pack(
    *,
    assets: tuple[Asset, ...] = (),
    vulnerabilities: tuple[Vulnerability, ...] = (),
    intel: tuple[ThreatIntel, ...] = (),
    services: tuple[BusinessService, ...] = (),
) -> DataPack:
    """Assemble a pack directly, bypassing file loading."""
    return DataPack(
        assets=assets or (make_asset(),),
        vulnerabilities=vulnerabilities or (make_vuln(),),
        threat_intel=intel,
        business_services=services or (make_service(business_service="Example Service"),),
        remediation_hints=(),
        threat_report="",
    )


@pytest.mark.unit
class TestJoining:
    def test_finding_is_joined_to_its_asset(self) -> None:
        correlated = correlate(make_pack())
        assert len(correlated) == 1
        assert correlated[0].asset.asset_id == "A-1"

    def test_finding_is_joined_to_its_business_service(self) -> None:
        correlated = correlate(make_pack())
        assert correlated[0].service is not None
        assert correlated[0].service.business_service == "Example Service"

    def test_absent_service_definition_is_tolerated(self) -> None:
        """A missing definition must not stop the finding being ranked."""
        pack = make_pack(
            assets=(make_asset(business_service="Undefined Service"),),
        )
        assert correlate(pack)[0].service is None

    def test_finding_without_a_known_asset_is_excluded(self) -> None:
        """Without an asset there is no exposure or business context to weigh."""
        pack = make_pack(vulnerabilities=(make_vuln(asset_id="A-MISSING"),))
        assert correlate(pack) == ()

    def test_input_order_is_preserved(self) -> None:
        pack = make_pack(
            vulnerabilities=(
                make_vuln(vuln_id="V-1"),
                make_vuln(vuln_id="V-2"),
                make_vuln(vuln_id="V-3"),
            )
        )
        assert [r.risk_id for r in correlate(pack)] == ["V-1", "V-2", "V-3"]


@pytest.mark.unit
class TestThreatIntelligenceJoin:
    def test_matching_campaign_is_attached(self) -> None:
        correlated = correlate(make_pack(intel=(make_intel(),)))
        assert len(correlated[0].intel) == 1

    def test_every_matching_campaign_is_kept(self) -> None:
        """The join is many-to-many; taking only the first match loses evidence."""
        pack = make_pack(
            intel=(
                make_intel(intel_id="TI-1", campaign_name="First"),
                make_intel(intel_id="TI-2", campaign_name="Second"),
            )
        )
        correlated = correlate(pack)
        assert len(correlated[0].intel) == 2
        assert correlated[0].campaign_names == ("First", "Second")

    def test_unrelated_campaign_is_not_attached(self) -> None:
        pack = make_pack(intel=(make_intel(matched_cve_or_control="CVE-1999-0001"),))
        assert correlate(pack)[0].intel == ()

    def test_peak_maturity_is_taken_across_campaigns(self) -> None:
        pack = make_pack(
            intel=(
                make_intel(intel_id="TI-1", exploit_maturity="Proof of Concept"),
                make_intel(intel_id="TI-2", exploit_maturity="Active Exploitation"),
            )
        )
        assert correlate(pack)[0].peak_exploit_maturity is ExploitMaturity.ACTIVE_EXPLOITATION

    def test_maturity_without_campaigns_is_not_applicable(self) -> None:
        assert correlate(make_pack())[0].peak_exploit_maturity is ExploitMaturity.NOT_APPLICABLE

    def test_unnamed_actors_are_excluded_from_attribution(self) -> None:
        pack = make_pack(intel=(make_intel(threat_actor="Unknown"),))
        assert correlate(pack)[0].threat_actors == ()

    def test_named_actors_are_reported(self) -> None:
        pack = make_pack(intel=(make_intel(threat_actor="ExampleActor"),))
        assert correlate(pack)[0].threat_actors == ("ExampleActor",)


@pytest.mark.unit
class TestCatalogueEnrichment:
    def test_published_identifier_is_enriched(self) -> None:
        entry = KevEntry(cve_id="CVE-2024-21762", known_ransomware_campaign_use=True)
        correlated = correlate(make_pack(), {"CVE-2024-21762": entry})

        assert correlated[0].kev is not None
        assert correlated[0].ransomware_linked is True

    def test_absent_entry_leaves_the_finding_unenriched(self) -> None:
        assert correlate(make_pack(), {})[0].kev is None

    def test_local_identifier_is_never_looked_up(self) -> None:
        """A locally minted identifier cannot appear in the public catalogue."""
        pack = make_pack(vulnerabilities=(make_vuln(cve="CTRL-SYN-001"),))
        entry = KevEntry(cve_id="CTRL-SYN-001")

        correlated = correlate(pack, {"CTRL-SYN-001": entry})
        assert correlated[0].kev is None

    def test_ransomware_link_can_come_from_intelligence_alone(self) -> None:
        pack = make_pack(intel=(make_intel(ransomware_association="Yes"),))
        assert correlate(pack)[0].ransomware_linked is True

    def test_no_evidence_means_no_ransomware_link(self) -> None:
        assert correlate(make_pack())[0].ransomware_linked is False


@pytest.mark.unit
class TestExposureConflict:
    def test_disagreement_is_recorded(self) -> None:
        pack = make_pack(
            assets=(make_asset(internet_exposed="Yes"),),
            vulnerabilities=(make_vuln(asset_exposure="Internal"),),
        )
        correlated = correlate(pack)

        assert correlated[0].exposure_conflict is True
        assert correlated[0].is_internet_facing is True

    def test_agreement_records_no_conflict(self) -> None:
        assert correlate(make_pack())[0].exposure_conflict is False

    def test_inventory_decides_exposure(self) -> None:
        """The inventory is the system of record for the asset itself."""
        pack = make_pack(
            assets=(make_asset(internet_exposed="No"),),
            vulnerabilities=(make_vuln(asset_exposure="Internet"),),
        )
        assert correlate(pack)[0].is_internet_facing is False


@pytest.mark.unit
class TestUnmatchedIntelligence:
    def test_unrelated_records_are_identified(self) -> None:
        pack = make_pack(
            intel=(
                make_intel(intel_id="TI-1"),
                make_intel(intel_id="TI-2", matched_cve_or_control="CVE-1999-0001"),
            )
        )
        assert unmatched_intelligence(pack) == ("TI-2",)

    def test_fully_matched_feed_reports_nothing(self) -> None:
        assert unmatched_intelligence(make_pack(intel=(make_intel(),))) == ()

"""Tests for domain entities.

These types are the contract between ingestion and the risk model. The
behaviour asserted here is what every downstream component is entitled to
assume without re-checking.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from cyber_risk.models.domain import (
    Asset,
    BusinessService,
    ThreatIntel,
    Vulnerability,
)
from cyber_risk.models.enums import (
    Confidence,
    Criticality,
    DeploymentEnvironment,
    ExploitMaturity,
    Exposure,
    FindingKind,
    ImpactLevel,
    RiskAppetite,
    Severity,
)

ASSET: dict[str, Any] = {
    "asset_id": "A-0001",
    "asset_name": "example-host",
    "asset_type": "API Server",
    "environment": "Production",
    "owner_team": "Platform",
    "business_service": "Example Service",
    "internet_exposed": "Yes",
    "criticality": "Critical",
    "data_classification": "Internal",
    "edr_installed": "Yes",
    "last_seen_days": "1",
    "location": "UAE",
    "vendor_product": "nginx 1.22",
}

VULN: dict[str, Any] = {
    "vuln_id": "V-0001",
    "asset_id": "A-0001",
    "vulnerability_name": "Example Flaw",
    "cve": "CVE-2024-21762",
    "severity": "Critical",
    "cvss": "9.8",
    "exploit_available": "Yes",
    "patch_available": "Yes",
    "days_open": "30",
    "asset_exposure": "Internet",
    "auth_required": "No",
    "status": "Open",
    "affected_component": "Example Component",
}

SERVICE: dict[str, Any] = {
    "business_service": "Example Service",
    "business_owner": "Example Owner",
    "business_impact": "Example impact statement",
    "customer_facing": "Yes",
    "compliance_scope": "PCI DSS, ISO 27001",
    "revenue_impact": "Critical",
    "rto_hours": "1",
    "depends_on": "Other Service",
    "risk_appetite": "Very Low",
}

INTEL: dict[str, Any] = {
    "intel_id": "TI-0001",
    "threat_actor": "ExampleActor",
    "campaign_name": "Example Campaign",
    "target_sector": "Financial Services",
    "target_region": "Middle East",
    "matched_cve_or_control": "CVE-2024-21762",
    "exploit_maturity": "Active Exploitation",
    "active_last_seen": "2026-04-20",
    "ransomware_association": "Yes",
    "confidence": "High",
    "summary": "Example summary.",
}


@pytest.mark.unit
class TestFlagParsing:
    @pytest.mark.parametrize("raw", ["Yes", "yes", "YES", "true", "Y", "1"])
    def test_affirmative_values_become_true(self, raw: str) -> None:
        assert Asset(**{**ASSET, "internet_exposed": raw}).internet_exposed is True

    @pytest.mark.parametrize("raw", ["No", "no", "false", "N", "0", ""])
    def test_negative_values_become_false(self, raw: str) -> None:
        assert Asset(**{**ASSET, "internet_exposed": raw}).internet_exposed is False

    def test_unrecognised_flag_is_rejected(self) -> None:
        """An unparsed flag must fail rather than default to a safe-looking value."""
        with pytest.raises(ValidationError):
            Asset(**{**ASSET, "internet_exposed": "maybe"})


@pytest.mark.unit
class TestAsset:
    def test_missing_owner_is_reported(self) -> None:
        assert Asset(**{**ASSET, "owner_team": "  "}).has_owner is False

    def test_present_owner_is_reported(self) -> None:
        assert Asset(**ASSET).has_owner is True

    @pytest.mark.parametrize(("days", "stale"), [(0, False), (30, False), (31, True), (180, True)])
    def test_staleness_threshold(self, days: int, stale: bool) -> None:
        assert Asset(**{**ASSET, "last_seen_days": days}).is_stale is stale

    def test_negative_last_seen_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Asset(**{**ASSET, "last_seen_days": -1})

    def test_unknown_environment_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Asset(**{**ASSET, "environment": "QA"})

    def test_entities_are_immutable(self) -> None:
        with pytest.raises(ValidationError):
            Asset(**ASSET).criticality = Criticality.LOW  # type: ignore[misc]

    def test_unexpected_column_is_rejected(self) -> None:
        """Schema drift must fail loudly, not be silently absorbed."""
        with pytest.raises(ValidationError):
            Asset(**{**ASSET, "unexpected_column": "value"})


@pytest.mark.unit
class TestVulnerabilityClassification:
    @pytest.mark.parametrize(
        "identifier", ["CVE-2024-21762", "CVE-2023-4966", "CVE-2025-24813"]
    )
    def test_published_identifiers_are_catalogue_assessable(self, identifier: str) -> None:
        vuln = Vulnerability(**{**VULN, "cve": identifier})
        assert vuln.finding_kind is FindingKind.CVE
        assert vuln.is_catalogue_assessable is True

    @pytest.mark.parametrize(
        "identifier",
        ["CVE-SYN-2026-0011", "CTRL-SYN-001", "K8S-SYN-002", "CICD-SYN-001"],
    )
    def test_local_identifiers_are_control_deficiencies(self, identifier: str) -> None:
        """Locally minted findings are kept and classified, never discarded."""
        vuln = Vulnerability(**{**VULN, "cve": identifier})
        assert vuln.finding_kind is FindingKind.CONTROL_DEFICIENCY
        assert vuln.is_catalogue_assessable is False

    def test_cvss_bounds_are_enforced(self) -> None:
        for bad in (-0.1, 10.1):
            with pytest.raises(ValidationError):
                Vulnerability(**{**VULN, "cvss": bad})

    @pytest.mark.parametrize("value", [0.0, 5.5, 10.0])
    def test_valid_cvss_is_accepted(self, value: float) -> None:
        assert Vulnerability(**{**VULN, "cvss": value}).cvss == value


@pytest.mark.unit
class TestBusinessService:
    def test_compliance_scope_is_split(self) -> None:
        assert BusinessService(**SERVICE).compliance_scope == ("PCI DSS", "ISO 27001")

    @pytest.mark.parametrize("sentinel", ["None", "none", "N/A", "-", "unknown"])
    def test_null_sentinels_do_not_count_as_compliance(self, sentinel: str) -> None:
        """A service marked 'None' must not register as regulated."""
        service = BusinessService(**{**SERVICE, "compliance_scope": sentinel})
        assert service.compliance_scope == ()
        assert service.is_regulated is False

    def test_blank_dependencies_become_empty(self) -> None:
        assert BusinessService(**{**SERVICE, "depends_on": ""}).depends_on == ()

    def test_multiple_dependencies_are_split(self) -> None:
        service = BusinessService(**{**SERVICE, "depends_on": "A Service, B Service"})
        assert service.depends_on == ("A Service", "B Service")

    def test_regulated_service_is_flagged(self) -> None:
        assert BusinessService(**SERVICE).is_regulated is True


@pytest.mark.unit
class TestThreatIntel:
    @pytest.mark.parametrize("region", ["Middle East", "Global", "global"])
    def test_relevant_regions_are_in_scope(self, region: str) -> None:
        assert ThreatIntel(**{**INTEL, "target_region": region}).targets_our_region is True

    def test_irrelevant_region_is_out_of_scope(self) -> None:
        assert ThreatIntel(**{**INTEL, "target_region": "Nordics"}).targets_our_region is False

    def test_unknown_exploit_maturity_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ThreatIntel(**{**INTEL, "exploit_maturity": "Rumoured"})


@pytest.mark.unit
class TestOrdinalRanking:
    """Ranks drive the scoring model, so their ordering is load-bearing."""

    @pytest.mark.parametrize(
        "sequence",
        [
            [Criticality.LOW, Criticality.MEDIUM, Criticality.HIGH, Criticality.CRITICAL],
            [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
            [ImpactLevel.LOW, ImpactLevel.MEDIUM, ImpactLevel.HIGH, ImpactLevel.CRITICAL],
            [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH],
            [Exposure.INTERNAL, Exposure.INTERNET],
            [
                DeploymentEnvironment.DEVELOPMENT,
                DeploymentEnvironment.STAGING,
                DeploymentEnvironment.PRODUCTION,
            ],
            [
                ExploitMaturity.NOT_APPLICABLE,
                ExploitMaturity.PROOF_OF_CONCEPT,
                ExploitMaturity.WEAPONIZED,
                ExploitMaturity.ACTIVE_EXPLOITATION,
            ],
        ],
    )
    def test_ranks_increase_with_severity(self, sequence: list[Any]) -> None:
        ranks = [member.rank for member in sequence]
        assert ranks == sorted(ranks)
        assert ranks[0] == 0.0
        assert ranks[-1] == 1.0

    def test_lower_risk_appetite_ranks_higher(self) -> None:
        """A service the business least wants disrupted must rank up, not down."""
        assert RiskAppetite.VERY_LOW.rank > RiskAppetite.HIGH.rank

    def test_ranks_are_normalised(self) -> None:
        for member in list(Criticality) + list(ExploitMaturity):
            assert 0.0 <= member.rank <= 1.0


@pytest.mark.unit
class TestAlreadyTypedInput:
    """Values may arrive already typed, for example from JSON rather than CSV."""

    def test_boolean_input_passes_through(self) -> None:
        assert Asset(**{**ASSET, "internet_exposed": True}).internet_exposed is True
        assert Asset(**{**ASSET, "edr_installed": False}).edr_installed is False

    def test_sequence_input_passes_through(self) -> None:
        service = BusinessService(**{**SERVICE, "compliance_scope": ["PCI DSS"]})
        assert service.compliance_scope == ("PCI DSS",)

    def test_single_member_ordinal_ranks_at_the_top(self) -> None:
        from cyber_risk.models.enums import OrdinalEnum

        class Solitary(OrdinalEnum):
            ONLY = "Only"

        assert Solitary.ONLY.rank == 1.0

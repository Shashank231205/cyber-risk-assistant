"""Tests for the deterministic risk model.

The central assertion is the one the brief sets out: a maximum-severity flaw
on an isolated development host must rank below a lesser flaw on an
internet-facing payment system under active attack. A model that fails that
comparison is doing severity sorting with extra steps.
"""

from __future__ import annotations

import pytest

from cyber_risk.config.settings import RiskWeights
from cyber_risk.models.domain import Asset, BusinessService, ThreatIntel, Vulnerability
from cyber_risk.models.risk import CorrelatedRisk, KevEntry
from cyber_risk.scoring.engine import (
    rank_risks,
    score_active_exploitation,
    score_business_criticality,
    score_internet_exposure,
    score_missing_controls,
    score_ransomware_association,
    score_risk,
    select_top_risks,
)

WEIGHTS = RiskWeights(_env_file=None)


def make_asset(**overrides: object) -> Asset:
    """An internet-facing production asset unless overridden."""
    base: dict[str, object] = {
        "asset_id": "A-1",
        "asset_name": "example-host",
        "asset_type": "API Server",
        "environment": "Production",
        "owner_team": "Platform",
        "business_service": "Example Service",
        "internet_exposed": "Yes",
        "criticality": "Critical",
        "data_classification": "Customer PII",
        "edr_installed": "Yes",
        "last_seen_days": 1,
        "location": "UAE",
        "vendor_product": "nginx",
    }
    return Asset(**{**base, **overrides})


def make_vuln(**overrides: object) -> Vulnerability:
    """A high-severity, internet-exposed finding unless overridden."""
    base: dict[str, object] = {
        "vuln_id": "V-1",
        "asset_id": "A-1",
        "vulnerability_name": "Example Flaw",
        "cve": "CVE-2024-21762",
        "severity": "Critical",
        "cvss": 9.0,
        "exploit_available": "Yes",
        "patch_available": "Yes",
        "days_open": 10,
        "asset_exposure": "Internet",
        "auth_required": "No",
        "status": "Open",
        "affected_component": "Component",
    }
    return Vulnerability(**{**base, **overrides})


def make_service(**overrides: object) -> BusinessService:
    """A regulated, customer-facing service unless overridden."""
    base: dict[str, object] = {
        "business_service": "Payment Processing",
        "business_owner": "Owner",
        "business_impact": "Payments fail.",
        "customer_facing": "Yes",
        "compliance_scope": "PCI DSS",
        "revenue_impact": "Critical",
        "rto_hours": 1,
        "depends_on": "",
        "risk_appetite": "Very Low",
    }
    return BusinessService(**{**base, **overrides})


def make_intel(**overrides: object) -> ThreatIntel:
    """An active, regional, ransomware-linked campaign unless overridden."""
    base: dict[str, object] = {
        "intel_id": "TI-1",
        "threat_actor": "ExampleActor",
        "campaign_name": "Example Campaign",
        "target_sector": "Financial Services",
        "target_region": "Middle East",
        "matched_cve_or_control": "CVE-2024-21762",
        "exploit_maturity": "Active Exploitation",
        "active_last_seen": "2026-04-20",
        "ransomware_association": "Yes",
        "confidence": "High",
        "summary": "Summary.",
    }
    return ThreatIntel(**{**base, **overrides})


def make_risk(**overrides: object) -> CorrelatedRisk:
    """A correlated risk with sensible defaults."""
    base: dict[str, object] = {
        "vulnerability": make_vuln(),
        "asset": make_asset(),
        "service": make_service(),
        "intel": (),
    }
    return CorrelatedRisk(**{**base, **overrides})


@pytest.mark.evaluation
class TestPrioritisationIsNotSeveritySorting:
    """The behaviour the brief specifies, asserted directly."""

    def test_exposed_payment_system_outranks_isolated_development_host(self) -> None:
        isolated = CorrelatedRisk(
            vulnerability=make_vuln(
                vuln_id="V-DEV", cvss=10.0, severity="Critical", asset_exposure="Internal"
            ),
            asset=make_asset(
                asset_id="A-DEV",
                environment="Development",
                internet_exposed="No",
                criticality="Low",
                business_service="Internal Tooling",
            ),
            service=make_service(
                business_service="Internal Tooling",
                customer_facing="No",
                compliance_scope="None",
                revenue_impact="Low",
                rto_hours=24,
                risk_appetite="High",
            ),
        )
        exposed = CorrelatedRisk(
            vulnerability=make_vuln(vuln_id="V-PAY", cvss=8.0, severity="High"),
            asset=make_asset(),
            service=make_service(),
            intel=(make_intel(),),
        )

        isolated_score = score_risk(isolated, WEIGHTS).score
        exposed_score = score_risk(exposed, WEIGHTS).score

        assert exposed_score > isolated_score, (
            f"severity 8.0 exposed payment system scored {exposed_score:.1f}, "
            f"severity 10.0 isolated development host scored {isolated_score:.1f}"
        )

    def test_severity_alone_cannot_reach_the_top(self) -> None:
        """Maximum severity with no other evidence must not outrank real risk."""
        severity_only = CorrelatedRisk(
            vulnerability=make_vuln(cvss=10.0, exploit_available="No", auth_required="Yes"),
            asset=make_asset(internet_exposed="No", criticality="Low"),
            service=make_service(customer_facing="No", revenue_impact="Low"),
        )
        assert score_risk(severity_only, WEIGHTS).score < 50.0

    def test_identical_severity_is_separated_by_context(self) -> None:
        exposed = make_risk(intel=(make_intel(),))
        internal = CorrelatedRisk(
            vulnerability=make_vuln(asset_exposure="Internal"),
            asset=make_asset(internet_exposed="No"),
            service=make_service(),
        )
        assert score_risk(exposed, WEIGHTS).score > score_risk(internal, WEIGHTS).score


@pytest.mark.unit
class TestInternetExposureFactor:
    def test_exposed_asset_scores_high(self) -> None:
        score, _ = score_internet_exposure(make_risk())
        assert score >= 0.9

    def test_internal_production_scores_above_internal_development(self) -> None:
        production, _ = score_internet_exposure(
            CorrelatedRisk(
                vulnerability=make_vuln(asset_exposure="Internal"),
                asset=make_asset(internet_exposed="No", environment="Production"),
            )
        )
        development, _ = score_internet_exposure(
            CorrelatedRisk(
                vulnerability=make_vuln(asset_exposure="Internal"),
                asset=make_asset(internet_exposed="No", environment="Development"),
            )
        )
        assert production > development

    def test_authentication_requirement_lowers_the_score(self) -> None:
        without_auth, _ = score_internet_exposure(make_risk())
        with_auth, _ = score_internet_exposure(
            make_risk(vulnerability=make_vuln(auth_required="Yes"))
        )
        assert without_auth > with_auth

    def test_inventory_wins_when_sources_disagree(self) -> None:
        """The inventory is the system of record for the asset."""
        risk = CorrelatedRisk(
            vulnerability=make_vuln(asset_exposure="Internal"),
            asset=make_asset(internet_exposed="Yes"),
            exposure_conflict=True,
        )
        score, evidence = score_internet_exposure(risk)

        assert score >= 0.9
        assert any("disagree" in item for item in evidence)


@pytest.mark.unit
class TestActiveExploitationFactor:
    def test_catalogue_listing_is_decisive(self) -> None:
        score, evidence = score_active_exploitation(
            make_risk(kev=KevEntry(cve_id="CVE-2024-21762"))
        )
        assert score == 1.0
        assert any("catalogue" in item for item in evidence)

    def test_unassessable_identifier_is_never_reported_as_safe(self) -> None:
        """Absence of a catalogue entry means unknown, not absent."""
        _, evidence = score_active_exploitation(
            make_risk(vulnerability=make_vuln(cve="CTRL-SYN-001"))
        )
        joined = " ".join(evidence).lower()
        assert "cannot be confirmed" in joined
        assert "not exploited" not in joined

    def test_observed_campaign_maturity_raises_the_score(self) -> None:
        quiet, _ = score_active_exploitation(
            make_risk(vulnerability=make_vuln(exploit_available="No"), intel=())
        )
        active, _ = score_active_exploitation(
            make_risk(vulnerability=make_vuln(exploit_available="No"), intel=(make_intel(),))
        )
        assert active > quiet

    def test_severity_contribution_is_capped(self) -> None:
        """Severity alone must not saturate the exploitation factor."""
        score, _ = score_active_exploitation(
            make_risk(
                vulnerability=make_vuln(cvss=10.0, exploit_available="No"),
                intel=(),
            )
        )
        assert score < 0.5


@pytest.mark.unit
class TestBusinessCriticalityFactor:
    def test_regulated_customer_facing_service_scores_higher(self) -> None:
        regulated, _ = score_business_criticality(make_risk())
        unregulated, _ = score_business_criticality(
            make_risk(
                service=make_service(
                    customer_facing="No", compliance_scope="None", revenue_impact="Low"
                )
            )
        )
        assert regulated > unregulated

    def test_missing_service_definition_is_reported(self) -> None:
        _, evidence = score_business_criticality(make_risk(service=None))
        assert any("unknown" in item.lower() for item in evidence)

    def test_lower_risk_appetite_raises_the_score(self) -> None:
        cautious, _ = score_business_criticality(make_risk())
        tolerant, _ = score_business_criticality(
            make_risk(service=make_service(risk_appetite="High"))
        )
        assert cautious > tolerant


@pytest.mark.unit
class TestRansomwareFactor:
    def test_no_evidence_scores_zero(self) -> None:
        score, evidence = score_ransomware_association(make_risk(intel=()))
        assert score == 0.0
        assert evidence == []

    def test_catalogue_ransomware_flag_is_decisive(self) -> None:
        score, _ = score_ransomware_association(
            make_risk(kev=KevEntry(cve_id="CVE-1", known_ransomware_campaign_use=True))
        )
        assert score == 1.0

    def test_regional_targeting_raises_the_score(self) -> None:
        regional, _ = score_ransomware_association(make_risk(intel=(make_intel(),)))
        global_only, _ = score_ransomware_association(
            make_risk(intel=(make_intel(target_region="Global"),))
        )
        assert regional > global_only

    def test_non_ransomware_campaigns_do_not_count(self) -> None:
        score, _ = score_ransomware_association(
            make_risk(intel=(make_intel(ransomware_association="No"),))
        )
        assert score == 0.0


@pytest.mark.unit
class TestMissingControlsFactor:
    def test_full_controls_score_zero(self) -> None:
        score, evidence = score_missing_controls(make_risk())
        assert score == 0.0
        assert any("present" in item for item in evidence)

    def test_absent_endpoint_agent_raises_the_score(self) -> None:
        score, _ = score_missing_controls(make_risk(asset=make_asset(edr_installed="No")))
        assert score > 0.0

    def test_unavailable_patch_raises_the_score(self) -> None:
        score, _ = score_missing_controls(
            make_risk(vulnerability=make_vuln(patch_available="No"))
        )
        assert score > 0.0

    def test_long_unremediated_finding_raises_the_score(self) -> None:
        score, evidence = score_missing_controls(
            make_risk(vulnerability=make_vuln(days_open=200))
        )
        assert score > 0.0
        assert any("200 days" in item for item in evidence)

    def test_unowned_asset_raises_the_score(self) -> None:
        score, _ = score_missing_controls(make_risk(asset=make_asset(owner_team="")))
        assert score > 0.0


@pytest.mark.unit
class TestBreakdownIntegrity:
    def test_every_factor_is_represented(self) -> None:
        breakdown = score_risk(make_risk(), WEIGHTS).breakdown
        assert len(breakdown.factors) == 5

    def test_contributions_sum_to_the_total(self) -> None:
        breakdown = score_risk(make_risk(intel=(make_intel(),)), WEIGHTS).breakdown
        assert sum(f.contribution for f in breakdown.factors) == pytest.approx(
            breakdown.total
        )

    def test_score_stays_within_bounds(self) -> None:
        maximum = score_risk(
            make_risk(
                asset=make_asset(edr_installed="No", owner_team="", last_seen_days=200),
                vulnerability=make_vuln(patch_available="No", days_open=400),
                intel=(make_intel(),),
                kev=KevEntry(cve_id="CVE-1", known_ransomware_campaign_use=True),
            ),
            WEIGHTS,
        ).score
        assert 0.0 <= maximum <= 100.0

    def test_every_factor_carries_evidence(self) -> None:
        """A contribution a reader cannot interrogate is not explainable."""
        breakdown = score_risk(make_risk(intel=(make_intel(),)), WEIGHTS).breakdown
        assert all(f.evidence for f in breakdown.factors if f.contribution > 0)

    def test_dominant_factor_is_the_largest_contributor(self) -> None:
        breakdown = score_risk(make_risk(intel=(make_intel(),)), WEIGHTS).breakdown
        dominant = breakdown.dominant_factor
        assert dominant is not None
        assert dominant.contribution == max(f.contribution for f in breakdown.factors)

    def test_weights_change_the_outcome(self) -> None:
        """Weights are configuration, so re-tuning must actually take effect."""
        internal = CorrelatedRisk(
            vulnerability=make_vuln(asset_exposure="Internal", cvss=10.0),
            asset=make_asset(internet_exposed="No"),
            service=make_service(),
        )
        default = score_risk(internal, WEIGHTS).score
        exposure_ignored = score_risk(
            internal, RiskWeights(_env_file=None, internet_exposure=0.0)
        ).score
        assert default != exposure_ignored


@pytest.mark.unit
class TestRankingDeterminism:
    def test_ranking_is_ordered_by_score(self) -> None:
        risks = (
            make_risk(vulnerability=make_vuln(vuln_id="V-1")),
            CorrelatedRisk(
                vulnerability=make_vuln(vuln_id="V-2", asset_exposure="Internal"),
                asset=make_asset(asset_id="A-2", internet_exposed="No"),
            ),
        )
        scores = [s.score for s in rank_risks(risks, WEIGHTS)]
        assert scores == sorted(scores, reverse=True)

    def test_repeated_runs_produce_identical_order(self) -> None:
        risks = tuple(
            make_risk(vulnerability=make_vuln(vuln_id=f"V-{n}")) for n in range(10)
        )
        first = [s.risk.risk_id for s in rank_risks(risks, WEIGHTS)]
        second = [s.risk.risk_id for s in rank_risks(risks, WEIGHTS)]
        assert first == second

    def test_ties_are_broken_predictably(self) -> None:
        """Identical evidence must still yield a stable, explainable order."""
        risks = (
            make_risk(vulnerability=make_vuln(vuln_id="V-9")),
            make_risk(vulnerability=make_vuln(vuln_id="V-2")),
        )
        assert [s.risk.risk_id for s in rank_risks(risks, WEIGHTS)] == ["V-2", "V-9"]

    def test_empty_input_produces_empty_output(self) -> None:
        assert rank_risks((), WEIGHTS) == ()


@pytest.mark.unit
class TestSelection:
    def test_selection_prefers_distinct_assets(self) -> None:
        """Several findings on one host usually resolve to a single action."""
        risks = (
            *(make_risk(vulnerability=make_vuln(vuln_id=f"V-{n}")) for n in range(4)),
            CorrelatedRisk(
                vulnerability=make_vuln(vuln_id="V-OTHER", asset_id="A-2"),
                asset=make_asset(asset_id="A-2", asset_name="other-host"),
                service=make_service(),
            ),
        )
        selected = select_top_risks(rank_risks(risks, WEIGHTS), 2)
        assert len({s.risk.asset.asset_id for s in selected}) == 2

    def test_list_is_filled_even_when_assets_repeat(self) -> None:
        """The caller asked for a fixed number of entries and must receive them."""
        risks = tuple(
            make_risk(vulnerability=make_vuln(vuln_id=f"V-{n}")) for n in range(5)
        )
        assert len(select_top_risks(rank_risks(risks, WEIGHTS), 3)) == 3

    def test_diversity_can_be_disabled(self) -> None:
        risks = tuple(
            make_risk(vulnerability=make_vuln(vuln_id=f"V-{n}")) for n in range(5)
        )
        selected = select_top_risks(rank_risks(risks, WEIGHTS), 3, one_per_asset=False)
        assert len({s.risk.asset.asset_id for s in selected}) == 1

    def test_selection_preserves_descending_order(self) -> None:
        risks = tuple(
            make_risk(
                vulnerability=make_vuln(vuln_id=f"V-{n}", cvss=float(n)),
                asset=make_asset(asset_id=f"A-{n}"),
            )
            for n in range(5)
        )
        scores = [s.score for s in select_top_risks(rank_risks(risks, WEIGHTS), 5)]
        assert scores == sorted(scores, reverse=True)

    def test_requesting_more_than_available_returns_all(self) -> None:
        risks = (make_risk(),)
        assert len(select_top_risks(rank_risks(risks, WEIGHTS), 10)) == 1


@pytest.mark.unit
class TestEvidenceAggregation:
    def test_evidence_is_gathered_in_contribution_order(self) -> None:
        breakdown = score_risk(make_risk(intel=(make_intel(),)), WEIGHTS).breakdown
        gathered = breakdown.all_evidence

        assert gathered
        assert gathered[0] in breakdown.ranked_factors[0].evidence

    def test_anonymous_campaign_still_produces_evidence(self) -> None:
        """Attribution may be absent; the ransomware link still must be stated."""
        _, evidence = score_ransomware_association(
            make_risk(intel=(make_intel(threat_actor="", campaign_name=""),))
        )
        assert any("ransomware" in item.lower() for item in evidence)

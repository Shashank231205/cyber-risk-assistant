"""Tests for loading and data quality assessment."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyber_risk.core.exceptions import DataSourceNotFoundError, SchemaValidationError
from cyber_risk.ingestion.loaders import DataPack
from cyber_risk.ingestion.quality_checks import MAX_REFERENCES, assess_quality
from cyber_risk.models.enums import DataQualitySeverity

ASSETS_CSV = (
    "asset_id,asset_name,asset_type,environment,owner_team,business_service,"
    "internet_exposed,criticality,data_classification,edr_installed,"
    "last_seen_days,location,vendor_product\n"
    "A-1,host-one,API Server,Production,Platform,Example Service,Yes,Critical,"
    "Internal,Yes,1,UAE,nginx\n"
)

VULNS_CSV = (
    "vuln_id,asset_id,vulnerability_name,cve,severity,cvss,exploit_available,"
    "patch_available,days_open,asset_exposure,auth_required,status,affected_component\n"
    "V-1,A-1,Example Flaw,CVE-2024-21762,Critical,9.8,Yes,Yes,30,Internet,No,Open,Component\n"
)

INTEL_CSV = (
    "intel_id,threat_actor,campaign_name,target_sector,target_region,"
    "matched_cve_or_control,exploit_maturity,active_last_seen,"
    "ransomware_association,confidence,summary\n"
    "TI-1,Actor,Campaign,Financial Services,Middle East,CVE-2024-21762,"
    "Active Exploitation,2026-04-20,Yes,High,Summary.\n"
)

SERVICES_CSV = (
    "business_service,business_owner,business_impact,customer_facing,"
    "compliance_scope,revenue_impact,rto_hours,depends_on,risk_appetite\n"
    "Example Service,Owner,Impact statement,Yes,PCI DSS,Critical,1,,Very Low\n"
)

HINTS_CSV = (
    "finding_type,recommended_action,priority_hint,validation_evidence\n"
    "Example Finding,Do the thing,P0,Evidence\n"
)

REPORT_MD = "# Advisory\n\nExample advisory body.\n"

FILES = {
    "assets.csv": ASSETS_CSV,
    "vulnerabilities.csv": VULNS_CSV,
    "threat_intelligence.csv": INTEL_CSV,
    "business_services.csv": SERVICES_CSV,
    "remediation_guidance.csv": HINTS_CSV,
    "synthetic_threat_report.md": REPORT_MD,
}


@pytest.fixture
def pack_dir(tmp_path: Path) -> Path:
    """A minimal, internally consistent data pack."""
    for name, content in FILES.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    return tmp_path


def write(directory: Path, name: str, content: str) -> None:
    """Overwrite one file in a pack directory."""
    (directory / name).write_text(content, encoding="utf-8")


@pytest.mark.unit
class TestLoading:
    def test_a_complete_pack_loads(self, pack_dir: Path) -> None:
        pack = DataPack.load(pack_dir)
        assert len(pack.assets) == 1
        assert len(pack.vulnerabilities) == 1
        assert pack.threat_report.startswith("# Advisory")

    def test_missing_directory_is_reported(self, tmp_path: Path) -> None:
        with pytest.raises(DataSourceNotFoundError):
            DataPack.load(tmp_path / "absent")

    @pytest.mark.parametrize("name", list(FILES))
    def test_every_file_is_required(self, pack_dir: Path, name: str) -> None:
        (pack_dir / name).unlink()
        with pytest.raises(DataSourceNotFoundError):
            DataPack.load(pack_dir)

    def test_invalid_row_is_rejected(self, pack_dir: Path) -> None:
        write(pack_dir, "assets.csv", ASSETS_CSV.replace(",Critical,", ",Catastrophic,"))
        with pytest.raises(SchemaValidationError):
            DataPack.load(pack_dir)

    def test_unexpected_column_is_rejected(self, pack_dir: Path) -> None:
        """Schema drift must stop the run rather than be silently absorbed."""
        header, row = ASSETS_CSV.strip().splitlines()
        write(pack_dir, "assets.csv", f"{header},surprise\n{row},value\n")
        with pytest.raises(SchemaValidationError):
            DataPack.load(pack_dir)

    def test_header_without_rows_is_rejected(self, pack_dir: Path) -> None:
        write(pack_dir, "assets.csv", ASSETS_CSV.splitlines()[0] + "\n")
        with pytest.raises(SchemaValidationError):
            DataPack.load(pack_dir)

    def test_empty_file_is_rejected(self, pack_dir: Path) -> None:
        write(pack_dir, "assets.csv", "")
        with pytest.raises(SchemaValidationError):
            DataPack.load(pack_dir)

    def test_byte_order_mark_is_tolerated(self, pack_dir: Path) -> None:
        """Spreadsheet exports commonly carry a BOM on the first column name."""
        write(pack_dir, "assets.csv", "﻿" + ASSETS_CSV)
        assert len(DataPack.load(pack_dir).assets) == 1

    def test_validation_failure_does_not_disclose_row_contents(
        self, pack_dir: Path
    ) -> None:
        """The message reaching a caller must not echo confidential data."""
        write(
            pack_dir,
            "assets.csv",
            ASSETS_CSV.replace("host-one", "secret-host-name").replace(
                ",Critical,", ",Catastrophic,"
            ),
        )
        with pytest.raises(SchemaValidationError) as caught:
            DataPack.load(pack_dir)

        assert "secret-host-name" not in str(caught.value.to_public_dict())


@pytest.mark.unit
class TestIndexes:
    def test_assets_are_indexed_by_id(self, pack_dir: Path) -> None:
        assert "A-1" in DataPack.load(pack_dir).assets_by_id

    def test_services_are_indexed_by_name(self, pack_dir: Path) -> None:
        assert "Example Service" in DataPack.load(pack_dir).services_by_name

    def test_intelligence_keeps_every_match_for_an_identifier(
        self, pack_dir: Path
    ) -> None:
        """One identifier can be referenced by several campaigns."""
        second = INTEL_CSV.strip().splitlines()[1].replace("TI-1", "TI-2")
        write(pack_dir, "threat_intelligence.csv", INTEL_CSV + second + "\n")

        grouped = DataPack.load(pack_dir).intel_by_identifier
        assert len(grouped["CVE-2024-21762"]) == 2


@pytest.mark.unit
class TestQualityChecks:
    def test_a_clean_pack_reports_nothing(self, pack_dir: Path) -> None:
        report = assess_quality(DataPack.load(pack_dir))
        assert report.issues == ()
        assert report.has_critical is False

    def test_exposure_conflict_is_critical(self, pack_dir: Path) -> None:
        """Exposure is the heaviest ranking factor, so disagreement is critical."""
        write(pack_dir, "vulnerabilities.csv", VULNS_CSV.replace(",Internet,", ",Internal,"))

        report = assess_quality(DataPack.load(pack_dir))
        codes = {i.code: i for i in report.issues}

        assert codes["exposure_conflict"].severity is DataQualitySeverity.CRITICAL
        assert codes["exposure_conflict"].references == ("V-1",)
        assert report.has_critical is True

    def test_asset_without_findings_is_reported_as_unknown(self, pack_dir: Path) -> None:
        extra = ASSETS_CSV.strip().splitlines()[1].replace("A-1,host-one", "A-2,host-two")
        write(pack_dir, "assets.csv", ASSETS_CSV + extra + "\n")

        codes = {i.code for i in assess_quality(DataPack.load(pack_dir)).issues}
        assert "no_findings_recorded" in codes

    def test_unowned_asset_is_reported(self, pack_dir: Path) -> None:
        write(pack_dir, "assets.csv", ASSETS_CSV.replace(",Platform,", ",,"))
        codes = {i.code for i in assess_quality(DataPack.load(pack_dir)).issues}
        assert "unowned_asset" in codes

    def test_stale_inventory_is_reported(self, pack_dir: Path) -> None:
        write(pack_dir, "assets.csv", ASSETS_CSV.replace(",Yes,1,UAE,", ",Yes,120,UAE,"))
        codes = {i.code for i in assess_quality(DataPack.load(pack_dir)).issues}
        assert "stale_inventory" in codes

    def test_locally_identified_finding_is_reported_as_not_assessable(
        self, pack_dir: Path
    ) -> None:
        """Not assessable must never be presented as not exploited."""
        write(pack_dir, "vulnerabilities.csv", VULNS_CSV.replace("CVE-2024-21762", "CTRL-SYN-001"))
        write(
            pack_dir,
            "threat_intelligence.csv",
            INTEL_CSV.replace("CVE-2024-21762", "CTRL-SYN-001"),
        )

        issue = next(
            i
            for i in assess_quality(DataPack.load(pack_dir)).issues
            if i.code == "not_catalogue_assessable"
        )
        assert "not exploited" in issue.detail

    def test_unrelated_intelligence_is_reported_as_information(
        self, pack_dir: Path
    ) -> None:
        write(
            pack_dir,
            "threat_intelligence.csv",
            INTEL_CSV.replace("CVE-2024-21762", "CVE-2019-0001"),
        )

        issue = next(
            i
            for i in assess_quality(DataPack.load(pack_dir)).issues
            if i.code == "intelligence_not_matched"
        )
        assert issue.severity is DataQualitySeverity.INFO

    def test_undefined_business_service_is_reported(self, pack_dir: Path) -> None:
        write(pack_dir, "assets.csv", ASSETS_CSV.replace("Example Service", "Unknown Service"))
        codes = {i.code for i in assess_quality(DataPack.load(pack_dir)).issues}
        assert "undefined_business_service" in codes

    def test_reference_lists_are_bounded(self, pack_dir: Path) -> None:
        """Findings must not become a dump of the inventory."""
        rows = [
            ASSETS_CSV.strip().splitlines()[1].replace("A-1,host-one", f"A-{n},host-{n}")
            for n in range(2, 40)
        ]
        write(pack_dir, "assets.csv", ASSETS_CSV + "\n".join(rows) + "\n")

        issue = next(
            i
            for i in assess_quality(DataPack.load(pack_dir)).issues
            if i.code == "no_findings_recorded"
        )
        assert issue.affected_count == 38
        assert len(issue.references) == MAX_REFERENCES


@pytest.mark.unit
class TestReportOrdering:
    def test_issues_are_ordered_most_severe_first(self, pack_dir: Path) -> None:
        write(pack_dir, "vulnerabilities.csv", VULNS_CSV.replace(",Internet,", ",Internal,"))
        write(pack_dir, "assets.csv", ASSETS_CSV.replace(",Platform,", ",,"))

        severities = [i.severity for i in assess_quality(DataPack.load(pack_dir)).ordered]
        assert severities[0] is DataQualitySeverity.CRITICAL

    def test_issues_can_be_filtered_by_severity(self, pack_dir: Path) -> None:
        write(pack_dir, "vulnerabilities.csv", VULNS_CSV.replace(",Internet,", ",Internal,"))

        report = assess_quality(DataPack.load(pack_dir))
        assert len(report.by_severity(DataQualitySeverity.CRITICAL)) == 1


@pytest.mark.integration
class TestSuppliedDataPack:
    """The checks must behave correctly on the data the system actually ships."""

    @pytest.fixture
    def pack(self) -> DataPack:
        from cyber_risk.config.settings import PROJECT_ROOT

        return DataPack.load(PROJECT_ROOT / "data" / "raw")

    def test_every_record_loads(self, pack: DataPack) -> None:
        assert len(pack.assets) == 60
        assert len(pack.vulnerabilities) == 114
        assert len(pack.threat_intel) == 40
        assert len(pack.business_services) == 20
        assert len(pack.remediation_hints) == 30

    def test_every_finding_resolves_to_an_asset(self, pack: DataPack) -> None:
        known = set(pack.assets_by_id)
        assert all(v.asset_id in known for v in pack.vulnerabilities)

    def test_every_asset_resolves_to_a_service(self, pack: DataPack) -> None:
        known = set(pack.services_by_name)
        assert all(a.business_service in known for a in pack.assets)

    def test_known_quality_issues_are_detected(self, pack: DataPack) -> None:
        codes = {i.code for i in assess_quality(pack).issues}
        assert {
            "exposure_conflict",
            "unowned_asset",
            "stale_inventory",
            "not_catalogue_assessable",
            "intelligence_not_matched",
            "no_findings_recorded",
        } <= codes


@pytest.mark.unit
class TestOrphanedFindings:
    """A finding whose asset is absent cannot be scored and must be reported."""

    def test_orphaned_finding_is_critical(self, pack_dir: Path) -> None:
        loaded = DataPack.load(pack_dir)
        pack = DataPack(
            assets=[],
            vulnerabilities=loaded.vulnerabilities,
            threat_intel=loaded.threat_intel,
            business_services=loaded.business_services,
            remediation_hints=loaded.remediation_hints,
            threat_report=loaded.threat_report,
        )

        issue = next(
            i for i in assess_quality(pack).issues if i.code == "orphaned_vulnerability"
        )
        assert issue.severity is DataQualitySeverity.CRITICAL
        assert issue.references == ("V-1",)

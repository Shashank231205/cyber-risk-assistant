"""Tests for parsing and loading the public reference corpora."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyber_risk.core.exceptions import ReferenceDataError
from cyber_risk.ingestion.reference_data import (
    EXPECTED_CONTROLS,
    ControlDocument,
    load_control_snapshot,
    load_kev_snapshot,
    load_manifest,
    parse_kev,
    parse_nist_catalogue,
)

KEV_CSV = (
    "cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,"
    "requiredAction,dueDate,knownRansomwareCampaignUse,notes,cwes\n"
    "CVE-2024-21762,Fortinet,FortiOS,Out-of-Bounds Write,2024-02-09,Description,"
    "Apply mitigations,2024-02-16,Known,notes,CWE-787\n"
    "CVE-2023-4966,Citrix,NetScaler,Buffer Overflow,2023-10-18,Description,"
    "Apply updates,2023-10-25,Unknown,notes,CWE-119\n"
)

CATALOGUE_JSON = json.dumps(
    {
        "catalog": {
            "groups": [
                {
                    "id": "si",
                    "title": "System and Information Integrity",
                    "controls": [
                        {
                            "id": "si-2",
                            "title": "Flaw Remediation",
                            "parts": [
                                {"name": "statement", "prose": "Identify and correct flaws."},
                                {"name": "gdn", "prose": "Flaw remediation guidance."},
                            ],
                            "controls": [
                                {
                                    "id": "si-2.1",
                                    "title": "Central Management",
                                    "parts": [
                                        {"name": "statement", "prose": "Manage centrally."}
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    }
)


@pytest.mark.unit
class TestExploitedVulnerabilityCatalogue:
    def test_entries_are_parsed(self) -> None:
        entries = parse_kev(KEV_CSV.encode("utf-8"))
        assert len(entries) == 2
        assert entries[0].cve_id == "CVE-2024-21762"

    def test_ransomware_flag_is_interpreted(self) -> None:
        entries = {e.cve_id: e for e in parse_kev(KEV_CSV.encode("utf-8"))}
        assert entries["CVE-2024-21762"].known_ransomware_campaign_use is True
        assert entries["CVE-2023-4966"].known_ransomware_campaign_use is False

    def test_required_action_is_retained(self) -> None:
        """The catalogue's own instruction is quoted rather than paraphrased."""
        entries = parse_kev(KEV_CSV.encode("utf-8"))
        assert entries[0].required_action == "Apply mitigations"

    def test_byte_order_mark_is_tolerated(self) -> None:
        assert len(parse_kev(("﻿" + KEV_CSV).encode("utf-8"))) == 2

    def test_rows_without_an_identifier_are_skipped(self) -> None:
        payload = KEV_CSV + ",Vendor,Product,Name,,,,,,,\n"
        assert len(parse_kev(payload.encode("utf-8"))) == 2

    def test_unexpected_structure_is_rejected(self) -> None:
        with pytest.raises(ReferenceDataError):
            parse_kev(b"unrelated,columns\n1,2\n")

    def test_catalogue_without_entries_is_rejected(self) -> None:
        with pytest.raises(ReferenceDataError):
            parse_kev(KEV_CSV.splitlines()[0].encode("utf-8"))


@pytest.mark.unit
class TestControlCatalogue:
    def test_controls_are_parsed(self) -> None:
        controls = {c.control_id: c for c in parse_nist_catalogue(CATALOGUE_JSON.encode())}
        assert "SI-2" in controls
        assert controls["SI-2"].title == "Flaw Remediation"

    def test_statement_and_discussion_are_captured(self) -> None:
        control = next(
            c for c in parse_nist_catalogue(CATALOGUE_JSON.encode()) if c.control_id == "SI-2"
        )
        assert "Identify and correct flaws." in control.statement
        assert "Flaw remediation guidance." in control.discussion

    def test_enhancements_are_captured(self) -> None:
        """Enhancements are retrievable controls in their own right."""
        ids = {c.control_id for c in parse_nist_catalogue(CATALOGUE_JSON.encode())}
        assert "SI-2.1" in ids

    def test_family_is_recorded(self) -> None:
        control = next(
            c for c in parse_nist_catalogue(CATALOGUE_JSON.encode()) if c.control_id == "SI-2"
        )
        assert control.family == "System and Information Integrity"

    def test_invalid_json_is_rejected(self) -> None:
        with pytest.raises(ReferenceDataError):
            parse_nist_catalogue(b"{not json")

    def test_missing_groups_are_rejected(self) -> None:
        with pytest.raises(ReferenceDataError):
            parse_nist_catalogue(json.dumps({"catalog": {}}).encode())

    def test_empty_catalogue_is_rejected(self) -> None:
        payload = json.dumps({"catalog": {"groups": [{"id": "x", "title": "X"}]}})
        with pytest.raises(ReferenceDataError):
            parse_nist_catalogue(payload.encode())


@pytest.mark.unit
class TestControlText:
    def test_text_combines_identifier_title_and_body(self) -> None:
        control = ControlDocument(
            control_id="SI-2",
            title="Flaw Remediation",
            statement="Statement text.",
            discussion="Discussion text.",
        )
        text = control.text

        assert text.startswith("SI-2 Flaw Remediation")
        assert "Statement text." in text
        assert "Discussion text." in text

    def test_absent_sections_are_omitted_cleanly(self) -> None:
        control = ControlDocument(control_id="AC-1", title="Policy")
        assert control.text == "AC-1 Policy"


@pytest.mark.unit
class TestSnapshotLoading:
    def test_missing_catalogue_snapshot_is_reported(self, tmp_path: Path) -> None:
        with pytest.raises(ReferenceDataError):
            load_kev_snapshot(tmp_path)

    def test_missing_control_snapshot_is_reported(self, tmp_path: Path) -> None:
        with pytest.raises(ReferenceDataError):
            load_control_snapshot(tmp_path)

    def test_absent_manifest_returns_nothing(self, tmp_path: Path) -> None:
        assert load_manifest(tmp_path) is None


@pytest.mark.integration
class TestCommittedSnapshots:
    """The snapshots the repository ships must be usable as committed."""

    @pytest.fixture
    def directory(self) -> Path:
        from cyber_risk.config.settings import PROJECT_ROOT

        return PROJECT_ROOT / "data" / "reference"

    def test_manifest_records_provenance(self, directory: Path) -> None:
        manifest = load_manifest(directory)
        assert manifest is not None
        assert manifest.retrieved_at
        assert manifest.kev_digest
        assert manifest.nist_digest

    def test_exploited_vulnerability_snapshot_loads(self, directory: Path) -> None:
        catalogue = load_kev_snapshot(directory)
        assert len(catalogue) > 1_000
        assert all(key.startswith("CVE-") for key in catalogue)

    def test_control_snapshot_loads(self, directory: Path) -> None:
        assert len(load_control_snapshot(directory)) > 1_000

    def test_scenario_controls_are_present_with_text(self, directory: Path) -> None:
        """Guidance is quoted from these, so empty text would be useless."""
        controls = {c.control_id: c for c in load_control_snapshot(directory)}
        for control_id in EXPECTED_CONTROLS:
            assert control_id in controls, f"{control_id} is missing"
            assert len(controls[control_id].text) > 200

    def test_manifest_counts_match_the_snapshots(self, directory: Path) -> None:
        manifest = load_manifest(directory)
        assert manifest is not None
        assert manifest.kev_entries == len(load_kev_snapshot(directory))
        assert manifest.nist_controls == len(load_control_snapshot(directory))


@pytest.mark.unit
class TestFetching:
    """The download path, exercised without touching the network."""

    @pytest.fixture
    def stub_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import cyber_risk.ingestion.reference_data as module

        payloads = {"kev": KEV_CSV.encode("utf-8"), "nist": CATALOGUE_JSON.encode("utf-8")}

        class Response:
            def __init__(self, content: bytes) -> None:
                self.content = content

            def raise_for_status(self) -> None:
                return None

        class Client:
            def __enter__(self) -> Client:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def get(self, url: str) -> Response:
                return Response(payloads["kev" if "kev" in url else "nist"])

        monkeypatch.setattr(module, "create_client", Client)
        monkeypatch.setattr(module, "EXPECTED_CONTROLS", ("SI-2",))

    def test_snapshots_are_written(self, tmp_path: Path, stub_client: None) -> None:
        from cyber_risk.ingestion.reference_data import fetch_snapshots

        manifest = fetch_snapshots(
            kev_url="https://example.test/kev.csv",
            nist_url="https://example.test/nist.json",
            destination=tmp_path,
        )

        assert manifest.kev_entries == 2
        assert manifest.nist_controls == 2
        assert len(load_kev_snapshot(tmp_path)) == 2

    def test_manifest_records_a_content_digest(
        self, tmp_path: Path, stub_client: None
    ) -> None:
        """Provenance is what makes a run traceable to its reference data."""
        from cyber_risk.ingestion.reference_data import fetch_snapshots

        manifest = fetch_snapshots(
            kev_url="https://example.test/kev.csv",
            nist_url="https://example.test/nist.json",
            destination=tmp_path,
        )
        assert len(manifest.kev_digest) == 16
        assert manifest.kev_digest != manifest.nist_digest

    def test_unreachable_source_fails_without_writing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A partial snapshot is worse than none: it looks complete."""
        import cyber_risk.ingestion.reference_data as module
        from cyber_risk.ingestion.reference_data import fetch_snapshots

        class FailingClient:
            def __enter__(self) -> FailingClient:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def get(self, url: str) -> object:
                raise OSError("network unreachable")

        monkeypatch.setattr(module, "create_client", FailingClient)

        with pytest.raises(ReferenceDataError):
            fetch_snapshots(
                kev_url="https://example.test/kev.csv",
                nist_url="https://example.test/nist.json",
                destination=tmp_path,
            )
        assert not (tmp_path / "kev_catalogue.json").exists()

    def test_snapshot_missing_expected_controls_is_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Silently degraded retrieval quality is worse than a failed build."""
        import cyber_risk.ingestion.reference_data as module

        monkeypatch.setattr(module, "EXPECTED_CONTROLS", ("XX-99",))
        with pytest.raises(ReferenceDataError, match=r"XX-99|expected controls"):
            module._verify_expected_controls(parse_nist_catalogue(CATALOGUE_JSON.encode()))

    def test_empty_response_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import cyber_risk.ingestion.reference_data as module

        class Empty:
            content = b""

            def raise_for_status(self) -> None:
                return None

        class Client:
            def get(self, url: str) -> Empty:
                return Empty()

        with pytest.raises(ReferenceDataError):
            module._download(Client(), "https://example.test/x", "catalogue")

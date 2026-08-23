"""End-to-end tests against the running application.

These exercise the assembled system: startup builds the real container, loads
the real snapshots and reads the real index. They are skipped when the index
has not been built, so a fresh clone is not blocked before `make index`.

Narration is forced to the deterministic path so the suite makes no network
calls and its assertions do not depend on a model's wording.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from cyber_risk.config.settings import PROJECT_ROOT, Settings

INDEX_FILE = PROJECT_ROOT / "data" / "processed" / "nist_index" / "vectors.npy"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not INDEX_FILE.is_file(),
        reason="retrieval index not built; run `make index`",
    ),
]


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    """A client against the fully assembled application.

    Constructed with explicit settings that configure no API keys, so
    narration takes the deterministic path: the suite makes no network calls
    and its assertions do not depend on a model's wording.
    """
    from cyber_risk.api.app import create_app

    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    with TestClient(create_app(settings)) as test_client:
        yield test_client


class TestOperations:
    def test_liveness_answers(self, client: TestClient) -> None:
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_readiness_reports_the_index(self, client: TestClient) -> None:
        payload = client.get("/ready").json()

        assert payload["status"] == "ready"
        assert payload["controls_indexed"] > 1000

    def test_documentation_is_available(self, client: TestClient) -> None:
        assert client.get("/docs").status_code == 200

    def test_favicon_does_not_error(self, client: TestClient) -> None:
        assert client.get("/favicon.ico").status_code == 204


class TestSecurityHeaders:
    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "no-referrer"),
            ("cross-origin-opener-policy", "same-origin"),
        ],
    )
    def test_header_is_present(self, client: TestClient, header: str, expected: str) -> None:
        assert client.get("/health").headers[header] == expected

    def test_scripts_are_forbidden_by_policy(self, client: TestClient) -> None:
        """The page runs no scripts, so the policy should not permit any."""
        policy = client.get("/").headers["content-security-policy"]

        assert "script-src 'none'" in policy
        assert "frame-ancestors 'none'" in policy

    def test_every_response_is_correlatable(self, client: TestClient) -> None:
        assert client.get("/health").headers["x-request-id"]

    def test_correlation_identifiers_are_unique(self, client: TestClient) -> None:
        first = client.get("/health").headers["x-request-id"]
        second = client.get("/health").headers["x-request-id"]
        assert first != second


class TestHtmlReport:
    def test_page_renders(self, client: TestClient) -> None:
        response = client.get("/")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_page_is_self_contained(self, client: TestClient) -> None:
        """No external assets, so the page renders under a strict policy."""
        body = client.get("/").text

        assert "<script" not in body
        assert "https://" not in body.split("</head>")[0]

    def test_page_presents_prose_not_a_table_of_identifiers(
        self, client: TestClient
    ) -> None:
        body = client.get("/").text

        assert "Cyber Risk Briefing" in body
        assert "not severity ordering" in body

    def test_page_states_what_it_could_not_see(self, client: TestClient) -> None:
        assert "What this report could not see" in client.get("/").text

    def test_page_states_its_provenance(self, client: TestClient) -> None:
        body = client.get("/").text

        assert "Provenance" in body
        assert "Reference data retrieved" in body


class TestJsonReport:
    def test_report_has_the_expected_shape(self, client: TestClient) -> None:
        payload = client.get("/report").json()

        assert len(payload["risks"]) == 5
        assert payload["total_findings"] == 114
        assert payload["total_assets"] == 60

    def test_every_required_element_is_present(self, client: TestClient) -> None:
        """The brief requires asset, finding, intel, service and a reason."""
        risk = client.get("/report").json()["risks"][0]

        assert risk["asset"]
        assert risk["identifier"]
        assert risk["business_service"]
        assert risk["threat_activity"]
        assert risk["narrative"]
        assert risk["factors"]

    def test_guidance_is_attributed_to_a_named_control(self, client: TestClient) -> None:
        control = client.get("/report").json()["risks"][0]["control"]

        assert control["control_id"]
        assert "NIST SP 800-53" in control["citation"]
        assert control["excerpt"]

    def test_risks_are_ordered_by_score(self, client: TestClient) -> None:
        scores = [risk["score"] for risk in client.get("/report").json()["risks"]]
        assert scores == sorted(scores, reverse=True)

    def test_top_risks_are_internet_facing(self, client: TestClient) -> None:
        """Exposure is the heaviest factor, so the top of the list reflects it."""
        risks = client.get("/report").json()["risks"]
        assert all(risk["internet_facing"] for risk in risks[:3])

    def test_selection_prefers_distinct_assets(self, client: TestClient) -> None:
        risks = client.get("/report").json()["risks"]
        assert len({risk["asset"] for risk in risks}) == len(risks)

    def test_data_quality_findings_are_included(self, client: TestClient) -> None:
        codes = {issue["code"] for issue in client.get("/report").json()["data_quality"]}
        assert "exposure_conflict" in codes

    def test_provenance_is_reported(self, client: TestClient) -> None:
        provenance = client.get("/report").json()["provenance"]

        assert provenance["controls_indexed"] > 1000
        assert provenance["exploited_catalogue_entries"] > 1000
        assert provenance["narration_source"]

    def test_limit_is_respected(self, client: TestClient) -> None:
        assert len(client.get("/report?limit=3").json()["risks"]) == 3

    @pytest.mark.parametrize("limit", [-1, 51, 999])
    def test_invalid_limit_is_rejected(self, client: TestClient, limit: int) -> None:
        assert client.get(f"/report?limit={limit}").status_code == 422


class TestMarkdownReport:
    def test_markdown_renders(self, client: TestClient) -> None:
        response = client.get("/report.md")

        assert response.status_code == 200
        assert "text/markdown" in response.headers["content-type"]

    def test_markdown_is_readable_without_processing(self, client: TestClient) -> None:
        body = client.get("/report.md").text

        assert body.startswith("# Cyber Risk Briefing")
        assert "**Fix it**" in body
        assert "NIST SP 800-53" in body

    def test_markdown_separates_fixing_from_containing(self, client: TestClient) -> None:
        """One control says how to remove the flaw, another how to limit its use."""
        body = client.get("/report.md").text
        assert "**Contain it**" in body


class TestDisclosure:
    def test_unknown_route_reveals_nothing(self, client: TestClient) -> None:
        response = client.get("/does-not-exist")

        assert response.status_code == 404
        assert "Traceback" not in response.text
        assert "/srv/" not in response.text

    def test_validation_errors_carry_no_internal_paths(self, client: TestClient) -> None:
        body = client.get("/report?limit=999").text

        assert "Traceback" not in body
        assert "cyber_risk" not in body


class TestScoreBars:
    """The factor bars are the page's explanation of the score."""

    def test_bars_render_with_a_width(self, client: TestClient) -> None:
        """A bar with no width shows the reader nothing."""
        import re

        fills = re.findall(r'<span class="fill [a-z]*" style="width:(\d+)%"', client.get("/").text)

        assert fills, "no score bars were rendered"
        assert any(int(width) > 0 for width in fills)

    def test_fill_is_a_block_so_its_height_applies(self, client: TestClient) -> None:
        """Regression: an inline fill ignores its height and renders empty."""
        assert "display: block" in client.get("/").text

    def test_each_factor_has_its_own_colour(self, client: TestClient) -> None:
        """The same factor keeps one colour, so two risks can be compared."""
        import re

        classes = set(re.findall(r'<span class="fill ([a-z]+)"', client.get("/").text))
        assert classes == {"exposure", "exploit", "business", "ransomware", "controls"}

    def test_motion_is_optional(self, client: TestClient) -> None:
        """Animation must not be forced on a reader who has asked for less."""
        assert "prefers-reduced-motion" in client.get("/").text

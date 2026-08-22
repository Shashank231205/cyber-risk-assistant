"""Tests for embeddings, vector storage and control retrieval.

Retrieval is exercised against a stub embedding backend so the behaviour under
test is the retrieval logic rather than the quality of a particular model.
Model quality is measured separately, against the real index.
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pytest

from cyber_risk.core.exceptions import IndexNotBuiltError, RetrievalError
from cyber_risk.ingestion.reference_data import ControlDocument
from cyber_risk.models.risk import CorrelatedRisk
from cyber_risk.retrieval.embeddings import Vector, normalise
from cyber_risk.retrieval.retriever import (
    EXCERPT_LIMIT,
    ControlRetriever,
    build_index,
    build_query,
)
from cyber_risk.retrieval.vector_store import NumpyVectorStore
from tests.unit.test_scoring_engine import make_asset, make_intel, make_service, make_vuln

CONTROLS = (
    ControlDocument(
        control_id="SI-2",
        title="Flaw Remediation",
        family="System and Information Integrity",
        statement="Identify, report, and correct system flaws.",
    ),
    ControlDocument(
        control_id="AC-2",
        title="Account Management",
        family="Access Control",
        statement="Define and document account types.",
    ),
    ControlDocument(
        control_id="AC-2.7",
        title="Privileged User Accounts",
        family="Access Control",
        statement="Establish and administer privileged accounts.",
    ),
)


class StubEmbedder:
    """Deterministic embeddings keyed by word overlap.

    Removes the model from the test so a retrieval regression is not masked by
    a model change, and vice versa.
    """

    VOCABULARY = ("flaw", "account", "network", "ransomware", "monitoring")

    @property
    def dimension(self) -> int:
        return len(self.VOCABULARY)

    def _vector(self, text: str) -> Vector:
        lowered = text.lower()
        counts = [float(lowered.count(word)) for word in self.VOCABULARY]
        if not any(counts):
            counts[0] = 1.0
        return normalise(np.asarray(counts, dtype=np.float32))

    def embed_documents(self, texts: list[str]) -> Vector:
        if not texts:
            return np.zeros((0, self.dimension), dtype=np.float32)
        return np.vstack([self._vector(text) for text in texts])

    def embed_query(self, text: str) -> Vector:
        return self._vector(text)


@pytest.fixture
def retriever() -> ControlRetriever:
    """A retriever over the stub corpus."""
    embedder = StubEmbedder()
    store = build_index(CONTROLS, embedder, NumpyVectorStore())
    return ControlRetriever(embedder, store, CONTROLS, top_k=2, minimum_score=0.30)


def make_risk(**overrides: object) -> CorrelatedRisk:
    """A correlated risk with sensible defaults."""
    base: dict[str, object] = {
        "vulnerability": make_vuln(),
        "asset": make_asset(),
        "service": make_service(),
    }
    return CorrelatedRisk(**{**base, **overrides})


@pytest.mark.unit
class TestNormalisation:
    def test_vectors_become_unit_length(self) -> None:
        vectors = normalise(np.asarray([[3.0, 4.0]], dtype=np.float32))
        assert float(np.linalg.norm(vectors[0])) == pytest.approx(1.0)

    def test_zero_vector_does_not_divide_by_zero(self) -> None:
        result = normalise(np.zeros((1, 4), dtype=np.float32))
        assert not np.isnan(result).any()

    def test_direction_is_preserved(self) -> None:
        original = np.asarray([[1.0, 2.0, 2.0]], dtype=np.float32)
        scaled = normalise(original)
        assert scaled[0][1] == pytest.approx(scaled[0][2])


@pytest.mark.unit
class TestVectorStore:
    def test_vectors_are_stored_and_found(self) -> None:
        store = NumpyVectorStore()
        store.add(np.eye(3, dtype=np.float32), ["a", "b", "c"])

        assert store.size == 3
        assert store.search(np.asarray([1.0, 0.0, 0.0], dtype=np.float32), 1)[0][0] == "a"

    def test_results_are_ordered_by_similarity(self) -> None:
        store = NumpyVectorStore()
        store.add(
            normalise(np.asarray([[1.0, 0.0], [0.7, 0.7], [0.0, 1.0]], dtype=np.float32)),
            ["near", "middle", "far"],
        )
        results = store.search(np.asarray([1.0, 0.0], dtype=np.float32), 3)
        assert [name for name, _ in results] == ["near", "middle", "far"]

    def test_mismatched_input_is_rejected(self) -> None:
        """A silent misalignment would attribute guidance to the wrong control."""
        store = NumpyVectorStore()
        with pytest.raises(RetrievalError):
            store.add(np.eye(3, dtype=np.float32), ["only-one"])

    def test_search_before_build_is_reported(self) -> None:
        with pytest.raises(IndexNotBuiltError):
            NumpyVectorStore().search(np.asarray([1.0], dtype=np.float32), 1)

    def test_save_before_build_is_reported(self, tmp_path: Path) -> None:
        with pytest.raises(IndexNotBuiltError):
            NumpyVectorStore().save(tmp_path)

    def test_load_without_an_index_is_reported(self, tmp_path: Path) -> None:
        with pytest.raises(IndexNotBuiltError):
            NumpyVectorStore().load(tmp_path)

    def test_index_survives_a_round_trip(self, tmp_path: Path) -> None:
        store = NumpyVectorStore()
        store.add(np.eye(3, dtype=np.float32), ["a", "b", "c"])
        store.save(tmp_path)

        restored = NumpyVectorStore()
        restored.load(tmp_path)

        assert restored.size == 3
        assert restored.search(np.asarray([0.0, 1.0, 0.0], dtype=np.float32), 1)[0][0] == "b"

    def test_inconsistent_index_is_rejected(self, tmp_path: Path) -> None:
        store = NumpyVectorStore()
        store.add(np.eye(3, dtype=np.float32), ["a", "b", "c"])
        store.save(tmp_path)
        (tmp_path / "documents.json").write_text('["a"]', encoding="utf-8")

        with pytest.raises(RetrievalError):
            NumpyVectorStore().load(tmp_path)

    def test_requesting_more_than_stored_returns_all(self) -> None:
        store = NumpyVectorStore()
        store.add(np.eye(2, dtype=np.float32), ["a", "b"])
        assert len(store.search(np.asarray([1.0, 0.0], dtype=np.float32), 10)) == 2


@pytest.mark.unit
class TestQueryConstruction:
    def test_query_describes_the_situation_not_only_the_title(self) -> None:
        """Controls describe activities, so a product name alone retrieves poorly."""
        query = build_query(make_risk())
        assert make_vuln().vulnerability_name in query
        assert len(query) > len(make_vuln().vulnerability_name) * 2

    def test_exposure_is_described(self) -> None:
        assert "internet-facing" in build_query(make_risk())

    def test_ransomware_evidence_is_described(self) -> None:
        query = build_query(make_risk(intel=(make_intel(),)))
        assert "ransomware" in query

    def test_absent_monitoring_is_described(self) -> None:
        query = build_query(make_risk(asset=make_asset(edr_installed="No")))
        assert "monitoring" in query

    def test_unavailable_patch_is_described(self) -> None:
        query = build_query(make_risk(vulnerability=make_vuln(patch_available="No")))
        assert "compensating controls" in query

    def test_control_deficiency_is_described_differently_from_a_flaw(self) -> None:
        """A missing control has no patch, so patch language would mislead."""
        deficiency = build_query(make_risk(vulnerability=make_vuln(cve="CTRL-SYN-001")))
        flaw = build_query(make_risk())

        assert "missing or ineffective security control" in deficiency
        assert "patch management" in flaw
        assert "patch management" not in deficiency

    def test_unowned_asset_is_described(self) -> None:
        query = build_query(make_risk(asset=make_asset(owner_team="")))
        assert "ownership" in query


@pytest.mark.unit
class TestRetrieval:
    def test_guidance_is_retrieved(self, retriever: ControlRetriever) -> None:
        results = retriever.retrieve(make_risk())
        assert results
        assert results[0].control_id in {c.control_id for c in CONTROLS}

    def test_result_count_respects_the_limit(self, retriever: ControlRetriever) -> None:
        assert len(retriever.retrieve(make_risk(), limit=1)) == 1

    def test_results_carry_attribution(self, retriever: ControlRetriever) -> None:
        """A reader must be able to see which control was consulted."""
        result = retriever.retrieve(make_risk())[0]

        assert result.control_id
        assert result.title
        assert result.excerpt
        assert "NIST SP 800-53" in result.citation

    def test_governing_control_is_preferred_over_its_enhancement(
        self, retriever: ControlRetriever
    ) -> None:
        """A reader deciding what to do needs the control stating the requirement."""
        results = retriever.retrieve_for_query("account account account", limit=2)
        assert results[0].control_id == "AC-2"

    def test_weak_matches_are_flagged_not_hidden(
        self, retriever: ControlRetriever
    ) -> None:
        """A poor match is reported as poor rather than presented as an answer."""
        results = retriever.retrieve_for_query("monitoring", limit=2)

        assert results
        assert all(r.is_weak_match for r in results)

    def test_strong_matches_are_not_flagged(self, retriever: ControlRetriever) -> None:
        results = retriever.retrieve_for_query("flaw", limit=1)
        assert results[0].is_weak_match is False

    def test_empty_catalogue_is_reported(self) -> None:
        embedder = StubEmbedder()
        store = build_index(CONTROLS, embedder, NumpyVectorStore())

        with pytest.raises(IndexNotBuiltError):
            ControlRetriever(embedder, store, ()).retrieve(make_risk())

    def test_index_entries_without_a_control_are_skipped(self) -> None:
        """A divergent index must not produce a control that cannot be quoted."""
        embedder = StubEmbedder()
        store = build_index(CONTROLS, embedder, NumpyVectorStore())
        partial = ControlRetriever(embedder, store, CONTROLS[:1], top_k=3)

        assert all(r.control_id == "SI-2" for r in partial.retrieve(make_risk()))

    def test_catalogue_size_is_reported(self, retriever: ControlRetriever) -> None:
        assert retriever.catalogue_size == len(CONTROLS)


@pytest.mark.unit
class TestExcerpts:
    def test_short_text_is_returned_whole(self, retriever: ControlRetriever) -> None:
        result = retriever.retrieve_for_query("flaw", limit=1)[0]
        assert result.excerpt == "Identify, report, and correct system flaws."

    def test_long_text_is_bounded(self) -> None:
        long_control = ControlDocument(
            control_id="XX-1",
            title="Long Control",
            statement=("This sentence is repeated to exceed the excerpt limit. " * 40),
        )
        embedder = StubEmbedder()
        store = build_index((long_control,), embedder, NumpyVectorStore())
        result = ControlRetriever(embedder, store, (long_control,)).retrieve(make_risk())[0]

        assert len(result.excerpt) <= EXCERPT_LIMIT + 3

    def test_whitespace_is_collapsed(self) -> None:
        control = ControlDocument(
            control_id="XX-2", title="Spaced", statement="First line.\n\n   Second line."
        )
        embedder = StubEmbedder()
        store = build_index((control,), embedder, NumpyVectorStore())
        result = ControlRetriever(embedder, store, (control,)).retrieve(make_risk())[0]

        assert result.excerpt == "First line. Second line."

    def test_title_is_used_when_there_is_no_body(self) -> None:
        control = ControlDocument(control_id="XX-3", title="Title Only")
        embedder = StubEmbedder()
        store = build_index((control,), embedder, NumpyVectorStore())
        result = ControlRetriever(embedder, store, (control,)).retrieve(make_risk())[0]

        assert result.excerpt == "Title Only"


@pytest.mark.integration
class TestRealIndex:
    """Retrieval quality against the committed catalogue and built index.

    Skipped when the index has not been built, so a fresh clone is not blocked
    before `make index` has run.
    """

    @pytest.fixture
    def real_retriever(self) -> ControlRetriever:
        from cyber_risk.config.settings import get_settings
        from cyber_risk.ingestion.reference_data import load_control_snapshot
        from cyber_risk.retrieval.embeddings import LocalEmbedder

        settings = get_settings()
        index_path = settings.resolve_path(settings.vector_index_path)
        if not (index_path / "vectors.npy").is_file():
            pytest.skip("the retrieval index has not been built")

        store = NumpyVectorStore()
        store.load(index_path)
        controls = load_control_snapshot(settings.resolve_path(settings.data_reference_dir))

        return ControlRetriever(
            LocalEmbedder(settings.embedding_model), store, controls, top_k=5
        )

    @pytest.mark.parametrize(
        ("query", "expected"),
        [
            ("unpatched software flaw needing a security patch", "SI-2"),
            ("scanning systems for vulnerabilities", "RA-5"),
            ("responding to a security incident", "IR-4"),
            ("managing user accounts and privileges", "AC-2"),
            ("component no longer supported by its vendor", "SA-22"),
        ],
    )
    def test_expected_control_is_retrieved(
        self, real_retriever: ControlRetriever, query: str, expected: str
    ) -> None:
        retrieved = [r.control_id for r in real_retriever.retrieve_for_query(query)]
        assert expected in retrieved, f"{query!r} returned {retrieved}"

    def test_excerpts_contain_no_template_syntax(
        self, real_retriever: ControlRetriever
    ) -> None:
        """Source template syntax reaching a reader is a defect, not a detail."""
        results = real_retriever.retrieve_for_query("patch management and flaw remediation")
        assert results
        assert not any(re.search(r"\{\{|\}\}", r.excerpt) for r in results)

    def test_matches_are_above_the_weak_threshold(
        self, real_retriever: ControlRetriever
    ) -> None:
        results = real_retriever.retrieve_for_query("internet-facing system under active attack")
        assert results[0].is_weak_match is False


@pytest.mark.unit
class TestFaissStore:
    """The FAISS store must behave identically, including without FAISS."""

    def test_results_match_the_exact_store(self) -> None:
        from cyber_risk.retrieval.vector_store import FaissVectorStore

        vectors = normalise(
            np.asarray([[1.0, 0.0], [0.7, 0.7], [0.0, 1.0]], dtype=np.float32)
        )
        query = np.asarray([1.0, 0.0], dtype=np.float32)

        exact = NumpyVectorStore()
        exact.add(vectors, ["near", "middle", "far"])
        faiss_store = FaissVectorStore()
        faiss_store.add(vectors, ["near", "middle", "far"])

        assert [name for name, _ in faiss_store.search(query, 3)] == [
            name for name, _ in exact.search(query, 3)
        ]

    def test_search_before_build_is_reported(self) -> None:
        from cyber_risk.retrieval.vector_store import FaissVectorStore

        with pytest.raises(IndexNotBuiltError):
            FaissVectorStore().search(np.asarray([1.0], dtype=np.float32), 1)

    def test_index_survives_a_round_trip(self, tmp_path: Path) -> None:
        from cyber_risk.retrieval.vector_store import FaissVectorStore

        store = FaissVectorStore()
        store.add(np.eye(3, dtype=np.float32), ["a", "b", "c"])
        store.save(tmp_path)

        restored = FaissVectorStore()
        restored.load(tmp_path)
        assert restored.search(np.asarray([0.0, 0.0, 1.0], dtype=np.float32), 1)[0][0] == "c"


@pytest.mark.unit
class TestLocalEmbedderFailures:
    def test_absent_library_is_reported_clearly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        from cyber_risk.core.exceptions import EmbeddingError
        from cyber_risk.retrieval.embeddings import LocalEmbedder

        real_import = builtins.__import__

        def blocked(name: str, *args: object, **kwargs: object) -> object:
            if name == "fastembed":
                raise ImportError("fastembed is not installed")
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", blocked)

        with pytest.raises(EmbeddingError, match="local embedding backend"):
            LocalEmbedder("any-model").embed_query("text")

    def test_embedding_no_documents_returns_an_empty_matrix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyber_risk.retrieval.embeddings import LocalEmbedder

        embedder = LocalEmbedder("any-model")
        monkeypatch.setattr(type(embedder), "dimension", property(lambda _: 384))

        assert embedder.embed_documents([]).shape == (0, 384)

    def test_model_failure_is_wrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyber_risk.core.exceptions import EmbeddingError
        from cyber_risk.retrieval.embeddings import LocalEmbedder

        class Failing:
            def embed(self, *_: object, **__: object) -> object:
                raise RuntimeError("inference failed")

            def query_embed(self, *_: object, **__: object) -> object:
                raise RuntimeError("inference failed")

        embedder = LocalEmbedder("any-model")
        monkeypatch.setattr(embedder, "_load", lambda: Failing())

        with pytest.raises(EmbeddingError):
            embedder.embed_query("text")
        with pytest.raises(EmbeddingError):
            embedder.embed_documents(["text"])


@pytest.mark.unit
class TestHostedEmbedder:
    """The hosted backend, exercised without touching the network."""

    def _patch_transport(
        self, monkeypatch: pytest.MonkeyPatch, payload: object, fail: bool = False
    ) -> None:
        import cyber_risk.core.http as http_module

        class Response:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> object:
                return payload

        class Client:
            def __enter__(self) -> Client:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def post(self, *_: object, **__: object) -> Response:
                if fail:
                    raise OSError("network unreachable")
                return Response()

        monkeypatch.setattr(http_module, "create_client", Client)

    def test_documents_are_embedded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyber_risk.retrieval.embeddings import GeminiEmbedder

        self._patch_transport(monkeypatch, {"embeddings": [{"values": [3.0, 4.0]}]})
        vectors = GeminiEmbedder("key").embed_documents(["text"])

        assert vectors.shape == (1, 2)
        assert float(np.linalg.norm(vectors[0])) == pytest.approx(1.0)

    def test_query_returns_a_single_vector(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyber_risk.retrieval.embeddings import GeminiEmbedder

        self._patch_transport(monkeypatch, {"embeddings": [{"values": [1.0, 0.0]}]})
        assert GeminiEmbedder("key").embed_query("text").shape == (2,)

    def test_dimension_is_discovered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyber_risk.retrieval.embeddings import GeminiEmbedder

        self._patch_transport(monkeypatch, {"embeddings": [{"values": [1.0, 0.0, 0.0]}]})
        assert GeminiEmbedder("key").dimension == 3

    def test_unreachable_service_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyber_risk.core.exceptions import EmbeddingError
        from cyber_risk.retrieval.embeddings import GeminiEmbedder

        self._patch_transport(monkeypatch, {}, fail=True)
        with pytest.raises(EmbeddingError, match="could not be reached"):
            GeminiEmbedder("key").embed_query("text")

    def test_empty_response_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyber_risk.core.exceptions import EmbeddingError
        from cyber_risk.retrieval.embeddings import GeminiEmbedder

        self._patch_transport(monkeypatch, {"embeddings": []})
        with pytest.raises(EmbeddingError, match="no vectors"):
            GeminiEmbedder("key").embed_query("text")

    def test_embedding_no_documents_makes_no_request(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyber_risk.retrieval.embeddings import GeminiEmbedder

        self._patch_transport(monkeypatch, {"embeddings": [{"values": [1.0, 0.0]}]})
        assert GeminiEmbedder("key").embed_documents([]).shape == (0, 2)

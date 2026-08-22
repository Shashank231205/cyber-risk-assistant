#!/usr/bin/env python3
"""Embed the security control catalogue and write the retrieval index.

Run at image build time. Embedding roughly 1,200 controls takes appreciably
longer than a request should, so doing it here means the deployed application
loads a prepared index instead of building one while somebody waits.

Usage:
    python scripts/build_index.py
    python scripts/build_index.py --verify
"""

from __future__ import annotations

import argparse
import sys
import time

from cyber_risk.config.settings import EmbeddingBackendName, Settings, get_settings
from cyber_risk.core.exceptions import CyberRiskError
from cyber_risk.core.logging import configure_logging
from cyber_risk.ingestion.reference_data import load_control_snapshot
from cyber_risk.retrieval.embeddings import EmbeddingBackend, GeminiEmbedder, LocalEmbedder
from cyber_risk.retrieval.retriever import ControlRetriever, build_index
from cyber_risk.retrieval.vector_store import NumpyVectorStore

#: Queries whose expected control is unambiguous, used to confirm the index
#: retrieves sensibly rather than merely existing.
PROBES = (
    ("unpatched software flaw needing a security patch", "SI-2"),
    ("scanning systems for vulnerabilities", "RA-5"),
    ("responding to a security incident", "IR-4"),
    ("managing user accounts and privileges", "AC-2"),
    ("component no longer supported by its vendor", "SA-22"),
)


def make_embedder(settings: Settings) -> EmbeddingBackend:
    """Construct the configured embedding backend."""
    if settings.embedding_backend is EmbeddingBackendName.GEMINI:
        key = settings.gemini_api_key
        if key is None:
            print(
                "error: the hosted embedding backend needs GEMINI_API_KEY.",
                file=sys.stderr,
            )
            raise SystemExit(1)
        return GeminiEmbedder(key.get_secret_value())

    return LocalEmbedder(settings.embedding_model, settings.embedding_batch_size)


def build() -> int:
    """Embed the catalogue and write the index. Returns an exit code."""
    settings = get_settings()
    controls = load_control_snapshot(settings.resolve_path(settings.data_reference_dir))
    destination = settings.resolve_path(settings.vector_index_path)

    print(f"embedding {len(controls):,} controls using {settings.embedding_backend.value}")
    started = time.perf_counter()

    store = build_index(controls, make_embedder(settings), NumpyVectorStore(), destination)

    print(f"wrote index to {destination}")
    print(f"  vectors : {store.size:,}")
    print(f"  elapsed : {time.perf_counter() - started:.1f}s")
    return 0


def verify() -> int:
    """Check the index retrieves the expected controls. Returns an exit code."""
    settings = get_settings()
    controls = load_control_snapshot(settings.resolve_path(settings.data_reference_dir))

    store = NumpyVectorStore()
    store.load(settings.resolve_path(settings.vector_index_path))

    retriever = ControlRetriever(
        make_embedder(settings),
        store,
        controls,
        top_k=settings.retrieval_top_k,
        minimum_score=settings.retrieval_min_score,
    )

    print(f"index holds {store.size:,} vectors over {retriever.catalogue_size:,} controls\n")

    failures = 0
    for query, expected in PROBES:
        results = retriever.retrieve_for_query(query, limit=5)
        retrieved = [r.control_id for r in results]
        hit = expected in retrieved
        failures += not hit
        print(
            f"  {'ok  ' if hit else 'MISS'} {expected:<7} {query[:44]:<46} "
            f"-> {', '.join(retrieved[:4])}"
        )

    if failures:
        print(f"\n{failures} probe(s) did not retrieve the expected control.", file=sys.stderr)
        return 1

    print("\nall probes retrieved their expected control")
    return 0


def main() -> int:
    """Entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify", action="store_true", help="check the existing index instead of building"
    )
    args = parser.parse_args()

    configure_logging(level="INFO")
    try:
        return verify() if args.verify else build()
    except CyberRiskError as error:
        print(f"error: {error.message}", file=sys.stderr)
        if error.detail:
            print(f"       {error.detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

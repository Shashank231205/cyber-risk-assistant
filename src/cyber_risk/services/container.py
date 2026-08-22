"""Composition root.

Everything the application needs is built here, once, and passed to the
components that use it. No module reaches for a global, which is what allows
any of them to be exercised with a stub in its place.

Construction is expensive: the reference snapshots are read, the retrieval
index is loaded and the embedding model is warmed. Doing that at startup means
no reader pays for it.
"""

from __future__ import annotations

from cyber_risk.config.settings import EmbeddingBackendName, Settings, VectorBackendName
from cyber_risk.core.exceptions import ConfigurationError
from cyber_risk.core.logging import get_logger
from cyber_risk.ingestion.reference_data import load_control_snapshot
from cyber_risk.retrieval.embeddings import EmbeddingBackend, GeminiEmbedder, LocalEmbedder
from cyber_risk.retrieval.retriever import ControlRetriever
from cyber_risk.retrieval.vector_store import (
    FaissVectorStore,
    NumpyVectorStore,
    VectorStore,
)
from cyber_risk.services.llm import ProviderChain, build_providers
from cyber_risk.services.narration import NarrationService
from cyber_risk.services.report_service import ReportService
from cyber_risk.services.summary import SummaryService

logger = get_logger(__name__)


def build_embedder(settings: Settings) -> EmbeddingBackend:
    """Construct the configured embedding backend."""
    if settings.embedding_backend is EmbeddingBackendName.GEMINI:
        key = settings.gemini_api_key
        if key is None:
            raise ConfigurationError(
                "The hosted embedding backend is selected but no key is configured.",
                detail="EMBEDDING_BACKEND=gemini requires GEMINI_API_KEY",
            )
        return GeminiEmbedder(key.get_secret_value())

    return LocalEmbedder(settings.embedding_model, settings.embedding_batch_size)


def build_store(settings: Settings) -> VectorStore:
    """Construct the configured vector store."""
    if settings.vector_backend is VectorBackendName.FAISS:
        return FaissVectorStore()
    return NumpyVectorStore()


def build_retriever(settings: Settings) -> ControlRetriever:
    """Load the prepared index and return a retriever over it."""
    controls = load_control_snapshot(settings.resolve_path(settings.data_reference_dir))

    store = build_store(settings)
    store.load(settings.resolve_path(settings.vector_index_path))

    return ControlRetriever(
        build_embedder(settings),
        store,
        controls,
        top_k=settings.retrieval_top_k,
        minimum_score=settings.retrieval_min_score,
    )


class Application:
    """The assembled application."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.chain = ProviderChain(build_providers(settings))
        self.retriever = build_retriever(settings)
        self.reports = ReportService.from_settings(
            settings,
            self.retriever,
            NarrationService(self.chain),
            SummaryService(self.chain),
        )

        logger.info(
            "application ready",
            controls=self.retriever.catalogue_size,
            providers=self.chain.names or ("deterministic",),
        )

    def warm_up(self) -> None:
        """Perform first-use work now rather than during a request.

        The embedding model loads lazily, so a query is issued here to move
        that cost out of the first reader's request.
        """
        self.retriever.retrieve_for_query("warm up the embedding model", limit=1)
        logger.info("embedding model warmed")

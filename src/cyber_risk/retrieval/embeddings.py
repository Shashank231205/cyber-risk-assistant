"""Embedding backends.

Retrieval runs against the security control catalogue, which is prose: a
reader asks about a payment gateway under active exploitation, and the control
that answers it says "flaw remediation" without using any of those words.
Exact matching cannot bridge that gap, which is why this corpus is embedded
while the structured records are queried directly.

The default backend runs locally through ONNX. The obvious alternative,
``sentence-transformers``, pulls in PyTorch at roughly 400 MB resident, which
does not fit the 512 MB free-tier ceiling this system targets. The ONNX build
serves the same model at a fraction of that.

A hosted backend is available as a fallback. Both are reached through one
protocol so the choice is configuration rather than a code path.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import numpy as np
from numpy.typing import NDArray

from cyber_risk.core.exceptions import EmbeddingError
from cyber_risk.core.logging import get_logger

logger = get_logger(__name__)

Vector = NDArray[np.float32]

#: Query prefix recommended for this model family. Asymmetric retrieval
#: instructs the query side only; documents are embedded unprefixed.
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "


@runtime_checkable
class EmbeddingBackend(Protocol):
    """Turns text into vectors for retrieval."""

    @property
    def dimension(self) -> int:
        """Length of the vectors this backend produces."""
        ...

    def embed_documents(self, texts: list[str]) -> Vector:
        """Embed corpus documents, returning one row per text."""
        ...

    def embed_query(self, text: str) -> Vector:
        """Embed a single search query."""
        ...


def normalise(vectors: Vector) -> Vector:
    """Scale vectors to unit length.

    With unit vectors an inner product is cosine similarity, so the store
    needs only one similarity operation and scores are directly comparable
    between backends of different dimensionality.
    """
    magnitudes = np.linalg.norm(vectors, axis=-1, keepdims=True)
    unit: Vector = (vectors / np.maximum(magnitudes, 1e-12)).astype(np.float32)
    return unit


class LocalEmbedder:
    """Local ONNX embedding backend.

    Requires no API key and no network once the model is cached, so the
    deployed system keeps working when every hosted provider is unavailable.
    """

    def __init__(self, model_name: str, batch_size: int = 32) -> None:
        self._model_name = model_name
        self._batch_size = batch_size
        self._model: object | None = None
        self._dimension = 0

    def _load(self) -> object:
        """Load the model on first use, so importing this module stays cheap."""
        if self._model is None:
            try:
                from fastembed import TextEmbedding
            except ImportError as exc:
                raise EmbeddingError(
                    "The local embedding backend is unavailable.",
                    detail="fastembed is not installed",
                ) from exc

            logger.info("loading embedding model", model=self._model_name)
            self._model = TextEmbedding(self._model_name)
        return self._model

    @property
    def dimension(self) -> int:
        """Length of the vectors this backend produces."""
        if not self._dimension:
            self._dimension = int(self.embed_query("dimension probe").shape[-1])
        return self._dimension

    def embed_documents(self, texts: list[str]) -> Vector:
        """Embed corpus documents, returning one row per text."""
        if not texts:
            return np.zeros((0, self.dimension), dtype=np.float32)

        model = self._load()
        try:
            vectors = list(model.embed(texts, batch_size=self._batch_size))  # type: ignore[attr-defined]
        except Exception as exc:
            raise EmbeddingError(
                "Documents could not be embedded.",
                detail=f"local embedding failed for {len(texts)} documents: {exc}",
            ) from exc

        return normalise(np.asarray(vectors, dtype=np.float32))

    def embed_query(self, text: str) -> Vector:
        """Embed a single search query."""
        model = self._load()
        try:
            vectors = list(model.query_embed([text]))  # type: ignore[attr-defined]
        except Exception as exc:
            raise EmbeddingError(
                "The query could not be embedded.",
                detail=f"local query embedding failed: {exc}",
            ) from exc

        return normalise(np.asarray(vectors[0], dtype=np.float32))


class GeminiEmbedder:
    """Hosted embedding backend.

    Used when local inference is undesirable. Carries a network dependency and
    an API key, so it is a fallback rather than the default.
    """

    ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self, api_key: str, model_name: str = "text-embedding-004") -> None:
        self._api_key = api_key
        self._model_name = model_name
        self._dimension = 0

    @property
    def dimension(self) -> int:
        """Length of the vectors this backend produces."""
        if not self._dimension:
            self._dimension = int(self.embed_query("dimension probe").shape[-1])
        return self._dimension

    def _embed(self, texts: list[str], task: str) -> Vector:
        """Call the hosted embedding endpoint."""
        from cyber_risk.core.http import create_client

        requests = [
            {
                "model": f"models/{self._model_name}",
                "content": {"parts": [{"text": text}]},
                "taskType": task,
            }
            for text in texts
        ]

        try:
            with create_client() as client:
                response = client.post(
                    f"{self.ENDPOINT}/{self._model_name}:batchEmbedContents",
                    headers={"x-goog-api-key": self._api_key},
                    json={"requests": requests},
                )
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:
            raise EmbeddingError(
                "The embedding service could not be reached.",
                detail=f"hosted embedding request failed: {exc}",
            ) from exc

        embeddings = payload.get("embeddings")
        if not embeddings:
            raise EmbeddingError(
                "The embedding service returned no vectors.",
                detail="response contained no embeddings",
            )

        values = np.asarray([item["values"] for item in embeddings], dtype=np.float32)
        return normalise(values)

    def embed_documents(self, texts: list[str]) -> Vector:
        """Embed corpus documents, returning one row per text."""
        if not texts:
            return np.zeros((0, self.dimension), dtype=np.float32)
        return self._embed(texts, "RETRIEVAL_DOCUMENT")

    def embed_query(self, text: str) -> Vector:
        """Embed a single search query."""
        single: Vector = self._embed([text], "RETRIEVAL_QUERY")[0]
        return single

"""Vector storage and similarity search.

The control catalogue holds roughly 1,200 documents. At that size an exact
scan over a single array is around 0.5 MB of memory and well under a
millisecond per query, so the default store is plain NumPy: no index server,
no database, no extra dependency, and exact results rather than approximate
ones.

A dedicated index earns its place at a scale this corpus does not reach. The
backend is therefore selectable, and swapping in an approximate index later
is a configuration change rather than a rewrite, because both implementations
satisfy the same protocol.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

import numpy as np

from cyber_risk.core.exceptions import IndexNotBuiltError, RetrievalError
from cyber_risk.core.logging import get_logger
from cyber_risk.retrieval.embeddings import Vector

logger = get_logger(__name__)

VECTORS_FILE = "vectors.npy"
DOCUMENTS_FILE = "documents.json"


@runtime_checkable
class VectorStore(Protocol):
    """Stores document vectors and answers similarity queries."""

    def add(self, vectors: Vector, document_ids: list[str]) -> None:
        """Add vectors and the identifiers they correspond to."""
        ...

    def search(self, query: Vector, top_k: int) -> list[tuple[str, float]]:
        """Return the closest ``(document_id, score)`` pairs, best first."""
        ...

    def save(self, directory: Path) -> None:
        """Persist the store."""
        ...

    def load(self, directory: Path) -> None:
        """Restore the store from disk."""
        ...

    @property
    def size(self) -> int:
        """How many vectors are stored."""
        ...


class NumpyVectorStore:
    """Exact similarity search over a single array.

    Vectors are unit length, so the inner product is cosine similarity.
    """

    def __init__(self) -> None:
        self._vectors: Vector | None = None
        self._document_ids: list[str] = []

    def add(self, vectors: Vector, document_ids: list[str]) -> None:
        """Add vectors and the identifiers they correspond to."""
        if len(vectors) != len(document_ids):
            raise RetrievalError(
                "The index could not be built.",
                detail=(
                    f"vector count {len(vectors)} does not match document count "
                    f"{len(document_ids)}"
                ),
            )

        self._vectors = (
            vectors.astype(np.float32)
            if self._vectors is None
            else np.vstack([self._vectors, vectors.astype(np.float32)])
        )
        self._document_ids.extend(document_ids)

    def search(self, query: Vector, top_k: int) -> list[tuple[str, float]]:
        """Return the closest ``(document_id, score)`` pairs, best first."""
        if self._vectors is None or not self._document_ids:
            raise IndexNotBuiltError(
                "The guidance index is unavailable.",
                detail="search attempted before any vectors were added",
            )

        similarities = self._vectors @ query.astype(np.float32)
        count = min(top_k, len(self._document_ids))

        # argpartition finds the top candidates without sorting the whole array;
        # only those few are then ordered.
        candidates = np.argpartition(-similarities, count - 1)[:count]
        ordered = candidates[np.argsort(-similarities[candidates])]

        return [(self._document_ids[i], float(similarities[i])) for i in ordered]

    def save(self, directory: Path) -> None:
        """Persist the store."""
        if self._vectors is None:
            raise IndexNotBuiltError(
                "There is no index to save.",
                detail="save attempted before any vectors were added",
            )

        directory.mkdir(parents=True, exist_ok=True)
        np.save(directory / VECTORS_FILE, self._vectors)
        (directory / DOCUMENTS_FILE).write_text(
            json.dumps(self._document_ids), encoding="utf-8"
        )
        logger.info("index saved", vectors=len(self._document_ids))

    def load(self, directory: Path) -> None:
        """Restore the store from disk."""
        vectors_path = directory / VECTORS_FILE
        documents_path = directory / DOCUMENTS_FILE

        if not vectors_path.is_file() or not documents_path.is_file():
            raise IndexNotBuiltError(
                "The guidance index has not been built.",
                detail=f"no index found in {directory}",
            )

        self._vectors = np.load(vectors_path).astype(np.float32)
        self._document_ids = json.loads(documents_path.read_text(encoding="utf-8"))

        if len(self._vectors) != len(self._document_ids):
            raise RetrievalError(
                "The guidance index is inconsistent.",
                detail=(
                    f"index holds {len(self._vectors)} vectors for "
                    f"{len(self._document_ids)} documents"
                ),
            )

    @property
    def size(self) -> int:
        """How many vectors are stored."""
        return len(self._document_ids)


class FaissVectorStore(NumpyVectorStore):
    """Similarity search backed by a FAISS flat index.

    Behaves identically to the NumPy store at this corpus size and exists so
    that growth beyond an exact scan does not require touching callers. Falls
    back to the NumPy path when FAISS is not installed, since it is an
    optional dependency.
    """

    def __init__(self) -> None:
        super().__init__()
        self._index: object | None = None
        self._reported_absence = False

    def add(self, vectors: Vector, document_ids: list[str]) -> None:
        """Add vectors and the identifiers they correspond to."""
        super().add(vectors, document_ids)
        self._index = None

    def search(self, query: Vector, top_k: int) -> list[tuple[str, float]]:
        """Return the closest ``(document_id, score)`` pairs, best first."""
        index = self._ensure_index()
        if index is None:
            return super().search(query, top_k)

        count = min(top_k, self.size)
        scores, positions = index.search(  # type: ignore[attr-defined]
            query.astype(np.float32).reshape(1, -1), count
        )
        return [
            (self._document_ids[int(position)], float(score))
            for position, score in zip(positions[0], scores[0], strict=False)
            if position >= 0
        ]

    def _ensure_index(self) -> object | None:
        """Build the index on first search, or signal that FAISS is absent."""
        if self._index is not None:
            return self._index
        if self._vectors is None or not self._document_ids:
            raise IndexNotBuiltError(
                "The guidance index is unavailable.",
                detail="search attempted before any vectors were added",
            )

        try:
            import faiss
        except ImportError:
            # Logged once per store rather than per search: the condition is a
            # deployment fact, not an event.
            if not self._reported_absence:
                logger.info("faiss is not installed; using exact search instead")
                self._reported_absence = True
            return None

        index: object = faiss.IndexFlatIP(self._vectors.shape[1])
        index.add(self._vectors)  # type: ignore[attr-defined]
        self._index = index
        return index

    def load(self, directory: Path) -> None:
        """Restore the store from disk."""
        super().load(directory)
        self._index = None

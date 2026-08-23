"""Retrieving remediation guidance from the security control catalogue.

The query put to the index is built from what the system established about a
risk, not from the vulnerability title alone. A title names a product; the
control that answers it describes an activity. Describing the situation, an
unpatched internet-facing flaw under active exploitation with no endpoint
monitoring, retrieves the control that addresses it.

Retrieved guidance is always attributed. Each result carries the control
identifier, its title, the text it was matched on and the similarity score,
so a reader can see which control was consulted and how strong the match was.
Guidance below the configured floor is reported as a weak match rather than
presented as an answer.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from cyber_risk.core.exceptions import IndexNotBuiltError
from cyber_risk.core.logging import get_logger
from cyber_risk.ingestion.reference_data import ControlDocument
from cyber_risk.models.enums import FindingKind
from cyber_risk.models.risk import CorrelatedRisk
from cyber_risk.retrieval.embeddings import EmbeddingBackend
from cyber_risk.retrieval.vector_store import VectorStore

logger = get_logger(__name__)

#: Longest control excerpt shown to a reader. Enough to convey what the
#: control requires without reproducing the catalogue.
EXCERPT_LIMIT = 600

#: How many candidates to retrieve per requested result before re-ranking.
CANDIDATE_MULTIPLIER = 4

#: Preference applied to a governing control over its own enhancements.
#: A reader deciding what to do needs the control that states the requirement;
#: enhancements refine a requirement that the base control establishes, and on
#: their own they read as an answer to a question nobody asked. Deliberately
#: small, so a genuinely better-matching enhancement still wins.
BASE_CONTROL_PREFERENCE = 0.03


class RetrievedControl(BaseModel):
    """One control retrieved as guidance for a risk."""

    model_config = ConfigDict(frozen=True)

    control_id: str
    title: str
    family: str = ""
    excerpt: str
    score: float = Field(ge=-1.0, le=1.0)
    is_weak_match: bool = False

    @property
    def citation(self) -> str:
        """How this control should be referred to in output."""
        return f"NIST SP 800-53 Rev. 5 {self.control_id} ({self.title})"


def build_query(risk: CorrelatedRisk) -> str:
    """Describe a risk in the language the control catalogue uses.

    Controls are written in terms of activities an organisation performs, so
    the query states the situation rather than naming the product. A query of
    only the vulnerability title retrieves whatever control happens to mention
    that vendor, which is rarely the one that addresses the problem.
    """
    parts: list[str] = []

    # Lead with the action required. Describing the threat instead retrieves
    # controls about adversary deception and misdirection, which are a poor
    # answer to "what should we do about this".
    if risk.vulnerability.finding_kind is FindingKind.CONTROL_DEFICIENCY:
        parts.append(
            "Implement and assess a missing security control. "
            "Control implementation, assessment and configuration management"
        )
    else:
        parts.append(
            "Remediate a software flaw. Flaw remediation, install security "
            "patches and updates, patch management, corrective action"
        )

    if risk.vulnerability.exploit_available or risk.intel:
        parts.append(
            "Vulnerability monitoring and scanning, remediate identified "
            "vulnerabilities within defined response times"
        )

    if risk.is_internet_facing:
        parts.append(
            "Boundary protection for an externally reachable system, restrict "
            "external network connections"
        )

    if risk.ransomware_linked:
        parts.append(
            "Incident handling and recovery, system backup and restoration, "
            "contingency planning"
        )

    if not risk.asset.edr_installed:
        parts.append(
            "Continuous monitoring, malicious code protection, endpoint "
            "detection and response"
        )

    if not risk.vulnerability.patch_available:
        parts.append(
            "Unsupported system component without vendor support, compensating "
            "controls"
        )

    if not risk.vulnerability.auth_required:
        parts.append("Access enforcement, identification and authentication of users")

    if not risk.asset.has_owner:
        parts.append("Assign system ownership and responsibility for remediation")

    if risk.asset.is_stale:
        parts.append("Maintain an accurate system component inventory")

    parts.append(risk.vulnerability.vulnerability_name)
    if risk.vulnerability.affected_component:
        parts.append(risk.vulnerability.affected_component)

    return ". ".join(parts)


class ControlRetriever:
    """Retrieves catalogue guidance for a risk.

    Dependencies are injected so the retriever can be exercised with stub
    implementations and neither the embedding backend nor the store is
    constructed here.
    """

    def __init__(
        self,
        embedder: EmbeddingBackend,
        store: VectorStore,
        controls: tuple[ControlDocument, ...],
        *,
        top_k: int = 4,
        minimum_score: float = 0.30,
    ) -> None:
        self._embedder = embedder
        self._store = store
        self._controls = {control.control_id: control for control in controls}
        self._top_k = top_k
        self._minimum_score = minimum_score

    @property
    def catalogue_size(self) -> int:
        """How many controls are searchable."""
        return len(self._controls)

    def retrieve(
        self, risk: CorrelatedRisk, limit: int | None = None
    ) -> tuple[RetrievedControl, ...]:
        """Retrieve the most applicable controls for ``risk``."""
        return self.retrieve_for_query(build_query(risk), limit)

    def retrieve_for_query(
        self, query: str, limit: int | None = None
    ) -> tuple[RetrievedControl, ...]:
        """Retrieve the most applicable controls for a free-text query."""
        if not self._controls:
            raise IndexNotBuiltError(
                "The guidance catalogue is empty.",
                detail="retriever was constructed without any controls",
            )

        top_k = limit or self._top_k

        # Retrieve a wider candidate set than requested so the base-control
        # preference below has something to reorder.
        candidates = self._store.search(
            self._embedder.embed_query(query), top_k * CANDIDATE_MULTIPLIER
        )
        matches = _prefer_base_controls(candidates)[:top_k]

        results: list[RetrievedControl] = []
        for control_id, score in matches:
            control = self._controls.get(control_id)
            if control is None:
                # The index and the catalogue have diverged; skip rather than
                # fabricate a control that cannot be quoted.
                logger.warning("index references an unknown control", control_id=control_id)
                continue

            results.append(
                RetrievedControl(
                    control_id=control.control_id,
                    title=control.title,
                    family=control.family,
                    excerpt=_excerpt(control),
                    score=score,
                    is_weak_match=score < self._minimum_score,
                )
            )

        return tuple(results)


def _prefer_base_controls(
    candidates: list[tuple[str, float]],
) -> list[tuple[str, float]]:
    """Re-rank candidates to favour governing controls over enhancements.

    Enhancement identifiers extend their parent's, so a control identifier
    containing no separator is a governing control. The adjustment is applied
    for ordering only; the score reported to a reader stays the raw similarity,
    since a displayed score that has been quietly adjusted is misleading.
    """
    def adjusted(item: tuple[str, float]) -> float:
        control_id, score = item
        return score + (BASE_CONTROL_PREFERENCE if "." not in control_id else 0.0)

    return sorted(candidates, key=adjusted, reverse=True)


def _excerpt(control: ControlDocument) -> str:
    """Take a readable excerpt of a control's text."""
    body = control.statement or control.discussion or control.title
    collapsed = " ".join(body.split())

    if len(collapsed) <= EXCERPT_LIMIT:
        return collapsed

    truncated = collapsed[:EXCERPT_LIMIT]
    boundary = truncated.rfind(". ")
    if boundary > EXCERPT_LIMIT // 2:
        return truncated[: boundary + 1]
    return truncated.rstrip() + "..."


def build_index(
    controls: tuple[ControlDocument, ...],
    embedder: EmbeddingBackend,
    store: VectorStore,
    destination: Path | None = None,
) -> VectorStore:
    """Embed the control catalogue and populate the store.

    Run at build time rather than on startup, so a request never waits for the
    catalogue to be embedded.
    """
    texts = [control.text for control in controls]
    identifiers = [control.control_id for control in controls]

    logger.info("embedding control catalogue", controls=len(texts))
    store.add(embedder.embed_documents(texts), identifiers)

    if destination is not None:
        store.save(destination)

    return store

"""Turning scored evidence into readable prose.

Every risk is narrated in a single request rather than one request each. Five
sequential calls to a free-tier service cost five round trips and five chances
to be rate limited; one call costs one of each.

Narration is presentation. The ranking, the evidence and the retrieved control
are settled before this module runs, and the deterministic fallback produces a
complete report on its own. That is what keeps a rate-limited free tier from
turning into a failed report.

Generated text is validated before use: a response with the wrong number of
entries, or one that introduces a control identifier the evidence never
mentioned, is discarded in favour of the deterministic version.
"""

from __future__ import annotations

import re
from pathlib import Path

from cyber_risk.core.logging import get_logger
from cyber_risk.models.risk import ScoredRisk
from cyber_risk.retrieval.retriever import RetrievedControl
from cyber_risk.services.llm import ProviderChain

logger = get_logger(__name__)

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "narration.md"

#: Matches a control identifier so generated text can be checked for
#: references the supplied evidence never contained.
_CONTROL_PATTERN = re.compile(r"\b[A-Z]{2}-\d{1,2}(?:\.\d{1,2})?\b")

#: Matches the numbered lines the prompt asks for.
_NUMBERED_LINE = re.compile(r"^\s*(\d+)\s*[:.]\s*(.+)$")


def load_system_prompt() -> str:
    """Load the narration instructions."""
    return PROMPT_PATH.read_text(encoding="utf-8")


def describe_evidence(scored: ScoredRisk, control: RetrievedControl | None) -> str:
    """Render one risk as the evidence block handed to the model.

    Only facts the system established are included. The model is given no room
    to supply a detail because the detail was missing.
    """
    risk = scored.risk
    lines: list[str] = [
        f"Asset: {risk.asset.asset_name} ({risk.asset.asset_type}, "
        f"{risk.asset.environment.value.lower()}, {risk.asset.location})",
        f"Finding: {risk.vulnerability.vulnerability_name} [{risk.vulnerability.cve}]",
        f"Technical severity: {risk.vulnerability.cvss} of 10",
        f"Reachable from the internet: {'yes' if risk.is_internet_facing else 'no'}",
        f"Days open: {risk.vulnerability.days_open}",
    ]

    if risk.service is not None:
        service = risk.service
        lines.append(f"Business service: {service.business_service}")
        lines.append(f"Business impact if lost: {service.business_impact}")
        if service.compliance_scope:
            lines.append(f"Compliance scope: {', '.join(service.compliance_scope)}")
        lines.append(f"Recovery time objective: {service.rto_hours} hours")
    else:
        lines.append("Business service: not defined for this asset")

    if risk.kev is not None:
        lines.append(
            "Public catalogue: confirmed exploited in the wild"
            + (
                ", used in ransomware campaigns"
                if risk.kev.known_ransomware_campaign_use
                else ""
            )
        )
        if risk.kev.required_action:
            lines.append(f"Catalogue required action: {risk.kev.required_action}")
    elif not risk.vulnerability.is_catalogue_assessable:
        lines.append(
            "Public catalogue: not assessable, this identifier is assigned "
            "internally and cannot be looked up"
        )
    else:
        lines.append(
            "Public catalogue: no entry found, which does not establish that it "
            "is not exploited"
        )

    if risk.campaign_names:
        actors = ", ".join(risk.threat_actors) if risk.threat_actors else "an unnamed group"
        lines.append(
            f"Threat activity: campaign {', '.join(risk.campaign_names)} run by "
            f"{actors}, exploit maturity {risk.peak_exploit_maturity.value.lower()}"
        )
    else:
        lines.append("Threat activity: no campaign in the feed references this finding")

    lines.append("Why it ranks here:")
    lines.extend(f"  - {item}" for item in scored.breakdown.all_evidence)

    if control is not None:
        lines.append(f"Applicable control: {control.control_id} {control.title}")
        lines.append(f"Control requires: {control.excerpt}")
        if control.is_weak_match:
            lines.append("Control match confidence: low, treat as indicative only")
    else:
        lines.append("Applicable control: none retrieved")

    return "\n".join(lines)


def build_prompt(entries: list[tuple[ScoredRisk, RetrievedControl | None]]) -> str:
    """Assemble the single request covering every risk."""
    blocks = [
        f"### Risk {position}\n{describe_evidence(scored, control)}"
        for position, (scored, control) in enumerate(entries, start=1)
    ]
    return (
        f"There are {len(entries)} risks. Write one paragraph for each.\n\n"
        + "\n\n".join(blocks)
    )


def deterministic_narration(
    scored: ScoredRisk, control: RetrievedControl | None
) -> str:
    """Compose a paragraph from the evidence without a language model.

    The report must be producible with no provider configured, so this is a
    supported output rather than a degraded placeholder.
    """
    risk = scored.risk
    service = risk.service.business_service if risk.service else "an undefined service"
    reach = "reachable from the internet" if risk.is_internet_facing else "internal only"

    sentences = [
        f"{risk.asset.asset_name} is affected by "
        f"{risk.vulnerability.vulnerability_name} ({risk.vulnerability.cve}), "
        f"severity {risk.vulnerability.cvss} of 10, and is {reach}. "
        f"It supports {service}."
    ]

    if risk.kev is not None:
        confirmation = "is confirmed exploited in the wild"
        if risk.kev.known_ransomware_campaign_use:
            confirmation += " and is used in ransomware campaigns"
        sentences.append(f"This vulnerability {confirmation}.")
    elif not risk.vulnerability.is_catalogue_assessable:
        sentences.append(
            "This finding carries an internally assigned identifier, so its "
            "exploitation status could not be confirmed against the public catalogue."
        )

    if risk.campaign_names:
        actors = ", ".join(risk.threat_actors) or "an unnamed group"
        sentences.append(
            f"It is referenced by campaign {', '.join(risk.campaign_names)}, "
            f"attributed to {actors}."
        )

    dominant = scored.breakdown.dominant_factor
    if dominant is not None and dominant.evidence:
        sentences.append(f"It ranks here mainly because: {dominant.evidence[0].lower()}")

    if control is not None:
        sentences.append(
            f"{control.control_id} ({control.title}) applies: {control.excerpt}"
        )

    return " ".join(sentences)


def _parse_response(text: str, expected: int) -> list[str] | None:
    """Extract one paragraph per risk, or ``None`` if the shape is wrong."""
    paragraphs: dict[int, str] = {}
    for line in text.splitlines():
        match = _NUMBERED_LINE.match(line)
        if match:
            paragraphs[int(match.group(1))] = match.group(2).strip()

    if len(paragraphs) != expected or set(paragraphs) != set(range(1, expected + 1)):
        logger.warning(
            "generated narration had the wrong shape",
            expected=expected,
            received=len(paragraphs),
        )
        return None

    return [paragraphs[position] for position in range(1, expected + 1)]


def _mentions_unsupported_control(paragraph: str, control: RetrievedControl | None) -> bool:
    """Whether the text cites a control the evidence did not supply.

    A fabricated control identifier is the failure that matters most here: it
    reads as authoritative and sends somebody to the wrong requirement.
    """
    allowed = {control.control_id} if control is not None else set()
    return any(found not in allowed for found in _CONTROL_PATTERN.findall(paragraph))


class NarrationService:
    """Produces the prose shown for each risk."""

    def __init__(self, chain: ProviderChain) -> None:
        self._chain = chain

    async def narrate(
        self, entries: list[tuple[ScoredRisk, RetrievedControl | None]]
    ) -> tuple[list[str], str | None]:
        """Return one paragraph per risk and the provider that produced them.

        The provider is ``None`` when narration was produced deterministically,
        which the report states rather than hides.
        """
        if not entries:
            return [], None

        fallback = [
            deterministic_narration(scored, control) for scored, control in entries
        ]

        if not self._chain.is_available:
            return fallback, None

        generated = await self._chain.generate(load_system_prompt(), build_prompt(entries))
        if generated is None:
            return fallback, None

        paragraphs = _parse_response(generated, len(entries))
        if paragraphs is None:
            return fallback, None

        verified: list[str] = []
        for index, (paragraph, (_, control)) in enumerate(zip(paragraphs, entries, strict=True)):
            if _mentions_unsupported_control(paragraph, control):
                logger.warning("generated text cited an unsupplied control", position=index + 1)
                verified.append(fallback[index])
            else:
                verified.append(paragraph)

        return verified, self._chain.last_used

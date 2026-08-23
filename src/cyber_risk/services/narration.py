"""Turning scored evidence into readable prose.

Every risk is narrated in a single request rather than one request each. Five
sequential calls to a free-tier service cost five round trips and five chances
to be rate limited; one call costs one of each.

Narration is presentation. The ranking, the evidence and the retrieved control
are settled before this module runs, and the deterministic fallback produces a
complete report on its own, so a rate-limited free tier costs wording rather
than the report.

Generated text is validated before use. A response with the wrong number of
entries, or one introducing a control identifier the evidence never mentioned,
is discarded in favour of the deterministic version.
"""

from __future__ import annotations

import re
from pathlib import Path

from cyber_risk.core.logging import get_logger
from cyber_risk.models.narrative import RiskNarrative
from cyber_risk.models.risk import ScoredRisk
from cyber_risk.retrieval.retriever import RetrievedControl
from cyber_risk.services.llm import ProviderChain

logger = get_logger(__name__)

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "narration.md"

# Matches a control identifier, so generated text can be checked for
# references the supplied evidence never contained.
_CONTROL_PATTERN = re.compile(r"\b[A-Z]{2}-\d{1,2}(?:\.\d{1,2})?\b")

# Matches the numbered lines the instructions ask for.
_NUMBERED_LINE = re.compile(r"^\s*(\d+)\s*[:.]\s*(.+)$")

# Field labels within a line, in the order the instructions specify.
_FIELD_LABELS = ("ASSESSMENT", "THREAT", "IMPACT", "ACTION")


def load_system_prompt() -> str:
    """Load the narration instructions."""
    return PROMPT_PATH.read_text(encoding="utf-8")


def describe_evidence(scored: ScoredRisk, control: RetrievedControl | None) -> str:
    """Render one risk as the evidence block handed to the model.

    Only facts the system established are included, so the model has no room to
    supply a detail because the detail was missing.
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

    lines.append(_catalogue_line(risk))

    if risk.kev is not None and risk.kev.required_action:
        lines.append(f"Catalogue required action: {risk.kev.required_action}")

    if risk.campaign_names:
        actors = ", ".join(risk.threat_actors) if risk.threat_actors else "an unnamed group"
        lines.append(
            f"Threat activity: campaign {', '.join(risk.campaign_names)} run by "
            f"{actors}, exploit maturity {risk.peak_exploit_maturity.value.lower()}"
        )
    else:
        lines.append("Threat activity: no campaign in the feed references this finding")

    lines.append("Why it ranks here:")
    lines.extend(f"  {item}" for item in scored.breakdown.all_evidence)

    if control is not None:
        lines.append(f"Applicable control: {control.control_id} {control.title}")
        lines.append(f"Control requires: {control.excerpt}")
        if control.is_weak_match:
            lines.append("Control match confidence: low, treat as indicative only")
    else:
        lines.append("Applicable control: none retrieved")

    return "\n".join(lines)


def _catalogue_line(risk: object) -> str:
    """State what the public catalogue does and does not establish."""
    kev = risk.kev  # type: ignore[attr-defined]
    vulnerability = risk.vulnerability  # type: ignore[attr-defined]

    if kev is not None:
        suffix = ", used in ransomware campaigns" if kev.known_ransomware_campaign_use else ""
        return f"Public catalogue: confirmed exploited in the wild{suffix}"

    if not vulnerability.is_catalogue_assessable:
        return (
            "Public catalogue: not assessable, this identifier is assigned "
            "internally and cannot be looked up"
        )

    return (
        "Public catalogue: no entry found, which does not establish that it "
        "is not exploited"
    )


def build_prompt(entries: list[tuple[ScoredRisk, RetrievedControl | None]]) -> str:
    """Assemble the single request covering every risk."""
    blocks = [
        f"### Risk {position}\n{describe_evidence(scored, control)}"
        for position, (scored, control) in enumerate(entries, start=1)
    ]
    return (
        f"There are {len(entries)} risks. Produce one line for each.\n\n"
        + "\n\n".join(blocks)
    )


def deterministic_narrative(
    scored: ScoredRisk, control: RetrievedControl | None
) -> RiskNarrative:
    """Compose the four fields from evidence, without a language model.

    A supported output rather than a degraded placeholder: the report must be
    producible with no provider configured.
    """
    risk = scored.risk
    reach = "reachable from the internet" if risk.is_internet_facing else "internal only"

    assessment = (
        f"{risk.asset.asset_name} is a {risk.asset.environment.value.lower()} "
        f"{risk.asset.asset_type.lower()} affected by "
        f"{risk.vulnerability.vulnerability_name}, and is {reach}. "
        f"It has been open for {risk.vulnerability.days_open} days at severity "
        f"{risk.vulnerability.cvss} of 10."
    )

    threat = _deterministic_threat(scored)
    impact = _deterministic_impact(scored)
    action = (
        f"{control.control_id} {control.title} applies: {control.excerpt}"
        if control is not None
        else "No control was retrieved for this finding."
    )

    return RiskNarrative(
        assessment=assessment, threat=threat, impact=impact, action=action
    )


def _deterministic_threat(scored: ScoredRisk) -> str:
    """State what is known about who is attacking this."""
    risk = scored.risk
    parts: list[str] = []

    if risk.campaign_names:
        actors = ", ".join(risk.threat_actors) or "an unattributed group"
        parts.append(
            f"Referenced by campaign {', '.join(risk.campaign_names)}, "
            f"attributed to {actors}"
        )
    else:
        parts.append("No campaign in the current feed references this finding")

    if risk.kev is not None:
        confirmation = "confirmed exploited in the wild"
        if risk.kev.known_ransomware_campaign_use:
            confirmation += " and used in ransomware campaigns"
        parts.append(f"it is {confirmation}")
    elif not risk.vulnerability.is_catalogue_assessable:
        parts.append(
            "its identifier is internal, so exploitation could not be confirmed "
            "against the public catalogue"
        )

    return "; ".join(parts) + "."


def _deterministic_impact(scored: ScoredRisk) -> str:
    """State what stops working if this asset is compromised."""
    service = scored.risk.service
    if service is None:
        return "No business service is defined for this asset, so impact is unknown."

    sentence = f"Compromise affects {service.business_service}"
    if service.business_impact:
        sentence += f": {service.business_impact.rstrip('.')}"
    if service.compliance_scope:
        sentence += f", within {', '.join(service.compliance_scope)} scope"
    if service.rto_hours:
        sentence += f" and a {service.rto_hours}-hour recovery objective"
    return sentence + "."


def _parse_line(body: str) -> RiskNarrative | None:
    """Split one response line into its four labelled fields."""
    fields: dict[str, str] = {}

    for segment in body.split("||"):
        cleaned = segment.strip()
        for label in _FIELD_LABELS:
            prefix = f"{label}:"
            if cleaned.upper().startswith(prefix):
                fields[label] = cleaned[len(prefix) :].strip()
                break

    assessment = fields.get("ASSESSMENT", "").strip()
    if not assessment:
        # Without the leading assessment the entry has no opening sentence, so
        # the whole line is unusable however good the remaining fields are.
        return None

    return RiskNarrative(
        assessment=assessment,
        threat=fields.get("THREAT", "").strip(),
        impact=fields.get("IMPACT", "").strip(),
        action=fields.get("ACTION", "").strip(),
    )


def _parse_response(text: str, expected: int) -> list[RiskNarrative] | None:
    """Extract one narrative per risk, or nothing if the shape is wrong."""
    parsed: dict[int, RiskNarrative] = {}

    for line in text.splitlines():
        match = _NUMBERED_LINE.match(line)
        if not match:
            continue
        narrative = _parse_line(match.group(2))
        if narrative is not None:
            parsed[int(match.group(1))] = narrative

    if len(parsed) != expected or set(parsed) != set(range(1, expected + 1)):
        logger.warning(
            "generated narration had the wrong shape",
            expected=expected,
            received=len(parsed),
        )
        return None

    return [parsed[position] for position in range(1, expected + 1)]


def _cites_unsupported_control(
    narrative: RiskNarrative, control: RetrievedControl | None
) -> bool:
    """Whether the text cites a control the evidence did not supply.

    A fabricated control identifier is the failure that matters most here. It
    reads as authoritative and sends somebody to the wrong requirement.
    """
    allowed = {control.control_id} if control is not None else set()
    return any(found not in allowed for found in _CONTROL_PATTERN.findall(narrative.as_text()))


class NarrationService:
    """Produces the prose shown for each risk."""

    def __init__(self, chain: ProviderChain) -> None:
        self._chain = chain

    async def narrate(
        self, entries: list[tuple[ScoredRisk, RetrievedControl | None]]
    ) -> tuple[list[RiskNarrative], str | None]:
        """Return one narrative per risk and the provider that produced them.

        The provider is ``None`` when narration was produced deterministically,
        which the report states rather than hides.
        """
        if not entries:
            return [], None

        fallback = [
            deterministic_narrative(scored, control) for scored, control in entries
        ]

        if not self._chain.is_available:
            return fallback, None

        generated = await self._chain.generate(load_system_prompt(), build_prompt(entries))
        if generated is None:
            return fallback, None

        narratives = _parse_response(generated, len(entries))
        if narratives is None:
            return fallback, None

        verified: list[RiskNarrative] = []
        for index, (narrative, (_, control)) in enumerate(
            zip(narratives, entries, strict=True)
        ):
            if _cites_unsupported_control(narrative, control):
                logger.warning("generated text cited an unsupplied control", position=index + 1)
                verified.append(fallback[index])
            else:
                verified.append(narrative)

        return verified, self._chain.last_used

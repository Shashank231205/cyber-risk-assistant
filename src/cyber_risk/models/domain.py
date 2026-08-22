"""Domain entities for the risk model.

These types are the contract between ingestion and everything downstream.
They are validated on construction, so any component receiving one can rely
on its invariants without re-checking them.

Two decisions here are worth stating explicitly, because both affect the
correctness of the final ranking:

Identifiers are classified, not filtered.
    The vulnerability feed mixes public CVE identifiers with locally minted
    ones covering control deficiencies. Discarding the latter would drop real
    findings, several of which are named in the current advisory. They are
    instead classified, and the classification decides how each is enriched
    and remediated.

Absence of evidence is not evidence of absence.
    An identifier that cannot be looked up in the public exploited-vulnerability
    catalogue is recorded as *not assessable*, never as *not exploited*.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from cyber_risk.models.enums import (
    Confidence,
    Criticality,
    DeploymentEnvironment,
    ExploitMaturity,
    Exposure,
    FindingKind,
    ImpactLevel,
    RiskAppetite,
    Severity,
)

#: A published CVE identifier. Locally minted identifiers deliberately do not
#: match, which is how they are separated from catalogue-assessable ones.
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")

_TRUE_VALUES = frozenset({"yes", "true", "y", "1"})
_FALSE_VALUES = frozenset({"no", "false", "n", "0", ""})

NonEmptyStr = Annotated[str, Field(min_length=1)]


class DomainModel(BaseModel):
    """Base for domain entities: immutable, strict, and whitespace-tolerant."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)


def _parse_flag(value: Any) -> Any:
    """Coerce the feed's Yes/No convention into a boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE_VALUES:
            return True
        if text in _FALSE_VALUES:
            return False
    return value


#: Sentinel strings the source files use to mean "no value". Left in place they
#: would be counted as a real entry -- for example a service marked "None" for
#: compliance scope would otherwise register as regulated and attract weighting
#: it has not earned.
_NULL_SENTINELS = frozenset({"none", "n/a", "na", "null", "-", "unknown"})


def _split_multi(value: Any) -> Any:
    """Split a comma-separated cell into a tuple, dropping null sentinels."""
    if isinstance(value, str):
        return tuple(
            item.strip()
            for item in value.split(",")
            if item.strip() and item.strip().lower() not in _NULL_SENTINELS
        )
    return value


class Asset(DomainModel):
    """An entry in the asset inventory."""

    asset_id: NonEmptyStr
    asset_name: NonEmptyStr
    asset_type: str = ""
    environment: DeploymentEnvironment
    owner_team: str = ""
    business_service: NonEmptyStr
    internet_exposed: bool
    criticality: Criticality
    data_classification: str = ""
    edr_installed: bool
    last_seen_days: int = Field(ge=0)
    location: str = ""
    vendor_product: str = ""

    _coerce_flags = field_validator("internet_exposed", "edr_installed", mode="before")(
        _parse_flag
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_owner(self) -> bool:
        """Whether an owning team is recorded.

        An unowned asset has nobody to action its findings, so this is
        reported rather than silently tolerated.
        """
        return bool(self.owner_team.strip())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_stale(self) -> bool:
        """Whether the inventory record is too old to be trusted."""
        return self.last_seen_days > STALE_ASSET_THRESHOLD_DAYS


STALE_ASSET_THRESHOLD_DAYS = 30


class Vulnerability(DomainModel):
    """An open finding recorded against an asset."""

    vuln_id: NonEmptyStr
    asset_id: NonEmptyStr
    vulnerability_name: NonEmptyStr
    cve: NonEmptyStr
    severity: Severity
    cvss: float = Field(ge=0.0, le=10.0)
    exploit_available: bool
    patch_available: bool
    days_open: int = Field(ge=0)
    asset_exposure: Exposure
    auth_required: bool
    status: str = "Open"
    affected_component: str = ""

    _coerce_flags = field_validator(
        "exploit_available", "patch_available", "auth_required", mode="before"
    )(_parse_flag)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def finding_kind(self) -> FindingKind:
        """Whether this is a published CVE or a local control deficiency."""
        return (
            FindingKind.CVE
            if CVE_PATTERN.match(self.cve)
            else FindingKind.CONTROL_DEFICIENCY
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_catalogue_assessable(self) -> bool:
        """Whether this identifier can be looked up in the public KEV catalogue.

        Only published CVE identifiers can. A false value means *unknown*, and
        must never be presented as *not actively exploited*.
        """
        return self.finding_kind is FindingKind.CVE


class ThreatIntel(DomainModel):
    """A threat actor campaign record from the intelligence feed."""

    intel_id: NonEmptyStr
    threat_actor: str = ""
    campaign_name: str = ""
    target_sector: str = ""
    target_region: str = ""
    matched_cve_or_control: NonEmptyStr
    exploit_maturity: ExploitMaturity
    active_last_seen: str = ""
    ransomware_association: bool
    confidence: Confidence
    summary: str = ""

    _coerce_flags = field_validator("ransomware_association", mode="before")(_parse_flag)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def targets_our_region(self) -> bool:
        """Whether the campaign targets this organisation's operating region."""
        return self.target_region.strip().lower() in {"middle east", "global"}


class BusinessService(DomainModel):
    """A business service that assets support."""

    business_service: NonEmptyStr
    business_owner: str = ""
    business_impact: str = ""
    customer_facing: bool
    compliance_scope: tuple[str, ...] = ()
    revenue_impact: ImpactLevel
    rto_hours: int = Field(ge=0)
    depends_on: tuple[str, ...] = ()
    risk_appetite: RiskAppetite

    _coerce_flags = field_validator("customer_facing", mode="before")(_parse_flag)
    _coerce_lists = field_validator("compliance_scope", "depends_on", mode="before")(
        _split_multi
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_regulated(self) -> bool:
        """Whether any compliance regime applies to this service."""
        return bool(self.compliance_scope)


class RemediationHint(DomainModel):
    """A one-line remediation hint from the supplied guidance file.

    Used only to cross-check the computed priority ordering. Substantive
    remediation guidance is retrieved from the control catalogue, because a
    pre-written hint is not evidence that a control was actually consulted.
    """

    finding_type: NonEmptyStr
    recommended_action: str = ""
    priority_hint: str = ""
    validation_evidence: str = ""

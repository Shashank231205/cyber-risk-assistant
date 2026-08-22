"""Controlled vocabularies used across the risk domain.

Ordinal enums expose a ``rank`` so the scoring model can compare levels
without string comparisons scattered through the code. Ranks are normalised
to 0.0-1.0 so a factor's contribution is bounded by its configured weight
rather than by the number of levels it happens to have.
"""

from __future__ import annotations

from enum import Enum


class OrdinalEnum(str, Enum):
    """A string enum whose members carry an explicit order."""

    @property
    def rank(self) -> float:
        """Position of this member on a normalised 0.0-1.0 scale."""
        members = list(type(self))
        if len(members) == 1:
            return 1.0
        return members.index(self) / (len(members) - 1)


class DeploymentEnvironment(OrdinalEnum):
    """Environment an asset runs in, ordered by blast radius."""

    DEVELOPMENT = "Development"
    STAGING = "Staging"
    PRODUCTION = "Production"


class Criticality(OrdinalEnum):
    """Business criticality of an asset."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Severity(OrdinalEnum):
    """Vendor-assigned severity band for a vulnerability."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ImpactLevel(OrdinalEnum):
    """Revenue or business impact level for a service."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class RiskAppetite(OrdinalEnum):
    """Declared tolerance for risk on a business service.

    Ordered so that a *lower* appetite ranks *higher*: a service the business
    is least willing to see disrupted must attract more attention, not less.
    """

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    VERY_LOW = "Very Low"


class Exposure(OrdinalEnum):
    """Network reachability recorded against a vulnerability."""

    INTERNAL = "Internal"
    INTERNET = "Internet"


class ExploitMaturity(OrdinalEnum):
    """How far an exploit has progressed toward routine use.

    Richer than the vulnerability feed's binary exploit flag, and the two can
    disagree; the scoring model treats this as the stronger signal when
    threat intelligence is available.
    """

    NOT_APPLICABLE = "Not Applicable"
    SOCIAL_ENGINEERING = "Social Engineering"
    PROOF_OF_CONCEPT = "Proof of Concept"
    COMMODITY_EXPLOIT = "Commodity Exploit"
    WEAPONIZED = "Weaponized"
    ACTIVE_EXPLOITATION = "Active Exploitation"


class Confidence(OrdinalEnum):
    """Analyst confidence in a threat intelligence record."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class FindingKind(str, Enum):
    """What an entry in the vulnerability feed actually describes.

    The feed mixes two different things under one identifier column. They
    need different treatment: a patchable flaw is cross-referenced against
    the public exploited-vulnerability catalogue and remediated by patching,
    whereas a control deficiency can be neither, and pointing a reader at a
    patch for one would be misleading.
    """

    CVE = "cve"
    CONTROL_DEFICIENCY = "control_deficiency"


class DataQualitySeverity(str, Enum):
    """How much a detected data quality issue should worry the reader."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

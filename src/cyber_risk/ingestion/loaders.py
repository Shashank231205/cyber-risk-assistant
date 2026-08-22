"""Loading and validating the supplied data pack.

Loading is strict by design. A malformed risk input that is silently coerced
produces a ranking that looks authoritative and is wrong, which is worse than
a refusal to start. Every row is validated, and the first failure reports the
file and row number without echoing the row's contents.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import TypeVar

from pydantic import ValidationError

from cyber_risk.core.exceptions import DataSourceNotFoundError, SchemaValidationError
from cyber_risk.core.logging import get_logger
from cyber_risk.models.domain import (
    Asset,
    BusinessService,
    DomainModel,
    RemediationHint,
    ThreatIntel,
    Vulnerability,
)

logger = get_logger(__name__)

ModelT = TypeVar("ModelT", bound=DomainModel)

ASSETS_FILE = "assets.csv"
VULNERABILITIES_FILE = "vulnerabilities.csv"
THREAT_INTEL_FILE = "threat_intelligence.csv"
BUSINESS_SERVICES_FILE = "business_services.csv"
REMEDIATION_FILE = "remediation_guidance.csv"
THREAT_REPORT_FILE = "synthetic_threat_report.md"


def _read_rows(path: Path) -> Iterator[tuple[int, dict[str, str]]]:
    """Yield ``(row_number, row)`` pairs from a CSV file.

    Uses ``utf-8-sig`` so a byte order mark left by a spreadsheet export does
    not corrupt the first column name.
    """
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SchemaValidationError(
                "An input file could not be read.",
                detail=f"{path.name} contains no header row",
            )
        # Row numbering starts at 2 so reported positions match what a person
        # sees in a spreadsheet, where row 1 is the header.
        yield from enumerate(reader, start=2)


def _load_csv(path: Path, model: type[ModelT]) -> tuple[ModelT, ...]:
    """Load and validate every row of ``path`` into ``model``.

    Raises:
        DataSourceNotFoundError: If the file does not exist.
        SchemaValidationError: If any row fails validation.
    """
    if not path.is_file():
        raise DataSourceNotFoundError(
            "A required input file is unavailable.",
            detail=f"missing input file: {path}",
        )

    records: list[ModelT] = []
    for row_number, row in _read_rows(path):
        try:
            records.append(model(**row))
        except ValidationError as exc:
            # The row itself is confidential; report only where and which field.
            fields = ", ".join(str(e["loc"][0]) for e in exc.errors() if e["loc"])
            raise SchemaValidationError(
                "An input file did not match its expected schema.",
                detail=f"{path.name} row {row_number}: invalid field(s): {fields}",
                context={"file": path.name, "row": row_number},
            ) from exc

    if not records:
        raise SchemaValidationError(
            "An input file contained no records.",
            detail=f"{path.name} has a header but no data rows",
        )

    logger.info("loaded input file", file=path.name, records=len(records))
    return tuple(records)


class DataPack:
    """The validated contents of the supplied data pack.

    Constructed through :meth:`load` so that callers cannot assemble a
    partially validated pack.
    """

    def __init__(
        self,
        *,
        assets: Sequence[Asset],
        vulnerabilities: Sequence[Vulnerability],
        threat_intel: Sequence[ThreatIntel],
        business_services: Sequence[BusinessService],
        remediation_hints: Sequence[RemediationHint],
        threat_report: str,
    ) -> None:
        self.assets = tuple(assets)
        self.vulnerabilities = tuple(vulnerabilities)
        self.threat_intel = tuple(threat_intel)
        self.business_services = tuple(business_services)
        self.remediation_hints = tuple(remediation_hints)
        self.threat_report = threat_report

    @classmethod
    def load(cls, directory: Path) -> DataPack:
        """Load and validate every file in the data pack.

        Args:
            directory: Directory holding the supplied files.

        Returns:
            The validated pack.

        Raises:
            DataSourceNotFoundError: If a required file is missing.
            SchemaValidationError: If a file fails validation.
        """
        if not directory.is_dir():
            raise DataSourceNotFoundError(
                "The data directory is unavailable.",
                detail=f"missing data directory: {directory}",
            )

        report_path = directory / THREAT_REPORT_FILE
        if not report_path.is_file():
            raise DataSourceNotFoundError(
                "A required input file is unavailable.",
                detail=f"missing input file: {report_path}",
            )

        pack = cls(
            assets=_load_csv(directory / ASSETS_FILE, Asset),
            vulnerabilities=_load_csv(directory / VULNERABILITIES_FILE, Vulnerability),
            threat_intel=_load_csv(directory / THREAT_INTEL_FILE, ThreatIntel),
            business_services=_load_csv(
                directory / BUSINESS_SERVICES_FILE, BusinessService
            ),
            remediation_hints=_load_csv(directory / REMEDIATION_FILE, RemediationHint),
            threat_report=report_path.read_text(encoding="utf-8"),
        )
        logger.info(
            "data pack loaded",
            assets=len(pack.assets),
            vulnerabilities=len(pack.vulnerabilities),
            threat_intel=len(pack.threat_intel),
            business_services=len(pack.business_services),
        )
        return pack

    @property
    def assets_by_id(self) -> dict[str, Asset]:
        """Assets indexed by identifier."""
        return {asset.asset_id: asset for asset in self.assets}

    @property
    def services_by_name(self) -> dict[str, BusinessService]:
        """Business services indexed by name."""
        return {service.business_service: service for service in self.business_services}

    @property
    def intel_by_identifier(self) -> dict[str, tuple[ThreatIntel, ...]]:
        """Threat intelligence grouped by the identifier it references.

        A single identifier can be referenced by several campaigns, so the
        mapping holds every match rather than the first one found.
        """
        grouped: dict[str, list[ThreatIntel]] = {}
        for record in self.threat_intel:
            grouped.setdefault(record.matched_cve_or_control, []).append(record)
        return {key: tuple(value) for key, value in grouped.items()}

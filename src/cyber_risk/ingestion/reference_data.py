"""Fetching and parsing the public reference corpora.

Two public sources are used, and both are pinned to a local snapshot rather
than fetched at request time:

CISA Known Exploited Vulnerabilities catalogue
    Confirms which published CVE identifiers are exploited in the wild and
    which are associated with ransomware campaigns.

NIST SP 800-53 Rev. 5 control catalogue
    The source of remediation guidance. Guidance is quoted from the retrieved
    control text, so it is traceable to a named control rather than recalled
    from a model's training data.

Snapshots are taken at build time and recorded with the date and a content
digest. That makes a run reproducible, keeps the system working when an
upstream source is unreachable, and means the deployed application never
depends on a third party being available while somebody is reading the report.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from cyber_risk.core.exceptions import ReferenceDataError
from cyber_risk.core.http import create_client
from cyber_risk.core.logging import get_logger
from cyber_risk.models.risk import KevEntry

logger = get_logger(__name__)

KEV_SNAPSHOT = "kev_catalogue.json"
NIST_SNAPSHOT = "nist_sp800_53_controls.json"
MANIFEST = "manifest.json"

#: Controls the advisory scenario most directly depends on. Recorded so a
#: snapshot missing any of them fails verification rather than silently
#: degrading retrieval quality.
EXPECTED_CONTROLS = ("SI-2", "RA-5", "IR-4", "AC-2", "SA-22")

_TRUE = frozenset({"known", "yes", "true"})


class ControlDocument(BaseModel):
    """One retrievable control from the security control catalogue."""

    model_config = ConfigDict(frozen=True)

    control_id: str
    title: str
    family: str = ""
    statement: str = ""
    discussion: str = ""

    @property
    def text(self) -> str:
        """The full text used for embedding and for quotation."""
        parts = [f"{self.control_id} {self.title}"]
        if self.statement:
            parts.append(self.statement)
        if self.discussion:
            parts.append(self.discussion)
        return "\n\n".join(parts)


class SnapshotManifest(BaseModel):
    """Provenance for a set of reference snapshots."""

    model_config = ConfigDict(frozen=True)

    retrieved_at: str
    kev_source: str
    kev_digest: str
    kev_entries: int
    nist_source: str
    nist_digest: str
    nist_controls: int


def _digest(payload: bytes) -> str:
    """Return a short content digest for provenance."""
    return hashlib.sha256(payload).hexdigest()[:16]


def _as_bool(value: str) -> bool:
    """Interpret the catalogue's ransomware-use column."""
    return value.strip().lower() in _TRUE


def parse_kev(payload: bytes) -> tuple[KevEntry, ...]:
    """Parse the exploited vulnerability catalogue from its published CSV."""
    text = payload.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None or "cveID" not in reader.fieldnames:
        raise ReferenceDataError(
            "The exploited vulnerability catalogue could not be read.",
            detail="expected a cveID column in the published catalogue",
        )

    entries = tuple(
        KevEntry(
            cve_id=row["cveID"].strip(),
            vendor_project=row.get("vendorProject", "").strip(),
            product=row.get("product", "").strip(),
            vulnerability_name=row.get("vulnerabilityName", "").strip(),
            date_added=row.get("dateAdded", "").strip(),
            short_description=row.get("shortDescription", "").strip(),
            required_action=row.get("requiredAction", "").strip(),
            due_date=row.get("dueDate", "").strip(),
            known_ransomware_campaign_use=_as_bool(
                row.get("knownRansomwareCampaignUse", "")
            ),
        )
        for row in reader
        if row.get("cveID", "").strip()
    )
    if not entries:
        raise ReferenceDataError(
            "The exploited vulnerability catalogue was empty.",
            detail="the published catalogue contained no usable rows",
        )
    return entries


def _collect_prose(parts: list[dict[str, Any]] | None, wanted: str) -> str:
    """Gather prose from a control's nested parts by role.

    Control statements are a nested structure of labelled items; flattening
    them preserves the readable text without inventing an ordering.
    """
    if not parts:
        return ""

    collected: list[str] = []
    for part in parts:
        if part.get("name") == wanted:
            if prose := part.get("prose"):
                collected.append(str(prose).strip())
            nested = _collect_prose(part.get("parts"), wanted)
            if nested:
                collected.append(nested)
    return "\n".join(item for item in collected if item)


def _walk_groups(groups: list[dict[str, Any]], family: str = "") -> list[ControlDocument]:
    """Walk the catalogue's group tree, collecting every control."""
    documents: list[ControlDocument] = []

    for group in groups:
        group_title = str(group.get("title", family) or family)

        for control in group.get("controls", []):
            documents.extend(_read_control(control, group_title))

        if nested := group.get("groups"):
            documents.extend(_walk_groups(nested, group_title))

    return documents


def _read_control(control: dict[str, Any], family: str) -> list[ControlDocument]:
    """Read one control and any enhancements nested beneath it."""
    parts = control.get("parts", [])
    documents = [
        ControlDocument(
            control_id=str(control.get("id", "")).upper(),
            title=str(control.get("title", "")),
            family=family,
            statement=_collect_prose(parts, "statement"),
            discussion=_collect_prose(parts, "gdn") or _collect_prose(parts, "guidance"),
        )
    ]
    for enhancement in control.get("controls", []):
        documents.extend(_read_control(enhancement, family))
    return documents


def parse_nist_catalogue(payload: bytes) -> tuple[ControlDocument, ...]:
    """Parse the security control catalogue from its published JSON."""
    try:
        document = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ReferenceDataError(
            "The security control catalogue could not be read.",
            detail=f"invalid JSON in the published catalogue: {exc.msg}",
        ) from exc

    groups = document.get("catalog", {}).get("groups")
    if not groups:
        raise ReferenceDataError(
            "The security control catalogue had an unexpected structure.",
            detail="no control groups were present in the published catalogue",
        )

    controls = tuple(c for c in _walk_groups(groups) if c.control_id and c.title)
    if not controls:
        raise ReferenceDataError(
            "The security control catalogue contained no controls.",
            detail="the published catalogue parsed but yielded no controls",
        )
    return controls


def fetch_snapshots(
    *,
    kev_url: str,
    nist_url: str,
    destination: Path,
) -> SnapshotManifest:
    """Download both corpora and write them as local snapshots.

    Args:
        kev_url: Published location of the exploited vulnerability catalogue.
        nist_url: Published location of the security control catalogue.
        destination: Directory to write the snapshots into.

    Returns:
        A manifest recording provenance for the snapshots written.

    Raises:
        ReferenceDataError: If a source is unreachable or unusable.
    """
    destination.mkdir(parents=True, exist_ok=True)

    with create_client() as client:
        kev_payload = _download(client, kev_url, "exploited vulnerability catalogue")
        nist_payload = _download(client, nist_url, "security control catalogue")

    kev_entries = parse_kev(kev_payload)
    controls = parse_nist_catalogue(nist_payload)
    _verify_expected_controls(controls)

    (destination / KEV_SNAPSHOT).write_text(
        json.dumps([e.model_dump() for e in kev_entries], indent=1),
        encoding="utf-8",
    )
    (destination / NIST_SNAPSHOT).write_text(
        json.dumps([c.model_dump() for c in controls], indent=1),
        encoding="utf-8",
    )

    manifest = SnapshotManifest(
        retrieved_at=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        kev_source=kev_url,
        kev_digest=_digest(kev_payload),
        kev_entries=len(kev_entries),
        nist_source=nist_url,
        nist_digest=_digest(nist_payload),
        nist_controls=len(controls),
    )
    (destination / MANIFEST).write_text(
        manifest.model_dump_json(indent=1), encoding="utf-8"
    )

    logger.info(
        "reference snapshots written",
        kev_entries=len(kev_entries),
        controls=len(controls),
    )
    return manifest


def _download(client: Any, url: str, description: str) -> bytes:
    """Download one reference corpus."""
    try:
        response = client.get(url)
        response.raise_for_status()
    except Exception as exc:
        raise ReferenceDataError(
            "A reference source could not be retrieved.",
            detail=f"failed to download the {description} from {url}: {exc}",
        ) from exc

    payload: bytes = response.content
    if not payload:
        raise ReferenceDataError(
            "A reference source returned no content.",
            detail=f"empty response for the {description}",
        )
    return payload


def _verify_expected_controls(controls: tuple[ControlDocument, ...]) -> None:
    """Fail if the snapshot is missing controls the scenario depends on."""
    present = {c.control_id for c in controls}
    missing = [c for c in EXPECTED_CONTROLS if c not in present]
    if missing:
        raise ReferenceDataError(
            "The security control catalogue is missing expected controls.",
            detail=f"snapshot lacks controls: {', '.join(missing)}",
        )


def load_kev_snapshot(directory: Path) -> dict[str, KevEntry]:
    """Load the exploited vulnerability catalogue snapshot, keyed by CVE."""
    path = directory / KEV_SNAPSHOT
    if not path.is_file():
        raise ReferenceDataError(
            "The exploited vulnerability catalogue snapshot is unavailable.",
            detail=f"missing snapshot: {path}",
        )
    records = json.loads(path.read_text(encoding="utf-8"))
    return {r["cve_id"]: KevEntry(**r) for r in records}


def load_control_snapshot(directory: Path) -> tuple[ControlDocument, ...]:
    """Load the security control catalogue snapshot."""
    path = directory / NIST_SNAPSHOT
    if not path.is_file():
        raise ReferenceDataError(
            "The security control catalogue snapshot is unavailable.",
            detail=f"missing snapshot: {path}",
        )
    records = json.loads(path.read_text(encoding="utf-8"))
    return tuple(ControlDocument(**r) for r in records)


def load_manifest(directory: Path) -> SnapshotManifest | None:
    """Load snapshot provenance, if a manifest is present."""
    path = directory / MANIFEST
    if not path.is_file():
        return None
    return SnapshotManifest(**json.loads(path.read_text(encoding="utf-8")))

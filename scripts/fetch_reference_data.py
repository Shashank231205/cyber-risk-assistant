#!/usr/bin/env python3
"""Download the public reference corpora and write local snapshots.

Run at image build time so the deployed application never depends on a third
party being reachable while somebody is reading a report. Snapshots are
recorded with a retrieval date and a content digest, which makes any run
traceable to exactly the reference data it used.

Usage:
    python scripts/fetch_reference_data.py
    python scripts/fetch_reference_data.py --verify
"""

from __future__ import annotations

import argparse
import sys

from cyber_risk.config.settings import get_settings
from cyber_risk.core.exceptions import ReferenceDataError
from cyber_risk.core.logging import configure_logging
from cyber_risk.ingestion.reference_data import (
    EXPECTED_CONTROLS,
    fetch_snapshots,
    load_control_snapshot,
    load_kev_snapshot,
    load_manifest,
)


def verify() -> int:
    """Check that usable snapshots are present. Returns an exit code."""
    settings = get_settings()
    directory = settings.resolve_path(settings.data_reference_dir)

    manifest = load_manifest(directory)
    if manifest is None:
        print(
            "error: no reference snapshots found. "
            "Run `python scripts/fetch_reference_data.py`.",
            file=sys.stderr,
        )
        return 1

    catalogue = load_kev_snapshot(directory)
    controls = load_control_snapshot(directory)
    available = {c.control_id for c in controls}
    missing = [c for c in EXPECTED_CONTROLS if c not in available]

    print(f"retrieved      : {manifest.retrieved_at}")
    print(f"exploited CVEs : {len(catalogue):,} (digest {manifest.kev_digest})")
    print(f"controls       : {len(controls):,} (digest {manifest.nist_digest})")

    if missing:
        print(f"error: missing expected controls: {', '.join(missing)}", file=sys.stderr)
        return 1

    print(f"expected controls present: {', '.join(EXPECTED_CONTROLS)}")
    return 0


def download() -> int:
    """Fetch both corpora and write snapshots. Returns an exit code."""
    settings = get_settings()
    destination = settings.resolve_path(settings.data_reference_dir)

    try:
        manifest = fetch_snapshots(
            kev_url=settings.kev_source_url,
            nist_url=settings.nist_source_url,
            destination=destination,
        )
    except ReferenceDataError as error:
        print(f"error: {error.message}", file=sys.stderr)
        if error.detail:
            print(f"       {error.detail}", file=sys.stderr)
        return 1

    print(f"wrote snapshots to {destination}")
    print(f"  exploited CVEs : {manifest.kev_entries:,}")
    print(f"  controls       : {manifest.nist_controls:,}")
    print(f"  retrieved      : {manifest.retrieved_at}")
    return 0


def main() -> int:
    """Entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="check existing snapshots instead of downloading",
    )
    args = parser.parse_args()

    configure_logging(level="INFO")
    return verify() if args.verify else download()


if __name__ == "__main__":
    raise SystemExit(main())

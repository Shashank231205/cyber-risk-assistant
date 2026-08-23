#!/usr/bin/env python3
"""Regenerate pinned requirement files from ``pyproject.toml``.

``pyproject.toml`` is the single source of truth for dependencies. Plain
requirement files are still needed for platforms that build from them
directly, so they are generated rather than hand-maintained: a duplicated
dependency list edited by hand drifts out of sync silently.

Pins are taken from the versions actually resolved in the current
environment, which makes container and CI builds reproducible.

Usage:
    python scripts/sync_requirements.py           # write the files
    python scripts/sync_requirements.py --check   # verify they are current
"""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 relies on the tomli backport.
    import tomli as tomllib

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
RUNTIME_FILE = PROJECT_ROOT / "requirements.txt"
DEV_FILE = PROJECT_ROOT / "requirements-dev.txt"

HEADER = (
    "# {title}\n"
    "# Generated from pyproject.toml by scripts/sync_requirements.py; "
    "do not edit by hand.\n"
)


def _split_requirement(spec: str) -> tuple[str, str, str]:
    """Split a requirement spec into distribution name, extras and marker.

    The environment marker must be preserved: dropping it would install
    conditional dependencies on interpreters that do not need them.
    """
    requirement, _, marker = spec.partition(";")
    head = requirement.split(">=")[0].split("==")[0].split("~=")[0].strip()

    extras = ""
    if "[" in head:
        head, _, remainder = head.partition("[")
        extras = f"[{remainder.rstrip(']')}]"

    return head.strip(), extras, marker.strip()


def _pin(spec: str) -> str:
    """Pin a requirement spec to the version installed in this environment."""
    name, extras, marker = _split_requirement(spec)
    try:
        resolved = version(name)
    except PackageNotFoundError:
        if marker:
            # Conditional dependency that does not apply to this interpreter;
            # emit it unpinned so it still resolves where the marker matches.
            return f"{name}{extras}; {marker}"
        print(
            f"error: {name!r} is declared in pyproject.toml but is not installed. "
            "Run `pip install -e '.[dev]'` first.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None

    pinned = f"{name}{extras}=={resolved}"
    return f"{pinned}; {marker}" if marker else pinned


def _render() -> tuple[str, str]:
    """Return the rendered contents of the runtime and dev requirement files."""
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]

    runtime = sorted(_pin(dep) for dep in project["dependencies"])
    dev = sorted(_pin(dep) for dep in project["optional-dependencies"]["dev"])

    runtime_text = HEADER.format(title="Runtime dependencies: pinned for reproducible builds.")
    runtime_text += "\n".join(runtime) + "\n"

    dev_text = HEADER.format(
        title="Development and CI dependencies: pinned for reproducible builds."
    )
    dev_text += "-r requirements.txt\n" + "\n".join(dev) + "\n"

    return runtime_text, dev_text


def main() -> int:
    """Entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the files are out of date instead of writing them",
    )
    args = parser.parse_args()

    runtime_text, dev_text = _render()
    targets = ((RUNTIME_FILE, runtime_text), (DEV_FILE, dev_text))

    if args.check:
        stale = [
            path.name
            for path, expected in targets
            if not path.exists() or path.read_text(encoding="utf-8") != expected
        ]
        if stale:
            print(
                f"error: {', '.join(stale)} out of date. "
                "Run `python scripts/sync_requirements.py`.",
                file=sys.stderr,
            )
            return 1
        print("requirement files are up to date")
        return 0

    for path, content in targets:
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

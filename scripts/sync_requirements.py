#!/usr/bin/env python3
"""Regenerate the requirement files from ``pyproject.toml``.

``pyproject.toml`` is the single source of truth for dependencies. Plain
requirement files are still needed for platforms that install from them
directly, so they are generated rather than hand-maintained: a duplicated
dependency list edited by hand drifts out of sync silently.

The generated files mirror the constraints declared in ``pyproject.toml``
rather than the versions resolved in whichever environment ran this script.
Resolved versions differ between interpreters and platforms, so writing them
here would make the file's contents depend on where it was generated, and the
``--check`` mode could then never pass on more than one environment at a time.

These files are therefore a convenience mirror, not a lock file. Reproducible
installs down to the transitive tree need a resolver that records hashes; what
is guaranteed here is only that the two dependency lists agree.

Usage:
    python scripts/sync_requirements.py           # write the files
    python scripts/sync_requirements.py --check   # verify they are current
"""

from __future__ import annotations

import argparse
import sys
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


def _render() -> tuple[str, str]:
    """Return the contents of the runtime and development requirement files."""
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]

    runtime = sorted(project["dependencies"], key=str.lower)
    development = sorted(project["optional-dependencies"]["dev"], key=str.lower)

    runtime_text = HEADER.format(title="Runtime dependencies.")
    runtime_text += "\n".join(runtime) + "\n"

    dev_text = HEADER.format(title="Development and continuous integration dependencies.")
    dev_text += "-r requirements.txt\n" + "\n".join(development) + "\n"

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

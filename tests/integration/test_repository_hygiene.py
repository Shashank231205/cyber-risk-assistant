"""Guards on what the repository does and does not contain.

Two failure modes motivate these tests, and neither announces itself:

An ignore rule that is too broad silently drops source.
    A rule intended for downloaded model binaries also matched the domain
    package, so an entire layer would have been absent from a fresh clone
    while every local check still passed.

An ignore rule that is too narrow leaks a credential.
    Secrets are unrecoverable once published, so the protective rules are
    asserted rather than assumed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from cyber_risk.config.settings import PROJECT_ROOT

SOURCE_DIRECTORIES = ("src", "tests", "scripts")

MUST_BE_IGNORED = (
    ".env",
    ".env.local",
    ".env.production",
    "secrets/service-account.json",
    "private.pem",
    "api.key",
    "logs/application.log",
    "coverage.xml",
    ".venv/pyvenv.cfg",
    "data/outputs/report.md",
    "data/processed/index.faiss",
    "AI_Cyber_Risk_Assignment.docx",
)

MUST_BE_TRACKED = (
    ".env.example",
    ".gitignore",
    "pyproject.toml",
    "requirements.txt",
)


def is_ignored(relative_path: str) -> bool:
    """Whether git would ignore ``relative_path``."""
    result = subprocess.run(  # noqa: S603
        ["git", "check-ignore", "-q", relative_path],  # noqa: S607
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def git_available() -> bool:
    """Whether these tests can run in the current environment."""
    return (PROJECT_ROOT / ".git").exists()


pytestmark = pytest.mark.skipif(
    not git_available(), reason="not a git working tree"
)


@pytest.mark.integration
class TestSourceIsNotExcluded:
    """No source file may be excluded from the repository."""

    @pytest.mark.parametrize("directory", SOURCE_DIRECTORIES)
    def test_no_python_source_is_ignored(self, directory: str) -> None:
        root = PROJECT_ROOT / directory
        if not root.is_dir():
            pytest.skip(f"{directory} is absent")

        excluded = [
            str(path.relative_to(PROJECT_ROOT)).replace("\\", "/")
            for path in root.rglob("*.py")
            if "__pycache__" not in path.parts
            and is_ignored(str(path.relative_to(PROJECT_ROOT)).replace("\\", "/"))
        ]
        assert not excluded, f"ignore rules exclude source files: {excluded}"

    def test_the_domain_package_is_tracked(self) -> None:
        """Regression: a rule for model binaries also matched this package."""
        assert not is_ignored("src/cyber_risk/models/domain.py")

    @pytest.mark.parametrize("path", MUST_BE_TRACKED)
    def test_required_files_are_tracked(self, path: str) -> None:
        assert (PROJECT_ROOT / path).is_file(), f"{path} is missing"
        assert not is_ignored(path)


@pytest.mark.integration
class TestSecretsAreExcluded:
    @pytest.mark.parametrize("path", MUST_BE_IGNORED)
    def test_sensitive_paths_are_ignored(self, path: str) -> None:
        assert is_ignored(path), f"{path} would be committed"

    def test_no_env_file_is_tracked(self) -> None:
        """A committed .env is unrecoverable once pushed."""
        tracked = subprocess.run(
            ["git", "ls-files"],  # noqa: S607
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()

        offenders = [
            name
            for name in tracked
            if Path(name).name.startswith(".env") and Path(name).name != ".env.example"
        ]
        assert not offenders, f"environment files are tracked: {offenders}"

    def test_the_assignment_brief_is_not_tracked(self) -> None:
        """Source material for the exercise stays out of the public repository."""
        tracked = subprocess.run(
            ["git", "ls-files"],  # noqa: S607
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        assert not [n for n in tracked if n.lower().endswith((".docx", ".doc"))]

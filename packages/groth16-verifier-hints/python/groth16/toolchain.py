"""Discover tools without treating recorded local paths as requirements.

Version output is a compatibility claim, not binary provenance or proof evidence.
Only the exact pinned SHA256 is reported as matching the hosted release binary.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Mapping

PROJECT_ROOT = Path(__file__).resolve().parents[4]
NARGO_VERSION = "1.0.0-rc.3"


class ToolchainError(RuntimeError):
    """A requested tool is absent, cannot run, or has incompatible metadata."""


@dataclass(frozen=True)
class ResolvedTool:
    executable: Path
    selection: str
    version: str
    sha256: str
    pinned_binary_match: bool
    commit: str | None = None

    def to_dict(self) -> dict:
        return {**asdict(self), "executable": str(self.executable)}


def load_pins(project_root: Path | str | None = None) -> dict:
    root = Path(project_root) if project_root is not None else PROJECT_ROOT
    try:
        return json.loads((root / "toolchain-v6.json").read_text())
    except (OSError, ValueError) as exc:
        raise ToolchainError(
            f"Cannot read pinned toolchain metadata at {root}: {exc}"
        ) from exc


def backend_for_mode(pins: dict, mode: str) -> tuple[str, dict]:
    """Return the only backend a profile mode may declare, with its pins."""
    matches = [
        (name, spec)
        for name, spec in pins["backends"].items()
        if mode in spec.get("modes", [])
    ]
    if len(matches) != 1:
        raise ToolchainError(f"No unique backend is pinned for mode {mode!r}")
    return matches[0]


def _discover(
    explicit: str | Path | None,
    variable: str,
    command: str,
    environ: Mapping[str, str],
    historical: str | None = None,
) -> tuple[Path, str]:
    if explicit is not None:
        candidate, selection = str(explicit), "argument"
    elif environ.get(variable):
        candidate, selection = environ[variable], variable
    else:
        candidate = shutil.which(command, path=environ.get("PATH", os.defpath))
        selection = "PATH"
        if candidate is None and historical:
            candidate, selection = historical, "historical-local-fallback"
        if candidate is None:
            raise ToolchainError(
                f"Cannot find {command}; pass --{command}, set {variable}, or add it to PATH"
            )
    # A bare explicit name can also use PATH; strings are never evaluated as shell commands.
    path = shutil.which(candidate, path=environ.get("PATH", os.defpath))
    if path is None:
        raise ToolchainError(
            f"Selected {command} ({selection}) is not executable: {candidate}"
        )
    return Path(path).resolve(), selection


def _version(executable: Path, environ: Mapping[str, str]) -> str:
    try:
        result = subprocess.run(
            [str(executable), "--version"],
            env=dict(environ),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolchainError(f"Cannot run {executable} --version: {exc}") from exc
    if result.returncode:
        raise ToolchainError(
            f"{executable} --version failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_nargo(
    nargo: str | Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    project_root: Path | str | None = None,
    allow_historical: bool = False,
) -> ResolvedTool:
    """Resolve CLI > G16_NARGO > PATH, then validate exact pinned v6 Noir metadata.

    Historical local paths are used only with explicit opt-in AND no normal tool.
    An invalid explicit/PATH selection fails; it never silently selects another compiler.
    Callers execute ``[str(result.executable), ...]`` without a shell.
    """
    env = dict(os.environ if environ is None else environ)
    pins = load_pins(project_root)
    fallback = pins["noir"].get("binary")
    if fallback and not Path(fallback).is_absolute():
        fallback = str(PROJECT_ROOT.parents[2] / fallback)
    executable, selection = _discover(
        nargo,
        "G16_NARGO",
        "nargo",
        env,
        fallback if allow_historical else None,
    )
    version = _version(executable, env)
    # The Aztec v6 release compiler, then any recorded alternative release.
    releases = [
        (NARGO_VERSION, pins["noir"]["gitlink"], pins["noir"].get("sha256")),
        *(
            (entry["version"], entry["gitlink"], entry.get("sha256"))
            for entry in pins.get("noirAlternatives", [])
        ),
    ]
    nargo_line = re.search(r"^nargo version = ([^\s]+)$", version, re.MULTILINE)
    noirc_line = re.search(r"^noirc version = ([^\s]+)$", version, re.MULTILINE)
    git_line = re.search(
        r"\(git version hash: ([0-9a-f]{40}), is dirty: (true|false)\)", version
    )
    matched = [
        (release, commit, pinned)
        for release, commit, pinned in releases
        if nargo_line is not None
        and nargo_line[1] == release
        and noirc_line is not None
        and noirc_line[1] == f"{release}+{commit}"
        and git_line is not None
        and git_line[1] == commit
        and git_line[2] == "false"
    ]
    if not matched:
        expected = " or ".join(f"{release}+{commit}" for release, commit, _ in releases)
        raise ToolchainError(
            f"Incompatible nargo selected from {selection}: expected clean Noir "
            f"{expected}; reported {version!r}"
        )
    _, expected_commit, pinned = matched[0]
    sha256 = _sha256(executable)
    return ResolvedTool(
        executable,
        selection,
        version,
        sha256,
        sha256 == pinned,
        expected_commit,
    )


def resolve_bb(
    bb: str | Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    project_root: Path | str | None = None,
) -> ResolvedTool:
    """Locate optional BB and report its version/hash; this does not certify backend capability."""
    env = dict(os.environ if environ is None else environ)
    pins = load_pins(project_root)
    executable, selection = _discover(bb, "G16_BB", "bb", env)
    version = _version(executable, env)
    sha256 = _sha256(executable)
    return ResolvedTool(
        executable,
        selection,
        version,
        sha256,
        any(sha256 == spec.get("binarySha256") for spec in pins["backends"].values()),
    )


def inspect_source(path: Path | str, expected_commit: str) -> dict:
    """Report the exact checkout identity and tracked modifications, without changing it."""
    directory = Path(path).resolve()
    if not directory.is_dir():
        return {
            "path": str(directory),
            "status": "missing",
            "expected_commit": expected_commit,
        }
    try:

        def git(*args: str) -> str:
            return subprocess.check_output(
                ["git", "-C", str(directory), *args],
                text=True,
                stderr=subprocess.PIPE,
                timeout=15,
            ).strip()

        if Path(git("rev-parse", "--show-toplevel")).resolve() != directory:
            raise ToolchainError("path is not a checkout root")
        commit = git("rev-parse", "HEAD")
        changes = git("status", "--porcelain", "--untracked-files=no")
    except (OSError, subprocess.SubprocessError, ToolchainError) as exc:
        return {
            "path": str(directory),
            "status": "unavailable",
            "error": str(exc),
            "expected_commit": expected_commit,
        }
    return {
        "path": str(directory),
        "status": "matched" if commit == expected_commit else "mismatch",
        "commit": commit,
        "expected_commit": expected_commit,
        "tracked_changes": changes.splitlines(),
        "claim": "Checkout HEAD only; local modifications, binaries and installed Aztec/PXE packages are not attested.",
    }

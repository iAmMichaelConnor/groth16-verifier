#!/usr/bin/env python3
"""Read-only pinned v6 toolchain checks. Does not compile, install, prove or launch services."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/groth16-verifier-hints/python"))
from groth16.toolchain import (
    ToolchainError,
    inspect_source,
    load_pins,
    resolve_bb,
    resolve_nargo,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--nargo", help="Compiler executable; overrides G16_NARGO and PATH"
    )
    parser.add_argument(
        "--bb", help="Optional BB executable; overrides G16_BB and PATH"
    )
    parser.add_argument(
        "--aztec-source",
        help="Pinned aztec-packages checkout; overrides G16_AZTEC_SOURCE",
    )
    parser.add_argument(
        "--labs-source", help="Pinned aztec-node checkout; overrides G16_LABS_SOURCE"
    )
    parser.add_argument(
        "--require-aztec",
        action="store_true",
        help="Fail unless both source checkout HEADs match",
    )
    parser.add_argument(
        "--require-bb",
        action="store_true",
        help="Fail unless a BB executable can report its version; not capability attestation",
    )
    parser.add_argument(
        "--allow-historical-local-nargo",
        action="store_true",
        help="Opt into recorded local compiler path only when normal discovery finds nothing",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit the complete machine-readable report"
    )
    args = parser.parse_args(argv)
    pins = load_pins()
    report = {
        "target": "pinned-aztec-v6",
        "checks": {},
        "errors": [],
        "scope": "Discovery and metadata only; no circuit, proof or transaction verification.",
    }
    try:
        compiler = resolve_nargo(
            args.nargo, allow_historical=args.allow_historical_local_nargo
        )
        report["checks"]["nargo"] = {
            "status": "compatible",
            **compiler.to_dict(),
            "claim": "Version/commit compatibility is self-reported; pinned_binary_match separately records exact historical bytes.",
        }
    except ToolchainError as exc:
        report["checks"]["nargo"] = {"status": "failed", "error": str(exc)}
        report["errors"].append(str(exc))
    for name, path, commit in [
        (
            "aztec_source",
            args.aztec_source
            or os.environ.get("G16_AZTEC_SOURCE"),
            pins["aztecPackages"]["commit"],
        ),
        (
            "labs_source",
            args.labs_source
            or os.environ.get("G16_LABS_SOURCE"),
            pins["labs"]["gitlink"],
        ),
    ]:
        check = (
            inspect_source(path, commit)
            if path
            else {"path": None, "status": "missing", "expected_commit": commit}
        )
        report["checks"][name] = check
        explicitly_selected = (
            (args.aztec_source or os.environ.get("G16_AZTEC_SOURCE"))
            if name == "aztec_source"
            else (args.labs_source or os.environ.get("G16_LABS_SOURCE"))
        )
        if check["status"] != "matched" and (args.require_aztec or explicitly_selected):
            report["errors"].append(f"{name}: {check['status']}")
    try:
        backend = resolve_bb(args.bb)
        report["checks"]["bb"] = {
            "status": "available",
            **backend.to_dict(),
            "compatibility": "unverified",
            "claim": "A version string or matching recorded binary is not proof of the application's backend configuration.",
        }
    except ToolchainError as exc:
        report["checks"]["bb"] = {"status": "unavailable", "error": str(exc)}
        if args.require_bb or args.bb or os.environ.get("G16_BB"):
            report["errors"].append(str(exc))
    report["ok"] = not report["errors"]
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Pinned Aztec v6 metadata check: {'PASS' if report['ok'] else 'FAIL'}")
        for name, check in report["checks"].items():
            print(f"  {name}: {check['status']}")
            if "executable" in check:
                print(
                    f"    {check['executable']} ({check['selection']}); recorded binary match: {check['pinned_binary_match']}"
                )
            if check.get("tracked_changes"):
                print(
                    f"    {len(check['tracked_changes'])} tracked local changes; not attested"
                )
        for error in report["errors"]:
            print(f"  error: {error}")
        print(report["scope"])
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

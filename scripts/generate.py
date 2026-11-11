#!/usr/bin/env python3
"""Run every generator; with --check, write nothing and fail on drift.

- scripts/generate_sp1_key.py: the pinned SP1 v5 and v6 keys, the SP1 v6
  verification-key root and the SP1 API test keys, from fixtures/sp1-v5,
  fixtures/sp1-v6 and fixtures/multiplier;
- scripts/generate_test_keys.py: the fixed-key provider of the multiplier
  proof-vector package, from fixtures/multiplier;
- scripts/generate_test_vectors.py: the multiplier and SP1 v6 proof vectors,
  from fixtures/multiplier and fixtures/sp1-v6, through the hint SDK (needs
  Node.js and `npm ci` in packages/groth16-verifier-hints).

Generated Noir is formatted with $NARGO, else nargo on PATH.
"""

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GENERATORS = [
    ["scripts/generate_sp1_key.py"],
    ["scripts/generate_test_keys.py"],
    ["scripts/generate_test_vectors.py"],
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="write nothing; fail if a generated file is stale")
    args = parser.parse_args()
    failed = []
    for generator, *options in GENERATORS:
        command = [sys.executable, generator, *options] + (["--check"] if args.check else [])
        print(f"$ {' '.join(command[1:])}", flush=True)
        if subprocess.run(command, cwd=ROOT).returncode != 0:
            failed.append(generator)
    if failed:
        print(f"failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

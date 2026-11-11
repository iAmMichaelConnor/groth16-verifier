#!/usr/bin/env python3
"""Rebuild the optional asset without replacing the packaged measured bytes."""

from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--output-dir",
    type=Path,
    help="Fresh build/evidence directory; defaults to a temporary directory",
)
parser.add_argument(
    "--allow-network",
    action="store_true",
    help="Allow Cargo dependency retrieval if the cache is incomplete",
)
args = parser.parse_args()
out = (
    args.output_dir.resolve()
    if args.output_dir
    else Path(tempfile.mkdtemp(prefix="groth16-wasm-rebuild-"))
)
out.mkdir(parents=True, exist_ok=True)
provenance = json.loads((root / "provenance.json").read_text())
for name, expected in provenance["sourceHashes"].items():
    actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"Source differs from packaged provenance: {name}")
command = [
    "cargo",
    "+1.89.0",
    "build",
    "--locked",
    "--release",
    "--lib",
    "--target",
    "wasm32-unknown-unknown",
    "--manifest-path",
    str(root / "source/Cargo.toml"),
    "--target-dir",
    str(out / "target"),
]
if not args.allow_network:
    command.append("--offline")
environment = {**os.environ, "CARGO_BUILD_JOBS": "2"}
result = subprocess.run(command, env=environment, text=True, capture_output=True)
(out / "build.stdout").write_text(result.stdout)
(out / "build.stderr").write_text(result.stderr)
record = {"command": command, "exitCode": result.returncode, "jobs": 2}
if result.returncode == 0:
    built = (
        out
        / "target/wasm32-unknown-unknown/release/groth16_hint_runtime_tail_kernel.wasm"
    )
    record.update(
        {
            "sha256": hashlib.sha256(built.read_bytes()).hexdigest(),
            "expectedSha256": provenance["originModuleSha256"],
            "bytes": built.stat().st_size,
        }
    )
    record["byteIdentical"] = record["sha256"] == record["expectedSha256"]
(out / "rebuild.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps({"output": str(out), **record}, indent=2))
raise SystemExit(0 if record.get("byteIdentical") else 1)

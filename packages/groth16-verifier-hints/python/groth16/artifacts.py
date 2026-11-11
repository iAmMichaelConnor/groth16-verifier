"""Record byte identities after compilation, separately from source profiles."""

from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact_identity(path: Path, role: str, vk: Path | None = None) -> dict:
    data = Path(path).read_bytes()
    artifact = json.loads(data)
    if role == "producer":
        bytecode = artifact["bytecode"]
    elif role == "private-consumer":
        functions = [
            f
            for f in artifact["functions"]
            if f["name"].removeprefix("__aztec_nr_internals__") == "verify"
        ]
        if len(functions) != 1:
            raise ValueError("Expected exactly one generated verify function")
        bytecode = functions[0]["bytecode"]
    else:
        raise ValueError("Unknown artifact role")
    decoded = base64.b64decode(bytecode, validate=True)
    if not decoded:
        raise ValueError("Empty ACIR bytecode")
    return dict(
        role=role,
        artifactSha256=sha(data),
        bytecodeSha256=sha(decoded),
        verificationKeySha256=sha(Path(vk).read_bytes()) if vk else None,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--consumer", type=Path, required=True)
    parser.add_argument("--consumer-vk", type=Path)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--producer-vk", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    # Reuse the supported SDK's strict profile validator and canonical hashing.
    # Profile validation is delegated below to a narrow Node command, using the
    # same implementation as the consumer API, never a second JSON hash convention.
    import subprocess

    root = Path(__file__).resolve().parents[4]
    result = subprocess.run(
        [
            args.node,
            "--input-type=module",
            "-e",
            "import fs from 'node:fs'; import {profileHash,parseProfile} from './packages/groth16-verifier-hints/dist/current.js'; const p=parseProfile(JSON.parse(fs.readFileSync(process.argv[1])));console.log(JSON.stringify({hash:profileHash(p),mode:p.mode}));",
            str(args.profile.resolve()),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    profile = json.loads(result.stdout)
    if (profile["mode"] == "offchain") != bool(args.producer):
        raise ValueError("Only offchain profiles require a producer artifact")
    if args.producer_vk and not args.producer:
        raise ValueError("Producer key needs a producer artifact")
    entries = [artifact_identity(args.consumer, "private-consumer", args.consumer_vk)]
    if args.producer:
        entries.append(artifact_identity(args.producer, "producer", args.producer_vk))
    record = dict(
        schema="groth16-verifier-artifacts-v1",
        profileSha256=profile["hash"],
        artifacts=entries,
    )
    with args.out.open("x") as f:
        f.write(json.dumps(record, indent=2) + "\n")
    print(args.out)


if __name__ == "__main__":
    main()

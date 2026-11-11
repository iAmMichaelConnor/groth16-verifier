"""Generate application-local Groth16 key material and a current consumer profile.

Run from the repository root: python3 -m groth16.generate --help.
Python uses only its standard library; Node reuses the maintained SDK identities.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import warnings
from . import _offsets, _preprocess
from .toolchain import backend_for_mode, load_pins

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


class GenerationError(ValueError):
    """Invalid key/configuration or unavailable generation dependency."""


class GenerationWarning(UserWarning):
    """Accepted key with a documented completeness limitation."""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise GenerationError(f"Duplicate JSON property: {name}")
        result[name] = value
    return result


def _identity(request: dict, node: str) -> dict:
    executable = shutil.which(node)
    if executable is None:
        raise GenerationError("Node is required; pass --node or put node on PATH")
    result = subprocess.run(
        [executable, str(HERE / "identities.mjs")],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode:
        raise GenerationError(
            result.stderr.strip()
            or "SDK identity helper failed; build packages/groth16-verifier-hints"
        )
    return json.loads(result.stdout)


def _provider(key: dict, output: Path, name: str, alias: str) -> dict:
    key_file = output.parent / "_normalized_key.json"
    key_file.write_text(_json(key))
    try:
        record = _preprocess.generate(key_file, name, output)
    except (KeyError, TypeError, ValueError) as error:
        raise GenerationError(
            f"Invalid key or preprocessing invariant: {error}"
        ) from error
    source = output.read_text()
    correction = (
        None
        if record["biasCorrection"] is None
        else tuple(map(int, record["biasCorrection"]))
    )
    try:
        extra, pairs = _offsets.methods(correction, record["nPublic"])
    except ValueError as error:
        raise GenerationError(f"Invalid offset preprocessing: {error}") from error
    marker = " fn gamma_lines()->LineScheduleRaw"
    if source.count(marker) != 1:
        raise GenerationError("Unexpected provider emission format")
    source = source.replace(marker, extra + marker)
    source = re.sub(r"^use [^;]+;\n", "", source, flags=re.M)
    imports = (
        f"use {alias}::provider::{{VerifyingKey, FixedKey, Half, Fp, Fp2, Fp6, Fp12, "
        "G1Affine, G2Affine, LineEvaluation, LineScheduleRaw, BigNum};\n"
    )
    output.write_text(imports + source)
    output.with_suffix(".json").unlink()
    key_file.unlink()
    for field in ["keyFile", "keySha256", "sourceSha256"]:
        record.pop(field, None)
    record.update(
        {
            "candidateCount": _offsets.candidate_count(record["nPublic"]),
            "protocol": _offsets.PROTOCOL,
            "offsetPairsSha256": hashlib.sha256(
                json.dumps(pairs, separators=(",", ":")).encode()
            ).hexdigest(),
            "N0Policy": "Direct trusted IC0; one unused table sentinel",
            "checks": record["checks"]
            + [
                "finite distinct origins",
                "J + 2^60 O = K",
                "five-field injective encoding",
                "2*M*(S+1)+1 candidates",
            ],
        }
    )
    return record


def generate(
    vk_path: Path | str,
    out_dir: Path | str,
    *,
    name: str = "application",
    provider_name: str = "ApplicationKey",
    dependency_alias: str = "groth16",
    mode: str = "private",
    key_policy: str = "fixed",
    node: str = "node",
) -> dict:
    """Write a new directory atomically. Existing destinations are never replaced.

    Returns the deterministic generation record. Profiles identify configuration;
    compiled artifact and verification-key identities belong in a later record.
    """
    vk_path, destination = Path(vk_path), Path(out_dir)
    if destination.exists() or destination.is_symlink():
        raise GenerationError(f"Refuse to overwrite destination: {destination}")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name):
        raise GenerationError("Name must match [a-z][a-z0-9_]{0,63}")
    if not re.fullmatch(r"[A-Z][A-Za-z0-9_]*", provider_name):
        raise GenerationError("Provider name must start with an uppercase letter")
    if not re.fullmatch(r"[a-z][a-z0-9_]*", dependency_alias) or dependency_alias in {
        "crate",
        "dep",
        "self",
        "super",
    }:
        raise GenerationError("Dependency alias must be a lowercase Noir identifier")
    if mode not in {"private", "offchain"} or key_policy not in {
        "fixed",
        "runtime",
    }:
        raise GenerationError("Unsupported mode or key policy")
    try:
        supplied = json.loads(vk_path.read_text(), object_pairs_hook=_unique)
    except (OSError, ValueError) as error:
        raise GenerationError(f"Cannot read verification key: {error}") from error
    # SDK checks wire format, N<=256, curve, subgroup and key relations
    # (delta != +-gamma, delta != generator, some finite IC) before any output exists.
    checked = _identity({"operation": "key", "verificationKey": supplied}, node)
    key = checked["verificationKey"]
    limitations = []
    if [int(v) for v in key["IC"][0]] == [0, 0]:
        # Finite L is load-bearing for soundness, so the verifier keeps it.
        limitations.append(
            "IC0 is infinity: inputs with L = O (for example all zero) cannot be proved"
        )
    for text in limitations:
        warnings.warn(text, GenerationWarning, stacklevel=2)
    pins = load_pins()
    backend_name, backend_pins = backend_for_mode(pins, mode)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".groth16-generation-", dir=destination.parent
    ) as temp:
        stage = Path(temp) / "output"
        stage.mkdir()
        if key_policy == "fixed":
            preprocessing = _provider(
                key, stage / "application_key.nr", provider_name, dependency_alias
            )
            descriptor = {
                "schema": "groth16-fixed-key-v1",
                "verificationKey": key,
                "tPreimage": preprocessing.pop("tPreimage"),
            }
            identity = _identity({"operation": "fixed", **descriptor}, node)
            configuration_hash = identity["configurationHash"]
            (stage / "preprocessing.json").write_text(_json(preprocessing))
        else:
            descriptor = key
            configuration_hash = None
        profile = {
            "schema": "groth16-verifier-profile-v2",
            "name": name,
            "mode": mode,
            "keyPolicy": key_policy,
            "inputCount": key["nPublic"],
            "certificate": f"groth16-{key_policy}-global68-v1",
            "keyHash": checked["keyHash"],
            "configurationHash": configuration_hash,
            "statementSchema": "groth16-verifier-statement-v1",
            "toolchain": {
                "aztecCommit": backend_pins["aztecCommit"],
                "noirCommit": pins["noir"]["gitlink"],
                "backend": backend_name,
            },
            "domain": "finite-pairing-operands-v1",
        }
        identity = _identity({"operation": "profile", "profile": profile}, node)
        (stage / "key.json").write_text(_json(descriptor))
        (stage / "key.ts").write_text(
            "// Generated application key material; authorize through the matching profile.\n"
            "export const key = " + json.dumps(descriptor, indent=2) + " as const;\n"
            "export default key;\n"
        )
        (stage / "profile.json").write_text(_json(identity["profile"]))
        source_files = [
            HERE / f
            for f in [
                "generate.py",
                "_preprocess.py",
                "_offsets.py",
                "_pairing.py",
                "identities.mjs",
                "data/preprocessing.json",
            ]
        ]
        sdk = ROOT / "packages/groth16-verifier-hints/dist"
        record = {
            "schema": "groth16-generation-v1",
            "sourceKeySha256": digest(vk_path),
            "normalizedKeySha256": hashlib.sha256(
                json.dumps(key, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "profileSha256": identity["profileSha256"],
            "providerName": provider_name if key_policy == "fixed" else None,
            "dependencyAlias": dependency_alias if key_policy == "fixed" else None,
            "inputCount": key["nPublic"],
            "keyPolicy": key_policy,
            "generatorSources": {
                str(p.relative_to(HERE)): digest(p) for p in source_files
            },
            "sdkSources": {
                str(p.relative_to(sdk)): digest(p) for p in sorted(sdk.rglob("*.js"))
            },
            "files": {
                p.name: digest(p) for p in sorted(stage.iterdir()) if p.is_file()
            },
            "scope": "Trusted configuration/source generation only; no compilation, setup, proof or artifact key",
        }
        if limitations:
            record["limitations"] = limitations
        (stage / "generation.json").write_text(_json(record))
        # The final existence check also protects a destination created during preprocessing.
        if destination.exists() or destination.is_symlink():
            raise GenerationError(
                f"Destination appeared during generation: {destination}"
            )
        os.rename(stage, destination)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", default="application")
    parser.add_argument("--provider-name", default="ApplicationKey")
    parser.add_argument("--dependency-alias", default="groth16")
    parser.add_argument(
        "--mode", choices=["private", "offchain"], default="private"
    )
    parser.add_argument("--key-policy", choices=["fixed", "runtime"], default="fixed")
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    try:
        result = generate(
            args.vk,
            args.out,
            name=args.name,
            provider_name=args.provider_name,
            dependency_alias=args.dependency_alias,
            mode=args.mode,
            key_policy=args.key_policy,
            node=args.node,
        )
    except (GenerationError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Groth16 generation: {error}\n")
    print(
        json.dumps(
            {
                "output": str(args.out),
                "inputCount": result["inputCount"],
                "profileSha256": result["profileSha256"],
            }
        )
    )


if __name__ == "__main__":
    main()

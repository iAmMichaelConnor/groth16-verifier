"""Generate an application-local single-private-function verifier.

The templates compose existing arithmetic; they do not introduce an alternative
Groth16 relation. Key authorization is a compiled hash. Application-specific
input semantics and replay prevention belong in the caller's state transition.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[4]
# Noir package directory of each key policy's verifier.
VERIFIER_PACKAGES = {"fixed": "groth16", "runtime": "runtime_verifier"}
FIXED_BASE = "0x47524f544831365f5052454649585f5441494c5f5631"
RUNTIME_BASE = "0x4731365f52554e54494d455f5441494c00"


def private_source(profile: dict) -> str:
    n = profile["inputCount"]
    fixed = profile["keyPolicy"] == "fixed"
    if profile["mode"] != "private":
        raise ValueError("Private scaffold requires private mode")
    q = 76 if fixed else 94
    source = """use aztec::macros::aztec as aztec_contract;
use aztec::protocol::{address::AztecAddress, traits::Deserialize};
"""
    if fixed:
        source += "mod application_key;\n"
    source += f"""pub global N: u32 = {n};
pub global APPROVED_KEY: Field = {profile["keyHash"]};
pub global CAPSULE_BASE: Field = {FIXED_BASE if fixed else RUNTIME_BASE};
pub type PairingHints = ([[u128;3];36], [[[u128;3];12];66], [[u128;3];{q}], [[u128;3];9]);
// Capsules are untrusted witnesses. The unconditional complete verifier below
// constrains all arithmetic.
unconstrained fn load_hint<T>(address: AztecAddress, slot: Field) -> T where T: Deserialize {{
    aztec::oracle::capsules::load(address, slot, AztecAddress::zero()).expect(f"Missing Groth16 capsule")
}}
"""
    if not fixed:
        source += """pub type RawKey = [[u128;3];16+2*N];
fn decode_key(raw: RawKey) -> groth16::RawVerificationKey<N> {
    let mut ic = [[[0;3];2];N+1];
    for i in 0..N+1 { ic[i] = [raw[14+2*i], raw[15+2*i]]; }
    groth16::RawVerificationKey {
        alpha: [raw[0],raw[1]], beta: [raw[2],raw[3],raw[4],raw[5]],
        gamma: [raw[6],raw[7],raw[8],raw[9]], delta: [raw[10],raw[11],raw[12],raw[13]], ic,
    }
}
"""
    source += """#[aztec_contract]
pub contract Groth16Verifier {
    use aztec::macros::functions::external;
    use aztec::protocol::traits::ToField;
    use crate::{N, APPROVED_KEY, CAPSULE_BASE, PairingHints, load_hint};
"""
    source += (
        "    use crate::application_key::ApplicationKey;\n"
        if fixed
        else "    use crate::{RawKey, decode_key};\n"
    )
    source += """    // This returns verified inputs (the statement when N=0). It does not spend a nullifier or
    // authorize an application action. Add those policies to its caller.
    #[external("private")]
    fn verify(statement: Field, application: [Field;6], """
    if n > 0:
        source += "public_inputs: [Field;N], "
    source += "raw: [[u128;3];10]" if fixed else "key: RawKey, proof: [[u128;3];8]"
    source += ") -> " + ("Field" if n == 0 else "[Field;N]") + " {\n"
    if n == 0:
        source += "        let public_inputs: [Field;0] = [];\n"
    source += """        assert(application[0] == self.context.chain_id(), "Wrong chain");
        assert(application[1] == self.context.version(), "Wrong protocol version");
        assert(application[2] == self.address.to_field(), "Wrong consumer");
        assert(statement == schema::statement_id(application, APPROVED_KEY, public_inputs), "Wrong statement");
        // Safety: the complete verifier constrains every loaded arithmetic witness.
        let hints: PairingHints = unsafe { load_hint(self.address, CAPSULE_BASE+1) };
"""
    if fixed:
        if n == 0:
            source += """        let components: [[Field;2];0] = [];
        groth16::verify::<ApplicationKey,N>(public_inputs, raw, hints.0, components, hints.1, hints.2, hints.3);
"""
        else:
            source += """        // Safety: scalar components are checked against the public inputs.
        let components: [[Field;2];N] = unsafe { load_hint(self.address, CAPSULE_BASE) };
        groth16::verify::<ApplicationKey,N>(public_inputs, raw, hints.0, components, hints.1, hints.2, hints.3);
"""
    else:
        source += """        // Safety: the complete verifier checks the result and signed scalar split.
        let (claimed_l, magnitudes, negative): ([[u128;3];2], [[Field;2];N], [[bool;2];N]) = unsafe { load_hint(self.address, CAPSULE_BASE) };
        let split = groth16::Hints { claimed_l, magnitudes, negative, residue: hints.0, accumulators: hints.1, quotient: hints.2, block_residuals: hints.3 };
        let key_hash = groth16::verify(decode_key(key), public_inputs, proof, split);
"""
        source += (
            '        assert(key_hash == APPROVED_KEY, "Unauthorized Groth16 key");\n'
        )
    return (
        source
        + ("        statement" if n == 0 else "        public_inputs")
        + "\n    }\n}\n"
    )


def manifest(name: str, kind: str, dependencies: dict[str, Path]) -> str:
    # JSON strings are also TOML basic strings; this handles spaces and quotes.
    return (
        f'[package]\nname = {json.dumps(name)}\ntype = {json.dumps(kind)}\nauthors = [""]\n\n[dependencies]\n'
        + "".join(
            f"{alias} = {{ path = {json.dumps(str(path.resolve()))} }}\n"
            for alias, path in dependencies.items()
        )
    )


def scaffold(
    vk_path: Path,
    out_dir: Path,
    *,
    aztec: Path,
    name="application",
    mode="private",
    key_policy="fixed",
    node="node",
) -> dict:
    from .generate import generate

    out_dir = Path(out_dir).resolve()
    if out_dir.exists():
        raise FileExistsError(f"Refusing existing destination: {out_dir}")
    aztec = Path(aztec).resolve()
    if not (aztec / "Nargo.toml").is_file():
        raise ValueError("--aztec must point to the pinned v6 aztec Noir package")
    if mode != "private":
        raise ValueError("Use the producer scaffold for offchain mode")
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".groth16-scaffold-", dir=out_dir.parent))
    try:
        generation = generate(
            Path(vk_path),
            staging / "generated",
            name=name,
            mode=mode,
            key_policy=key_policy,
            node=node,
        )
        p = json.loads((staging / "generated/profile.json").read_text())
        (staging / "src").mkdir()
        (staging / "src/main.nr").write_text(private_source(p))
        if key_policy == "fixed":
            shutil.copy2(
                staging / "generated/application_key.nr",
                staging / "src/application_key.nr",
            )
        (staging / "Nargo.toml").write_text(
            manifest(
                name,
                "contract",
                {
                    "aztec": aztec,
                    "groth16": ROOT / "noir" / VERIFIER_PACKAGES[key_policy],
                    "schema": ROOT / "noir/runtime_key_schema",
                },
            )
        )
        (
            staging / "README.md"
        ).write_text(f"""# {name}\n\nGenerated {mode}/{key_policy} single-private-function Groth16 consumer, N={p["inputCount"]}.

Use generated/profile.json and generated/key.json with the TypeScript current entry.
For N>0, the ABI order is statement, application, public_inputs, then raw (fixed) or key, proof (runtime); it returns public_inputs.
For N=0, omit public_inputs: the ABI is statement, application, then raw (fixed) or key, proof (runtime), and returns statement. Empty arrays exist only inside the library call. The fixed N=0 private variant does not load an empty scalar capsule.
Capsules use scope zero and the intended contract address. No transaction is submitted by generation.

Run the pinned v6 nargo check, then compile with --skip-brillig-constraints-check --inliner-aggressiveness 0.
The latter compiler flag is an optimization; the former skips the static Brillig-call check, not circuit constraints.
These local path dependencies are intentional; use pinned Git tag/directory dependencies when distributing an application.
Verify your Aztec checkout with scripts/groth16-doctor.py before compiling.

Backend: {p["toolchain"]["backend"]}.
The generated example pins one approved key and checks chain, protocol version and its own contract address.
statement is a Poseidon2 digest of the caller's application tuple, the key hash and the public inputs. The Groth16 proof does not attest it:
anyone who holds a proof can call again with another action, beneficiary and nonce. Those fields are bound only if the original Groth16 circuit exposes them as public inputs.
It does not prove that Groth16 authenticated arbitrary outer context and does not prevent replay.
Implement public-input semantics, action authorization and any required nullifier in the application.
""")
        provenance = {
            "schema": "groth16-private-scaffold-v1",
            "profileSha256": generation["profileSha256"],
            "templateSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "files": {
                str(p.relative_to(staging)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(staging.rglob("*"))
                if p.is_file()
            },
            "scope": "Generated source/configuration only; no compiled artifact or proof identity",
        }
        (staging / "scaffold.json").write_text(json.dumps(provenance, indent=2) + "\n")
        os.rename(staging, out_dir)
        return {"directory": str(out_dir), "profile": p}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vk", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--aztec", required=True, type=Path)
    parser.add_argument("--name", default="application")
    parser.add_argument("--mode", choices=["private"], default="private")
    parser.add_argument("--key-policy", choices=["fixed", "runtime"], default="fixed")
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    try:
        result = scaffold(
            args.vk,
            args.out,
            aztec=args.aztec,
            name=args.name,
            mode=args.mode,
            key_policy=args.key_policy,
            node=args.node,
        )
    except (ValueError, OSError) as error:
        parser.exit(1, f"Groth16 scaffold: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

"""Generate an ordinary Noir producer and one-private-function Aztec O consumer.

Generation performs key preprocessing only. Compilation, verification-key
derivation, deployment and proof generation are explicit subsequent operations.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from .scaffold import ROOT, VERIFIER_PACKAGES, manifest


def producer_source(profile: dict) -> str:
    n = profile["inputCount"]
    fixed = profile["keyPolicy"] == "fixed"
    q = 76 if fixed else 94
    source = (
        "mod application_key;\nuse application_key::ApplicationKey;\n" if fixed else ""
    )
    source += (
        f"global N: u32 = {n};\nglobal APPROVED_KEY: Field = {profile['keyHash']};\n"
    )
    source += "// Exactly one public application input; backend accumulator inputs are separate.\nfn main(\n    statement: pub Field, application: [Field;6],\n"
    if n:
        source += "    inputs: [Field;N],\n"
    if fixed:
        source += "    raw: [[u128;3];10],\n"
        if n:
            source += "    glv_components: [[Field;2];N],\n"
    else:
        source += "    key: groth16::RawVerificationKey<N>, proof: [[u128;3];8], claimed_l: [[u128;3];2],\n"
        if n:
            source += "    magnitudes: [[Field;2];N], negative: [[bool;2];N],\n"
    source += f"""    residue: [[u128;3];36], accumulators: [[[u128;3];12];66],
    quotient: [[u128;3];{q}], block_residuals: [[u128;3];9],
) {{
"""
    if not n:
        source += "    let inputs: [Field;0] = [];\n"
        source += (
            "    let glv_components: [[Field;2];0] = [];\n"
            if fixed
            else "    let magnitudes: [[Field;2];0] = [];\n    let negative: [[bool;2];0] = [];\n"
        )
    if fixed:
        source += "    groth16::verify::<ApplicationKey,N>(inputs, raw, residue, glv_components, accumulators, quotient, block_residuals);\n"
    else:
        source += """    let hints = groth16::Hints { claimed_l, magnitudes, negative, residue, accumulators, quotient, block_residuals };
    let key_hash = groth16::verify(key, inputs, proof, hints);
    assert(key_hash == APPROVED_KEY, "Unauthorized Groth16 key");
"""
    return (
        source
        + '    assert(statement == schema::statement_id(application, APPROVED_KEY, inputs), "Wrong statement");\n}\n'
    )


def consumer_source(profile: dict) -> str:
    n = profile["inputCount"]
    source = f"""use aztec::macros::aztec as aztec_contract;
pub global N: u32 = {n};
pub global APPROVED_KEY: Field = {profile["keyHash"]};

#[aztec_contract]
pub contract Groth16OffchainConsumer {{
    use aztec::macros::{{functions::{{external, initializer}}, storage::storage}};
    use aztec::state_vars::PublicImmutable;
    use aztec::protocol::traits::ToField;
    use crate::{{N, APPROVED_KEY}};

    #[storage]
    struct Storage<Context> {{
        approved_producer_key_hash: PublicImmutable<Field, Context>,
    }}

    #[external("public")]
    #[initializer]
    fn constructor(producer_key_hash: Field) {{
        assert(producer_key_hash != 0, "Zero authorized producer key");
        self.storage.approved_producer_key_hash.initialize(producer_key_hash);
    }}

    // The producer key is application authorization: derive it from the exact
    // compiled producer and authenticate its bytes before initializing storage.
    #[external("private")]
    fn verify(statement: Field, application: [Field;6], """
    if n:
        source += "public_inputs: [Field;N], "
    source += (
        "producer_key: [Field;115], proof: [Field;458]) -> "
        + ("[Field;N]" if n else "Field")
        + " {\n"
    )
    if not n:
        source += "        let public_inputs: [Field;0] = [];\n"
    source += """        assert(application[0] == self.context.chain_id(), "Wrong chain");
        assert(application[1] == self.context.version(), "Wrong protocol version");
        assert(application[2] == self.address.to_field(), "Wrong consumer");
        assert(statement == schema::statement_id(application, APPROVED_KEY, public_inputs), "Wrong statement");
        // HONK_ZK = 6. Only statement is an application public input; the
        // backend's eight accumulator fields are handled by recursive verification.
        std::verify_proof_with_type(producer_key, proof, [statement], self.storage.approved_producer_key_hash.read(), 6);
        // A bound action/beneficiary/nonce is not a state transition or nullifier.
"""
    return (
        source
        + ("        public_inputs" if n else "        statement")
        + "\n    }\n}\n"
    )


def scaffold(
    vk_path: Path,
    out_dir: Path,
    *,
    aztec: Path,
    name="application",
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
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".groth16-producer-", dir=out_dir.parent))
    try:
        generate(
            Path(vk_path),
            staging / "generated",
            name=name,
            mode="offchain",
            key_policy=key_policy,
            node=node,
        )
        profile = json.loads((staging / "generated/profile.json").read_text())
        for folder, kind, source, dependencies in [
            (
                "producer",
                "bin",
                producer_source(profile),
                {
                    "groth16": ROOT / "noir" / VERIFIER_PACKAGES[key_policy],
                    "schema": ROOT / "noir/runtime_key_schema",
                },
            ),
            (
                "consumer",
                "contract",
                consumer_source(profile),
                {"aztec": aztec, "schema": ROOT / "noir/runtime_key_schema"},
            ),
        ]:
            target = staging / folder
            (target / "src").mkdir(parents=True)
            (target / "src/main.nr").write_text(source)
            # Prefixes remain below Noir's 64-character identifier limit.
            (target / "Nargo.toml").write_text(manifest(folder, kind, dependencies))
        if key_policy == "fixed":
            shutil.copy2(
                staging / "generated/application_key.nr",
                staging / "producer/src/application_key.nr",
            )
        abi = (
            ["statement", "application"]
            + (["public_inputs"] if profile["inputCount"] else [])
            + ["producer_key", "proof"]
        )
        record = {
            "schema": "groth16-offchain-scaffold-v1",
            "inputCount": profile["inputCount"],
            "keyPolicy": key_policy,
            "consumerArguments": abi,
            "consumerReturn": "public_inputs" if profile["inputCount"] else "statement",
            "constructorArguments": ["producer_key_hash"],
            "producerApplicationPublicInputs": ["statement"],
            "producerVerificationKeyFields": 115,
            "proofFields": 458,
            "recursiveProofType": 6,
            "profile": "generated/profile.json",
            "producer": "producer",
            "consumer": "consumer",
            "proofGenerated": False,
            "templateSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "files": {
                str(p.relative_to(staging)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(staging.rglob("*"))
                if p.is_file()
            },
        }
        (staging / "scaffold.json").write_text(json.dumps(record, indent=2) + "\n")
        (staging / "README.md").write_text(f"""# {name}: offchain Groth16 verification

This application uses {key_policy} key policy with {profile["inputCount"]} public inputs. The producer calls the maintained complete private verifier; its sole public application input is statement. The consumer compiles the approved Groth16 key hash and authorizes the producer verification-key hash in its constructor. Generation does not compile, derive a producer key, deploy, or prove.

Use generated/profile.json and generated/key.json with createVerifier from the SDK current entry. packet.producerInputs matches producer/src/main.nr. The offchain profile emits no capsules. At N=0 the external producer omits inputs and scalar decomposition arrays; the consumer omits public_inputs and returns statement. Empty arrays remain local values.

Verify the pinned toolchain using scripts/groth16-doctor.py. Run nargo check in producer and consumer, then explicitly compile with --skip-brillig-constraints-check --inliner-aggressiveness 0. Compilation can be expensive. These are local path dependencies; replace them with pinned Git tag/directory dependencies when distributing an application.

Derive the UltraHonk producer verification key from the exact compiled producer with the pinned backend's noir-recursive options. Retain its raw bytes, 115 canonical field values and Poseidon2 key hash; backend metadata vk[1] must be 9 (one statement plus eight recursive accumulator fields). This is not nine application public inputs. Initialize the consumer with that authenticated, nonzero key hash. Never authorize an arbitrary key supplied by a caller.

After compiling both packages and deriving the key, build artifact identity metadata with python3 -m groth16.artifacts --profile generated/profile.json --producer producer/target/producer.json --producer-vk /path/to/producer.vk --consumer /path/to/compiled-consumer-artifact.json --out /path/to/new-artifact-identities.json. The consumer artifact filename is compiler-dependent. Supply those exact bytes, the trusted profile, an executor and backend to createProducer from the SDK producer entry. Proof generation is explicit; locally verify its result before prepareOffchainCall from the SDK aztec entry. The pinned backend's generateRecursiveProofArtifacts returns no proofAsFields; use the authenticated adapter's direct 458-field proof representation including default IO instead.

Consumer ABI: {", ".join(abi)}. application is [chain_id, version, consumer_address, action, beneficiary, nonce]. The consumer checks chain, version, address, the recomputed statement and the authorized producer proof. application is a private producer input, so anyone who holds the Groth16 proof can make a new producer proof for another application tuple: the action and beneficiary are bound only if the original Groth16 circuit exposes them as public inputs. A host mock or ACVM simulation is not recursive cryptographic proof acceptance. The generated example does not consume a nonce, authorize an application action, or establish that the original Groth16 circuit authenticated arbitrary outer context. Add public-input interpretation, beneficiary checks and replay/nullifier policy in the application.

The finite outer pairing-input policy and the verifier's constrained hint relation are unchanged. Read the library README and docs/OPTIMIZATIONS.md for arithmetic domains and provenance requirements.
""")
        os.rename(staging, out_dir)
        return {"directory": str(out_dir), "profile": profile, "scaffold": record}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vk", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--aztec", required=True, type=Path)
    parser.add_argument("--name", default="application")
    parser.add_argument("--key-policy", choices=["fixed", "runtime"], default="fixed")
    parser.add_argument("--node", default="node")
    args = parser.parse_args()
    print(
        json.dumps(
            scaffold(
                args.vk,
                args.out,
                aztec=args.aztec,
                name=args.name,
                key_policy=args.key_policy,
                node=args.node,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

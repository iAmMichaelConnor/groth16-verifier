#!/usr/bin/env python3
"""Generate the Noir proof vectors of the saved proofs.

For the fixed-key verifier (tests/fixed_multiplier_vector) and the runtime-key
verifier (tests/runtime_multiplier_vector), writes the host hints of the
committed proof fixtures/multiplier/proof.json (public input 33) as Noir
constants, plus two tampered copies of the proof: A negated and B negated.
Both stay on their curves, so the tampered proofs pass the point checks and the
public-input binding and reach the pairing check, which must reject them.

For the SP1 v6 verifier (tests/sp1_v6_vector), writes the hints of the two
saved SP1 v6 proofs in fixtures/sp1-v6 and, with the first proof's hints, its
A negated, the A, B, C of two proofs for other keys (the SP1 v5 proof of the
groth16-verifier-sp1 tests and the SP1 v6.0.0 proof in fixtures/sp1-v6), and
input-binding vectors: one public input changed with its GLV components
recomputed, either with the saved input point L (the MSM check must reject it)
or with L moved to match (the pairing check must reject it). The vectors for
the exit code and the root, which sp1::v6::verify fixes, go to the sp1 package
(noir/sp1/src/generated/v6_test_vector.nr), whose tests reach the key.
Hint preparation only: no setup, proof or backend runs. Needs node and the
SDK's dependencies (`npm ci` in packages/groth16-verifier-hints).
--check compares the existing vectors without writing them.
"""

from __future__ import annotations
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

LIB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LIB / "packages/groth16-verifier-hints/python"))
sys.path.insert(0, str(LIB / "packages/groth16-verifier-sp1/python"))
sys.path.insert(0, str(LIB / "scripts"))
from groth16 import generate as g  # noqa: E402
from groth16 import _preprocess as preprocess  # noqa: E402
import generate_sp1_key  # noqa: E402
import sp1_v6  # noqa: E402
from noir_format import format_noir  # noqa: E402

FIXTURES = LIB / "fixtures/multiplier"
HELPER = LIB / "packages/groth16-verifier-hints/test/prepare-vector-inputs.mjs"
PUBLIC_INPUT = "33"
SELF = "scripts/generate_test_vectors.py"
# BN254 base field modulus.
Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583

# policy -> (destination, fields in the order of the Noir verifier's arguments, type)
FIXED_FIELDS = [
    ("inputs", "INPUTS", "[Field; 1]"),
    ("raw", "RAW", "[[u128; 3]; 10]"),
    ("residue", "RESIDUE", "[[u128; 3]; 36]"),
    ("glv_components", "GLV_COMPONENTS", "[[Field; 2]; 1]"),
    ("accumulators", "ACCUMULATORS", "[[[u128; 3]; 12]; 66]"),
    ("quotient", "QUOTIENT", "[[u128; 3]; 76]"),
    ("block_residuals", "BLOCK_RESIDUALS", "[[u128; 3]; 9]"),
]
RUNTIME_FIELDS = [
    ("inputs", "INPUTS", "[Field; 1]"),
    ("proof", "PROOF", "[[u128; 3]; 8]"),
    ("claimed_l", "CLAIMED_L", "[[u128; 3]; 2]"),
    ("magnitudes", "MAGNITUDES", "[[Field; 2]; 1]"),
    ("negative", "NEGATIVE", "[[bool; 2]; 1]"),
    ("residue", "RESIDUE", "[[u128; 3]; 36]"),
    ("accumulators", "ACCUMULATORS", "[[[u128; 3]; 12]; 66]"),
    ("quotient", "QUOTIENT", "[[u128; 3]; 94]"),
    ("block_residuals", "BLOCK_RESIDUALS", "[[u128; 3]; 9]"),
]
KEY_FIELDS = [
    ("alpha", "[[u128; 3]; 2]"),
    ("beta", "[[u128; 3]; 4]"),
    ("gamma", "[[u128; 3]; 4]"),
    ("delta", "[[u128; 3]; 4]"),
    ("ic", "[[[u128; 3]; 2]; 2]"),
]
DESTINATIONS = {
    "fixed": LIB / "tests/fixed_multiplier_vector/src/vector.nr",
    "runtime": LIB / "tests/runtime_multiplier_vector/src/vector.nr",
}
SP1_V6_FIXTURES = LIB / "fixtures/sp1-v6"
SP1_V6_VECTORS = LIB / "tests/sp1_v6_vector/src"
# Accepted proofs: module name -> fixture.
SP1_V6_PROOFS = {"multiply": "multiply.json", "clock": "clock.json"}
SP1_V5_PROOF = LIB / "packages/groth16-verifier-sp1/test/fixtures/fixed-sp1.json"
SP1_V6_0_PROOF = SP1_V6_FIXTURES / "fibonacci-v6.0.0.json"
SP1_V6_INNER_VECTOR = LIB / "noir/sp1/src/generated/v6_test_vector.nr"
# BN254 scalar field modulus.
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# Fq coordinate rows of A and B (y coordinates only) in each proof encoding:
# fixed raw = [A.x, A.y, B.x0, B.x1, B.y0, B.y1, C.x, C.y, L.x, L.y],
# runtime proof = [A.x, A.y, B.x0, B.x1, B.y0, B.y1, C.x, C.y].
NEGATIONS = {"NEGATED_A": (1,), "NEGATED_B": (4, 5)}
# A forged certificate for the saved proof: c = c_inverse = w = 1 and every
# accumulator, quotient coefficient and block residual zero. The residue
# relations hold for it, but the Miller-loop relations do not.
CERTIFICATE_SHAPES = {
    "fixed": {"accumulators": (66, 12), "quotient": 76},
    "runtime": {"accumulators": (66, 12), "quotient": 94},
}


def literal(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    return "[" + ", ".join(literal(v) for v in value) + "]"


def negate(limbs: list) -> list:
    """-y for one canonical Fq coordinate in 120/120/14-bit limbs."""
    y = sum(int(limb) << (120 * i) for i, limb in enumerate(limbs))
    if not 0 < y < Q:
        raise SystemExit("unexpected coordinate in the saved proof")
    n = Q - y
    return [str((n >> (120 * i)) & ((1 << 120) - 1)) for i in range(3)]


def tampered(proof: list, rows: tuple) -> list:
    return [negate(row) if i in rows else row for i, row in enumerate(proof)]


def prepare(
    policy: str,
    key: Path = FIXTURES / "verification_key.json",
    proof: Path = FIXTURES / "proof.json",
    inputs: tuple = (PUBLIC_INPUT,),
    name: str = "multiplier",
) -> dict:
    """Producer inputs of a saved proof under a freshly generated profile."""
    with tempfile.TemporaryDirectory(prefix="groth16-vector-") as temp:
        out = Path(temp) / "generated"
        g.generate(
            key,
            out,
            name=name,
            provider_name="Key1",
            mode="offchain",
            key_policy=policy,
        )
        result = subprocess.run(
            ["node", str(HELPER), str(out / "profile.json"), str(out / "key.json"), str(proof), *inputs],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode:
        raise SystemExit(f"{policy}: hint preparation failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def output(policy: str) -> str:
    values = prepare(policy)
    fields = FIXED_FIELDS if policy == "fixed" else RUNTIME_FIELDS
    lines = [
        "// TEST ONLY. Hints of a saved proof for the Circom multiplier key; they authorise nothing.\n",
        f"// Generated by {SELF}; do not edit.\n",
        "// Proof: fixtures/multiplier/proof.json, public input 33 (product = a * b).\n",
        "// The hints are host-computed and untrusted: the verifier constrains each of them.\n",
        "// NEGATED_A and NEGATED_B are the proof with A or B negated; they are on their\n",
        "// curves, but the pairing equation fails for them. FORGED_* is a certificate\n",
        "// of ones and zeros that satisfies the residue relations but not the Miller loop.\n",
    ]
    if policy == "runtime":
        lines.append("use verifier::RawVerificationKey;\n")
    for name, constant, noir_type in fields:
        lines.append(
            f"\npub global {constant}: {noir_type} = {literal(values[name])};\n"
        )
    name, constant, noir_type = fields[1]
    for prefix, rows in NEGATIONS.items():
        lines.append(
            f"\npub global {constant}_{prefix}: {noir_type} = "
            f"{literal(tampered(values[name], rows))};\n"
        )
    zero = ["0", "0", "0"]
    shape = CERTIFICATE_SHAPES[policy]
    residue = [["1", "0", "0"] if i in (0, 12, 24) else zero for i in range(36)]
    rows, columns = shape["accumulators"]
    forged = [
        ("RESIDUE", "[[u128; 3]; 36]", residue),
        ("ACCUMULATORS", f"[[[u128; 3]; {columns}]; {rows}]", [[zero] * columns] * rows),
        ("QUOTIENT", f"[[u128; 3]; {shape['quotient']}]", [zero] * shape["quotient"]),
        ("BLOCK_RESIDUALS", "[[u128; 3]; 9]", [zero] * 9),
    ]
    for constant, noir_type, value in forged:
        lines.append(f"\npub global FORGED_{constant}: {noir_type} = {literal(value)};\n")
    if policy == "runtime":
        key = values["key"]
        body = "".join(
            f"        {name}: {literal(key[name])},\n" for name, _ in KEY_FIELDS
        )
        lines.append(
            "\npub fn key() -> RawVerificationKey<1> {\n"
            "    RawVerificationKey {\n" + body + "    }\n}\n"
        )
    return "".join(lines)


def proof_rows(proof: dict) -> list:
    """A, B, C of a snarkjs proof as the first eight rows of the fixed `raw`."""
    values = [*proof["pi_a"][:2], *proof["pi_b"][0], *proof["pi_b"][1], *proof["pi_c"][:2]]
    return [to_limbs(int(v)) for v in values]


def to_limbs(v: int) -> list:
    return [str((v >> (120 * i)) & ((1 << 120) - 1)) for i in range(3)]


def from_limbs(row: list) -> int:
    return sum(int(limb) << (120 * i) for i, limb in enumerate(row))


# A large shift for the moved-input-point vectors (any value works; this one has
# no structure).
SHIFT = 0x2B5A4C3F17E9D0B8A6F4E2C0B1A3D5F7092846A1C3E5F7B9D0E2C4A6B8D0F13


def binding_variant(values: dict, inputs: list, ic: list, index: int, value: int, move_l: bool) -> dict:
    """The saved proof's hints for `inputs` with input `index` set to `value`.

    The GLV components of that input are recomputed, so the decomposition
    check passes. With `move_l` false the input point L in `raw` is the saved
    one, so the circuit's MSM disagrees with it; with `move_l` true L is
    replaced by L + (value - inputs[index]) * IC[index + 1], computed from the
    saved key, so the MSM agrees and the pairing check must reject it.
    """
    changed = list(inputs)
    changed[index] = value % R
    components = [list(c) for c in values["glv_components"]]
    components[index] = [str(x) for x in preprocess.split(changed[index])]
    raw = [list(row) for row in values["raw"]]
    if move_l:
        point = (from_limbs(raw[8]), from_limbs(raw[9]))
        moved = preprocess.add(point, preprocess.mul((changed[index] - inputs[index]) % R, ic[index + 1]))
        if moved is None:
            raise SystemExit("moved input point is infinity")
        raw[8], raw[9] = to_limbs(moved[0]), to_limbs(moved[1])
    return {"inputs": changed, "components": components, "raw": raw}


def variant_lines(name: str, variant: dict, comment: str, with_inputs: bool) -> list:
    lines = [f"\n// {comment}\n"]
    if with_inputs:
        lines.append(f"pub global INPUTS_{name}: [Field; 5] = {literal([f'{x:#x}' for x in variant['inputs']])};\n")
    lines.append(f"pub global COMPONENTS_{name}: [[Field; 2]; 5] = {literal(variant['components'])};\n")
    if variant["raw"] is not None:
        lines.append(f"pub global RAW_{name}: [[u128; 3]; 10] = {literal(variant['raw'])};\n")
    return lines


def hint_lines(values: dict) -> list:
    lines = []
    for field, constant, noir_type in FIXED_FIELDS[1:]:
        noir_type = noir_type.replace("[[Field; 2]; 1]", "[[Field; 2]; 5]")
        lines.append(f"\npub global {constant}: {noir_type} = {literal(values[field])};\n")
    return lines


def sp1_v6_outputs() -> dict[Path, str]:
    """Hints of each saved SP1 v6 proof, plus the negative vectors of the first."""
    files = {}
    key_json = generate_sp1_key.sp1_key(generate_sp1_key.SP1_V6_VK)
    ic = [(int(p[0]), int(p[1])) for p in key_json["IC"]]
    with tempfile.TemporaryDirectory(prefix="sp1-v6-vector-") as temp:
        key = Path(temp) / "key.json"
        key.write_text(json.dumps(key_json))
        for module, name in SP1_V6_PROOFS.items():
            fixture = sp1_v6.load_fixture(SP1_V6_FIXTURES / name)
            parsed = sp1_v6.parse_proof_bytes(fixture["proof_bytes"])
            digest = sp1_v6.public_inputs(fixture["vkey"], fixture["public_values"], 0)[1]
            # As SP1's onchain verifier builds them: exit code, root and nonce
            # are the proof's own words.
            inputs = [fixture["vkey"], digest, parsed["exit_code"], parsed["vk_root"], parsed["nonce"]]
            proof = Path(temp) / f"{module}.json"
            proof.write_text(json.dumps(parsed["proof"]))
            values = prepare("fixed", key, proof, tuple(map(str, inputs)), "sp1_v6")
            if values["inputs"] != list(map(str, inputs)):
                raise SystemExit(f"{module}: unexpected public inputs")
            count = len(fixture["public_values"])
            lines = [
                "// TEST ONLY. Hints of a saved SP1 v6 proof; they authorise nothing.\n",
                f"// Generated by {SELF}; do not edit.\n",
                f"// Proof: fixtures/sp1-v6/{name} (see fixtures/sp1-v6/manifest.json).\n",
                "// INPUTS are the five public inputs as SP1's onchain verifier builds them,\n",
                "// with the exit code, vk root and nonce read from the proof bytes.\n",
                "// The hints are host-computed and untrusted: the verifier constrains each of them.\n",
                f"\npub global PROGRAM_VKEY: Field = {fixture['vkey']:#066x};\n",
                f"\npub global PUBLIC_VALUES: [u8; {count}] = {literal(list(map(str, fixture['public_values'])))};\n",
                f"\npub global PROOF_NONCE: Field = {parsed['nonce']};\n",
                f"\npub global INPUTS: [Field; 5] = {literal([f'{x:#x}' for x in inputs])};\n",
            ] + hint_lines(values)
            if module != "multiply":
                files[SP1_V6_VECTORS / f"{module}.nr"] = "".join(lines)
                continue
            raw = values["raw"]
            v5 = json.loads(SP1_V5_PROOF.read_text())["proof"]
            v6_0 = sp1_v6.load_fixture(SP1_V6_0_PROOF)["proof_bytes"]
            # The v6.0.0 proof carries another selector and root, which the
            # parser rejects; take its words directly.
            words = [int.from_bytes(v6_0[4 + 32 * i : 36 + 32 * i], "big") for i in range(11)]
            v6_0_proof = {
                "pi_a": words[3:5],
                "pi_b": [[words[6], words[5]], [words[8], words[7]]],
                "pi_c": words[9:11],
            }
            lines += [
                "\n// RAW with A negated: on the curve, but the pairing equation fails.\n",
                f"pub global RAW_NEGATED_A: [[u128; 3]; 10] = {literal(tampered(raw, (1,)))};\n",
                "\n// RAW with A, B, C of the SP1 v5 proof in\n",
                "// packages/groth16-verifier-sp1/test/fixtures/fixed-sp1.json.\n",
                f"pub global RAW_V5_PROOF: [[u128; 3]; 10] = {literal(proof_rows(v5) + raw[8:])};\n",
                "\n// RAW with A, B, C of the SP1 v6.0.0 proof in fixtures/sp1-v6/fibonacci-v6.0.0.json.\n",
                f"pub global RAW_V6_0_PROOF: [[u128; 3]; 10] = {literal(proof_rows(v6_0_proof) + raw[8:])};\n",
            ]
            # Input-binding vectors reachable through sp1::v6::verify: the program
            # vkey (input 0), the public values (input 1) and the nonce (input 4).
            values_changed = bytearray(fixture["public_values"])
            values_changed[0] = (values_changed[0] + 1) % 256
            changed_digest = sp1_v6.public_inputs(0, bytes(values_changed), 0)[1]
            lines.append(
                f"\npub global PUBLIC_VALUES_CHANGED: [u8; {count}] = {literal(list(map(str, values_changed)))};\n"
            )
            for index, label, value in (
                (0, "VKEY", inputs[0] + 1),
                (1, "PUBLIC_VALUES", changed_digest),
                (4, "NONCE", inputs[4] + 1),
            ):
                stale = binding_variant(values, inputs, ic, index, value, False)
                stale["raw"] = None
                lines += variant_lines(
                    f"{label}_STALE_L", stale,
                    f"Input {index} changed, its GLV components recomputed, the saved L kept.", False,
                )
                shift = changed_digest if index == 1 else inputs[index] + SHIFT
                lines += variant_lines(
                    f"{label}_MOVED_L", binding_variant(values, inputs, ic, index, shift, True),
                    f"Input {index} changed, its GLV components recomputed, L moved to match.", False,
                )
            lines.append(f"\npub global PROGRAM_VKEY_SHIFTED: Field = {(inputs[0] + SHIFT) % R:#x};\n")
            lines.append(f"\npub global PROOF_NONCE_SHIFTED: Field = {(inputs[4] + SHIFT) % R:#x};\n")
            files[SP1_V6_VECTORS / f"{module}.nr"] = "".join(lines)
            # The inputs that sp1::v6::verify fixes (exit code, root) can only be
            # changed through the Groth16 statement, inside the sp1 package.
            inner = [
                "// TEST ONLY. Hints of the saved SP1 v6 proof fixtures/sp1-v6/multiply.json;\n",
                "// they authorise nothing. Used by the sp1 package's tests of the inputs that\n",
                "// sp1::v6::verify fixes.\n",
                f"// Generated by {SELF}; do not edit.\n",
                f"\npub(crate) global INPUTS: [Field; 5] = {literal([f'{x:#x}' for x in inputs])};\n",
            ] + [
                # Every test here supplies its own GLV components.
                line.replace("pub global", "pub(crate) global")
                for line in hint_lines(values)
                if "GLV_COMPONENTS" not in line
            ]
            for index, label, value, move_l in (
                (2, "EXIT_CODE_ONE", 1, False),
                (2, "EXIT_CODE_SHIFTED", inputs[2] + SHIFT, True),
                (3, "VK_ROOT_PLUS_ONE", inputs[3] + 1, False),
                (3, "VK_ROOT_V6_0", words[1], True),
            ):
                variant = binding_variant(values, inputs, ic, index, value, move_l)
                if not move_l:
                    variant["raw"] = None
                comment = (
                    f"Input {index} set, its GLV components recomputed, "
                    + ("L moved to match." if move_l else "the saved L kept.")
                )
                inner += [
                    line.replace("pub global", "pub(crate) global")
                    for line in variant_lines(label, variant, comment, True)
                ]
            files[SP1_V6_INNER_VECTOR] = "".join(inner)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    status = 0
    outputs = {destination: output(policy) for policy, destination in DESTINATIONS.items()}
    outputs.update(sp1_v6_outputs())
    texts = format_noir(outputs.values())
    for destination, text in zip(outputs, texts):
        if args.check:
            if not destination.is_file() or destination.read_text() != text:
                print(f"{destination.relative_to(LIB)}: out of date", file=sys.stderr)
                status = 1
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text)
    return status


if __name__ == "__main__":
    sys.exit(main())

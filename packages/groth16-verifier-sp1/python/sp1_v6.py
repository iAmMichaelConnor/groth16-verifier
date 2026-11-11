"""SP1 v6 Groth16 proof bytes and public inputs (SP1 circuit version v6.1.0).

The same rules as the TypeScript adapter (src/v6.ts) and the Noir entry point
sp1::v6::verify, for host scripts: the vector generator and the tests use it.
Standard library only; no hints, no proving.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
CIRCUIT_VERSION = "v6.1.0"
VERIFIER_SELECTOR = bytes.fromhex("4388a21c")
VK_ROOT = 0x002F850EE998974D6CC00E50CD0814B098C05BFADE466D28573240D057F25352
PROOF_BYTES = 356
# The twist coefficient 3 / (9 + i) of BN254's G2 curve y^2 = x^3 + b'.
TWIST_B = (
    19485874751759354771024239261021720505790618469301721065564631296452457478373,
    266929791119991161246907387137283842545076965332900288569378510910307636690,
)


def _fq2_mul(a: tuple, b: tuple) -> tuple:
    return ((a[0] * b[0] - a[1] * b[1]) % FQ, (a[0] * b[1] + a[1] * b[0]) % FQ)


def on_g1(x: int, y: int) -> bool:
    """Finite and on y^2 = x^3 + 3."""
    return (x, y) != (0, 0) and (y * y - x * x * x - 3) % FQ == 0


def on_twist(x: tuple, y: tuple) -> bool:
    """Finite and on the G2 twist y^2 = x^3 + 3 / (9 + i); (real, imaginary)."""
    if x == (0, 0) and y == (0, 0):
        return False
    rhs = _fq2_mul(_fq2_mul(x, x), x)
    return _fq2_mul(y, y) == ((rhs[0] + TWIST_B[0]) % FQ, (rhs[1] + TWIST_B[1]) % FQ)


def parse_proof_bytes(data: bytes) -> dict:
    """Split SP1 v6 proof bytes into the exit code, vk root, nonce and the
    snarkjs-form proof (Fq2 coefficients real first). Rejects what SP1's
    onchain verifier rejects before the pairing check, and A, B, C at infinity
    or off their curves (G2 subgroup membership is left to the verifier)."""
    if len(data) != PROOF_BYTES:
        raise ValueError(f"SP1 v6 proof must be exactly {PROOF_BYTES} bytes")
    if data[:4] != VERIFIER_SELECTOR:
        raise ValueError("SP1 v6 proof verifier selector mismatch")
    words = [int.from_bytes(data[4 + 32 * i : 36 + 32 * i], "big") for i in range(11)]
    exit_code, vk_root, nonce, *p = words
    if exit_code != 0:
        raise ValueError("SP1 v6 proof has a nonzero exit code")
    if vk_root != VK_ROOT:
        raise ValueError("SP1 v6 proof vk root mismatch")
    if nonce >= FR:
        raise ValueError("SP1 v6 proof nonce: noncanonical integer")
    if any(x >= FQ for x in p):
        raise ValueError("SP1 v6 proof: noncanonical coordinate")
    if not on_g1(p[0], p[1]):
        raise ValueError("SP1 v6 proof: A is infinity or not on the curve")
    if not on_twist((p[3], p[2]), (p[5], p[4])):
        raise ValueError("SP1 v6 proof: B is infinity or not on the twist")
    if not on_g1(p[6], p[7]):
        raise ValueError("SP1 v6 proof: C is infinity or not on the curve")
    # SP1's Ethereum encoding orders each Fq2 coefficient pair imaginary first.
    proof = {
        "protocol": "groth16",
        "curve": "bn128",
        "pi_a": [str(p[0]), str(p[1]), "1"],
        "pi_b": [[str(p[3]), str(p[2])], [str(p[5]), str(p[4])], ["1", "0"]],
        "pi_c": [str(p[6]), str(p[7]), "1"],
    }
    return {"exit_code": exit_code, "vk_root": vk_root, "nonce": nonce, "proof": proof}


def public_inputs(vkey: int, public_values: bytes, nonce: int) -> list[int]:
    """[program vkey, SHA256(public values) & (2^253-1), 0, VK_ROOT, nonce]."""
    if not 0 <= vkey < FR or not 0 <= nonce < FR:
        raise ValueError("SP1 program vkey and nonce must be canonical field elements")
    digest = bytearray(hashlib.sha256(public_values).digest())
    digest[0] &= 0x1F
    return [vkey, int.from_bytes(digest, "big"), 0, VK_ROOT, nonce]


def load_fixture(path: Path) -> dict:
    """An SP1 fixture JSON ({vkey, publicValues, proof}, hex strings)."""
    fixture = json.loads(Path(path).read_text())
    return {
        "vkey": int(fixture["vkey"], 16),
        "public_values": bytes.fromhex(fixture["publicValues"][2:]),
        "proof_bytes": bytes.fromhex(fixture["proof"][2:]),
    }

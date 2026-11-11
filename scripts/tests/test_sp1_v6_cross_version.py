"""SP1 v6.0.0 proofs fail under the pinned SP1 v6 key; pairing level, no circuit.

fixtures/sp1-v6/fibonacci-v6.0.0.json is a real proof for SP1 circuit version
v6.0.0. With its own five public inputs (exit code, root and nonce from its
bytes), it satisfies the Groth16 equation under the v6.0.0 key
(fixtures/sp1-v6/groth16_vk_v6.0.0.bin) and not under the pinned v6.1.0 key
(fixtures/sp1-v6/groth16_vk.bin) that sp1::v6 compiles in. The same check passes
the saved v6.1.0 proofs under the pinned key, so the equation code is not
rejecting everything. Uses the repository's pure-Python BN254 reference.
"""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages/groth16-verifier-hints/python"))
sys.path.insert(0, str(ROOT / "packages/groth16-verifier-sp1/python"))
sys.path.insert(0, str(ROOT / "scripts"))
from groth16 import _pairing as m, _preprocess as g  # noqa: E402
import generate_sp1_key  # noqa: E402
import sp1_v6  # noqa: E402

FIXTURES = ROOT / "fixtures/sp1-v6"


def statement(path: Path):
    """The fixture's five public inputs and its A, B, C, read from its bytes."""
    fixture = sp1_v6.load_fixture(path)
    data = fixture["proof_bytes"]
    words = [int.from_bytes(data[4 + 32 * i : 36 + 32 * i], "big") for i in range(11)]
    digest = sp1_v6.public_inputs(fixture["vkey"], fixture["public_values"], 0)[1]
    inputs = [fixture["vkey"], digest, words[0], words[1], words[2]]
    a = (words[3], words[4])
    b = [[str(words[6]), str(words[5])], [str(words[8]), str(words[7])], ["1", "0"]]
    c = (words[9], words[10])
    return inputs, a, b, c


def groth16_holds(key: dict, inputs, a, b, c) -> bool:
    """e(A, B) e(C, -delta) e(L, -gamma) e(-alpha, beta) == 1."""
    ic = [g.point(p) for p in key["IC"]]
    point = ic[0]
    for x, base in zip(inputs, ic[1:]):
        point = g.add(point, g.mul(x, base))
    neg = lambda p: (p[0], (-p[1]) % g.q)  # noqa: E731
    alpha = g.point(key["vk_alpha_1"])
    beta, gamma, delta = (g.twist(key[f]) for f in ("vk_beta_2", "vk_gamma_2", "vk_delta_2"))
    pairs = [m.G1Affine(*a), m.G1Affine(*neg(c)), m.G1Affine(*neg(point)), m.G1Affine(*neg(alpha))]
    value = m.final_exponentiation(m.miller_loop(pairs, [g.twist(b), delta, gamma, beta]))
    return value == m.Fp12.one()


class CrossVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pinned = generate_sp1_key.sp1_key(FIXTURES / "groth16_vk.bin")
        cls.v6_0 = generate_sp1_key.sp1_key(FIXTURES / "groth16_vk_v6.0.0.bin")

    def test_v6_0_proof_verifies_only_under_its_own_key(self):
        inputs, a, b, c = statement(FIXTURES / "fibonacci-v6.0.0.json")
        self.assertNotEqual(inputs[3], sp1_v6.VK_ROOT)
        self.assertTrue(groth16_holds(self.v6_0, inputs, a, b, c))
        self.assertFalse(groth16_holds(self.pinned, inputs, a, b, c))
        # Nor with the pinned root in place of its own.
        self.assertFalse(groth16_holds(self.pinned, inputs[:3] + [sp1_v6.VK_ROOT] + inputs[4:], a, b, c))

    def test_saved_v6_1_proofs_verify_under_the_pinned_key(self):
        for name in ("multiply.json", "clock.json"):
            inputs, a, b, c = statement(FIXTURES / name)
            self.assertTrue(groth16_holds(self.pinned, inputs, a, b, c), name)
            self.assertFalse(groth16_holds(self.v6_0, inputs, a, b, c), name)


if __name__ == "__main__":
    unittest.main()

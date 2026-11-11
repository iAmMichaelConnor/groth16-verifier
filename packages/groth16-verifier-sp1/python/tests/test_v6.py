"""SP1 v6 proof parsing and public inputs against the saved proofs; no proving."""

from pathlib import Path
import hashlib
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "packages/groth16-verifier-sp1/python"))
import sp1_v6

FIXTURES = ROOT / "fixtures/sp1-v6"


def with_word(data: bytes, index: int, value: int) -> bytes:
    """Replace word `index` (0: exit code, 1: vk root, 2: nonce, 3..10: A, B, C)."""
    start = 4 + 32 * index
    return data[:start] + value.to_bytes(32, "big") + data[start + 32 :]


class V6Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.multiply = sp1_v6.load_fixture(FIXTURES / "multiply.json")
        cls.clock = sp1_v6.load_fixture(FIXTURES / "clock.json")

    def test_constants_are_those_of_the_saved_key(self):
        key = (FIXTURES / "groth16_vk.bin").read_bytes()
        self.assertEqual(hashlib.sha256(key).digest()[:4], sp1_v6.VERIFIER_SELECTOR)

    def test_saved_proofs_give_the_recorded_public_inputs(self):
        parsed = sp1_v6.parse_proof_bytes(self.multiply["proof_bytes"])
        self.assertEqual((parsed["exit_code"], parsed["vk_root"], parsed["nonce"]), (0, sp1_v6.VK_ROOT, 0))
        # The public inputs the producer of multiply.json recorded with it.
        self.assertEqual(
            sp1_v6.public_inputs(self.multiply["vkey"], self.multiply["public_values"], parsed["nonce"]),
            [
                205922228921289178148469420413941188507828442907728971729484782450287372490,
                9747890225745800339047999895000149364384159344001995441670265923588659111166,
                0,
                83960146348496814183195590144795274058764451818716359375255161226434597714,
                0,
            ],
        )
        parsed = sp1_v6.parse_proof_bytes(self.clock["proof_bytes"])
        self.assertEqual(parsed["proof"]["pi_b"][2], ["1", "0"])

    def test_rejections(self):
        data = self.multiply["proof_bytes"]
        cases = [
            (data + b"\0", "356 bytes"),
            (data[:-1], "356 bytes"),
            (bytes.fromhex("a4594c59") + data[4:], "selector"),
            (sp1_v6.load_fixture(FIXTURES / "fibonacci-v6.0.0.json")["proof_bytes"], "selector"),
            (with_word(data, 0, 1), "exit code"),
            (with_word(data, 1, sp1_v6.VK_ROOT + 1), "vk root"),
            (with_word(data, 2, sp1_v6.FR), "nonce"),
            (with_word(data, 3, sp1_v6.FQ), "coordinate"),
            (with_word(data, 4, 5), "A is infinity or not on the curve"),
            (with_word(with_word(data, 3, 0), 4, 0), "A is infinity"),
            (with_word(data, 7, 1), "B is infinity or not on the twist"),
            (with_word(with_word(with_word(with_word(data, 5, 0), 6, 0), 7, 0), 8, 0), "B is infinity"),
            (with_word(data, 10, 7), "C is infinity or not on the curve"),
        ]
        for proof, message in cases:
            with self.assertRaisesRegex(ValueError, message):
                sp1_v6.parse_proof_bytes(proof)
        with self.assertRaises(ValueError):
            sp1_v6.public_inputs(sp1_v6.FR, b"", 0)


if __name__ == "__main__":
    unittest.main()

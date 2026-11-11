"""SP1 mapping and legacy Python CLI regressions; no proving or key generation."""

from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "packages/groth16-verifier-sp1/python"))
import sp1


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(
            (ROOT / "packages/groth16-verifier-sp1/test/fixtures/fixed-sp1.json").read_text()
        )
        p = cls.fixture["proof"]
        words = [
            p["pi_a"][0],
            p["pi_a"][1],
            p["pi_b"][0][1],
            p["pi_b"][0][0],
            p["pi_b"][1][1],
            p["pi_b"][1][0],
            p["pi_c"][0],
            p["pi_c"][1],
        ]
        cls.wire = "0xa4594c59" + "".join(f"{int(word):064x}" for word in words)

    def test_python_mapping_retains_variable_byte_domain(self):
        self.assertEqual(
            sp1.compute_sp1_public_inputs(7, b""),
            (
                7,
                int(
                    "03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    16,
                ),
            ),
        )
        for values in (b"a", bytes(range(32)), bytes(range(65))):
            key, digest = sp1.compute_sp1_public_inputs(7, values)
            self.assertEqual(key, 7)
            self.assertLess(digest, 1 << 253)

    def test_legacy_python_decoder_domain_and_fq2_order_are_preserved(self):
        a, b, c = sp1.parse_proof_bytes(self.wire)
        proof = self.fixture["proof"]
        self.assertEqual((a.x, a.y), tuple(map(int, proof["pi_a"][:2])))
        self.assertEqual((b.x.c0, b.x.c1), tuple(map(int, proof["pi_b"][0])))
        self.assertEqual((b.y.c0, b.y.c1), tuple(map(int, proof["pi_b"][1])))
        self.assertEqual((c.x, c.y), tuple(map(int, proof["pi_c"][:2])))
        # This retained development CLI decoder is not the strict public SDK parser.
        self.assertEqual(
            sp1.parse_proof_bytes("0x00000000" + self.wire[10:] + "00"), (a, b, c)
        )
        with self.assertRaisesRegex(ValueError, "too short"):
            sp1.parse_proof_bytes(self.wire[:-2])

    def test_cli_uses_generic_math_and_validates_saved_proof(self):
        with tempfile.TemporaryDirectory(prefix="sp1-cli-test-") as temporary:
            work = Path(temporary)
            request = {
                "proof": self.wire,
                "publicValues": "0x" + bytes(self.fixture["publicValues"]).hex(),
                "vkey": "0x" + f"{int(self.fixture['vkey']):064x}",
            }
            (work / "request.json").write_text(json.dumps(request))
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "packages/groth16-verifier-sp1/python/sp1.py"),
                    "--proof-json",
                    str(work / "request.json"),
                    "--output",
                    str(work / "output.json"),
                    "--emit-fixed-lines",
                    str(work / "lines.nr"),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads((work / "output.json").read_text())
            self.assertEqual(
                set(payload), {"c", "w", "lines", "b_lines_raw", "b_line_witness"}
            )
            for name in ("c", "w"):
                self.assertEqual(len(payload[name]), 12)
                self.assertTrue(all(len(limbs) == 3 for limbs in payload[name]))
            lines = (work / "lines.nr").read_text()
            self.assertIn("fn sp1_delta_lines()", lines)
            self.assertIn("fn sp1_gamma_lines()", lines)


if __name__ == "__main__":
    unittest.main()

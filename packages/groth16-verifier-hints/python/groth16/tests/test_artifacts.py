import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from groth16.artifacts import artifact_identity


class ArtifactIdentityTests(unittest.TestCase):
    def test_file_and_bytecode_identities_are_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "artifact.json"
            key = Path(tmp) / "vk"
            key.write_bytes(b"key bytes")
            p.write_text(json.dumps({"bytecode": base64.b64encode(b"code").decode()}))
            result = artifact_identity(p, "producer", key)
            self.assertEqual(
                result["artifactSha256"], hashlib.sha256(p.read_bytes()).hexdigest()
            )
            self.assertEqual(
                result["bytecodeSha256"], hashlib.sha256(b"code").hexdigest()
            )
            self.assertEqual(
                result["verificationKeySha256"],
                hashlib.sha256(key.read_bytes()).hexdigest(),
            )

    def test_selects_unique_generated_contract_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "contract.json"
            f = {"name": "__aztec_nr_internals__verify", "bytecode": "Y29kZQ=="}
            p.write_text(
                json.dumps(
                    {"functions": [f, {"name": "constructor", "bytecode": "b3RoZXI="}]}
                )
            )
            self.assertEqual(
                artifact_identity(p, "private-consumer")["bytecodeSha256"],
                hashlib.sha256(b"code").hexdigest(),
            )
            p.write_text(json.dumps({"functions": [f, f]}))
            with self.assertRaises(ValueError):
                artifact_identity(p, "private-consumer")

    def test_rejects_malformed_or_empty_bytecode(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "artifact.json"
            for value in ("", "***"):
                p.write_text(json.dumps({"bytecode": value}))
                with self.assertRaises(ValueError):
                    artifact_identity(p, "producer")


if __name__ == "__main__":
    unittest.main()

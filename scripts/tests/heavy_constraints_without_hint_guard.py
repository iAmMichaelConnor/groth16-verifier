"""The proof-vector rejections come from constraints, not only from a hint.

The pairing-stage negative tests (A negated, a forged certificate) fail first
at a Brillig assertion: the honest quadratic-expression hint refuses a relation
with a nonzero remainder. A prover can run hints without that assertion. This
test removes it from a scratch copy of internal/bignum and runs the same tests,
now expecting the constrained carry range checks of the relation to fail. The
honest proof must still verify.

Crates: tests/fixed_multiplier_vector and tests/runtime_multiplier_vector (the
Circom proof under the fixed-key and the runtime-key verifier) and
tests/sp1_v6_vector (the SP1 v6 verifier). Set HINT_GUARD_CRATES to a
comma-separated subset to run only those.

Uses $NARGO, else `nargo` on PATH. ACVM execution only; no proof.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Package -> (workspace member, test source, test threads, tests). One honest
# proof and one test per pairing-stage rejection kind, from each crate's
# `nightly` module; input-binding rejections fail at plain constraints, which
# the hint guard does not touch, so the probe does not rerun them. One fixed-key
# or SP1 test needs about 7.6 GB.
CRATES = {
    "fixed_multiplier_vector": (
        "tests/fixed_multiplier_vector", "src/lib.nr", "1",
        ("nightly::saved_proof_verifies", "nightly::negated_a_is_rejected_by_the_pairing_check",
         "nightly::forged_certificate_is_rejected"),
    ),
    "runtime_multiplier_vector": (
        "tests/runtime_multiplier_vector", "src/lib.nr", "4",
        ("nightly::saved_proof_verifies_and_returns_the_key_hash",
         "nightly::negated_a_is_rejected_by_the_pairing_check",
         "nightly::forged_certificate_is_rejected"),
    ),
    "sp1_v6_vector": (
        "tests/sp1_v6_vector", "src/lib.nr", "1",
        ("nightly::multiply_proof_verifies", "nightly::negated_a_is_rejected_by_the_pairing_check"),
    ),
}
HINT_GUARD = (
    '    assert(__is_zero(&remainder), "Quadratic expression hint has a nonzero remainder");'
)
HINT_MESSAGE = 'should_fail_with = "Quadratic expression hint has a nonzero remainder"'
CONSTRAINT_MESSAGE = 'should_fail_with = "call to assert_max_bit_size"'


class ConstraintsWithoutHintGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        nargo = shutil.which(os.environ.get("NARGO", "nargo"))
        if not nargo:
            raise RuntimeError("Put nargo on PATH or set NARGO to its path")
        cls.nargo = str(Path(nargo).resolve())

    def test_negative_vectors_fail_at_constraints(self):
        selected = os.environ.get("HINT_GUARD_CRATES")
        crates = {
            name: entry for name, entry in CRATES.items()
            if not selected or name in selected.split(",")
        }
        self.assertTrue(crates, "HINT_GUARD_CRATES names no known crate")
        with tempfile.TemporaryDirectory(prefix="groth16-no-hint-guard-") as work:
            root = Path(work)
            ignore = shutil.ignore_patterns("target")
            shutil.copytree(ROOT / "noir", root / "noir", ignore=ignore)
            members = []
            for crate, (member, source_path, _, tests) in crates.items():
                if not (root / member).exists():
                    shutil.copytree(ROOT / member, root / member, ignore=ignore)
                members.append(f'"{member}"')
                lib = root / member / source_path
                source = lib.read_text()
                self.assertGreaterEqual(source.count(HINT_MESSAGE), len(tests) - 1, crate)
                lib.write_text(source.replace(HINT_MESSAGE, CONSTRAINT_MESSAGE))
            (root / "Nargo.toml").write_text(
                "[workspace]\nmembers = [" + ", ".join(members) + "]\n"
            )
            expressions = root / "noir/internal/bignum/src/fns/expressions.nr"
            text = expressions.read_text()
            self.assertEqual(text.count(HINT_GUARD), 1)
            expressions.write_text(text.replace(HINT_GUARD, "    // Hint guard removed."))
            # One package at a time keeps the peak memory to one crate's tests.
            for crate, (_, _, threads, tests) in crates.items():
                result = subprocess.run(
                    [self.nargo, "test", "--package", crate, "--test-threads", threads, *tests],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=3600,
                )
                log = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
                self.assertEqual(result.returncode, 0, log[-4000:])
                for name in tests:
                    self.assertRegex(log, rf"Testing {name} \.\.\. ok", f"{crate}: {name}")
                self.assertEqual(log.count("Testing "), len(tests), crate)


if __name__ == "__main__":
    unittest.main()

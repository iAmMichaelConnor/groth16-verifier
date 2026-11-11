"""Host checks for the pairing geometry.

The private Miller schedule needs no denominator guards.

scripts/tests/check_schedule_denominators.py recomputes the scalar and norm gcds from
noir/bn254_fields/src/fp.nr. This test runs it on the real digits, checks that it rejects
a changed schedule, and checks that the fixed and runtime copies of the
unguarded schedule geometry stay byte-identical. It also checks that the G2
subgroup-helper vectors in noir/bn254_g2/src/g2.nr are the ones that
scripts/tests/g2_subgroup_vectors.py verifies. Host only; no nargo.
"""

import ast
import contextlib
import importlib.util
import io
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/tests/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load("check_schedule_denominators")
vectors = load("g2_subgroup_vectors")
GEOMETRY = (
    ROOT / "noir/groth16/src/optimized/global_pairing/schedule_geometry.nr",
    ROOT / "noir/internal/runtime_pairing/src/schedule_geometry.nr",
)


class ScheduleDenominatorTest(unittest.TestCase):
    def test_current_schedule_has_no_zero_denominator(self):
        self.assertEqual(tool.check(), [])

    def test_changed_digits_are_rejected(self):
        text = tool.FP.read_text()
        start = text.index("pub fn miller_loop_digits()")
        # Flip the first nonzero digit after the prefix: 6x+2 no longer holds.
        head, tail = text[:start], text[start:]
        changed = tail.replace("0i8, 0, 0, 1,", "0i8, 0, 0, -1,", 1)
        self.assertNotEqual(changed, tail)
        self.assertIn("digits do not encode 6x+2", tool.check(head + changed))

    def test_unguarded_geometry_copies_match(self):
        self.assertEqual(GEOMETRY[0].read_bytes(), GEOMETRY[1].read_bytes())
        self.assertNotIn("line_nonzero", GEOMETRY[0].read_text())

    def test_tool_models_the_fixed_schedule(self):
        # The tool models this call sequence by hand; fail if the code changes.
        source = (
            ROOT / "noir/groth16/src/optimized/global_pairing.nr"
        ).read_text()
        steps = [
            "double_step(b)",
            "line_compute(point, neg_g2_affine(b))",
            "add_step(point, b)",
            "for i in 0..63",
            "digits[62 - idx]",
            "double_step(point)",
            "add_step(point, if digit == 1 { b } else { bn })",
            "add_step(point, frobenius_g2(b))",
            "let q2 = frobenius_square_g2(b);",
            "line_with_endpoint(point, q2, frobenius_g2(q2))",
        ]
        position = 0
        for step in steps:
            position = source.index(step, position)

    def test_g2_vectors_match_the_checked_points(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vectors.main()  # asserts the off-twist and generator properties
        source = (ROOT / "noir/bn254_g2/src/g2.nr").read_text()
        tests = source[source.index("fn subgroup_helpers_reject_off_twist") :]
        found = re.findall(
            r"fp_from_limbs_checked\(\s*\[\s*"
            r"(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*,?\s*"
            r"\]\s*\)",
            tests,
        )
        expected = []
        for line in out.getvalue().splitlines():
            expected += [tuple(c) for c in ast.literal_eval(line.split(" ", 1)[1])]
        self.assertEqual(found, expected)


if __name__ == "__main__":
    unittest.main()

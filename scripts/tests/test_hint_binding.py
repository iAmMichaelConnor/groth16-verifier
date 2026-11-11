"""CurveJ equality must not take its result from a Brillig hint.

A Brillig hint is prover-controlled: a malicious prover can run any
unconstrained code. This test models that by replacing the BigNum `__eq`
method hint in a scratch copy of internal/bignum with one that inverts the
honest answer. It then executes `CurveJ::from(p) == CurveJ::from(q)` in each
bigcurve copy with nargo (ACVM execution only; no proof).

The constrained result must not move: G against 2G stays false and G against
G stays true. An `Eq` body made only of `__mul` and `__eq` hints would let the
inverted hint flip both outputs.

Uses $NARGO, else `nargo` on PATH.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

INTERNAL = Path(__file__).resolve().parents[2] / "noir/internal"
COPIES = ("bigcurve_fixed", "bigcurve_runtime_signed")
HONEST_HINT = "$crate::internal::__eq(&self.get_limbs(), &other.get_limbs())"
INVERTED_HINT = "!$crate::internal::__eq(&self.get_limbs(), &other.get_limbs())"

# BN254 G1 (y^2 = x^3 + 3 over Fq): generator G = (1, 2) and 2G by the tangent rule.
Q = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47
G = (1, 2)
_LAMBDA = 3 * G[0] * G[0] * pow(2 * G[1], -1, Q) % Q
_X2 = (_LAMBDA * _LAMBDA - 2 * G[0]) % Q
TWO_G = (_X2, (_LAMBDA * (G[0] - _X2) - G[1]) % Q)
assert (TWO_G[1] ** 2 - TWO_G[0] ** 3 - 3) % Q == 0

PROBE = """use bignum::{BigNum, BN254_Fq as Fp};
use bigcurve::{BigCurve, BN254};
use bigcurve::internal::CurveJ;

fn main(a: [[u128; 3]; 2], b: [[u128; 3]; 2]) -> pub bool {
    let p = BN254::from_coordinates(Fp::from_limbs(a[0]), Fp::from_limbs(a[1]), false);
    let q = BN254::from_coordinates(Fp::from_limbs(b[0]), Fp::from_limbs(b[1]), false);
    CurveJ::<Fp, BN254>::from(p) == CurveJ::<Fp, BN254>::from(q)
}
"""


def limbs(value):
    return [str((value >> (120 * i)) & ((1 << 120) - 1)) for i in range(3)]


def point_toml(name, point):
    rows = ", ".join("[" + ", ".join(f'"{x}"' for x in limbs(c)) + "]" for c in point)
    return f"{name} = [{rows}]\n"


def copy_package(source, destination):
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("target"))


class CurveJEqualityHintBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        nargo = shutil.which(os.environ.get("NARGO", "nargo"))
        if not nargo:
            raise RuntimeError("Put nargo on PATH or set NARGO to its path")
        cls.nargo = str(Path(nargo).resolve())

    def run_probe(self, root, name, p, q):
        prover = root / "probe" / f"{name}.toml"
        prover.write_text(point_toml("a", p) + point_toml("b", q))
        result = subprocess.run(
            [self.nargo, "execute", "--prover-name", name],
            cwd=root / "probe",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=90,
        )
        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        found = re.findall(r"Circuit output: (true|false)", result.stdout)
        self.assertEqual(len(found), 1, result.stdout[-2000:])
        return found[0] == "true"

    def test_inverted_eq_hint_does_not_change_curvej_equality(self):
        for copy in COPIES:
            with self.subTest(copy=copy), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                copy_package(INTERNAL / "bignum", root / "bignum")
                copy_package(INTERNAL / copy, root / copy)
                source = root / "bignum/src/bignum.nr"
                text = source.read_text()
                self.assertEqual(
                    text.count(HONEST_HINT), 1, "BigNum __eq hint not found"
                )
                source.write_text(text.replace(HONEST_HINT, INVERTED_HINT))
                (root / "probe/src").mkdir(parents=True)
                (root / "probe/Nargo.toml").write_text(
                    '[package]\nname = "curvej_eq_probe"\ntype = "bin"\nauthors = [""]\n\n'
                    "[dependencies]\n"
                    'bignum = { path = "../bignum" }\n'
                    f'bigcurve = {{ path = "../{copy}" }}\n'
                )
                (root / "probe/src/main.nr").write_text(PROBE)
                # 2G differs from G in x and in y, so the inverted hint claims
                # both coordinate checks hold.
                self.assertFalse(self.run_probe(root, "distinct", G, TWO_G))
                self.assertTrue(self.run_probe(root, "same", G, G))


if __name__ == "__main__":
    unittest.main()

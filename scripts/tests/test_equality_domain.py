"""Integer model of imported three-limb equality; no Noir/reachability proof.

Protect valid noncanonical aliases below 2^254. A wider alias is outside this
imported contract, even though a generic upstream API may deliberately accept it.
"""

from pathlib import Path
import random
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "noir/internal/bignum/src"
B = 1 << 120
M = 1 << 254


def limbs_value(body):
    limbs = [int(x.strip(), 0) for x in body.split(",") if x.strip()]
    assert len(limbs) == 3
    return sum(limb * B**i for i, limb in enumerate(limbs))


params = (SOURCE / "fields/bn254Fq.nr").read_text()
Q = limbs_value(re.search(r"\bmodulus:\s*\[([^]]+)\]", params).group(1))
constants = (SOURCE / "constants.nr").read_text()
R = limbs_value(re.search(r"GRUMPKIN_MODULUS[^=]*=\s*\[([^]]+)\]", constants).group(1))


def equality_model(x, y, modulus=Q, bits=254):
    if not (0 <= x < 1 << bits and 0 <= y < 1 << bits):
        raise ValueError("Outside the imported limb-width domain")
    high = x // (B * B) - y // (B * B)
    difference = (x - y) % R
    positive = high - modulus // (B * B)
    negative = high + modulus // (B * B)
    return (
        (difference == 0 and high == 0)
        or (difference == modulus % R and positive * (positive - 1) % R == 0)
        or (difference == -modulus % R and negative * (negative + 1) % R == 0)
    )


class EqualityDomainTests(unittest.TestCase):
    def test_actual_modulus_normalization_and_residual_bounds(self):
        self.assertRegex(params, r"derive_bignum\(3,\s*254,")
        self.assertLess(1 << 253, Q)
        self.assertLess(Q, M)
        self.assertLess(M, 2 * Q)
        self.assertLess(1 << 241, R)
        self.assertLess(R, Q)

    def test_valid_lazy_aliases_must_still_pass(self):
        for a, b in [(0, Q), (1, Q + 1), (M - Q - 1, M - 1)]:
            with self.subTest(a=a, b=b):
                self.assertTrue(equality_model(a, b))
                self.assertTrue(equality_model(b, a))

    def test_native_field_aliases_are_not_modular_equality(self):
        for a, b in [(0, R), (0, Q - R), (1, R + 1)]:
            with self.subTest(a=a, b=b):
                self.assertNotEqual(a % Q, b % Q)
                self.assertFalse(equality_model(a, b))
                self.assertFalse(equality_model(b, a))

    def test_wider_upstream_alias_is_outside_this_model_domain(self):
        a, b = M - Q + 1, M + 1
        self.assertEqual(a % Q, b % Q)
        with self.assertRaises(ValueError):
            equality_model(a, b)
        with self.assertRaises(ValueError):
            equality_model(b, a)

    def test_boundaries_and_deterministic_random_pairs(self):
        values = [
            0,
            1,
            Q - 1,
            Q,
            Q + 1,
            M - 1,
            M - Q - 1,
            M - Q,
            M - Q + 1,
            R - 1,
            R,
            R + 1,
        ]
        pairs = [(x, y) for x in values for y in values]
        rng = random.Random(45)
        pairs += [(rng.randrange(M), rng.randrange(M)) for _ in range(10000)]
        pairs += [(v, v + Q) for v in [0, 1, M - Q - 1]]
        self.assertEqual(len(pairs), 10147)
        for x, y in pairs:
            self.assertEqual(equality_model(x, y), (x - y) % Q == 0, (x, y))

    def test_all_retained_three_limb_parameter_sets(self):
        tested = []
        for path in sorted((SOURCE / "fields").glob("*.nr")):
            source = path.read_text()
            declaration = re.search(r"derive_bignum\(3,\s*(\d+),", source)
            if not declaration:
                continue
            bits = int(declaration[1])
            modulus = limbs_value(
                re.search(r"\bmodulus:\s*\[([^]]+)\]", source).group(1)
            )
            with self.subTest(parameter=path.stem):
                self.assertEqual(modulus.bit_length(), bits)
                self.assertTrue(240 < bits <= 360)
                self.check_normalized_domain(modulus, bits)
            tested.append(path.stem)
        # Includes the integer ring modulo 2^256, whose declared width is 257.
        self.assertIn("U256", tested)
        self.assertIn("bn254Fq", tested)
        self.assertIn("secp256k1Fq", tested)

    def test_runtime_normalization_boundaries(self):
        for bits in (241, 253, 254, 255, 257, 359, 360):
            for modulus in (1 << (bits - 1), (1 << (bits - 1)) + 1, (1 << bits) - 1):
                with self.subTest(bits=bits, modulus=modulus):
                    self.check_normalized_domain(modulus, bits)

    def test_short_modulus_breaks_the_required_single_modulus_difference(self):
        # A raw BigNumParams literal can bypass new()'s normalization check.
        # Two multiples then fit the operand envelope, beyond the 0/+q/-q cases.
        short_modulus = (1 << 252) + 17
        self.assertLess(2 * short_modulus, M)
        self.assertEqual((2 * short_modulus) % short_modulus, 0)
        self.assertFalse(equality_model(0, 2 * short_modulus, short_modulus, 254))

    def check_normalized_domain(self, modulus, bits):
        limit = 1 << bits
        self.assertLessEqual(limit, 2 * modulus)
        self.assertLess(2 * B, R)  # Signed high differences cannot alias in Field.
        self.assertLess(2 * B * B, R)  # Selected low residuals are exact integers.
        values = {
            0,
            1,
            modulus - 1,
            modulus,
            modulus + 1,
            limit - 1,
            limit - modulus - 1,
            limit - modulus,
            R - 1,
            R,
            R + 1,
        }
        values = sorted(v for v in values if 0 <= v < limit)
        pairs = [(x, y) for x in values for y in values]
        rng = random.Random(modulus)
        pairs += [(rng.randrange(limit), rng.randrange(limit)) for _ in range(500)]
        for x in (0, 1, limit - modulus - 1):
            if 0 <= x < limit - modulus:
                pairs.extend(((x, x + modulus), (x + modulus, x)))
        for x, y in pairs:
            self.assertEqual(
                equality_model(x, y, modulus, bits),
                (x - y) % modulus == 0,
                (bits, modulus, x, y),
            )


if __name__ == "__main__":
    unittest.main()

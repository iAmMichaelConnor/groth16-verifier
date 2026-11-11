"""SP1 fixed-key provenance; constants only, no circuit compilation or proof.

Sp1Key (noir/sp1/src/key.nr) delegates every FixedKey method to the
crate-private generated Key2 (generated/key.nr). The verifier computes L from
Key2's MSM data, and Key2 also carries the verification-key IC. These tests keep
the two consistent: Key2's IC must equal the IC of the saved SP1 v5 key
(groth16_vk.bin), and Key2's MSM data must be exactly what the generator derives
from that IC. The same holds for sp1::v6::Sp1V6Key (noir/sp1/src/v6.nr) and the
generated Key5 (generated/v6_key.nr) against the saved SP1 v6 key, and
sp1::v6::VK_ROOT must be the root SP1 pins for circuit version v6.1.0. The
whole of both generated key files must also equal their regeneration, which
covers the line tables, the t-preimage and the verification-key points.
"""

from pathlib import Path
import functools, hashlib, json, re, sys, unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages/groth16-verifier-hints/python"))
from groth16 import _offsets, _pairing as m, _preprocess as g

FIXED = ROOT / "noir/sp1/src"
KEY2 = FIXED / "generated/key.nr"
FIXED_KEY = FIXED / "key.nr"
SDK_DESCRIPTOR = ROOT / "packages/groth16-verifier-sp1/src/config.js"
KEY5 = FIXED / "generated/v6_key.nr"
V6 = FIXED / "v6.nr"
SDK_DESCRIPTOR_V6 = ROOT / "packages/groth16-verifier-sp1/src/config-v6.js"
V6_MANIFEST = ROOT / "fixtures/sp1-v6/manifest.json"
# The root SP1 pins for circuit version v6.1.0: VK_ROOT_BYTES in
# crates/verifier/src/lib.rs of succinctlabs/sp1 v6.10.0, and VK_ROOT() in
# contracts/src/v6.1.0/SP1VerifierGroth16.sol of succinctlabs/sp1-contracts.
SP1_V6_VK_ROOT = 0x002F850EE998974D6CC00E50CD0814B098C05BFADE466D28573240D057F25352
KEY_METHODS = [
    "verification_key",
    "msm_points",
    "msm_correction",
    "msm_correction_including_offset",
    "msm_offset_pairs",
    "gamma_lines",
    "delta_lines",
    "t_preimage",
]


def generator():
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import generate_sp1_key
    finally:
        sys.path.pop(0)
    return generate_sp1_key


def upstream_key():
    """The vendored SP1 v5 groth16_vk.bin, decoded by the key generator."""
    return generator().sp1_key()


def sdk_descriptor(source):
    """The SDK's SP1 descriptor object; it is JSON apart from trailing commas."""
    body = source[source.index("{") : source.rindex("}") + 1]
    return json.loads(re.sub(r",(\s*[\]}])", r"\1", body))


def upstream_ic():
    """The three IC points of the saved SP1 v5 key, as integer pairs."""
    return [(int(p[0]), int(p[1])) for p in upstream_key()["IC"]]


def sdk_ic(source):
    """The IC points of the SDK's SP1 descriptor (prepareSp1Key)."""
    block = source[source.index('"IC"') : source.index('"tPreimage"')]
    values = [int(v) for v in re.findall(r'"([0-9]+)"', block)]
    return [tuple(values[i : i + 2]) for i in range(0, len(values), 3)]


def impl_block(source, name, n=2):
    start = source.index(f"impl FixedKey<{n}> for {name} {{")
    depth = 0
    for i in range(start, len(source)):
        depth += {"{": 1, "}": -1}.get(source[i], 0)
        if source[i] == "}" and depth == 0:
            return source[start : i + 1]
    raise ValueError(f"unterminated impl for {name}")


def compact(source):
    """Source without comments, whitespace or trailing commas: `nargo fmt` layout
    does not matter."""
    source = re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", source))
    return re.sub(r",([\]})])", r"\1", source)


def key2_methods(key2, n=2):
    """Generated Key<n> method name -> its compacted source 'fnname()->Type{body}'."""
    source = compact(key2)
    head = f"implFixedKey<{n}>forKey{n}{{"
    start = source.index(head) + len(head)
    depth, end = 1, start
    while depth:
        depth += {"{": 1, "}": -1}.get(source[end], 0)
        end += 1
    parts = re.split(r"(?=fn\w+\(\)->)", source[start : end - 1])
    return {re.match(r"fn(\w+)\(", p).group(1): p for p in parts if p}


def sp1_key_bodies(fixed_key, name="Sp1Key", n=2):
    """Method name -> body, for the named key's methods whose body has no braces."""
    block = impl_block(fixed_key, name, n)
    return dict(re.findall(r"fn (\w+)\(\) -> [^{]+\{\s*([^{}]*?)\s*\}", block))


def problems(key2, fixed_key, descriptor):
    """Return every mismatch between the SP1 key sources; empty means consistent."""
    found = []
    ic = upstream_ic()
    if sdk_ic(descriptor) != ic:
        found.append("SDK SP1 descriptor IC differs from the saved SP1 key")
    for p in ic:
        g.point(p)
    methods = key2_methods(key2)
    expected_ic = (
        " fn verification_key()->VerifyingKey<3> {VerifyingKey{ic:["
        + ",".join(g.gp(p, "G1Affine") for p in ic)
        + "],"
    )
    if not methods.get("verification_key", "").startswith(compact(expected_ic)):
        found.append("Key2 verification_key IC differs from the saved SP1 key")
    bases, correction = g.msm_bases(ic)
    expected = g.msm_source(bases, correction) + _offsets.methods(correction, 2)[0]
    for line in expected.splitlines(keepends=True):
        name = re.match(r" fn (\w+)\(", line).group(1)
        if methods.get(name) != compact(line):
            found.append(f"Key2 {name} not derived from the saved SP1 key")
    bodies = sp1_key_bodies(fixed_key)
    for method in KEY_METHODS:
        if bodies.get(method) != f"Key2::{method}()":
            found.append(f"Sp1Key::{method} does not delegate to Key2")
    return found


@functools.cache
def regenerated(path):
    """The generated key file at `path` (KEY2 or KEY5) as the generator emits
    it now, from the saved upstream key, before formatting."""
    gk = generator()
    key, name = (gk.sp1_key(), "Key2") if path == KEY2 else (gk.sp1_key(gk.SP1_V6_VK), "Key5")
    return gk.sp1_key_file(path, gk._emit(key, name))


def same_key_file(path, source):
    """Whether `source` is the regenerated file at `path`, ignoring comments,
    layout and import order (`nargo fmt` sorts imports): every line table,
    t-preimage, verification-key point and MSM table is compared."""
    strip = lambda text: compact(re.sub(r"^use [^;]+;", "", text, flags=re.M))  # noqa: E731
    return strip(source) == strip(regenerated(path))


# Fields that the IC and MSM checks above do not cover: function or field name
# in the generated file; the first number after it gets one digit changed.
UNCOVERED_FIELDS = ["fixed_gamma_lines", "fixed_delta_lines", "fn t_preimage", "gamma_neg", "delta_neg"]


def mutate_after(source, marker):
    """`source` with one digit of the first number after `marker` changed."""
    start = source.index(marker)
    match = re.compile(r"\b(?:0x[0-9a-f]+|[0-9]{4,})\b").search(source, start)
    i = match.end() - 1
    digit = "1" if source[i] != "1" else "2"
    return source[:i] + digit + source[i + 1 :]


@functools.cache
def v6_expected():
    """The saved SP1 v6 key's IC and the provider methods derived from it."""
    key = generator().sp1_key(generator().SP1_V6_VK)
    ic = [(int(p[0]), int(p[1])) for p in key["IC"]]
    bases, correction = g.msm_bases(ic)
    return ic, g.msm_source(bases, correction) + _offsets.methods(correction, 5)[0]


def v6_problems(key5, v6, descriptor):
    """Every mismatch between the SP1 v6 key sources; empty means consistent."""
    found = []
    ic, expected = v6_expected()
    if sdk_ic(descriptor) != ic:
        found.append("SDK SP1 v6 descriptor IC differs from the saved SP1 v6 key")
    methods = key2_methods(key5, 5)
    expected_ic = (
        " fn verification_key()->VerifyingKey<6> {VerifyingKey{ic:["
        + ",".join(g.gp(p, "G1Affine") for p in ic)
        + "],"
    )
    if not methods.get("verification_key", "").startswith(compact(expected_ic)):
        found.append("Key5 verification_key IC differs from the saved SP1 v6 key")
    for line in expected.splitlines(keepends=True):
        name = re.match(r" fn (\w+)\(", line).group(1)
        if methods.get(name) != compact(line):
            found.append(f"Key5 {name} not derived from the saved SP1 v6 key")
    bodies = sp1_key_bodies(v6, "Sp1V6Key", 5)
    for method in KEY_METHODS:
        if bodies.get(method) != f"Key5::{method}()":
            found.append(f"Sp1V6Key::{method} does not delegate to Key5")
    root = re.search(r"pub global VK_ROOT: Field = (0x[0-9a-f]+);", key5)
    if not root or int(root.group(1), 16) != SP1_V6_VK_ROOT:
        found.append("Key5 VK_ROOT is not the root SP1 pins for v6.1.0")
    return found


class Sp1KeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = [p.read_text() for p in [KEY2, FIXED_KEY, SDK_DESCRIPTOR]]

    def test_sp1_key_has_one_consistent_source(self):
        self.assertEqual(problems(*self.sources), [])

    def test_sdk_descriptor_is_the_upstream_sp1_key(self):
        # Check the SDK descriptor's whole key and t-preimage against the saved
        # upstream key bytes.
        descriptor = sdk_descriptor(self.sources[2])
        key = upstream_key()
        self.assertEqual(descriptor["verificationKey"], key)
        alpha, beta = g.point(key["vk_alpha_1"]), g.twist(key["vk_beta_2"])
        target = m.final_exponentiation(m.miller_loop([m.G1Affine(*alpha)], [beta]))
        preimage = m.compute_t_preimage(target)
        self.assertEqual(
            descriptor["tPreimage"], [str(v) for v in m.fp12_to_coeffs(preimage)]
        )

    def test_drifted_key2_rows_are_detected(self):
        # Rows for K' = K + IC1 make the private path accept the statement for
        # program vkey + 1 when given vkey.
        key2, fixed_key, descriptor = self.sources
        ic = upstream_ic()
        _, correction = g.msm_bases(ic)
        good, _ = _offsets.methods(correction, 2)
        bad, _ = _offsets.methods(g.add(correction, ic[1]), 2)
        good_rows = [l for l in good.splitlines(True) if "msm_offset_pairs" in l][0]
        bad_rows = [l for l in bad.splitlines(True) if "msm_offset_pairs" in l][0]
        self.assertEqual(compact(key2).count(compact(good_rows)), 1)
        drifted = compact(key2).replace(compact(good_rows), compact(bad_rows))
        self.assertIn(
            "Key2 msm_offset_pairs not derived from the saved SP1 key",
            problems(drifted, fixed_key, descriptor),
        )

    def test_hand_copied_sp1_literals_are_detected(self):
        key2, fixed_key, descriptor = self.sources
        copied = fixed_key.replace(
            "Key2::msm_correction()",
            "Half { x: Fp::from_limbs([1, 0, 0]), y: Fp::from_limbs([2, 0, 0]), is_infinity: false }",
        )
        self.assertIn(
            "Sp1Key::msm_correction does not delegate to Key2",
            problems(key2, copied, descriptor),
        )

    def test_swapped_delegation_is_detected(self):
        key2, fixed_key, descriptor = self.sources
        a = "Key2::msm_correction()"
        b = "Key2::msm_correction_including_offset()"
        swapped = fixed_key.replace(a, "@").replace(b, a).replace("@", b)
        self.assertEqual(
            problems(key2, swapped, descriptor),
            [
                "Sp1Key::msm_correction does not delegate to Key2",
                "Sp1Key::msm_correction_including_offset does not delegate to Key2",
            ],
        )

    def test_stale_copy_in_a_comment_does_not_hide_drift(self):
        key2, fixed_key, descriptor = self.sources
        methods = key2_methods(key2)
        line = methods["msm_correction"]
        drifted = compact(key2).replace(
            line, line.replace("is_infinity:false", "is_infinity:true")
        )
        drifted = "//" + line + "\n" + drifted
        self.assertIn(
            "Key2 msm_correction not derived from the saved SP1 key",
            problems(drifted, fixed_key, descriptor),
        )


class WholeKeyFileTests(unittest.TestCase):
    """Each generated key file equals its regeneration, so a changed digit in a
    line table, the t-preimage or a verification-key point is detected here
    as well as by `scripts/generate.py --check`."""

    def test_key_files_are_regenerated_exactly(self):
        for path in (KEY2, KEY5):
            self.assertTrue(same_key_file(path, path.read_text()), path.name)

    def test_one_changed_digit_in_each_uncovered_field_is_detected(self):
        for path in (KEY2, KEY5):
            source = path.read_text()
            for marker in UNCOVERED_FIELDS:
                mutated = mutate_after(source, marker)
                self.assertNotEqual(mutated, source)
                self.assertFalse(same_key_file(path, mutated), f"{path.name}: {marker}")


class Sp1V6KeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = [p.read_text() for p in [KEY5, V6, SDK_DESCRIPTOR_V6]]

    def test_sp1_v6_key_has_one_consistent_source(self):
        self.assertEqual(v6_problems(*self.sources), [])

    def test_sdk_descriptor_is_the_upstream_sp1_v6_key(self):
        descriptor = sdk_descriptor(self.sources[2])
        key = generator().sp1_key(generator().SP1_V6_VK)
        self.assertEqual(descriptor["verificationKey"], key)
        alpha, beta = g.point(key["vk_alpha_1"]), g.twist(key["vk_beta_2"])
        target = m.final_exponentiation(m.miller_loop([m.G1Affine(*alpha)], [beta]))
        self.assertEqual(
            descriptor["tPreimage"],
            [str(v) for v in m.fp12_to_coeffs(m.compute_t_preimage(target))],
        )

    def test_vk_root_derives_from_the_saved_recursion_keys(self):
        self.assertEqual(generator().sp1_v6_vk_root(), SP1_V6_VK_ROOT)

    def test_saved_files_match_the_manifest(self):
        files = json.loads(V6_MANIFEST.read_text())["files"]
        for name, entry in files.items():
            data = (V6_MANIFEST.parent / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"], name)

    def test_drifted_root_and_delegation_are_detected(self):
        key5, v6, descriptor = self.sources
        drifted = key5.replace(f"{SP1_V6_VK_ROOT:064x}", f"{SP1_V6_VK_ROOT + 1:064x}")
        self.assertIn(
            "Key5 VK_ROOT is not the root SP1 pins for v6.1.0",
            v6_problems(drifted, v6, descriptor),
        )
        copied = v6.replace("Key5::t_preimage()", "Key5::t_preimage().conjugate()")
        self.assertIn(
            "Sp1V6Key::t_preimage does not delegate to Key5",
            v6_problems(key5, copied, descriptor),
        )


if __name__ == "__main__":
    unittest.main()

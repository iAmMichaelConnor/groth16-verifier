"""Consumer generation tests; no circuit compilation, setup or proof generation."""

from pathlib import Path
import copy, json, os, subprocess, sys, tempfile, unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from groth16 import _preprocess
from groth16.generate import GenerationError, GenerationWarning, generate

ROOT = Path(__file__).resolve().parents[5]
Q = _preprocess.q


def negate_g2(p):
    return [p[0], [str((-int(v)) % Q) for v in p[1]], *p[2:]]


def generator_g2():
    # The canonical BN254 G2 generator (EIP-197), snarkjs real/imaginary order.
    return [
        [
            "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            "11559732032986387107991004021392285783925812861821192530917403151452391805634",
        ],
        [
            "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            "4082367875863433681332203403145435568316851327593401208105741076214120093531",
        ],
        ["1", "0"],
    ]


def nonsubgroup_g2():
    """First point on the twist with x = (k, 0) that is outside the r-subgroup."""
    m = _preprocess.m

    def power(a, e):
        out = m.Fp2(1, 0)
        while e:
            if e & 1:
                out = out.mul(a)
            a = a.square()
            e >>= 1
        return out

    b = m.Fp2(3, 0).mul(m.Fp2(9, 1).inverse())
    for k in range(1, 1000):
        x = m.Fp2(k, 0)
        rhs = x.square().mul(x).add(b)
        # Fp2 square root for p = 3 mod 4 (Adj and Rodriguez-Henriquez, Alg. 9).
        a1 = power(rhs, (Q - 3) // 4)
        alpha = a1.square().mul(rhs)
        x0 = a1.mul(rhs)
        if (alpha.c0, alpha.c1) == (Q - 1, 0):
            y = m.Fp2(0, 1).mul(x0)
        else:
            y = power(alpha.add(m.Fp2(1, 0)), (Q - 1) // 2).mul(x0)
        if y.square() == rhs and _preprocess.g2mul(_preprocess.r, (x, y)) is not None:
            return [[str(x.c0), str(x.c1)], [str(y.c0), str(y.c1)], ["1", "0"]]
    raise AssertionError("no non-subgroup twist point found")


def degenerate_keys(key):
    """Keys that pass every per-point check but are degenerate."""
    cases = {}
    k = copy.deepcopy(key)
    k["vk_delta_2"] = k["vk_gamma_2"]
    cases["delta_eq_gamma"] = k
    k = copy.deepcopy(key)
    k["vk_delta_2"] = negate_g2(k["vk_gamma_2"])
    cases["delta_eq_neg_gamma"] = k
    k = copy.deepcopy(key)
    k["vk_gamma_2"] = k["vk_beta_2"]  # gamma is no longer the generator
    k["vk_delta_2"] = generator_g2()
    cases["delta_eq_generator"] = k
    k = copy.deepcopy(key)
    k["vk_gamma_2"] = k["vk_beta_2"]
    k["vk_delta_2"] = negate_g2(generator_g2())
    cases["delta_eq_neg_generator"] = k
    k = copy.deepcopy(key)
    k["IC"] = [["0", "1", "0"] for _ in k["IC"]]
    cases["all_ic_infinity"] = k
    k = copy.deepcopy(key)
    k["nPublic"] = 0
    k["IC"] = [["0", "0"]]
    cases["n0_ic0_infinity"] = k
    return cases


class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = json.loads(
            (ROOT / "fixtures/multiplier/verification_key.json").read_text()
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_key(self, key=None, **kw):
        path = self.root / "vk.json"
        path.write_text(json.dumps(self.key if key is None else key))
        out = self.root / "generated"
        record = generate(path, out, **kw)
        return out, record

    def test_genuine_and_deterministic_provider(self):
        out, record = self.run_key(dependency_alias="verifier", provider_name="AppKey")
        source = (out / "application_key.nr").read_text()
        self.assertIn("use verifier::provider::", source)
        self.assertIn("pub struct AppKey", source)
        self.assertNotIn("use crate::", source)
        self.assertNotIn("noir_bn254_pairing::", source)
        self.assertEqual(
            json.loads((out / "key.json").read_text())["schema"], "groth16-fixed-key-v1"
        )
        other = self.root / "other"
        again = generate(
            self.root / "vk.json",
            other,
            dependency_alias="verifier",
            provider_name="AppKey",
        )
        self.assertEqual(record, again)
        for name in record["files"]:
            self.assertEqual((out / name).read_bytes(), (other / name).read_bytes())
        with self.assertRaises(GenerationError):
            generate(self.root / "vk.json", out)

    def test_n0_direct_policy(self):
        key = copy.deepcopy(self.key)
        key["nPublic"] = 0
        key["IC"] = key["IC"][:1]
        out, _ = self.run_key(key)
        record = json.loads((out / "preprocessing.json").read_text())
        self.assertEqual(record["candidateCount"], 1)
        self.assertEqual(record["fixedBases"], [])

    def test_unused_ic_and_n3(self):
        key = copy.deepcopy(self.key)
        key["nPublic"] = 3
        key["IC"] = [key["IC"][0], ["0", "1", "0"], key["IC"][1], ["0", "0"]]
        out, _ = self.run_key(key)
        record = json.loads((out / "preprocessing.json").read_text())
        self.assertEqual(record["candidateCount"], 409)
        self.assertEqual(record["fixedBases"][:4], [None] * 4)
        self.assertEqual(record["fixedBases"][8:], [None] * 4)

    def test_runtime_has_no_provider_or_fixed_configuration(self):
        out, record = self.run_key(key_policy="runtime")
        self.assertFalse((out / "application_key.nr").exists())
        self.assertIsNone(record["providerName"])
        profile = json.loads((out / "profile.json").read_text())
        self.assertIsNone(profile["configurationHash"])
        self.assertEqual(profile["schema"], "groth16-verifier-profile-v2")

    def test_private_and_offchain_profiles_use_stock_v6_release(self):
        for mode in ["private", "offchain"]:
            with self.subTest(mode=mode):
                path = self.root / "vk.json"
                path.write_text(json.dumps(self.key))
                out = self.root / f"generated-{mode}"
                generate(path, out, mode=mode, key_policy="runtime")
                profile = json.loads((out / "profile.json").read_text())
                self.assertEqual(profile["toolchain"]["backend"], "stock-v6")
                self.assertEqual(
                    profile["toolchain"]["aztecCommit"],
                    "0219f11d8133970df3974fe5ae65e006bf8c193a",
                )

    def test_malformed_keys_leave_no_output(self):
        cases = []
        for count in [-1, 257, 1.5, True]:
            key = copy.deepcopy(self.key)
            key["nPublic"] = count
            cases.append(key)
        key = copy.deepcopy(self.key)
        key["IC"] = []
        cases.append(key)
        key = copy.deepcopy(self.key)
        key["vk_alpha_1"] = ["0", "0"]
        cases.append(key)
        key = copy.deepcopy(self.key)
        key["vk_alpha_1"][0] = "01"
        cases.append(key)
        key = copy.deepcopy(self.key)
        key["vk_alpha_1"][0] = 1
        cases.append(key)
        key = copy.deepcopy(self.key)
        key["unknown"] = 1
        cases.append(key)
        key = copy.deepcopy(self.key)
        key["IC"][0] = ["1", "3"]
        cases.append(key)
        key = copy.deepcopy(self.key)
        key["vk_beta_2"] = [["0", "0"], ["0", "0"]]
        cases.append(key)
        for key in cases:
            with self.subTest(key=key):
                with self.assertRaises(GenerationError):
                    self.run_key(key)
                self.assertFalse((self.root / "generated").exists())

    def test_degenerate_keys_rejected_by_sdk_and_preprocessing(self):
        # The fixture is a snarkjs key: gamma is the generator, delta is contributed.
        self.assertEqual(self.key["vk_gamma_2"], generator_g2())
        for name, key in degenerate_keys(self.key).items():
            with self.subTest(name=name, path="generate"):
                with self.assertRaises(GenerationError):
                    self.run_key(key)
                self.assertFalse((self.root / "generated").exists())
            # The Python preprocessing checks the same relations on its own.
            with self.subTest(name=name, path="_preprocess"):
                path = self.root / f"{name}.json"
                path.write_text(json.dumps(key))
                with self.assertRaises(ValueError):
                    _preprocess.generate(path, "X", self.root / name / "k.nr")

    def test_ic0_infinity_is_accepted_with_a_recorded_limitation(self):
        key = copy.deepcopy(self.key)
        key["IC"][0] = ["0", "1", "0"]
        with self.assertWarns(GenerationWarning):
            _, record = self.run_key(key)
        self.assertEqual(len(record["limitations"]), 1)
        path = self.root / "vk.json"
        path.write_text(json.dumps(self.key))
        self.assertNotIn("limitations", generate(path, self.root / "plain"))

    def test_finite_l_policy_is_kept_in_the_verifier(self):
        # Generator rejection of identically-infinite L and the verifier's
        # finite-L requirement belong together: admitting L = O in the verifier
        # would allow A = C = alpha, B = beta + delta for every key.
        entry = ROOT / "noir/groth16/src/optimized/entry.nr"
        self.assertIn(
            'assert(!points[2].is_infinity(), "Groth16 input MSM must be finite");',
            entry.read_text(),
        )

    def test_preprocessing_checks_survive_python_optimize(self):
        # Validation must not be a bare assert, which python -O removes.
        cases = degenerate_keys(self.key)
        k = copy.deepcopy(self.key)
        k["vk_alpha_1"][0] = str(int(k["vk_alpha_1"][0]) + Q)
        cases["alpha_x_plus_q"] = k
        k = copy.deepcopy(self.key)
        k["IC"] = k["IC"][:-1]
        cases["ic_short"] = k
        k = copy.deepcopy(self.key)
        k["vk_beta_2"] = nonsubgroup_g2()
        cases["beta_nonsubgroup"] = k
        script = (
            "import json, pathlib, sys\n"
            "from groth16 import _preprocess\n"
            "if not sys.flags.optimize: raise SystemExit('expected python -O')\n"
            "out = pathlib.Path(sys.argv[1])\n"
            "for name in json.loads(sys.argv[2]):\n"
            "    try:\n"
            "        _preprocess.generate(out / f'{name}.json', 'X', out / name / 'k.nr')\n"
            "        print('EMITTED', name)\n"
            "    except ValueError:\n"
            "        print('REJECTED', name)\n"
        )
        for name, key in cases.items():
            (self.root / f"{name}.json").write_text(json.dumps(key))
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        result = subprocess.run(
            [
                sys.executable,
                "-O",
                "-c",
                script,
                str(self.root),
                json.dumps(list(cases)),
            ],
            cwd=ROOT / "packages/groth16-verifier-hints/python",
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=True,
        )
        self.assertEqual(
            result.stdout.split("\n")[:-1], [f"REJECTED {name}" for name in cases]
        )

    def test_invalid_configuration(self):
        for args in [
            {"name": "Bad Name"},
            {"provider_name": "bad"},
            {"dependency_alias": "a::b"},
            {"dependency_alias": "crate"},
            {"mode": "public"},
            {"key_policy": "untrusted"},
        ]:
            with self.subTest(args=args):
                with self.assertRaises(GenerationError):
                    self.run_key(**args)

    def test_duplicate_properties(self):
        path = self.root / "vk.json"
        path.write_text('{"nPublic":0,"nPublic":1}')
        with self.assertRaises(GenerationError):
            generate(path, self.root / "out")


if __name__ == "__main__":
    unittest.main()

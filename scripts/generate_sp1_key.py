#!/usr/bin/env python3
"""Generate the fixed-key Noir providers that the Groth16 checks compile.

Outputs, all deterministic (no randomness, no proving, no setup):

- noir/sp1/src/generated/key.nr: the crate-private SP1 v5
  key data behind sp1::Sp1Key, from the saved upstream
  fixtures/sp1-v5/groth16_vk.bin.
- noir/sp1/src/generated/v6_key.nr: the crate-private SP1 v6 key data behind
  sp1::v6::verify (its crate-private Sp1V6Key), from the saved upstream fixtures/sp1-v6/groth16_vk.bin,
  and the pinned recursion verification-key root sp1::v6::VK_ROOT, from the
  saved upstream fixtures/sp1-v6/verifier_vks.bin.
- tests/sp1_api_typecheck/src/test_keys/*.nr: TEST ONLY providers of
  several shapes for the sp1_api_typecheck typechecks.

The test keys reuse the alpha, beta, gamma and delta of the Circom multiplier
fixture or of SP1 v5, and choose their IC points by construction. They have no
trusted setup; nobody can or should prove against them. Each shape exercises
the provider emission for one case of the MSM preprocessing (the groth16 hint
package's _preprocess.py and _offsets.py, which this script calls unchanged):

  key1, n0   the multiplier key, and its IC0 alone as an N=0 key
  key3       SP1 v5 with IC3 = 19*G1 appended (N=3)
  n1_ic0_infinity   IC0 at infinity with a finite IC1 (accepted with a warning)
  n1_exception, n3_exception   IC points that are small multiples of the first
             offset origin O, so the offset rows meet exceptional additions
  n1_j_infinity     IC0 chosen so that the first offset row's J is infinity
  n1_k_infinity     IC0 chosen so that the bias correction K is infinity

Run: python3 scripts/generate_sp1_key.py [--check]
--check regenerates into memory and reports drift; it writes nothing.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import json
from pathlib import Path
import re
import sys
import tempfile

LIB = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(LIB / "packages/groth16-verifier-hints/python"))
sys.path.insert(0, str(LIB / "scripts"))
from groth16 import _offsets, _pairing as m, _preprocess as g  # noqa: E402
from noir_format import format_noir  # noqa: E402

q = g.q
SP1_VK = LIB / "fixtures/sp1-v5/groth16_vk.bin"
SP1_V6_VK = LIB / "fixtures/sp1-v6/groth16_vk.bin"
SP1_V6_VKS = LIB / "fixtures/sp1-v6/verifier_vks.bin"
MULTIPLIER_VK = LIB / "fixtures/multiplier/verification_key.json"
KEY2 = LIB / "noir/sp1/src/generated/key.nr"
KEY5 = LIB / "noir/sp1/src/generated/v6_key.nr"
TEST_KEYS = LIB / "tests/sp1_api_typecheck/src/test_keys"
SELF = "scripts/generate_sp1_key.py"

PROVIDER_IMPORTS = """use groth16::provider::{
    VerifyingKey, FixedKey, Half, Fp, Fp2, Fp6, Fp12, G1Affine, G2Affine, LineEvaluation,
    LineScheduleRaw, BigNum,
};
"""

KEY2_HEADER = f"""// SP1 v5 key data. Crate-private; applications use sp1::Sp1Key, which delegates
// every FixedKey method to Key2. Generated from the saved SP1 v5 key
// (fixtures/sp1-v5) by
// {SELF}; do not edit.
// scripts/tests/test_sp1_key.py checks the IC against that key and that the
// MSM data derive from it.
"""

KEY5_HEADER = f"""// SP1 v6 key data. Crate-private; applications use sp1::v6::verify, whose
// crate-private key Sp1V6Key delegates every FixedKey method to Key5, and
// sp1::v6::VK_ROOT. Generated from the saved SP1 v6 key and recursion key data
// (fixtures/sp1-v6) by
// {SELF}; do not edit.
// scripts/tests/test_sp1_key.py checks the IC against that key, that the MSM
// data derive from it, and VK_ROOT against the root SP1 pins.
"""

# --- SP1 verification keys (gnark compressed encoding) -----------------------


def _fp2_pow(a: m.Fp2, e: int) -> m.Fp2:
    out = m.Fp2(1, 0)
    while e:
        if e & 1:
            out = out.mul(a)
        a = a.square()
        e >>= 1
    return out


def _fp2_sqrt(a: m.Fp2) -> m.Fp2:
    """Square root in Fq2 = Fq[i]/(i^2+1), q = 3 mod 4 (Adj, Rodriguez-Henriquez, alg. 9)."""
    a1 = _fp2_pow(a, (q - 3) // 4)
    alpha = a1.square().mul(a)
    x0 = a1.mul(a)
    if alpha == m.Fp2(q - 1, 0):
        x = m.Fp2(0, 1).mul(x0)
    else:
        x = _fp2_pow(alpha.add(m.Fp2(1, 0)), (q - 1) // 2).mul(x0)
    g.require(x.square() == a, "G2 x has no point on the twist")
    return x


def _largest(v: int) -> bool:
    return v > (q - 1) // 2


def _g1(data: bytes) -> list[str]:
    flag, x = data[0] >> 6, int.from_bytes(bytes([data[0] & 0x3F]) + data[1:32], "big")
    g.require(flag in (2, 3) and x < q, "Expected a compressed finite G1 point")
    y = pow((x**3 + 3) % q, (q + 1) // 4, q)
    g.require(y * y % q == (x**3 + 3) % q, "G1 x has no point on the curve")
    if _largest(y) != (flag == 3):
        y = q - y
    return [str(x), str(y), "1"]


def _g2(data: bytes) -> list[list[str]]:
    flag = data[0] >> 6
    x1 = int.from_bytes(bytes([data[0] & 0x3F]) + data[1:32], "big")
    x0 = int.from_bytes(data[32:64], "big")
    g.require(
        flag in (2, 3) and x0 < q and x1 < q, "Expected a compressed finite G2 point"
    )
    x = m.Fp2(x0, x1)
    b = m.Fp2(3, 0).mul(m.Fp2(9, 1).inverse())
    y = _fp2_sqrt(x.square().mul(x).add(b))
    # gnark orders Fq2 lexicographically by the imaginary part, then the real part.
    largest = _largest(y.c1) if y.c1 else _largest(y.c0)
    if largest != (flag == 3):
        y = y.neg()
    return [[str(x.c0), str(x.c1)], [str(y.c0), str(y.c1)], ["1", "0"]]


def sp1_key(path: Path = SP1_VK) -> dict:
    """The snarkjs-form key of an SP1 groth16_vk.bin (gnark VerifyingKey.WriteTo).

    Layout: G1.Alpha, G1.Beta, G2.Beta, G2.Gamma, G1.Delta, G2.Delta, u32 count
    and the K (IC) points, then an empty commitment section.
    """
    raw = path.read_bytes()
    count = int.from_bytes(raw[288:292], "big")
    end = 292 + 32 * count
    g.require(raw[end:] == bytes(8), "SP1 key has commitments; not supported")
    return {
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": count - 1,
        "vk_alpha_1": _g1(raw[0:32]),
        "vk_beta_2": _g2(raw[64:128]),
        "vk_gamma_2": _g2(raw[128:192]),
        "vk_delta_2": _g2(raw[224:288]),
        "IC": [_g1(raw[i : i + 32]) for i in range(292, end, 32)],
    }


def sp1_v6_vk_root() -> int:
    """The recursion verification-key root that SP1 v6 binds as public input 3.

    verifier_vks.bin is the bincode encoding of SP1's VerifierRecursionVks:
    the root (eight KoalaBear words, little-endian u32, canonical), a bool and
    a u64 key count. SP1 maps the root to BN254 by koalabears_to_bn254:
    result = result * 2^31 + word, over the eight words in order.
    """
    raw = SP1_V6_VKS.read_bytes()
    g.require(len(raw) == 41, "Unexpected SP1 verifier_vks.bin length")
    root = 0
    for i in range(8):
        word = int.from_bytes(raw[4 * i : 4 * i + 4], "little")
        g.require(word < 2**31 - 2**24 + 1, "Noncanonical KoalaBear word")
        root = root * 2**31 + word
    return root


# --- Test key shapes ---------------------------------------------------------


def _with_ic(base: dict, ic: list) -> dict:
    key = {k: v for k, v in base.items() if k != "vk_alphabeta_12"}
    key["nPublic"] = len(ic) - 1
    key["IC"] = [
        ["0", "1", "0"] if p is None else [str(p[0]), str(p[1]), "1"] for p in ic
    ]
    return key


def _ic(key: dict) -> list:
    return [None if p[2] == "0" else (int(p[0]), int(p[1])) for p in key["IC"]]


def test_keys(multiplier: dict, sp1: dict) -> dict:
    """Module name -> (provider type name, snarkjs key, description)."""
    O = _offsets.initial_offset()
    F = g.mul(1 << (4 * (_offsets.PROTOCOL["windows"] - 1)), O)
    mic = _ic(multiplier)
    # K = IC0 - 2^126 sum(bases); with IC0 absent msm_bases returns -2^126 sum.
    _, minus_sum = g.msm_bases([None, O])
    neg = lambda p: (p[0], -p[1] % q)  # noqa: E731
    return {
        "key1": (
            "Key1",
            _with_ic(multiplier, mic),
            "the Circom multiplier fixture (fixtures/multiplier). Its trusted\n"
            "// setup is a local development setup; the relation product = a*b proves nothing.",
        ),
        "key3": (
            "Key3",
            _with_ic(sp1, [*_ic(sp1), g.mul(19, (1, 2))]),
            "SP1 v5 alpha, beta, gamma, delta and IC0..IC2, plus IC3 = 19*G1.\n"
            "// For inputs (x1, x2, 0) its L equals SP1's L, so any valid SP1 proof is\n"
            "// accepted with x3 = 0.",
        ),
        "n0": (
            "TestKey",
            _with_ic(multiplier, mic[:1]),
            "N=0 with the multiplier fixture's alpha, beta, gamma, delta and IC0.",
        ),
        "n1_ic0_infinity": (
            "TestKey",
            _with_ic(multiplier, [None, mic[1]]),
            "the multiplier key with IC0 at infinity. The generator accepts it\n"
            "// with a warning: inputs whose L is infinity cannot be proved.",
        ),
        "n1_exception": (
            "TestKey",
            _with_ic(multiplier, [g.mul(17, O), O]),
            "multiplier alpha..delta; IC = [17*O, O] for the first offset origin O.",
        ),
        "n3_exception": (
            "TestKey",
            _with_ic(multiplier, [g.mul(k, O) for k in (17, 1, 19, 23)]),
            "multiplier alpha..delta; IC = [17*O, O, 19*O, 23*O] for the first\n"
            "// offset origin O.",
        ),
        "n1_j_infinity": (
            "TestKey",
            _with_ic(multiplier, [g.add(F, neg(minus_sum)), O]),
            "multiplier alpha..delta; IC1 = O and IC0 chosen so that the bias\n"
            "// correction K equals 2^60*O: the first offset row's J is infinity.",
        ),
        "n1_k_infinity": (
            "TestKey",
            _with_ic(multiplier, [neg(minus_sum), O]),
            "multiplier alpha..delta; IC1 = O and IC0 chosen so that the bias\n"
            "// correction K is infinity.",
        ),
    }


# --- Emission ----------------------------------------------------------------


def _emit(key: dict, name: str) -> str:
    """Provider source as the groth16 generator emits it, before imports."""
    with tempfile.TemporaryDirectory() as temp:
        vk, out = Path(temp) / "key.json", Path(temp) / "provider.nr"
        vk.write_text(json.dumps(key))
        record = g.generate(vk, name, out)
        source = out.read_text()
    correction = (
        None
        if record["biasCorrection"] is None
        else tuple(map(int, record["biasCorrection"]))
    )
    extra, _ = _offsets.methods(correction, record["nPublic"])
    marker = " fn gamma_lines()->LineScheduleRaw"
    g.require(source.count(marker) == 1, "Unexpected provider emission format")
    return source.replace(marker, extra + marker)


def sp1_key_file(path: Path, source: str) -> str:
    """The unformatted generated key file (KEY2 or KEY5) for an emitted provider."""
    body = re.sub(r"^use [^;]+;\n", "", source, flags=re.M)
    if path == KEY2:
        return PROVIDER_IMPORTS + KEY2_HEADER + body
    root = (
        "\n/// The recursion verification-key root of SP1 circuit version v6.1.0.\n"
        f"pub global VK_ROOT: Field = 0x{sp1_v6_vk_root():064x};\n"
    )
    return PROVIDER_IMPORTS + KEY5_HEADER + body + root


def outputs() -> dict[Path, str]:
    multiplier = json.loads(MULTIPLIER_VK.read_text())
    sp1 = sp1_key()
    sp1_v6 = sp1_key(SP1_V6_VK)
    g.require(sp1_v6["nPublic"] == 5, "SP1 v6 key must have five public inputs")
    keys = test_keys(multiplier, sp1)
    jobs = [(sp1, "Key2"), (sp1_v6, "Key5")]
    jobs += [(key, name) for name, key, _ in keys.values()]
    # Each emission computes two line schedules and a t-preimage in pure Python.
    with ProcessPoolExecutor() as pool:
        sources = list(pool.map(_emit, *zip(*jobs)))
    files = {KEY2: sp1_key_file(KEY2, sources[0]), KEY5: sp1_key_file(KEY5, sources[1])}
    modules = []
    for (module, (_, _, description)), source in zip(keys.items(), sources[2:]):
        body = re.sub(r"^use [^;]+;\n", "", source, flags=re.M)
        body = body.replace(
            "// Generated trusted code. Change key through regeneration and a new compiled verifier.\n",
            "",
        )
        header = (
            "// TEST ONLY. Do not use this provider to authorise anything in an application.\n"
            f"// Generated by {SELF}; do not edit.\n"
            f"// Key: {description}\n"
        )
        if module != "key1":
            header += "// No trusted setup exists for this key.\n"
        files[TEST_KEYS / f"{module}.nr"] = header + PROVIDER_IMPORTS + body
        modules.append(module)
    files[TEST_KEYS / "mod.nr"] = (
        "//! TEST ONLY providers for the typechecks in lib.nr. Generated by\n"
        f"//! {SELF}; each file states its key.\n"
        + "".join(f"pub mod {module};\n" for module in modules)
    )
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = outputs()
    files = dict(zip(files, format_noir(files.values())))
    stale = sorted(set(TEST_KEYS.iterdir()) - set(files))
    if args.check:
        drift = [
            p for p, text in files.items() if not p.is_file() or p.read_text() != text
        ]
        for path in drift + stale:
            print(f"{path.relative_to(LIB)}: out of date", file=sys.stderr)
        return 1 if drift or stale else 0
    for path in stale:
        path.unlink()
    for path, text in files.items():
        path.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

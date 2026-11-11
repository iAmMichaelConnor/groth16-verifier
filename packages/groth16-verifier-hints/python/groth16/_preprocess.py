"""Trusted fixed preprocessing. Arithmetic materialized from the validated generator.

The BN254 arithmetic is in _pairing.py; see NOTICE for its origin.
"""

from pathlib import Path
import hashlib, json
from . import _pairing as m


def require(condition, message):
    """Raise ValueError. Unlike a bare assert, `python -O` cannot remove it."""
    if not condition:
        raise ValueError(message)


H = Path(__file__).resolve().parent
ENGINE = H / "_pairing.py"
q = m.P
r = m.R
D = 1 << 126
params = json.loads((H / "data/preprocessing.json").read_text())
beta = int(params["beta"])
lam = int(params["lambda"])
basis = [list(map(int, row)) for row in params["basis"]]


def add(p, t):
    if p is None:
        return t
    if t is None:
        return p
    x, y = p
    u, v = t
    if x == u:
        if (y + v) % q == 0:
            return None
        s = 3 * x * x * pow(2 * y, -1, q) % q
    else:
        s = (v - y) * pow(u - x, -1, q) % q
    z = (s * s - x - u) % q
    return z, (s * (x - z) - y) % q


def mul(n, p):
    if n < 0:
        return mul(-n, (p[0], -p[1] % q))
    out = None
    while n:
        if n & 1:
            out = add(out, p)
        p = add(p, p)
        n >>= 1
    return out


def split(k):
    u, v = basis
    det = u[0] * v[1] - u[1] * v[0]

    def nearest(a, b):
        if b < 0:
            return nearest(-a, -b)
        return (a + b // 2) // b

    aa = nearest(k * v[1], det)
    bb = nearest(-k * u[1], det)
    a = k - aa * u[0] - bb * v[0] + D
    b = -aa * u[1] - bb * v[1] + D
    require(
        0 <= a < 1 << 127
        and 0 <= b < 1 << 127
        and (a + lam * b - D * (1 + lam) - k) % r == 0,
        "GLV split out of range",
    )
    return [a, b]


def g2add(p, t):
    if p is None:
        return t
    if t is None:
        return p
    x, y = p
    u, v = t
    if x == u:
        if y.add(v).is_zero():
            return None
        s = x.square().mul_by_element(3).mul(y.double().inverse())
    else:
        s = v.sub(y).mul(u.sub(x).inverse())
    z = s.square().sub(x).sub(u)
    return z, s.mul(x.sub(z)).sub(y)


def g2mul(n, p):
    out = None
    while n:
        if n & 1:
            out = g2add(out, p)
        p = g2add(p, p)
        n >>= 1
    return out


def normal(v):
    v = int(v)
    require(0 <= v < q, "Noncanonical fixed key coordinate")
    return v


def point(a):
    require(
        len(a) in (2, 3) and (len(a) == 2 or int(a[2]) == 1),
        "Expected finite affine G1 key point",
    )
    p = tuple(map(normal, a[:2]))
    require((p[1] * p[1] - p[0] ** 3 - 3) % q == 0, "G1 key point not on curve")
    require(mul(r, p) is None, "G1 key point outside subgroup")
    return p


def twist(a):
    require(
        len(a) in (2, 3) and (len(a) == 2 or list(map(int, a[2])) == [1, 0]),
        "Expected finite affine G2 key point",
    )
    p = (m.Fp2(*map(normal, a[0])), m.Fp2(*map(normal, a[1])))
    require(not (p[0].is_zero() and p[1].is_zero()), "Expected finite G2 key point")
    require(
        p[1].square()
        == p[0].square().mul(p[0]).add(m.Fp2(3, 0).mul(m.Fp2(9, 1).inverse())),
        "G2 key point not on twist",
    )
    require(g2mul(r, p) is None, "Fixed G2 key point outside subgroup")
    return m.G2Affine(*p)


# Canonical G2 generator (snarkjs real/imaginary order). snarkjs `zkey new` sets
# delta_2 = gamma_2 = this point until a phase-2 contribution is made.
G2_GENERATOR = (
    (
        10857046999023057135944570762232829481370756359578518086990519993285655852781,
        11559732032986387107991004021392285783925812861821192530917403151452391805634,
    ),
    (
        8495653923123431417604973247489272438418190587263600148770280649306958101930,
        4082367875863433681332203403145435568316851327593401208105741076214120093531,
    ),
)


def g2_ints(p):
    return ((p.x.c0, p.x.c1), (p.y.c0, p.y.c1))


def check_key_relations(gamma, delta, ic):
    """Reject degenerate keys that pass the per-point checks.

    Mirrors parseVerificationKey in packages/groth16-verifier-hints/src/parsers.ts. It
    cannot detect a key whose trapdoor is known to someone.
    """
    g, d = g2_ints(gamma), g2_ints(delta)
    neg_g = (g[0], ((-g[1][0]) % q, (-g[1][1]) % q))
    # delta = +-gamma: A = alpha, B = beta, C = -+L verifies for every input.
    require(
        d != g and d != neg_g,
        "Key delta equals plus or minus gamma; anyone can forge proofs",
    )
    # delta = +-generator: public trapdoor +-1. delta = generator is also the
    # snarkjs key without a phase-2 contribution.
    gen = G2_GENERATOR
    neg_gen = (gen[0], ((-gen[1][0]) % q, (-gen[1][1]) % q))
    require(
        d != gen and d != neg_gen,
        "Key delta is plus or minus the G2 generator; no phase-2 contribution",
    )
    # The verifier requires finite L = IC0 + sum(x_i IC_i). All-infinity IC
    # makes L infinity for every input, so every proof would be rejected.
    require(
        any(p is not None for p in ic),
        "Every IC point is infinity; L is always infinity and every proof is rejected",
    )


def limbs(v):
    return [(v >> (120 * i)) & ((1 << 120) - 1) for i in range(3)]


def fp(v):
    return "Fp::from_limbs(" + json.dumps(limbs(v)) + ")"


def f2(v):
    return "Fp2{c0:" + fp(v.c0) + ",c1:" + fp(v.c1) + "}"


def f12(v):
    a = m.fp12_to_coeffs(v)

    def f6(i):
        return (
            "Fp6{b0:"
            + f2(m.Fp2(a[i], a[i + 1]))
            + ",b1:"
            + f2(m.Fp2(a[i + 2], a[i + 3]))
            + ",b2:"
            + f2(m.Fp2(a[i + 4], a[i + 5]))
            + "}"
        )

    return "Fp12{c0:" + f6(0) + ",c1:" + f6(6) + "}"


def gp(p, typ):
    if p is None:
        return (
            typ
            + "{x:"
            + fp(0)
            + ",y:"
            + fp(0)
            + (",is_infinity:true" if typ == "Half" else "")
            + "}"
        )
    return (
        typ
        + "{x:"
        + fp(p[0])
        + ",y:"
        + fp(p[1])
        + (",is_infinity:false" if typ == "Half" else "")
        + "}"
    )


def g2(p):
    return "G2Affine{x:" + f2(p.x) + ",y:" + f2(p.y) + "}"


def msm_bases(ic):
    """Shifted GLV MSM bases and bias correction K = IC0 - 2^126 sum(P + phi(P))."""
    bases = []
    correction = ic[0]
    for p in ic[1:]:
        if p is None:
            bases.extend([None] * 4)
            continue
        for base in (p, (p[0] * beta % q, p[1])):
            require(mul(lam, p) == (p[0] * beta % q, p[1]), "GLV endomorphism mismatch")
            bases.extend([base, mul(1 << 64, base)])
            correction = add(correction, mul(-D, base))
    for p in bases:
        if p is None:
            continue
        require(mul(r, p) is None, "MSM base outside subgroup")
        require(
            all(mul(d, p) is not None for d in range(-15, 16, 2)),
            "MSM base window multiple is infinity",
        )
    return bases, correction


def msm_source(bases, correction):
    return (
        f" fn msm_points()->[Half;{len(bases)}] {{["
        + ",".join(gp(p, "Half") for p in bases)
        + "]}\n fn msm_correction()->Half {"
        + gp(correction, "Half")
        + "}\n"
    )


def generate(vk_path, name, out):
    vk = json.loads(vk_path.read_text())
    require(
        vk["protocol"] == "groth16" and vk["curve"] == "bn128",
        "Expected a groth16/bn128 key",
    )
    N = int(vk["nPublic"])
    require(N >= 0 and len(vk["IC"]) == N + 1, "Key IC length must equal N+1")
    ic = [
        None if list(map(int, v)) in ([0, 0], [0, 0, 1], [0, 1, 0]) else point(v)
        for v in vk["IC"]
    ]
    alpha = point(vk["vk_alpha_1"])
    b = twist(vk["vk_beta_2"])
    gamma = twist(vk["vk_gamma_2"])
    delta = twist(vk["vk_delta_2"])
    check_key_relations(gamma, delta, ic)
    require(mul(lam, (1, 2)) == (beta, 2), "GLV lambda/beta mismatch")
    bases, correction = msm_bases(ic)
    target = m.final_exponentiation(m.miller_loop([m.G1Affine(*alpha)], [b]))
    pre = m.compute_t_preimage(target)
    require(
        m.final_exponentiation(pre) == target.inverse(),
        "t-preimage does not invert e(alpha, beta)",
    )
    schedule = m.emit_fixed_lines_file(
        m.compute_line_schedule_raw(delta.neg()),
        m.compute_line_schedule_raw(gamma.neg()),
    )
    header = """// Generated trusted code. Change key through regeneration and a new compiled verifier.
use crate::types::VerifyingKey;
use crate::optimized::fixed_key::FixedKey;
use crate::optimized::fixed_key_glv::Half;
use noir_bn254_pairing::fp6::Fp6;
use noir_bn254_pairing::fp12::Fp12;
use noir_bn254_pairing::g1::G1Affine;
use noir_bn254_pairing::g2::G2Affine;
"""
    source = (
        header
        + schedule
        + f"\npub struct {name} {{}}\nimpl FixedKey<{N}> for {name} {{\n"
    )
    source += (
        f" fn verification_key()->VerifyingKey<{N + 1}> {{VerifyingKey{{ic:["
        + ",".join(gp(p, "G1Affine") for p in ic)
        + "],gamma_neg:"
        + g2(gamma.neg())
        + ",delta_neg:"
        + g2(delta.neg())
        + ",alpha_beta:"
        + f12(target)
        + "}}\n"
    )
    source += msm_source(bases, correction)
    source += (
        " fn gamma_lines()->LineScheduleRaw {fixed_gamma_lines()}\n fn delta_lines()->LineScheduleRaw {fixed_delta_lines()}\n fn t_preimage()->Fp12 {"
        + f12(pre)
        + "}\n}\n"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(source)
    record = {
        "tPreimage": [str(v) for v in m.fp12_to_coeffs(pre)],
        "nPublic": N,
        "keyFile": str(vk_path),
        "keySha256": hashlib.sha256(vk_path.read_bytes()).hexdigest(),
        "sourceSha256": hashlib.sha256(source.encode()).hexdigest(),
        "engineSha256": hashlib.sha256(ENGINE.read_bytes()).hexdigest(),
        "keyEncoding": "canonical snarkjs real/imaginary order, positive G2 points",
        "fixedBases": [None if p is None else [str(v) for v in p] for p in bases],
        "biasCorrection": None if correction is None else [str(v) for v in correction],
        "ic": [None if p is None else [str(v) for v in p] for p in ic],
        "checks": [
            "IC count N+1",
            "canonical finite alpha; IC entries may be canonical infinity, but not all of them",
            "delta differs from +-gamma and from the G2 generator",
            "all key G2 prime subgroup",
            "all shifted GLV bases derived from matching IC",
            "same alpha/beta target and preimage convention",
            "gamma/delta schedules generated from same key",
        ],
        "scope": "Trusted generated compile-time provider. A changed key requires new source/VK; not runtime-key verification.",
    }
    out.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n")
    return record

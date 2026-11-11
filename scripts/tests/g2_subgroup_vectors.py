#!/usr/bin/env python3
"""Check and print the G2 subgroup-helper test vectors in noir/bn254_g2/src/g2.nr.

OFF_TWIST is a finite point of order r on y^2 = x^3 + 2*b' over Fq2, where
b' = 3/(9+u) is the BN254 twist coefficient. It is not on the twist, but the
psi-based subgroup tests alone accept it, because psi is also an endomorphism of
that curve. The point is a fixed counterexample; this script checks every
claimed property instead of trusting it. GENERATOR is the standard BN254 G2
generator. Run: python3 -I scripts/tests/g2_subgroup_vectors.py
"""

Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def mul(a, b):
    return ((a[0] * b[0] - a[1] * b[1]) % Q, (a[0] * b[1] + a[1] * b[0]) % Q)


def add(a, b):
    return ((a[0] + b[0]) % Q, (a[1] + b[1]) % Q)


def sub(a, b):
    return ((a[0] - b[0]) % Q, (a[1] - b[1]) % Q)


def inv(a):
    n = pow((a[0] * a[0] + a[1] * a[1]) % Q, -1, Q)
    return (a[0] * n % Q, -a[1] * n % Q)


XI = (9, 1)
B_TWIST = mul((3, 0), inv(XI))


def on_curve(p, b):
    x, y = p
    return mul(y, y) == add(mul(mul(x, x), x), b)


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if add(p[1], q[1]) == (0, 0):
            return None
        lam = mul(mul((3, 0), mul(p[0], p[0])), inv(add(p[1], p[1])))
    else:
        lam = mul(sub(q[1], p[1]), inv(sub(q[0], p[0])))
    x = sub(sub(mul(lam, lam), p[0]), q[0])
    return (x, sub(mul(lam, sub(p[0], x)), p[1]))


def scalar_mul(k, p):
    acc = None
    while k:
        if k & 1:
            acc = point_add(acc, p)
        p = point_add(p, p)
        k >>= 1
    return acc


def limbs(v):
    m = (1 << 120) - 1
    return [v & m, (v >> 120) & m, v >> 240]


def from_limbs(l):
    return l[0] + (l[1] << 120) + (l[2] << 240)


OFF_TWIST_LIMBS = [
    [1008354172772749500084674423945802449, 393640661873537768149756591489476381, 7764],
    [379954470204241540519998871331293624, 509082248551301784711528529932116717, 5279],
    [877318628609403309530455760740484661, 681357190983881418967679313141325507, 9453],
    [289804573017912744684746561070507812, 210356562473645026805680891440010386, 7032],
]
GENERATOR = (
    (
        10857046999023057135944570762232829481370756359578518086990519993285655852781,
        11559732032986387107991004021392285783925812861821192530917403151452391805634,
    ),
    (
        8495653923123431417604973247489272438418190587263600148770280649306958101930,
        4082367875863433681332203403145435568316851327593401208105741076214120093531,
    ),
)


def main():
    v = [from_limbs(l) for l in OFF_TWIST_LIMBS]
    off = ((v[0], v[1]), (v[2], v[3]))
    assert all(0 <= c < Q for c in v)
    assert not on_curve(off, B_TWIST), "off-twist vector is on the twist"
    assert on_curve(off, add(B_TWIST, B_TWIST)), "vector is not on y^2 = x^3 + 2b'"
    assert scalar_mul(R, off) is None, "vector does not have order r"
    assert on_curve(GENERATOR, B_TWIST)
    assert scalar_mul(R, GENERATOR) is None
    for name, p in [("OFF_TWIST", off), ("GENERATOR", GENERATOR)]:
        coords = [p[0][0], p[0][1], p[1][0], p[1][1]]
        print(name, [[hex(x) for x in limbs(c)] for c in coords])


if __name__ == "__main__":
    main()

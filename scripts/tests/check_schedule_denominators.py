#!/usr/bin/env python3
"""Check that the private BN254 Miller schedule never meets a zero denominator.

The private schedule geometry (noir/groth16/src/optimized/global_pairing/
schedule_geometry.nr and its byte-identical copy internal/runtime_pairing/src/
schedule_geometry.nr) has no nonzero-denominator guards. This script is the
argument that it needs none.

Precondition. B is finite, canonical and on the twist E': y^2 = x^3 + 3/(9+u)
over Fq2. B is NOT assumed to be in G2; the terminal endpoint relation proves
that, so assuming it here would be circular.

Argument.
1. #E'(Fq2) = N = r*h with h = 2q - r. N is squarefree (r is prime, h is the
   product of the distinct primes in H_FACTORS, and r does not divide h), so
   E'(Fq2) is cyclic and ord(B) divides N.
2. Every point the schedule meets is [k]B for an integer k, or (at the end) a
   combination of B and its Frobenius images psi^i(B). A doubling of T = [k]B
   divides by 2y_T, which is zero only if [2k]B = O. An addition or line through
   [k]B and [d]B divides by x_T - x_Q, which is zero only if [k-d]B = O or
   [k+d]B = O. If gcd(v, N) = 1, then [v]B = O forces B = O, which the
   precondition excludes. So each such v must have gcd(v, N) = 1.
3. psi acts on E'(Fq2) with characteristic polynomial X^2 - tX + q
   (t = q + 1 - r), so a combination a + b*psi is zero on B only if its norm
   a^2 + abt + b^2 q shares a factor with ord(B). The final addition and the
   endpoint chords need norm gcd 1. The endpoint relation itself,
   n + psi - psi^2 + psi^3 with n = 6x + 2, must have norm gcd exactly r: that
   is what proves B is in G2.

The scalar sequence follows the code: double B, line through 2B and -B, add B
(the top NAF digits 1, 0, -1 give 3B), then for each NAF digit from the top (noir/bn254_fields/src/fp.nr miller_loop_digits) a
doubling and, for a nonzero digit d, an addition of [d]B. Re-run this script
whenever the digits, the seed or the schedule change.
Run: python3 -I scripts/tests/check_schedule_denominators.py
"""

from math import gcd
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
FP = ROOT / "noir/bn254_fields/src/fp.nr"
Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
H_FACTORS = (10069, 5864401, 1875725156269)


def digits_and_seed(text):
    body = text[text.index("pub fn miller_loop_digits()") :]
    body = body[body.index("[", body.index("{")) + 1 : body.index("]", body.index("{"))]
    digits = [int(d.replace("i8", "")) for d in re.findall(r"-?\d+i8|-?\d+", body)]
    seed = re.search(r"pub fn seed_x0\(\) -> u128 \{\s*(\d+)\s*\}", text)
    return digits, int(seed.group(1))


def probable_prime(n):
    if n < 2:
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def check(text=None):
    """Return a list of failures; empty means the schedule is safe."""
    digits, seed = digits_and_seed(FP.read_text() if text is None else text)
    failures = []
    t = Q + 1 - R
    h = 2 * Q - R
    n_order = R * h
    rest, rem = divmod(h, H_FACTORS[0] * H_FACTORS[1] * H_FACTORS[2])
    primes = list(H_FACTORS) + [rest]
    if rem or not all(probable_prime(p) for p in primes) or len(set(primes)) != 4:
        failures.append("cofactor factorisation")
    if not probable_prime(R) or h % R == 0:
        failures.append("N is not squarefree")
    if len(digits) != 66:
        failures.append("digit count")
    n = sum(d * 2**i for i, d in enumerate(digits))
    if n != 6 * seed + 2:
        failures.append("digits do not encode 6x+2")

    def scalar(name, v):
        if gcd(v % n_order or n_order, n_order) != 1:
            failures.append(name)

    # Prefix: T = 2B; line through 2B and -B; add B to get 3B.
    scalar("prefix double B", 2)
    scalar("prefix T", 2)
    scalar("prefix line 2B,-B", 2 + 1)
    scalar("prefix add 2B,B (x)", 2 - 1)
    scalar("prefix add 2B,B (-x)", 2 + 1)
    k = 3
    if digits[63:] != [-1, 0, 1]:
        failures.append("prefix assumes the top digits 1, 0, -1 (3B)")
    for i in range(63):
        d = digits[62 - i]
        scalar(f"round {i} T", k)
        scalar(f"round {i} double", 2 * k)
        k = 2 * k
        if d:
            scalar(f"round {i} add (x)", k - d)
            scalar(f"round {i} add (-x)", k + d)
            k = k + d
        scalar(f"round {i} result", k)
    if k != n:
        failures.append("loop does not reach 6x+2")

    def mul(u, v):
        return (
            u[0] * v[0] - u[1] * v[1] * Q,
            u[0] * v[1] + u[1] * v[0] + u[1] * v[1] * t,
        )

    def norm(u):
        return u[0] * u[0] + u[0] * u[1] * t + u[1] * u[1] * Q

    def comb(*terms):
        return (sum(a for a, _ in terms), sum(b for _, b in terms))

    psi = (0, 1)
    psi2 = mul(psi, psi)
    psi3 = mul(psi2, psi)
    neg = lambda u: (-u[0], -u[1])
    nn = (n, 0)
    for name, e in [
        ("final add n, psi (x)", comb(nn, neg(psi))),
        ("final add n, psi (-x)", comb(nn, psi)),
        ("endpoint chord n+psi, psi^2 (x)", comb(nn, psi, psi2)),
        ("endpoint chord n+psi, psi^2 (-x)", comb(nn, psi, neg(psi2))),
    ]:
        if gcd(norm(e), n_order) != 1:
            failures.append(name)
    if gcd(norm(comb(nn, psi, neg(psi2), psi3)), n_order) != R:
        failures.append("endpoint relation norm gcd is not r")
    return failures


def main():
    failures = check()
    if failures:
        raise SystemExit("schedule denominator check failed: " + ", ".join(failures))
    print(
        "schedule denominators: all nonzero for finite B on the twist; endpoint gcd = r"
    )


if __name__ == "__main__":
    main()

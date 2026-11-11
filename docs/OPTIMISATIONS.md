# Mathematical guide to the verifier optimisations

This reference describes the verifiers' arithmetic, transcript and
selectable-offset contracts. Source comments enforce the equations. See
[the API](../README.md) and the [security contracts](SECURITY.md).

## Statement, fields and representations

Write `q` for the BN254 base prime and `r` for its scalar prime. Noir `Field` is Fr; `Fp` coordinates and pairing calculations emulate Fq. For a verification key with public-input coefficients IC, the checked statement is

```text
L = IC[0] + sum(i=0..N-1) [s_i] IC[i+1]
e(A,B) * e(C,-delta) * e(L,-gamma) * e(-alpha,beta) = 1.
```

The finite outer API validates the required proof/key points and rejects a final infinity where documented. Intermediate cancellation is allowed by the corrected G1 algorithm. Runtime keys require their own validation and authorization; fixed providers supply trusted constants for one key. Public-input interpretation and authorization are application obligations.

With `B = 2^120`, an emulated coordinate is `a0 + B*a1 + B^2*a2`, with limb widths 120/120/14. A bounded representative is below `2^254`; a canonical one additionally lies below `q`. External encodings retain canonical checks. Selected internal witnesses may use `a+q` when it still fits the limb bounds: the modular arithmetic checks the same field element, while the transcript commits the exact representation. Such aliases are a deliberate domain, not missing constraints.

## Pairings as polynomial certificates

The direct extension is `Fq[X]/M(X)`, where

```text
M(X) = X^12 - 18*X^6 + 82.
```

It follows from the existing tower relations `i^2=-1`, `v^3=9+i`, `X^2=v`: substitute `i=X^6-9`. A tower coefficient pair `a+b*i` at degree `d` becomes `(a-9*b)X^d+b*X^(d+6)`. The implemented tower degree order is `[0,2,4,1,3,5]`. Evaluation weights share powers of one challenge rather than materializing every intermediate extension product. This is the direct-extension approach described in the [Garaga author's exposition](https://hackmd.io/@feltroidprime/B1eyHHXNT).

For relation polynomials `R_i`, the circuit checks

```text
sum(i=0..67) rho^i * R_i(z) = Q(z) * M(z).
```

The witnesses first commit raw proof/MSM coordinates, all 36 residue coefficients and all 66 accumulator polynomials. The first domain-separated hash derives nonzero `rho`; the second binds every quotient coefficient before deriving `z`. Both challenges are Fr elements embedded into Fq, with subsequent powers computed in Fq. Hash order, domain headers, runtime context, encoding bounds and polynomial degree are part of the soundness argument. This is a randomized polynomial identity check under the Fiat–Shamir assumptions, not deterministic coefficient equality at an arbitrary supplied point.

Fixed-key relations have degree at most 87, so dividing by degree-12 `M` needs at most `87-12+1=76` coefficients. Runtime-key relations have degree at most 105, requiring 94. The shared certificate helper supports exactly those compile-time lengths. Prefix and terminal intermediate witnesses lower the largest relation degrees; their defining identities and adjacent identities are both checked, and the intermediate values are committed before `rho`.

| Identity indices | Checked obligation |
| --- | --- |
| 0 | Residue inverse |
| 1–2 | Prefix intermediate and remaining prefix |
| 3–65 | All 63 Miller transitions |
| 66 | Terminal line product |
| 67 | Final residue equation |

The check is factored into nine independently constrained residuals:

```text
D_i = products[i] - outputs[i]
R_b = sum(j=0..7, 8*b+j<68) rho^j * D_(8*b+j)
Q(z)*M(z) = sum(b=0..8) (rho^8)^b * R_b.
```

Every identity keeps weight `rho^i`. The last block has four live relations and four zero positions. Sixteen one-by-one product slots per block and ten in the terminal equation retain the reviewed nonnative carry bounds. Residuals need not be hashed separately because every residual is constrained by its complete defining equation. Checking only their final weighted sum would leave a free compensating witness. The quotient evaluator includes the final partial block: 76 coefficients use four full 16-coefficient blocks plus twelve; 94 use five plus fourteen.

The residue construction replaces conventional final exponentiation, following Novakovic and Eagen's [On Proving Pairings](https://eprint.iacr.org/2024/640). With BN parameter `x=4965661367192848881`, Miller parameter `n=6*x+2` and `lambda_res=n+q-q^2+q^3`, the fixed source convention checks

```text
c*ci = 1
f * t_preimage * w = c^lambda_res,  with w in Fq6.
```

The inverse excludes `c=0`. The upper six tower coefficients of `w` are zero, which is essential: arbitrary Fq12 scaling could make a false pairing product pass. Fixed-key precomputation supplies the matching line schedules and fixed contribution; the runtime composition instead checks its variable-key terms. The exponent convention and Fq6 restriction are required together.

The residue decoder uses bounded representatives for `c[0..11]`, real `ci` slots 12,14,16,18,20,22, and `w[24..29]`. Imaginary `ci` slots 13,15,17,19,21,23 remain canonical before the inherited negation used by Frobenius. Slots 30..35 remain canonical and zero. Relaxing all 36 slots would discard that precondition; requiring all 36 canonical would unnecessarily restrict valid internal representations.

Frobenius squared is diagonal in the tower basis. For its diagonal map `D` and evaluation functional `ell_a(v)=dot(v,a)`, `ell_a(Dv)=ell_(Da)(v)`. The implementation computes `ci^q` once, computes `Da` once, and evaluates `ci^q`, `c^(q^2)` and `ci^(q^3)` without separately constructing every transformed extension element. This saves field operations while retaining the same terminal equation and canonicality rules.

## Exact schedule geometry

The signed digit array represents `6*x+2`, least-significant digit first. Indices 65,64,63 are `1,0,-1`; the remaining scheduled loop visits 62 down to zero. The shared accessor changes neither signs nor ordering. The endpoint relation

```text
[6*x+2]B + psi(B) - psi^2(B) = -psi^3(B)
```

provides the G2 subgroup check in the existing convention. Its proof is on the full twist group, so it does not assume subgroup membership to establish subgroup membership. The [schedule check](../scripts/tests/check_schedule_denominators.py) recomputes the endpoint norm gcd (it is r).

The cheaper private affine geometry omits generic exceptional branches only where the checked finite origin and exact scalar/Frobenius schedule imply nonzero denominators. The [schedule check](../scripts/tests/check_schedule_denominators.py) derives those implications from the digits in `noir/bn254_fields/src/fp.nr`, with the precondition that B is finite and on the twist. They do not apply to arbitrary affine additions, a changed schedule, or unvalidated points. General-purpose guarded geometry remains separate. Circuit-specific pairing arithmetic is also discussed in El Housni's [Pairings in Rank-1 Constraint Systems](https://eprint.iacr.org/2022/1162); R1CS counts do not transfer directly to this backend.

## GLV and complete selectable-offset execution

The efficient endomorphism satisfies `phi(P)=[lambda_glv]P`. GLV splits scalar multiplication into shorter components, following Gallant, Lambert and Vanstone's [original paper](https://link.springer.com/chapter/10.1007/3-540-44647-8_11). The circuit constrains biased components, rather than trusting the decomposition hint:

```text
s = (u-2^126) + lambda_glv*(v-2^126) mod r
0 <= u,v < 2^127
u = u_lo + 2^64*u_hi,  v = v_lo + 2^64*v_hi
0 <= lo < 2^64,  0 <= hi < 2^63.
```

The chunk recompositions are below `2^127<r`, so native equality is exact integer equality. Four fixed bases per input incorporate the endomorphism and the `2^64` shift. Sixteen signed radix-16 windows per chunk share doublings; the digit/skew equations remain constrained. The generic API accepts native-Fr inputs.

A single fixed starting offset can force an exceptional intermediate for a valid finite MSM. The corrected algorithm selects from trusted pairs `(O_j,C_j)`, using cheaper distinct-x intermediate formulas and a complete final addition. If

```text
K = IC[0] - [2^126] sum(i) (IC[i+1] + phi(IC[i+1]))
C_j = K - [2^60]O_j,
```

then the final result is the required `L`, whichever safe pair is chosen. The 60 doublings come from four between each of sixteen windows. The same bounded index selects both origin and correction; independent choices would break this equation.

For `M=4*N` chunk bases and `S=16` windows there are `M*(S+1)=68*N` guarded additions, including skew candidates evaluated even when the skew is false. At each site the mathematical accumulator is `[2^k]O+T`. Equality of its x-coordinate with a finite operand excludes at most the two origins solving `[2^k]O+T=±D`. Since G1 has odd prime order, multiplication by `2^k` is invertible. Thus `2*M*(S+1)+1=136*N+1` distinct finite origins suffice; two inputs need 273.

For the selected execution, distinct-x addition of finite points cannot yield infinity, and doubling a nonzero point in this odd-order group cannot yield infinity. The complete final correction adds no excluded-origin cases. Infinity IC coefficients use the already reviewed trusted-provider correction scheme; `N=0` bypasses the scalar schedule and requires index zero. This sufficiency argument applies to the exact fixed schedule and provider invariants, not to an arbitrary call of the low-level helper.

The search is an untrusted hint. An out-of-range index fails; an unsafe index fails constrained replay; a safe index yields the same mathematical result. Packed rows bind four 120/120/14-bit coordinates and one Boolean correction-infinity flag. Each low word is below `2^240<r`; the combined high word is below `2^57<r`. Recomposition is therefore injective. Curve validity and the origin/correction relation come from the trusted generated table, not from the decoder alone.

## Shared nonnative arithmetic and exact comparisons

Fused expressions check one relation `sum_k L_k*R_k + sum_j A_j = quotient*q`, sharing quotient and carry work across products. The quotient is hinted but range checked, and every operand retains its limb bounds. Writing convolution coefficients as `e_i`, carries enforce `e_i+c_(i-1)=B*c_i` and a final zero coefficient. The coefficient and carry bounds are what make native-field constraints describe the intended integer relation; field equality alone would permit aliases.

The narrow-tail specialization requires three limbs, `241<=MOD_BITS<=258`, at most 32 expanded products and eight linear terms. With `T=2^(MOD_BITS-240)<=2^18`, the signed coefficient before the final carry is bounded by

```text
|e_3 + incoming| < 321*B*T + 2^126 < 2^148.
```

The borrow lift is `2^148`, giving a 28-bit final carry after division by `B`; the final coefficient cancels the corresponding `2^28` compensation. Earlier carries keep their original bounds, and other shapes keep the 126-bit fallback.

A smaller fixed-bias specialization requires three limbs, a 254-bit modulus, at most three expanded products and eight linear terms. It represents signed carries as `c+2^125` in 126 bits, and the final carry as `c+2^27` in 28 bits, eliminating borrow flags for that shape. The lower coefficient bound is below `32*B^2`; the tail fits the corresponding signed bound. It propagates the decoded carry, not the biased value. Unused borrow hints in this branch have no mathematical role. The specialization requires normalized moduli and padded operands. Neither specialization proves arbitrary shapes complete or permits dropping quotient/range checks.

Exact three-limb equality also exploits range bounds. For normalized modulus `q`, bounded inputs lie below `2^MOD_BITS<=2q`, so equal residues differ only by `0,+q,-q`. Write `d=low+B^2*high`, with `|low|<B^2`. The zero branch fixes `high=0`; the `+q` branch restricts `high-q_high` to `{0,1}`; the `-q` branch restricts `high+q_high` to `{0,-1}`. These carry-root checks reduce the remaining native comparison to an integer residual of magnitude below `2^241<r`. Negating this exact equality gives the corrected inequality used by BN254 guards. A native comparison of whole coordinates alone is insufficient because `q>r`. Other limb-count fallbacks retain their documented limitations.

Dense transcript packing similarly depends on bounds: combine two 120-bit limbs into one word below `2^240`, and up to eighteen 14-bit top limbs into a word below `2^252`, both below Fr. Fixed arity/order/padding make the encoding injective. The packing helper alone does not range check its arguments; callers must do that first.

## Representation and maintenance boundary

Public derived-curve negation multiplies y by canonical minus one. The modular
multiplication relation accepts bounded aliases, constrains input/output limb
ranges and preserves x and the infinity tag. It does not prove the result is a
unique canonical representative. For the supported built-in curves, one
unflagged product has at most seven 120-bit terms per convolution coefficient,
below `7*2^240 < 2^243`, inside the existing 246-bit guard. Lower-level BigNum
negation still requires a canonical operand. Arbitrary custom modulus/provider
contracts and other limb-count equality fallbacks remain separate obligations.

Shared helpers preserve compile-time input counts, table lengths and exactly
the two reviewed quotient lengths. Keep one nominal identity for shared field
types; different BigCurve implementations are not interchangeable merely because
some source files match. Changes to formulas, schedules, transcript order, key
constants, representation bounds or dependencies require the corresponding
mathematical and composition checks. Equal gate counts do not imply equal
bytecode. These local arguments are not a compiler/backend or formal soundness
proof. Published methods are attributed above; the carry, offset and scheduling
conditions describe this implementation's own call shapes.

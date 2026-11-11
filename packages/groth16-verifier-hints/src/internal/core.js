import {
  RUNTIME_66,
  RUNTIME_67,
  RUNTIME_68,
  FIXED_66,
  FIXED_67,
  FIXED_68,
} from "../schemas.js";
// Experimental hint kernel, not a verifier or an audited production package.
// MIT Noble 1.7.0 is pinned to the existing exact installation for this comparison.
import { bn254 } from "@noble/curves/bn254";
const { Fp: F, Fp2: E, Fp12: T } = bn254.fields;
const Q = F.ORDER,
  R = bn254.fields.Fr.ORDER,
  X = 4965661367192848881n;
const mod = (x, p = Q) => ((x % p) + p) % p;
function inv(x, p) {
  let [a, b, u, v] = [mod(x, p), p, 1n, 0n];
  while (b) {
    const q = a / b;
    [a, b] = [b, a - q * b];
    [u, v] = [v, u - q * v];
  }
  if (a !== 1n) throw Error("noninvertible");
  return mod(u, p);
}
const f2 = (a) => ({ c0: BigInt(a[0]), c1: BigInt(a[1]) });
const f6 = (a) => ({
  c0: f2(a.slice(0, 2)),
  c1: f2(a.slice(2, 4)),
  c2: f2(a.slice(4, 6)),
});
const f12 = (a) => ({ c0: f6(a.slice(0, 6)), c1: f6(a.slice(6, 12)) });
const flat2 = (a) => [a.c0, a.c1],
  flat6 = (a) => [...flat2(a.c0), ...flat2(a.c1), ...flat2(a.c2)],
  flat = (a) => [...flat6(a.c0), ...flat6(a.c1)];
const limbs = (x) => [
  x & ((1n << 120n) - 1n),
  (x >> 120n) & ((1n << 120n) - 1n),
  x >> 240n,
];
const encoded = (a) => a.map(limbs);
const check = (v, s) => {
  if (!v) throw Error(s);
};
// Noble's tower uses i^2=-1, v^3=9+i and w^2=v. With Z=w,
// i=Z^6-9 and therefore Z^12-18Z^6+82=0. The direct basis below
// expresses a+b*i at powers j,j+6 as (a-9b)+b*Z^6.
// Fq12 tower order [1,v,v^2,w,vw,v^2w] maps to j=[0,2,4,1,3,5].
// This is the exact basis used by Noir's polynomial certificate checker.
function direct(a) {
  const out = Array(12).fill(0n);
  [0, 2, 4, 1, 3, 5].forEach((j, i) => {
    out[j] = mod(a[2 * i] - 9n * a[2 * i + 1]);
    out[j + 6] = a[2 * i + 1];
  });
  return out;
}
function tower(a) {
  const v = [];
  for (const j of [0, 2, 4, 1, 3, 5])
    v.push(mod(a[j] + 9n * a[j + 6]), a[j + 6]);
  return f12(v);
}
function mul(a, b) {
  const out = Array(a.length + b.length - 1).fill(0n);
  for (let i = 0; i < a.length; i++)
    for (let j = 0; j < b.length; j++) out[i + j] += a[i] * b[j];
  return out.map((x) => mod(x));
}
// Divide over Fq by the monic irreducible polynomial M(Z)=Z^12-18Z^6+82.
// Return [remainder, quotient]; each accepted identity has zero remainder.
// Keep high zero coefficients where the fixed packet schema requires them.
function divide(a) {
  a = [...a];
  const q = Array(Math.max(0, a.length - 12)).fill(0n);
  for (let i = a.length - 1; i >= 12; i--) {
    const t = mod(a[i]);
    q[i - 12] = t;
    a[i] = 0n;
    a[i - 6] += 18n * t;
    a[i - 12] -= 82n * t;
  }
  return [a.slice(0, 12).map((x) => mod(x)), q];
}
const subtract = (a, b) => a.map((x, i) => mod(x - (b[i] ?? 0n)));
function step(p, q) {
  let slope;
  if (q === undefined) {
    check(!E.is0(p.y), "zero tangent denominator");
    slope = E.div(E.mul(E.sqr(p.x), 3n), E.mul(p.y, 2n));
    q = p;
  } else {
    check(!E.eql(q.x, p.x), "zero secant denominator");
    slope = E.div(E.sub(q.y, p.y), E.sub(q.x, p.x));
  }
  const x = E.sub(E.sub(E.sqr(slope), p.x), q.x),
    y = E.sub(E.mul(slope, E.sub(p.x, x)), p.y);
  return [
    { x, y },
    { r1: E.neg(slope), r2: E.sub(E.mul(slope, p.x), p.y) },
  ];
}
const neg = (p) => ({ x: p.x, y: E.neg(p.y) });
// The circuit uses a fixed 63-round signed-digit schedule, preceded by a
// three-line initialization and followed by two Frobenius lines. Slopes are
// normalized to affine form. Their omitted scale lies in a proper subfield
// and is accounted for by the residue witness, not ignored in the equation.
// The final endpoint is also the G2 subgroup test used by the circuit.
function schedule(q, k) {
  const [twice, d] = step(q),
    [triple, a] = step(twice, q),
    [, l] = step(twice, neg(q));
  const s = { d, l, a, rounds: [] };
  let p = triple;
  for (const digit of k.loop) {
    let d, a;
    [p, d] = step(p);
    if (digit !== 0) [p, a] = step(p, digit === 1 ? q : neg(q));
    s.rounds.push({ d, a });
  }
  const psi = (p) => ({
    x: E.mul(E.frobeniusMap(p.x, 1), k.psiX),
    y: E.mul(E.frobeniusMap(p.y, 1), k.psiY),
  });
  const psi2 = { x: E.mul(q.x, k.minusPsi2X), y: E.mul(q.y, k.minusPsi2Y) };
  [p, s.endA] = step(p, psi(q));
  [p, s.endL] = step(p, psi2);
  const endpoint = psi(psi2);
  check(
    E.eql(p.x, endpoint.x) && E.eql(p.y, endpoint.y),
    "G2 subgroup endpoint",
  );
  return s;
}
function line(l, p) {
  const out = Array(12).fill(0n);
  for (const [j, v] of [
    [0, { c0: p[1], c1: 0n }],
    [1, E.mul(l.r1, p[0])],
    [3, l.r2],
  ]) {
    out[j] = mod(v.c0 - 9n * v.c1);
    out[j + 6] = v.c1;
  }
  return out.slice(0, 10);
}
function miller(points, s, k) {
  let v = T.ONE;
  const times = (l, i) => {
    v = T.mul(v, tower([...line(l, points[i]), 0n, 0n]));
  };
  s.forEach((x, i) => times(x.d, i));
  v = T.sqr(v);
  s.forEach((x, i) => {
    times(x.l, i);
    times(x.a, i);
  });
  for (let i = 0; i < 63; i++) {
    v = T.sqr(v);
    s.forEach((x, j) => {
      times(x.rounds[i].d, j);
      if (k.loop[i] !== 0) times(x.rounds[i].a, j);
    });
  }
  s.forEach((x, i) => {
    times(x.endA, i);
    times(x.endL, i);
  });
  return v;
}
// Host-side witness construction for the residue test from Novakovic/Eagen,
// "On Proving Pairings": https://eprint.iacr.org/2024/640.
//
// Let lambda=6x+2+q-q^2+q^3. We need value*w=c^lambda, c!=0,
// with w in Fq6. Since gcd(lambda,q^12-1)=3r, a plain lambda-th
// root would miss valid final-exponent kernel elements. A 27th root of
// unity in Fq6 supplies the correction; try its three cube classes,
// invert the coprime factors modulo h=(q^12-1)/r, then find the cube
// root in the remaining small 3-primary group. Every result is checked.
// This helper is not the security boundary: Noir constrains the residue,
// Miller transitions, inverse and subfield membership independently.
function residue(value, root) {
  check(T.eql(T.finalExponentiate(value), T.ONE), "invalid Groth16 pairing");
  const order = Q ** 12n - 1n;
  let w;
  for (let i = 0n; i < 3n; i++) {
    const cand = T.pow(root, i);
    if (T.eql(T.pow(T.mul(value, cand), order / 3n), T.ONE)) {
      w = cand;
      break;
    }
  }
  check(w !== undefined, "no residue root");
  const h = order / R,
    lam = 6n * X + 2n + Q - Q ** 2n + Q ** 3n,
    factor = lam / R;
  let u = T.pow(T.mul(value, w), inv(R, h));
  u = T.pow(u, inv(factor / 3n, h));
  let s = order;
  while (s % 3n === 0n) s /= 3n;
  const exp = (s + 1n) / 3n,
    correction = T.pow(root, exp);
  let c = T.pow(u, exp);
  const ui = T.inv(u);
  let rounds = 0;
  while (!T.eql(T.mul(T.pow(c, 3n), ui), T.ONE)) {
    c = T.mul(c, correction);
    check(++rounds <= 27, "cube root iteration");
  }
  check(T.eql(T.pow(c, lam), T.mul(value, w)), "invalid residue identity");
  check(
    flat(w)
      .slice(6)
      .every((x) => x === 0n),
    "w not Fq6",
  );
  return [c, T.inv(c), w];
}
function relations(
  points,
  s,
  k,
  c,
  ci,
  w,
  preimage = undefined,
  splitPrefix = false,
  splitTail = false,
) {
  // Global66-v1 relation order:
  // 0: c*ci=1; 1: initialized accumulator; 2..64: 63 rounds;
  // 65: Frobenius tail, fixed target preimage (if used), and w.
  // Each accumulator is a reduced degree<12 representative. Retain the
  // unreduced products so that certificate() can prove divisibility by M.
  const cp = direct(flat(c)),
    cip = direct(flat(ci)),
    polys = [subtract(mul(cp, cip), [1n])],
    accs = [];
  let p = mul(cip, cip);
  s.forEach((x, i) => (p = mul(p, line(x.d, points[i]))));
  // Global67 commits H before squaring, reducing the maximum polynomial degree.
  // Keep its unreduced divisibility relation as its own obligation before rho.
  if (splitPrefix) {
    const h = divide(p)[0];
    polys.push(subtract(p, h));
    accs.push(encoded(flat(tower(h))));
    p = h;
  }
  p = mul(p, p);
  s.forEach((x, i) => {
    p = mul(p, line(x.l, points[i]));
    p = mul(p, line(x.a, points[i]));
  });
  p = mul(p, cp);
  let a = divide(p)[0];
  polys.push(subtract(p, a));
  accs.push(encoded(flat(tower(a))));
  for (let i = 0; i < 63; i++) {
    p = mul(a, a);
    s.forEach((x, j) => {
      p = mul(p, line(x.rounds[i].d, points[j]));
      if (k.loop[i] !== 0) p = mul(p, line(x.rounds[i].a, points[j]));
    });
    if (k.loop[i] !== 0) p = mul(p, k.loop[i] === 1 ? cip : cp);
    a = divide(p)[0];
    polys.push(subtract(p, a));
    accs.push(encoded(flat(tower(a))));
  }
  p = a;
  s.forEach((x, i) => {
    p = mul(p, line(x.endA, points[i]));
    p = mul(p, line(x.endL, points[i]));
  });
  // Global68 commits the reduced terminal line product before any fixed preimage,
  // subfield w and Frobenius factors. Its own identity retains that obligation.
  if (splitTail) {
    const terminal = divide(p)[0];
    polys.push(subtract(p, terminal));
    accs.push(encoded(flat(tower(terminal))));
    p = terminal;
  }
  for (const f of [
    ...(preimage ? [preimage] : []),
    w,
    T.frobeniusMap(ci, 1),
    T.frobeniusMap(c, 2),
    T.frobeniusMap(ci, 3),
  ])
    p = mul(p, direct(flat(f)));
  polys.push(subtract(p, [1n]));
  return [polys, accs];
}
function dense(values) {
  // Input limbs are already bounded 120/120/14-bit values. Each low word
  // is <2^240; eighteen packed high limbs occupy at most252bits, below Fr.
  // Fixed shape/order makes this packing injective on the bounded encoding.
  const out = values.map(([a, b]) => a + (b << 120n));
  for (let i = 0; i < values.length; i += 18) {
    let v = 0n;
    for (let j = 0; j < 18 && i + j < values.length; j++)
      v += values[i + j][2] << BigInt(j * 14);
    out.push(v);
  }
  return out;
}
function hash(xs, k) {
  // Match Noir's width-four, rate-three Poseidon2 sponge, including length
  // in the capacity lane. Return the first field of the final permutation.
  // This terminal output is a Fiat-Shamir commitment, not a chain state
  // that callers may extend without reapplying the prescribed sponge.
  const matrix = ([a, b, c, d]) =>
    [
      5n * a + 7n * b + c + 3n * d,
      4n * a + 6n * b + c + d,
      a + 3n * b + 5n * c + 7n * d,
      a + b + 4n * c + 6n * d,
    ].map((x) => mod(x, R));
  const pow5 = (x) => {
    const x2 = (x * x) % R;
    return (((x2 * x2) % R) * x) % R;
  };
  const perm = (s) => {
    s = matrix(s);
    for (let r = 0; r < 64; r++) {
      if (r < 4 || r >= 60)
        s = matrix(s.map((x, i) => pow5(mod(x + k.poseidonC[4 * r + i], R))));
      else {
        s[0] = pow5(mod(s[0] + k.poseidonC[4 * r], R));
        const total = s.reduce((a, b) => a + b, 0n);
        s = s.map((x, i) => mod(k.poseidonD[i] * x + total, R));
      }
    }
    return s;
  };
  let state = [0n, 0n, 0n, BigInt(xs.length) << 64n];
  for (let i = 0; i < Math.max(1, xs.length); i += 3) {
    for (let j = 0; j < 3 && i + j < xs.length; j++)
      state[j] = mod(state[j] + xs[i + j], R);
    state = perm(state);
  }
  return state[0];
}
function certificate(raw, context, res, accs, polys, k, schema) {
  const { domain, quotient: size, identities: count } = schema;
  check(
    polys.length === count && accs.length === schema.accumulators,
    "certificate schema shape",
  );
  // Bind every proof/residue/accumulator coefficient before choosing rho.
  // The quotient is then fixed by that rho and committed before choosing z.
  // Reversing either dependency lets a prover adapt witnesses to challenges.
  //
  // Local blocks of eight identities use rho^0..rho^7; the terminal sum
  // restores rho^(8b) for block b. This equals the full sum over rho^i.
  // Opposite errors in different blocks cannot simply cancel unweighted.
  const parts = polys.map(divide);
  // The fixed packet remains padded. Split formats may discard only zero leading
  // coefficients, notably the terminal w factor's absent odd tower half.
  if (count >= 67)
    for (const [, quotient] of parts)
      while (quotient.length && quotient[quotient.length - 1] === 0n)
        quotient.pop();
  check(
    parts.every(([r]) => r.every((x) => x === 0n)),
    "nonzero polynomial remainder",
  );
  check(
    parts.every(([, q]) => q.length <= size),
    "quotient exceeds schema",
  );
  const rho = hash(
    [
      domain,
      BigInt(count),
      ...context,
      ...dense([...raw, ...res, ...accs.flat()]),
    ],
    k,
  );
  check(rho !== 0n, "zero rho");
  const powers = [1n];
  for (let i = 1; i < count; i++) powers.push((powers[i - 1] * rho) % Q);
  const q = Array(size).fill(0n);
  for (let i = 0; i < count; i++)
    for (let j = 0; j < parts[i][1].length; j++)
      q[j] = mod(q[j] + powers[i] * parts[i][1][j]);
  const encodedQ = encoded(q),
    z = hash([domain + 1n, rho, ...dense(encodedQ)], k);
  const ev = (a) => a.reduceRight((v, x) => mod(v * z + x), 0n);
  const blocks = [];
  for (let j = 0; j < count; j += 8) {
    let b = 0n;
    for (let i = j; i < Math.min(j + 8, count); i++)
      b += powers[i - j] * ev(polys[i]);
    blocks.push(mod(b));
  }
  let residual = ev(q) * mod(z ** 12n - 18n * z ** 6n + 82n);
  for (let j = 0; j < blocks.length; j++) residual -= powers[j * 8] * blocks[j];
  check(mod(residual) === 0n, "terminal identity");
  return {
    data: {
      raw,
      context,
      residue: res,
      accumulators: accs,
      quotient: encodedQ,
      block_residuals: encoded(blocks),
    },
    facts: { rho, z },
  };
}
export function prepareConstants(raw) {
  const k = {};
  for (const [name, a] of Object.entries(raw))
    k[name] =
      name === "loop"
        ? a.map(Number)
        : name.startsWith("psi") || name.startsWith("minusPsi")
          ? f2(a)
          : name === "root27"
            ? f12(a)
            : a.map(BigInt);
  check(
    T.eql(T.pow(k.root27, 27n), T.ONE) && !T.eql(T.pow(k.root27, 9n), T.ONE),
    "bad root27 constant",
  );
  return k;
}
function generateRuntime(input, k, schema) {
  const times = {},
    phase = (name, fn) => {
      const t = performance.now(),
        v = fn();
      times[name] = (performance.now() - t) / 1000;
      return v;
    };
  const points = input.points.map((p) => p.map(BigInt)),
    origins = input.origins.map((p) => ({
      x: f2(p.slice(0, 2)),
      y: f2(p.slice(2, 4)),
    }));
  const s = phase("schedules", () => origins.map((q) => schedule(q, k)));
  const normalized = phase("miller", () => miller(points, s, k));
  const [c, ci, w] = phase("residue", () => residue(normalized, k.root27));
  const [polys, accs] = phase("relations", () =>
    relations(
      points,
      s,
      k,
      c,
      ci,
      w,
      undefined,
      schema.identities >= 67,
      schema === RUNTIME_68,
    ),
  );
  const output = phase("certificate", () =>
    certificate(
      input.raw.map((a) => a.map(BigInt)),
      input.context.map(BigInt),
      encoded([...flat(c), ...flat(ci), ...flat(w)]),
      accs,
      polys,
      k,
      schema,
    ),
  );
  return { normalized: flat(normalized), ...output, times };
}
export const generateKernel = (input, k) =>
  generateRuntime(input, k, RUNTIME_66);
export const generateKernel67 = (input, k) =>
  generateRuntime(input, k, RUNTIME_67);
export const generateKernel68 = (input, k) =>
  generateRuntime(input, k, RUNTIME_68);
// Runtime-key parser/preprocessing is separate from arithmetic to expose cold/warm cost.
// All coordinates are checked before Noble construction; no modular-reduction decoding.
const canonical = (x, p = Q) => {
  check(
    typeof x === "string" || typeof x === "bigint",
    "integer must be string/bigint",
  );
  const v = BigInt(x);
  check(v >= 0n && v < p, "noncanonical integer");
  return v;
};
function g1(raw, allowInfinity = false) {
  check(
    Array.isArray(raw) && (raw.length === 2 || raw.length === 3),
    "G1 arity",
  );
  const x = canonical(raw[0]),
    y = canonical(raw[1]);
  if (raw.length === 3) {
    const z = canonical(raw[2]);
    if (z === 0n) {
      check(
        allowInfinity && x === 0n && (y === 0n || y === 1n),
        "invalid infinity",
      );
      return bn254.G1.ProjectivePoint.ZERO;
    }
    check(z === 1n, "non-affine G1");
  }
  if (allowInfinity && x === 0n && y === 0n)
    return bn254.G1.ProjectivePoint.ZERO;
  check(allowInfinity || x !== 0n || y !== 0n, "finite G1 required");
  const p = bn254.G1.ProjectivePoint.fromAffine({ x, y });
  p.assertValidity();
  return p;
}
function g2(raw) {
  check(
    Array.isArray(raw) && (raw.length === 2 || raw.length === 3),
    "G2 arity",
  );
  for (const v of raw) check(v.length === 2, "Fq2 arity");
  if (raw.length === 3)
    check(
      canonical(raw[2][0]) === 1n && canonical(raw[2][1]) === 0n,
      "non-affine G2",
    );
  const x = { c0: canonical(raw[0][0]), c1: canonical(raw[0][1]) },
    y = { c0: canonical(raw[1][0]), c1: canonical(raw[1][1]) };
  check(!E.is0(x) || !E.is0(y), "finite G2 required");
  const p = bn254.G2.ProjectivePoint.fromAffine({ x, y });
  p.assertValidity();
  return p;
}
const coords1 = (p) => {
    const a = p.toAffine();
    return [a.x, a.y];
  },
  coords2 = (p) => {
    const a = p.toAffine();
    return [...flat2(a.x), ...flat2(a.y)];
  };
export function prepareKey(key, k) {
  check(key.protocol === "groth16" && key.curve === "bn128", "key format");
  const n = Number(key.nPublic);
  check(
    Number.isSafeInteger(n) && n >= 0 && n <= 256 && key.IC.length === n + 1,
    "input arity",
  );
  const alpha = g1(key.vk_alpha_1),
    beta = g2(key.vk_beta_2),
    gamma = g2(key.vk_gamma_2),
    delta = g2(key.vk_delta_2),
    ic = key.IC.map((p) => g1(p, true));
  const coordinates = [
    ...coords1(alpha),
    ...coords2(beta),
    ...coords2(gamma),
    ...coords2(delta),
    ...ic.flatMap(coords1),
  ];
  const keyHash = hash(
    [
      0x4731365f52554e54494d455f563100n,
      BigInt(n),
      ...dense(encoded(coordinates)),
    ],
    k,
  );
  return { n, alpha, beta, gamma, delta, ic, keyHash };
}
export function prepareRequest(proof, inputs, key, k) {
  // L=IC0+sum(input_i*IC_i). Native multiplication is complete and skips
  // zero terms explicitly; finite L is the selected circuit API's restriction.
  // The runtime pairing order is (A,B),(C,-delta),(L,-gamma),(-alpha,beta).
  check(inputs.length === key.n, "input arity");
  const scalars = inputs.map((x) => canonical(x, R));
  const A = g1(proof.pi_a),
    B = g2(proof.pi_b),
    C = g1(proof.pi_c);
  let L = key.ic[0];
  for (let i = 0; i < scalars.length; i++)
    if (
      scalars[i] !== 0n &&
      !key.ic[i + 1].equals(bn254.G1.ProjectivePoint.ZERO)
    )
      L = L.add(key.ic[i + 1].multiply(scalars[i]));
  check(!L.equals(bn254.G1.ProjectivePoint.ZERO), "finite L required");
  const raw = encoded([
    ...coords1(A),
    ...coords2(B),
    ...coords1(C),
    ...coords1(L),
    ...coords1(key.alpha),
    ...coords2(key.beta),
    ...coords2(key.gamma),
    ...coords2(key.delta),
  ]);
  const context = [
    BigInt(key.n),
    key.keyHash,
    hash([0x4731365f52554e54494d455f563101n, BigInt(key.n), ...scalars], k),
  ];
  return {
    points: [coords1(A), coords1(C), coords1(L), coords1(key.alpha.negate())],
    origins: [
      coords2(B),
      coords2(key.delta.negate()),
      coords2(key.gamma.negate()),
      coords2(key.beta),
    ],
    raw,
    context,
  };
}
export { hash, dense, encoded, coords1, coords2, Q, R };
// Cheap malformed-backend diagnostic only. It does not verify the Miller identities.
export function checkResiduePreflight(values) {
  const c = f12(values.slice(0, 12)),
    ci = f12(values.slice(12, 24));
  check(T.eql(T.mul(c, ci), T.ONE), "Kernel residue inverse mismatch");
  check(
    values.slice(30, 36).every((x) => x === 0n),
    "Kernel residue w is not in Fq6",
  );
}
// Separate fixed three-pair API. Runtime callers retain the defaults above.
export function prepareFixedContext(key, preimage, k) {
  // Fixed preprocessing replaces (-alpha,beta) by a trusted t whose final
  // exponent equals e(alpha,beta)^-1. Use the same actual Noble convention
  // on both sides; pairing libraries can differ in their normalizations.
  const t = f12(preimage);
  check(
    T.eql(
      T.mul(T.finalExponentiate(t), bn254.pairing(key.alpha, key.beta)),
      T.ONE,
    ),
    "Fixed preimage does not match alpha/beta",
  );
  const point = (p) => {
    const a = p.toAffine();
    return { x: a.x, y: a.y };
  };
  return {
    t,
    delta: schedule(point(key.delta.negate()), k),
    gamma: schedule(point(key.gamma.negate()), k),
  };
}
function generateFixed(input, configuration, k, schema) {
  const points = input.points.slice(0, 3),
    origin = input.origins[0];
  const b = { x: f2(origin.slice(0, 2)), y: f2(origin.slice(2, 4)) };
  const s = [schedule(b, k), configuration.delta, configuration.gamma];
  const normalized = T.mul(miller(points, s, k), configuration.t);
  const [c, ci, w] = residue(normalized, k.root27);
  const [polys, accs] = relations(
    points,
    s,
    k,
    c,
    ci,
    w,
    configuration.t,
    schema.identities >= 67,
    schema === FIXED_68,
  );
  return {
    normalized: flat(normalized),
    ...certificate(
      input.raw.slice(0, 10),
      [],
      encoded([...flat(c), ...flat(ci), ...flat(w)]),
      accs,
      polys,
      k,
      schema,
    ),
  };
}

export const generateFixedKernel = (input, configuration, k) =>
  generateFixed(input, configuration, k, FIXED_66);
export const generateFixedKernel67 = (input, configuration, k) =>
  generateFixed(input, configuration, k, FIXED_67);

export const generateFixedKernel68 = (input, configuration, k) =>
  generateFixed(input, configuration, k, FIXED_68);

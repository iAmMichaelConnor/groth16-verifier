// Reference oracle for the bn254_oracle_tests package: answers nargo's
// `resolve_foreign_call` JSON-RPC requests with values computed by
// @noble/curves. Usage: node oracle_server.mjs PORT (run.sh starts it).
import http from "node:http";
import { randomBytes } from "node:crypto";
import { bn254 } from "@noble/curves/bn254";

const { Fp, Fp2, Fp6, Fp12, Fr } = bn254.fields;
const { G1, G2 } = bn254;
const MASK = (1n << 120n) - 1n;

// Noir passes every argument flattened to field elements, struct fields in
// declaration order. An Fp is a BigNum: three little-endian 120-bit limbs.
// The tower is the same as the Noir one: Fp2 = Fp[u]/(u^2 + 1),
// Fp6 = Fp2[v]/(v^3 - (9 + u)), Fp12 = Fp6[w]/(w^2 - v).
const reader = (inputs) => {
  const fields = inputs.flat().map((s) => BigInt(s.startsWith("0x") ? s : `0x${s}`));
  let i = 0;
  const fp = () => Fp.create(fields[i++] + (fields[i++] << 120n) + (fields[i++] << 240n));
  const fp2 = () => ({ c0: fp(), c1: fp() });
  const fp6 = () => ({ c0: fp2(), c1: fp2(), c2: fp2() });
  const fp12 = () => ({ c0: fp6(), c1: fp6() });
  const g1 = () => G1.ProjectivePoint.fromAffine({ x: fp(), y: fp() });
  const g2 = () => G2.ProjectivePoint.fromAffine({ x: fp2(), y: fp2() });
  return { fp2, fp6, fp12, g1, g2, left: () => fields.length - i };
};

const limbs = (x) => [x & MASK, (x >> 120n) & MASK, x >> 240n];
const fp2Out = (a) => [...limbs(a.c0), ...limbs(a.c1)];
const fp6Out = (a) => [...fp2Out(a.c0), ...fp2Out(a.c1), ...fp2Out(a.c2)];
const fp12Out = (a) => [...fp6Out(a.c0), ...fp6Out(a.c1)];
const g1Out = (p) => { const { x, y } = p.toAffine(); return [...limbs(x), ...limbs(y)]; };
const g2Out = (p) => { const { x, y } = p.toAffine(); return [...fp2Out(x), ...fp2Out(y)]; };
const inverseOrZero = (F, a) => (F.is0(a) ? F.ZERO : F.inv(a));

// Random values are logged so that a failing run can be reproduced.
const uniform = (modulus) => BigInt(`0x${randomBytes(48).toString("hex")}`) % modulus;
const logged = (name, values) => {
  console.log(`${name}: ${values.map((v) => `0x${v.toString(16)}`).join(" ")}`);
  return values;
};
const scalar = (name) => logged(name, [uniform(Fr.ORDER - 1n) + 1n])[0];

const handlers = {
  // [a * b, a^2, a^-1 (zero for a = 0)]
  fp2_reference: (r) => {
    const a = r.fp2(), b = r.fp2();
    return [Fp2.mul(a, b), Fp2.sqr(a), inverseOrZero(Fp2, a)].flatMap(fp2Out);
  },
  fp6_reference: (r) => {
    const a = r.fp6(), b = r.fp6();
    return [Fp6.mul(a, b), Fp6.sqr(a), inverseOrZero(Fp6, a)].flatMap(fp6Out);
  },
  // [a * b, a^2, a^-1 (zero for a = 0), a^p, a^(p^2), a^(p^3)]
  fp12_reference: (r) => {
    const a = r.fp12(), b = r.fp12();
    const out = [Fp12.mul(a, b), Fp12.sqr(a), inverseOrZero(Fp12, a)];
    for (const power of [1, 2, 3]) out.push(Fp12.frobeniusMap(a, power));
    return out.flatMap(fp12Out);
  },
  random_g1: () => g1Out(G1.ProjectivePoint.BASE.multiply(scalar("random_g1"))),
  random_g2: () => g2Out(G2.ProjectivePoint.BASE.multiply(scalar("random_g2"))),
  random_fp12: () => {
    const coefficients = Array.from({ length: 12 }, () => uniform(Fp.ORDER));
    return fp12Out(Fp12.fromBigTwelve(logged("random_fp12", coefficients)));
  },
  // prod_i e(P_i, Q_i) for the arrays P (G1 points) and Q (G2 points).
  pairing_reference: (r) => {
    const n = r.left() / 18;
    const ps = Array.from({ length: n }, r.g1);
    const qs = Array.from({ length: n }, r.g2);
    return fp12Out(bn254.pairingBatch(ps.map((g1, i) => ({ g1, g2: qs[i] }))));
  },
  final_exponentiation_reference: (r) => fp12Out(Fp12.finalExponentiate(r.fp12())),
};

const hex = (x) => x.toString(16).padStart(64, "0");

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.end("ok");
    return;
  }
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    const { id, method, params } = JSON.parse(body);
    let reply;
    try {
      const call = params?.[0];
      const handler = method === "resolve_foreign_call" && handlers[call?.function];
      if (!handler) throw new Error(`unknown call ${method} ${call?.function}`);
      reply = { jsonrpc: "2.0", id, result: { values: [handler(reader(call.inputs)).map(hex)] } };
    } catch (error) {
      console.error(error);
      reply = { jsonrpc: "2.0", id, error: { code: -32000, message: String(error) } };
    }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(reply));
  });
});

server.listen(Number(process.argv[2]), "127.0.0.1");

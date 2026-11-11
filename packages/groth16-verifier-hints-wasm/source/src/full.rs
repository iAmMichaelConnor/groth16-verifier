//! Shared global66/global67/global68 arithmetic for runtime four-pair and fixed three-pair certificates.
use super::*;
use ark_bn254::Fr;
use ark_ff::AdditiveGroup;
use std::{str::FromStr, sync::OnceLock};
#[path = "constants.rs"]
mod constants;
#[derive(Clone, Copy)]
struct Point {
    x: Fq2,
    y: Fq2,
}
#[derive(Clone, Copy)]
struct Line {
    r1: Fq2,
    r2: Fq2,
}
struct Schedule {
    d: Line,
    l: Line,
    a: Line,
    rounds: Vec<(Line, Option<Line>)>,
    end_a: Line,
    end_l: Line,
}
struct Config {
    root: Fq12,
    psi_x: Fq2,
    psi_y: Fq2,
    psi2_x: Fq2,
    psi2_y: Fq2,
    d: [Fr; 4],
    c: [Fr; 256],
}
static CONFIG: OnceLock<Config> = OnceLock::new();
fn cfg() -> &'static Config {
    CONFIG.get_or_init(|| {
        let f = |x: &str| Fq::from_str(x).unwrap();
        let f2 = |a: [&str; 2]| Fq2::new(f(a[0]), f(a[1]));
        let a = constants::ROOT27.map(f);
        Config {
            root: from_flat(&a),
            psi_x: f2(constants::PSIX),
            psi_y: f2(constants::PSIY),
            psi2_x: f2(constants::MINUSPSI2X),
            psi2_y: f2(constants::MINUSPSI2Y),
            d: constants::POSEIDOND.map(|x| Fr::from_str(x).unwrap()),
            c: constants::POSEIDONC.map(|x| Fr::from_str(x).unwrap()),
        }
    })
}
pub fn prepare() {
    let _ = cfg();
    super::prepare();
}
fn flat(v: Fq12) -> [Fq; 12] {
    [
        v.c0.c0.c0, v.c0.c0.c1, v.c0.c1.c0, v.c0.c1.c1, v.c0.c2.c0, v.c0.c2.c1, v.c1.c0.c0,
        v.c1.c0.c1, v.c1.c1.c0, v.c1.c1.c1, v.c1.c2.c0, v.c1.c2.c1,
    ]
}
fn from_flat(a: &[Fq]) -> Fq12 {
    let b = |i| Fq2::new(a[i], a[i + 1]);
    Fq12::new(Fq6::new(b(0), b(2), b(4)), Fq6::new(b(6), b(8), b(10)))
}
fn direct(a: Fq12) -> Vec<Fq> {
    let vals = flat(a);
    let mut out = vec![Fq::zero(); 12];
    for (i, j) in [0, 2, 4, 1, 3, 5].iter().enumerate() {
        out[*j] = vals[2 * i] - Fq::from(9u32) * vals[2 * i + 1];
        out[*j + 6] = vals[2 * i + 1];
    }
    out
}
fn tower(a: &[Fq]) -> Fq12 {
    let mut out = vec![];
    for j in [0, 2, 4, 1, 3, 5] {
        out.extend([a[j] + Fq::from(9u32) * a[j + 6], a[j + 6]]);
    }
    from_flat(&out)
}
fn neg(p: Point) -> Point {
    Point { x: p.x, y: -p.y }
}
fn step(p: Point, q: Option<Point>) -> (Point, Line) {
    let (q, s) = match q {
        None => {
            assert!(!p.y.is_zero());
            (
                p,
                p.x.square() * Fq2::from(3u32) * (p.y.double().inverse().unwrap()),
            )
        }
        Some(q) => {
            assert_ne!(q.x, p.x);
            (q, (q.y - p.y) * (q.x - p.x).inverse().unwrap())
        }
    };
    let x = s.square() - p.x - q.x;
    let y = s * (p.x - x) - p.y;
    (
        Point { x, y },
        Line {
            r1: -s,
            r2: s * p.x - p.y,
        },
    )
}
fn psi(p: Point) -> Point {
    let k = cfg();
    Point {
        x: Fq2::new(p.x.c0, -p.x.c1) * k.psi_x,
        y: Fq2::new(p.y.c0, -p.y.c1) * k.psi_y,
    }
}
fn schedule(q: Point) -> Schedule {
    let (twice, d) = step(q, None);
    let (triple, a) = step(twice, Some(q));
    let (_, l) = step(twice, Some(neg(q)));
    let mut p = triple;
    let mut rounds = vec![];
    for digit in constants::LOOP {
        let (v, d) = step(p, None);
        p = v;
        let mut a = None;
        if digit != 0 {
            let (v, l) = step(p, Some(if digit == 1 { q } else { neg(q) }));
            p = v;
            a = Some(l);
        }
        rounds.push((d, a));
    }
    let (p, end_a) = step(p, Some(psi(q)));
    let k = cfg();
    let psi2 = Point {
        x: q.x * k.psi2_x,
        y: q.y * k.psi2_y,
    };
    let (p, end_l) = step(p, Some(psi2));
    let endpoint = psi(psi2);
    assert_eq!(p.x, endpoint.x);
    assert_eq!(p.y, endpoint.y);
    Schedule {
        d,
        l,
        a,
        rounds,
        end_a,
        end_l,
    }
}
fn line(l: Line, p: (Fq, Fq)) -> Vec<Fq> {
    let mut a = vec![Fq::zero(); 12];
    for (j, v) in [
        (0, Fq2::new(p.1, Fq::zero())),
        (1, l.r1 * Fq2::new(p.0, Fq::zero())),
        (3, l.r2),
    ] {
        a[j] = v.c0 - Fq::from(9u32) * v.c1;
        a[j + 6] = v.c1;
    }
    a.truncate(10);
    a
}
fn element(l: Line, p: (Fq, Fq)) -> Fq12 {
    let mut a = line(l, p);
    a.resize(12, Fq::zero());
    tower(&a)
}
fn miller(p: &[(Fq, Fq)], s: &[Schedule]) -> Fq12 {
    let mut v = Fq12::one();
    for (i, x) in s.iter().enumerate() {
        v *= element(x.d, p[i]);
    }
    v.square_in_place();
    for (i, x) in s.iter().enumerate() {
        v *= element(x.l, p[i]);
        v *= element(x.a, p[i]);
    }
    for j in 0..63 {
        v.square_in_place();
        for (i, x) in s.iter().enumerate() {
            v *= element(x.rounds[j].0, p[i]);
            if let Some(a) = x.rounds[j].1 {
                v *= element(a, p[i]);
            }
        }
    }
    for (i, x) in s.iter().enumerate() {
        v *= element(x.end_a, p[i]);
        v *= element(x.end_l, p[i]);
    }
    v
}
fn mul(a: &[Fq], b: &[Fq]) -> Vec<Fq> {
    let mut out = vec![Fq::zero(); a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] += *x * y;
        }
    }
    out
}
fn divide(mut a: Vec<Fq>) -> (Vec<Fq>, Vec<Fq>) {
    let mut q = vec![Fq::zero(); a.len().saturating_sub(12)];
    for i in (12..a.len()).rev() {
        let t = a[i];
        q[i - 12] = t;
        a[i] = Fq::zero();
        a[i - 6] += Fq::from(18u32) * t;
        a[i - 12] -= Fq::from(82u32) * t;
    }
    a.truncate(12);
    (a, q)
}
fn sub(mut a: Vec<Fq>, b: &[Fq]) -> Vec<Fq> {
    for (i, v) in b.iter().enumerate() {
        a[i] -= v;
    }
    a
}
fn relations(
    p: &[(Fq, Fq)],
    s: &[Schedule],
    c: Fq12,
    ci: Fq12,
    w: Fq12,
    preimage: Option<Fq12>,
    split_prefix: bool,
    split_tail: bool,
) -> (Vec<Vec<Fq>>, Vec<Vec<Fq>>) {
    let cp = direct(c);
    let cip = direct(ci);
    let mut polys = vec![sub(mul(&cp, &cip), &[Fq::one()])];
    let mut v = mul(&cip, &cip);
    for (i, x) in s.iter().enumerate() {
        v = mul(&v, &line(x.d, p[i]));
    }
    let mut accs = vec![];
    if split_prefix {
        // Commit reduced H and retain its independent unreduced identity.
        let h = divide(v.clone()).0;
        polys.push(sub(v, &h));
        accs.push(flat(tower(&h)).to_vec());
        v = h;
    }
    v = mul(&v, &v);
    for (i, x) in s.iter().enumerate() {
        v = mul(&v, &line(x.l, p[i]));
        v = mul(&v, &line(x.a, p[i]));
    }
    v = mul(&v, &cp);
    let (mut a, _) = divide(v.clone());
    polys.push(sub(v, &a));
    accs.push(flat(tower(&a)).to_vec());
    for j in 0..63 {
        let mut v = mul(&a, &a);
        for (i, x) in s.iter().enumerate() {
            v = mul(&v, &line(x.rounds[j].0, p[i]));
            if let Some(l) = x.rounds[j].1 {
                v = mul(&v, &line(l, p[i]));
            }
        }
        if constants::LOOP[j] != 0 {
            v = mul(&v, if constants::LOOP[j] == 1 { &cip } else { &cp });
        }
        a = divide(v.clone()).0;
        polys.push(sub(v, &a));
        accs.push(flat(tower(&a)).to_vec());
    }
    let mut v = a;
    for (i, x) in s.iter().enumerate() {
        v = mul(&v, &line(x.end_a, p[i]));
        v = mul(&v, &line(x.end_l, p[i]));
    }
    if split_tail {
        // Global68 binds the reduced line-product terminal as an extra identity.
        let terminal = divide(v.clone()).0;
        polys.push(sub(v, &terminal));
        accs.push(flat(tower(&terminal)).to_vec());
        v = terminal;
    }
    let mut ci1 = ci;
    ci1.frobenius_map_in_place(1);
    let mut c2 = c;
    c2.frobenius_map_in_place(2);
    let mut ci3 = ci;
    ci3.frobenius_map_in_place(3);
    if let Some(t) = preimage {
        v = mul(&v, &direct(t));
    }
    for x in [w, ci1, c2, ci3] {
        v = mul(&v, &direct(x));
    }
    polys.push(sub(v, &[Fq::one()]));
    (polys, accs)
}
fn matrix(s: [Fr; 4]) -> [Fr; 4] {
    let [a, b, c, d] = s;
    [
        a * Fr::from(5u32) + b * Fr::from(7u32) + c + d * Fr::from(3u32),
        a * Fr::from(4u32) + b * Fr::from(6u32) + c + d,
        a + b * Fr::from(3u32) + c * Fr::from(5u32) + d * Fr::from(7u32),
        a + b + c * Fr::from(4u32) + d * Fr::from(6u32),
    ]
}
fn hash(xs: &[Fr]) -> Fr {
    let k = cfg();
    let iv: BigUint = BigUint::from(xs.len()) << 64usize;
    let mut s = [
        Fr::zero(),
        Fr::zero(),
        Fr::zero(),
        Fr::from_be_bytes_mod_order(&iv.to_bytes_be()),
    ];
    for chunk in xs.chunks(3) {
        for (i, x) in chunk.iter().enumerate() {
            s[i] += x;
        }
        s = matrix(s);
        for r in 0..64 {
            if r < 4 || r >= 60 {
                s = matrix(std::array::from_fn(|i| (s[i] + k.c[4 * r + i]).pow([5])));
            } else {
                s[0] = (s[0] + k.c[4 * r]).pow([5]);
                let sum: Fr = s.iter().sum();
                s = std::array::from_fn(|i| s[i] * k.d[i] + sum);
            }
        }
    }
    s[0]
}
fn dense(xs: &[Fq]) -> Vec<Fr> {
    let nums: Vec<BigUint> = xs
        .iter()
        .map(|x| BigUint::from_bytes_be(&x.into_bigint().to_bytes_be()))
        .collect();
    let mask = (BigUint::one() << 240) - 1u32;
    let mut out: Vec<Fr> = nums
        .iter()
        .map(|x| Fr::from_be_bytes_mod_order(&(x & &mask).to_bytes_be()))
        .collect();
    for chunk in nums.chunks(18) {
        let mut high = BigUint::zero();
        for (i, x) in chunk.iter().enumerate() {
            high += (x >> 240) << (14 * i);
        }
        out.push(Fr::from_be_bytes_mod_order(&high.to_bytes_be()));
    }
    out
}
fn evaluate(a: &[Fq], z: Fq) -> Fq {
    a.iter().rev().fold(Fq::zero(), |v, x| v * z + x)
}
fn write_field<F: PrimeField>(v: F, out: &mut Vec<u8>) {
    let b = v.into_bigint().to_bytes_be();
    out.extend(std::iter::repeat(0).take(32 - b.len()));
    out.extend(b);
}
/// Both formats share the exact polynomial and transcript implementation.
pub(crate) fn generate(input: &[u8], schema: &super::schema::Schema) -> Vec<u8> {
    let fixed = schema.fixed;
    let count = schema.identities;
    assert_eq!(input.len(), if fixed { 960 } else { 864 });
    let fq_len = if fixed { 960 } else { 768 };
    let mut raw = vec![];
    for b in input[..fq_len].chunks_exact(32) {
        assert!(b < Fq::MODULUS.to_bytes_be().as_slice(), "noncanonical Fq");
        raw.push(Fq::from_be_bytes_mod_order(b));
    }
    let mut context = vec![];
    for b in input[fq_len..].chunks_exact(32) {
        assert!(b < Fr::MODULUS.to_bytes_be().as_slice(), "noncanonical Fr");
        context.push(Fr::from_be_bytes_mod_order(b));
    }
    let mut p = vec![(raw[0], raw[1]), (raw[6], raw[7]), (raw[8], raw[9])];
    let point = |i| Point {
        x: Fq2::new(raw[i], raw[i + 1]),
        y: Fq2::new(raw[i + 2], raw[i + 3]),
    };
    let origins = if fixed {
        vec![point(2), point(10), point(14)]
    } else {
        p.push((raw[10], -raw[11]));
        vec![point(2), neg(point(20)), neg(point(16)), point(12)]
    };
    let preimage = if fixed {
        Some(from_flat(&raw[18..30]))
    } else {
        None
    };
    let schedules: Vec<_> = origins.into_iter().map(schedule).collect();
    let normalized = miller(&p, &schedules) * preimage.unwrap_or(Fq12::one());
    raw.truncate(if fixed { 10 } else { 24 });
    let width = schema.quotient;
    let mut request = vec![];
    encode(normalized, &mut request);
    encode(cfg().root, &mut request);
    let residue = residue_bytes(&request);
    let c = decode(&residue[..384]);
    let ci = decode(&residue[384..768]);
    let w = decode(&residue[768..]);
    let (polys, accs) = relations(&p, &schedules, c, ci, w, preimage, count >= 67, count == 68);
    assert_eq!(polys.len(), count);
    assert_eq!(accs.len(), schema.accumulators);
    let mut parts: Vec<_> = polys.iter().cloned().map(divide).collect();
    // Only high ZERO coefficients may be discarded for the split-format bound.
    if count >= 67 {
        for (_, q) in &mut parts {
            while q.last().is_some_and(|x| x.is_zero()) {
                q.pop();
            }
        }
    }

    assert!(parts.iter().all(|(r, _)| r.iter().all(|x| x.is_zero())));
    let mut coefficients = raw;
    coefficients.extend(flat(c));
    coefficients.extend(flat(ci));
    coefficients.extend(flat(w));
    for a in &accs {
        coefficients.extend(a);
    }
    let domain = Fr::from_str(schema.domain).unwrap();
    let mut transcript = vec![domain, Fr::from(count as u32)];
    transcript.extend(context);
    transcript.extend(dense(&coefficients));
    let rho = hash(&transcript);
    assert!(!rho.is_zero());
    let rhof = Fq::from_be_bytes_mod_order(&rho.into_bigint().to_bytes_be());
    let mut powers = vec![Fq::one(); count];
    for i in 1..count {
        powers[i] = powers[i - 1] * rhof;
    }
    let mut q = vec![Fq::zero(); width];
    for (i, (_, part)) in parts.iter().enumerate() {
        assert!(part.len() <= width);
        for (j, v) in part.iter().enumerate() {
            q[j] += powers[i] * v;
        }
    }
    let mut transcript = vec![domain + Fr::one(), rho];
    transcript.extend(dense(&q));
    let z = hash(&transcript);
    let zf = Fq::from_be_bytes_mod_order(&z.into_bigint().to_bytes_be());
    let mut blocks = vec![];
    for j in (0..count).step_by(8) {
        let mut b = Fq::zero();
        for i in j..std::cmp::min(j + 8, count) {
            b += powers[i - j] * evaluate(&polys[i], zf);
        }
        blocks.push(b);
    }
    let mut final_sum =
        evaluate(&q, zf) * (zf.pow([12]) - Fq::from(18u32) * zf.pow([6]) + Fq::from(82u32));
    for (j, b) in blocks.iter().enumerate() {
        final_sum -= powers[j * 8] * b;
    }
    assert!(final_sum.is_zero());
    let mut out = vec![];
    encode(normalized, &mut out);
    out.extend(residue);
    for a in accs {
        for x in a {
            write_field(x, &mut out);
        }
    }
    for x in q.into_iter().chain(blocks) {
        write_field(x, &mut out);
    }
    write_field(rho, &mut out);
    write_field(z, &mut out);
    assert_eq!(out.len(), schema.output_bytes);
    out
}

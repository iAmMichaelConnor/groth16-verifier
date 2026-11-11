use bignum::bignum::evaluate_quadratic_expression;
use fields::fp::Fp;
use fields::fp12::Fp12;
use fields::fp2::Fp2;
use fields::fp6::Fp6;
use g2::g2::LineEvaluation;

pub fn twelve<let N: u32>(a: [Fp; N], offset: u32) -> [Fp; 12] {
    let mut result = [Fp::from(0); 12];
    for i in 0..12 {
        result[i] = a[offset + i];
    }
    result
}

pub fn fp12(a: [Fp; 12]) -> Fp12 {
    Fp12 {
        c0: Fp6 { b0: fp2(a[0], a[1]), b1: fp2(a[2], a[3]), b2: fp2(a[4], a[5]) },
        c1: Fp6 { b0: fp2(a[6], a[7]), b1: fp2(a[8], a[9]), b2: fp2(a[10], a[11]) },
    }
}

pub fn coefficients(a: Fp12) -> [Fp; 12] {
    [
        a.c0.b0.c0, a.c0.b0.c1, a.c0.b1.c0, a.c0.b1.c1, a.c0.b2.c0, a.c0.b2.c1, a.c1.b0.c0,
        a.c1.b0.c1, a.c1.b1.c0, a.c1.b1.c1, a.c1.b2.c0, a.c1.b2.c1,
    ]
}

// z starts as a native Fr challenge embedded in Fq. These powers must be
// computed modulo q, not by taking native Fr powers and embedding afterwards.
pub fn powers(z: Fp) -> [Fp; 17] {
    let mut result = [Fp::from(1); 17];
    for i in 1..17 {
        result[i] = result[i - 1] * z;
    }
    result
}

pub fn fp2(a: Fp, b: Fp) -> Fp2 {
    Fp2 { c0: a, c1: b }
}

unconstrained fn dot_hint<let N: u32>(a: [Fp; N], b: [Fp; N]) -> Fp {
    let mut r = Fp::from(0);
    for i in 0..N {
        r = r + a[i] * b[i];
    }
    r
}

// One fused non-native quadratic equation replaces repeated reduced additions.
// The unconstrained calculation supplies only a candidate result. The range
// checks and complete integer/CRT relation in evaluate_quadratic_expression
// enforce correctness, including against a malicious witness generator.
// Use only expression shapes covered by the checked carry and coefficient bounds.
pub fn dot<let N: u32>(a: [Fp; N], b: [Fp; N]) -> Fp {
    // Safety: the complete exact Fq dot-product equation constrains this hint.
    let r = unsafe { dot_hint(a, b) };
    let mut lhs = [[Fp::from(0)]; N];
    let mut rhs = lhs;
    for i in 0..N {
        lhs[i] = [a[i]];
        rhs[i] = [b[i]];
    }
    evaluate_quadratic_expression(lhs, [[false]; N], rhs, [[false]; N], [r], [true]);
    r
}

unconstrained fn difference_hint(a: Fp, b: Fp, c: Fp) -> Fp {
    a - b * c
}

pub fn assert_terminal_identity(product: Fp, qz: Fp, modulus: Fp) {
    // Safety: the complete equation binds the hinted residual; its value must be1.
    let residual = unsafe { difference_hint(product, qz, modulus) };
    evaluate_quadratic_expression(
        [[qz]],
        [[false]],
        [[modulus]],
        [[false]],
        [product, residual],
        [true, false],
    );
    assert(residual == Fp::from(1), "Invalid Groth16 staged residue");
}

// The tower has i^2=-1 and X^6=9+i. Hence a+b*i at tower degree d maps to
// (a-9*b)*X^d+b*X^(d+6). The degree order [0,2,4,1,3,5] matches Fq12's
// Fq6/Fq2 storage order. These are evaluation weights for that exact basis.
// Changing basis/order requires changing both hint generation and constraints.
pub fn tower_weights(powers: [Fp; 17]) -> [Fp; 12] {
    let degrees = [0, 2, 4, 1, 3, 5];
    let mut weights = [Fp::from(0); 12];
    for i in 0..6 {
        let j = degrees[i];
        weights[2 * i] = powers[j];
        weights[2 * i + 1] = powers[j + 6] - Fp::from(9) * powers[j];
    }
    weights
}

pub fn line_weights(x: Fp, y: Fp, powers: [Fp; 17]) -> [Fp; 6] {
    let u = powers[6] - Fp::from(9);
    let xz = x * powers[1];
    [y, y * u, xz, xz * u, powers[3], powers[9] - Fp::from(9) * powers[3]]
}

pub fn line_value(line: LineEvaluation, weights: [Fp; 6]) -> Fp {
    dot(
        [line.r0.c0, line.r0.c1, line.r1.c0, line.r1.c1, line.r2.c0, line.r2.c1],
        weights,
    )
}

// This evaluates every supplied coefficient, including the final partial block,
// at the SAME z as the relation polynomials. Blocks of 16 share powers z^0..z^15;
// outer scales are powers of z^16. The block size is an arithmetic choice, not
// a recursion boundary or permission to omit coefficients.
// Q(z)=sum_b (z^16)^b * sum_{j<16,16*b+j<N} q_(16*b+j)*z^j.
// N=76 has a 12-coefficient last block; N=94 has a 14-coefficient last block.
// Zero padding changes neither degree nor the coefficient commitment.
pub fn quotient_value<let N: u32>(q: [Fp; N], powers: [Fp; 17]) -> Fp {
    let mut p16 = [Fp::from(0); 16];
    for j in 0..16 {
        p16[j] = powers[j];
    }
    let mut blocks = [Fp::from(0); (N + 15) / 16];
    for i in 0..(N + 15) / 16 {
        let mut coeffs = [Fp::from(0); 16];
        for j in 0..16 {
            if 16 * i + j < N {
                coeffs[j] = q[16 * i + j];
            }
        }
        blocks[i] = dot(coeffs, p16);
    }
    let mut scales = [Fp::from(1); (N + 15) / 16];
    for i in 1..(N + 15) / 16 {
        scales[i] = scales[i - 1] * powers[16];
    }
    dot(blocks, scales)
}

/// Evaluate the three terminal Frobenius factors against one linear functional.
/// Frobenius^2 is diagonal over Fq in the existing tower basis. Move its same
/// real scalar for both coordinates of each Fq2 slot onto the evaluation weights,
/// and reuse those weights for c and Frobenius^1(ci). This changes no transcript.
/// ci imaginary components must be canonical before the inherited conjugation;
/// all other operands retain the existing bounded BigNum evaluator contract.
// With ell_a(v)=dot(v,a) and diagonal Frobenius^2 matrix D,
// ell_a(Dv)=ell_(Da)(v). Return ell_a(ci^q), ell_(Da)(c),
// ell_(Da)(ci^q), which are exactly ci^q, c^(q^2), ci^(q^3) at z.
// Sharing Da avoids materializing/reducing two transformed Fq12 elements.
pub fn residue_frobenius_evaluations(c: Fp12, ci: Fp12, weights: [Fp; 12]) -> (Fp, Fp, Fp) {
    let ci1 = ci.frobenius();
    let factors = [
        Fp::from(1),
        fields::fp2::frobenius_2_power_2(),
        fields::fp2::frobenius_2_power_4(),
        fields::fp2::frobenius_2_power_1(),
        fields::fp2::frobenius_2_power_3(),
        fields::fp2::frobenius_2_power_5(),
    ];
    let mut square_weights = weights;
    for i in 0..6 {
        square_weights[2 * i] = weights[2 * i] * factors[i];
        square_weights[2 * i + 1] = weights[2 * i + 1] * factors[i];
    }
    (
        dot(coefficients(ci1), weights), dot(coefficients(c), square_weights),
        dot(coefficients(ci1), square_weights),
    )
}

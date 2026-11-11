use crate::fp::{Fp, fp_zero};

/// G1 affine point over Fp. Infinity is the encoding (0, 0).
pub struct G1Affine {
    pub x: Fp,
    pub y: Fp,
}

impl G1Affine {
    pub fn is_infinity(self) -> bool {
        (self.x == fp_zero()) & (self.y == fp_zero())
    }
}

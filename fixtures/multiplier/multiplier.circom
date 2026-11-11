pragma circom 2.2.3;

// Prove knowledge of private factors for a public product.
template Multiplier() {
    signal input a;
    signal input b;
    signal output product;
    product <== a * b;
}

component main = Multiplier();

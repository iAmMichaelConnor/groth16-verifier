export function prepareConstants(raw: any): {};
export function prepareKey(key: any, k: any): {
    n: number;
    alpha: import("@noble/curves/abstract/weierstrass").ProjPointType<bigint>;
    beta: import("@noble/curves/abstract/weierstrass").ProjPointType<import("@noble/curves/abstract/tower").Fp2>;
    gamma: import("@noble/curves/abstract/weierstrass").ProjPointType<import("@noble/curves/abstract/tower").Fp2>;
    delta: import("@noble/curves/abstract/weierstrass").ProjPointType<import("@noble/curves/abstract/tower").Fp2>;
    ic: any;
    keyHash: bigint;
};
export function prepareRequest(proof: any, inputs: any, key: any, k: any): {
    points: any[][];
    origins: any[][];
    raw: any;
    context: any[];
};
export function checkResiduePreflight(values: any): void;
export function prepareFixedContext(key: any, preimage: any, k: any): {
    t: {
        c0: {
            c0: {
                c0: bigint;
                c1: bigint;
            };
            c1: {
                c0: bigint;
                c1: bigint;
            };
            c2: {
                c0: bigint;
                c1: bigint;
            };
        };
        c1: {
            c0: {
                c0: bigint;
                c1: bigint;
            };
            c1: {
                c0: bigint;
                c1: bigint;
            };
            c2: {
                c0: bigint;
                c1: bigint;
            };
        };
    };
    delta: {
        d: {
            x: import("@noble/curves/abstract/tower").Fp2;
            y: import("@noble/curves/abstract/tower").Fp2;
            r1?: undefined;
            r2?: undefined;
        } | {
            r1: import("@noble/curves/abstract/tower").Fp2;
            r2: import("@noble/curves/abstract/tower").Fp2;
            x?: undefined;
            y?: undefined;
        };
        l: {
            x: import("@noble/curves/abstract/tower").Fp2;
            y: import("@noble/curves/abstract/tower").Fp2;
            r1?: undefined;
            r2?: undefined;
        } | {
            r1: import("@noble/curves/abstract/tower").Fp2;
            r2: import("@noble/curves/abstract/tower").Fp2;
            x?: undefined;
            y?: undefined;
        };
        a: {
            x: import("@noble/curves/abstract/tower").Fp2;
            y: import("@noble/curves/abstract/tower").Fp2;
            r1?: undefined;
            r2?: undefined;
        } | {
            r1: import("@noble/curves/abstract/tower").Fp2;
            r2: import("@noble/curves/abstract/tower").Fp2;
            x?: undefined;
            y?: undefined;
        };
        rounds: never[];
    };
    gamma: {
        d: {
            x: import("@noble/curves/abstract/tower").Fp2;
            y: import("@noble/curves/abstract/tower").Fp2;
            r1?: undefined;
            r2?: undefined;
        } | {
            r1: import("@noble/curves/abstract/tower").Fp2;
            r2: import("@noble/curves/abstract/tower").Fp2;
            x?: undefined;
            y?: undefined;
        };
        l: {
            x: import("@noble/curves/abstract/tower").Fp2;
            y: import("@noble/curves/abstract/tower").Fp2;
            r1?: undefined;
            r2?: undefined;
        } | {
            r1: import("@noble/curves/abstract/tower").Fp2;
            r2: import("@noble/curves/abstract/tower").Fp2;
            x?: undefined;
            y?: undefined;
        };
        a: {
            x: import("@noble/curves/abstract/tower").Fp2;
            y: import("@noble/curves/abstract/tower").Fp2;
            r1?: undefined;
            r2?: undefined;
        } | {
            r1: import("@noble/curves/abstract/tower").Fp2;
            r2: import("@noble/curves/abstract/tower").Fp2;
            x?: undefined;
            y?: undefined;
        };
        rounds: never[];
    };
};
export function generateKernel(input: any, k: any): any;
export function generateKernel67(input: any, k: any): any;
export function generateKernel68(input: any, k: any): any;
export function generateFixedKernel(input: any, configuration: any, k: any): {
    data: {
        raw: any;
        context: any;
        residue: any;
        accumulators: any;
        quotient: any;
        block_residuals: any;
    };
    facts: {
        rho: bigint;
        z: bigint;
    };
    normalized: any[];
};
export function generateFixedKernel67(input: any, configuration: any, k: any): {
    data: {
        raw: any;
        context: any;
        residue: any;
        accumulators: any;
        quotient: any;
        block_residuals: any;
    };
    facts: {
        rho: bigint;
        z: bigint;
    };
    normalized: any[];
};
export function generateFixedKernel68(input: any, configuration: any, k: any): {
    data: {
        raw: any;
        context: any;
        residue: any;
        accumulators: any;
        quotient: any;
        block_residuals: any;
    };
    facts: {
        rho: bigint;
        z: bigint;
    };
    normalized: any[];
};
export function hash(xs: any, k: any): bigint;
export function dense(values: any): any;
export function encoded(a: any): any;
export function coords1(p: any): any[];
export function coords2(p: any): any[];
export const Q: bigint;
export const R: bigint;

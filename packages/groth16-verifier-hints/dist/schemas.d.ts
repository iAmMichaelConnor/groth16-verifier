/** Internal immutable protocol metadata, pinned to the compiled Noir formats. */
export interface CertificateSchema {
    readonly id: number;
    readonly name: string;
    readonly identities: number;
    readonly accumulators: number;
    readonly quotient: number;
    readonly domain: bigint;
    readonly capsuleBase: bigint;
    readonly inputBytes: number;
    readonly outputBytes: number;
}
export declare const RUNTIME_66: Readonly<CertificateSchema>;
export declare const FIXED_66: Readonly<CertificateSchema>;
export declare const RUNTIME_67: Readonly<CertificateSchema>;
export declare const FIXED_67: Readonly<CertificateSchema>;
export declare const FIXED_68: Readonly<CertificateSchema>;
export declare const RUNTIME_68: Readonly<CertificateSchema>;

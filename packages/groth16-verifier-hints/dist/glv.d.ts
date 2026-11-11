import { type Integer } from "./parsers.js";
/** Nearest lattice-plane split. Both signed components have magnitude < 2^126. */
export declare function decomposeScalar(value: Integer): Readonly<{
    magnitudes: readonly [bigint, bigint];
    negative: readonly [boolean, boolean];
}>;

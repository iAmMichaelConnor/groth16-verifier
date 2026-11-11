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
const schema = (value: CertificateSchema): Readonly<CertificateSchema> =>
  Object.freeze(value);
export const RUNTIME_66 = schema({
  id: 1,
  name: "groth16-runtime-global66-v1",
  identities: 66,
  accumulators: 64,
  quotient: 188,
  domain: 0x4731365f52554e54494d455f504149525f563100n,
  capsuleBase: 0x4731365f52554e54494d455f48494e5400n,
  inputBytes: 864,
  outputBytes: 32480,
});
export const FIXED_66 = schema({
  id: 2,
  name: "groth16-fixed-global66-v1",
  identities: 66,
  accumulators: 64,
  quotient: 152,
  domain: 407173916385039488777917032230477238504980361472n,
  capsuleBase: 0x47524f544831365f5354414745n,
  inputBytes: 960,
  outputBytes: 31328,
});
export const RUNTIME_67 = schema({
  id: 3,
  name: "groth16-runtime-global67-v1",
  identities: 67,
  accumulators: 65,
  quotient: 115,
  domain: 26636177751600359597021628385971156694668806978941184n,
  capsuleBase: 0x4731365f52554e54494d455f50524546495800n,
  inputBytes: 864,
  outputBytes: 30528,
});
export const FIXED_67 = schema({
  id: 4,
  name: "groth16-fixed-global67-v1",
  identities: 67,
  accumulators: 65,
  quotient: 108,
  domain: 406435817740251192357087807242550169024528265472n,
  capsuleBase: 0x47524f544831365f5052454649585f5631n,
  inputBytes: 960,
  outputBytes: 30304,
});

export const FIXED_68 = schema({
  id: 5,
  name: "groth16-fixed-global68-v1",
  identities: 68,
  accumulators: 66,
  quotient: 76,
  domain: 1587639913047856220144874247109043781673300224n,
  capsuleBase: 0x47524f544831365f5052454649585f5441494c5f5631n,
  inputBytes: 960,
  outputBytes: 29664,
});

export const RUNTIME_68 = schema({
  id: 6,
  name: "groth16-runtime-global68-v1",
  identities: 68,
  accumulators: 66,
  quotient: 94,
  domain: 406435817742925408890100530792079663938818945280n,
  capsuleBase: 0x4731365f52554e54494d455f5441494c00n,
  inputBytes: 864,
  outputBytes: 30240,
});

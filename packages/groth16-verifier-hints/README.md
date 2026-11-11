> **Experimental software. Unaudited. May contain bugs.**

# groth16-verifier-hints

Prepares BN254 Groth16 hints (ordinary snarkjs/Circom keys and proofs, fixed or
runtime keys) for the Noir verifiers in this repository. Unpublished: install
from a packed tarball (`npm pack` in this directory). Generating key material
and Aztec consumers, choosing a profile and calling the consumer are covered in
[docs/INTEGRATION.md](../../docs/INTEGRATION.md).

```ts
import { createVerifier } from 'groth16-verifier-hints/current';
const verifier = createVerifier(profile, fixedKeyDescriptor, { backend: 'stock-v6' });
const prepared = await verifier.prepare({
  proof: snarkjsProof,
  publicInputs: ['33'],
  application: [chainId, version, consumerAddress, action, beneficiary, nonce],
});
// prepared.capsules, prepared.callArguments, prepared.producerInputs,
// plus the profile hash, statement, application fields and underlying hints.
```

`/current` binds the key, input count, certificate, statement schema, compiler
pins and backend declaration of a trusted `groth16-verifier-profile-v2` profile
(`parseProfile` validates, `profileHash` hashes). For a runtime profile pass the
snarkjs verification key instead of the descriptor.

## Runtime contract

ESM with TypeScript declarations. The default implementation uses pinned Noble
dependencies; importing it does not start Barretenberg, download an SRS, run
Python, prove or submit. Field values are `bigint` or canonical unsigned
decimal/hex strings, never JavaScript numbers (convert large JSON integers
losslessly first). Proof and key objects use snarkjs `groth16`/`bn128` tags and
real/imaginary Fq2 order; Ethereum byte encodings need an adapter. Pairing operands
and the computed point L must be finite; unused infinity IC entries are supported.
Prepared key handles live in a private WeakMap and stop being handles if cloned.

Hints and capsules (`{scope, slot, values}`) are untrusted witness data; producer
inputs are data, not a proof. The circuit checks the relation; the application
authorizes the key or producer, binds context and enforces replay policy.

## Entry points

| Entry | Purpose |
| --- | --- |
| `/current` | Profile-bound preparation for generated consumers |
| `/fixed` | Advanced fixed-key preparation (`prepareFixedKey`, `fixedConfigurationHash`, versioned hint functions) |
| `/transcript` | Canonical-field Poseidon2 for integration transcripts |
| `/wasm`, `/wasm-assets` | Caller-supplied WASM kernels; digest-checked asset loading |
| `/aztec` | `preparePrivateCall`, `prepareOffchainCall` over caller-supplied SDK constructors |
| `/producer` | `createProducer` over caller-supplied NoirJS/UltraHonk factories |
| `/worker`, `/worker-handler` | Owned WASM Worker client and its worker-side installer |
| package root | Runtime helpers, parsing, GLV and serialization |

**Certificate versions are not interchangeable.** Generated consumers use the 68
format through `/current`. Unsuffixed `prepareRuntimeHints` / `prepareFixedHints`
produce the 66-identity format (fixed: 64 accumulators, Q152) and the `67`
helpers the 67-identity format (65 accumulators, Q108); transcript domains and
capsule slots differ, and runtime certificates (four pairs, runtime68 Q94) differ
from fixed ones. `privateCallArguments` checks only runtime arity.

**Fixed keys.** The `/current` descriptor is
`{schema: 'groth16-fixed-key-v1', verificationKey, tPreimage}` with twelve
canonical Fq coefficients matching the compiled provider's key and alpha-beta
preimage. Preprocessing checks `FE(t_preimage) * e(alpha,beta) = 1` in Noble's
pairing convention (another final-exponent convention selects the wrong
preimage); a self-computed hash beside an untrusted descriptor is not approval.
`/fixed` uses `schema: 'groth16-fixed-global66-v1'` for every version, naming the
encoding, not the certificate. `prepareFixedHints68` returns raw10, residue36, 66
accumulators, Q76, nine residuals and a 2,631-field common capsule with the residue
as a separate argument. Scaffolded wrappers instead read a 2,739-field capsule from
the same slot with the 108 residue fields first, which only `/current` produces:
passing `prepareFixedHints68(...).capsules` to them rejects a valid proof. The fixed
GLV frontend emits biased components `x+2^126, y+2^126` (each below `2^127`)
rather than the runtime magnitude/sign encoding. Residue witnesses are not unique;
correctness rests on the constrained relation.

## Optional WASM kernel

The separate private package `groth16-verifier-hints-wasm`
(`packages/groth16-verifier-hints-wasm`) supplies one digest-pinned kernel serving all six
certificate schemas; nothing loads it implicitly.

```ts
import { createProfileWasmKernel } from 'groth16-verifier-hints/wasm-assets';
const bytes = await readFile(new URL(import.meta.resolve('groth16-verifier-hints-wasm/v1/hints-kernel.wasm')));
const kernel = await createProfileWasmKernel(profile, bytes);
const prepared = await verifier.prepare(request, { kernel });
```

In a browser the application serves the asset same-origin and passes the fetched
bytes. The loader copies them, checks the length and SHA-256 in `v1/manifest.json`
(471,268 bytes,
`7d26252af3c97a54b5a9f27f4ead6b7317ea0ca7b637d98affdd711f242dd2d0`) and the
module capabilities, and picks fixed68 or runtime68 from the profile. An invalid
proof may trap an instance; recreate the kernel. The `/wasm` adapter takes module
bytes for advanced use (`createRuntimeWasmKernels68`; `createWasmKernels68` lacks
`runtime68`); authenticate them first.

The binary is not tracked. Build it with Rust 1.89.0 and the
`wasm32-unknown-unknown` target:
`python3 packages/groth16-verifier-hints-wasm/rebuild.py --output-dir /fresh/dir`
(offline Cargo unless `--allow-network`; `source/Cargo.lock` pins dependencies and
`provenance.json` the sources and expected digest). When `rebuild.json` reports
`byteIdentical: true`, copy
`target/wasm32-unknown-unknown/release/groth16_hint_runtime_tail_kernel.wasm` to
`packages/groth16-verifier-hints-wasm/v1/hints-kernel.wasm`. `test:wasm` and `test:all`
need it; `test:fast` does not.

## Optional WASM Worker

Async calls do not unblock the UI thread. `/worker` moves the WASM kernel into a
dedicated Worker; parsing, validation, input MSM and packet creation stay on the
main thread (there is no JavaScript-kernel Worker).

```ts
// hints.worker.ts, bundled as a separate ES module
import { installWasmWorker } from 'groth16-verifier-hints/worker-handler';
installWasmWorker(self);
```

```ts
import { createWasmWorkerKernel } from 'groth16-verifier-hints/worker';
const client = await createWasmWorkerKernel(profile, wasmBytes,
  () => new Worker(workerUrl, { type: 'module' }));
try {
  const prepared = await verifier.prepare(request, { kernel: client.kernel });
} finally {
  client.dispose();
}
```

The factory must return a **new** Worker, which the client then owns.
`dispose()`, initialization failure, malformed responses, kernel or worker errors
and timeouts (default 60,000 ms; fourth argument `{ timeoutMs }`) reject pending
requests and terminate it once; recreate the client after a failure. Buffers are
copied before transfer. The main thread builds the final packet so it keeps its
module-local provenance, which the Aztec and producer adapters check; a packet
cloned back from a Worker would lose it. Use the `ES2022`/`WebWorker` libraries for
the worker entry.

## Python tools

`python/groth16` holds the build-time generators (`groth16.generate`,
`groth16.scaffold`, `groth16.producer`, `groth16.artifacts`) and the toolchain
resolver; docs/INTEGRATION.md documents them. Tests, from the repository root:
`python3 -m unittest discover -s packages/groth16-verifier-hints/python/groth16/tests -v`.

## Development

From the repository root:

```sh
npm ci --ignore-scripts --prefix packages/groth16-verifier-hints
npm run build --prefix packages/groth16-verifier-hints   # verifies exports and declarations before replacing dist
npm test --prefix packages/groth16-verifier-hints        # focused current SDK checks
npm run test:distribution --prefix packages/groth16-verifier-hints
npm pack ./packages/groth16-verifier-hints
```

Host tests, witness and constraint checks, private calls and complete proofs are
distinct evidence levels.

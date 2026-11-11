# Contributing

Thank you for your interest in contributing! This guide covers the
[layout](#layout), [setup](#setup), [tests](#tests), [benchmarks](#benchmarks),
[generated files](#generated-files), [releases](#releases) and how this
repository [differs from the noir-library-starter
template](#differences-from-the-noir-library-starter-template). Keep pull
requests focused, and open an issue first for anything substantial. Breaking
changes must update the README or the documentation. Run every command below
from the repository root.

## Layout

The repository is a Nargo workspace: the libraries are in `noir/<package>/`,
their support packages in `noir/internal/<package>/`, and test-only packages in
`tests/<package>/`.

## Setup

- Noir: install with [noirup](https://github.com/noir-lang/noirup), e.g.
  `noirup -v 1.0.0`. Either version CI tests works (see the README).
- Python 3.10+ (standard library only), for the generators and host checks.
- Node.js 22+, for the hint SDKs, the proof-vector generator
  (`npm ci --ignore-scripts --prefix packages/groth16-verifier-hints`) and the
  oracle tests (`npm ci --ignore-scripts --prefix tests/bn254_oracle_tests`).
- bb, only for benchmarks:
  `curl -L https://bbup.aztec.network | bash && ~/.bb/bbup -v 6.0.0`.

## Tests

```bash
nargo test --force-brillig --inliner-aggressiveness 0 --package bn254_g1  # one package, as pull requests run it
nargo test --package bignum                                               # constrained, as pull requests run bignum
nargo test --package bn254_g2 --test-threads 4                            # one package constrained, as the nightly slow mode runs it
nargo check --workspace                                                   # every package, incl. the API typecheck crates
./scripts/check-public-api.sh                                             # partial verifier helpers stay private
```

`nargo test` proves nothing: it compiles each test and executes it. Run as
written (constrained), each test compiles to an ACIR circuit; with
`--force-brillig` the same test compiles to unconstrained bytecode and executes
the same assertions. `--inliner-aggressiveness 0` is what makes that fast here:
with the default inliner, compiling the BN254 arithmetic as Brillig mostly took
longer than the constrained run, and over 12 minutes for `bn254_g2`,
`runtime_g1`, `bn254_fields_slow_tests` and `runtime_multiplier_vector`. Pull
requests run every package with both flags except the vendored suites, which
run constrained only, as their upstreams run them (`bignum` on pull requests,
all three nightly): many of their tests feed a malicious hint and expect a
failed constraint, and a few that pass constrained fail in Brillig (23, 9 and 9
of their tests fail unconstrained; some share their names with passing
instances, and nargo cannot exclude tests, so a suite cannot be split by
mode). The nightly workflow runs the same set on Noir nightly, and every
package constrained on Noir 1.0.0 (the slow mode), except `bn254_pairing` (see
below) and `fixed_multiplier_vector` and `sp1_v6_vector`, whose constrained runs
are opt-in. The proof-vector packages and `sp1` run only their `nightly` modules
constrained (`nargo test --package P nightly::`): one test per stage of the
circuit, because the constrained run compiles the same circuit for every test
and only shows that it enforces what the fast run already checked for every
input. Constrained tests pass their
inputs through `std::hint::black_box` so that the compiler cannot fold them
away.

Memory grows with `--test-threads` (nargo's default is one thread per core);
CI passes 4, the vCPUs of a hosted runner, except where the table says. Measured
locally with Noir 1.0.0; the unconstrained mode is `--force-brillig
--inliner-aggressiveness 0`, and the local constrained runs used the thread
counts given:

| Package | Tests | Per pull request, 4 threads | Nightly slow mode | Local constrained run |
| --- | ---: | --- | --- | --- |
| `bn254_fields` | 6 | unconstrained: 18 to 25 s, 0.6 GB | `--no-fuzz` (3 tests), 4 threads, 30 min timeout | `--no-fuzz`, 4 threads: 6 s, 0.4 GB |
| `bn254_fields_slow_tests` | 6 | unconstrained: 9 s, 0.7 GB | 1 thread, 60 min timeout | 1 thread: 11 min, 15.0 GB; 6 threads: 7 min 16 s, 20.9 GB |
| `bn254_g1` | 3 | unconstrained: 6 s, 0.6 GB | 4 threads, 30 min timeout | 32 threads: 19 s, 0.8 GB |
| `bn254_g2` | 2 | unconstrained: 12 s, 0.6 GB | 4 threads, 30 min timeout | 4 threads: 1 min 24 s to 3 min 15 s, 4.3 GB |
| `bn254_pairing` | 3 | unconstrained: 21 s, 3.1 GB | not run | 4 threads: stopped after 3 min at 19.4 GB |
| `runtime_key_schema` | 5 | unconstrained: 6 s, 0.6 GB | 4 threads, 30 min timeout | 32 threads: 12 s, 0.6 GB |
| `sp1` | 11 | unconstrained: 15 s, 2.4 GB | `nightly::` (4 tests), 4 threads, 30 min timeout | `nightly::`, 4 threads: 4 s, 0.9 GB |
| `bignum` | 363 | constrained: 2 min 5 s, 1.3 GB | 4 threads, 30 min timeout | 4 threads: 2 min 5 s, 1.3 GB |
| `bigcurve_fixed` | 152 | not run (9 tests fail unconstrained) | 4 threads, 60 min timeout | 4 threads: 6 min to over 10 min, 5.8 GB |
| `bigcurve_runtime_signed` | 152 | not run (9 tests fail unconstrained) | 4 threads, 60 min timeout | 4 threads: 5 min 47 s to over 10 min, 5.5 GB |
| `fixed_g1_helpers` | 8 | unconstrained: 6 s, 0.5 GB | 4 threads, 30 min timeout | 32 threads: 9 s, 0.9 GB |
| `runtime_g1` | 4 | unconstrained: 12 s, 0.9 GB | 4 threads, 30 min timeout | 4 threads: 1 min 30 s, 1.2 GB |
| `transcript_packing` | 2 | unconstrained: 2 s, 0.1 GB | 4 threads, 30 min timeout | 32 threads: 3 s, 0.1 GB |
| `fixed_multiplier_vector` | 5 | unconstrained: 28 s, 2.4 GB | not run; opt-in: `nightly::` (4 tests), 1 thread, about 16 min | `nightly::`, 4 threads: 4 min 8 s, 30.1 GB (about 4 min and 7.5 GB per test) |
| `runtime_multiplier_vector` | 5 | unconstrained: 26 s, 2.6 GB | `nightly::` (4 tests), 4 threads, 30 min timeout | `nightly::`, 4 threads: 1 min 32 s, 6.9 GB |
| `sp1_v6_vector` | 12 | unconstrained: 31 s, 2.9 GB | not run; opt-in: `nightly::` (3 tests), 1 thread, about 14 min | `nightly::`, 3 threads: 4 min 31 s, 22.8 GB (about 4.5 min and 7.6 GB per test) |

Ranges are the fastest and slowest of several local runs on a shared machine.
A `*_slow_tests` crate is a sibling crate holding tests that need their own
handling in the nightly constrained run (memory or time) or that only make sense
constrained; it also runs per pull request when its fast mode takes under about
2 minutes.
`bn254_fields_slow_tests` runs per pull request (9 s unconstrained).

`bn254_fields_slow_tests` holds the `bn254_fields` tower tests whose circuits
are large (the Fp12 relations and the sparse, Frobenius and cyclotomic
routines against the general multiplication); constrained, a single one of
them needs most of a hosted runner's 16 GB, as does a single
`fixed_multiplier_vector` or `sp1_v6_vector` test (about 7.6 GB and 4 to 5
minutes each). The nightly workflow runs `bn254_fields_slow_tests` one test at
a time and does not run the other two: they and the hint-guard probe run only
when the nightly workflow is started by hand with `heavy` ticked. The opt-in
times in the table are estimates from the local per-test times.

Tests that take arguments are random-input tests: nargo's fuzzer runs each one
on inputs it generates, starting from all zeros, for about a second (at least
nine inputs). The `random_` tests in `bn254_fields` check on random elements
what the fixed tests check on small ones: the sparse, specialised and inverse
Fp2, Fp6 and Fp12 routines against the general multiplication, commutativity,
distributivity, and the Frobenius and cyclotomic identities. They are
`unconstrained`, so they check computed values, not constraints, and they check
the routines against each other (`bn254_oracle_tests`, below, checks them
against an external reference); their coefficients are Noir `Field` values, so
none lies between r and p. Compiled without `--inliner-aggressiveness 0`, each
took over 2.5 minutes and 7 to 10 GB, so the slow mode runs `bn254_fields` with
`--no-fuzz`, which skips them.

`bn254_pairing`'s tests are `unconstrained` too: they compare e(G1, G2) with the
value `@noble/curves` (a dependency of the hint SDK) computes, check that it is
not 1 and has order r, and check bilinearity and `pairing_multi` on fixed
scalars (a fuzzed pairing input took about a minute). Constrained, two tests of
pairing properties (three pairings and one two-pair product) peaked above 60 GB
at four threads, far beyond a hosted runner, and the unconstrained tests
compiled without `--inliner-aggressiveness 0` were still running after 3
minutes at 19.4 GB, so the slow mode does not run the package. Its tower
arithmetic is tested in `bn254_fields` and its G2 helpers in `bn254_g2`.

`tests/bn254_oracle_tests` compares the tower arithmetic and the pairing with
`@noble/curves` (MIT, pinned in the package's `package.json`), an
implementation independent of this repository: Fp2, Fp6 and Fp12
multiplication, squaring and inversion, the three Frobenius maps and the
sparse line product on fuzzer inputs, and `pairing`, `pairing_multi` and
`final_exponentiation` on random points and Fp12 elements that the oracle
draws and logs. The values agree without conversion: both use the same tower,
and both final exponentiations return the canonical pairing to the power
2x(6x^2 + 3x + 1). `miller_loop` is not compared: the two Miller loop values
differ and agree only after the final exponentiation. These tests are
`unconstrained` too, so they compare values, not constraints. They call an
oracle and fail without its server, so no other test run selects the package:
`tests/bn254_oracle_tests/run.sh` starts the server (`oracle_server.mjs`, on
127.0.0.1:8095), runs the package in the pull-request mode and stops the
server. Locally the run took 20 to 29 s and 1.8 GB on either toolchain, with
25 to 57 fuzzer inputs per tower test; the host job runs it on pull requests.

The `tests/` packages run the verifiers on saved proofs. On the Circom proof
(`fixtures/multiplier`), `fixed_multiplier_vector` and
`runtime_multiplier_vector` check that it verifies, that a changed public input
is rejected, and that the proof with A or B negated, or with a forged
certificate, is rejected by the pairing check. Those pairing rejections happen
first at a Brillig hint's self-check;
`scripts/tests/heavy_constraints_without_hint_guard.py` removes that check in a
scratch copy and requires the constraints to reject them.

`sp1_v6_vector` runs `sp1::v6::verify` on two saved SP1 v6 proofs
(`fixtures/sp1-v6`); both verify. For the program vkey, the public values and
the nonce, a vector changes the input and recomputes its GLV components: with
the saved input point L the input MSM rejects it, and with L moved to match
the pairing check rejects it. The exit code and the root are fixed by
`v6::verify`, so their vectors run against the Groth16 statement in the `sp1`
package (`noir/sp1/src/v6/binding_tests.nr`), the only place the crate-private
key is reachable. The proof with A negated, and the A, B, C of an SP1 v5 and an
SP1 v6.0.0 proof put with the saved statement, fail the pairing check; the SP1
v6.0.0 proof with its own statement is checked at the pairing level by
`scripts/tests/test_sp1_v6_cross_version.py`.
`runtime_api_typecheck` and `sp1_api_typecheck` only need to compile.

Host checks (Python standard library and Node):

```bash
python3 -m unittest discover -s scripts/tests -p 'test_*.py'      # schedule, subgroup, equality, SP1 key, hint binding (about 1 min)
python3 -m unittest discover -s scripts/tests -p 'heavy_*.py'     # constraints without the hint guard (all three crates 19 min, 7.9 GB; HINT_GUARD_CRATES=sp1_v6_vector selects crates)
python3 -m unittest discover -s packages/groth16-verifier-hints/python/groth16/tests -p 'test_*.py'
python3 -m unittest discover -s packages/groth16-verifier-sp1/python/tests -p 'test_*.py'
npm run test:fast --prefix packages/groth16-verifier-hints
npm test --prefix packages/groth16-verifier-sp1
tests/bn254_oracle_tests/run.sh                                   # tower and pairing against @noble/curves (about 20 to 30 s)
```

### What CI runs

Every pull request runs each package in the mode the table gives, in its own
`test` job (one job per package and toolchain; the unconstrained ones took under
30 seconds locally, the longest is `bignum`, constrained, about 2 minutes),
`nargo check --workspace` with `check-public-api.sh` (about 2 minutes), the host
tests with the oracle tests (about 3 minutes, of which the oracle run took 20 to
30 seconds locally) and the benchmark workflow, whose constrained export is
the longest job: about 7 minutes, dominated by `sp1_verify` and
`runtime_verifier`. Expect a pull request's checks to finish in about 10
minutes when it touches a circuit, and a few minutes otherwise.

The nightly workflow runs the pull-request set on Noir nightly, and each
package in the table's slow-mode column constrained on Noir 1.0.0, one job per
package (the `nightly` modules only, where a package has one). Started by hand
with `heavy` ticked, it also runs `fixed_multiplier_vector` and `sp1_v6_vector`
constrained and the hint-guard probe: for the two multiplier packages the
honest proof, A negated and the forged certificate, and for `sp1_v6_vector` the
honest proof and A negated. The probe reruns those tests constrained, without
the Brillig hint's self-check, the fixed-key and SP1 packages one test at a
time. Input-binding rejections fail at plain constraints that the hint guard
does not touch, so the probe does not rerun them. It needs the constrained
mode: what it shows is that the circuit's range checks reject those proofs,
which an unconstrained run cannot show.

Not run in CI at all:

- `bn254_pairing` constrained (see above);
- the Brillig benchmark report (see [Benchmarks](#benchmarks)).

## Benchmarks

On pull requests the benchmark workflow runs only when a change can alter a
circuit (library sources, the workspace manifest, the report scripts or the
workflow itself); every push to `main` runs it.

`bn254_fields`, `bn254_g1`, `bn254_g2`, `runtime_verifier` and `sp1` each have a
`benchmarks.nr` module of `#[export]` functions. See the README for the command;
the benchmark workflow posts the gate diff on pull requests and records history
on the `gh-pages` branch, which must exist before the first workflow run.
Locally the export took 7 minutes and the largest single export peaked at 7.5
GB, so CI exports one package at a time. The `sp1` package exports both SP1
benchmarks, one after the other: 9 min 18 s locally, on a loaded machine.
There is no Brillig report:
`nargo export --workspace --force-brillig` took about 26 minutes for
`sp1_verify` alone, and `runtime_verify_1` had not finished after another 37
minutes.

## Generated files

Generated Noir is never edited by hand. `python3 scripts/generate.py` runs every
generator, which rewrites its outputs; with `--check` it writes nothing and
fails if a committed file is stale (CI runs it). Generated Noir is formatted
with `nargo fmt` (`$NARGO`, else `nargo` on `PATH`) through
`scripts/noir_format.py`.

| Generator | Writes | From |
| --- | --- | --- |
| `generate_test_keys.py` | `tests/fixed_multiplier_vector/src/key1.nr` | `fixtures/multiplier/verification_key.json` |
| `generate_test_vectors.py` | `tests/{fixed,runtime}_multiplier_vector/src/vector.nr`, `tests/sp1_v6_vector/src/{multiply,clock}.nr`, `noir/sp1/src/generated/v6_test_vector.nr` | `fixtures/multiplier`, `fixtures/sp1-v6`, through the hint SDK (needs Node and `npm ci` in `packages/groth16-verifier-hints`) |
| `generate_sp1_key.py` | `noir/sp1/src/generated/key.nr`, `noir/sp1/src/generated/v6_key.nr`, `tests/sp1_api_typecheck/src/test_keys/*.nr` | `fixtures/sp1-v5/groth16_vk.bin`, `fixtures/sp1-v6/{groth16_vk,verifier_vks}.bin`, `fixtures/multiplier` |

The generators reuse the key preprocessing in
`packages/groth16-verifier-hints/python/groth16`, so a change there shows up as
stale generated files.

### The Circom fixture

`fixtures/multiplier` is a Circom circuit (`product = a * b`), a development
trusted setup and one proof with public input 33. Neither Circom nor snarkjs is
needed to use or test this repository. To make a new fixture, install them
separately (both are GPL-3.0, so they are not dependencies of this repository),
for example in a scratch directory:

```bash
npm install circom2@0.2.23 snarkjs@0.7.6
npx circom2 multiplier.circom --r1cs --wasm
npx snarkjs powersoftau new bn128 8 pot0.ptau
npx snarkjs powersoftau contribute pot0.ptau pot1.ptau -e="entropy"
npx snarkjs powersoftau prepare phase2 pot1.ptau pot.ptau
npx snarkjs groth16 setup multiplier.r1cs pot.ptau key0.zkey
npx snarkjs zkey contribute key0.zkey key.zkey -e="entropy"
npx snarkjs zkey export verificationkey key.zkey verification_key.json
npx snarkjs groth16 fullprove input.json multiplier_js/multiplier.wasm key.zkey proof.json public.json
```

Copy `verification_key.json`, `proof.json` and `public.json` into
`fixtures/multiplier`, update the hashes in its `manifest.json`, and rerun the
generators. The key generator rejects a key without a phase-2 contribution.

### The SP1 fixtures

`fixtures/sp1-v5` and `fixtures/sp1-v6` hold the official SP1 Groth16 keys and,
for v6, the recursion verification-key data the pinned root derives from, saved
real proofs, and the SP1 v6.0.0 key that only the cross-version test uses; `fixtures/sp1-v6/manifest.json` records the source, commit,
path, licence and SHA-256 of each file, and `scripts/tests/test_sp1_key.py`
checks the hashes. No SP1 tooling is needed to use or test this repository. For
a new SP1 release, compare `crates/verifier/vk-artifacts/groth16_vk.bin` and
`verifier_vks.bin` at its tag with the saved files: if either changed, the
release needs a new pinned key, not an edit of these.

## Releases

Pull request titles follow [Conventional
Commits](https://www.conventionalcommits.org/en/v1.0.0/), which drive the
changelog and version numbers:

```
<type>[optional scope]: <description>
```

- `feat:` new functionality (appears in the changelog);
- `fix:` bug fixes (appears in the changelog);
- `chore:` everything else (omitted from the changelog unless breaking).

Mark a breaking change with `!` after the type or scope, e.g.
`feat(runtime_verifier)!: Return the input commitment`. Use the package name as
the scope when a change touches one package.

[Release Please](https://github.com/googleapis/release-please) runs on every
push to `main`. It opens or updates a release pull request with the next version
and the changelog; merging that pull request tags the release. All packages
share one version and one tag. The first release is v0.1.0. The npm packages
under `packages/` carry that version: Release Please writes it into their
`package.json` and `package-lock.json` files (`extra-files` in
`release-please-config.json`).

The release workflow uses the default `GITHUB_TOKEN`, and pull requests opened
with it do not trigger CI; to run the checks on release pull requests, replace
it in `release.yml` with a personal access token stored as a repository secret.

### Publishing checklist

Before the first release:

- create an empty `gh-pages` branch, where the benchmark workflow records
  history;
- enable private vulnerability reporting in the repository's security settings,
  for the README's reporting link.

## Differences from the noir-library-starter template

- **Workspace with packages under `noir/`.** The repository publishes several
  libraries (the two verifiers, `sp1` and the BN254 arithmetic), so consumers
  add a `directory` to the git dependency. Support packages that consumers
  never import live in `noir/internal/`; nargo resolves them through the
  published packages' relative path dependencies.
- **Test-only crates in `tests/`.** The proof-vector packages, the API
  typecheck crates and the oracle tests are workspace members that use the
  published packages only through their public API; keeping them out of `noir/`
  leaves that directory to the packages consumers depend on and their support
  packages.
- **Two Noir versions per pull request.** The template tests every Noir release
  from the minimum supported version, and nightly, on each pull request. This
  repository tests the two ends, 1.0.0-rc.3 (the minimum, which Aztec 6.0.0
  ships) and 1.0.0 (the latest release), per pull request, and Noir nightly in
  the nightly workflow.
- **Vendored BigNum and BigCurve.** `noir/internal/bignum` and the two
  `noir/internal/bigcurve_*` packages are modified copies of noir-bignum and
  noir_bigcurve (see NOTICE), because the verifiers depend on changes that the
  upstream releases do not have. Their test suites run constrained only, as
  upstream runs them, in the nightly workflow (`bignum`'s also on pull
  requests). There are two BigCurve copies because each carries the MSM of one
  verifier (the selected-offset fixed-base MSM for `groth16` and `bn254_g1`, the
  signed MSM for the runtime-key verifier); kept apart, a change made for one
  verifier cannot change the other's circuit.
- **Tests run per package, with a thread cap.** One CI job per package and
  toolchain, with `--test-threads 4`, unconstrained except `bignum`. The
  constrained runs are in the nightly workflow, whose matrix sets the thread
  count and timeout per package (figures above).
- **Extra CI jobs.** `check` type-checks the whole workspace (including the API
  typecheck crates, which have no tests) and runs `check-public-api.sh` on
  every toolchain; `host` runs the hint SDKs' and generators' tests and the
  host-side arguments in `scripts/tests` (the schedule denominators, the G2
  subgroup vectors, the three-limb equality model, the SP1 key consistency and
  a malicious-hint probe of BigCurve equality) and the oracle tests; the opt-in
  `heavy` job runs the malicious-hint probe of the verifiers' rejections, which
  needs about 8 GB.
- **Oracle tests in their own package, on npm and plain JavaScript.** The
  template keeps its oracle tests in the library's `src` and runs every test
  through `scripts/run.sh` and a TypeScript server built with yarn. Here they
  are in `tests/bn254_oracle_tests`, which only its own `run.sh` selects, so
  that no other test run needs the server; the server is one `.mjs` file on
  Node's `http` module, with `@noble/curves` as its only dependency, installed
  with npm like the other Node packages and with no build step. The other
  reference values are fixed vectors from a saved proof and saved keys,
  generated into Noir tests.
- **Generated keys and test vectors.** The format job also runs every
  generator with `--check`. The proof-vector generator needs Node, because hint
  preparation lives in the TypeScript SDK.
- **Host packages.** `packages/` holds the TypeScript hint SDKs and the Python
  key generator. Without them a verifier cannot be used: the hints are computed
  off-circuit.
- **Committed `dist/` in the TypeScript packages.** The SDKs are not published
  to npm: consumers pack and install them from a checkout at a release tag
  (credential-proofs does), so the built JavaScript and declarations must be in
  git. The host job's `check:dist` checks the hint SDK's `dist/` against its
  sources.
- **Committed SP1 API test keys.** `tests/sp1_api_typecheck/src/test_keys`
  (about 2.3 MB of generated providers, one per MSM preprocessing case) is
  committed so that `nargo check --workspace` needs no generator run; the
  format job's `scripts/generate.py --check` keeps it in step with the
  generator.
- **`toolchain-v6.json`.** The hint SDK's Aztec profiles pin the Aztec v6
  toolchain (Noir and aztec-packages commits and the stock bb 6.0.0 backend)
  from this file. Nothing in the Noir libraries, their tests or CI checks a
  tool hash.
- **No Brillig benchmark report.** `nargo export --force-brillig` of the
  verifiers takes well over an hour (see [Benchmarks](#benchmarks)), so the
  benchmark workflow reports circuit sizes only.
- **bb is installed by version.** `bbup -nv` cannot resolve Noir 1.0.0 (no entry
  in bbup's version map), so the benchmark workflow names bb 6.0.0 directly and
  measures with Noir 1.0.0 rather than the minimum version.
- **Release Please starts at 0.1.0** (`initial-version`), not at the template's
  0.0.0.
- **Workflows trigger on `main`**, not `master`, and third-party actions are
  pinned by commit.

# Native Language Bindings (Python, Node.js)

`soroban-upgrade-safeguard` is a Rust library and CLI. Teams automating it
from Python or Node.js previously had to shell out to the CLI binary and
parse its human or JSON output. `bindings/python` (PyO3) and
`bindings/node` (napi-rs) wrap the comparison engine as native extensions
instead: no subprocess, no network, one implementation of the
compatibility rules shared by the CLI and both bindings.

This document covers what exists today, how to build and use it, and what
is explicitly deferred.

---

## Scope of this first pass

| Capability | Status |
| --- | --- |
| Byte comparison (`compare_bytes`/`compareBytes`) | ✅ |
| File comparison (`compare_files`/`compareFiles`) | ✅ |
| Storage schema input (policy: which keys are declared) | ✅ |
| Suppression config input (policy: `.safeguard.toml`-shaped TOML text) | ✅ |
| `explain`/`strict`/`contract` options | ✅ |
| Structured, non-string-parsed error model | ✅ |
| Structured report conversion (no JSON-string round trip) | ✅ |
| RPC-backed comparison (`--contract-id`/`--rpc-url`) | ❌ not exposed — bindings are no-network by design |
| Lineage store validation | ❌ not yet exposed |
| Complexity budgets | ❌ not yet exposed |
| Prebuilt wheels / npm prebuilds for common platforms | ❌ source-build only; see [Unsupported platforms](#unsupported-platforms-and-what-prebuilts-would-take) |
| Published packages (PyPI / npm) | ❌ not published; build from source |
| Cross-language CI (building + running both bindings on every push) | ❌ not wired into CI yet |
| Cancellation of an in-flight comparison | ❌ not supported — see [Cancellation and memory](#cancellation-and-memory) |

Everything marked ❌ is a deliberate scope cut for this pass, not an
oversight — each is a substantial separate effort (platform build
matrices, publishing credentials and workflows, an async/cancellable
comparison API). Treat this as the foundation those build on, not the
finished state.

---

## Architecture

```text
                     ┌─────────────────────────────┐
                     │ src/binding_api.rs            │
                     │ (in the main crate)            │
                     │                                 │
 bytes/files/schema/ │  CompareRequest  ──────────►   │
 policy in            │  compare_bytes(..)  -> Result  │
                     │  compare_files(..)  <SafetyReport,│
                     │                       Error>     │
                     └───────────────┬─────────────────┘
                                     │ same Rust types, no
                                     │ serialization in between
              ┌──────────────────────┴──────────────────────┐
              │                                              │
   ┌──────────▼──────────┐                      ┌────────────▼───────────┐
   │ bindings/python       │                      │ bindings/node           │
   │ (PyO3 + pythonize)     │                      │ (napi-rs)                │
   │                        │                      │                          │
   │ dict/list built        │                      │ JS object/array built    │
   │ directly from the       │                      │ directly from the        │
   │ report's serde model     │                      │ report's serde model      │
   │ via `pythonize`           │                      │ via napi's `serde-json`   │
   │                            │                      │ feature                   │
   │ failures raise             │                      │ failures become a         │
   │ SafeguardError(kind,         │                      │ tagged {ok,report,error}  │
   │ details)                      │                      │ object; index.js re-throws│
   │                                 │                      │ SafeguardError(kind,details)│
   └────────────────────────┘                      └──────────────────────────┘
```

`src/binding_api.rs` is the single place that turns raw bytes/paths plus a
plain-data `CompareRequest` into a `SafetyReport`, returning
`Result<SafetyReport, crate::error::Error>` — never `anyhow::Result`. The
crate root's own public functions (`compare_wasm_bytes`,
`compare_wasm_files_with_options`, ...) are the right shape for the CLI,
but a couple of their internal call sites collapse a typed `Error` into an
`anyhow::anyhow!("{}", e)` message, which cannot be recovered structurally
downstream. `binding_api` avoids that: both bindings get a fully typed
error all the way to the language boundary.

### Why not just serialize to a JSON string?

The acceptance bar for this feature is converting findings, provenance,
scope, and errors "without lossy string parsing." Serializing
`SafetyReport` to a JSON string and having Python/Node `JSON.parse()` it
back would technically work and wouldn't lose any *data* — but it adds an
unnecessary text round-trip, and it means every number/bool/null is
re-inferred by a generic JSON parser instead of being produced directly
from the Rust value. Both bindings instead walk the report's `serde::Serialize`
implementation straight into native values:

- Python: [`pythonize`](https://docs.rs/pythonize), which implements a
  `serde::Serializer` that builds `PyObject`s (dict/list/str/int/float/
  bool/None) directly.
- Node: `napi`'s `serde-json` cargo feature, which converts a
  `serde_json::Value` into napi/JS values directly (object/array/string/
  number/bool/null), still without ever materializing a JSON string.

### Errors

Both bindings expose a `SafeguardError`-shaped type with two fields:

- `kind` — the stable string form of `soroban_upgrade_safeguard::error::ErrorKind`
  (e.g. `"WasmValidation"`, `"InvalidInput"`, `"SectionExtraction"`).
  Stable across releases; match on this, not on `details`.
- `details` — a free-text, human-oriented explanation. Wording may change
  between releases; never parse it.

Python raises `SafeguardError` as a normal exception (a `#[pyclass(extends
= PyException)]` with `.kind`/`.details` getters — real attributes, not a
formatted message you'd have to regex). Node's native layer never throws:
`compareBytes`/`compareFiles` return a tagged `{ ok, report, error }`
object from Rust (no custom-exception-property plumbing needed across the
FFI boundary), and the hand-written `index.js` wrapper throws a JS
`SafeguardError` instance when `ok` is `false`, so the common path still
reads like ordinary try/catch. Call the raw native export directly if you
want the tagged object instead of an exception.

---

## Installation

Neither package is published yet. Both build from source against the
Rust workspace at the repository root (`[workspace] members = ["bindings/python", "bindings/node"]`
in the root `Cargo.toml` — the root CLI/library crate is still the
default build target, so plain `cargo build`/`cargo test` there are
unaffected by this).

### Python

```bash
pip install maturin
cd bindings/python
maturin develop             # build + install into the active virtualenv
# or build a wheel to distribute:
maturin build --release
pip install target/wheels/soroban_upgrade_safeguard-*.whl
```

See `bindings/python/README.md` for usage.

### Node.js

```bash
cd bindings/node
npm install                 # pulls in @napi-rs/cli as a dev dependency
npm run build:debug         # or: npm run build (release)
```

This produces `soroban_upgrade_safeguard.node` in `bindings/node/`, loaded
by the hand-written `index.js` there. See `bindings/node/README.md` for
usage.

---

## Version compatibility

Three version numbers are in play for each binding: the Rust engine crate
(`soroban-upgrade-safeguard`'s own `Cargo.toml` version, exposed at
runtime as `engine_version()`/`engineVersion()` and the constant
`soroban_upgrade_safeguard::ENGINE_VERSION`), the binding crate
(`soroban-upgrade-safeguard-python`/`-node`), and the published
language package (PyPI/npm, not yet published).

Policy for this pass, to be formalized once publishing exists:

- The binding crates are **not** independently versioned from the engine
  in any meaningful way yet — both pin the engine via a workspace `path`
  dependency, so a given binding build always matches the engine commit
  it was built from exactly. There is no cross-version compatibility
  matrix to maintain yet because nothing is published for a caller to mix
  versions of.
- Once published, the plan is to track the engine's version for the
  language package's own major/minor (e.g. engine `0.3.x` → Python package
  `0.3.x`), with the language package's patch version free for
  binding-only fixes. This is **not implemented or enforced yet** — there
  is no CI check pinning them together, and no deprecation policy
  written down. Treat any version numbers in `bindings/*/Cargo.toml` and
  `bindings/*/package.json`/`pyproject.toml` as provisional until that
  policy exists.
- `engine_version()` (Python) / `engineVersion()` (Node) always reports
  the actual engine build linked into the extension, so callers can check
  this themselves regardless of the policy above.

---

## Unsupported platforms, and what prebuilts would take

Today, both bindings are **source-only**: there is no prebuilt binary for
any platform, and no CI step builds one. A caller needs:

- A Rust stable toolchain (matching whatever MSRV the engine crate ends
  up declaring).
- Python: `maturin` and a Python ≥ 3.8 interpreter with development
  headers.
- Node: `@napi-rs/cli` (pulled in as a dev dependency) and a Node ≥ 16
  installation.

Shipping prebuilt wheels/npm packages for the common targets (`linux-x64`,
`linux-arm64`, `macos-x64`, `macos-arm64`, `win32-x64`, each for Python
and Node, times whichever Python ABI tags/Node N-API versions are
targeted) is a real project on its own: a CI matrix building on each
target OS/arch (cross-compilation for Rust FFI extensions is unreliable
enough that most projects in this space build natively per-runner), a
packaging/publishing pipeline (PyPI trusted publishing or API tokens; npm
`optionalDependencies` per-platform packages, as `@napi-rs/cli`'s own
`--platform` flag scaffolds), and a decision on which platforms are
actually supported (musl vs. glibc Linux, which Node N-API version floor,
which Python ABI floor). None of that exists yet — the `targets` field
that `@napi-rs/cli` would use for this is deliberately left out of
`bindings/node/package.json` for now, since listing it without the CI to
back it would be misleading.

---

## Cancellation and memory

- **Cancellation**: there is no way to cancel an in-flight
  `compare_bytes`/`compare_files` call. Both bindings call directly into
  synchronous Rust code on the calling thread (Python: the GIL is held for
  the duration; Node: this blocks the JS event loop for the call's
  duration, same as any synchronous native addon call). A real
  cancellation story would need an async/background-thread API on both
  sides (Python: release the GIL and support `KeyboardInterrupt` polling;
  Node: run on napi-rs's `AsyncTask`/a worker thread and return a
  `Promise`), which is a meaningfully different API shape left for a
  later pass.
- **Bounded memory**: inputs are taken as borrowed/owned byte buffers
  (PyO3's `&[u8]` from a Python `bytes`/`bytearray`, napi-rs's `Buffer`
  from a Node `Buffer`) without an extra full copy on the way in. Beyond
  that, no additional memory bounding is implemented in the bindings
  themselves — whatever limits the engine itself enforces (see
  `src/limits.rs`) apply equally here, and nothing in the bindings relaxes
  or tightens them.

---

## Cross-language fixtures

`src/binding_api.rs` has a Rust-only unit test
(`compare_bytes_matches_the_crate_root_convenience_function`) asserting
`binding_api::compare_bytes` produces byte-for-byte the same JSON as the
crate root's own `compare_wasm_bytes_with_options` for the same inputs —
this is the guarantee that the bindings aren't a second, divergent
implementation.

`bindings/python/tests/test_parity.py` and
`bindings/node/__test__/parity.test.js` go one step further: they run the
*actual CLI binary* and the actual compiled binding against the same
fixture WASM files and assert the key report fields match. **Neither has
been executed** as part of this change — they require the native
extension to be built first (`maturin develop` / `npm run build:debug`),
and this environment has no `pip`/`maturin`/`@napi-rs/cli` installed. Both
tests skip themselves cleanly (rather than failing) when their
prerequisites aren't built, and both describe in a comment exactly how to
run them for real. Treat them as written-but-unverified until someone
runs them in an environment with the full toolchain.

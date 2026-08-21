# Soroban Upgrade Safeguard Documentation

This document explains what Soroban Upgrade Safeguard does, how it works internally, and how to read its output. It is meant for contract authors who want to understand exactly why a given upgrade is flagged as safe or unsafe.

## Table of Contents

1. [Overview](#overview)
2. [Why Upgrade Safety Matters](#why-upgrade-safety-matters)
3. [What a Passing Verdict Guarantees](#what-a-passing-verdict-guarantees)
4. [Installation](#installation)
5. [Docker](#docker)
6. [Command Line Usage](#command-line-usage)
7. [How the Analysis Works](#how-the-analysis-works)
8. [Storage Schema Analysis](#storage-schema-analysis)
9. [Detection Categories](#detection-categories)
10. [Severity Levels](#severity-levels)
11. [Cascading Layout Breaks](#cascading-layout-breaks)
12. [Spec Entry Integrity and Duplicate Detection](#spec-entry-integrity-and-duplicate-detection)
13. [Reading the Report](#reading-the-report)
14. [Suppressing Known Breaking Changes](#suppressing-known-breaking-changes)
15. [Resource Limits and Hardening Against Malicious Input](#resource-limits-and-hardening-against-malicious-input)
16. [Exit Codes and CI Integration](#exit-codes-and-ci-integration)
17. [Limitations](#limitations)
18. [Migration Note](#migration-note)
19. [Frequently Asked Questions](#frequently-asked-questions)

## Overview

Soroban Upgrade Safeguard is a command line tool that compares two compiled Soroban contract builds (WASM files) and reports whether upgrading from the old build to the new build would introduce breaking changes. It focuses on three areas that commonly cause silent failures after a deployment:

- Storage layout of structs, enums, and unions
- Public function signatures
- Event schemas used by off-chain indexers

The tool reads the contract interface that the Soroban SDK embeds inside the compiled WASM, decodes it, and performs a deep structural comparison. It does not need source code, a running network, or any external service.

## Why Upgrade Safety Matters

On Stellar, a Soroban contract can be upgraded in place by swapping the WASM behind the same contract address. The contract keeps its existing on-chain storage entries across the upgrade. This is powerful, but it carries a risk: the new code must still be able to read data that the old code wrote.

Soroban serializes most user-defined types by field position rather than by field name. If the new version of a struct removes a field, reorders fields, or changes a field type, the bytes already stored on chain no longer match what the new code expects. The result is orphaned data, deserialization panics, or integrations that quietly read the wrong values.

These problems usually do not appear at compile time. They appear in production, after the upgrade is live and real data is involved. The goal of this tool is to surface those problems before you deploy.

## What a Passing Verdict Guarantees

This section is the most important one in this document. Read it before you treat a green run as permission to deploy.

By default, the tool reads only the `contractspecv0` custom section, which describes a contract's **callable surface**: its exported functions and the user-defined types those functions mention. Everything the tool says by default is a statement about that surface and nothing else.

**A passing run certifies:**

- No exported function was removed, and none changed its parameters or return types.
- No exported user-defined type changed in a way that breaks its layout.
- The environment metadata (`contractenvmetav0`) was compared.

**A passing run does NOT certify:**

- That the upgrade is **storage compatible**.
- That internal types serialized into persistent, instance, or temporary storage kept their layout.
- That storage-key types kept their discriminants, so existing entries still resolve.
- That function bodies behave the same way.

The reason for that gap is structural. Soroban storage compatibility is decided by the bytes a contract writes: the layout of the values it serializes into storage, and the discriminants of the types it builds storage keys from. Neither has to appear in `contractspecv0`. A type used only as a storage payload is invisible to the exported spec, so a contract can keep its public interface byte-identical while reordering the fields of an internal struct or shifting a storage-key discriminant. That is guaranteed data corruption on upgrade, and by default the tool cannot see it.

This is why the verdict vocabulary is deliberately bounded. A pass reads:

```
Status: ✅ PASSED (No exported-interface breaking changes)
Scope:  Exported interface + environment metadata only — storage layout is NOT verified by this result.
        Storage layout: NOT analyzed — no storage schema supplied.
```

"No exported-interface breaks" and "storage compatible" are different claims, and the tool only makes the first one unless you give it more to work with. To close the gap, supply a [storage schema](#storage-schema-analysis).

## Installation

Install the published crate from crates.io:

```bash
cargo install soroban-upgrade-safeguard
```

Alternatively, you can build and install the binary from a local checkout of the repository root:

```bash
cargo install --path .
```

This places a `soroban-upgrade-safeguard` binary on your Cargo bin path. You can also run it directly during development without installing:

```bash
cargo run -- <OLD_WASM> <NEW_WASM>
```

## Docker

Pre-built images are published automatically to the GitHub Container Registry (`ghcr.io`) from CI. You can pull a published image directly:

```bash
docker pull ghcr.io/shippedlabs/soroban-upgrade-safeguard:latest
```

Alternatively, you can build the image manually from the repository root:

```bash
docker build -t soroban-upgrade-safeguard .
```

The build uses two stages: the first compiles a release binary using `rust:slim-bookworm`; the second copies only that binary into `debian:bookworm-slim`. The final image does not contain `cargo`, `rustc`, or `rustup`.

### Local mode

Mount a directory that contains your WASM files and pass the in-container paths as arguments:

```bash
docker run --rm \
  -v $(pwd)/tests/wasm:/wasms \
  soroban-upgrade-safeguard \
  /wasms/v1.wasm /wasms/v2.wasm
```

All paths you pass must be paths inside the container. Use `--format` to choose a different output format:

```bash
docker run --rm \
  -v $(pwd)/tests/wasm:/wasms \
  soroban-upgrade-safeguard \
  /wasms/v1.wasm /wasms/v2.wasm --format json
```

### RPC mode

```bash
docker run --rm \
  -v $(pwd)/path/to/new:/wasms \
  soroban-upgrade-safeguard \
  --contract-id C... \
  --rpc-url https://soroban-testnet.stellar.org \
  /wasms/new.wasm
```

For local development against a local RPC node:

```bash
soroban-upgrade-safeguard \
  --contract-id C... \
  --rpc-url http://localhost:8000 \
  --allow-http-local \
  new.wasm
```

To pin the expected on-chain WASM hash (CI/CD safety):

```bash
soroban-upgrade-safeguard \
  --contract-id C... \
  --rpc-url https://soroban-testnet.stellar.org \
  --expected-wasm-hash a1b2c3d4e5f6... \
  new.wasm
```

#### Authenticated RPC endpoints

Keep credentials outside command lines, configuration files, reports, and CI
logs. Configure each header as `HEADER_NAME=ENVIRONMENT_VARIABLE`; the tool
reads the secret only when it sends an RPC request:

```bash
export SOROBAN_RPC_TOKEN="..."
soroban-upgrade-safeguard \
  --contract-id C... \
  --rpc-url https://provider.example/rpc \
  --rpc-header Authorization=SOROBAN_RPC_TOKEN \
  new.wasm
```

Multiple provider headers are supported by repeating `--rpc-header`. Header
names are validated, missing or empty environment variables are rejected, and
secret values are never serialized into reports or debug output. RPC redirects
are refused for authenticated requests so provider credentials cannot reach a
different origin. In CI, store the secret in the runner's secret store and
export it for the step rather than putting it in a workflow argument or file.

### Suppression config

Mount the directory that contains `.safeguard.toml` and point to it with `--config`:

```bash
docker run --rm \
  -v $(pwd)/tests/wasm:/wasms \
  -v $(pwd):/config \
  soroban-upgrade-safeguard \
  /wasms/v1.wasm /wasms/v2.wasm --config /config/.safeguard.toml
```

### CI example

The image preserves exit code semantics (0 = safe, 1 = critical findings). Use it directly as a pipeline step:

```yaml
- name: Check upgrade safety
  run: |
    docker run --rm \
      -v ${{ github.workspace }}/wasm:/wasms \
      soroban-upgrade-safeguard /wasms/on-chain.wasm /wasms/candidate.wasm
```

## Command Line Usage

The tool supports several invocation modes. It no longer assumes exactly two positional
arguments; instead use the mode appropriate to your environment:

- Local file comparison (two positional WASM paths):

```bash
soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>
```

- RPC baseline mode (fetch the on-chain baseline; single positional new WASM):

```bash
soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>
```

- Manifest (batch) mode: compare many pairs listed in a manifest file:

```bash
soroban-upgrade-safeguard --manifest <MANIFEST_PATH>
```

- Directory scan (pair by file stem):

```bash
soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR>
```

- Glob pair mode (pair matches by file stem):

```bash
soroban-upgrade-safeguard --old-glob '<OLD_PATTERN>' --new-glob '<NEW_PATTERN>'
```

The first form (two positional paths) remains the simplest for ad-hoc, local checks.
RPC mode fetches the baseline from chain and verifies it cryptographically; manifest,
directory, and glob modes run batch comparisons. The full usage strings and options
match the CLI help output (`--help`) and the `override_usage` in `src/main.rs`.

Common flags: `--format <text|json|markdown|html|github-actions|junit>`, `--explain`, `--strict`, `--expect-bump <patch|minor|major>`, `--config <PATH>`, the resource-limit overrides `--max-xdr-depth`, `--max-xdr-len`, `--max-entries`, and `--max-walk-depth` (see [Resource Limits](#resource-limits-and-hardening-against-malicious-input)), and the `https://` input overrides `--remote-max-bytes`, `--remote-timeout-secs`, `--remote-max-redirects`, `--remote-cache-dir`, `--no-remote-cache`, and `--clear-remote-cache` (see [Remote HTTPS inputs](#remote-https-inputs)).

### Spec JSON input mode

Instead of a WASM binary, either side of a comparison can be supplied as a **contract spec JSON file** using `--old-spec` or `--new-spec`:

```bash
# Check a candidate WASM against a published spec (old side is spec JSON)
soroban-upgrade-safeguard --old-spec published-spec.json candidate.wasm

# Spec vs spec (both sides are spec JSON files)
soroban-upgrade-safeguard --old-spec v1-spec.json --new-spec v2-spec.json

# Spec as the new side only
soroban-upgrade-safeguard deployed.wasm --new-spec candidate-spec.json
```

#### Spec JSON file format

The file must be a JSON object with a single `entries` array. Each element is a **base64-encoded `SCSpecEntry` XDR value** — the same encoding used in Stellar RPC responses:

```json
{
  "entries": [
    "AAAAAQAAAA...",
    "AAAAAQAAAB..."
  ]
}
```

To produce this file from a WASM binary with the Stellar CLI:

```bash
stellar contract inspect --wasm contract.wasm --output xdr-base64-array \
  | python3 -c "import sys, json; print(json.dumps({'entries': json.load(sys.stdin)}))" \
  > contract-spec.json
```

#### Skipped comparisons in spec-only mode

A spec JSON file contains only the `contractspecv0` interface entries. Comparisons that require data from the full WASM binary are skipped when one or both sides is a spec file, and the report records exactly what was skipped:

| Comparison | WASM vs WASM | Spec vs WASM / WASM vs Spec | Spec vs Spec |
| :--- | :---: | :---: | :---: |
| Exported interface (functions, types) | ✅ | ✅ | ✅ |
| Environment metadata (`contractenvmetav0`) | ✅ | ⚠️ skipped | ⚠️ skipped |
| Build metadata (`contractmetav0`) | ✅ | ⚠️ skipped | ⚠️ skipped |
| Export section (binary vs spec agreement) | ✅ | ⚠️ skipped | ⚠️ skipped |
| Import section (host-function diff) | ✅ | ⚠️ skipped | ⚠️ skipped |

Skipped comparisons are reported as "not available" in the analysis scope rather than silently ignored, so the verdict is never read as broader than what actually ran. The exported interface comparison — the primary safety gate — always runs regardless of input mode.

`--old-spec` cannot be combined with `--contract-id` (RPC already fetches the full WASM).

### Building from source with `--old-crate` / `--new-crate`

Instead of pointing at a pre-built WASM artifact, either side of a comparison can be a **local Cargo crate directory**. The tool builds it automatically and feeds the result into the analysis pipeline:

```bash
# Build the new side from source; compare against a deployed on-chain contract
soroban-upgrade-safeguard \
  --contract-id CDEPLOYED... \
  --rpc-url https://soroban-mainnet.stellar.org \
  --new-crate ./contracts/my_contract

# Build both sides from source (useful when iterating across two branches)
soroban-upgrade-safeguard \
  --old-crate ./contracts/v1 \
  --new-crate ./contracts/v2

# Build the new side from source; old side is a saved WASM artifact
soroban-upgrade-safeguard deployed.wasm --new-crate ./contracts/my_contract
```

Pass a path to a directory containing `Cargo.toml`. The tool runs:

```text
cargo build --target wasm32-unknown-unknown --release --locked
```

inside that directory, locates the produced `.wasm` artifact via `cargo metadata`, and loads it through the normal validation path. Nothing downstream is aware that the bytes came from a build rather than a file.

#### Toolchain requirements

| Requirement | How to satisfy |
| :--- | :--- |
| **Cargo** on `$PATH` | Install Rust via [rustup.rs](https://rustup.rs) |
| **`wasm32-unknown-unknown` target** installed | `rustup target add wasm32-unknown-unknown` |
| **`crate-type = ["cdylib"]`** in `[lib]` | Required for Cargo to produce a `.wasm` artifact |

Both requirements are checked before the build starts. A missing target produces a clear error with the exact `rustup` command to run rather than a cryptic rustc error.

#### CI notes

- Cargo's dependency downloads run on first use. Subsequent runs are fast if the Cargo cache is warm.
- `--locked` is set automatically, so the build respects the crate's `Cargo.lock` and is reproducible.
- The build always targets `--release` so the Soroban SDK emits the `contractspecv0` custom section that this tool reads.
- `--old-crate` cannot be combined with `--contract-id` or `--old-spec`. `--new-crate` cannot be combined with `--new-spec`.

### Remote HTTPS inputs

Anywhere the CLI accepts a local WASM path — the positional comparison arguments, `extract`, and each entry in a `--manifest` batch file — it also accepts an `https://` URL, so a release pipeline that publishes immutable build artifacts to object storage does not need a separate download-and-verify step before running the tool. The same resolver backs `--old-storage-schema` / `--new-storage-schema` on `attest` and `verify-attestation`, since a storage-schema manifest is itself just a JSON/TOML spec file read from a path.

```bash
# Compare a local build against a published release artifact.
soroban-upgrade-safeguard old.wasm \
  "https://releases.example.com/v2/contract.wasm#sha256=3b1a2c9e4d5f60718293847566172839405162738495061728394051627384"

# Both sides published, in a batch manifest (pairs.old / pairs.new accept the
# same https://…#sha256=<hex> syntax as any other path field).
soroban-upgrade-safeguard --manifest pairs.toml
```

#### Reference syntax

A remote reference is an `https://` URL followed by a `#sha256=<hex>` fragment naming the digest the downloaded bytes must match:

```text
https://cdn.example.com/releases/v2/contract.wasm#sha256=<64 lowercase or uppercase hex characters>
```

The fragment is never sent to the server (URL fragments are client-side only), which is what makes it a safe place to pin an expected digest onto a bare URL without a second flag per input position. The digest is **mandatory** — a `https://` URL with no `#sha256=` fragment, or a fragment that isn't exactly 64 hex characters, is rejected before any network request is made.

#### Transport policy

Every remote fetch is HTTPS-only, on every hop:

- The initial request must be `https://`; the fetch is refused before connecting otherwise.
- A redirect that would downgrade to plain `http://` is rejected — capped, in either case, by `--remote-max-redirects` (default 5).
- No `Authorization` or `Cookie` header is ever forwarded to a redirected request, including a same-origin one.
- The response body is capped at `--remote-max-bytes` (default 64 MiB), enforced by bounding how many bytes are read from the stream rather than trusting a `Content-Length` header a server could omit or misstate.
- The whole request is bounded by `--remote-timeout-secs` (default 30).
- After download, the SHA-256 of the bytes is compared against the reference's expected digest; a mismatch is reported as an integrity failure and the bytes are discarded rather than analyzed.

#### Caching

Because every reference names its own digest, a verified download is cached content-addressed and can be served again without re-fetching, with no risk of staleness — the reference itself changes if the artifact does. The cache lives under `--remote-cache-dir` (default: a `soroban-upgrade-safeguard/remote-cache` directory under the OS temp dir, or the path in `SOROBAN_SAFEGUARD_REMOTE_CACHE` if set). `--no-remote-cache` bypasses both reading and writing the cache for a single run without deleting anything already cached; `--clear-remote-cache` deletes the whole cache directory and exits.

#### Provenance

A remote fetch prints a line naming the final (post-redirect) URL, the verified digest, the cache status (`hit`, `miss`, or `bypassed`), and the response's `Content-Type`, so a CI log always identifies exactly which bytes were analyzed — not just the URL that was requested.

## How the Analysis Works

The analysis runs as a short pipeline. Each stage lives in its own module under `src/`.

1. **Load and validate (`loader.rs`).** Each file is read from disk and checked for the WASM magic header. The tool accepts both binary WASM (`.wasm`) and WebAssembly Text format (`.wat`). A `.wat` file is detected by its extension or by the absence of the `\0asm` magic bytes, assembled to binary using the `wat` crate, and then validated identically to a binary input — nothing downstream is aware of the distinction. A malformed `.wat` produces a clear assembly error naming the file and the parse problem. The tool then walks every WASM payload to confirm the binary is structurally well formed before any deeper work happens. A corrupt or non-WASM file fails fast with a clear message.

   When the baseline is fetched from an RPC endpoint (`--contract-id` / `--rpc-url`), the loader applies a **zero-trust pipeline**: the URL is validated for transport security (HTTPS required unless `--allow-http-local` is set), the RPC response entries are checked for matching ledger keys, and the SHA-256 hash of the fetched bytecode is verified against the on-chain contract instance hash. An optional `--expected-wasm-hash` flag provides additional hash pinning.

2. **Extract metadata (`parser.rs`).** The Soroban SDK stores the contract interface in custom WASM sections. The parser scans for the `contractspecv0` section and decodes the concatenated XDR `ScSpecEntry` objects it contains. The `contractenvmetav0` section is decoded too, and environment metadata differences are compared as part of the analysis. Protocol interface version changes are reported as `Warning`; other environment metadata changes are reported as `Info`. The parser also walks the WASM type and import sections to record every function import as an `ImportedFunction` — a `(module, name)` pair plus its resolved parameter/result types, when resolvable. See [Host Imports and Protocol Capabilities](#host-imports-and-protocol-capabilities).

3. **Build the spec model (`spec.rs`).** Decoded entries are sorted into a `ContractSpec`, which groups functions, structs, enums, unions, and error enums into separate maps keyed by name. This gives the comparison stage fast lookups by type name.

4. **Compare (`diff.rs`).** The old and new specs are compared item by item. Functions, structs, and enums are matched by name and then examined for the specific breaking changes described below. Every difference becomes a `Finding` with a severity and a category. `compare_host_imports` separately classifies host-import changes against the [capability registry](capability-registry.md).

5. **Map dependencies (`mapper.rs`).** A `LayoutMapper` builds a reverse dependency graph over user-defined types. This is what lets the tool understand that a change to a small shared type can break every larger type that embeds it.

6. **Report (`report.rs`).** All findings are aggregated into a `SafetyReport`, grouped by category, counted by severity, and rendered as a colored summary. The overall run is considered safe only when there are zero critical findings.

Every report also carries an **analysis scope**, which records which of these dimensions actually ran. It is printed under the status line and exposed as a `scope` object in JSON, so neither a human nor a CI job has to guess how much a verdict covers.

## Storage Schema Analysis

A storage schema is an opt-in manifest in which you declare the types that actually govern your storage layout. It is the bridge between what the exported spec exposes and what determines on-chain compatibility.

### Why it is needed

Consider a lending contract that stores positions under a key enum `DataKey::Position(Address)` and serializes an internal struct `PositionState { collateral: i128, debt: i128 }`. Neither type is exported. An upgrade that swaps those two fields, or renames the key variant, leaves the public interface byte-identical. Without a schema the tool reports PASSED, and on deploy every stored position decodes with collateral and debt reversed while existing keys stop resolving.

Declaring those two types lets the tool diff them with the same engine and the same severities it already applies to exported types.

### Supplying a schema

A manifest describes the storage layout of **one build**. Detecting a reorder requires two snapshots, so you supply one manifest per side:

```bash
soroban-upgrade-safeguard ./on-chain.wasm ./candidate.wasm \
  --old-storage-schema ./schemas/v1.storage-schema.toml \
  --new-storage-schema ./schemas/v2.storage-schema.toml
```

Both flags are required together. Supplying only one is an error, because a single snapshot cannot show a change. Keep the manifest versioned next to your contract and update it in the same commit that changes a storage type.

### Manifest format

TOML and JSON are both accepted with the same shape. A ready-to-copy template lives at [`.storage-schema.example.toml`](../.storage-schema.example.toml).

```toml
# Storage-key types: what addresses your entries.
[[storage_key]]
name = "DataKey"
kind = "union"             # "union" for data-carrying, "enum" for unit variants
durability = "persistent"  # persistent | instance | temporary (optional)

  [[storage_key.variant]]
  name = "Admin"           # void variant, no payload

  [[storage_key.variant]]
  name = "Position"
  type = ["Address"]       # tuple payload types, in order

# Internal value types: what you serialize into those entries.
[[value_type]]
name = "PositionState"
kind = "struct"
durability = "persistent"

  [[value_type.field]]
  name = "collateral"
  type = "i128"

  [[value_type.field]]
  name = "debt"
  type = "i128"
```

A unit enum declares explicit discriminants instead of variants:

```toml
[[value_type]]
name = "Status"
kind = "enum"

  [[value_type.case]]
  name = "Active"
  value = 0

  [[value_type.case]]
  name = "Paused"
  value = 1
```

**Declaration order is layout order.** Soroban serializes struct fields and union variants positionally, so the order you write them in is the order stored on chain. Write them in the order your Rust type declares them. For a unit enum the `value` is the discriminant that is actually written, so order in the file does not matter but the numbers do.

### Type spelling

Type strings use the same Rust-like spelling the report prints, so a type named in a finding can be pasted straight back into a manifest.

| Spelling | Meaning |
| :--- | :--- |
| `bool`, `u32`, `i32`, `u64`, `i64`, `u128`, `i128`, `u256`, `i256` | scalars |
| `Bytes`, `String`, `Symbol`, `Address`, `Timepoint`, `Duration` | built-ins |
| `Val`, `Error`, `()` | raw value, error, void |
| `Option<T>`, `Vec<T>`, `Map<K, V>`, `Result<T, E>` | containers |
| `BytesN<32>` | fixed-length bytes |
| `(Address, u32)` | tuple |
| `PositionState` | a user-defined type, exported or declared in the manifest |

### Validation and reconciliation

A manifest is a safety input, so it is validated strictly rather than interpreted loosely. Unknown keys, a `kind` that does not match the member table supplied, duplicate fields, two enum cases sharing a discriminant, and unparseable type strings are all hard errors. A typo fails loudly instead of silently narrowing coverage.

Each manifest is also reconciled against its own build's exported spec. A declared type that the spec has never heard of is fine, since that is precisely the internal-type case the manifest exists for. But when a declared name **is** exported, the two must agree on field order, field types, variant order, payloads, and discriminants. Disagreement stops the run:

```
Error: Storage schema for the old build disagrees with that build's exported contract spec

Caused by:
    struct 'ConfigData': field at position 0 is declared as 'threshold' but the old build
    exports 'admin' there. Field order is layout, so this disagreement cannot be reconciled
    automatically.
```

This is deliberate. A manifest that contradicts the contract is more dangerous than no manifest, because it would certify a layout the contract does not use.

### How storage findings are reported

Storage findings reuse the exported-interface categories behind a `Storage ` prefix, and each message is qualified with the declared role and durability:

```
--- [STORAGE STRUCT FIELD REORDERED] ---
🔴 [declared storage value (persistent)] Struct 'PositionState': field at position 0 changed
   from 'collateral' to 'debt'. Positional serialization breaks layout compatibility.
```

Severities match the exported rules with one deliberate exception. Appending a field is a **Warning** for a storage value, because existing entries still decode for the fields that were already there and only need a migration or default. The same append to a storage **key** is **Critical**, because a key's bytes are the address of every entry written under it, so changing its shape orphans all existing data.

When a schema is analyzed, the verdict widens but stays bounded:

```
Status: ✅ PASSED (No exported-interface or declared-storage breaks)
Scope:  Exported interface + environment metadata, plus a declared storage schema
        (1 key type(s), 1 value type(s)). Storage coverage is limited to the declared types.
```

Storage findings count toward `is_safe` and therefore toward the exit code, so a declared-layout break blocks a deployment exactly as an exported break does.

### Coverage limits

Coverage is bounded by what you declare. A storage type you forget to declare is not analyzed, and the report does not pretend otherwise. If a declaration references a type that is neither declared in the manifest nor exported by the contract, that dangling reference is reported as an informational finding rather than quietly skipped.

Storage schemas apply to a single contract pair and are refused in batch mode, since one manifest cannot describe several different contracts.

## Detection Categories

The comparison stage looks for the following classes of change.

### Functions

- **Function Removed.** A function that existed in the old build is gone in the new build. Existing callers and dependent contracts will break. Critical.
- **Function Signature Changed.** The number of parameters changed. Critical.
- **Parameter Type Changed.** A parameter kept its position but changed type. Critical.
- **Parameter Renamed.** A parameter changed name but kept its type. This is a warning, since positional encoding still matches but client code referring to the name may need updates.
- **Return Type Changed.** The count or type of return values changed. Critical.
- **Function Added.** A new function appears in the new build. Informational.

### Structs

- **Struct Removed.** A struct present in the old build is missing. Any storage entry of that type becomes unreadable. Critical.
- **Struct Field Removed.** A named field disappeared. Critical.
- **Struct Field Reordered.** The field at a given position now has a different name, which means the positional layout shifted. Critical.
- **Struct Field Type Changed.** A field kept its name and position but changed type. Critical.
- **Struct Field Added.** A new field was appended after the existing fields. This is a warning rather than a critical issue, because appended fields do not move existing fields, but old storage entries will lack the value, so a migration or default must be in place.
- **Struct Added.** A brand new struct. Informational.

### Enums

- **Enum Removed.** An enum is gone. Critical.
- **Enum Case Removed.** A variant disappeared, so stored values using it become invalid. Critical.
- **Enum Case Value Changed.** A variant kept its name but its integer value changed, which breaks serialization. Critical.
- **Enum Case Added.** A new variant. Informational.

### Unions

- **Union Removed.** A union present in the old build is missing. Any stored values using this union become invalid. Critical.
- **Union Case Removed.** A union case disappeared, breaking positional discriminants and layout compatibility. Critical.
- **Union Case Reordered.** A case moved position; unions serialize by positional discriminant, so reordering breaks layout. Critical.
- **Union Case Type Changed.** A case's payload type changed (non-numeric or multi-value change). Critical.
- **Union Case Type Widened.** A numeric widening of a case payload (e.g. `i32` → `i64`). Warning.
- **Union Case Type Narrowed.** A numeric narrowing of a case payload. Critical.
- **Union Case Type Signedness Changed.** A numeric signedness change in a case payload. Critical.
- **Union Case Added.** A new case appended to the union. Informational.
- **Union Added.** A new union type in the new build. Informational.
- **Union Documentation Changed.** Doc-string changes for a union. Informational.

### Error Enums

- **Error Enum Removed.** An error enum present in the old build is missing. Clients matching on these error codes will break. Critical.
- **Error Enum Case Removed.** A case was removed from an error enum. Critical.
- **Error Enum Case Value Changed.** A case's numeric value changed, breaking error-code compatibility. Critical.
- **Error Enum Case Added.** A new error enum case was added. Informational.
- **Error Enum Added.** A new error enum type in the new build. Informational.
- **Error Enum Documentation Changed.** Doc-string changes for an error enum. Informational.

### Type Renames

Types are compared by structure, not only by name, so renaming a type is recognized as a rename instead of being reported as an unrelated removal plus addition. See [Type Identity](#type-identity) for how the matching works and what it deliberately refuses to match.

- **Type Renamed.** The old type was matched to a new one with an identical layout. Stored data stays compatible; only client-side type names need updating. Informational.
- **Type Renamed With Changes.** The old type was matched to a new one whose layout also changed. The rename itself is a warning, and the actual breaking changes are reported alongside it as ordinary field- or case-level findings.

### Events

Soroban's `contractspecv0` carries no marker that says "this type is an event", so the tool cannot infer it from the spec. Instead you declare it, in the `[classification]` table of `.safeguard.toml`. See [Type Classification](#type-classification).

Classification affects only the **wording** of a finding and the remediation advice attached to it — a type classified as an event gets guidance about off-chain indexers and subscribers, because a change that is merely awkward for storage can be fully breaking for an indexer. It never affects the finding's `category`.

### Host Imports and Protocol Capabilities

A WASM import that a contract did not need before can raise the minimum Stellar protocol version the target network must support, independently of anything visible in the exported spec. `diff::compare_host_imports` classifies these changes using the versioned registry in `src/capability.rs`, which maps recognized `(module, name)` host-import wire codes (e.g. `("l", "_")` is `put_contract_data`) to a capability id, a capability group, and the protocol version at which the capability became available. See [Updating the Capability Registry](capability-registry.md) for what the registry is generated from and how to refresh it, and [`capability-reference.md`](capability-reference.md) for the full generated list.

- **Host Import Added.** The new build imports a recognized capability the old build did not. Warning — verify the target network has activated the required protocol.
- **Host Import Removed.** A recognized capability the old build imported is no longer imported. Informational.
- **Host Import Signature Changed.** The same `(module, name)` import appears on both sides but its resolved parameter/result types differ. Critical for a recognized capability (this should never legitimately happen and likely indicates a toolchain problem), Warning for an unrecognized one. Never reported when either side's type index could not be resolved — a missing signature is not evidence of a change.
- **Unknown Host Import.** The import's `(module, name)` pair is not in the registry. Its protocol requirement is deliberately left unset rather than guessed; the finding exists purely so the import stays visible. Warning.
- **Protocol Requirement Raised.** The highest `min_protocol` among the new build's recognized imports exceeds the old build's. Warning, and only computed when both sides have at least one recognized import to compare.
- **Protocol Environment Mismatch.** A single build's own `contractenvmetav0` protocol version is lower than the minimum protocol implied by its own recognized imports — an internal inconsistency in how the binary was produced. Critical.

## Type Identity

A contract spec identifies every user-defined type by name, but a name is not an identity. Two questions have to be kept apart:

- **Is this the same type as before?** — a *structural* question.
- **What kind of thing is it?** — a *semantic* question, covered in [Type Classification](#type-classification).

### Why name matching alone is not enough

Matching purely on name gets two cases wrong, in opposite directions.

- **Renames are false breaks.** Renaming `Config` to `Settings` without touching a single field produces "Struct Removed" plus "Struct Added" — two findings, one of them critical, for a change that is byte-for-byte compatible on chain.
- **Swaps are false matches.** If `Config` is deleted and an unrelated new type happens to be called `Config`, name matching reports only the field-level differences between two types that have nothing to do with each other, quietly treating a full replacement as an edit.

### How matching actually works

Types that exist under the same name in both specs are compared in place, exactly as before. The types left over — present only in the old spec, or only in the new one — are then matched against each other structurally, per kind (structs to structs, enums to enums, and so on; a struct is never matched to an enum).

Each type gets a **fingerprint**: a canonical string built from its members and their types, with the type's own name excluded. Matching then proceeds in two tiers:

1. **Identical fingerprint.** The layouts are the same, so this is a pure rename. Reported as **Type Renamed** (Info) — no migration needed.
2. **Similar member sets.** Otherwise the candidates are scored by [Jaccard similarity](https://en.wikipedia.org/wiki/Jaccard_index) over their member keys (name and type together). A pair must score at least `0.5` — more than half their members in common — to be considered a rename at all. Reported as **Type Renamed With Changes** (Warning), followed by the ordinary field- or case-level findings describing what actually changed.

Anything not matched under those rules is reported as a plain removal and a plain addition, which is the conservative outcome: an unmatched removal stays critical.

The matching is **deterministic** — candidates are iterated in sorted order and ties are broken by the lexicographically smaller new name, so the same pair of specs always produces the same output — and **bounded**, at one comparison per (removed, added) pair within a kind.

### What it deliberately does not do

- A removed type and an added type that share fewer than half their members are **not** matched. A rewrite is a rewrite.
- Each type participates in at most one rename. When several candidates are plausible, the best-scoring one wins and the rest fall back to removal/addition.
- Two unrelated types with coincidentally identical layouts (say, two distinct `struct Wrapper { value: u32 }`) can be matched. This is unavoidable — they are indistinguishable in the spec — and harmless: the finding is informational and the layouts really are compatible.
- Names are compared case-sensitively. `Config` and `config` are different names; if both exist, they are separate types.

## Type Classification

Classification answers the second question: what kind of thing a type is. Today that means one distinction — is it an **event**, consumed by off-chain indexers and subscribers, or an ordinary **storage/interface** type?

Nothing in `contractspecv0` records this. The tool used to guess from the name, treating any type whose name contained `event` as an event type. That guess is wrong in both directions: `PreventList` and `EventCounterCache` are not events, and a genuine `Transfer` event is not caught.

So it is configured explicitly, in `.safeguard.toml`:

```toml
[classification]
# Genuine events, by exact type name. Names need not contain "event".
events = ["Transfer", "LedgerEvent", "PriceUpdate"]

# Types to keep as ordinary storage. Takes precedence over everything below.
storage = ["PreventList", "EventCounterCache"]

# Opt-in fallback: treat any name containing "event" (case-insensitive) as an
# event. Off by default.
name_heuristic = false
```

Resolution precedence, first match wins:

1. listed in `storage` → storage
2. listed in `events` → event (declared)
3. `name_heuristic = true` and the name contains `event` → event (heuristic)
4. otherwise → storage

With no `[classification]` section, **nothing is treated as an event**. The tool makes no claim it cannot back up.

### Classification never affects the suppression key

This is the important property. A finding's `category` describes structure only — `Struct Field Removed`, `Enum Case Value Changed` — and never encodes classification. Event-ness is reported separately, in the finding's `classification` field:

```json
{
  "severity": "critical",
  "category": "Enum Case Value Changed",
  "target": "StatusEvent.Paused",
  "type_name": "StatusEvent",
  "classification": { "class": "event", "heuristic": false }
}
```

Because the suppression key (`category` + `target`) contains no classification, editing `[classification]` cannot move a finding out from under an existing suppression rule, and cannot pull an unrelated one under it. Reclassifying a type changes how a finding reads, never whether it fails the run.

When a classification came from the opt-in heuristic rather than a declaration, the report says so in the finding message and sets `"heuristic": true`, so a reviewer can always tell a guess from a fact.

### Category compatibility

Earlier versions folded the event guess into the category string itself. Those names are no longer emitted, but suppression configs that use them keep working — each is mapped onto its structural replacement:

| Pre-1.0 category | Stable category |
| :--- | :--- |
| `Event Definition Removed` | `Struct Removed` |
| `Event Field Removed` | `Struct Field Removed` |
| `Event Field Reordered` | `Struct Field Reordered` |
| `Event Field Type Changed` | `Struct Field Type Changed` |
| `Event Enum Removed` | `Enum Removed` |
| `Event Enum Case Removed` | `Enum Case Removed` |
| `Event Enum Case Value Changed` | `Enum Case Value Changed` |
| `Event Enum Case Added` | `Enum Case Added` |

New rules should use the stable names. `Error Enum …` categories are unrelated to events and were never remapped.

> **Full reference**: The [Finding Category Reference](finding-categories.md) page
> documents every category with its exact suppression string, default severity,
> trigger description, and detailed remediation guidance.

## Rule Registry

Every detection rule has a stable `rule_id` that is independent of the human
readable category label. The table below lists the registered rules, their
severity, and the guidance used when `--explain` is enabled.

| rule_id | Label | Severity | Guidance |
| :--- | :--- | :--- | :--- |
| `environment` | Environment | Info | Verify the target network supports the new protocol version and adjust tooling as needed. |
| `function_removed` | Function Removed | Critical | Restore the function or deprecate it in client integrations. |
| `function_documentation_changed` | Function Documentation Changed | Info | Keep downstream consumers aware of the updated docs and behavior. |
| `function_added` | Function Added | Info | Inform integrations about the new function. |
| `function_signature_changed` | Function Signature Changed | Critical | Update call sites and tests to match the new parameter structure. |
| `parameter_renamed` | Parameter Renamed | Warning | Update named-argument integrations to use the new parameter name. |
| `parameter_reordered` | Parameter Reordered | Critical | Restore the original parameter order. |
| `parameter_type_changed` | Parameter Type Changed | Critical | Update caller arguments and SDKs to use the new type. |
| `return_type_changed` | Return Type Changed | Critical | Update caller expectations and SDKs to the new return type. |
| `event_definition_removed` | Event Definition Removed | Critical | Update or remove downstream event consumers. |
| `struct_removed` | Struct Removed | Critical | Restore the struct or migrate any stored data that depends on it. |
| `struct_documentation_changed` | Struct Documentation Changed | Info | Keep documentation aligned with the intended struct usage. |
| `struct_added` | Struct Added | Info | Inform consumers about the new struct. |
| `struct_field_removed` | Struct Field Removed | Critical | Restore the field or perform a storage migration. |
| `event_field_removed` | Event Field Removed | Critical | Update indexers and consumers that expect the removed field. |
| `struct_field_reordered` | Struct Field Reordered | Critical | Restore the original field order. |
| `event_field_reordered` | Event Field Reordered | Critical | Update consumers to handle the new field ordering. |
| `struct_field_type_changed` | Struct Field Type Changed | Critical | Revert the type change or migrate existing data. |
| `event_field_type_changed` | Event Field Type Changed | Critical | Update event consumers to handle the new field type. |
| `struct_field_added` | Struct Field Added | Warning | Ensure consumers and storage migrations handle the new field. |
| `event_enum_removed` | Event Enum Removed | Critical | Restore the enum or update downstream event consumers. |
| `enum_removed` | Enum Removed | Critical | Restore the enum or migrate any stored data that uses it. |
| `enum_documentation_changed` | Enum Documentation Changed | Info | Ensure the updated docs are clear for consumers. |
| `enum_added` | Enum Added | Info | Inform consumers about the new enum type. |
| `enum_case_removed` | Enum Case Removed | Critical | Restore the case or migrate data that depends on it. |
| `event_enum_case_removed` | Event Enum Case Removed | Critical | Restore the case or update event consumers. |
| `enum_case_value_changed` | Enum Case Value Changed | Critical | Revert the value change to preserve serialization compatibility. |
| `event_enum_case_value_changed` | Event Enum Case Value Changed | Critical | Revert the change or update event consumers. |
| `enum_case_added` | Enum Case Added | Info | Ensure consumers can handle the new case. |
| `event_enum_case_added` | Event Enum Case Added | Info | Update consumers to handle the new event enum case. |
| `union_removed` | Union Removed | Critical | Restore the union or migrate data that uses it. |
| `union_added` | Union Added | Info | Inform consumers about the new union type. |
| `union_case_removed` | Union Case Removed | Critical | Restore the case or migrate existing data. |
| `union_case_reordered` | Union Case Reordered | Critical | Restore the original case order. |
| `union_case_type_changed` | Union Case Type Changed | Critical | Revert the type change or migrate data. |
| `union_case_added` | Union Case Added | Info | Ensure consumers can handle the new union case. |
| `error_enum_removed` | Error Enum Removed | Critical | Restore the error enum or update clients. |
| `error_enum_added` | Error Enum Added | Info | Inform client integrations about the new error enum. |
| `error_enum_case_removed` | Error Enum Case Removed | Critical | Restore the case or update client error handling. |
| `error_enum_case_value_changed` | Error Enum Case Value Changed | Critical | Revert the value change to preserve error-code compatibility. |
| `error_enum_case_added` | Error Enum Case Added | Info | Ensure clients can handle the new error case. |
| `cascading_layout_break` | Cascading Layout Break | Critical | Resolve the underlying layout break in the referenced type. |
| `host_import_added` | Host Import Added | Warning | Verify the target network has activated the required protocol before deploying. |
| `host_import_removed` | Host Import Removed | Info | No action typically required. |
| `host_import_signature_changed` | Host Import Signature Changed | Warning | Investigate why the same import now resolves to a different function type. |
| `unknown_host_import` | Unknown Host Import | Warning | Verify the import's requirement manually; consider proposing it for the capability registry. |
| `protocol_requirement_raised` | Protocol Requirement Raised | Warning | Confirm the target network has activated the reported protocol before deploying. |
| `protocol_environment_mismatch` | Protocol Environment Mismatch | Critical | Rebuild with a matching SDK/toolchain version. |

## Severity Levels

Every finding carries one of three severity levels.

- **Critical.** A change that will cause data corruption, serialization panics, or broken integrations. The presence of any critical finding marks the whole run as unsafe. Do not deploy.
- **Warning.** A change that may affect external systems or requires a migration step, but does not by itself corrupt local storage. Appended struct fields and parameter renames fall here.
- **Info.** A non-breaking, additive change recorded for visibility, such as a new function or a new enum case.

## Cascading Layout Breaks

The most subtle failures come from shared types. Suppose a small struct named `Money` is used as a field inside `Account`, and `Account` is used inside `Ledger`. If you change `Money`, the stored bytes for every `Account` and every `Ledger` are now wrong, even though you never touched those larger types directly.

To catch this, `mapper.rs` builds a reverse dependency graph: for each user-defined type, it records which other types embed it. After the direct comparison finds the set of types with critical changes, `diff.rs` walks that graph outward and marks every dependent type as broken too, transitively. These appear in the report under the **Cascading Layout Break** category, naming both the affected parent type and the underlying modified type that caused the break. Cyclic type references are handled safely so the walk always terminates.

## Spec Entry Integrity and Duplicate Detection

WASM binaries are permitted to carry more than one custom section with the same name. The Soroban toolchain typically emits a single `contractspecv0` section, but a crafted or malformed build can contain multiple. The parser concatenates entries from all `contractspecv0` sections in order, and then `spec.rs` checks for duplicate names within each kind (function, struct, enum, union, error enum).

### Why duplicates are a soundness problem

If two sections define the same type name differently, the analysis model contains the first definition it encountered. Any subsequent conflicting definition is discarded from the model. This creates a gap: the definition the tool analyzes may not be the one the contract actually uses. An attacker who controls section ordering can steer the tool to analyze a benign definition while the real, breaking one is ignored. The upgrade appears safe; in production it corrupts data.

### Detection policy

The tool compares every pair of definitions that share a name and kind using their serialized XDR bytes:

- **Conflicting duplicates** (same name, different bytes) produce a **`Spec Entry Conflict`** finding at `Critical` severity. The run is marked `is_safe: false` and exits with code 1. This is true regardless of which side carries the duplicate (old or new) and regardless of whether `--compat-duplicates` is set.

- **Identical duplicates** (same name, byte-identical bytes) produce a **`Spec Entry Duplicate`** finding. The severity depends on the mode:
  - **Default mode**: `Warning`. The WASM is non-canonical and the condition is suspicious.
  - **Compat mode** (`--compat-duplicates`): `Info`. Legitimate toolchains that historically emit split sections with identical entries can set this flag to suppress the warning without hiding genuine conflicts.

The first encountered definition is always the one used for comparison. The policy is deterministic and independent of `HashMap` iteration order.

### JSON fields

The `scope` object in JSON output always reflects the duplicate status:

```json
{
  "scope": {
    "old_spec_section_count": 2,
    "new_spec_section_count": 1,
    "old_duplicate_names": ["Ledger"],
    "new_duplicate_names": []
  }
}
```

`old_spec_section_count` and `new_spec_section_count` give the raw number of `contractspecv0` sections found in each binary. `old_duplicate_names` and `new_duplicate_names` list every entry name that appeared more than once (across all kinds), sorted for stable output. These fields are always present; the name lists are omitted from JSON when empty.

### Compat mode

Some older SDK versions emit two `contractspecv0` sections with identical entries. To handle those WASMs without failing, pass `--compat-duplicates`:

```bash
soroban-upgrade-safeguard old.wasm new.wasm --compat-duplicates
```

In compat mode, identical duplicates become informational and no longer cause a `Warning`. Conflicting duplicates remain `Critical` regardless — a difference in definitions cannot be safely ignored in any mode.

### Coverage

Duplicate detection covers all five spec entry kinds: functions, structs, enums, unions, and error enums. Provenance (which section each entry came from, zero-indexed) is tracked through decoding and reported in every finding message and in the `scope` JSON so an operator can identify exactly which sections are involved.

## Zero-Trust RPC Baseline Retrieval

When using `--contract-id` and `--rpc-url` to fetch the on-chain baseline, the tool implements a **zero-trust pipeline** that protects against malicious or compromised RPC endpoints:

### Cryptographic Hash Verification

After fetching the contract bytecode from the RPC, the tool computes its SHA-256 hash and compares it against the hash stored in the contract instance's `ContractExecutable::Wasm` entry. If the hashes do not match — indicating tampered bytecode — execution aborts immediately with an `IntegrityError[HashMismatch]`.

### Defensive Key Matching

Every entry returned by `getLedgerEntries` is validated against the expected ledger key:

- The RPC response entry's `key` field must match the XDR-base64 encoding of the ledger key that was requested.
- Empty entry arrays are rejected.
- Duplicate entries (multiple responses sharing the same key) are rejected as possible RPC manipulation.
- Missing `key` or `xdr` fields in any entry are rejected.

This replaces the insecure `entries[0]` pattern that previously trusted the RPC to return the correct entry.

### StellarAsset Handling

Contracts that are built-in `StellarAsset` contracts (which have no WASM bytecode) are detected upfront with a clear error message rather than producing confusing downstream failures.

### Transport Security

- By default, only `https://` URLs are accepted for RPC connections.
- The `--allow-http-local` flag permits `http://` connections exclusively to `localhost` or `127.0.0.1` for local development.
- Remote HTTP URLs are rejected even when `--allow-http-local` is set.
- Redirect following is disabled in the HTTP client to prevent HTTPS-to-HTTP downgrade attacks.

### Expected Hash Pinning

The optional `--expected-wasm-hash <HEX>` flag lets callers pin the expected on-chain WASM hash. After the RPC fetch completes and the hash is verified against the instance entry, the tool also compares it against this user-supplied value. A mismatch fails immediately, providing an additional integrity check for CI/CD pipelines that know the expected deployment hash ahead of time.

### IntegrityError Types

| Error | Cause |
|-------|-------|
| `IntegrityError[HashMismatch]` | The SHA-256 of the fetched bytecode does not match the hash in the contract instance entry |
| `IntegrityError[KeyMismatch]` | The ledger key in the RPC response does not match the requested key |

### Report Metadata

When the baseline is fetched from RPC, the report includes:

- `baseline_source`: Set to `"RPC"` (or `"Local File"` for disk-based comparisons).
- `verified_code_hash`: The verified SHA-256 hash of the on-chain WASM, expressed as a hex string.

These fields appear in the JSON output (`--format json`) and in the text/Markdown summaries:

```bash
soroban-upgrade-safeguard --contract-id C... \
  --rpc-url https://soroban-testnet.stellar.org \
  --format json \
  new.wasm
```

Example JSON excerpt:

```json
{
  "baseline_source": "RPC",
  "verified_code_hash": "a1b2c3d4e5f6..."
}
```

## JSON Schema

The JSON output is the integration surface for dashboards, bots, and other
tooling, so its shape is published as a JSON Schema (Draft 2020-12) under
[`schema/`](../schema):

- [`schema/report.schema.json`](../schema/report.schema.json) — the single-pair
  document (`--format json` on a contract pair).
- [`schema/batch-report.schema.json`](../schema/batch-report.schema.json) — the
  batch document (`--manifest`, `--old-dir`/`--new-dir`, or `--old-glob`/`--new-glob` with `--format json`),
  whose top level differs from the single-pair shape and embeds a single-pair
  report per contract under `results`.

Both schemas are **derived from the Rust output types**, not hand-written, so
they cannot silently drift from what the tool emits: `tests/schema_validation.rs`
regenerates them from the types and validates real emitted output — including a
run with suppressed findings and one produced with `--explain` — against the
committed files, failing if they diverge. Conditionally omitted fields
(`suppressed`, `suppression_reason`, `remediation`, the duplicate-name lists, …)
are marked optional, and the enumerated fields (the `counts` severities and
`recommended_bump`) are constrained to their allowed values.

To regenerate the committed schema after intentionally changing an output type:

```bash
UPDATE_SCHEMA=1 cargo test --test schema_validation schemas_match_the_types
```

### Stability

The crate is pre-1.0 (`0.x`). While it remains pre-1.0 the JSON shape may still
change between minor versions, but such changes will be **additive wherever
possible** — new optional fields rather than renamed or removed ones — and any
breaking change to the shape will be called out in the release notes. Consumers
should ignore unknown fields so additive changes do not break them. A firmer
"additive changes only within a major version" guarantee is intended once the
crate reaches 1.0.

## Reading the Report

A run prints a header for each loaded contract with a one line summary of how many functions, structs, enums, unions, and error enums it contains. It then prints the safety report.

The report begins with an overall status line that is either passed or failed, followed by counts of critical, warning, and info findings. Below that, findings are grouped by category, sorted for stable output, and each line is prefixed with a colored marker that maps to its severity. When the run fails, a closing action-required notice explains the practical consequences of deploying anyway.

If the two contracts have identical exports and types, the report states that no relevant changes were detected and the run passes.

## Suppressing Known Breaking Changes

Sometimes a breaking change is deliberate and already accounted for — a planned
storage migration, a re-initialization gated behind an admin call, or a
deprecated function dropped on purpose. A suppression config lets a team
whitelist specific, reviewed findings so they no longer fail the run, while
keeping them visible in the report as explicitly acknowledged.

### Config file

By default the tool looks for `.safeguard.toml` in the current directory. You
can point at a different file with `--config <PATH>`:

```bash
soroban-upgrade-safeguard ./on-chain.wasm ./candidate.wasm --config .safeguard.toml
```

If no `--config` is given and `.safeguard.toml` is absent, nothing is
suppressed and the tool behaves exactly as it always has. If you pass
`--config` explicitly and the file is missing or malformed, that is a hard
error rather than a silent no-op, so a typo never quietly disables suppression.

Each `[[suppress]]` entry acknowledges exactly one finding. The stable key is
`rule_id`, and the legacy `category` field is still accepted as a compatibility
alias for older configs:

```toml
[[suppress]]
rule_id = "struct_field_removed"
target  = "ConfigData.threshold"
reason  = "Planned storage migration in v2 drops the unused threshold field."

[[suppress]]
rule_id = "function_signature_changed"
target  = "initialize"
reason  = "Re-init is intentional and gated behind the migration admin call."
```

A ready-to-copy template lives at [`.safeguard.example.toml`](../.safeguard.example.toml).

### How matching works

Matching is **exact**: a rule applies only when both its stable `rule_id` and
its `target` equal the finding's own values. This strictness keeps a suppression
from over-applying to a sibling field, enum case, or parameter. A rule that
omits `target` matches only findings that themselves have no target (for
example `Environment` changes). Legacy configs that still use `category` are
mapped to the same rule id automatically, so existing suppressions keep working.

- **Category & Target**: matched verbatim.
- **Fingerprint**: calculated as the SHA-256 hex hash of:
  `category:<category>\ntarget:<target_or_empty>\nmessage:<normalized_message>`
  where `<normalized_message>` has all consecutive whitespace collapsed to single spaces and leading/trailing whitespace removed. If the finding content changes or drifts, the fingerprint will mismatch and suppression stops applying.
- **Expiry**: evaluated against the current system date (`YYYY-MM-DD`). Expired rules trigger a hard failure during config loading.
- **Targetless Wildcards**: omitting `target` matches only targetless findings (e.g., `Environment`). This requires explicit opt-in (`allow_targetless = true`) and is capped at a ceiling of 3 rules.

### Legacy Format & Migration

For backwards compatibility, old-format rules (lacking `author`, `expiry`, or `fingerprint`) will trigger a warning on `stderr` during execution for one release before becoming a hard error. To migrate an old rule:
1. Run `soroban-upgrade-safeguard` with `--format json`.
2. Copy the finding's `category` and `target`.
3. Add `author`, `reason`, `expiry` (`YYYY-MM-DD`), and compute or copy the `fingerprint`.

`category` is always **structural** — it describes what changed in the shape of
the contract and nothing else. In particular it never encodes whether a type is
an event, so editing `[classification]` can never change which findings a rule
matches. Configs written against the older event-flavored category names still
work; see [Category compatibility](#category-compatibility) for the mapping.

### What suppression does and does not change

A suppressed finding is **not hidden**. It is still listed in the report, marked `[SUPPRESSED]`, and prominently summarized in the Applied Suppressions Audit Log in text and Markdown outputs. In JSON output, suppressed findings carry `"suppressed": true`, along with `suppression_reason`, `suppression_author`, `suppression_expiry`, and `suppression_fingerprint`.

If any Critical findings are suppressed and the gate passes, a prominent **Security Notice** warning is printed on `stderr` at exit.

## Resource Limits and Hardening Against Malicious Input

The tool runs as a CI gate and, in RPC mode, decodes WASM fetched for an arbitrary
contract ID. The input WASM and its embedded `contractspecv0` / `contractenvmetav0`
sections are therefore treated as **adversarial**. Without bounds, a crafted section
could declare an enormous vector length (a multi-gigabyte allocation) or nest a type
to arbitrary depth (a native stack overflow that aborts the process). A gate that can
be crashed on demand is a gate that can be bypassed.

A single resource policy is threaded through every decode and every recursive type
walk. Four limits, each independently configurable:

| Limit | Default | Bounds |
| :--- | :--- | :--- |
| `max_xdr_depth` | 64 | XDR recursion depth per entry. Guards against stack overflow at decode time. |
| `max_xdr_len` | 33554432 (32 MiB) | Bytes decoded per custom section — shared across every entry in the section, so it also caps the total decoded bytes. Guards against oversized-length allocations. |
| `max_entries` | 100000 | Decoded spec entries, **summed across all `contractspecv0` sections** (a module may carry more than one). Env-metadata entries are budgeted separately. |
| `max_walk_depth` | 128 | Recursion depth for the type walkers — structural equality, finding-message rendering, and cascade detection — which operate on already-decoded types. |

The distinction between `max_xdr_len` (a **per-section byte cap**) and `max_entries`
(a **cross-section count cap**) matters: many individually valid sections cannot be
summed to exhaust memory, and a single section cannot over-allocate before the entry
cap trips.

### Configuring limits

Set a `[limits]` table in `.safeguard.toml` (the same file used for suppressions).
Every field is optional; an omitted field keeps the default:

```toml
[limits]
max_xdr_depth  = 128
max_xdr_len    = 67108864   # 64 MiB
max_entries    = 200000
max_walk_depth = 256
```

Or override any single limit for one run with a flag. Precedence is **flags > file >
defaults**:

```bash
soroban-upgrade-safeguard old.wasm new.wasm --max-xdr-depth 128 --max-walk-depth 256
```

The defaults accept every fixture and a representative corpus of real mainnet specs.
Raise a limit only if a legitimate, unusually large contract is rejected.

### Behavior when a limit is exceeded

An input that exceeds a limit is rejected with a controlled, typed error and the CLI
exits with **code 2** — distinct from `1` (breaking changes) so a pipeline can tell
"the input was rejected as adversarial" apart from "the upgrade is unsafe". The
process never aborts with a stack overflow or an out-of-memory kill.

In **batch mode**, the policy is enforced **per pair**: a pair that trips a limit (or
otherwise errors) fails only that pair and is reported as errored — the rest of the
run continues rather than aborting. The overall run then exits `2` if any pair hit a
limit, else `1` if any pair had breaking changes, else `0`.

## Exit Codes and CI Integration

The tool is designed to drop into a continuous integration pipeline.

- Exit code `0`: no critical findings. The upgrade is considered safe to deploy.
- Exit code `1`: at least one critical finding, a failed `--expect-bump` gate, or a fatal error such as a missing or malformed WASM file.
- Exit code `2`: a resource limit was exceeded on untrusted input (see [Resource Limits](#resource-limits-and-hardening-against-malicious-input)). Raise the relevant limit to proceed.

Because the process exits non-zero on critical findings, you can gate a deployment job on it directly:

```bash
soroban-upgrade-safeguard ./on-chain.wasm ./candidate.wasm
```

If that command fails, the pipeline stops before the upgrade is published.

## Limitations

- **Storage layout is only analyzed when you declare it.** Without a storage schema, the tool sees only the exported interface and says so explicitly in every format. With one, coverage extends exactly as far as the types you declared and no further.
- **The schema is a declaration, not a measurement.** The tool trusts what you declare, after checking it does not contradict the exported spec. It does not read the compiled code to confirm that the declared types are the ones actually written to storage. Keeping the manifest truthful is the team's responsibility, in the same way a type signature is.
- Storage access patterns are not extracted from the WASM code section. A future change could infer storage writes and key construction statically, which would remove the need to declare them by hand. That work is deliberately out of scope here.
- Event detection relies on a name heuristic. A type that represents an event but does not contain `event` in its name will be analyzed as an ordinary struct or enum.
- The tool reasons about the declared interface in the spec sections. It does not analyze the function bodies, so a change in internal logic that keeps the same interface is invisible to it.
- Appended struct fields on values are reported as warnings rather than errors. Whether they are truly safe depends on having a migration or default in place, which the tool cannot verify.
- Comparison is by name. Renaming a type is seen as removing the old name and adding a new one, not as a rename.
- Storage schemas are not supported in batch mode, because a manifest describes one specific contract's layout.

## Migration Note

This release changes the wording of the verdict and adds a new optional input. Nothing you already run breaks, but two things look different.

### The verdict wording changed

The status line is now explicit about the scope it covers.

| Before | After |
| :--- | :--- |
| `✅ PASSED (No breaking changes detected)` | `✅ PASSED (No exported-interface breaking changes)` |
| `❌ FAILED (Critical breaking changes detected)` | `❌ FAILED (Exported-interface breaking changes detected)` |

When a storage schema is supplied, the passing wording widens to `✅ PASSED (No exported-interface or declared-storage breaks)`.

The old wording was not inaccurate about what had been checked, but it implied a broader guarantee than the analysis supported. A reader could reasonably take "no breaking changes detected" to mean "safe to upgrade", including storage. It did not mean that, and it never had. The new wording states the boundary instead of leaving it to be inferred, and every format now carries a scope line saying whether storage layout was analyzed.

**If you match on output text**, update any assertion on the old status strings. The severity counts, category names, `is_safe`, and exit-code semantics are unchanged, so tooling that keys on those needs no changes.

### JSON gained scope fields

Two additive fields appear at the top level. Existing fields are untouched, so consumers that ignore unknown keys need no changes.

```json
{
  "is_safe": true,
  "certifies": "Exported interface + environment metadata only — storage layout is NOT verified by this result.",
  "scope": {
    "exported_interface_analyzed": true,
    "env_metadata_analyzed": true,
    "storage_layout_analyzed": false,
    "summary": "..."
  }
}
```

If your pipeline treats `is_safe: true` as "storage compatible", check `scope.storage_layout_analyzed` as well. When it is `false`, storage was not examined at all. When it is `true`, `storage_key_types` and `storage_value_types` report how many declared types were covered.

### The new storage-schema input

`--old-storage-schema` and `--new-storage-schema` are optional. Omitting them reproduces the previous behavior exactly, now with honest scope reporting. Adopting them is incremental: declare your storage-key types and the internal types you serialize into storage, starting with the ones holding value-bearing data. Partial coverage is genuinely useful, and the report always states how far it reached. See [Storage Schema Analysis](#storage-schema-analysis) for the format.

## Frequently Asked Questions

**Does the tool need access to the Stellar network?**
No. It works entirely from the two local WASM files.

**Can I run it on contracts built by tools other than the standard Soroban SDK?**
It works on any WASM that embeds a standard `contractspecv0` custom section. If that section is missing, there is nothing to compare and the spec will appear empty.

**Why is an appended field only a warning?**
Appending a field does not move existing fields, so old data still deserializes for the fields that were already there. The new field, however, has no stored value in old entries, so you need a migration or a default. The tool flags this so you remember to handle it. Note that appending to a declared storage **key** is Critical rather than a warning, because it changes the address of every entry.

**What counts as a safe upgrade?**
Any run that finishes with zero critical findings, *within the scope that was analyzed*. Warnings and info findings are worth reviewing but do not block deployment. Read [What a Passing Verdict Guarantees](#what-a-passing-verdict-guarantees) before treating a pass as storage compatibility.

**Does a green run mean my upgrade is storage safe?**
Not on its own. By default the tool analyzes only the exported interface, and it says so in the report. Storage layout is analyzed only when you supply a [storage schema](#storage-schema-analysis), and then only for the types you declared.

**Do I have to declare every storage type?**
No. Partial coverage is useful and the report always states how far the analysis reached. Start with your storage-key types and the internal types that hold value-bearing data, since those are where a silent layout change is most costly.

**Why do I need two schema files instead of one?**
A layout change is only observable as a difference between two snapshots. One file describes one build, so detecting that a field moved requires the layout before and after. Keeping the manifest in version control means you usually already have both.

For guidance on contributing changes to this tool, see [contributing.md](contributing.md).

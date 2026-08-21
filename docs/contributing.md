# Contributing to Soroban Upgrade Safeguard

Thank you for your interest in improving Soroban Upgrade Safeguard. This guide explains how the project is laid out, how to set up a development environment, and what we expect from a contribution before it is merged.

## Table of Contents

1. [Ways to Contribute](#ways-to-contribute)
2. [Development Setup](#development-setup)
3. [Project Structure](#project-structure)
4. [Building and Running](#building-and-running)
5. [Testing](#testing)
6. [Test Fixtures](#test-fixtures)
7. [Fuzzing](#fuzzing)
8. [Benchmarking](#benchmarking)
9. [Code Coverage](#code-coverage)
10. [Minimum Supported Rust Version](#minimum-supported-rust-version)
11. [Coding Guidelines](#coding-guidelines)
12. [Adding a New Detection Rule](#adding-a-new-detection-rule)
13. [Commit and Pull Request Process](#commit-and-pull-request-process)
14. [Reporting Bugs](#reporting-bugs)
15. [Code of Conduct](#code-of-conduct)

## Ways to Contribute

There are many useful contributions beyond writing code:

- Reporting a bug with a clear reproduction
- Improving the documentation in the `docs` folder
- Adding test fixtures that cover edge cases the tool currently misses
- Proposing or implementing a new detection rule
- Improving the clarity of the CLI output

Small, focused changes are easier to review and land faster than large ones. If you plan a large change, open an issue first so we can agree on the approach before you invest time.

## Development Setup

You need Rust 1.85 or later — see
[Minimum Supported Rust Version](#minimum-supported-rust-version) for how that
floor is determined and kept honest. Install a toolchain with rustup if you do
not already have one:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

1. **Fork the Repository**: Navigate to [ShippedLabs/soroban-upgrade-safeguard](https://github.com/ShippedLabs/soroban-upgrade-safeguard) on GitHub and click the **Fork** button to create a copy under your personal GitHub account.
   
2. **Clone Your Fork**: Clone your personal fork locally to your machine:
   ```bash
   git clone [https://github.com/](https://github.com/)<your-username>/soroban-upgrade-safeguard.git
   cd soroban-upgrade-safeguard
   cargo build
   ```

We recommend installing the standard formatting and linting components:

```bash
rustup component add rustfmt clippy
```

Optional: install the `pre-commit` framework to run quick checks automatically on every commit.

```bash
pip install pre-commit
pre-commit install
```

The repository includes a `.pre-commit-config.yaml` that runs `cargo fmt` and `cargo clippy` on staged files. These checks are intentionally limited to fast, local validations so they catch common problems before pushing. Running the full test suite is left to CI (or to a manual `pre-push` hook if you opt in).

## Project Structure

The source lives under `src/` and is split into focused modules. Understanding this layout makes it much easier to find where a change belongs.

- `main.rs` parses command line arguments with clap and drives the full pipeline.
- `lib.rs` exposes the reusable library API and the canonical comparison pipeline.
- `color.rs` decides whether terminal output should use color.
- `suppression.rs` parses `.safeguard.toml` and matches acknowledged findings.
- `limits.rs` defines the resource limits that protect decoding and type walks from untrusted input.
- `loader.rs` reads a WASM file from disk and validates that it is a well formed WASM binary.
- `parser.rs` extracts the Soroban custom sections, decodes the XDR spec entries, and records every WASM function import (module, name, resolved signature).
- `spec.rs` defines `ContractSpec`, the in-memory model that groups functions and user-defined types by name.
- `storage_schema.rs` loads optional manifests for checking internal storage layouts.
- `capability.rs` is the versioned registry mapping recognized Soroban host imports to protocol capability metadata; see [Updating the Capability Registry](capability-registry.md).
- `mapper.rs` turns type definitions into readable signatures and builds the reverse dependency graph used for cascade detection.
- `diff.rs` holds the comparison logic and the `Finding` and `Severity` types. This is where most detection rules live, including `compare_host_imports`, which classifies host-import changes against `capability.rs`.
- `dependency.rs` propagates breaking changes across declared contract dependencies in batch comparisons.
- `report.rs` aggregates findings into a `SafetyReport` and renders the colored summary.

Tests and fixtures live under `tests/`.

Snapshot tests live in `tests/snapshot_tests.rs` and cover the Text, Markdown, and JSON output formats. They use a custom snapshot helper that compares rendered output against stored `.txt`, `.md`, and `.json` files in `tests/snapshots/`.

### Updating snapshots

When you intentionally change the output format (e.g., add a new finding category or modify the report layout), the snapshot tests will fail. To update all snapshots:

```bash
UPDATE_SNAPSHOTS=1 cargo test --test snapshot_tests
```

Review the changed snapshot files with `git diff tests/snapshots/` to confirm the differences are expected, then commit them alongside your code changes.

For a deeper explanation of how these pieces fit together at runtime, read [documentation.md](documentation.md).

## Building and Running

Build a debug binary:

```bash
cargo build
```

Run the tool against two WASM files without installing it:

```bash
cargo run -- ./tests/wasm/old.wasm ./tests/wasm/new.wasm
```

Build an optimized release binary:

```bash
cargo build --release
```

## Testing

Run the full test suite before opening a pull request:

```bash
cargo test
```

Every behavior change should come with a test that fails before your change and passes after it. When you add a new detection rule, add at least one test that proves the rule fires on a breaking input and one that proves it stays quiet on a compatible input. This keeps the rule honest and guards against false positives, which are just as harmful as missed breaks because they train users to ignore the report.

## Test Fixtures

Integration tests compare real compiled contracts. The `tests/` directory contains a `build_fixtures.sh` helper and a `fixtures` directory with paired contract sources, along with a `wasm` directory for the compiled outputs.

When you add a fixture, keep each pair minimal and focused on a single kind of change so the resulting test reads clearly. A fixture that mixes many unrelated changes makes failures hard to diagnose. Document briefly what the pair is meant to demonstrate, either in a short comment or in the test that consumes it.

## Fuzzing

The parsing path decodes input the tool does not control — a WASM binary, in RPC
mode fetched from a remote endpoint — so it is exercised by coverage-guided
fuzzing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz). The targets
live in `fuzz/` and are **not** part of `cargo test`: they need a nightly
toolchain and libFuzzer, so they are run on demand rather than in the normal
suite.

### One-time setup

`cargo-fuzz` builds with libFuzzer, which requires a nightly toolchain:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

### Targets

- `extract_metadata` — feeds arbitrary bytes through the full WASM parse and
  custom-section XDR decode (`parser::extract_metadata`).
- `decode_spec_entries` — feeds arbitrary bytes straight into the concatenated
  `ScSpecEntry` XDR cursor loop (`parser::decode_spec_entries`), bypassing the
  WASM wrapper so the loop is reached without first building a valid module.

Both assert the same property: the function returns `Ok` or `Err` on any input
and never panics or hangs. Loop termination depends on the XDR cursor position
strictly advancing each iteration; libFuzzer's timeout enforces the no-hang half
of the property.

### Running

```bash
# Run a target until stopped (Ctrl-C). Seeds come from fuzz/corpus/<target>/.
cargo +nightly fuzz run extract_metadata
cargo +nightly fuzz run decode_spec_entries

# Time-boxed run, e.g. a quick smoke check or a CI budget:
cargo +nightly fuzz run extract_metadata -- -max_total_time=60
cargo +nightly fuzz run decode_spec_entries -- -max_total_time=60
```

A seed corpus derived from the `tests/wasm` fixtures is committed under
`fuzz/corpus/<target>/` — the full modules for `extract_metadata`, and the
extracted `contractspecv0` section bytes for `decode_spec_entries`. Any crash or
hang is written to `fuzz/artifacts/<target>/`; reproduce it with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

`stellar-xdr`'s `arbitrary` feature is declared in `fuzz/Cargo.toml` rather than
in the crate's release dependencies, so structure-aware targets can use it
without pulling it into the shipped binary (see issue #79).

## Benchmarking

There was no performance measurement of any kind until issue #135: the tool's
cost profile — and whether a given change makes it worse — was previously
unknown. `benches/pipeline.rs` uses [Criterion](https://github.com/bheisler/criterion.rs)
to benchmark the four stages of the analysis pipeline independently:

- **Parsing** — decoding concatenated `ScSpecEntry` XDR bytes.
- **Spec building** — `ContractSpec::from_entries_checked`, including duplicate detection.
- **Diffing** — `diff::compare` across two specs.
- **Cascade detection** — the reverse-dependency graph walk in `mapper.rs`.
- **Report rendering** — text-format `SafetyReport` generation.

The checked-in `tests/wasm` fixtures are too small to show how cost scales, so
each stage runs against synthetically generated specs at three sizes (10, 100,
1000 items) rather than one small real-world input — the interesting question
is the scaling curve, not a single absolute number. Run the full suite with:

```bash
cargo bench
```

Criterion keeps a rolling baseline in `target/criterion/` and reports the
percentage change against the previous run for every benchmark, so the first
run after this harness lands establishes the baseline and every run after
that is a comparison. A meaningful change is a consistent shift outside
Criterion's reported noise threshold (it flags this explicitly per
benchmark, e.g. "Performance has regressed") — a single run drifting by a
few percent with no such flag is noise, not a regression. Investigate any
stage whose growth from size 10 to size 1000 is worse than roughly linear;
that is the shape issue #135 flags as a risk in `detect_cascading_layout_breaks`
and the duplicate-scan in `report.rs`'s suppression matching.

## Code Coverage

CI measures line coverage on every pull request with
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) and publishes the
per-file summary — including the count for `src/diff.rs`, where most detection
rules live — to the run's job summary. Run it locally with:

```bash
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview
cargo llvm-cov --workspace --summary-only
```

Add `--html` and open `target/llvm-cov/html/index.html` for a line-by-line
view of exactly which branches a test suite run did or did not reach.

The coverage job does not fail the build on a threshold. With over forty
finding categories emitted from `src/diff.rs`, and known gaps such as
`fetch_wasm_from_rpc`'s error paths (unreachable without a network) and the
batch renderers in `src/main.rs`, a threshold chosen before anyone has looked
at the real baseline tends to get lowered to fit rather than met. Establish
the baseline first, call out any detection rule with zero coverage as a
follow-up issue, and decide on enforcement — and the number — deliberately
afterward.

## Minimum Supported Rust Version

`rust-version` in `Cargo.toml` declares 1.85. This is not a guess: it is the
highest `rust-version` among every direct and transitive dependency actually
resolved in `Cargo.lock` at the time it was set (checkable yourself with
`cargo metadata --format-version 1`, which surfaces each package's declared
`rust_version`; at the time of writing the binding constraint was clap
4.6.1's floor of 1.85). CI's `msrv` job builds and tests against exactly that
version with `cargo build --locked` / `cargo test --locked`, so the declared
floor is verified on every pull request rather than trusted blindly.

The real minimum is a function of the dependency tree, not just this crate's
own code, so it can rise on an ordinary dependency update with no visible
diff in `src/`. When bumping a dependency, re-run `cargo metadata` (or check
the new version's own `rust-version`) and compare against 1.85: if the
update raises the floor, bump `rust-version` in the same pull request so the
change is deliberate and documented rather than discovered later by a user
on an older toolchain hitting a compile error. The `msrv` CI job exists
specifically to catch the case where this step is missed — a dependency
bump that silently raises the real floor fails that job instead of merging
quietly.

Pinning the toolchain contributors build with (a `rust-toolchain.toml`) is a
separate decision from declaring this floor, and is not currently done:
`rust-version` states what the crate supports, not what any given
contributor's local toolchain must be.

## Coding Guidelines

- Format every change with `cargo fmt` before committing.
- Run `cargo clippy` and resolve warnings rather than silencing them, unless there is a clear and documented reason.
- Match the style of the surrounding code: the existing modules use short doc comments on public items and keep functions focused on one task.
- Prefer clear, descriptive names over abbreviations.
- Error handling uses the `anyhow` crate. Add context to errors with `.context(...)` so failures explain what the tool was trying to do.
- Keep user-facing messages specific. A good finding names the type, the field or parameter, and what changed, so the reader can act without opening the source.

## Adding a New Detection Rule

Most new rules belong in `diff.rs`. The general shape is:

1. Decide the category name and the severity. Critical means the change will break a deployed contract or its integrations. Warning means it may require a migration or affect external systems. Info means it is additive and safe.
2. Add the comparison logic inside the relevant function, such as `compare_functions`, `compare_structs`, or `compare_enums`, or add a new comparison function and call it from `compare`.
3. Push a `Finding` with a clear message when the condition is met.
4. If your rule concerns a user-defined type whose change could cascade to types that embed it, set the `type_name` field on the `Finding` to `Some(name)` so the cascade detector can identify affected types from structured data.
5. Add tests and, if helpful, a fixture pair.

When in doubt about whether something should be critical or a warning, lean toward the stricter level only when the change genuinely corrupts stored data or breaks callers. Overusing critical erodes trust in the report.

## Commit and Pull Request Process

1. Create a branch from `main` for your work.
2. Keep commits focused and write clear commit messages that explain why the change is needed, not only what changed.
3. Ensure `cargo fmt --check`, `cargo clippy`, `cargo build`, and `cargo test` all pass locally before pushing. These are the exact steps the CI workflow runs, so a clean local run means CI will pass.
4. Open a pull request that describes the change, the motivation, and how you verified it. Link any related issue. The CI workflow at `.github/workflows/ci.yml` will run automatically and must be green before the pull request can be merged.
5. Be responsive to review feedback. Small follow-up commits during review are fine; we can squash on merge.

## Reporting Bugs

A good bug report includes:

- What you ran, including the exact command
- What you expected to happen
- What actually happened, including the full output
- If possible, the two WASM files or a minimal pair of contract sources that reproduce the issue

Reproducible reports are far easier to fix. If you can attach a fixture pair that triggers the bug, that is the most helpful form of all.

## Code of Conduct

Be respectful and constructive in all project spaces. Assume good intent, give specific and actionable feedback, and keep discussion focused on the work. We want this to be a welcoming project for contributors of every experience level.
# Contributing to Soroban Upgrade Safeguard

Thank you for your interest in improving Soroban Upgrade Safeguard. This guide explains how the project is laid out, how to set up a development environment, and what we expect from a contribution before it is merged.

## Table of Contents

1. [Ways to Contribute](#ways-to-contribute)
2. [Development Setup](#development-setup)
3. [Project Structure](#project-structure)
4. [Building and Running](#building-and-running)
5. [Testing](#testing)
6. [Test Fixtures](#test-fixtures)
7. [Fuzzing](#fuzzing)
8. [Coding Guidelines](#coding-guidelines)
9. [Adding a New Detection Rule](#adding-a-new-detection-rule)
10. [Commit and Pull Request Process](#commit-and-pull-request-process)
11. [Reporting Bugs](#reporting-bugs)
12. [Code of Conduct](#code-of-conduct)

## Ways to Contribute

There are many useful contributions beyond writing code:

- Reporting a bug with a clear reproduction
- Improving the documentation in the `docs` folder
- Adding test fixtures that cover edge cases the tool currently misses
- Proposing or implementing a new detection rule
- Improving the clarity of the CLI output

Small, focused changes are easier to review and land faster than large ones. If you plan a large change, open an issue first so we can agree on the approach before you invest time.

## Development Setup

You need a recent stable Rust toolchain. Install it with rustup if you do not already have it:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then clone the repository and confirm it builds:

```bash
git clone <your-fork-url>
cd soroban-upgrade-safeguard
cargo build
```

We recommend installing the standard formatting and linting components:

```bash
rustup component add rustfmt clippy
```

## Project Structure

The source lives under `src/` and is split into focused modules. Understanding this layout makes it much easier to find where a change belongs.

- `main.rs` parses command line arguments with clap and drives the full pipeline.
- `loader.rs` reads a WASM file from disk and validates that it is a well formed WASM binary.
- `parser.rs` extracts the Soroban custom sections and decodes the XDR spec entries.
- `spec.rs` defines `ContractSpec`, the in-memory model that groups functions and user-defined types by name.
- `mapper.rs` turns type definitions into readable signatures and builds the reverse dependency graph used for cascade detection.
- `diff.rs` holds the comparison logic and the `Finding` and `Severity` types. This is where most detection rules live.
- `report.rs` aggregates findings into a `SafetyReport` and renders the colored summary.

Tests and fixtures live under `tests/`.

For a deeper explanation of how these pieces fit together at runtime, read [documentation.md](documentation.md).

## Building and Running

Build a debug binary:

```bash
cargo build
```

Run the tool against two WASM files without installing it:

```bash
cargo run -- ./tests/wasm/old.wasm ./tests/wasm/new.wasm
```

Build an optimized release binary:

```bash
cargo build --release
```

## Testing

Run the full test suite before opening a pull request:

```bash
cargo test
```

Every behavior change should come with a test that fails before your change and passes after it. When you add a new detection rule, add at least one test that proves the rule fires on a breaking input and one that proves it stays quiet on a compatible input. This keeps the rule honest and guards against false positives, which are just as harmful as missed breaks because they train users to ignore the report.

## Test Fixtures

Integration tests compare real compiled contracts. The `tests/` directory contains a `build_fixtures.sh` helper and a `fixtures` directory with paired contract sources, along with a `wasm` directory for the compiled outputs.

When you add a fixture, keep each pair minimal and focused on a single kind of change so the resulting test reads clearly. A fixture that mixes many unrelated changes makes failures hard to diagnose. Document briefly what the pair is meant to demonstrate, either in a short comment or in the test that consumes it.

## Coding Guidelines

- Format every change with `cargo fmt` before committing.
- Run `cargo clippy` and resolve warnings rather than silencing them, unless there is a clear and documented reason.
- Match the style of the surrounding code: the existing modules use short doc comments on public items and keep functions focused on one task.
- Prefer clear, descriptive names over abbreviations.
- Error handling uses the `anyhow` crate. Add context to errors with `.context(...)` so failures explain what the tool was trying to do.
- Keep user-facing messages specific. A good finding names the type, the field or parameter, and what changed, so the reader can act without opening the source.

## Adding a New Detection Rule

Most new rules belong in `diff.rs`. The general shape is:

1. Decide the category name and the severity. Critical means the change will break a deployed contract or its integrations. Warning means it may require a migration or affect external systems. Info means it is additive and safe.
2. Add the comparison logic inside the relevant function, such as `compare_functions`, `compare_structs`, or `compare_enums`, or add a new comparison function and call it from `compare`.
3. Push a `Finding` with a clear message when the condition is met.
4. If your rule concerns a user-defined type whose change could cascade to types that embed it, set the `type_name` field on the `Finding` to `Some(name)` so the cascade detector can identify affected types from structured data.
5. Add tests and, if helpful, a fixture pair.

When in doubt about whether something should be critical or a warning, lean toward the stricter level only when the change genuinely corrupts stored data or breaks callers. Overusing critical erodes trust in the report.

## Commit and Pull Request Process

1. Create a branch from `main` for your work.
2. Keep commits focused and write clear commit messages that explain why the change is needed, not only what changed.
3. Ensure `cargo fmt --check`, `cargo clippy`, `cargo build`, and `cargo test` all pass locally before pushing. These are the exact steps the CI workflow runs, so a clean local run means CI will pass.
4. Open a pull request that describes the change, the motivation, and how you verified it. Link any related issue. The CI workflow at `.github/workflows/ci.yml` will run automatically and must be green before the pull request can be merged.
5. Be responsive to review feedback. Small follow-up commits during review are fine; we can squash on merge.

## Reporting Bugs

A good bug report includes:

- What you ran, including the exact command
- What you expected to happen
- What actually happened, including the full output
- If possible, the two WASM files or a minimal pair of contract sources that reproduce the issue

Reproducible reports are far easier to fix. If you can attach a fixture pair that triggers the bug, that is the most helpful form of all.

## Code of Conduct

Be respectful and constructive in all project spaces. Assume good intent, give specific and actionable feedback, and keep discussion focused on the work. We want this to be a welcoming project for contributors of every experience level.

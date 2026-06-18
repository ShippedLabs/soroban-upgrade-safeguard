# Contributing to Soroban Upgrade Safeguard

Thank you for your interest in improving Soroban Upgrade Safeguard. This guide explains how the project is laid out, how to set up a development environment, and what we expect from a contribution before it is merged.

## Table of Contents

1. [Ways to Contribute](#ways-to-contribute)
2. [Development Setup](#development-setup)
3. [Project Structure](#project-structure)
4. [Building and Running](#building-and-running)
5. [Testing](#testing)
6. [Test Fixtures](#test-fixtures)
7. [Coding Guidelines](#coding-guidelines)
8. [Adding a New Detection Rule](#adding-a-new-detection-rule)
9. [Commit and Pull Request Process](#commit-and-pull-request-process)
10. [Reporting Bugs](#reporting-bugs)
11. [Code of Conduct](#code-of-conduct)

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

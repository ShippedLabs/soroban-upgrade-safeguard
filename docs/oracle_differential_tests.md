# Differential Oracle Tests

## Overview

The differential oracle suite (`tests/oracle_differential.rs`) compares
safeguard's internal type-model against an independent reference decoder that
traverses raw `ScSpecTypeDef` XDR values directly.  When the two agree the test
passes silently.  A disagreement indicates a bug in either
`mapper::type_to_string` or in the oracle's reference traversal.

The suite also validates **discriminant serialization decisions**: each enum and
error-enum case carries a `u32` wire value; the oracle re-reads that field via
the reference path and flags any mismatch between the two reads.

## Architecture

```
ScSpecEntry (stellar-xdr)
        │
        ├─── safeguard model path ────► mapper::type_to_string()
        │                                        │
        └─── reference oracle path ──► oracle::reference_type_path()
                                                 │
                                      oracle::compare_type_paths()
                                           ↓ OracleDivergence? ↓
                                         (none = clean, some = bug)

ScSpecUdtEnumV0 / ScSpecUdtErrorEnumV0
        │
        ├─── safeguard discriminant ──► case.value (direct XDR field read)
        │
        └─── reference discriminant ──► re_read.value (independent re-read)
                                                 │
                                  oracle::compare_enum_discriminants()
                                      ↓ DiscriminantMismatch? ↓
                                    (none = clean, some = decode bug)
```

The oracle adapter lives in `src/oracle.rs`.  It defines:

- `OracleDivergence` — type-path disagreement between safeguard and the reference.
- `DiscriminantMismatch` — enum case value disagreement.
- `CounterexampleRecord` — captures the divergence, the seed, and toolchain metadata
  for corpus storage and deterministic reproduction.
- `OracleReport` — aggregates comparisons, divergences, discriminant mismatches,
  and counterexample records.
- `compare_type_paths(label, type_def)` — single-type comparison.
- `compare_spec(spec)` — whole-spec scan (structs, functions, unions, enums,
  error-enums).
- `compare_spec_with_seed(spec, seed)` — like `compare_spec` but records `seed`
  in each `CounterexampleRecord` for deterministic reproduction.
- `compare_enum_discriminants(name, enum_def)` — enum discriminant check.
- `compare_error_enum_discriminants(name, enum_def)` — error-enum discriminant check.
- Fixture helpers: `map_type`, `vec_type`, `option_type`, `tuple_type`,
  `udt_type`, `spec_with_field_types`, `spec_with_fn`, `spec_with_enum`,
  `spec_with_error_enum`, `spec_with_union`.

## Test Categories

| # | Category | What is verified |
|---|---|---|
| 1 | Primitive type paths | Every scalar `ScSpecTypeDef` variant renders identically |
| 2 | Container type paths | Vec, Map, Option, Result, Tuple, BytesN, UDT |
| 3 | Deeply nested containers | Multi-level nesting of containers |
| 4 | Serialization decisions | Map key appears in path, tuple order preserved, BytesN size encoded |
| 5 | Enum discriminants | `u32` case values read identically by both paths |
| 6 | Error enum discriminants | Same as 5 for error enums |
| 7 | Union payload types | Tuple case payload types agree |
| 8 | Full spec comparison | All of the above through `compare_spec_with_seed` |
| 9 | Counterexample recording | `CounterexampleRecord` populated; carries seed + toolchain metadata |
| 10 | Oracle report invariants | `is_clean`, `merge`, comparison count |
| 11 | Network-gated | Extended tests skipped unless `SAFEGUARD_ORACLE_NETWORK=1` |

## Running the Tests

### Hermetic mode (default, no network access required)

```sh
cargo test oracle_differential
```

All tests in the suite are self-contained and synthesise `ScSpecTypeDef`
values in-process.

### Extended / network mode

Set `SAFEGUARD_ORACLE_NETWORK=1` before running to enable tests that would
make network calls or invoke external toolchains.  These tests are skipped
silently otherwise.

```sh
SAFEGUARD_ORACLE_NETWORK=1 cargo test oracle_differential
```

## Reproducing a Failure

Each failing test prints its seed and the exact divergence:

```
oracle report has failures:
divergence at 'swap.opts': safeguard='...' reference='...'
[counterexample seed=corpus_token_v1] divergence at 'transfer.amount': ...
```

Re-run the same test with `-- --nocapture` to see the full output:

```sh
cargo test oracle_differential::oracle_full_corpus_fixture_clean -- --nocapture
```

## Counterexample Recording

When a divergence is detected, `compare_spec_with_seed` automatically creates a
`CounterexampleRecord` that bundles:

- The `OracleDivergence` (label, safeguard path, reference path).
- The seed string passed to `compare_spec_with_seed` (fixture name, proptest
  seed, or any other stable identifier).
- Toolchain metadata: `tool_version`, `stellar_xdr_version`, `rustc_version`.

Records can be serialized to JSON and stored as corpus fixtures under
`tests/fixtures/` so failures remain reproducible after toolchain upgrades:

```rust
// Capture a counterexample record
let record = CounterexampleRecord::from_divergence(divergence, "my_fixture_v1");
println!("{}", record.reproduction_command());
```

The reproduction command printed to stderr tells the developer exactly which
test to re-run and with which seed.

## Adding New Fixtures

1. Add a new `#[test]` in `tests/oracle_differential.rs`.
2. Use the fixture helpers from `oracle::*` to build the `ScSpecTypeDef`
   values, or construct a full `ContractSpec` inline.
3. Call `compare_spec_with_seed` with a stable fixture name as the seed so
   any divergence includes the fixture name in its `CounterexampleRecord`.
4. Call `assert_oracle_clean` on the result.
5. Keep every test hermetic: no `std::fs::read`, no network calls.

Example:

```rust
#[test]
fn oracle_my_new_type_clean() {
    let spec = spec_with_field_types(vec![
        ("balance", map_type(ScSpecTypeDef::Address, ScSpecTypeDef::U64)),
    ]);
    let report = compare_spec_with_seed(&spec, "fixture_my_new_type");
    assert_oracle_clean(&report);
}
```

## CI Integration

The suite runs automatically as part of `cargo test` in the existing
[CI workflow](../.github/workflows/ci.yml) on every push and pull request
across Ubuntu, macOS, and Windows.

To run the network-gated variant in CI, set `SAFEGUARD_ORACLE_NETWORK` in the
workflow step:

```yaml
- name: Run oracle differential tests (extended)
  env:
    SAFEGUARD_ORACLE_NETWORK: "1"
  run: cargo test oracle_differential
```

This is also available via the `oracle-differential-extended` job in
[`.github/workflows/oracle-differential.yml`](../.github/workflows/oracle-differential.yml).

## Reference Decoder vs. Safeguard Model

The reference decoder in `oracle::reference_type_path` is an independent
reimplementation of `mapper::type_to_string` that works directly on the XDR
tree.  It intentionally does *not* call `type_to_string` — any shared code
would defeat the point of an independent oracle check.

If you change `mapper::type_to_string` (e.g. to add a new `ScSpecTypeDef`
variant), you must also update `oracle::reference_type_str` to match.
The `oracle_primitive_*` and container tests will catch any mismatch.

## Separating Oracle Disagreements from Compatibility Findings

Oracle disagreements (`OracleDivergence`, `DiscriminantMismatch`) are distinct
from ordinary compatibility `Finding` values:

| | `Finding` | `OracleDivergence` / `DiscriminantMismatch` |
|---|---|---|
| Origin | `diff::compare(old, new)` | `oracle::compare_type_paths` / `compare_enum_discriminants` |
| Meaning | A change between two contract versions | A disagreement between two decoders on the same input |
| Severity | Critical / Warning / Info | Always a bug |
| Suppressed? | Yes, via `.safeguard.toml` | No — fix the decoder |
| In report output? | Yes | No (test-only) |

Never suppress an oracle divergence via the suppression config — fix the
underlying decoder inconsistency instead.

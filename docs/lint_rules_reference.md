# Lint Rules Reference

`soroban-upgrade-safeguard lint` validates **one** decoded contract spec (and
its optional declared storage schema) in isolation. It answers "is this
artifact well-formed?" -- not "is it compatible with some other build?" -- so
its findings use a separate rule-ID namespace and severity scale from the
upgrade-compatibility categories documented in
[`compatibility_rules_reference.md`](./compatibility_rules_reference.md), and
are never mixed into a comparison report.

## Usage

```
soroban-upgrade-safeguard lint <WASM> [--storage-schema SCHEMA] [--format text|markdown|json] [--explain] [--strict]
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean, or only warning/info findings without `--strict`. |
| `2` | At least one error-severity finding: the artifact is structurally invalid. |
| `3` | Only warning/info findings, but `--strict` was passed. |

## Rules

| Rule ID | Default severity | Description |
|---|---|---|
| `duplicate-declaration` | Error | Same name declared more than once for the same entry kind. Only the first is kept; the rest are silently dropped by the decoder. |
| `cross-kind-name-collision` | Error | Same name declared for more than one entry kind (e.g. both a struct and an enum named `Token`). |
| `duplicate-case-name` | Warning | Two cases of the same enum/union/error-enum share a name. |
| `conflicting-discriminant` | Error | Two cases of the same enum/error-enum share a discriminant value, making wire decoding ambiguous. |
| `dangling-type-reference` | Error | A field, case, or function signature references a UDT name that is not declared anywhere in the spec. |
| `unreachable-declaration` | Info | A struct/enum/union is declared but never reachable from any exported function's inputs/outputs. (Error enums are exempt -- see note below.) |
| `unanalyzable-recursive-shape` | Warning | A type nests containers (`Vec`/`Map`/`Option`/`Result`/`Tuple`) deeper than the configured `--max-walk-depth`, so it cannot be safely analyzed. |
| `inconsistent-origin` | Info | The same name is declared with different `lib` origin metadata across kinds, so its true source library is ambiguous. |
| `storage-schema-invalid` | Error | The optional `--storage-schema` file is structurally invalid (see [`storage-inference.md`](./storage-inference.md)). |
| `storage-schema-mismatch` | Warning | The declared storage schema disagrees with storage evidence inferred from the WASM body. |

### Why error enums are exempt from `unreachable-declaration`

`contractspecv0` records the *shape* of a function's error type via the
generic `ScSpecTypeDef::Error` marker on `Result<_, Error>`, not a named
`Udt` reference to a specific error-enum declaration. That means an error
enum is never structurally "reachable" in the type-reference graph even when
it is genuinely the error type returned by a function, so flagging it as
unreachable would be a near-constant false positive.

## Reused analysis

Per the design goal of not duplicating existing single-artifact checks, this
module reuses:

- `ContractSpec::duplicate_declarations` for `duplicate-declaration` (same
  first-wins semantics as `ContractSpec::from_entries`).
- `LayoutMapper` (from `crate::mapper`) for the type-reference graph
  underlying `dangling-type-reference` and `unreachable-declaration`.
- `ResourcePolicy` (from `crate::limits`) for the `--max-walk-depth` bound
  behind `unanalyzable-recursive-shape`.
- `StorageSchema::validate` / `StorageSchema::reconcile` (from
  `crate::storage_schema`) for `storage-schema-invalid` and
  `storage-schema-mismatch`.

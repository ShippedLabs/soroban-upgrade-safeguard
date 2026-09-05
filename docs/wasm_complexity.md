# WASM Complexity Delta Analysis

## Overview

The complexity analyser profiles the **code section** of both WASM builds and
produces a deterministic, bounded summary of static complexity signals. The
summary is diffed between the old and new builds and can be gated with
configurable budgets.

This is **static analysis only**. It counts instructions as they appear in the
decoded bytecode; it does not execute the contract, simulate host calls, or
measure fuel consumption. A function that is called a million times at runtime
looks identical to one that is never called. Use the Soroban runtime's own
metering for cost estimation; use this tool for change-review visibility.

---

## Instruction families

Instructions are grouped into nine coarse families rather than tracked
per-opcode, keeping the output stable across compiler versions that freely
substitute equivalent sequences:

| Family | What it counts |
|---|---|
| `arithmetic` | i32/i64/f32/f64 arithmetic and bitwise operations |
| `control` | block, loop, if, else, end, br, br_if, br_table, return, unreachable, nop |
| `calls` | call, call_indirect, return_call, return_call_indirect |
| `memory` | load/store (all widths), memory.size, memory.grow, memory.copy, memory.fill, memory.init, data.drop |
| `comparison` | eq/ne/lt/gt/le/ge for all numeric types, eqz |
| `conversion` | type-conversion and reinterpret instructions |
| `reference` | ref.null, ref.is_null, ref.func, ref.eq |
| `simd` | v128 load/store/splat/const/shuffle/swizzle |
| `other` | everything else (select, drop, local.get/set/tee, global.get/set, table ops, …) |

Module-level totals also include:

- **`defined_functions`** — number of function bodies in the Code section.
  Imported functions are not counted here (they appear in the Runtime Surface
  analysis instead).
- **`total_instructions`** — sum of all instructions across all function bodies.

---

## Delta representation

For each metric the tool reports:

| Field | Description |
|---|---|
| `old` | Value in the baseline build |
| `new` | Value in the candidate build |
| `absolute` | `new − old` (negative means a decrease) |
| `pct` | `(absolute / old) × 100`, rounded to 2 decimal places. `null` when `old == 0` |

Deltas use `BTreeMap` throughout, so output order is always alphabetical by
family name — identical inputs always produce identical output regardless of
platform or tool version.

---

## Resource limits

The profiler is bounded to prevent runaway analysis on adversarial inputs:

| Limit | Value | Rationale |
|---|---|---|
| Max function bodies per module | 8 192 | Generous ceiling for real Soroban contracts |
| Max instructions per function body | 1 000 000 | Prevents stack exhaustion on pathological inputs |

When the function limit is hit the profile is marked truncated and counts cover
only the decoded functions. A malformed function body is skipped silently; the
rest of the module is still profiled.

---

## Configuring budgets

Add `[[complexity_budget]]` tables to `.safeguard.toml`. Each entry constrains
one metric and requires at least one of `limit` (absolute ceiling on the new
build's value) or `pct_limit` (maximum allowed percentage increase).

```toml
# Fail if the new build exceeds 50 000 total instructions
[[complexity_budget]]
metric = "total_instructions"
limit  = 50000

# Fail if total instructions grew by more than 20 %
[[complexity_budget]]
metric    = "total_instructions"
pct_limit = 20.0

# Both checks in one entry — both must pass
[[complexity_budget]]
metric    = "control"
limit     = 5000
pct_limit = 15.0

# Cap the number of newly-defined functions
[[complexity_budget]]
metric = "defined_functions"
limit  = 200
```

Valid metric names: `total_instructions`, `defined_functions`, and any family
label — `arithmetic`, `control`, `calls`, `memory`, `comparison`, `conversion`,
`reference`, `simd`, `other`.

### Precedence

Complexity violations **always gate `is_safe`**, independent of `--strict` and
the axis gate policy. A budget is an explicit opt-in; once configured it is
always enforced. There is no way to suppress a complexity violation with a
`[[suppress]]` entry — suppressions cover interface-compatibility findings only.

### Calibration guidance

Budget values should be calibrated against the **static counts this tool
reports**, not against expected execution cost or gas limits. Run the tool once
without a budget to capture the current baseline, then set limits at a
comfortable margin above those values.

---

## Separation from compatibility axes

The complexity profile is a separate, orthogonal signal:

- It does **not** appear in the per-axis verdict table (Storage Layout, Call
  ABI, Event & Indexer, Source Level, Runtime Surface).
- Complexity violations are reported in a dedicated section of the report
  ("WASM Complexity Delta") and in `complexity_violations` in the JSON output.
- `is_safe` is set to `false` when any budget is exceeded, regardless of
  whether all compatibility axes passed.

This separation means you can have a fully interface-compatible upgrade that
still fails the gate because its code section grew too large — which is exactly
the scenario this feature was designed to catch.

---

## Report output

### Text

```
========================================
    WASM COMPLEXITY DELTA
========================================
(Static analysis only — not an execution-cost estimate)
  defined_functions:     10 → 12 (+2, +20.00%)
  total_instructions:    4500 → 5200 (+700, +15.56%)
  Per-family instruction counts:
    arithmetic:          1200 → 1400 (+200, +16.67%)
    calls:               80 → 95 (+15, +18.75%)
    control:             600 → 680 (+80, +13.33%)
    ...
```

### Markdown

The delta is rendered as a table under `### 📊 WASM Complexity Delta` with
columns: Metric, Old, New, Δ Absolute, Δ %.

### JSON

The renderable report includes `complexity_old`, `complexity_new`,
`complexity_delta`, and `complexity_violations` fields when a budget is
configured. All fields are omitted when no budget is set.

---

## Limitations

- **Static only** — runtime call frequency, host function cost, and fuel
  consumption are not modelled.
- **Truncation** — modules exceeding the function or instruction limits produce
  partial profiles. The counts cover decoded content only.
- **Compiler variance** — two semantically equivalent builds compiled with
  different optimisation levels may show significant count differences. Budget
  values should be set with this in mind.
- **No per-function attribution in the report** — per-function breakdowns are
  captured in `complexity_old.functions` / `complexity_new.functions` in the
  JSON report but are not surfaced in text or Markdown output. This is
  intentional: the per-function data is available for tooling but not shown
  by default to keep the report readable.

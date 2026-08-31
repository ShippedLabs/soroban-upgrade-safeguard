# Real-World Corpus Findings & Issue Log

This document tracks findings, edge cases, false positives, and missed breaks surfaced by running `soroban-upgrade-safeguard` against the real-world validation corpus.

---

## Discovered Insights & Findings

### Issue #1: Alphabetical Field Ordering in Soroban SDK Struct Specs

- **Status**: Documented & Tracked
- **Discovered In**: `blend_lending_pool` upgrade pair (`blend_pool_v1` -> `blend_pool_v2`)
- **Severity**: Structural / Guidance Insight

#### Description
When adding a new field `oracle: String` to an existing struct `PoolConfig { admin: String, reserve_factor: u32 }`, the Soroban SDK macro sorts struct fields alphabetically when emitting the `contractspecv0` XDR section.

Because `'oracle'` sorts alphabetically before `'reserve_factor'` (`'o'` < `'r'`), the field positions shifted:
- `v1`: `[0: admin, 1: reserve_factor]`
- `v2`: `[0: admin, 1: oracle, 2: reserve_factor]`

This caused field position 1 to change from `u32` to `String`, resulting in a positional serialization break (`Struct Field Reordered` & `Struct Field Type Changed`).

#### Resolution / Mitigation
To append a struct field in Soroban without shifting existing positional indices, developers must ensure the new field name sorts alphabetically after all existing field names (e.g. `z_oracle` or prefixing), or provide custom storage migration logic. `soroban-upgrade-safeguard` correctly flags positional field reordering as a Critical breaking change.

---

### Issue #2: Function Parameter Deletion vs Renaming Detection

- **Status**: Verified Correct Behavior
- **Discovered In**: `soroswap_router` upgrade pair (`soroswap_router_v1` -> `soroswap_router_v2`)
- **Severity**: Critical

#### Description
Removing a parameter (`deadline`) from `swap_exact_tokens` reduced the parameter count from 5 to 4. `soroban-upgrade-safeguard` accurately identified this signature mutation and flagged a `Function Signature Changed` Critical finding, recommending a Major SemVer bump.

---

### Issue #3: Primitive Type Changes in Oracle Data Structs

- **Status**: Verified Correct Behavior
- **Discovered In**: `reflector_oracle` upgrade pair (`reflector_oracle_v1` -> `reflector_oracle_v2`)
- **Severity**: Critical

#### Description
Changing `price: i128` to `price: u128` in `PriceData` modifies the underlying byte layout and signedness representation. The analyzer correctly raised `Struct Field Type Changed` as a Critical finding.

---

## Tracking New Corpus Proposals

To submit a new real-world upgrade pair or report a false positive/missed break found in real mainnet contract upgrades, follow the instructions in [`tests/real_world_corpus/README.md`](../tests/real_world_corpus/README.md).

# Semantic Versioning & Public API Policy

This document outlines the Semantic Versioning (SemVer) policy for `soroban-upgrade-safeguard`. It defines what constitutes a breaking change, how the public API surface is verified, and the policy for retiring deprecated items.

---

## The Curated Public API Surface

Only the symbols exported at the crate root level when the `unstable` feature is **disabled** represent the stable public API of the library target:

*   **Primary Functions**: `compare_wasm_bytes`, `compare_wasm_bytes_with_options`, `compare_wasm_bytes_with_storage_schemas`, `compare_wasm_files`, `compare_wasm_files_with_options`, `compare_wasm_files_with_storage_schemas`.
*   **Structured Types**: `CompareOptions`, `SafetyReport`, `ReportedFinding`, `Finding`, `Severity`, `AnalysisScope`, `StorageScopeState`, `ResourcePolicy`, `LimitError`, `SuppressionConfig`, `SuppressionRule`, `StorageSchema`.

---

## SemVer Classification Rules

### 1. Major Version Bump (Breaking Changes)
A major version bump (e.g. `0.2.0` -> `1.0.0`) is required for any change that breaks backward compatibility for external consumers using the curated public API. 

Examples of breaking changes:
*   Renaming or deleting a public struct, enum, function, or method.
*   Modifying the return type or input parameter types of a public function.
*   Making a public struct field private (though most stable fields have already been converted to accessors).
*   Adding a new variant to a public enum that is **not** marked `#[non_exhaustive]`.

---

### 2. Minor Version Bump (Backward-Compatible Additions)
A minor version bump (e.g. `0.2.0` -> `0.3.0`) is used for adding functionality in a backward-compatible manner.

Examples:
*   Adding new public functions or methods.
*   Adding fields to a struct marked `#[non_exhaustive]`.
*   Implementing new traits for existing public types.
*   Adding new variants to an enum marked `#[non_exhaustive]`.

---

### 3. Patch Version Bump (Fixes & Internals)
A patch version bump (e.g. `0.2.0` -> `0.2.1`) is used for backward-compatible bug fixes and internal-only changes.

Examples:
*   Refactoring code inside private modules.
*   Performance optimizations.
*   Fixing bugs in finding detection or type mapping.
*   Changing internal types or private collections (e.g. switching internal maps from `HashMap` to `BTreeMap`).

---

## Storage Layout Changes & Crate Versioning

Because `soroban-upgrade-safeguard` validates smart-contract storage schemas, changes in the validation rules themselves can shift what findings are emitted:

### Storage Durability Semantics
*   **Persistent Storage Layout Shift**: Changing the type or layout of a field serialized inside a `Persistent` storage entry is structurally a breaking change. The validator reports this as a **Critical** finding.
*   **Temporary Storage Layout Shift**: Shifts in `Temporary` storage entries are analyzed similarly, but since temporary storage can be regenerated, some consumers may choose to suppress these. They are reported as **Warning** or **Critical** depending on the specific structures.
*   **Crate Versioning Impact**: If we introduce new checks that flag previously unflagged unsafe upgrades as `Critical`, it is considered a backward-compatible addition to the tool's capabilities (emits more findings), so it warrants a minor version bump (e.g., `0.2.0` -> `0.3.0`), not a major version bump, as the API remains stable.

---

## Callable Spec Interface Semantics

The validator diffs the `contractspecv0` section exported by Soroban binaries. Here is how interface shifts map to SemVer:

### Functions
*   **Removing a function**: Structurally breaking. Requires a major bump of the smart contract's own version, and is reported as a **Critical** upgrade finding.
*   **Reordering parameters**: Breaks binary compatibility for callers invoking the function by index/order. Reported as a **Critical** upgrade finding.
*   **Adding an input parameter**: Breaks existing invocations. Reported as **Critical**.

### User-Defined Types (UDTs)
*   **Adding a field to a struct**: Appending a field to an existing struct alters XDR field count for stored entries (`Struct Field Added`, `Warning`, `ChangeKind::MigrationRequiring`), while inserting a field mid-struct shifts positional layout (`Struct Field Inserted`, `Critical`, `ChangeKind::Breaking`).
*   **Modifying enum discriminants**: Modifying or removing case values changes serialization. Reported as **Critical** (`ChangeKind::Breaking`).

---

## Contract Upgrade `recommended_bump` Derivation

Beyond versioning this crate itself, `soroban-upgrade-safeguard` recommends a SemVer bump (`"patch"`, `"minor"`, or `"major"`) for every analyzed smart-contract upgrade alongside structured context (`recommended_bump_reason` and `bump_rationale`).

### 1. Change-Kind Classification (`ChangeKind`)

Recommendations are derived from each finding's structural `ChangeKind` (defined on `FindingCategory::change_kind()`), independent of display severity overrides:

| `ChangeKind` | Representative Categories | Baseline Bump | `bump_rationale.change_profile` |
| :--- | :--- | :--- | :--- |
| `cosmetic` | `Function/Struct/Enum Documentation Changed`, `Environment`, `Host Import Removed`, `Data/Element Segment Changed`, `WASM Proposal Removed`, `Build Manifest Mismatch/Stale` | `"patch"` | `"cosmetic"` |
| `additive` | `Function Added`, `Struct/Enum/Union/Error Enum Added`, `Enum/Event Enum/Union/Error Enum Case Added`, `Memory/Table/Global Added` | `"minor"` | `"additive"` |
| `migration_requiring` | `Struct Field Added`, `Parameter Renamed`, `Protocol Requirement Raised`, `Host Import Added / Signature Changed / Unknown`, `Memory/Table Limits Changed`, `Global/Start Function Removed`, `Start Function Changed`, `WASM Proposal Added` | `"minor"` | `"migration_requiring"` |
| `breaking` | Signature/parameter/return incompatibilities, struct/enum/union/event removals or layout mutations, `Cascading Layout Break`, `Protocol Environment Mismatch`, storage durability/namespace/map key-value changes, directional `call_abi` breaks, empirical decode failures | `"major"` | `"breaking"` |

When zero findings and zero `contractenvmetav0` differences exist, `change_profile` is `"identical"` and `recommended_bump` is `"patch"`. When `contractenvmetav0` differs with zero compatibility findings, `change_profile` is `"cosmetic"` (`env_metadata_changed: true`) and `recommended_bump` remains `"patch"`.

### 2. Distinguishing Additive vs Migration-Requiring Upgrades

In three-level SemVer, both purely additive upgrades (e.g. `Function Added`) and compatible-with-migration upgrades (e.g. `Struct Field Added`, or a `Struct Field Type Changed` covered by a verified `[[migration]]` declaration) recommend `"minor"`. Consumers distinguish them via `bump_rationale.change_profile` (`"additive"` vs `"migration_requiring"`) and `SafetyReport::upgrade_change_profile()`.

### 3. Suppression, Ungated Axes, and Verdict Consistency

`recommended_bump` is guaranteed never to contradict `is_safe`:

*   **Safe verdict (`is_safe: true`)**: Never recommends `"major"`.
*   **Suppressed breaking changes (`[[suppress]]`)**: Suppressing a breaking finding records human acceptance of the break for this deployment (`is_safe: true`), not byte-for-byte identity. When all breaking changes are suppressed (and no migration-requiring changes are present), `change_profile` is `"suppressed_breaking"` and `recommended_bump` is capped at `"minor"`. Suppressing cosmetic-only findings yields `"patch"`.
*   **Verified migrations (`[[migration]]`)**: A breaking finding covered by a verified migration resolves the safety gate (`is_safe: true`) and classifies the upgrade as `"migration_requiring"` (`"minor"`).
*   **Ungated compatibility axes**: An unsuppressed breaking finding on an axis disabled in `[policy]` (for example `gate_event_indexer = false`) does not fail `is_safe` and is likewise capped at `"minor"` (`"suppressed_breaking"`, recorded under `ungated_breaking_count`).

### 4. `--strict` Mode Interaction

`--strict` tightens the safety gate so `Warning` findings fail the run (`is_safe: false`), without changing the structural nature of the upgrade. A warning-only upgrade under `--strict` sets `is_safe: false`, `bump_rationale.strict_gate_failed: true`, and keeps `recommended_bump: "minor"`.

### 5. Batch Mode Rollup

In batch mode (`--manifest` or directory comparison), per-pair profiles roll up via `rollup_batch_bumps` by taking the maximum `UpgradeChangeProfile` across all pairs. Any pair that fails analysis (`BatchResult::Error`) forces the batch recommendation conservatively to `"major"` alongside `is_safe: false`.

---

## Automated Verification (CI Check)

To prevent accidental breaking changes, the crate enforces an automated snapshot test:

1.  **Public API Snapshot**: The file `tests/snapshots/public-api.txt` contains a text representation of the current public API.
2.  **Test Execution**: In CI, `cargo test --test public_api` builds the crate's documentation and asserts that it matches this snapshot file.
3.  **Updating Snapshots**: If you intentionally modify the public API:
    *   Regenerate the snapshot locally: `UPDATE_SNAPSHOTS=yes cargo test --test public_api`.
    *   Add a version note under `docs/api-changes/` (e.g. `docs/api-changes/0.2.0-accessors.md`) or update `docs/version_note.md` explaining the rationale for the change.
4.  **CI Validation**: The script `scripts/check_api_changes.py` runs in CI to verify that if the snapshot was changed, an accompanying version note change exists. If not, the build fails.

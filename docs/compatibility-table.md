# Release Compatibility Table

This page records, for every published release of `soroban-upgrade-safeguard`,
the minimum supported Rust toolchain, the Soroban / Stellar XDR version used for
protocol metadata, and the report schema version the release writes. Use it when
deciding which release to pin, when debugging a schema mismatch, or when
preparing a release that changes any of these dimensions.

## Table of Contents

1. [Compatibility matrix](#compatibility-matrix)
2. [Column definitions](#column-definitions)
3. [Rust toolchain notes](#rust-toolchain-notes)
4. [Soroban protocol metadata notes](#soroban-protocol-metadata-notes)
5. [Report schema notes](#report-schema-notes)
6. [Keeping this table current](#keeping-this-table-current)

---

## Compatibility matrix

| Tool version | Min Rust (MSRV) | `stellar-xdr` crate | Soroban protocol env | Report schema version | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `0.1.0` | 1.85 | 21.2.0 | `curr` (protocol 21) | 1 | Initial release |
| `0.2.0` _(planned)_ | 1.85 | 21.2.0 | `curr` (protocol 21) | 1 | Library API curation; stable public surface; `unstable` feature flag |

> **How to read the planned rows.** Rows marked _planned_ describe changes
> that are committed in the repository and documented in
> `docs/api-changes/` but have not shipped a crate to crates.io yet. Do
> not pin a planned version in production until the crate is published.

---

## Column definitions

**Tool version** — the `version` field in `Cargo.toml` / the published crate
version on crates.io. This is what `soroban-upgrade-safeguard --version` prints
and what `provenance.tool_version` carries inside every JSON report.

**Min Rust (MSRV)** — the `rust-version` field in `Cargo.toml`. This is the
oldest `rustc` that is guaranteed to compile the crate. CI builds and tests
against this exact version on every pull request (the `msrv` job in
`.github/workflows/ci.yml`). Bumping a dependency that raises this floor bumps
the MSRV in the same pull request.

**`stellar-xdr` crate** — the version of the
[`stellar-xdr`](https://crates.io/crates/stellar-xdr) dependency in
`Cargo.toml`. This crate contains the XDR-generated types for Soroban contract
spec entries (`ScSpecEntry`, `contractspecv0`) and environment metadata
(`contractenvmetav0`). Its version number tracks the Stellar protocol release.

**Soroban protocol env** — the `stellar-xdr` feature that activates the current
XDR definitions (`curr`). `curr` corresponds to the highest protocol version
the crate was built against. The full mapping is maintained in the
`stellar-xdr` changelog; the value shown here is the human-readable protocol
version implied by the `stellar-xdr` dependency version in that row's release.

**Report schema version** — the value of `REPORT_SCHEMA_VERSION` in
`src/render.rs` at the time the release was cut. This integer is written into
every `--format json` output as `report_schema_version`. A consumer that reads
saved JSON reports must support this version, or run `upgrade-report` to
migrate older documents forward. See [Report Schema Migrations](report_migrations.md)
for the full migration path.

---

## Rust toolchain notes

The MSRV is enforced mechanically, not aspirationally. The binding constraint
at any given time is the highest `rust-version` among every dependency in
`Cargo.lock`. Run `cargo metadata --format-version 1` and look at each
package's `rust_version` field to verify the floor yourself.

CI installs the MSRV via `dtolnay/rust-toolchain` and runs `cargo build
--locked` / `cargo test --locked` against it. If you see a compile error on
a toolchain at or above the declared MSRV, that is a bug — please open an
issue with your `rustc --version` output.

The default CI workflow (`ci.yml`) builds on `ubuntu-latest`, `macos-latest`,
and `windows-latest` using `dtolnay/rust-toolchain@stable` for the regular
test matrix. The MSRV job pins the exact floor. Both must be green before a
pull request merges.

When adding or updating a dependency: check the new package's declared
`rust-version`, compare it against the table above, and bump `rust-version`
in `Cargo.toml` in the same pull request if the floor rises.

---

## Soroban protocol metadata notes

`contractenvmetav0` records the Soroban protocol interface version and SDK
version at build time. The tool reads this section from both WASM inputs and
reports differences under the `Environment` category.

`stellar-xdr` is pinned to an exact version in `Cargo.toml` (not a `^`
range). Updating this dependency to pick up a new protocol's XDR types is a
deliberate, reviewed step — not a silent transitive pull. When a new Soroban
protocol version ships:

1. Update `stellar-xdr` to the corresponding crate version.
2. Update the **Soroban protocol env** column in this table.
3. Run `cargo test` to confirm all XDR decode tests still pass.
4. Open a pull request with the crate bump and the table update together.

The capability registry (`src/capability.rs`) maps recognized host-import
`(module, name)` codes to the protocol version at which they became
available. Adding new capabilities there is independent of the `stellar-xdr`
bump but often accompanies it. See [Updating the Capability Registry](capability-registry.md).

---

## Report schema notes

`REPORT_SCHEMA_VERSION` lives in `src/render.rs`. The current value is `1`.

Schema version history:

| Schema version | First tool release | What changed |
| :--- | :--- | :--- |
| 0 (implicit) | pre-`0.1.0` | Any report with `report_schema_version` absent. Structurally identical to version 1 — the field simply did not exist yet. |
| 1 | `0.1.0` | Added `report_schema_version`. Also the first version that `upgrade-report` writes explicitly. |

A report at schema version 0 can be migrated to version 1 with no data loss:

```bash
soroban-upgrade-safeguard upgrade-report old_report.json --output upgraded.json
```

See [Report Schema Migrations](report_migrations.md) for the full migration
framework, what is preserved, and how to add a new step when the schema next
changes.

**Consumers should treat `report_schema_version` as follows:**

- If the field is absent, treat the document as schema version 0 and run
  `upgrade-report` before processing.
- If the field is present and equal to the supported version, process normally.
- If the field is present and higher than the supported version, reject the
  document — do not guess at the new shape. Use a newer build of the tool, or
  ask the producer to downgrade the report.
- New _optional_ fields may be added to any schema version in a backward-
  compatible way. Consumers must ignore unknown fields to remain forward-
  compatible.

For the full compatibility contract for JSON consumers — stable fields,
additive fields, deprecated fields, enum values, and rule IDs — see
[Report Schema Compatibility Policy](report_schema_compatibility.md).

---

## Keeping this table current

Whenever a release changes the tool version, MSRV, `stellar-xdr` version, or
`REPORT_SCHEMA_VERSION`, **update this table in the same pull request** as the
source change. The table is a documentation artifact, not generated code, so
it can drift if updates are deferred.

### Quick update checklist

- [ ] Bump the tool version row (or add a new row) in the
  [compatibility matrix](#compatibility-matrix).
- [ ] If `rust-version` in `Cargo.toml` changed, update the **Min Rust** cell.
- [ ] If `stellar-xdr` in `Cargo.toml` changed, update the **`stellar-xdr` crate**
  and **Soroban protocol env** cells.
- [ ] If `REPORT_SCHEMA_VERSION` in `src/render.rs` changed, update the
  **Report schema version** cell and add a row to the
  [schema version history](#report-schema-notes) table.
- [ ] Move any _planned_ row to a confirmed row once the crate is published to
  crates.io.

### CI check

The `test` job in `.github/workflows/ci.yml` runs `cargo test`, which
includes a test that reads the current `Cargo.toml` version,
`REPORT_SCHEMA_VERSION`, and the `stellar-xdr` dependency version and
asserts they are all represented in this file. If the test fails after a
version bump, update this table and re-run.

The test lives in `tests/compatibility_table.rs` and looks for the current
`CARGO_PKG_VERSION`, the `stellar-xdr` version from `Cargo.lock`, and
`REPORT_SCHEMA_VERSION` as literal strings within this file. It is
intentionally lightweight: a missing entry is a failing test, not a silent
gap.

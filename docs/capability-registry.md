# Updating the Capability Registry

`src/capability.rs` maps every recognized Soroban host import to protocol
capability metadata: the capability group it belongs to, the Stellar
protocol version at which it became available, and a short description.
`diff::compare_host_imports` uses this registry to classify host-import
changes between two contract builds and to compute the minimum protocol a
contract's recognized imports imply. See [Host Imports and Protocol
Capabilities](documentation.md#host-imports-and-protocol-capabilities) for
what the classification looks like, and
[`capability-reference.md`](capability-reference.md) for the full generated
table.

## Source of truth

The registry is generated from `soroban-env-common/env.json` in
[`stellar/rs-soroban-env`](https://github.com/stellar/rs-soroban-env), the
repository that defines the actual Soroban host function interface. That
file lists every host module (`context`, `ledger`, `crypto`, `map`, `vec`,
`int`, `buf`, `address`, `call`, `prng`, plus an internal `test` module that
is deliberately excluded — see below) and, for each function, the exact wire
codes a compiled contract uses to import it:

- `module.export` — the short module string embedded in the WASM import
  (e.g. `"l"` for `ledger`).
- `functions[].export` — the short name string embedded in the WASM import
  (e.g. `"_"`).
- `functions[].name` — the descriptive host function name (e.g.
  `put_contract_data`), used to build the registry's `capability_id` as
  `"{module.name}.{function.name}"` (e.g. `"ledger.put_contract_data"`).
- `functions[].min_supported_protocol` — present only for a function added
  after Soroban's mainnet launch. When absent, the function has been
  available since [`BASELINE_PROTOCOL`](../src/capability.rs) (protocol 20).
- `functions[].max_supported_protocol` — present only for a function that
  was removed or superseded on a specific protocol. The registry does not
  currently encode this; see [Known gaps](#known-gaps).

**Do not hand-derive these wire codes from the human-readable function
names.** They are short, sequentially assigned codes (`"0"`, `"1"`, ...,
`"a"`, `"b"`, ...) with no relationship to the function's name — verify each
entry against `env.json` directly, or better, regenerate the whole registry
mechanically (below) rather than editing entries by hand.

The `test` module (`module.export == "t"`) is host-side test scaffolding
(`protocol_gated_dummy` and similar) that real contracts never import. It is
excluded from the registry entirely; do not add it back.

## Regenerating the registry

1. Fetch the current `env.json` from the `rs-soroban-env` branch/tag you want
   to track (usually `main`, or the tag for a specific Stellar Core release):

   ```bash
   curl -sL -A "soroban-upgrade-safeguard" \
     https://raw.githubusercontent.com/stellar/rs-soroban-env/main/soroban-env-common/env.json \
     -o env.json
   ```

2. Run a small script over it to emit one `HostImportCapability { .. }`
   struct literal per function, skipping the `t` module, and mapping each
   module's `export` code to the corresponding [`CapabilityGroup`] variant.
   This is exactly the shape `REGISTRY` in `src/capability.rs` already has —
   diff the freshly generated entries against the committed ones rather than
   regenerating the whole file blindly, so an unexpected upstream change
   (a renamed function, a shifted wire code) is easy to spot in review
   instead of silently overwritten.

3. Update [`REGISTRY_VERSION`](../src/capability.rs) when the data actually
   changes (an entry added, removed, or its `min_protocol` corrected) so
   consumers caching classification results by capability id know to
   invalidate.

4. Regenerate the committed reference doc and confirm the registry's own
   tests pass:

   ```bash
   cargo test --lib capability::
   ```

   `capability::tests::generated_markdown_matches_committed_file` fails with
   the exact `cp` command to run if `docs/capability-reference.md` is out of
   sync — follow the printed instructions rather than hand-editing that
   file, the same way `docs/finding-categories.md` is kept in sync with
   `FindingCategory` (see `docs/contributing.md`).

5. Add or update a fixture exercising the new boundary (see below) and run
   the full suite: `cargo fmt --check`, `cargo clippy`, `cargo test`.

## When a new protocol ships

A new Stellar protocol version typically adds a handful of new host
functions and, occasionally, changes `max_supported_protocol` on an
existing one. Two things are worth checking specifically:

- **New capabilities**: added as new `REGISTRY` entries with the new
  protocol's number as `min_protocol`. Once added, any contract that starts
  importing one will correctly surface a `Protocol Requirement Raised`
  finding pointing at the new floor.
- **Protocol-boundary test coverage**: add a case to `tests/host_imports.rs`
  (or extend an existing one) using the new capability's real wire code, so
  the boundary is exercised with real data rather than only the previously
  committed protocol-21 case. `crossing_a_protocol_boundary_is_reported` is
  the template to copy.

## Adding a single unrecognized import by hand

If you need to classify one specific import without doing a full
regeneration (for example, while triaging an `Unknown Host Import` finding
in the wild), look up its `(module, name)` pair directly in `env.json` and
add exactly one `HostImportCapability` entry to `REGISTRY`, following the
existing formatting. Run `cargo test --lib capability::` afterward — it
checks for duplicate wire keys, duplicate capability ids, and that every
entry meets `BASELINE_PROTOCOL`, and it will regenerate
`capability-reference.md` for you (via the failure's printed `cp` command)
so the committed reference stays in sync.

## Known gaps

- **Deprecated/removed imports.** `max_supported_protocol` from upstream is
  not yet modeled. A capability that was removed on some protocol will
  still be reported as available indefinitely. If this matters for your
  use case, extend `HostImportCapability` with an optional
  `max_protocol: Option<u32>` field and thread it through
  `compare_host_imports`.
- **Provider-specific and non-Soroban imports.** Anything outside the
  Soroban host interface (a custom runtime, a test harness import, a
  future non-Stellar provider) will never appear in `env.json` and is
  always classified as an `Unknown Host Import`. That is by design — see
  the acceptance criteria in issue #326 — but it means the registry cannot
  be the single source of truth for every WASM import a contract might
  declare, only for the Soroban host interface itself.

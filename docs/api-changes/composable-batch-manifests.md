# API Change — Composable Batch Manifests

Adds the `manifest` module, which owns batch-manifest parsing, `include`
composition, and settings resolution.

## New surface

`manifest` follows the same visibility pattern as every other module: `pub mod`
under the `unstable` feature, private otherwise. It is **not** re-exported at the
crate root, so the stable API is unchanged.

```toml
soroban-upgrade-safeguard = { version = "0.2.0", default-features = false, features = ["unstable"] }
```

Under `unstable`, `soroban_upgrade_safeguard::manifest` exposes:

| Item | Purpose |
| :--- | :--- |
| `resolve(&Path, &CliSettings) -> Result<ResolvedManifest>` | Parse a manifest and everything it includes into a ready-to-run composition. |
| `cli_only_settings(&CliSettings) -> ResolvedSettings` | The same fold with no manifest, for directory-scan mode. |
| `RawManifest`, `RawDefaults`, `RawPair` | The on-disk schema. All use `deny_unknown_fields`. |
| `PolicyOverrides` | `Option<bool>` mirror of `suppression::PolicyConfig`, so a layer can override one gate without restating the rest. |
| `ResolvedManifest`, `ResolvedPair`, `ResolvedSettings`, `ResolvedPolicy`, `ResolvedLimits` | The resolved composition, every value carrying its origin. |
| `Sourced<T>`, `Origin` | Provenance: `BuiltIn`, `Cli`, or `File(PathBuf)`. |
| `SourcedDependency` | A `dependency::ContractDependency` plus the file that declared it. |
| `CliSettings` | The command-line layer of the precedence chain. |
| `MAX_INCLUDE_DEPTH` | The include-depth cap (8). |
| `settings_map(&ResolvedSettings)` | Flat `BTreeMap` view of resolved settings. |

## Behavior changes

These affect the CLI, not the library API, but are recorded here because they
change what an existing manifest does.

1. **Relative `old`/`new` now resolve against the manifest's directory**, not the
   process working directory. Manifests using absolute paths are unaffected.
2. **Unknown manifest fields are now a hard error.** Previously they were
   silently discarded. The one documented-but-unparsed block, `[[dependencies]]`,
   is explicitly accepted so manifests written from `src/dependency.rs`'s docs
   keep working; it is composed and reported but still not propagated.
3. **Duplicate pair names fail before any pair runs**, rather than mid-loop with
   earlier reports already written.
4. **Manifest parse failures report both parser errors** with line and column,
   replacing the previous "as either TOML or JSON" message that discarded them.

## Internal

`config::resolve_path` changed from private to `pub(crate)` so `manifest` can
share it instead of duplicating the Windows-drive handling. It is not part of the
public API under either feature configuration.

See [Batch Manifests](../batch_manifests.md) for the user-facing format.

# Environment Variables

Every environment variable the CLI reads, in one place. Each is optional —
omitting it keeps the compiled-in default — and every one of them is
overridden by its corresponding CLI flag when both are set. This page is a
quick index; follow the links for the full precedence rules and behavior of
each.

| Variable | Purpose | CLI override | Default when unset |
|---|---|---|---|
| `SOROBAN_SAFEGUARD_CONFIG` | Path to the suppression config (`.safeguard.toml`) to load, for a CI system that can't rely on the current-directory auto-discovery. | `--config <PATH>` / `--no-config` | Auto-discovered `.safeguard.toml` in the current directory (see [Configuration Resolution](config-resolution.md)). |
| `SOROBAN_SAFEGUARD_METADATA_CACHE` | Directory used to cache decoded contract-spec metadata by content hash, shared across local files, `https://`, `oci://`, RPC, batch manifests, and watch mode. | `--metadata-cache-dir <DIR>` | `<OS_TEMP_DIR>/soroban-upgrade-safeguard/metadata-cache` (see [Metadata Cache](metadata_cache.md)). |
| `SOROBAN_SAFEGUARD_REMOTE_CACHE` | Directory used to cache verified `https://` input downloads by digest. | `--remote-cache-dir <DIR>` / `--no-remote-cache` / `--clear-remote-cache` | `<OS_TEMP_DIR>/soroban-upgrade-safeguard/remote-cache` (see [Remote HTTPS Inputs](remote-https-inputs.md#caching)). |
| `SOROBAN_SAFEGUARD_OCI_CACHE` | Directory used to cache verified `oci://` input layers by digest. | `--oci-cache-dir <DIR>` / `--no-oci-cache` / `--clear-oci-cache` | `<OS_TEMP_DIR>/soroban-upgrade-safeguard/oci-cache` (see [Documentation — OCI registry inputs](documentation.md#oci-registry-inputs)). |
| `NO_COLOR` | Disables colored output when set to any non-empty value, regardless of `--color`'s default. Standard cross-tool convention (see [no-color.org](https://no-color.org/)). | `--color <auto\|always\|never>` / `--no-color` / `--plain` | Color follows `--color auto`: on when stdout is a terminal, off otherwise. |

All four `SOROBAN_SAFEGUARD_*` cache/config variables follow the same
precedence: an explicit CLI flag wins, the environment variable is checked
next, and a directory under the OS temp dir (or, for config, the current
directory) is the last resort. `--show-config` prints which of these three
tiers produced each resolved value, labeled `cli`, `env`, or `default`.

## Relocating caches in a sandboxed or ephemeral environment

A CI runner or sandbox with a restricted or non-persistent temp directory can
redirect every cache the tool writes without touching any CLI invocation, by
setting all three cache variables once (e.g. in the job's environment or a
shared shell profile):

```bash
export SOROBAN_SAFEGUARD_METADATA_CACHE=/var/cache/safeguard/metadata
export SOROBAN_SAFEGUARD_REMOTE_CACHE=/var/cache/safeguard/remote
export SOROBAN_SAFEGUARD_OCI_CACHE=/var/cache/safeguard/oci
```

This is equivalent to passing `--metadata-cache-dir`, `--remote-cache-dir`,
and `--oci-cache-dir` on every invocation, but does not require modifying
each call site.

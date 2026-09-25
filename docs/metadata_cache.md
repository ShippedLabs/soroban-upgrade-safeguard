# Content-Addressed Metadata Cache

## Overview

Every analysis run validates the WASM binary, decodes XDR sections, builds
the contract model, canonicalizes the interface, and reconstructs dependency
graphs.  For batch and watch workflows that process the same WASM repeatedly
(e.g. a CI job that re-runs on every push, or a watch loop that fires on each
file save), this work is identical and the cost is pure overhead.

The metadata cache stores the result of that work, keyed by the content hash
of the WASM bytes and every analysis setting that affects the resulting model.
On a cache hit the decoded model is returned immediately; the WASM is not
re-parsed.

## What Is (and Is Not) Cached

**Cached** (safe to reuse across runs):

| Field | Description |
|---|---|
| `spec_entries_json` | JSON-serialized `Vec<ScSpecEntry>` from the decoder registry |
| `interface_version` | Packed `u64` from `contractenvmetav0`, if present |
| `spec_version_verified` | Whether the spec was decoded through the versioned registry |
| `interface_hash` | SHA-256 hex of the normalized spec interface |

**Never cached** (depend on a second input or current policy):

- Compatibility `Finding` values — they depend on a pair of WASMs.
- Suppression decisions — they depend on `.safeguard.toml`.
- Final safety verdicts.

## Cache Identity

Cache entries are keyed by a compound identity that covers:

1. **SHA-256 of the WASM bytes** — the primary content key.
2. **Tool version** (`CARGO_PKG_VERSION`) — ensures that a model produced by
   an older version of the tool is not reused by a newer one.
3. **Cache schema version** (`CACHE_SCHEMA_VERSION`) — bumped when the
   on-disk format changes in a backward-incompatible way.
4. **Parser-options hash** — an opaque string encoding any feature flags or
   resource policy settings that affect model construction.

A mismatch on **any** field is treated as a miss, never as an incorrect hit.

## Cache Directory

The default cache directory is resolved in this order:

1. `--metadata-cache-dir <DIR>` (explicit CLI override).
2. `$SOROBAN_SAFEGUARD_METADATA_CACHE` environment variable.
3. `$TMPDIR/soroban-upgrade-safeguard/metadata-cache/` (OS temp dir default).

All input sources share the same cache directory: local files, `https://`,
`oci://`, Soroban RPC, batch manifests, and watch mode all read from and
write to the same location, maximizing hit rates across workflows.

## CLI Flags

| Flag | Meaning |
|---|---|
| `--metadata-cache-dir <DIR>` | Override the default cache directory |
| `--no-metadata-cache` | Bypass reads and writes for this run |
| `--clear-metadata-cache` | Delete the entire cache directory and exit |
| `--metadata-cache-stats` | Print cache directory summary to stderr after the run |
| `--inspect-metadata-cache` | List all entries in the cache and exit |

### Examples

```sh
# Run with cache bypassed (always re-decode from scratch)
soroban-upgrade-safeguard old.wasm new.wasm --no-metadata-cache

# Use a project-local cache directory
soroban-upgrade-safeguard old.wasm new.wasm --metadata-cache-dir .cache/safeguard

# Print cache size and entry list after the run
soroban-upgrade-safeguard old.wasm new.wasm --metadata-cache-stats

# Inspect the cache without running an analysis
soroban-upgrade-safeguard --inspect-metadata-cache

# Use a custom directory and inspect it
soroban-upgrade-safeguard --inspect-metadata-cache \
  --metadata-cache-dir .cache/safeguard

# Delete the entire cache
soroban-upgrade-safeguard --clear-metadata-cache
```

## Correctness Guarantees

- **Atomic writes**: entries are written to a `.tmp` file then atomically
  renamed to `payload.json`, so a concurrent writer on the same key produces
  a valid entry (last write wins, no torn reads).
- **Re-verification on read**: the stored key fields are checked against the
  request key before the entry is used; a mismatch (stale schema, tool upgrade,
  corrupted hash) produces an invalidation, never a stale hit.
- **Safe degradation**: a truncated, corrupt, or JSON-invalid entry is silently
  treated as a miss; the analysis continues normally without the cache.
- **Tool upgrades**: `tool_version` and `schema_version` in the compound key
  ensure that upgrading the tool invalidates all stale entries rather than
  using them under a different schema.

## Cache Statistics

`--metadata-cache-stats` prints a one-line summary to stderr after every run:

```
metadata-cache: 3 entries in '/tmp/soroban-upgrade-safeguard/metadata-cache' (18432 bytes total)
  [schema=1  tool=0.1.0]  content=a1b2c3d4…  hash=cafebabe…  4096 bytes
  ...
```

`--inspect-metadata-cache` prints the same summary without running an analysis,
useful for auditing the cache before a batch run.

## Invalidation Scenarios

| Scenario | Result |
|---|---|
| Same WASM, same tool version | Cache hit |
| Same WASM, tool upgraded | Miss (tool_version mismatch) |
| Same WASM, schema bumped | Miss (schema_version mismatch) |
| Same WASM, different parser options | Miss (parser_options_hash mismatch) |
| Different WASM bytes | Miss (content_sha256 mismatch) |
| Corrupt `payload.json` | Invalidation (counted separately from miss) |
| `--no-metadata-cache` | Always miss; nothing is read or written |

## Rust API

```rust
use soroban_upgrade_safeguard::metadata_cache::{
    build_entry, clear_cache, default_cache_dir, inspect_entries, lookup, store,
    CacheIdentity, CacheKey, CacheStats, MetadataCacheConfig,
};

// Build a key for a given WASM
let key = CacheKey::new(sha256_hex(&wasm_bytes), CacheIdentity::default());

// Look up the cache
let mut stats = CacheStats::default();
let cache_dir = default_cache_dir();
match lookup(&cache_dir, &key, /*no_cache=*/ false, &mut stats) {
    CacheLookup::Hit(entry) => { /* use entry */ }
    CacheLookup::Miss | CacheLookup::Invalidated => {
        // parse wasm, then store result
        let entry = build_entry(&key, spec_json, version, verified, hash);
        store(&cache_dir, &key, &entry, false);
    }
}

// Print stats
if print_stats { stats.print_summary(); }

// Inspect entries
for info in inspect_entries(&cache_dir) {
    println!("{} ({} bytes)", info.content_sha256, info.payload_bytes);
}
```

## Testing

```sh
# Run unit tests for the metadata cache module
cargo test metadata_cache

# Run the integration tests
cargo test --test metadata_cache_tests
```

## Never Cache Findings or Verdicts

A `CachedMetadata` entry must never contain:

- `Finding` values (depend on a pair of WASMs and comparison policy).
- Suppression decisions (depend on `.safeguard.toml`).
- Final `is_safe` verdicts (depend on all of the above).

These are the properties verified by
`cached_metadata_has_no_findings_field` in the unit test suite.

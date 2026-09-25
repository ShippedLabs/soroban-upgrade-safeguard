//! Content-addressed cache for parsed WASM metadata and normalized specs.
//!
//! # Purpose
//!
//! Every analysis run validates the WASM binary, decodes XDR sections, builds
//! the contract model, canonicalizes the interface, and reconstructs dependency
//! graphs.  Batch and watch workflows repeatedly perform that work for identical
//! bytes.  This module adds a cache layer that stores the result of that work
//! keyed by the content hash of the WASM bytes plus every analysis setting that
//! affects the resulting model.
//!
//! # What is (and is not) cached
//!
//! **Cached** (safe to reuse across runs):
//! - Validated, decoded `ScSpecEntry` list (serialized as JSON).
//! - Decoded `ContractEnvMeta` (interface version + protocol version).
//! - The `InterfaceHash` of the normalized spec.
//! - `spec_version_verified` and `spec_interface_version` from the decoder
//!   registry pass.
//!
//! **Never cached** (depend on a second input or current policy):
//! - Compatibility `Finding` values — they depend on a pair of WASMs.
//! - Suppression decisions — they depend on `.safeguard.toml`.
//! - Final safety verdicts.
//!
//! # Cache identity
//!
//! Cache entries are keyed by a compound identity that covers:
//! - SHA-256 of the WASM bytes (the content key).
//! - Tool version string (`env!("CARGO_PKG_VERSION")`).
//! - Cache schema version (bumped when the on-disk format changes).
//! - A hash of parser options / feature flags that affect model construction.
//!
//! A mismatch on any identity field is treated as a miss, never as an error.
//!
//! # Correctness guarantees
//!
//! - Entries are written atomically via a `.tmp` rename.
//! - On read, the stored identity is re-verified before the entry is used.
//! - Truncated, corrupt, or JSON-invalid entries are silently treated as misses.
//! - The cache directory may be on a shared filesystem; each entry lives in a
//!   separate subdirectory named by the full compound key hash to avoid races.
//!
//! # CLI surface
//!
//! | Flag | Meaning |
//! |---|---|
//! | `--no-metadata-cache` | Bypass reads and writes for this run |
//! | `--clear-metadata-cache` | Delete the entire cache directory |
//! | `--metadata-cache-dir <path>` | Override the default cache directory |
//! | `--metadata-cache-stats` | Print hit/miss/invalidation counts to stderr |
//!
//! The default cache directory is `$TMPDIR/soroban-upgrade-safeguard/metadata-cache/`
//! or the path in `SOROBAN_SAFEGUARD_METADATA_CACHE` if set.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::loader::sha256_hex;

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Current on-disk schema version.  Bump this whenever the serialized format
/// of [`CachedMetadata`] changes in a backward-incompatible way.  Any entry
/// whose stored schema version differs from this value is silently treated as
/// a cache miss rather than a deserialization error.
pub const CACHE_SCHEMA_VERSION: u32 = 1;

/// Tool version baked in at compile time.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Environment variable that overrides the default metadata cache directory.
pub const CACHE_DIR_ENV_VAR: &str = "SOROBAN_SAFEGUARD_METADATA_CACHE";

// ---------------------------------------------------------------------------
// Cache identity
// ---------------------------------------------------------------------------

/// Everything that can affect the model produced from a given WASM, excluding
/// the WASM bytes themselves (those are the content key).
///
/// Changing any field here causes entries produced under the old settings to be
/// treated as misses rather than incorrect hits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheIdentity {
    /// On-disk schema version — bumped on breaking format changes.
    pub schema_version: u32,
    /// Tool binary version (`CARGO_PKG_VERSION`).
    pub tool_version: String,
    /// Opaque string encoding the parser options / feature flags that affect
    /// model construction.  Callers set this to a stable serialization of
    /// whatever options they pass to the parser; an empty string means
    /// "default options".
    pub parser_options_hash: String,
}

impl CacheIdentity {
    /// Construct an identity with the current schema and tool versions and the
    /// given parser-options opaque string.
    pub fn new(parser_options_hash: impl Into<String>) -> Self {
        Self {
            schema_version: CACHE_SCHEMA_VERSION,
            tool_version: TOOL_VERSION.to_string(),
            parser_options_hash: parser_options_hash.into(),
        }
    }

    /// Serialize this identity to a stable JSON string for use as part of the
    /// cache key.
    pub fn to_key_string(&self) -> String {
        // Stable serialization: sort keys alphabetically (serde_json does this
        // in insertion order, so we build a sorted representation manually).
        format!(
            "parser_options_hash={}&schema_version={}&tool_version={}",
            self.parser_options_hash, self.schema_version, self.tool_version
        )
    }
}

impl Default for CacheIdentity {
    fn default() -> Self {
        Self::new("")
    }
}

// ---------------------------------------------------------------------------
// Compound cache key
// ---------------------------------------------------------------------------

/// The full compound cache key: content hash + identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    /// SHA-256 hex of the WASM bytes.
    pub content_sha256: String,
    /// The identity of the analysis settings.
    pub identity: CacheIdentity,
}

impl CacheKey {
    pub fn new(content_sha256: impl Into<String>, identity: CacheIdentity) -> Self {
        Self {
            content_sha256: content_sha256.into(),
            identity,
        }
    }

    /// Compute a stable hex key string that uniquely identifies this
    /// (content, identity) pair on disk.
    pub fn to_dir_name(&self) -> String {
        let combined = format!("{}:{}", self.content_sha256, self.identity.to_key_string());
        sha256_hex(combined.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Cached payload
// ---------------------------------------------------------------------------

/// The data stored in a single cache entry.
///
/// Only model-level data is stored here — never findings, verdicts, or
/// suppression decisions that depend on a second WASM or current policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMetadata {
    /// The compound cache key that produced this entry (stored for
    /// re-verification on read).
    pub key: CachedKey,
    /// The SHA-256 hex of the WASM bytes (redundant with `key.content_sha256`
    /// but preserved here for cheap read-side integrity checks without having
    /// to re-hash the source bytes).
    pub content_sha256: String,
    /// JSON-serialized `Vec<stellar_xdr::curr::ScSpecEntry>` as produced by
    /// the decoder registry.
    pub spec_entries_json: String,
    /// The interface version, if present in the WASM.
    pub interface_version: Option<u64>,
    /// Whether the spec was decoded through the versioned registry.
    pub spec_version_verified: bool,
    /// The SHA-256 hex of the normalized interface hash.
    pub interface_hash: String,
}

/// The key fields stored inside the entry for re-verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedKey {
    pub schema_version: u32,
    pub tool_version: String,
    pub parser_options_hash: String,
    pub content_sha256: String,
}

impl CachedKey {
    fn from_cache_key(key: &CacheKey) -> Self {
        Self {
            schema_version: key.identity.schema_version,
            tool_version: key.identity.tool_version.clone(),
            parser_options_hash: key.identity.parser_options_hash.clone(),
            content_sha256: key.content_sha256.clone(),
        }
    }

    fn matches(&self, key: &CacheKey) -> bool {
        self.schema_version == key.identity.schema_version
            && self.tool_version == key.identity.tool_version
            && self.parser_options_hash == key.identity.parser_options_hash
            && self.content_sha256 == key.content_sha256
    }
}

// ---------------------------------------------------------------------------
// Cache statistics
// ---------------------------------------------------------------------------

/// Counters accumulated during a cache session.
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
    /// Entries that were present on disk but failed validation (corrupt,
    /// truncated, wrong schema, wrong tool version, etc.).
    pub invalidations: usize,
}

impl CacheStats {
    /// Print a one-line summary to stderr.
    pub fn print_summary(&self) {
        eprintln!(
            "metadata-cache: {} hit(s), {} miss(es), {} invalidation(s)",
            self.hits, self.misses, self.invalidations
        );
    }
}

// ---------------------------------------------------------------------------
// Cache configuration
// ---------------------------------------------------------------------------

/// Configuration for the metadata cache.
#[derive(Debug, Clone)]
pub struct MetadataCacheConfig {
    /// When `true`, neither read from nor write to the cache.
    pub no_cache: bool,
    /// Override the default cache directory.
    pub cache_dir: Option<PathBuf>,
    /// When `true`, print hit/miss/invalidation counts to stderr after the run.
    pub print_stats: bool,
}

impl Default for MetadataCacheConfig {
    fn default() -> Self {
        Self {
            no_cache: false,
            cache_dir: None,
            print_stats: false,
        }
    }
}

impl MetadataCacheConfig {
    /// Resolve the cache directory: explicit override > env var > OS temp dir.
    pub fn resolved_cache_dir(&self) -> PathBuf {
        if let Some(ref dir) = self.cache_dir {
            return dir.clone();
        }
        default_cache_dir()
    }
}

/// The default metadata cache directory.
pub fn default_cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(CACHE_DIR_ENV_VAR) {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    std::env::temp_dir()
        .join("soroban-upgrade-safeguard")
        .join("metadata-cache")
}

/// Delete the entire metadata cache directory.  A no-op if it does not exist.
pub fn clear_cache(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cache read / write
// ---------------------------------------------------------------------------

fn entry_dir(cache_dir: &Path, key: &CacheKey) -> PathBuf {
    cache_dir.join(key.to_dir_name())
}

/// Attempt to read a cache entry.
///
/// Returns `None` (a miss) when:
/// - The entry directory does not exist.
/// - `payload.json` is missing, truncated, or not valid JSON.
/// - The stored key fields do not match `key` (wrong schema, tool version, or
///   content hash — i.e. a stale or tampered entry).
///
/// Never returns an `Err`; all failures are silently converted to misses so
/// that a corrupt cache does not break the analysis pipeline.
pub fn read_entry(cache_dir: &Path, key: &CacheKey) -> Option<CachedMetadata> {
    let dir = entry_dir(cache_dir, key);
    let json = std::fs::read_to_string(dir.join("payload.json")).ok()?;
    let entry: CachedMetadata = serde_json::from_str(&json).ok()?;
    // Re-verify the stored key matches the requested key.
    if !entry.key.matches(key) {
        return None;
    }
    Some(entry)
}

/// Write a cache entry atomically.
///
/// Uses a `.tmp` file + rename so concurrent writers on the same entry are
/// safe (last write wins, no torn reads).  A failure to write (read-only
/// filesystem, full disk, permission error) is silently ignored — the caller
/// already has the data in memory.
pub fn write_entry(cache_dir: &Path, key: &CacheKey, entry: &CachedMetadata) {
    let dir = entry_dir(cache_dir, key);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let json = match serde_json::to_string(entry) {
        Ok(j) => j,
        Err(_) => return,
    };
    let tmp = dir.join("payload.json.tmp");
    if std::fs::write(&tmp, &json).is_err() {
        return;
    }
    let _ = std::fs::rename(&tmp, dir.join("payload.json"));
}

// ---------------------------------------------------------------------------
// High-level cache access
// ---------------------------------------------------------------------------

/// The outcome of a cache lookup.
#[derive(Debug)]
pub enum CacheLookup {
    /// Found a valid, verified entry.
    Hit(CachedMetadata),
    /// No entry, or the entry failed validation.
    Miss,
    /// An entry existed but was invalid (corrupt / stale schema / tool
    /// version mismatch).
    Invalidated,
}

impl CacheLookup {
    pub fn is_hit(&self) -> bool {
        matches!(self, CacheLookup::Hit(_))
    }
}

/// Look up `key` in the cache and update `stats`.
///
/// `no_cache` → always returns `Miss` without reading disk.
pub fn lookup(
    cache_dir: &Path,
    key: &CacheKey,
    no_cache: bool,
    stats: &mut CacheStats,
) -> CacheLookup {
    if no_cache {
        stats.misses += 1;
        return CacheLookup::Miss;
    }

    let dir = entry_dir(cache_dir, key);
    let payload_path = dir.join("payload.json");

    if !payload_path.exists() {
        stats.misses += 1;
        return CacheLookup::Miss;
    }

    // File exists — try to read and validate it.
    match read_entry(cache_dir, key) {
        Some(entry) => {
            stats.hits += 1;
            CacheLookup::Hit(entry)
        }
        None => {
            // File was present but failed validation.
            stats.invalidations += 1;
            CacheLookup::Invalidated
        }
    }
}

/// Store `entry` in the cache unless `no_cache` is set.
pub fn store(cache_dir: &Path, key: &CacheKey, entry: &CachedMetadata, no_cache: bool) {
    if !no_cache {
        write_entry(cache_dir, key, entry);
    }
}

// ---------------------------------------------------------------------------
// Builder helper
// ---------------------------------------------------------------------------

/// Build a [`CachedMetadata`] from the raw components produced by the parser.
///
/// `spec_entries_json` should be the JSON serialization of the decoded
/// `Vec<ScSpecEntry>` (use `serde_json::to_string`).
pub fn build_entry(
    key: &CacheKey,
    spec_entries_json: String,
    interface_version: Option<u64>,
    spec_version_verified: bool,
    interface_hash: String,
) -> CachedMetadata {
    CachedMetadata {
        key: CachedKey::from_cache_key(key),
        content_sha256: key.content_sha256.clone(),
        spec_entries_json,
        interface_version,
        spec_version_verified,
        interface_hash,
    }
}

// ---------------------------------------------------------------------------
// Cache inspection
// ---------------------------------------------------------------------------

/// A summary of a single on-disk cache entry, returned by [`inspect_entries`].
#[derive(Debug, Clone)]
pub struct CacheEntryInfo {
    /// The on-disk directory name (the compound-key SHA-256 hex).
    pub dir_name: String,
    /// The tool version stored in this entry.
    pub tool_version: String,
    /// The schema version stored in this entry.
    pub schema_version: u32,
    /// The SHA-256 of the WASM bytes this entry covers.
    pub content_sha256: String,
    /// The stored interface hash.
    pub interface_hash: String,
    /// Approximate on-disk size of the payload file in bytes.
    pub payload_bytes: u64,
}

/// List all valid entries in `cache_dir` and return summary information for
/// each.  Invalid, corrupt, or unrecognized entries are silently skipped.
///
/// This is the backing function for `--metadata-cache-stats` and
/// `--inspect-metadata-cache` output.
pub fn inspect_entries(cache_dir: &Path) -> Vec<CacheEntryInfo> {
    let read_dir = match std::fs::read_dir(cache_dir) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };

    let mut entries = Vec::new();

    for dir_entry in read_dir.flatten() {
        let path = dir_entry.path();
        if !path.is_dir() {
            continue;
        }
        let payload_path = path.join("payload.json");
        let metadata = match std::fs::metadata(&payload_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let json = match std::fs::read_to_string(&payload_path) {
            Ok(j) => j,
            Err(_) => continue,
        };
        let entry: CachedMetadata = match serde_json::from_str(&json) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let dir_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        entries.push(CacheEntryInfo {
            dir_name,
            tool_version: entry.key.tool_version,
            schema_version: entry.key.schema_version,
            content_sha256: entry.content_sha256,
            interface_hash: entry.interface_hash,
            payload_bytes: metadata.len(),
        });
    }

    entries
}

/// Print a human-readable summary of all cache entries to stderr, followed
/// by an aggregate total.  Used by `--inspect-metadata-cache`.
pub fn print_cache_inspect(cache_dir: &Path) {
    let entries = inspect_entries(cache_dir);
    if entries.is_empty() {
        eprintln!(
            "metadata-cache: no entries in '{}'",
            cache_dir.display()
        );
        return;
    }
    let total_bytes: u64 = entries.iter().map(|e| e.payload_bytes).sum();
    eprintln!(
        "metadata-cache: {} entr{} in '{}' ({} bytes total)",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" },
        cache_dir.display(),
        total_bytes
    );
    for e in &entries {
        eprintln!(
            "  [schema={}  tool={}]  content={}…  hash={}…  {} bytes",
            e.schema_version,
            e.tool_version,
            &e.content_sha256[..8.min(e.content_sha256.len())],
            &e.interface_hash[..8.min(e.interface_hash.len())],
            e.payload_bytes,
        );
    }
}

// ---------------------------------------------------------------------------
// Cached-extraction helper (pipeline integration)
// ---------------------------------------------------------------------------

/// The outcome of a cache-assisted extraction.
///
/// Returned by [`extract_with_cache`] so callers can distinguish a genuine
/// cache hit from a freshly computed result.
#[derive(Debug)]
pub enum CachedExtractOutcome {
    /// The result was read from the cache.
    CacheHit(CachedMetadata),
    /// The result was freshly computed and has been written to the cache.
    Computed(CachedMetadata),
    /// The result was freshly computed but the cache was bypassed (`no_cache`).
    ComputedNocache(CachedMetadata),
}

impl CachedExtractOutcome {
    /// The metadata regardless of how it was obtained.
    pub fn metadata(&self) -> &CachedMetadata {
        match self {
            Self::CacheHit(m) | Self::Computed(m) | Self::ComputedNocache(m) => m,
        }
    }

    /// Whether the result came from the cache.
    pub fn was_cache_hit(&self) -> bool {
        matches!(self, Self::CacheHit(_))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(content: &str) -> CacheKey {
        CacheKey::new(sha256_hex(content.as_bytes()), CacheIdentity::default())
    }

    fn test_entry(key: &CacheKey) -> CachedMetadata {
        build_entry(
            key,
            "[]".to_string(),
            Some(((20u64) << 32) | 0),
            true,
            "abc123".to_string(),
        )
    }

    // ------------------------------------------------------------------
    // CacheIdentity
    // ------------------------------------------------------------------

    #[test]
    fn identity_default_uses_current_schema_and_tool_version() {
        let id = CacheIdentity::default();
        assert_eq!(id.schema_version, CACHE_SCHEMA_VERSION);
        assert_eq!(id.tool_version, TOOL_VERSION);
    }

    #[test]
    fn identity_key_string_is_deterministic() {
        let id = CacheIdentity::new("opts_hash_xyz");
        let s1 = id.to_key_string();
        let s2 = id.to_key_string();
        assert_eq!(s1, s2);
        assert!(s1.contains("opts_hash_xyz"));
        assert!(s1.contains(TOOL_VERSION));
    }

    // ------------------------------------------------------------------
    // CacheKey
    // ------------------------------------------------------------------

    #[test]
    fn cache_key_dir_name_is_deterministic() {
        let k = test_key("hello wasm");
        assert_eq!(k.to_dir_name(), k.to_dir_name());
    }

    #[test]
    fn different_content_produces_different_dir_names() {
        let k1 = test_key("wasm_a");
        let k2 = test_key("wasm_b");
        assert_ne!(k1.to_dir_name(), k2.to_dir_name());
    }

    #[test]
    fn different_identity_produces_different_dir_name() {
        let sha = sha256_hex(b"bytes");
        let k1 = CacheKey::new(sha.clone(), CacheIdentity::new("opts_a"));
        let k2 = CacheKey::new(sha, CacheIdentity::new("opts_b"));
        assert_ne!(k1.to_dir_name(), k2.to_dir_name());
    }

    // ------------------------------------------------------------------
    // Read / Write round-trip
    // ------------------------------------------------------------------

    fn temp_dir_for_test(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("safeguard-metadata-cache-test-{}-{}", suffix, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn write_then_read_round_trips() {
        let cache_dir = temp_dir_for_test("round-trip");
        let key = test_key("round_trip_wasm");
        let entry = test_entry(&key);

        write_entry(&cache_dir, &key, &entry);
        let loaded = read_entry(&cache_dir, &key).expect("entry should be readable");
        assert_eq!(loaded.content_sha256, entry.content_sha256);
        assert_eq!(loaded.interface_hash, "abc123");
        assert!(loaded.spec_version_verified);

        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn read_missing_entry_returns_none() {
        let cache_dir = temp_dir_for_test("missing");
        let key = test_key("nonexistent");
        assert!(read_entry(&cache_dir, &key).is_none());
    }

    #[test]
    fn read_corrupt_entry_returns_none() {
        let cache_dir = temp_dir_for_test("corrupt");
        let key = test_key("corrupt_wasm");
        let dir = entry_dir(&cache_dir, &key);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("payload.json"), b"not valid json at all {{{{").unwrap();
        assert!(read_entry(&cache_dir, &key).is_none());
        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn read_wrong_key_entry_returns_none() {
        let cache_dir = temp_dir_for_test("wrong-key");
        let key1 = test_key("wasm_one");
        let key2 = test_key("wasm_two");
        let entry = test_entry(&key1);
        write_entry(&cache_dir, &key1, &entry);
        // key2 has a different dir name — should be a natural miss.
        assert!(read_entry(&cache_dir, &key2).is_none());
        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn stale_schema_version_is_a_miss() {
        let cache_dir = temp_dir_for_test("stale-schema");
        let key = test_key("wasm_stale");
        let entry = test_entry(&key);

        // Write a valid entry first.
        write_entry(&cache_dir, &key, &entry);

        // Now mutate the stored payload to have schema_version = 0 (stale).
        let dir = entry_dir(&cache_dir, &key);
        let json = std::fs::read_to_string(dir.join("payload.json")).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["key"]["schema_version"] = serde_json::json!(0u32);
        std::fs::write(dir.join("payload.json"), serde_json::to_string(&v).unwrap()).unwrap();

        // Must be treated as a miss because the stored key won't match.
        assert!(read_entry(&cache_dir, &key).is_none());
        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    // ------------------------------------------------------------------
    // lookup() + store() high-level API
    // ------------------------------------------------------------------

    #[test]
    fn lookup_miss_when_no_cache_set() {
        let cache_dir = temp_dir_for_test("no-cache");
        let key = test_key("wasm_no_cache");
        let entry = test_entry(&key);
        write_entry(&cache_dir, &key, &entry);

        let mut stats = CacheStats::default();
        let result = lookup(&cache_dir, &key, /*no_cache=*/ true, &mut stats);
        assert!(!result.is_hit());
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn lookup_hit_after_store() {
        let cache_dir = temp_dir_for_test("hit-after-store");
        let key = test_key("wasm_store");
        let entry = test_entry(&key);

        let mut stats = CacheStats::default();
        // Miss first.
        let r1 = lookup(&cache_dir, &key, false, &mut stats);
        assert!(!r1.is_hit());

        // Store.
        store(&cache_dir, &key, &entry, false);

        // Hit on second lookup.
        let r2 = lookup(&cache_dir, &key, false, &mut stats);
        assert!(r2.is_hit());
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn lookup_counts_invalidation_for_corrupt_entry() {
        let cache_dir = temp_dir_for_test("invalidation");
        let key = test_key("wasm_corrupt");
        let dir = entry_dir(&cache_dir, &key);
        std::fs::create_dir_all(&dir).unwrap();
        // Write corrupt payload so the file exists but is invalid JSON.
        std::fs::write(dir.join("payload.json"), b"{{corrupt}}").unwrap();

        let mut stats = CacheStats::default();
        let result = lookup(&cache_dir, &key, false, &mut stats);
        assert!(!result.is_hit());
        assert_eq!(stats.invalidations, 1);
        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    // ------------------------------------------------------------------
    // clear_cache
    // ------------------------------------------------------------------

    #[test]
    fn clear_cache_removes_all_entries() {
        let cache_dir = temp_dir_for_test("clear");
        let key = test_key("wasm_clear");
        let entry = test_entry(&key);
        write_entry(&cache_dir, &key, &entry);
        assert!(cache_dir.exists());

        clear_cache(&cache_dir).expect("clear_cache must not fail");
        assert!(!cache_dir.exists());
    }

    #[test]
    fn clear_cache_is_noop_when_dir_absent() {
        let cache_dir = temp_dir_for_test("clear-absent");
        assert!(!cache_dir.exists());
        clear_cache(&cache_dir).expect("clear_cache on missing dir must not fail");
    }

    // ------------------------------------------------------------------
    // default_cache_dir
    // ------------------------------------------------------------------

    #[test]
    fn default_cache_dir_uses_env_var_when_set() {
        // Temporarily set the env var.
        std::env::set_var(CACHE_DIR_ENV_VAR, "/tmp/my-custom-cache");
        let dir = default_cache_dir();
        std::env::remove_var(CACHE_DIR_ENV_VAR);
        assert_eq!(dir, PathBuf::from("/tmp/my-custom-cache"));
    }

    #[test]
    fn default_cache_dir_falls_back_to_temp_dir() {
        std::env::remove_var(CACHE_DIR_ENV_VAR);
        let dir = default_cache_dir();
        assert!(dir.to_string_lossy().contains("soroban-upgrade-safeguard"));
        assert!(dir.to_string_lossy().contains("metadata-cache"));
    }

    // ------------------------------------------------------------------
    // build_entry
    // ------------------------------------------------------------------

    #[test]
    fn build_entry_stores_all_fields() {
        let key = test_key("build_entry_wasm");
        let entry = build_entry(
            &key,
            "[1,2,3]".to_string(),
            Some(0x0000001400000000), // protocol 20
            true,
            "deadbeef".to_string(),
        );
        assert_eq!(entry.spec_entries_json, "[1,2,3]");
        assert_eq!(entry.interface_version, Some(0x0000001400000000));
        assert!(entry.spec_version_verified);
        assert_eq!(entry.interface_hash, "deadbeef");
        assert_eq!(entry.content_sha256, key.content_sha256);
    }

    // ------------------------------------------------------------------
    // Never caches findings or verdicts (structural / doc test)
    // ------------------------------------------------------------------

    #[test]
    fn cached_metadata_has_no_findings_field() {
        // This is a compile-time check: CachedMetadata must not have a
        // `findings` field.  We verify it structurally by ensuring the
        // struct only contains the expected fields.
        let key = test_key("no_findings_wasm");
        let entry = test_entry(&key);
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            !json.contains("\"findings\""),
            "CachedMetadata must never serialize findings"
        );
        assert!(
            !json.contains("\"verdict\""),
            "CachedMetadata must never serialize verdicts"
        );
        assert!(
            !json.contains("\"suppression\""),
            "CachedMetadata must never serialize suppression decisions"
        );
    }

    // ------------------------------------------------------------------
    // CacheStats
    // ------------------------------------------------------------------

    #[test]
    fn stats_default_all_zero() {
        let s = CacheStats::default();
        assert_eq!(s.hits, 0);
        assert_eq!(s.misses, 0);
        assert_eq!(s.invalidations, 0);
    }
}

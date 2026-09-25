//! Integration tests for the content-addressed metadata cache.
//!
//! These tests exercise the cache end-to-end: round-trips through
//! `write_entry`/`read_entry`, the `lookup`/`store` high-level API,
//! invalidation on schema and tool version mismatch, corruption handling,
//! concurrency safety via atomic writes, and the `clear_cache` utility.

use std::path::PathBuf;

use soroban_upgrade_safeguard::metadata_cache::{
    build_entry, clear_cache, default_cache_dir, lookup, store, CacheIdentity, CacheKey,
    CacheStats, CachedMetadata, MetadataCacheConfig, CACHE_SCHEMA_VERSION, CACHE_DIR_ENV_VAR,
    TOOL_VERSION,
};
use soroban_upgrade_safeguard::loader::sha256_hex;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "safeguard-mc-integ-{}-{}",
        label,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn key_for(content: &str) -> CacheKey {
    CacheKey::new(sha256_hex(content.as_bytes()), CacheIdentity::default())
}

fn entry_for(key: &CacheKey) -> CachedMetadata {
    build_entry(
        key,
        "[]".to_string(),
        Some(((20u64) << 32) | 0),
        true,
        "cafebabe".to_string(),
    )
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_round_trip() {
    let dir = tmp_dir("round-trip");
    let key = key_for("round_trip_bytes");
    let entry = entry_for(&key);

    store(&dir, &key, &entry, false);

    let mut stats = CacheStats::default();
    let result = lookup(&dir, &key, false, &mut stats);
    assert!(result.is_hit(), "expected a cache hit after store");
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 0);

    if let soroban_upgrade_safeguard::metadata_cache::CacheLookup::Hit(loaded) = result {
        assert_eq!(loaded.interface_hash, "cafebabe");
        assert!(loaded.spec_version_verified);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Miss when nothing stored
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_miss_when_empty() {
    let dir = tmp_dir("miss-empty");
    let key = key_for("never_stored");
    let mut stats = CacheStats::default();

    let result = lookup(&dir, &key, false, &mut stats);
    assert!(!result.is_hit());
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 0);
}

// ---------------------------------------------------------------------------
// no_cache bypasses read and write
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_no_cache_flag_bypasses_read() {
    let dir = tmp_dir("no-cache-read");
    let key = key_for("no_cache_wasm");
    let entry = entry_for(&key);

    // Store normally first.
    store(&dir, &key, &entry, false);

    // Lookup with no_cache=true must still miss.
    let mut stats = CacheStats::default();
    let result = lookup(&dir, &key, true, &mut stats);
    assert!(!result.is_hit());
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn metadata_cache_no_cache_flag_bypasses_write() {
    let dir = tmp_dir("no-cache-write");
    let key = key_for("no_cache_write_wasm");
    let entry = entry_for(&key);

    // Store with no_cache=true — should not write anything.
    store(&dir, &key, &entry, true);

    let mut stats = CacheStats::default();
    let result = lookup(&dir, &key, false, &mut stats);
    // Nothing was written, so this must miss.
    assert!(!result.is_hit());

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Invalidation: corrupt payload
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_corrupt_entry_is_invalidated() {
    let dir = tmp_dir("corrupt");
    let key = key_for("corrupt_wasm");

    // Compute the entry directory path directly and write garbage.
    let entry_dir = dir.join(key.to_dir_name());
    std::fs::create_dir_all(&entry_dir).unwrap();
    std::fs::write(entry_dir.join("payload.json"), b"{{not valid json}}").unwrap();

    let mut stats = CacheStats::default();
    let result = lookup(&dir, &key, false, &mut stats);
    assert!(!result.is_hit());
    assert_eq!(stats.invalidations, 1, "corrupt entry must count as invalidation");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Invalidation: stale schema version stored in payload
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_stale_schema_version_is_miss() {
    let dir = tmp_dir("stale-schema");
    let key = key_for("stale_schema_wasm");
    let entry = entry_for(&key);

    // Write a valid entry, then corrupt the schema_version field.
    store(&dir, &key, &entry, false);
    let payload_path = dir.join(key.to_dir_name()).join("payload.json");
    let json = std::fs::read_to_string(&payload_path).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    // Set schema_version to something that doesn't match current.
    v["key"]["schema_version"] = serde_json::json!(CACHE_SCHEMA_VERSION + 99);
    std::fs::write(&payload_path, serde_json::to_string(&v).unwrap()).unwrap();

    let mut stats = CacheStats::default();
    let result = lookup(&dir, &key, false, &mut stats);
    assert!(!result.is_hit(), "stale schema version must not produce a hit");
    // Either miss or invalidation is acceptable (file exists → invalidation).
    assert!(stats.misses + stats.invalidations > 0);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Invalidation: different tool version stored in payload
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_different_tool_version_is_miss() {
    let dir = tmp_dir("tool-version");
    let key = key_for("tool_version_wasm");
    let entry = entry_for(&key);

    store(&dir, &key, &entry, false);
    let payload_path = dir.join(key.to_dir_name()).join("payload.json");
    let json = std::fs::read_to_string(&payload_path).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["key"]["tool_version"] = serde_json::json!("0.0.0-ancient");
    std::fs::write(&payload_path, serde_json::to_string(&v).unwrap()).unwrap();

    let mut stats = CacheStats::default();
    let result = lookup(&dir, &key, false, &mut stats);
    assert!(!result.is_hit(), "different tool version must not produce a hit");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Different content → different cache entries (no cross-contamination)
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_different_content_separate_entries() {
    let dir = tmp_dir("separate-entries");
    let key_a = key_for("wasm_content_a");
    let key_b = key_for("wasm_content_b");

    let mut entry_a = entry_for(&key_a);
    entry_a.interface_hash = "hash_a".to_string();
    let mut entry_b = entry_for(&key_b);
    entry_b.interface_hash = "hash_b".to_string();

    store(&dir, &key_a, &entry_a, false);
    store(&dir, &key_b, &entry_b, false);

    let mut stats = CacheStats::default();
    if let soroban_upgrade_safeguard::metadata_cache::CacheLookup::Hit(loaded_a) =
        lookup(&dir, &key_a, false, &mut stats)
    {
        assert_eq!(loaded_a.interface_hash, "hash_a");
    } else {
        panic!("key_a should hit");
    }

    if let soroban_upgrade_safeguard::metadata_cache::CacheLookup::Hit(loaded_b) =
        lookup(&dir, &key_b, false, &mut stats)
    {
        assert_eq!(loaded_b.interface_hash, "hash_b");
    } else {
        panic!("key_b should hit");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// clear_cache removes everything
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_clear_removes_all_entries() {
    let dir = tmp_dir("clear-all");
    let key = key_for("wasm_to_clear");
    let entry = entry_for(&key);

    store(&dir, &key, &entry, false);
    assert!(dir.exists(), "cache dir must exist after store");

    clear_cache(&dir).expect("clear_cache must not fail");
    assert!(!dir.exists(), "cache dir must be gone after clear");
}

#[test]
fn metadata_cache_clear_is_noop_on_missing_dir() {
    let dir = tmp_dir("clear-missing");
    assert!(!dir.exists());
    clear_cache(&dir).expect("clear_cache on missing dir must not fail");
}

// ---------------------------------------------------------------------------
// Cached payload never contains findings/verdicts
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_entry_never_contains_findings_or_verdicts() {
    let key = key_for("no_findings_check");
    let entry = entry_for(&key);
    let json = serde_json::to_string(&entry).unwrap();

    assert!(
        !json.contains("\"findings\""),
        "cache entry must not contain findings"
    );
    assert!(
        !json.contains("\"verdict\""),
        "cache entry must not contain verdicts"
    );
    assert!(
        !json.contains("\"suppression\""),
        "cache entry must not contain suppression decisions"
    );
}

// ---------------------------------------------------------------------------
// MetadataCacheConfig::resolved_cache_dir
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_config_resolves_explicit_dir() {
    let explicit = PathBuf::from("/tmp/explicit-cache-dir");
    let config = MetadataCacheConfig {
        cache_dir: Some(explicit.clone()),
        ..Default::default()
    };
    assert_eq!(config.resolved_cache_dir(), explicit);
}

// ---------------------------------------------------------------------------
// Performance: hit is faster than miss (smoke test, not timing-sensitive)
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_second_lookup_is_a_hit() {
    let dir = tmp_dir("perf-smoke");
    let key = key_for("perf_wasm_bytes");
    let entry = entry_for(&key);

    let mut stats = CacheStats::default();

    // First lookup: miss.
    let r1 = lookup(&dir, &key, false, &mut stats);
    assert!(!r1.is_hit());

    // Store.
    store(&dir, &key, &entry, false);

    // Second lookup: hit.
    let r2 = lookup(&dir, &key, false, &mut stats);
    assert!(r2.is_hit());

    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.invalidations, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// inspect_entries
// ---------------------------------------------------------------------------

use soroban_upgrade_safeguard::metadata_cache::{inspect_entries, CachedExtractOutcome};

#[test]
fn metadata_cache_inspect_empty_dir_returns_empty_vec() {
    let dir = tmp_dir("inspect-empty");
    // Directory does not exist yet — inspect must return empty, not panic.
    let entries = inspect_entries(&dir);
    assert!(entries.is_empty(), "inspect of missing dir must return empty vec");
}

#[test]
fn metadata_cache_inspect_returns_one_entry_after_store() {
    let dir = tmp_dir("inspect-one");
    let key = key_for("inspect_wasm");
    let entry = entry_for(&key);

    store(&dir, &key, &entry, false);

    let infos = inspect_entries(&dir);
    assert_eq!(infos.len(), 1, "expected one entry after storing one");
    let info = &infos[0];
    assert_eq!(info.content_sha256, entry.content_sha256);
    assert_eq!(info.interface_hash, entry.interface_hash);
    assert!(info.payload_bytes > 0, "payload_bytes must be non-zero");
    assert_eq!(info.schema_version, CACHE_SCHEMA_VERSION);
    assert_eq!(info.tool_version, TOOL_VERSION);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn metadata_cache_inspect_returns_multiple_entries() {
    let dir = tmp_dir("inspect-multi");
    for i in 0..3u32 {
        let key = key_for(&format!("wasm_{i}"));
        let mut entry = entry_for(&key);
        entry.interface_hash = format!("hash_{i}");
        store(&dir, &key, &entry, false);
    }

    let infos = inspect_entries(&dir);
    assert_eq!(infos.len(), 3, "expected 3 entries");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn metadata_cache_inspect_skips_corrupt_entries() {
    let dir = tmp_dir("inspect-corrupt");
    // Write a corrupt payload.
    let corrupt_dir = dir.join("aaabbbccc");
    std::fs::create_dir_all(&corrupt_dir).unwrap();
    std::fs::write(corrupt_dir.join("payload.json"), b"{{corrupt}}").unwrap();

    // Write one valid entry.
    let key = key_for("valid_wasm");
    let entry = entry_for(&key);
    store(&dir, &key, &entry, false);

    let infos = inspect_entries(&dir);
    // Only the valid entry should appear; corrupt one silently skipped.
    assert_eq!(infos.len(), 1, "corrupt entry must be skipped by inspect");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn metadata_cache_inspect_dir_name_is_nonempty() {
    let dir = tmp_dir("inspect-dirname");
    let key = key_for("dirname_wasm");
    let entry = entry_for(&key);
    store(&dir, &key, &entry, false);

    let infos = inspect_entries(&dir);
    assert_eq!(infos.len(), 1);
    assert!(!infos[0].dir_name.is_empty(), "dir_name must be non-empty");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// CachedExtractOutcome
// ---------------------------------------------------------------------------

#[test]
fn cached_extract_outcome_cache_hit_was_hit() {
    let key = key_for("outcome_hit_wasm");
    let entry = entry_for(&key);
    let outcome = CachedExtractOutcome::CacheHit(entry.clone());
    assert!(outcome.was_cache_hit());
    assert_eq!(outcome.metadata().interface_hash, entry.interface_hash);
}

#[test]
fn cached_extract_outcome_computed_was_not_hit() {
    let key = key_for("outcome_computed_wasm");
    let entry = entry_for(&key);
    let outcome = CachedExtractOutcome::Computed(entry.clone());
    assert!(!outcome.was_cache_hit());
}

#[test]
fn cached_extract_outcome_computed_nocache_was_not_hit() {
    let key = key_for("outcome_nocache_wasm");
    let entry = entry_for(&key);
    let outcome = CachedExtractOutcome::ComputedNocache(entry.clone());
    assert!(!outcome.was_cache_hit());
}

// ---------------------------------------------------------------------------
// CacheStats accumulation across multiple operations
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_stats_accumulate_correctly() {
    let dir = tmp_dir("stats-accum");
    let mut stats = CacheStats::default();

    let key_a = key_for("stats_wasm_a");
    let key_b = key_for("stats_wasm_b");
    let entry_a = entry_for(&key_a);

    // Two misses
    let _ = lookup(&dir, &key_a, false, &mut stats);
    let _ = lookup(&dir, &key_b, false, &mut stats);
    assert_eq!(stats.misses, 2);
    assert_eq!(stats.hits, 0);

    // Store key_a
    store(&dir, &key_a, &entry_a, false);

    // One hit for key_a
    let _ = lookup(&dir, &key_a, false, &mut stats);
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 2);
    assert_eq!(stats.invalidations, 0);

    // Write a corrupt entry for key_b
    let corrupt_dir = dir.join(key_b.to_dir_name());
    std::fs::create_dir_all(&corrupt_dir).unwrap();
    std::fs::write(corrupt_dir.join("payload.json"), b"{{bad}}").unwrap();

    // Invalidation for key_b
    let _ = lookup(&dir, &key_b, false, &mut stats);
    assert_eq!(stats.invalidations, 1);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Shared cache across different "input sources" (simulated by using the same
// cache dir for two separate CacheKey instances with different content hashes)
// ---------------------------------------------------------------------------

#[test]
fn metadata_cache_shared_across_input_sources() {
    // Simulate the "shared across all input sources" requirement by storing
    // entries with content hashes representing a local file, an HTTPS
    // download, and an OCI layer — all in the same cache directory.
    let dir = tmp_dir("shared-sources");

    let local_key = CacheKey::new(sha256_hex(b"local_wasm_bytes"), CacheIdentity::default());
    let https_key = CacheKey::new(sha256_hex(b"https_wasm_bytes"), CacheIdentity::default());
    let oci_key = CacheKey::new(sha256_hex(b"oci_wasm_bytes"), CacheIdentity::default());

    fn make_entry(key: &CacheKey, tag: &str) -> soroban_upgrade_safeguard::metadata_cache::CachedMetadata {
        build_entry(key, "[]".to_string(), None, false, tag.to_string())
    }

    store(&dir, &local_key, &make_entry(&local_key, "local"), false);
    store(&dir, &https_key, &make_entry(&https_key, "https"), false);
    store(&dir, &oci_key, &make_entry(&oci_key, "oci"), false);

    let infos = inspect_entries(&dir);
    assert_eq!(infos.len(), 3, "all three source entries must be in the shared cache");

    let hashes: Vec<String> = infos.iter().map(|i| i.interface_hash.clone()).collect();
    assert!(hashes.contains(&"local".to_string()));
    assert!(hashes.contains(&"https".to_string()));
    assert!(hashes.contains(&"oci".to_string()));

    let _ = std::fs::remove_dir_all(&dir);
}

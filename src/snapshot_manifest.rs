// SPDX-License-Identifier: MIT

//! Integrity manifests for empirical storage snapshots.
//!
//! [`load_empirical_entries`](crate::empirical::load_empirical_entries) accepts a
//! flat JSON array (or `{"entries": [...]}` object) of base64 XDR storage
//! entries with no provenance at all: nothing ties the entries to the
//! contract, code, network, or ledger they were sampled from, and nothing
//! detects an altered, reordered, duplicated, or mixed-ledger snapshot.
//!
//! A [`SnapshotManifest`] closes that gap. It is an optional `manifest`
//! object alongside the existing `entries` array:
//!
//! ```json
//! {
//!   "manifest": {
//!     "version": 1,
//!     "contract_id": "C...",
//!     "code_hash": "...",
//!     "network": "Test SDF Network ; September 2015",
//!     "ledger_sequence": 123456,
//!     "source": "rpc-sample",
//!     "generator": "soroban-upgrade-safeguard/0.1.0",
//!     "entry_count": 2,
//!     "entries": [
//!       { "index": 0, "durability": "persistent", "instance": true, "key_sha256": "...", "sha256": "..." },
//!       { "index": 1, "durability": "persistent", "instance": false, "key_sha256": "...", "sha256": "..." }
//!     ],
//!     "manifest_sha256": "..."
//!   },
//!   "entries": ["<base64 XDR>", "<base64 XDR>"]
//! }
//! ```
//!
//! [`verify_snapshot`] re-derives every entry's digest, checks ordering and
//! uniqueness of the manifest's declared indices, confirms every entry
//! belongs to the manifest's declared contract and carries the durability
//! the manifest says it does, and (when given an [`ExpectedContext`))
//! cross-checks the manifest's contract/code/network/ledger against values
//! already established elsewhere in the run (e.g. RPC-verified
//! provenance). A snapshot with no manifest still loads — for
//! snapshots captured before this feature existed — but is reported
//! [`SnapshotIntegrity::Unverified`] rather than
//! [`SnapshotIntegrity::Verified`].

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellar_xdr::curr::{ContractDataDurability, ContractDataEntry, Limits, ScAddress, ScVal, WriteXdr};

use crate::error::Error;

/// Current version of the snapshot-manifest format.
pub const SNAPSHOT_MANIFEST_VERSION: u32 = 1;

/// Per-entry digest recorded in a [`SnapshotManifest`], in capture order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEntryDigest {
    /// Position of this entry in the manifest's declared order, `0..entry_count`.
    pub index: usize,
    /// `"persistent"` or `"temporary"` (the entry's `ContractDataDurability`).
    pub durability: String,
    /// Whether this entry's key is the contract instance key
    /// (`ScVal::LedgerKeyContractInstance`), i.e. instance storage rather
    /// than a regular keyed data entry.
    pub instance: bool,
    /// SHA-256 of the entry key's canonical XDR encoding.
    pub key_sha256: String,
    /// SHA-256 of the full entry's canonical XDR encoding (contract, key,
    /// durability, and value), so any change to the stored value is
    /// detected even if the key is untouched.
    pub sha256: String,
}

/// A versioned integrity manifest binding a storage snapshot to the
/// contract, code, network, and ledger it was captured from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub version: u32,
    /// Strkey-encoded contract ID (`C...`) every entry must belong to.
    pub contract_id: String,
    /// Lowercase hex SHA-256 of the contract's verified WASM code.
    pub code_hash: String,
    /// Network passphrase the snapshot was captured against.
    pub network: String,
    /// Ledger sequence the entries were sampled at.
    pub ledger_sequence: u64,
    /// Free-text description of how the snapshot was captured, e.g.
    /// `"rpc-sample"`, `"core-export"`, `"manual"`.
    pub source: String,
    /// Capture time in RFC 3339, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    /// Tool/version that produced the manifest.
    pub generator: String,
    /// Schema-version assumptions the capture process made, e.g.
    /// `{"storage_schema_version": "2"}`. Free-form so capture tooling can
    /// record whatever it checked without a manifest format change.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub schema_assumptions: BTreeMap<String, String>,
    pub entry_count: usize,
    pub entries: Vec<SnapshotEntryDigest>,
    /// Self-hash of this manifest, computed over the manifest's own
    /// canonical JSON with this field blanked. Detects tampering with the
    /// manifest itself (as opposed to the entries it describes).
    pub manifest_sha256: String,
}

/// Values already established elsewhere in the run (RPC-verified
/// provenance, a `--contract-id` argument, ...) that a loaded manifest's
/// self-reported identity is cross-checked against. Any `None` field is
/// not checked.
#[derive(Debug, Clone, Default)]
pub struct ExpectedContext {
    pub contract_id: Option<String>,
    pub code_hash: Option<String>,
    pub network: Option<String>,
    pub ledger_sequence: Option<u64>,
}

/// Outcome of checking a loaded snapshot's manifest (or lack of one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotIntegrity {
    /// Every entry's digest, ordering, uniqueness, contract membership, and
    /// durability matched the manifest, and the manifest's own self-hash
    /// and (when checked) expected contract/code/network/ledger matched.
    Verified,
    /// No manifest was present. The snapshot still loads, but nothing in it
    /// is provably bound to a contract, code hash, network, or ledger.
    Unverified,
    /// A manifest was present but failed verification.
    Failed,
}

/// Snapshot coverage and integrity status, surfaced in reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIntegrityReport {
    pub integrity: SnapshotIntegrity,
    pub entries_total: usize,
    pub entries_verified: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<String>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn durability_label(d: &ContractDataDurability) -> &'static str {
    match d {
        ContractDataDurability::Temporary => "temporary",
        ContractDataDurability::Persistent => "persistent",
    }
}

fn is_instance_key(key: &ScVal) -> bool {
    matches!(key, ScVal::LedgerKeyContractInstance)
}

fn contract_id_strkey(address: &ScAddress) -> Result<String, Error> {
    match address {
        ScAddress::Contract(hash) => Ok(stellar_strkey::Contract(hash.0).to_string()),
        ScAddress::Account(_) => Err(Error::Integrity {
            details: "Storage entry's contract address is an account, not a contract".to_string(),
            source: None,
        }),
    }
}

fn to_xdr_bytes<T: WriteXdr>(value: &T, what: &str) -> Result<Vec<u8>, Error> {
    value.to_xdr(Limits::none()).map_err(|e| Error::XdrDecoding {
        entry_index: None,
        byte_offset: None,
        details: format!("Failed to re-encode {what} for hashing: {e}"),
        source: Some(Box::new(e)),
    })
}

/// Compute the manifest digest for a single entry at `index`.
pub fn digest_entry(index: usize, entry: &ContractDataEntry) -> Result<SnapshotEntryDigest, Error> {
    let key_bytes = to_xdr_bytes(&entry.key, "entry key")?;
    let entry_bytes = to_xdr_bytes(entry, "entry")?;
    Ok(SnapshotEntryDigest {
        index,
        durability: durability_label(&entry.durability).to_string(),
        instance: is_instance_key(&entry.key),
        key_sha256: sha256_hex(&key_bytes),
        sha256: sha256_hex(&entry_bytes),
    })
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, Error> {
    let buf = serde_json::to_vec(value).map_err(|e| Error::Integrity {
        details: format!("Failed to serialize manifest for hashing: {e}"),
        source: Some(Box::new(e)),
    })?;
    let val: serde_json::Value = serde_json::from_slice(&buf).map_err(|e| Error::Integrity {
        details: format!("Failed to canonicalize manifest JSON: {e}"),
        source: Some(Box::new(e)),
    })?;
    serde_json::to_string(&val).map_err(|e| Error::Integrity {
        details: format!("Failed to produce canonical manifest JSON: {e}"),
        source: Some(Box::new(e)),
    })
}

fn manifest_self_hash(manifest: &SnapshotManifest) -> Result<String, Error> {
    let mut blanked = manifest.clone();
    blanked.manifest_sha256 = String::new();
    let canonical = canonical_json(&blanked)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

/// Inputs supplied by whatever captured the snapshot, used by
/// [`build_manifest`] to compute the rest (per-entry digests and the
/// manifest's own self-hash).
#[derive(Debug, Clone, Default)]
pub struct ManifestInputs {
    pub contract_id: String,
    pub code_hash: String,
    pub network: String,
    pub ledger_sequence: u64,
    pub source: String,
    pub captured_at: Option<String>,
    pub generator: Option<String>,
    pub schema_assumptions: BTreeMap<String, String>,
}

/// Build a fully-populated, self-consistent [`SnapshotManifest`] for
/// `entries`, in the order given.
pub fn build_manifest(
    inputs: &ManifestInputs,
    entries: &[ContractDataEntry],
) -> Result<SnapshotManifest, Error> {
    let mut digests = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        digests.push(digest_entry(i, entry)?);
    }

    let generator = inputs
        .generator
        .clone()
        .unwrap_or_else(|| format!("soroban-upgrade-safeguard/{}", env!("CARGO_PKG_VERSION")));

    let mut manifest = SnapshotManifest {
        version: SNAPSHOT_MANIFEST_VERSION,
        contract_id: inputs.contract_id.clone(),
        code_hash: inputs.code_hash.clone(),
        network: inputs.network.clone(),
        ledger_sequence: inputs.ledger_sequence,
        source: inputs.source.clone(),
        captured_at: inputs.captured_at.clone(),
        generator,
        schema_assumptions: inputs.schema_assumptions.clone(),
        entry_count: digests.len(),
        entries: digests,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = manifest_self_hash(&manifest)?;
    Ok(manifest)
}

/// Verify a loaded snapshot's manifest (or report that it has none) against
/// the entries actually present and, where supplied, context already
/// established elsewhere in the run.
///
/// Called before empirical type-replay runs: a [`SnapshotIntegrity::Failed`]
/// result means the snapshot must be rejected outright, not merely
/// annotated, since nothing in a tampered or mixed-ledger snapshot can be
/// trusted to replay meaningfully.
pub fn verify_snapshot(
    manifest: Option<&SnapshotManifest>,
    entries: &[ContractDataEntry],
    expected: &ExpectedContext,
) -> Result<SnapshotIntegrityReport, Error> {
    let manifest = match manifest {
        None => {
            return Ok(SnapshotIntegrityReport {
                integrity: SnapshotIntegrity::Unverified,
                entries_total: entries.len(),
                entries_verified: 0,
                manifest_version: None,
                contract_id: None,
                ledger_sequence: None,
                network: None,
                issues: vec!["Snapshot has no integrity manifest".to_string()],
            });
        }
        Some(m) => m,
    };

    if manifest.version != SNAPSHOT_MANIFEST_VERSION {
        return Err(Error::Integrity {
            details: format!(
                "Unsupported snapshot manifest version {} (this build supports version {})",
                manifest.version, SNAPSHOT_MANIFEST_VERSION
            ),
            source: None,
        });
    }

    let mut issues = Vec::new();

    let recomputed_self_hash = manifest_self_hash(manifest)?;
    if recomputed_self_hash != manifest.manifest_sha256 {
        issues.push("Manifest self-hash mismatch: the manifest itself was altered".to_string());
    }

    if manifest.entry_count != manifest.entries.len() {
        issues.push(format!(
            "Manifest declares entry_count {} but lists {} entries",
            manifest.entry_count,
            manifest.entries.len()
        ));
    }
    if manifest.entries.len() != entries.len() {
        issues.push(format!(
            "Manifest describes {} entries but the snapshot contains {}",
            manifest.entries.len(),
            entries.len()
        ));
    }

    let mut seen_indices = HashSet::new();
    let mut seen_manifest_hashes = HashSet::new();
    let mut by_index: BTreeMap<usize, &SnapshotEntryDigest> = BTreeMap::new();
    for digest in &manifest.entries {
        if !seen_indices.insert(digest.index) {
            issues.push(format!("Manifest index {} is declared more than once", digest.index));
        }
        if !seen_manifest_hashes.insert(digest.sha256.clone()) {
            issues.push(format!(
                "Manifest declares the same entry digest {} more than once",
                digest.sha256
            ));
        }
        by_index.insert(digest.index, digest);
    }
    for i in 0..manifest.entries.len() {
        if !by_index.contains_key(&i) {
            issues.push(format!("Manifest is missing entry index {i} (ordering gap)"));
        }
    }

    let mut verified_count = 0;
    let mut seen_actual_hashes = HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        let actual = match digest_entry(i, entry) {
            Ok(d) => d,
            Err(e) => {
                issues.push(format!("Entry {i}: failed to hash for verification: {e}"));
                continue;
            }
        };

        if !seen_actual_hashes.insert(actual.sha256.clone()) {
            issues.push(format!(
                "Entry {i} duplicates another entry already present in the snapshot (digest {})",
                actual.sha256
            ));
            continue;
        }

        let declared = match by_index.get(&i) {
            Some(d) => *d,
            None => {
                issues.push(format!("Entry {i} is not described by the manifest"));
                continue;
            }
        };

        if declared.sha256 != actual.sha256 || declared.key_sha256 != actual.key_sha256 {
            issues.push(format!(
                "Entry {i}: digest does not match the manifest (tampered, reordered, or substituted)"
            ));
            continue;
        }
        if declared.durability != actual.durability {
            issues.push(format!(
                "Entry {i}: durability '{}' does not match the manifest's declared '{}'",
                actual.durability, declared.durability
            ));
            continue;
        }
        if declared.instance != actual.instance {
            issues.push(format!(
                "Entry {i}: instance-storage flag does not match the manifest"
            ));
            continue;
        }

        match contract_id_strkey(&entry.contract) {
            Ok(cid) if cid == manifest.contract_id => {}
            Ok(cid) => {
                issues.push(format!(
                    "Entry {i}: belongs to contract '{cid}', but the manifest declares '{}'",
                    manifest.contract_id
                ));
                continue;
            }
            Err(e) => {
                issues.push(format!("Entry {i}: {e}"));
                continue;
            }
        }

        verified_count += 1;
    }

    if let Some(expected_cid) = &expected.contract_id {
        if expected_cid != &manifest.contract_id {
            issues.push(format!(
                "Manifest contract '{}' does not match the expected contract '{}'",
                manifest.contract_id, expected_cid
            ));
        }
    }
    if let Some(expected_hash) = &expected.code_hash {
        if expected_hash != &manifest.code_hash {
            issues.push(format!(
                "Manifest code hash '{}' does not match the verified code hash '{}'",
                manifest.code_hash, expected_hash
            ));
        }
    }
    if let Some(expected_network) = &expected.network {
        if expected_network != &manifest.network {
            issues.push(format!(
                "Manifest network '{}' does not match the expected network '{}'",
                manifest.network, expected_network
            ));
        }
    }
    if let Some(expected_ledger) = expected.ledger_sequence {
        if expected_ledger != manifest.ledger_sequence {
            issues.push(format!(
                "Manifest ledger sequence {} does not match the expected ledger {}",
                manifest.ledger_sequence, expected_ledger
            ));
        }
    }

    let integrity = if issues.is_empty() {
        SnapshotIntegrity::Verified
    } else {
        SnapshotIntegrity::Failed
    };

    Ok(SnapshotIntegrityReport {
        integrity,
        entries_total: entries.len(),
        entries_verified: verified_count,
        manifest_version: Some(manifest.version),
        contract_id: Some(manifest.contract_id.clone()),
        ledger_sequence: Some(manifest.ledger_sequence),
        network: Some(manifest.network.clone()),
        issues,
    })
}

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Well-known member names a snapshot bundle directory (see
/// [`crate::bundle`]) may hold the snapshot envelope under.
pub const BUNDLE_SNAPSHOT_MEMBER: &str = "snapshot.json";
pub const BUNDLE_SNAPSHOT_MEMBER_GZ: &str = "snapshot.json.gz";

fn decompress_gzip(raw: &[u8], path: &Path) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(raw);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| Error::FileAccess {
        path: path.to_path_buf(),
        details: format!("Failed to decompress gzip-compressed snapshot: {e}"),
        source: Some(Box::new(e)),
    })?;
    Ok(out)
}

fn looks_gzipped(path: &Path, raw: &[u8]) -> bool {
    let ext_gz = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("gz"))
        .unwrap_or(false);
    ext_gz || raw.len() >= 2 && raw[0..2] == GZIP_MAGIC
}

/// Read the raw (decompressed, de-bundled) snapshot JSON bytes from `path`.
///
/// `path` may be:
/// - a plain JSON file,
/// - a gzip-compressed JSON file (`.gz`, or detected by magic bytes),
/// - or a bundle directory (see [`crate::bundle`]) whose membership is
///   verified via [`crate::bundle::verify_bundle`] before the
///   [`BUNDLE_SNAPSHOT_MEMBER`] (or its gzip-compressed form) member is read
///   from it. Bundle verification covers the *file*, not the entries
///   within it — [`verify_snapshot`] still runs on whatever manifest and
///   entries the bundled JSON contains.
pub fn read_snapshot_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    if path.is_dir() {
        let manifest = crate::bundle::verify_bundle(path).map_err(|e| Error::Integrity {
            details: format!("Bundle integrity check failed for '{}': {e}", path.display()),
            source: None,
        })?;

        let (member_name, is_gz) = if manifest.members.contains_key(BUNDLE_SNAPSHOT_MEMBER) {
            (BUNDLE_SNAPSHOT_MEMBER, false)
        } else if manifest.members.contains_key(BUNDLE_SNAPSHOT_MEMBER_GZ) {
            (BUNDLE_SNAPSHOT_MEMBER_GZ, true)
        } else {
            return Err(Error::InvalidInput {
                details: format!(
                    "Bundle '{}' does not contain a '{}' or '{}' member",
                    path.display(),
                    BUNDLE_SNAPSHOT_MEMBER,
                    BUNDLE_SNAPSHOT_MEMBER_GZ
                ),
            });
        };

        let member_path = path.join(member_name);
        let raw = std::fs::read(&member_path).map_err(|e| Error::FileAccess {
            path: member_path.clone(),
            details: format!("Failed to read bundle member: {e}"),
            source: Some(Box::new(e)),
        })?;

        return if is_gz {
            decompress_gzip(&raw, &member_path)
        } else {
            Ok(raw)
        };
    }

    let raw = std::fs::read(path).map_err(|e| Error::FileAccess {
        path: path.to_path_buf(),
        details: format!("Failed to read empirical file: {e}"),
        source: Some(Box::new(e)),
    })?;

    if looks_gzipped(path, &raw) {
        decompress_gzip(&raw, path)
    } else {
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{ExtensionPoint, Hash, ScMap, ScMapEntry};

    fn contract_address(byte: u8) -> ScAddress {
        ScAddress::Contract(Hash([byte; 32]))
    }

    fn contract_id_for(byte: u8) -> String {
        stellar_strkey::Contract([byte; 32]).to_string()
    }

    fn entry(contract_byte: u8, key: ScVal, val: ScVal, durability: ContractDataDurability) -> ContractDataEntry {
        ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: contract_address(contract_byte),
            key,
            val,
            durability,
        }
    }

    fn sample_entries() -> Vec<ContractDataEntry> {
        vec![
            entry(
                1,
                ScVal::LedgerKeyContractInstance,
                ScVal::Map(Some(ScMap(
                    vec![ScMapEntry {
                        key: ScVal::Symbol("admin".try_into().unwrap()),
                        val: ScVal::U32(1),
                    }]
                    .try_into()
                    .unwrap(),
                ))),
                ContractDataDurability::Persistent,
            ),
            entry(
                1,
                ScVal::Symbol("balance".try_into().unwrap()),
                ScVal::U64(500),
                ContractDataDurability::Persistent,
            ),
        ]
    }

    fn sample_inputs() -> ManifestInputs {
        ManifestInputs {
            contract_id: contract_id_for(1),
            code_hash: "a".repeat(64),
            network: "Test SDF Network ; September 2015".to_string(),
            ledger_sequence: 100,
            source: "rpc-sample".to_string(),
            captured_at: None,
            generator: None,
            schema_assumptions: BTreeMap::new(),
        }
    }

    #[test]
    fn valid_snapshot_is_verified() {
        let entries = sample_entries();
        let manifest = build_manifest(&sample_inputs(), &entries).unwrap();

        let report = verify_snapshot(Some(&manifest), &entries, &ExpectedContext::default()).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Verified);
        assert_eq!(report.entries_verified, entries.len());
        assert_eq!(report.entries_total, entries.len());
        assert!(report.issues.is_empty());
    }

    #[test]
    fn tampered_entry_value_is_rejected() {
        let entries = sample_entries();
        let manifest = build_manifest(&sample_inputs(), &entries).unwrap();

        let mut tampered = entries.clone();
        tampered[1].val = ScVal::U64(999_999);

        let report =
            verify_snapshot(Some(&manifest), &tampered, &ExpectedContext::default()).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Failed);
        assert!(report.entries_verified < tampered.len());
        assert!(
            report.issues.iter().any(|i| i.contains("does not match the manifest")),
            "issues: {:?}",
            report.issues
        );
    }

    #[test]
    fn tampered_manifest_self_hash_is_rejected() {
        let entries = sample_entries();
        let mut manifest = build_manifest(&sample_inputs(), &entries).unwrap();
        manifest.ledger_sequence = 999; // mutate without recomputing manifest_sha256

        let report = verify_snapshot(Some(&manifest), &entries, &ExpectedContext::default()).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Failed);
        assert!(report.issues.iter().any(|i| i.contains("self-hash mismatch")));
    }

    #[test]
    fn entry_from_the_wrong_contract_is_rejected() {
        let entries = sample_entries();
        let manifest = build_manifest(&sample_inputs(), &entries).unwrap();

        // Swap in an entry whose digest the manifest doesn't know about at
        // all, simulating an entry spliced in from a different contract's
        // (or a different ledger's) snapshot.
        let mut mixed = entries.clone();
        mixed[1] = entry(
            2,
            ScVal::Symbol("balance".try_into().unwrap()),
            ScVal::U64(500),
            ContractDataDurability::Persistent,
        );

        let report = verify_snapshot(Some(&manifest), &mixed, &ExpectedContext::default()).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Failed);
        assert!(
            report.issues.iter().any(|i| i.contains("belongs to contract") || i.contains("does not match the manifest")),
            "issues: {:?}",
            report.issues
        );
    }

    #[test]
    fn wrong_durability_entry_is_rejected() {
        let entries = sample_entries();
        let manifest = build_manifest(&sample_inputs(), &entries).unwrap();

        let mut mixed = entries.clone();
        mixed[1].durability = ContractDataDurability::Temporary;

        let report = verify_snapshot(Some(&manifest), &mixed, &ExpectedContext::default()).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Failed);
        // Changing durability changes the entry's canonical XDR encoding,
        // so it is caught as a digest mismatch rather than reaching the
        // durability-label comparison specifically — either is a correct
        // rejection of the tampered entry.
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn mixed_ledger_sequence_is_rejected_via_expected_context() {
        let entries = sample_entries();
        let manifest = build_manifest(&sample_inputs(), &entries).unwrap();

        let expected = ExpectedContext {
            ledger_sequence: Some(200), // a different ledger than the manifest declares
            ..Default::default()
        };

        let report = verify_snapshot(Some(&manifest), &entries, &expected).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Failed);
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("ledger sequence") && i.contains("does not match")));
    }

    #[test]
    fn wrong_code_hash_is_rejected_via_expected_context() {
        let entries = sample_entries();
        let manifest = build_manifest(&sample_inputs(), &entries).unwrap();

        let expected = ExpectedContext {
            code_hash: Some("b".repeat(64)),
            ..Default::default()
        };

        let report = verify_snapshot(Some(&manifest), &entries, &expected).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Failed);
        assert!(report.issues.iter().any(|i| i.contains("code hash")));
    }

    #[test]
    fn duplicate_entry_is_rejected() {
        let entries = sample_entries();
        let manifest = build_manifest(&sample_inputs(), &entries).unwrap();

        // Duplicate the second entry into a third slot, without extending
        // the manifest to describe it.
        let mut duplicated = entries.clone();
        duplicated.push(entries[1].clone());

        let report =
            verify_snapshot(Some(&manifest), &duplicated, &ExpectedContext::default()).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Failed);
        assert!(
            report.issues.iter().any(|i| i.contains("duplicates") || i.contains("not described by the manifest")),
            "issues: {:?}",
            report.issues
        );
    }

    #[test]
    fn duplicate_manifest_index_is_rejected() {
        let entries = sample_entries();
        let mut manifest = build_manifest(&sample_inputs(), &entries).unwrap();
        let mut second = manifest.entries[1].clone();
        second.index = 0; // collide with entries[0]'s index
        manifest.entries[1] = second;
        // manifest_sha256 is now stale too, but we want to isolate the
        // index-uniqueness check, so recompute it.
        manifest.manifest_sha256 = manifest_self_hash(&manifest).unwrap();

        let report = verify_snapshot(Some(&manifest), &entries, &ExpectedContext::default()).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Failed);
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("declared more than once")));
    }

    #[test]
    fn legacy_snapshot_without_manifest_is_unverified_not_failed() {
        let entries = sample_entries();

        let report = verify_snapshot(None, &entries, &ExpectedContext::default()).unwrap();

        assert_eq!(report.integrity, SnapshotIntegrity::Unverified);
        assert_eq!(report.entries_total, entries.len());
        assert_eq!(report.entries_verified, 0);
    }

    #[test]
    fn unsupported_manifest_version_is_rejected() {
        let entries = sample_entries();
        let mut manifest = build_manifest(&sample_inputs(), &entries).unwrap();
        manifest.version = SNAPSHOT_MANIFEST_VERSION + 1;

        let err = verify_snapshot(Some(&manifest), &entries, &ExpectedContext::default())
            .expect_err("unknown manifest version must be rejected");
        assert!(format!("{err}").contains("Unsupported snapshot manifest version"));
    }
}

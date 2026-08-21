//! Round-trip, tampering, redaction, compatibility, and documentation tests
//! for the RPC record/replay bundle system.
//!
//! All tests are hermetic — no network access is required or performed.

use soroban_upgrade_safeguard::rpc_bundle::{
    BundleArtifact, BundleEntry, ReplayBundle, ReplayBundleError, BUNDLE_VERSION,
};
use soroban_upgrade_safeguard::rpc_record::{replay_wasm_from_bundle, ReplayError};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Minimal valid WASM binary (magic + version, no sections).
const MINIMAL_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// Build a minimal but structurally valid JSON response for a
/// `getLedgerEntries` call returning `xdr_b64` as the single entry.
fn ledger_entries_response(xdr_b64: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "entries": [
                { "xdr": xdr_b64 }
            ],
            "latestLedger": 12345
        }
    })
}

/// Build a complete two-entry bundle that replay_wasm_from_bundle can consume.
///
/// The instance response XDR is synthetic: we encode a minimal
/// ContractInstance pointing at a dummy WASM hash, then embed the WASM bytes
/// as an artifact.
fn minimal_replay_bundle() -> ReplayBundle {
    use stellar_xdr::curr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ExtensionPoint, Hash,
        LedgerEntry, LedgerEntryData, LedgerEntryExt, Limits, ScAddress, ScContractInstance, ScVal,
        WriteXdr,
    };

    // Build a synthetic wasm hash (32 zero bytes)
    let wasm_hash = Hash([0u8; 32]);

    // Build a ContractInstance ScVal
    let instance_val = ScVal::ContractInstance(ScContractInstance {
        executable: ContractExecutable::Wasm(wasm_hash.clone()),
        storage: None,
    });

    // Wrap it in a ContractDataEntry
    let contract_bytes = [0u8; 32];
    let data_entry = ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: ScAddress::Contract(Hash(contract_bytes)),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: instance_val,
    };

    // Wrap in LedgerEntry
    let ledger_entry = LedgerEntry {
        last_modified_ledger_seq: 0,
        data: LedgerEntryData::ContractData(data_entry),
        ext: LedgerEntryExt::V0,
    };

    let xdr_b64 = ledger_entry
        .to_xdr_base64(Limits::none())
        .expect("encode instance");

    // Build a minimal code entry (WASM bytes wrapped in ContractCodeEntry)
    use stellar_xdr::curr::{BytesM, ContractCodeEntry};
    let code_entry = LedgerEntry {
        last_modified_ledger_seq: 0,
        data: LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: stellar_xdr::curr::ContractCodeEntryExt::V0,
            hash: wasm_hash,
            code: BytesM::try_from(MINIMAL_WASM.to_vec()).expect("wasm bytes"),
        }),
        ext: LedgerEntryExt::V0,
    };
    let code_xdr_b64 = code_entry
        .to_xdr_base64(Limits::none())
        .expect("encode code");

    let mut bundle = ReplayBundle::new(
        "https://soroban-testnet.stellar.org",
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        vec![],
    );
    bundle.push_entry(
        "getLedgerEntries",
        serde_json::json!({"keys": ["instance_key_b64"]}),
        ledger_entries_response(&xdr_b64),
    );
    bundle.push_entry(
        "getLedgerEntries",
        serde_json::json!({"keys": ["code_key_b64"]}),
        ledger_entries_response(&code_xdr_b64),
    );
    bundle.push_artifact("contract_wasm", MINIMAL_WASM);
    bundle
}

// ── BundleEntry tests ─────────────────────────────────────────────────────────

#[test]
fn bundle_entry_hash_roundtrip() {
    let response = serde_json::json!({"result": {"entries": []}, "id": 1});
    let entry = BundleEntry::new(0, "getLedgerEntries", serde_json::Value::Null, response);
    assert!(
        entry.verify_hash().is_ok(),
        "freshly constructed entry must pass hash verification"
    );
}

#[test]
fn bundle_entry_detects_tampered_response() {
    let response = serde_json::json!({"result": {"entries": [{"xdr": "abc"}]}, "id": 1});
    let mut entry = BundleEntry::new(0, "getLedgerEntries", serde_json::Value::Null, response);
    // Tamper: replace the stored hash with a wrong value
    entry.response_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert!(
        entry.verify_hash().is_err(),
        "tampered hash must be detected"
    );
}

// ── BundleArtifact tests ──────────────────────────────────────────────────────

#[test]
fn artifact_encode_decode_roundtrip() {
    let artifact = BundleArtifact::new("wasm", MINIMAL_WASM);
    let decoded = artifact.decode_verified().expect("decode must succeed");
    assert_eq!(decoded, MINIMAL_WASM);
}

#[test]
fn artifact_detects_tampered_bytes() {
    let mut artifact = BundleArtifact::new("wasm", MINIMAL_WASM);
    // Corrupt the Base64 payload by replacing it with different bytes
    use base64::Engine as _;
    artifact.bytes_b64 =
        base64::engine::general_purpose::STANDARD.encode(b"not the original bytes");
    assert!(
        artifact.decode_verified().is_err(),
        "corrupted artifact must fail integrity check"
    );
}

#[test]
fn artifact_detects_tampered_hash() {
    let mut artifact = BundleArtifact::new("wasm", MINIMAL_WASM);
    artifact.sha256 =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert!(
        artifact.decode_verified().is_err(),
        "wrong stored hash must fail integrity check"
    );
}

// ── ReplayBundle serialization ────────────────────────────────────────────────

#[test]
fn bundle_serializes_and_deserializes_cleanly() {
    let bundle = minimal_replay_bundle();
    let json = bundle.to_json().expect("serialize");
    let loaded = ReplayBundle::from_json(&json).expect("deserialize + validate");
    assert_eq!(loaded.version, BUNDLE_VERSION);
    assert_eq!(loaded.entries.len(), 2);
    assert_eq!(loaded.artifacts.len(), 1);
}

#[test]
fn bundle_rejects_wrong_version() {
    let mut bundle = minimal_replay_bundle();
    bundle.version = 999;
    let json = serde_json::to_string(&bundle).expect("serialize");
    match ReplayBundle::from_json(&json) {
        Err(ReplayBundleError::UnsupportedVersion { found: 999, .. }) => {}
        other => panic!("expected UnsupportedVersion, got {:?}", other),
    }
}

#[test]
fn bundle_detects_reordered_entries() {
    let mut bundle = minimal_replay_bundle();
    // Swap sequence numbers to simulate reordering
    bundle.entries[0].sequence = 1;
    bundle.entries[1].sequence = 0;
    let json = serde_json::to_string(&bundle).expect("serialize");
    match ReplayBundle::from_json(&json) {
        Err(ReplayBundleError::EntryOutOfOrder { .. }) => {}
        other => panic!("expected EntryOutOfOrder, got {:?}", other),
    }
}

#[test]
fn bundle_detects_tampered_entry() {
    let mut bundle = minimal_replay_bundle();
    // Corrupt the first entry's stored hash
    bundle.entries[0].response_hash =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let json = serde_json::to_string(&bundle).expect("serialize");
    match ReplayBundle::from_json(&json) {
        Err(ReplayBundleError::TamperedEntry(_)) => {}
        other => panic!("expected TamperedEntry, got {:?}", other),
    }
}

#[test]
fn bundle_detects_tampered_artifact() {
    let mut bundle = minimal_replay_bundle();
    bundle.artifacts[0].sha256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let json = serde_json::to_string(&bundle).expect("serialize");
    match ReplayBundle::from_json(&json) {
        Err(ReplayBundleError::TamperedArtifact(_)) => {}
        other => panic!("expected TamperedArtifact, got {:?}", other),
    }
}

// ── URL redaction ─────────────────────────────────────────────────────────────

#[test]
fn bundle_sanitized_url_strips_credentials() {
    let bundle = ReplayBundle::new(
        "https://user:secret@soroban-mainnet.example.com/rpc?api_key=abc",
        "CONTRACT",
        vec![],
    );
    assert!(
        !bundle.sanitized_url.contains("secret"),
        "credential must be stripped from sanitized URL: {}",
        bundle.sanitized_url
    );
    assert!(
        !bundle.sanitized_url.contains("api_key"),
        "query string must be stripped from sanitized URL: {}",
        bundle.sanitized_url
    );
}

#[test]
fn bundle_sanitized_url_strips_query_string_only() {
    let bundle = ReplayBundle::new(
        "https://clean.example.com/rpc?key=secret",
        "CONTRACT",
        vec![],
    );
    assert!(
        !bundle.sanitized_url.contains("secret"),
        "query secret must be stripped: {}",
        bundle.sanitized_url
    );
    assert!(
        bundle.sanitized_url.contains("clean.example.com"),
        "host must be preserved: {}",
        bundle.sanitized_url
    );
}

// ── Header name recording ─────────────────────────────────────────────────────

#[test]
fn bundle_records_header_names_not_values() {
    let bundle = ReplayBundle::new(
        "https://example.com",
        "CONTRACT",
        vec!["Authorization".to_string(), "X-Api-Key".to_string()],
    );
    let json = bundle.to_json().expect("serialize");
    assert!(
        json.contains("Authorization"),
        "header name must appear in bundle"
    );
    assert!(
        json.contains("X-Api-Key"),
        "header name must appear in bundle"
    );
    // Values were never set, so nothing sensitive can appear
}

// ── Replay engine ─────────────────────────────────────────────────────────────

#[test]
fn replay_round_trip_produces_valid_wasm_module() {
    let bundle = minimal_replay_bundle();
    let json = bundle.to_json().expect("serialize");
    let module = replay_wasm_from_bundle(&json).expect("replay must succeed");
    assert_eq!(module.bytes, MINIMAL_WASM);
    assert!(
        module.path.starts_with("replay://bundle/"),
        "replay path must be prefixed: {}",
        module.path
    );
    assert!(!module.sha256.is_empty(), "sha256 must be populated");
}

#[test]
fn replay_rejects_bundle_missing_artifact() {
    let mut bundle = minimal_replay_bundle();
    bundle.artifacts.clear();
    let json = serde_json::to_string(&bundle).expect("serialize");
    // Re-sign hashes so validation passes (entries unchanged)
    match replay_wasm_from_bundle(&json) {
        Err(ReplayError::MissingArtifact { label }) => {
            assert_eq!(label, "contract_wasm");
        }
        other => panic!("expected MissingArtifact, got {:?}", other),
    }
}

#[test]
fn replay_rejects_invalid_wasm_in_artifact() {
    let mut bundle = minimal_replay_bundle();
    // Replace the artifact with non-WASM bytes
    bundle.artifacts[0] = BundleArtifact::new("contract_wasm", b"not a wasm binary");
    let json = serde_json::to_string(&bundle).expect("serialize");
    match replay_wasm_from_bundle(&json) {
        Err(ReplayError::InvalidWasm { .. }) => {}
        other => panic!("expected InvalidWasm, got {:?}", other),
    }
}

#[test]
fn replay_detects_extra_unconsumed_entries() {
    let mut bundle = minimal_replay_bundle();
    // Add an extra entry that the replay engine will not consume
    bundle.push_entry(
        "getLedgerEntries",
        serde_json::json!({}),
        serde_json::json!({"result": {"entries": []}}),
    );
    let json = bundle.to_json().expect("serialize");
    match replay_wasm_from_bundle(&json) {
        Err(ReplayError::Bundle(ReplayBundleError::UnconsumedEntries { count: 1 })) => {}
        other => panic!("expected UnconsumedEntries(1), got {:?}", other),
    }
}

// ── Compatibility ─────────────────────────────────────────────────────────────

#[test]
fn bundle_version_constant_is_one() {
    // Guards against accidental version bumps without updating tests.
    assert_eq!(BUNDLE_VERSION, 1);
}

#[test]
fn bundle_json_contains_version_field() {
    let bundle = ReplayBundle::new("https://example.com", "C", vec![]);
    let json = bundle.to_json().expect("serialize");
    assert!(
        json.contains("\"version\""),
        "bundle JSON must include version field"
    );
    assert!(
        json.contains("\"1\"") || json.contains(": 1"),
        "version must be 1 in JSON"
    );
}

//! Record and replay transport for hermetic RPC troubleshooting.
//!
//! # Recording
//!
//! Wrap [`record_wasm_from_rpc`] around a live `fetch_wasm_from_rpc` call to
//! capture all JSON-RPC interactions into a [`ReplayBundle`]. The bundle can
//! be serialized to JSON and attached to a bug report, checked into a test
//! fixture directory, or stored for regression testing — without any secrets.
//!
//! ```no_run
//! use soroban_upgrade_safeguard::rpc_record::record_wasm_from_rpc;
//!
//! let (module, bundle) = record_wasm_from_rpc(
//!     "CABC...",
//!     "https://soroban-testnet.stellar.org",
//! )?;
//! std::fs::write("bundle.json", bundle.to_json()?)?;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! # Replay
//!
//! Load a bundle and replay it through the same decoding and analysis paths
//! used by the live loader — no network access required.
//!
//! ```no_run
//! use soroban_upgrade_safeguard::rpc_record::replay_wasm_from_bundle;
//!
//! let json = std::fs::read_to_string("bundle.json")?;
//! let module = replay_wasm_from_bundle(&json)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use std::cell::RefCell;

use stellar_xdr::curr::{
    ContractExecutable, Hash, LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyContractCode,
    LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal, WriteXdr,
};

use crate::error::Error;
use crate::loader::{sha256_hex, WasmModule};
use crate::rpc::redact_url;
use crate::rpc_bundle::{ReplayBundle, ReplayBundleError};

// ── Recording ────────────────────────────────────────────────────────────────

/// Perform a live RPC fetch of `contract_id` from `rpc_url` **and** record
/// every JSON-RPC interaction into a sanitized [`ReplayBundle`].
///
/// The returned bundle contains no secrets: authorization header values and
/// URL credentials are stripped before writing. The bundle can be serialized
/// with [`ReplayBundle::to_json`] and shared freely.
///
/// # Errors
///
/// Propagates any [`Error`] from the underlying RPC calls. The bundle is only
/// returned when the full fetch succeeds.
pub fn record_wasm_from_rpc(
    contract_id: &str,
    rpc_url: &str,
) -> Result<(WasmModule, ReplayBundle), Error> {
    let recorder = Recorder::new(rpc_url, contract_id);
    let module = fetch_wasm_recording(contract_id, rpc_url, &recorder)?;
    let mut bundle = recorder.into_bundle();
    bundle.push_artifact("contract_wasm", &module.bytes);
    Ok((module, bundle))
}

/// Internal recorder that intercepts `query_rpc` calls and stores each
/// sanitized request/response pair.
struct Recorder {
    url: String,
    contract_id: String,
    entries: RefCell<Vec<(String, serde_json::Value, serde_json::Value)>>,
}

impl Recorder {
    fn new(url: &str, contract_id: &str) -> Self {
        Self {
            url: url.to_string(),
            contract_id: contract_id.to_string(),
            entries: RefCell::new(Vec::new()),
        }
    }

    fn record(&self, method: &str, params: serde_json::Value, response: serde_json::Value) {
        self.entries
            .borrow_mut()
            .push((method.to_string(), params, response));
    }

    fn into_bundle(self) -> ReplayBundle {
        let mut bundle = ReplayBundle::new(&self.url, self.contract_id.clone(), Vec::new());
        for (method, params, response) in self.entries.into_inner() {
            bundle.push_entry(method, params, response);
        }
        bundle
    }
}

/// Execute the two-step contract fetch (instance → code) while recording every
/// JSON-RPC call into `recorder`.
fn fetch_wasm_recording(
    contract_id: &str,
    rpc_url: &str,
    recorder: &Recorder,
) -> Result<WasmModule, Error> {
    use stellar_strkey::Strkey;

    // ── Step 1: resolve contract bytes from strkey ───────────────────────────
    let strkey = Strkey::from_string(contract_id).map_err(|e| Error::InvalidInput {
        details: format!("Invalid contract ID '{}': {}", contract_id, e),
    })?;
    let contract_bytes = match strkey {
        Strkey::Contract(c) => c.0,
        _ => {
            return Err(Error::InvalidInput {
                details: format!("'{}' is not a contract ID", contract_id),
            })
        }
    };

    // ── Step 2: fetch contract instance ─────────────────────────────────────
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(contract_bytes)),
        key: ScVal::LedgerKeyContractInstance,
        durability: stellar_xdr::curr::ContractDataDurability::Persistent,
    });
    let key_b64 = instance_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| Error::XdrDecoding {
            entry_index: None,
            byte_offset: None,
            details: format!("Failed to serialize instance LedgerKey: {}", e),
            source: Some(Box::new(e)),
        })?;

    let params = serde_json::json!({ "keys": [key_b64] });
    let response = query_and_record(rpc_url, recorder, "getLedgerEntries", params.clone())?;

    // ── Step 3: extract WASM hash from instance ──────────────────────────────
    let entries = response["result"]["entries"]
        .as_array()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: redact_url(rpc_url),
            code: 0,
            message: "RPC response missing 'entries' array".to_string(),
        })?;
    if entries.is_empty() {
        return Err(Error::RpcProtocol {
            rpc_url: redact_url(rpc_url),
            code: 0,
            message: format!("Contract '{}' not found on-chain", contract_id),
        });
    }
    let xdr_b64 = entries[0]["xdr"]
        .as_str()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: redact_url(rpc_url),
            code: 0,
            message: "Instance entry missing 'xdr' field".to_string(),
        })?;
    let entry =
        LedgerEntry::from_xdr_base64(xdr_b64, Limits::none()).map_err(|e| Error::XdrDecoding {
            entry_index: Some(0),
            byte_offset: None,
            details: format!("Failed to decode instance LedgerEntry: {}", e),
            source: Some(Box::new(e)),
        })?;
    let contract_data = match entry.data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => {
            return Err(Error::RpcProtocol {
                rpc_url: redact_url(rpc_url),
                code: 0,
                message: "Unexpected ledger entry type for contract instance".to_string(),
            })
        }
    };
    let instance = match contract_data.val {
        ScVal::ContractInstance(i) => i,
        _ => {
            return Err(Error::RpcProtocol {
                rpc_url: redact_url(rpc_url),
                code: 0,
                message: "Expected ContractInstance ScVal".to_string(),
            })
        }
    };
    let wasm_hash = match instance.executable {
        ContractExecutable::Wasm(h) => h,
        ContractExecutable::StellarAsset => {
            return Err(Error::UnsupportedContract {
                contract_id: contract_id.to_string(),
                kind: "Stellar Asset".to_string(),
            })
        }
    };

    // ── Step 4: fetch WASM code ──────────────────────────────────────────────
    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: wasm_hash.clone(),
    });
    let code_key_b64 = code_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| Error::XdrDecoding {
            entry_index: None,
            byte_offset: None,
            details: format!("Failed to serialize code LedgerKey: {}", e),
            source: Some(Box::new(e)),
        })?;

    let code_params = serde_json::json!({ "keys": [code_key_b64] });
    let code_response =
        query_and_record(rpc_url, recorder, "getLedgerEntries", code_params.clone())?;

    let code_entries = code_response["result"]["entries"]
        .as_array()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: redact_url(rpc_url),
            code: 0,
            message: "Code response missing 'entries' array".to_string(),
        })?;
    if code_entries.is_empty() {
        return Err(Error::RpcProtocol {
            rpc_url: redact_url(rpc_url),
            code: 0,
            message: format!("WASM code not found for hash {}", hex::encode(wasm_hash.0)),
        });
    }
    let code_xdr_b64 = code_entries[0]["xdr"]
        .as_str()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: redact_url(rpc_url),
            code: 0,
            message: "Code entry missing 'xdr' field".to_string(),
        })?;
    let code_entry = LedgerEntry::from_xdr_base64(code_xdr_b64, Limits::none()).map_err(|e| {
        Error::XdrDecoding {
            entry_index: Some(0),
            byte_offset: None,
            details: format!("Failed to decode code LedgerEntry: {}", e),
            source: Some(Box::new(e)),
        }
    })?;
    let wasm_bytes = match code_entry.data {
        LedgerEntryData::ContractCode(code) => code.code.to_vec(),
        _ => {
            return Err(Error::RpcProtocol {
                rpc_url: redact_url(rpc_url),
                code: 0,
                message: "Unexpected ledger entry type for contract code".to_string(),
            })
        }
    };

    // ── Step 5: validate and return ──────────────────────────────────────────
    if wasm_bytes.len() < 4 || &wasm_bytes[0..4] != b"\0asm" {
        return Err(Error::Integrity {
            details: format!("Fetched WASM for '{}' has invalid magic bytes", contract_id),
            source: None,
        });
    }

    Ok(WasmModule {
        path: format!("stellar://{}", contract_id),
        sha256: sha256_hex(&wasm_bytes),
        bytes: wasm_bytes,
    })
}

/// Send a live JSON-RPC request and store the sanitized interaction.
fn query_and_record(
    rpc_url: &str,
    recorder: &Recorder,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });

    let agent = ureq::AgentBuilder::new()
        .redirect_auth_headers(ureq::RedirectAuthHeaders::Never)
        .build();

    let response: serde_json::Value = agent
        .post(rpc_url)
        .send_json(payload)
        .map_err(|e| Error::RpcTransport {
            rpc_url: redact_url(rpc_url),
            details: format!("RPC request failed ({:?})", e.kind()),
            source: None,
        })?
        .into_json()
        .map_err(|_| Error::RpcTransport {
            rpc_url: redact_url(rpc_url),
            details: "Failed to parse RPC response body".to_string(),
            source: None,
        })?;

    if let Some(err) = response.get("error") {
        let msg = err["message"].as_str().unwrap_or("Unknown RPC error");
        let code = err["code"].as_i64().unwrap_or(0);
        return Err(Error::RpcProtocol {
            rpc_url: redact_url(rpc_url),
            code,
            message: msg.to_string(),
        });
    }

    // Record the sanitized interaction (params already contain no secrets)
    recorder.record(method, params, response.clone());

    Ok(response)
}

// ── Replay ───────────────────────────────────────────────────────────────────

/// Replay a captured [`ReplayBundle`] (given as a JSON string) through the
/// same decoding and analysis paths used by the live loader.
///
/// No network access is performed. Every entry is consumed in order and the
/// WASM bytes come from the bundle's embedded artifact (verified by SHA-256).
///
/// # Errors
///
/// Returns an error if:
/// - The bundle JSON is malformed or fails integrity checks.
/// - Entries are out of order, missing, or extra.
/// - The embedded WASM artifact fails its integrity check.
pub fn replay_wasm_from_bundle(bundle_json: &str) -> Result<WasmModule, ReplayError> {
    let bundle = ReplayBundle::from_json(bundle_json).map_err(ReplayError::Bundle)?;
    replay_wasm_from_bundle_struct(&bundle)
}

/// Same as [`replay_wasm_from_bundle`] but accepts an already-parsed and
/// validated [`ReplayBundle`].
pub fn replay_wasm_from_bundle_struct(bundle: &ReplayBundle) -> Result<WasmModule, ReplayError> {
    let mut cursor = BundleCursor::new(bundle);

    // ── Entry 0: instance fetch ──────────────────────────────────────────────
    let instance_resp = cursor.next("getLedgerEntries")?;

    // Decode instance entry to extract WASM hash — same path as live loader
    let entries = instance_resp["result"]["entries"]
        .as_array()
        .ok_or_else(|| ReplayError::MalformedEntry {
            sequence: 0,
            details: "Missing 'entries' array in instance response".to_string(),
        })?;
    if entries.is_empty() {
        return Err(ReplayError::MalformedEntry {
            sequence: 0,
            details: "Empty 'entries' array in instance response".to_string(),
        });
    }
    let xdr_b64 = entries[0]["xdr"]
        .as_str()
        .ok_or_else(|| ReplayError::MalformedEntry {
            sequence: 0,
            details: "Missing 'xdr' in instance entry".to_string(),
        })?;
    let entry = LedgerEntry::from_xdr_base64(xdr_b64, Limits::none()).map_err(|e| {
        ReplayError::MalformedEntry {
            sequence: 0,
            details: format!("XDR decode failed: {}", e),
        }
    })?;
    let contract_data = match entry.data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => {
            return Err(ReplayError::MalformedEntry {
                sequence: 0,
                details: "Unexpected ledger entry type for contract instance".to_string(),
            })
        }
    };
    let instance = match contract_data.val {
        ScVal::ContractInstance(i) => i,
        _ => {
            return Err(ReplayError::MalformedEntry {
                sequence: 0,
                details: "Expected ContractInstance ScVal".to_string(),
            })
        }
    };
    let _wasm_hash = match instance.executable {
        ContractExecutable::Wasm(h) => h,
        ContractExecutable::StellarAsset => {
            return Err(ReplayError::MalformedEntry {
                sequence: 0,
                details: "Stellar Asset contracts cannot be replayed".to_string(),
            })
        }
    };

    // ── Entry 1: code fetch (response consumed for completeness) ────────────
    let _code_resp = cursor.next("getLedgerEntries")?;

    cursor.finish()?;

    // ── Extract WASM from artifact ───────────────────────────────────────────
    let artifact = bundle
        .artifact("contract_wasm")
        .ok_or(ReplayError::MissingArtifact {
            label: "contract_wasm".to_string(),
        })?;
    let wasm_bytes = artifact
        .decode_verified()
        .map_err(ReplayError::ArtifactIntegrity)?;

    if wasm_bytes.len() < 4 || &wasm_bytes[0..4] != b"\0asm" {
        return Err(ReplayError::InvalidWasm {
            details: "Replayed WASM has invalid magic bytes".to_string(),
        });
    }

    let sha = sha256_hex(&wasm_bytes);
    Ok(WasmModule {
        path: format!("replay://bundle/{}", bundle.contract_id),
        sha256: sha,
        bytes: wasm_bytes,
    })
}

/// A sequential cursor over a bundle's entries, enforcing order and detecting
/// missing or extra entries.
struct BundleCursor<'a> {
    bundle: &'a ReplayBundle,
    pos: usize,
}

impl<'a> BundleCursor<'a> {
    fn new(bundle: &'a ReplayBundle) -> Self {
        Self { bundle, pos: 0 }
    }

    /// Advance to the next entry, asserting it has the expected `method`.
    fn next(&mut self, expected_method: &str) -> Result<&serde_json::Value, ReplayError> {
        if self.pos >= self.bundle.entries.len() {
            return Err(ReplayError::Bundle(ReplayBundleError::ExhaustedEntries {
                method: expected_method.to_string(),
            }));
        }
        let entry = &self.bundle.entries[self.pos];
        if entry.method != expected_method {
            return Err(ReplayError::Bundle(ReplayBundleError::MethodMismatch {
                expected: expected_method.to_string(),
                got: entry.method.clone(),
            }));
        }
        self.pos += 1;
        Ok(&entry.response)
    }

    /// Assert that all entries have been consumed.
    fn finish(&self) -> Result<(), ReplayError> {
        let remaining = self.bundle.entries.len() - self.pos;
        if remaining > 0 {
            return Err(ReplayError::Bundle(ReplayBundleError::UnconsumedEntries {
                count: remaining,
            }));
        }
        Ok(())
    }
}

/// Errors that can occur during replay.
#[derive(Debug)]
pub enum ReplayError {
    /// The bundle itself is invalid (wrong version, bad hash, etc.).
    Bundle(ReplayBundleError),
    /// A response entry does not contain the expected fields.
    MalformedEntry { sequence: usize, details: String },
    /// The expected artifact is absent from the bundle.
    MissingArtifact { label: String },
    /// An artifact's integrity check failed.
    ArtifactIntegrity(String),
    /// The replayed WASM bytes are not a valid WASM binary.
    InvalidWasm { details: String },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bundle(e) => write!(f, "Bundle error: {}", e),
            Self::MalformedEntry { sequence, details } => {
                write!(f, "Malformed entry at sequence {}: {}", sequence, details)
            }
            Self::MissingArtifact { label } => {
                write!(f, "Required artifact '{}' is missing from bundle", label)
            }
            Self::ArtifactIntegrity(msg) => write!(f, "Artifact integrity error: {}", msg),
            Self::InvalidWasm { details } => write!(f, "Invalid WASM in bundle: {}", details),
        }
    }
}

impl std::error::Error for ReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bundle(e) => Some(e),
            _ => None,
        }
    }
}

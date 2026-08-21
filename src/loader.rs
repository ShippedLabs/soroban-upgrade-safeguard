use std::io::Read;
use std::path::{Path, PathBuf};

use ring::digest::{digest, SHA256};
use stellar_xdr::curr::{
    ContractDataEntry, ContractExecutable, ExtensionPoint, Hash, LedgerEntry, LedgerEntryData,
    LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal,
    WriteXdr,
};
use wasmparser::Parser;

use crate::error::Error;
use crate::rpc::RpcClientConfig;

/// Holds raw WASM bytes alongside the validated file path.
#[derive(Debug)]
pub struct WasmModule {
    pub path: String,
    pub bytes: Vec<u8>,
    /// Lowercase hex SHA-256 of `bytes`, computed at load time. Fingerprints the
    /// exact bytecode analyzed so a report can be tied back to the build that
    /// produced it. In RPC mode this equals the on-chain contract code hash.
    pub sha256: String,
}

/// Compute the lowercase hex SHA-256 of a byte slice.
///
/// Used to fingerprint each analyzed WASM for provenance. Kept public so
/// library callers and tests can reproduce the same identifier the report
/// displays.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(digest(&SHA256, bytes).as_ref())
}

/// Reads a WASM file from disk, validates it is a valid WASM binary,
/// and returns a `WasmModule` ready for further analysis.
pub fn load_wasm(path: &Path) -> Result<WasmModule, Error> {
    // 1. Check the file exists
    if !path.exists() {
        return Err(Error::FileAccess {
            path: path.to_path_buf(),
            details: "File not found".to_string(),
            source: None,
        });
    }

    // 2. Read all bytes into memory
    let bytes = std::fs::read(path).map_err(|e| Error::FileAccess {
        path: path.to_path_buf(),
        details: format!("Failed to read file: {}", path.display()),
        source: Some(Box::new(e)),
    })?;

    wasm_module_from_bytes(
        bytes,
        path.to_path_buf(),
        path.to_string_lossy().into_owned(),
    )
}

/// Reads a WASM binary from stdin, validates it like a file input, and labels
/// the source as `-` in diagnostics and reports.
pub fn load_wasm_from_stdin(stdin: &mut impl Read) -> Result<WasmModule, Error> {
    let mut bytes = Vec::new();
    stdin
        .read_to_end(&mut bytes)
        .map_err(|e| Error::FileAccess {
            path: PathBuf::from("-"),
            details: "Failed to read stdin".to_string(),
            source: Some(Box::new(e)),
        })?;

    wasm_module_from_bytes(bytes, PathBuf::from("-"), "-".to_string())
}

fn wasm_module_from_bytes(
    bytes: Vec<u8>,
    validation_path: PathBuf,
    display_path: String,
) -> Result<WasmModule, Error> {
    // 3. Validate the WASM magic header (0x00 0x61 0x73 0x6d)
    if bytes.len() < 4 || &bytes[0..4] != b"\0asm" {
        return Err(Error::WasmValidation {
            path: Some(validation_path),
            details: format!(
                "'{}' does not appear to be a valid WASM binary (bad magic bytes)",
                display_path
            ),
            byte_offset: None,
            source: None,
        });
    }

    // 4. Do a full structural parse to detect any deeper format errors
    validate_wasm_structure(&bytes).map_err(|e| Error::WasmValidation {
        path: Some(validation_path),
        details: format!("WASM validation failed for '{}'", display_path),
        byte_offset: None,
        source: Some(Box::new(e)),
    })?;

    Ok(WasmModule {
        path: display_path,
        sha256: sha256_hex(&bytes),
        bytes,
    })
}

/// Iterates through all WASM payloads and fails fast on any parse error.
fn validate_wasm_structure(bytes: &[u8]) -> Result<(), Error> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        let _ = payload.map_err(|e| Error::WasmValidation {
            path: None,
            details: "Malformed WASM payload encountered".to_string(),
            byte_offset: None,
            source: Some(Box::new(e)),
        })?;
    }
    Ok(())
}

/// Fetches a deployed Soroban contract's WASM bytes from Stellar RPC by contract ID.
pub fn fetch_wasm_from_rpc(contract_id: &str, rpc_url: &str) -> Result<WasmModule, Error> {
    fetch_wasm_from_rpc_inner(contract_id, rpc_url, None)
}

pub fn fetch_wasm_from_rpc_with_config(
    contract_id: &str,
    config: &RpcClientConfig,
) -> Result<WasmModule, Error> {
    fetch_wasm_from_rpc_inner(contract_id, &config.url, Some(config))
}

fn fetch_wasm_from_rpc_inner(
    contract_id: &str,
    rpc_url: &str,
    auth: Option<&RpcClientConfig>,
) -> Result<WasmModule, Error> {
    // 1. Parse contract_id using stellar_strkey
    let strkey =
        stellar_strkey::Strkey::from_string(contract_id).map_err(|e| Error::InvalidInput {
            details: format!("Invalid contract ID '{}': {}", contract_id, e),
        })?;

    let contract_bytes = match strkey {
        stellar_strkey::Strkey::Contract(c) => c.0,
        _ => {
            return Err(Error::InvalidInput {
                details: format!("Provided ID '{}' is not a valid contract ID", contract_id),
            })
        }
    };

    // 2. Build LedgerKey for contract instance
    let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(contract_bytes)),
        key: ScVal::LedgerKeyContractInstance,
        durability: stellar_xdr::curr::ContractDataDurability::Persistent,
    });

    // 3. Serialize LedgerKey to Base64
    let key_b64 = ledger_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| Error::XdrDecoding {
            entry_index: None,
            byte_offset: None,
            details: format!("Failed to serialize LedgerKey to base64: {}", e),
            source: Some(Box::new(e)),
        })?;

    // 4. Query getLedgerEntries RPC
    let response = query_rpc(
        rpc_url,
        auth,
        "getLedgerEntries",
        serde_json::json!({
            "keys": [key_b64]
        }),
    )?;

    // 5. Extract LedgerEntry XDR from response
    let entries = response["result"]["entries"]
        .as_array()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: rpc_url.to_string(),
            code: 0,
            message: "RPC response did not contain 'entries' array".to_string(),
        })?;

    if entries.is_empty() {
        return Err(Error::RpcProtocol {
            rpc_url: rpc_url.to_string(),
            code: 0,
            message: format!("Contract '{}' not found on-chain", contract_id),
        });
    }

    let entry_xdr_b64 = entries[0]["xdr"]
        .as_str()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: rpc_url.to_string(),
            code: 0,
            message: "RPC response entry missing 'xdr' field".to_string(),
        })?;

    // 6. Deserialize LedgerEntry
    let entry = LedgerEntry::from_xdr_base64(entry_xdr_b64, Limits::none()).map_err(|e| {
        Error::XdrDecoding {
            entry_index: Some(0),
            byte_offset: None,
            details: format!("Failed to deserialize LedgerEntry XDR: {}", e),
            source: Some(Box::new(e)),
        }
    })?;

    // 7. Get ContractInstance val
    let contract_data = match entry.data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => {
            return Err(Error::RpcProtocol {
                rpc_url: rpc_url.to_string(),
                code: 0,
                message: "Unexpected ledger entry type returned for contract instance".to_string(),
            })
        }
    };

    let instance = match contract_data.val {
        ScVal::ContractInstance(inst) => inst,
        _ => {
            return Err(Error::RpcProtocol {
                rpc_url: rpc_url.to_string(),
                code: 0,
                message: "Expected ScVal::ContractInstance in contract data".to_string(),
            })
        }
    };

    // 8. Extract WASM hash from instance executable
    let wasm_hash = match instance.executable {
        ContractExecutable::Wasm(hash) => hash,
        ContractExecutable::StellarAsset => {
            return Err(Error::UnsupportedContract {
                contract_id: contract_id.to_string(),
                kind: "Stellar Asset".to_string(),
            })
        }
    };

    // 9. Fetch WASM code using WASM hash
    let code_ledger_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: wasm_hash.clone(),
    });

    let code_key_b64 =
        code_ledger_key
            .to_xdr_base64(Limits::none())
            .map_err(|e| Error::XdrDecoding {
                entry_index: None,
                byte_offset: None,
                details: format!(
                    "Failed to serialize ContractCode LedgerKey to base64: {}",
                    e
                ),
                source: Some(Box::new(e)),
            })?;

    let code_response = query_rpc(
        rpc_url,
        auth,
        "getLedgerEntries",
        serde_json::json!({
            "keys": [code_key_b64]
        }),
    )?;

    let code_entries = code_response["result"]["entries"]
        .as_array()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: rpc_url.to_string(),
            code: 0,
            message: "RPC response for contract code did not contain 'entries' array".to_string(),
        })?;

    if code_entries.is_empty() {
        return Err(Error::RpcProtocol {
            rpc_url: rpc_url.to_string(),
            code: 0,
            message: format!(
                "WASM code not found on-chain for hash {}",
                hex::encode(wasm_hash.0)
            ),
        });
    }

    let code_entry_xdr_b64 = code_entries[0]["xdr"]
        .as_str()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: rpc_url.to_string(),
            code: 0,
            message: "RPC response code entry missing 'xdr' field".to_string(),
        })?;

    let code_entry =
        LedgerEntry::from_xdr_base64(code_entry_xdr_b64, Limits::none()).map_err(|e| {
            Error::XdrDecoding {
                entry_index: Some(0),
                byte_offset: None,
                details: format!("Failed to deserialize ContractCode LedgerEntry XDR: {}", e),
                source: Some(Box::new(e)),
            }
        })?;

    let contract_code = match code_entry.data {
        LedgerEntryData::ContractCode(code) => code,
        _ => {
            return Err(Error::RpcProtocol {
                rpc_url: rpc_url.to_string(),
                code: 0,
                message: "Unexpected ledger entry type returned for contract code".to_string(),
            })
        }
    };

    let wasm_bytes = contract_code.code.to_vec();

    // Validate WASM bytes
    if wasm_bytes.len() < 4 || &wasm_bytes[0..4] != b"\0asm" {
        return Err(Error::Integrity {
            details: format!(
                "Fetched WASM for contract '{}' has invalid magic bytes",
                contract_id
            ),
            source: None,
        });
    }

    validate_wasm_structure(&wasm_bytes).map_err(|e| Error::Integrity {
        details: format!(
            "WASM validation failed for fetched contract '{}'",
            contract_id
        ),
        source: Some(Box::new(e)),
    })?;

    Ok(WasmModule {
        path: format!("stellar://{}", contract_id),
        sha256: sha256_hex(&wasm_bytes),
        bytes: wasm_bytes,
    })
}

/// Helper to execute JSON-RPC request to Stellar RPC.
fn query_rpc(
    rpc_url: &str,
    auth: Option<&RpcClientConfig>,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });

    let (agent, headers) = match auth {
        Some(config) => config.request_parts()?,
        None => (
            ureq::AgentBuilder::new()
                .redirect_auth_headers(ureq::RedirectAuthHeaders::Never)
                .build(),
            crate::rpc::ResolvedRpcHeaders::empty(),
        ),
    };
    let mut request = agent.post(rpc_url);
    for (name, value) in &headers.values {
        request = request.set(name, value);
    }
    let response: serde_json::Value = request
        .send_json(payload)
        .map_err(|e| Error::RpcTransport {
            rpc_url: crate::rpc::redact_url(rpc_url),
            details: format!("RPC request failed ({:?})", e.kind()),
            source: None,
        })?
        .into_json()
        .map_err(|_e| Error::RpcTransport {
            rpc_url: crate::rpc::redact_url(rpc_url),
            details: "Failed to parse RPC response body".to_string(),
            source: None,
        })?;

    if let Some(err) = response.get("error") {
        let msg = err["message"].as_str().unwrap_or("Unknown RPC error");
        let code = err["code"].as_i64().unwrap_or(0);
        return Err(Error::RpcProtocol {
            rpc_url: crate::rpc::redact_url(rpc_url),
            code,
            message: msg.to_string(),
        });
    }

    Ok(response)
}

/// Fetches instance storage entries of a deployed contract from Stellar RPC.
pub fn fetch_instance_storage_from_rpc(
    contract_id: &str,
    rpc_url: &str,
) -> Result<Vec<ContractDataEntry>, Error> {
    fetch_instance_storage_from_rpc_inner(contract_id, rpc_url, None)
}

pub fn fetch_instance_storage_from_rpc_with_config(
    contract_id: &str,
    config: &RpcClientConfig,
) -> Result<Vec<ContractDataEntry>, Error> {
    fetch_instance_storage_from_rpc_inner(contract_id, &config.url, Some(config))
}

fn fetch_instance_storage_from_rpc_inner(
    contract_id: &str,
    rpc_url: &str,
    auth: Option<&RpcClientConfig>,
) -> Result<Vec<ContractDataEntry>, Error> {
    let strkey =
        stellar_strkey::Strkey::from_string(contract_id).map_err(|e| Error::InvalidInput {
            details: format!("Invalid contract ID '{}': {}", contract_id, e),
        })?;

    let contract_bytes = match strkey {
        stellar_strkey::Strkey::Contract(c) => c.0,
        _ => {
            return Err(Error::InvalidInput {
                details: format!("Provided ID '{}' is not a valid contract ID", contract_id),
            })
        }
    };

    let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(contract_bytes)),
        key: ScVal::LedgerKeyContractInstance,
        durability: stellar_xdr::curr::ContractDataDurability::Persistent,
    });

    let key_b64 = ledger_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| Error::XdrDecoding {
            entry_index: None,
            byte_offset: None,
            details: format!("Failed to serialize LedgerKey to base64: {}", e),
            source: Some(Box::new(e)),
        })?;

    let response = query_rpc(
        rpc_url,
        auth,
        "getLedgerEntries",
        serde_json::json!({
            "keys": [key_b64]
        }),
    )?;

    let entries = response["result"]["entries"]
        .as_array()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: rpc_url.to_string(),
            code: 0,
            message: "RPC response did not contain 'entries' array".to_string(),
        })?;

    if entries.is_empty() {
        return Err(Error::RpcProtocol {
            rpc_url: rpc_url.to_string(),
            code: 0,
            message: format!("Contract '{}' not found on-chain", contract_id),
        });
    }

    let entry_xdr_b64 = entries[0]["xdr"]
        .as_str()
        .ok_or_else(|| Error::RpcProtocol {
            rpc_url: rpc_url.to_string(),
            code: 0,
            message: "RPC response entry missing 'xdr' field".to_string(),
        })?;

    let entry = LedgerEntry::from_xdr_base64(entry_xdr_b64, Limits::none()).map_err(|e| {
        Error::XdrDecoding {
            entry_index: Some(0),
            byte_offset: None,
            details: format!("Failed to deserialize LedgerEntry XDR: {}", e),
            source: Some(Box::new(e)),
        }
    })?;

    let contract_data = match entry.data {
        LedgerEntryData::ContractData(cd) => cd,
        _ => {
            return Err(Error::RpcProtocol {
                rpc_url: rpc_url.to_string(),
                code: 0,
                message: "Unexpected ledger entry type returned for contract instance".to_string(),
            })
        }
    };

    let instance = match contract_data.val {
        ScVal::ContractInstance(inst) => inst,
        _ => {
            return Err(Error::RpcProtocol {
                rpc_url: rpc_url.to_string(),
                code: 0,
                message: "Expected ScVal::ContractInstance in contract data".to_string(),
            })
        }
    };

    Ok(instance
        .storage
        .map(|s| {
            s.0.iter()
                .map(|entry| ContractDataEntry {
                    ext: ExtensionPoint::V0,
                    contract: ScAddress::Contract(Hash(contract_bytes)),
                    key: entry.key.clone(),
                    durability: stellar_xdr::curr::ContractDataDurability::Persistent,
                    val: entry.val.clone(),
                })
                .collect()
        })
        .unwrap_or_default())
}

// ── Retry-aware public API ────────────────────────────────────────────────────

/// Fetch a deployed contract's WASM from an ordered list of RPC endpoints,
/// retrying transient failures according to `policy`.
///
/// Endpoints are tried left-to-right. On a retryable failure (transport error,
/// HTTP 429, HTTP 503) the engine backs off and moves to the next endpoint.
/// Non-retryable failures (integrity errors, invalid inputs, malformed
/// responses) abort immediately.
///
/// For the common single-endpoint case use [`EndpointList::single`].
pub fn fetch_wasm_with_retry(
    contract_id: &str,
    endpoints: &crate::rpc_retry::EndpointList,
    policy: &crate::rpc_retry::RpcResiliencePolicy,
    sleeper: &dyn crate::rpc_retry::Sleeper,
) -> Result<WasmModule, Error> {
    crate::rpc_retry::with_retry(policy, endpoints, sleeper, |url| {
        fetch_wasm_from_rpc(contract_id, url)
    })
}

use std::io::Read;
use std::path::{Path, PathBuf};

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use stellar_xdr::curr::{
    ContractDataEntry, ContractExecutable, ExtensionPoint, Hash, LedgerEntry, LedgerEntryData,
    LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal,
    WriteXdr,
};
use wasmparser::Parser;

use crate::error::Error;
use crate::oci::{self, OciArtifact, OciArtifactKind, OciFetchConfig, OciReference};
use crate::remote::{self, FetchedArtifact, RemoteFetchConfig, RemoteRef};
use crate::rpc::RpcClientConfig;

/// Normalize a path string for display in a report (JSON or human-readable):
/// convert backslashes to forward slashes so a report generated on Windows
/// and one generated on Unix show the same path *shape*, and diffing,
/// snapshotting, or parsing report output doesn't have to special-case the
/// producing platform's separator.
///
/// Deliberately just a separator swap, nothing more:
///
/// - It does **not** canonicalize or make the path absolute. A relative path
///   given as `../other/contract.wasm` stays relative and stays exactly that
///   many directories long — normalizing it to an absolute path would fold
///   in the current directory and everything above the input, which is
///   exactly the "unrelated directories" a report must not leak. The
///   original, OS-native path is always still the one used for the actual
///   filesystem read and for error messages — this function is display-only.
/// - It does **not** lose the ability to tell two different paths apart:
///   `a/b.wasm` and `a\b.wasm` normalize to the same `a/b.wasm`, which is
///   correct — they name the same file on the platform that produced either
///   of them (Windows accepts `/` as a separator too) — while two inputs
///   that were genuinely different paths remain different strings after
///   normalization.
///
/// Windows also allows `/` directly, so this never changes what the path
/// *means* on either platform — only how it prints.
pub fn normalize_path_display(path: &str) -> String {
    path.replace('\\', "/")
}

/// Symlink resolution recorded for a local input: what was asked for, and
/// what was actually read after following every hop of the chain. `None` on
/// [`WasmModule::symlink`] means the input was a direct file (or came from a
/// non-filesystem source), not that resolution was skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymlinkResolution {
    /// The path exactly as given, before resolution, with display
    /// normalization applied (see [`normalize_path_display`]).
    pub requested: String,
    /// The final, fully resolved (canonical) path that was actually read —
    /// the end of the chain for one or more hops. Absolute by construction
    /// (symlink resolution requires it to unambiguously identify the real
    /// file), with display normalization applied.
    pub resolved: String,
}

/// Holds raw WASM bytes alongside the validated file path.
#[derive(Debug, Clone)]
pub struct WasmModule {
    pub path: String,
    pub bytes: Vec<u8>,
    /// Lowercase hex SHA-256 of `bytes`, computed at load time. Fingerprints the
    /// exact bytecode analyzed so a report can be tied back to the build that
    /// produced it. In RPC mode this equals the on-chain contract code hash.
    pub sha256: String,
    /// Provenance metadata captured if loaded from RPC.
    pub rpc_provenance: Option<crate::rpc::RpcProvenance>,
    /// Set when this module was loaded from a local path that was (or passed
    /// through) a symlink. `None` for a direct file, or for any non-local
    /// source (stdin, RPC, a `https://` URL, an `oci://` reference).
    pub symlink: Option<SymlinkResolution>,
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
///
/// A symlinked input is followed transparently (through however many hops
/// the chain has) and recorded in [`WasmModule::symlink`]. Use
/// [`load_wasm_with_policy`] to reject symlinked inputs outright instead.
pub fn load_wasm(path: &Path) -> Result<WasmModule, Error> {
    load_wasm_with_policy(path, false)
}

/// Like [`load_wasm`], but with explicit control over symlinked inputs.
///
/// When `reject_symlinks` is `true`, a `path` that is itself a symlink (or
/// resolves through one) fails with [`Error::SymlinkRejected`] instead of
/// being followed — for pipelines where an input must be a direct file, not
/// whatever it happens to point at. A broken link or a symlink cycle is
/// always an error, regardless of this setting.
pub fn load_wasm_with_policy(path: &Path, reject_symlinks: bool) -> Result<WasmModule, Error> {
    // 1. Determine whether `path` itself names a symlink, without following
    // it — `Path::exists`/`fs::metadata` would silently follow through to
    // the target and never tell us.
    let is_symlink = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_symlink(),
        Err(_) => {
            // No entry at all (not even a broken symlink) — fall through to
            // the existing "file not found" handling below, which produces a
            // clearer message than the raw `symlink_metadata` error would.
            false
        }
    };

    let symlink = if is_symlink {
        if reject_symlinks {
            // Resolve on a best-effort basis purely so the rejection message
            // can name what the link points to; a failure to resolve doesn't
            // change the outcome (still rejected), so it's not propagated.
            let resolved = std::fs::canonicalize(path).ok();
            return Err(Error::SymlinkRejected {
                path: path.to_path_buf(),
                resolved,
            });
        }

        let resolved = std::fs::canonicalize(path).map_err(|e| {
            // `canonicalize` fails on a broken target (NotFound) or a
            // symlink cycle (ELOOP on Unix); either way, name the link so
            // the failure is diagnosable instead of a bare OS error.
            Error::FileAccess {
                path: path.to_path_buf(),
                details: format!(
                    "Failed to resolve symlink '{}' to a real file",
                    path.display()
                ),
                source: Some(Box::new(e)),
            }
        })?;

        Some(SymlinkResolution {
            requested: normalize_path_display(&path.to_string_lossy()),
            resolved: normalize_path_display(&resolved.to_string_lossy()),
        })
    } else {
        None
    };

    // 2. Check the file exists (following the symlink, if any, to its target).
    if !path.exists() {
        return Err(Error::FileAccess {
            path: path.to_path_buf(),
            details: "File not found".to_string(),
            source: None,
        });
    }

    // Directory inputs are valid filesystem paths, but not valid WASM files.
    // Keep this distinct from "file not found" and malformed-WASM errors so
    // the user gets a precise diagnostic while the rest of the loader behavior
    // stays unchanged.
    if path.is_dir() {
        return Err(Error::InvalidInput {
            details: format!(
                "'{}' is a directory. Expected a WASM file, not a directory.",
                path.display()
            ),
        });
    }

    // 3. Read all bytes into memory
    let bytes = std::fs::read(path).map_err(|e| Error::FileAccess {
        path: path.to_path_buf(),
        details: format!("Failed to read file: {}", path.display()),
        source: Some(Box::new(e)),
    })?;

    wasm_module_from_bytes(
        bytes,
        path.to_path_buf(),
        path.to_string_lossy().into_owned(),
        symlink,
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

    // An empty stream (stdin closed or redirected from an empty source)
    // would otherwise fall through to the generic "bad magic bytes" check
    // in `wasm_module_from_bytes`, which reads as a WASM parsing problem
    // rather than what actually happened: no input arrived at all. Name
    // that distinctly, before any WASM-specific validation runs.
    if bytes.is_empty() {
        return Err(Error::InvalidInput {
            details: "No bytes were read from stdin ('-'). Expected a WASM binary on stdin; \
                      pipe one in, e.g. `cat contract.wasm | soroban-upgrade-safeguard - other.wasm`."
                .to_string(),
        });
    }

    wasm_module_from_bytes(bytes, PathBuf::from("-"), "-".to_string(), None)
}

/// Downloads a WASM binary from an `https://…#sha256=<hex>` reference,
/// verifies it against the pinned digest, and validates it like a local file.
///
/// Returns both the resulting [`WasmModule`] (whose `path` is the sanitized
/// final URL, mirroring how [`fetch_wasm_from_rpc`] labels RPC-sourced
/// modules) and the [`FetchedArtifact`] provenance record — original URL,
/// cache status, and media type — for callers that want to surface it.
pub fn load_wasm_from_url(
    remote: &RemoteRef,
    config: &RemoteFetchConfig,
) -> Result<(WasmModule, FetchedArtifact), Error> {
    let artifact = remote::fetch_verified(remote, config)?;
    let module = wasm_module_from_bytes(
        artifact.bytes.clone(),
        PathBuf::from(&artifact.final_url),
        artifact.final_url.clone(),
        None,
    )?;
    Ok((module, artifact))
}

/// Resolves a WASM binary from an `oci://<registry>/<repository>@sha256:<hex>`
/// reference, verifies it against the resolved layer digest, and validates
/// it like a local file.
///
/// Returns both the resulting [`WasmModule`] (whose `path` is a
/// `oci://registry/repository@sha256:...` label built from the resolved
/// digest, mirroring how [`fetch_wasm_from_rpc`] labels RPC-sourced modules)
/// and the [`OciArtifact`] provenance record for callers that want to
/// surface registry/repository/manifest/layer details.
pub fn load_wasm_from_oci(
    reference: &OciReference,
    config: &OciFetchConfig,
) -> Result<(WasmModule, OciArtifact), Error> {
    let artifact = oci::resolve_oci_artifact(reference, OciArtifactKind::Wasm, config)?;
    let label = format!(
        "oci://{}/{}@{}",
        artifact.registry, artifact.repository, artifact.layer_digest
    );
    let module =
        wasm_module_from_bytes(artifact.bytes.clone(), PathBuf::from(&label), label, None)?;
    Ok((module, artifact))
}

fn wasm_module_from_bytes(
    bytes: Vec<u8>,
    validation_path: PathBuf,
    display_path: String,
    symlink: Option<SymlinkResolution>,
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
    validate_wasm_structure(&bytes).map_err(|e| {
        let byte_offset = e.byte_offset();
        Error::WasmValidation {
            path: Some(validation_path),
            details: format!("WASM validation failed for '{}'", display_path),
            byte_offset,
            source: Some(Box::new(e)),
        }
    })?;

    Ok(WasmModule {
        // Normalized here, at the point the path is recorded for the report,
        // rather than earlier — the validation errors above intentionally
        // still show `display_path` exactly as given, for diagnostics.
        path: normalize_path_display(&display_path),
        sha256: sha256_hex(&bytes),
        bytes,
        rpc_provenance: None,
        symlink,
    })
}

/// Iterates through all WASM payloads and fails fast on any parse error.
fn validate_wasm_structure(bytes: &[u8]) -> Result<(), Error> {
    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        let _ = payload.map_err(|e| Error::WasmValidation {
            path: None,
            details: "Malformed WASM payload encountered".to_string(),
            byte_offset: Some(e.offset() as u64),
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

/// Extract the `latestLedger` sequence number from a JSON-RPC response, if present.
pub fn extract_latest_ledger(response: &serde_json::Value) -> Option<u64> {
    let result = response.get("result")?;
    let val = result.get("latestLedger")?;
    if let Some(n) = val.as_u64() {
        Some(n)
    } else if let Some(s) = val.as_str() {
        s.parse::<u64>().ok()
    } else {
        None
    }
}

/// Extract the `liveUntilLedgerSeq` expiration field from a single
/// `getLedgerEntries` JSON-RPC entry, if present.
///
/// Entries with no TTL (e.g. entry types Stellar RPC never assigns
/// expiration to) simply omit the field, and a value in an unexpected shape
/// is treated the same as absent: expiration is supplementary durability
/// context for the reader, not something that should turn otherwise valid
/// ledger data into a hard failure.
pub fn extract_entry_expiration(entry: &serde_json::Value) -> Option<u64> {
    let val = entry.get("liveUntilLedgerSeq")?;
    if let Some(n) = val.as_u64() {
        Some(n)
    } else if let Some(s) = val.as_str() {
        s.parse::<u64>().ok()
    } else {
        None
    }
}

/// Returns `true` if `content_type` (the raw `Content-Type` header value, or
/// `None` if the header was absent) is compatible with a JSON-RPC response
/// body.
///
/// A missing header is accepted leniently, since some RPC providers omit
/// `Content-Type` entirely despite returning a valid JSON body. Standard
/// (`application/json`) and vendor-specific (`application/vnd.api+json`,
/// etc. — anything using the `+json` structured syntax suffix) JSON types
/// are accepted case-insensitively and regardless of a trailing parameter
/// such as `; charset=utf-8`. Anything else (HTML, XML, binary payloads,
/// plain text, ...) is rejected so a misconfigured endpoint or proxy
/// produces a clear error instead of an opaque JSON parse failure.
fn is_json_content_type(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return true;
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    matches!(
        media_type.as_str(),
        "application/json" | "text/json" | "application/json-rpc" | "application/x-json"
    ) || media_type.ends_with("+json")
}

/// Query the Stellar network passphrase from the RPC endpoint, returning a fallback if unavailable.
fn query_network_passphrase(rpc_url: &str, auth: Option<&RpcClientConfig>) -> String {
    if let Ok(response) = query_rpc(rpc_url, auth, "getNetwork", serde_json::json!({})) {
        if let Some(pass) = response["result"]["passphrase"].as_str() {
            return pass.to_string();
        }
        if let Some(pass) = response["result"]["networkPassphrase"].as_str() {
            return pass.to_string();
        }
    }
    "Public Global Stellar Network ; September 2015".to_string()
}

fn fetch_wasm_from_rpc_inner(
    contract_id: &str,
    rpc_url: &str,
    auth: Option<&RpcClientConfig>,
) -> Result<WasmModule, Error> {
    // `config.url` (when `auth` is set) is already normalized by
    // `RpcClientConfig::new`; normalizing again here is a no-op for it and
    // ensures the bare (no-config) call path gets the same treatment, so
    // provenance and request construction always see the same canonical URL.
    let rpc_url = crate::rpc::normalize_url(rpc_url)?;
    let rpc_url = rpc_url.as_str();

    let max_retries = auth
        .map(|c| c.max_snapshot_retries)
        .unwrap_or(crate::rpc::DEFAULT_MAX_SNAPSHOT_RETRIES);

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

    let instance_ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(Hash(contract_bytes)),
        key: ScVal::LedgerKeyContractInstance,
        durability: stellar_xdr::curr::ContractDataDurability::Persistent,
    });

    let instance_key_b64 = instance_ledger_key
        .to_xdr_base64(Limits::none())
        .map_err(|e| Error::XdrDecoding {
            entry_index: None,
            byte_offset: None,
            details: format!("Failed to serialize LedgerKey to base64: {}", e),
            source: Some(Box::new(e)),
        })?;

    let mut attempt = 0u32;
    loop {
        // 1. Fetch Contract Instance
        let instance_response = query_rpc(
            rpc_url,
            auth,
            "getLedgerEntries",
            serde_json::json!({ "keys": [instance_key_b64.clone()] }),
        )?;

        let instance_seq = extract_latest_ledger(&instance_response);

        let entries = instance_response["result"]["entries"]
            .as_array()
            .ok_or_else(|| Error::RpcProtocol {
                rpc_url: crate::rpc::redact_url(rpc_url),
                code: 0,
                message: "RPC response did not contain 'entries' array".to_string(),
            })?;

        if entries.is_empty() {
            return Err(Error::RpcProtocol {
                rpc_url: crate::rpc::redact_url(rpc_url),
                code: 0,
                message: format!("Contract '{}' not found on-chain", contract_id),
            });
        }

        let instance_expiration = extract_entry_expiration(&entries[0]);

        let entry_xdr_b64 = entries[0]["xdr"]
            .as_str()
            .ok_or_else(|| Error::RpcProtocol {
                rpc_url: crate::rpc::redact_url(rpc_url),
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
                    rpc_url: crate::rpc::redact_url(rpc_url),
                    code: 0,
                    message: "Unexpected ledger entry type returned for contract instance"
                        .to_string(),
                })
            }
        };

        let instance = match contract_data.val {
            ScVal::ContractInstance(inst) => inst,
            _ => {
                return Err(Error::RpcProtocol {
                    rpc_url: crate::rpc::redact_url(rpc_url),
                    code: 0,
                    message: "Expected ScVal::ContractInstance in contract data".to_string(),
                })
            }
        };

        let wasm_hash = match instance.executable {
            ContractExecutable::Wasm(hash) => hash,
            ContractExecutable::StellarAsset => {
                return Err(Error::UnsupportedContract {
                    contract_id: contract_id.to_string(),
                    kind: "Stellar Asset".to_string(),
                })
            }
        };

        // 2. Fetch Contract Code
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
            serde_json::json!({ "keys": [code_key_b64] }),
        )?;

        let code_seq = extract_latest_ledger(&code_response);

        // 3. Snapshot Consistency Check
        if let (Some(s1), Some(s2)) = (instance_seq, code_seq) {
            if s1 != s2 {
                attempt += 1;
                if attempt <= max_retries {
                    continue;
                } else {
                    return Err(Error::RpcSnapshotConsistency {
                        rpc_url: crate::rpc::redact_url(rpc_url),
                        details: format!(
                            "Inconsistent ledger sequence across dependent reads: instance ledger {}, code ledger {}",
                            s1, s2
                        ),
                        attempts: attempt,
                        observed_sequences: vec![s1, s2],
                    });
                }
            }
        }

        let code_entries = code_response["result"]["entries"]
            .as_array()
            .ok_or_else(|| Error::RpcProtocol {
                rpc_url: crate::rpc::redact_url(rpc_url),
                code: 0,
                message: "RPC response for contract code did not contain 'entries' array"
                    .to_string(),
            })?;

        if code_entries.is_empty() {
            return Err(Error::RpcProtocol {
                rpc_url: crate::rpc::redact_url(rpc_url),
                code: 0,
                message: format!(
                    "WASM code not found on-chain for hash {}",
                    hex::encode(wasm_hash.0)
                ),
            });
        }

        let code_entry_xdr_b64 =
            code_entries[0]["xdr"]
                .as_str()
                .ok_or_else(|| Error::RpcProtocol {
                    rpc_url: crate::rpc::redact_url(rpc_url),
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
                    rpc_url: crate::rpc::redact_url(rpc_url),
                    code: 0,
                    message: "Unexpected ledger entry type returned for contract code".to_string(),
                })
            }
        };

        let wasm_bytes = contract_code.code.to_vec();

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

        let network = query_network_passphrase(rpc_url, auth);
        let resolved_seq = instance_seq.or(code_seq).unwrap_or(0);
        let provenance = crate::rpc::RpcProvenance {
            ledger_sequence: resolved_seq,
            network,
            rpc_endpoint: crate::rpc::redact_url(rpc_url),
            code_hash: hex::encode(wasm_hash.0),
            live_until_ledger_seq: instance_expiration,
        };

        return Ok(WasmModule {
            path: format!("stellar://{}", contract_id),
            sha256: sha256_hex(&wasm_bytes),
            bytes: wasm_bytes,
            rpc_provenance: Some(provenance),
            symlink: None,
        });
    }
}

/// Deterministic (never random) JSON-RPC request ID sent with every request,
/// so the response can be verified to actually answer it.
const JSON_RPC_REQUEST_ID: i64 = 1;

/// Verify that a JSON-RPC response's `id` matches the `id` sent with the
/// request. A proxy or misconfigured endpoint can return a valid-looking
/// response that actually answers a different request; this is the only way
/// to catch that.
fn validate_response_id(
    response: &serde_json::Value,
    expected_id: i64,
    rpc_url: &str,
) -> Result<(), Error> {
    match response.get("id") {
        Some(val) if val.as_i64() == Some(expected_id) => Ok(()),
        Some(val) => Err(Error::RpcIdMismatch {
            rpc_url: crate::rpc::redact_url(rpc_url),
            expected_id,
            received_id: Some(match val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            }),
        }),
        None => Err(Error::RpcIdMismatch {
            rpc_url: crate::rpc::redact_url(rpc_url),
            expected_id,
            received_id: None,
        }),
    }
}

/// Helper to execute JSON-RPC request to Stellar RPC.
fn query_rpc(
    rpc_url: &str,
    auth: Option<&RpcClientConfig>,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let request_id = JSON_RPC_REQUEST_ID;
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params
    });

    let (agent, headers) = match auth {
        Some(config) => config.request_parts()?,
        None => (
            crate::rpc::default_agent(),
            crate::rpc::ResolvedRpcHeaders::empty(),
        ),
    };
    let mut request = agent.post(rpc_url);
    for (name, value) in &headers.values {
        request = request.set(name, value);
    }
    let response = request
        .send_json(payload)
        .map_err(|e| Error::RpcTransport {
            rpc_url: crate::rpc::redact_url(rpc_url),
            details: format!("RPC request failed ({:?})", e.kind()),
            source: None,
        })?;

    let content_type = response.header("Content-Type").map(str::to_string);
    if !is_json_content_type(content_type.as_deref()) {
        return Err(Error::RpcTransport {
            rpc_url: crate::rpc::redact_url(rpc_url),
            details: format!(
                "endpoint returned unsupported Content-Type '{}'; expected a JSON content type",
                content_type.as_deref().unwrap_or("<none>")
            ),
            source: None,
        });
    }

    let response: serde_json::Value = response.into_json().map_err(|_e| Error::RpcTransport {
        rpc_url: crate::rpc::redact_url(rpc_url),
        details: "Failed to parse RPC response body".to_string(),
        source: None,
    })?;

    let allow_id_mismatch = auth.map(|c| c.allow_id_mismatch).unwrap_or(false);
    if !allow_id_mismatch {
        validate_response_id(&response, request_id, rpc_url)?;
    }

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

/// Fetch instance storage together with the ledger snapshot used for the read.
/// The provenance can be compared with the contract/code snapshot before
/// empirical validation is performed.
pub fn fetch_instance_storage_from_rpc_with_provenance(
    contract_id: &str,
    config: &RpcClientConfig,
) -> Result<(Vec<ContractDataEntry>, crate::rpc::RpcProvenance), Error> {
    fetch_instance_storage_from_rpc_with_provenance_inner(contract_id, &config.url, Some(config))
}

fn fetch_instance_storage_from_rpc_inner(
    contract_id: &str,
    rpc_url: &str,
    auth: Option<&RpcClientConfig>,
) -> Result<Vec<ContractDataEntry>, Error> {
    Ok(fetch_instance_storage_from_rpc_with_provenance_inner(contract_id, rpc_url, auth)?.0)
}

fn fetch_instance_storage_from_rpc_with_provenance_inner(
    contract_id: &str,
    rpc_url: &str,
    auth: Option<&RpcClientConfig>,
) -> Result<(Vec<ContractDataEntry>, crate::rpc::RpcProvenance), Error> {
    // See the matching comment in `fetch_wasm_from_rpc_inner`: this keeps the
    // bare and `RpcClientConfig`-backed call paths consistent.
    let rpc_url = crate::rpc::normalize_url(rpc_url)?;
    let rpc_url = rpc_url.as_str();

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

    let instance_expiration = extract_entry_expiration(&entries[0]);

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

    let entries = instance
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
        .unwrap_or_default();
    let ledger_sequence = extract_latest_ledger(&response).ok_or_else(|| Error::RpcProtocol {
        rpc_url: crate::rpc::redact_url(rpc_url),
        code: 0,
        message: "RPC response missing latestLedger for snapshot provenance".to_string(),
    })?;
    let network = query_network_passphrase(rpc_url, auth);
    Ok((
        entries,
        crate::rpc::RpcProvenance {
            ledger_sequence,
            network,
            rpc_endpoint: crate::rpc::redact_url(rpc_url),
            code_hash: String::new(),
            live_until_ledger_seq: instance_expiration,
        },
    ))
}

#[cfg(test)]
mod path_display_tests {
    use super::normalize_path_display;

    // These are pure string-transformation tests — they exercise
    // `normalize_path_display` against hand-built strings representing what
    // either platform could have produced, rather than depending on which
    // platform the test itself happens to run on. That's what makes them a
    // real cross-platform check: a run on Linux CI still verifies the exact
    // Windows-style inputs a Windows user would pass.

    #[test]
    fn converts_backslashes_to_forward_slashes() {
        assert_eq!(
            normalize_path_display("sub\\dir\\contract.wasm"),
            "sub/dir/contract.wasm"
        );
    }

    #[test]
    fn already_forward_slash_paths_are_unchanged() {
        let path = "sub/dir/contract.wasm";
        assert_eq!(normalize_path_display(path), path);
    }

    #[test]
    fn mixed_separators_normalize_consistently() {
        assert_eq!(
            normalize_path_display("sub\\dir/contract.wasm"),
            "sub/dir/contract.wasm"
        );
    }

    #[test]
    fn a_bare_filename_with_no_separators_is_unchanged() {
        assert_eq!(normalize_path_display("contract.wasm"), "contract.wasm");
    }

    #[test]
    fn empty_string_is_unchanged() {
        assert_eq!(normalize_path_display(""), "");
    }

    #[test]
    fn a_windows_drive_letter_path_normalizes() {
        assert_eq!(
            normalize_path_display("C:\\Users\\dev\\contract.wasm"),
            "C:/Users/dev/contract.wasm"
        );
    }

    #[test]
    fn a_windows_unc_path_normalizes() {
        assert_eq!(
            normalize_path_display("\\\\server\\share\\contract.wasm"),
            "//server/share/contract.wasm"
        );
    }

    #[test]
    fn a_relative_path_with_parent_references_stays_relative() {
        // Normalization must not canonicalize or absolutize — a `..`-relative
        // path stays exactly as many directories long, so a report never
        // gains directory structure beyond what was actually supplied.
        assert_eq!(
            normalize_path_display("..\\..\\shared\\contract.wasm"),
            "../../shared/contract.wasm"
        );
    }

    #[test]
    fn distinct_paths_remain_distinct_after_normalization() {
        // The property that matters for "distinguishing equivalent paths":
        // two genuinely different paths must not collapse to the same string.
        assert_ne!(
            normalize_path_display("a\\b.wasm"),
            normalize_path_display("a\\c.wasm")
        );
    }

    #[test]
    fn equivalent_paths_from_either_platform_normalize_to_the_same_string() {
        // The same logical path, written the way either platform would
        // naturally produce it, must read identically in a report — this is
        // what makes a snapshot taken on one OS comparable to a run on another.
        assert_eq!(
            normalize_path_display("sub\\dir\\contract.wasm"),
            normalize_path_display("sub/dir/contract.wasm")
        );
    }

    #[test]
    fn is_idempotent() {
        let once = normalize_path_display("sub\\dir\\contract.wasm");
        let twice = normalize_path_display(&once);
        assert_eq!(once, twice);
    }
}

#[cfg(test)]
mod expiration_tests {
    use super::extract_entry_expiration;

    #[test]
    fn extracts_numeric_expiration() {
        let entry = serde_json::json!({ "xdr": "ignored", "liveUntilLedgerSeq": 555555 });
        assert_eq!(extract_entry_expiration(&entry), Some(555555));
    }

    #[test]
    fn extracts_string_encoded_expiration() {
        let entry = serde_json::json!({ "xdr": "ignored", "liveUntilLedgerSeq": "400000" });
        assert_eq!(extract_entry_expiration(&entry), Some(400000));
    }

    #[test]
    fn missing_field_returns_none() {
        let entry = serde_json::json!({ "xdr": "ignored" });
        assert_eq!(extract_entry_expiration(&entry), None);
    }

    #[test]
    fn malformed_field_returns_none_without_error() {
        let entry =
            serde_json::json!({ "xdr": "ignored", "liveUntilLedgerSeq": { "nested": true } });
        assert_eq!(extract_entry_expiration(&entry), None);

        let entry = serde_json::json!({ "xdr": "ignored", "liveUntilLedgerSeq": "not-a-number" });
        assert_eq!(extract_entry_expiration(&entry), None);

        let entry = serde_json::json!({ "xdr": "ignored", "liveUntilLedgerSeq": null });
        assert_eq!(extract_entry_expiration(&entry), None);
    }
}

#[cfg(test)]
mod content_type_tests {
    use super::is_json_content_type;

    #[test]
    fn accepts_standard_json() {
        assert!(is_json_content_type(Some("application/json")));
    }

    #[test]
    fn accepts_standard_json_case_insensitively() {
        assert!(is_json_content_type(Some("APPLICATION/JSON")));
        assert!(is_json_content_type(Some("Application/Json")));
    }

    #[test]
    fn accepts_json_with_charset_parameter() {
        assert!(is_json_content_type(Some(
            "application/json; charset=utf-8"
        )));
        assert!(is_json_content_type(Some("application/json;charset=UTF-8")));
    }

    #[test]
    fn accepts_vendor_json_content_types() {
        assert!(is_json_content_type(Some("application/vnd.api+json")));
        assert!(is_json_content_type(Some("application/hal+json")));
        assert!(is_json_content_type(Some(
            "application/vnd.custom+json; charset=utf-8"
        )));
        assert!(is_json_content_type(Some("text/json")));
        assert!(is_json_content_type(Some("application/json-rpc")));
    }

    #[test]
    fn accepts_missing_content_type() {
        assert!(is_json_content_type(None));
    }

    #[test]
    fn rejects_html() {
        assert!(!is_json_content_type(Some("text/html")));
        assert!(!is_json_content_type(Some("text/html; charset=utf-8")));
    }

    #[test]
    fn rejects_binary_and_other_incompatible_types() {
        assert!(!is_json_content_type(Some("application/octet-stream")));
        assert!(!is_json_content_type(Some("image/png")));
        assert!(!is_json_content_type(Some("application/xml")));
        assert!(!is_json_content_type(Some("text/plain")));
    }
}

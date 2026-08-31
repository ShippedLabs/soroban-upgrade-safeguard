//! Integration tests for the `--contract-id` / `--rpc-url` RPC fetch mode.
//!
//! These tests spin up a lightweight HTTP mock server that emulates the
//! Stellar RPC `getLedgerEntries` endpoint, returning pre-built XDR payloads
//! so we can exercise the full fetch→parse→compare pipeline without touching
//! a real network.

use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use soroban_upgrade_safeguard::error::ErrorKind;
use soroban_upgrade_safeguard::loader::fetch_wasm_from_rpc;
use soroban_upgrade_safeguard::loader::fetch_wasm_from_rpc_with_config;
use soroban_upgrade_safeguard::rpc::RpcClientConfig;

use stellar_xdr::curr::{
    ContractCodeEntry, ContractDataDurability, ContractDataEntry, ContractExecutable,
    ExtensionPoint, Hash, LedgerEntry, LedgerEntryData, LedgerEntryExt, Limits, ScAddress,
    ScContractInstance, ScVal, WriteXdr,
};

/// Contract ID used in tests (a valid C... strkey for 32 zero bytes).
const TEST_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// Path to a fixture WASM under `tests/wasm/`.
fn wasm_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Read a fixture WASM file's raw bytes.
fn wasm_bytes(name: &str) -> Vec<u8> {
    std::fs::read(wasm_fixture(name)).expect("failed to read WASM fixture")
}

/// Build LedgerEntry XDR (base64) for the contract instance response.
/// Contains the WASM hash pointing at the given code bytes.
fn build_instance_entry_xdr(wasm_hash: &[u8; 32]) -> String {
    let entry = LedgerEntry {
        last_modified_ledger_seq: 100,
        data: LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(Hash([0u8; 32])),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(Hash(*wasm_hash)),
                storage: None,
            }),
        }),
        ext: LedgerEntryExt::V0,
    };
    entry
        .to_xdr_base64(Limits::none())
        .expect("failed to encode instance entry")
}

/// Build LedgerEntry XDR (base64) for the contract code response.
fn build_code_entry_xdr(wasm_hash: &[u8; 32], code: &[u8]) -> String {
    let entry = LedgerEntry {
        last_modified_ledger_seq: 100,
        data: LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: stellar_xdr::curr::ContractCodeEntryExt::V0,
            hash: Hash(*wasm_hash),
            code: code.try_into().expect("WASM code too large for BytesM"),
        }),
        ext: LedgerEntryExt::V0,
    };
    entry
        .to_xdr_base64(Limits::none())
        .expect("failed to encode code entry")
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];

    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let n = stream.read(&mut buf).expect("failed to read request");
        if n == 0 {
            return String::new();
        }
        request.extend_from_slice(&buf[..n]);
    }

    let Some(header_end) = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
    else {
        return String::new();
    };

    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);

    let target_len = header_end + content_length;
    while request.len() < target_len {
        let n = stream.read(&mut buf).expect("failed to read request body");
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
    }

    String::from_utf8_lossy(&request).into_owned()
}

fn finish_http_response(stream: &mut std::net::TcpStream, response: &[u8]) {
    stream
        .write_all(response)
        .expect("failed to write HTTP response");
    stream.flush().expect("failed to flush HTTP response");
}

/// A tiny HTTP server that handles exactly three sequential requests
/// (instance lookup, code lookup, then `getNetwork`) and returns pre-canned
/// JSON-RPC responses.
///
/// Returns the bound address (e.g. "127.0.0.1:PORT").
fn start_mock_rpc(instance_xdr: String, code_xdr: String) -> (String, Arc<TcpListener>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);

    thread::spawn(move || {
        // Handle the getLedgerEntries responses (instance, then code)...
        for xdr in [instance_xdr, code_xdr].iter() {
            let (mut stream, _) = listener_clone.accept().expect("failed to accept");

            read_http_request(&mut stream);

            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "latestLedger": 200,
                    "entries": [{
                        "key": "ignored",
                        "xdr": xdr,
                        "lastModifiedLedgerSeq": 100
                    }]
                }
            });
            let body_str = serde_json::to_string(&body).unwrap();

            let response = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_str.len(),
                body_str
            );
            finish_http_response(&mut stream, response.as_bytes());
        }

        // ...then the trailing `getNetwork` call the loader always issues to
        // populate RPC provenance.
        let (mut stream, _) = listener_clone.accept().expect("failed to accept");
        let _ = read_http_request(&mut stream);
        let body =
            serde_json::to_string(&build_network_response("Test SDF Network ; September 2015"))
                .unwrap();
        let response = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        finish_http_response(&mut stream, response.as_bytes());
    });

    (addr, listener)
}

/// Start a mock server that returns empty entries (contract not found).
fn start_mock_rpc_not_found() -> (String, Arc<TcpListener>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let listener_clone = Arc::clone(&listener);

    thread::spawn(move || {
        let (mut stream, _) = listener_clone.accept().expect("failed to accept");
        read_http_request(&mut stream);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": 200,
                "entries": []
            }
        });
        let body_str = serde_json::to_string(&body).unwrap();
        let response = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body_str.len(),
            body_str
        );
        finish_http_response(&mut stream, response.as_bytes());
    });

    (addr, listener)
}

/// Build a JSON-RPC success response containing one ledger entry with the given XDR.
fn build_rpc_success(xdr: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "latestLedger": 200,
            "entries": [{
                "key": "ignored",
                "xdr": xdr,
                "lastModifiedLedgerSeq": 100
            }]
        }
    })
}

/// Build a JSON-RPC success response with an empty entries array.
fn build_rpc_empty_entries() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "latestLedger": 200,
            "entries": []
        }
    })
}

/// Build a JSON-RPC error response.
fn build_rpc_error(code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": code,
            "message": message
        }
    })
}

/// A generic mock RPC server that returns the given JSON-RPC response bodies in
/// order, one per incoming connection.  Binds to an ephemeral port.
fn start_mock_rpc_with(responses: Vec<serde_json::Value>) -> (String, Arc<TcpListener>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let l = Arc::clone(&listener);

    thread::spawn(move || {
        for resp in responses {
            if let Ok((mut stream, _)) = l.accept() {
                let _ = read_http_request(&mut stream);
                let body = serde_json::to_string(&resp).unwrap();
                let response = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                finish_http_response(&mut stream, response.as_bytes());
            }
        }
    });

    (addr, listener)
}

/// Build a LedgerEntry XDR (base64) for a contract instance whose executable is
/// `StellarAsset` (i.e. a built-in asset contract with no WASM bytecode).
fn build_stellar_asset_entry_xdr() -> String {
    let entry = LedgerEntry {
        last_modified_ledger_seq: 100,
        data: LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(Hash([0u8; 32])),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::StellarAsset,
                storage: None,
            }),
        }),
        ext: LedgerEntryExt::V0,
    };
    entry
        .to_xdr_base64(Limits::none())
        .expect("failed to encode StellarAsset instance entry")
}

// ---------------------------------------------------------------------------
// Existing integration tests (via binary)
// ---------------------------------------------------------------------------

#[test]
fn rpc_fetch_compares_on_chain_against_local() {
    // Use v1.wasm as the "on-chain" contract and v2.wasm as the "candidate"
    let code = wasm_bytes("v1.wasm");
    let wasm_hash: [u8; 32] = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        code.hash(&mut hasher);
        let h = hasher.finish();
        // Just use the hash bytes repeated to fill 32 bytes
        let mut arr = [0u8; 32];
        arr[..8].copy_from_slice(&h.to_le_bytes());
        arr
    };

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);
    let (addr, _listener) = start_mock_rpc(instance_xdr, code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
        ])
        .arg(wasm_fixture("v2.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");

    let json: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}\n---stderr---\n{stderr}")
    });

    // v1 vs v2 should produce a breaking report
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert!(json["counts"]["critical"].as_u64().unwrap() >= 1);

    // The exit code must be 1 for a breaking upgrade
    let code = output.status.code().expect("no exit code");
    assert_eq!(code, 1, "breaking upgrade must exit 1");
}

#[test]
fn rpc_fetch_safe_comparison() {
    // Use v1.wasm as both "on-chain" and "candidate" — should be safe
    let code = wasm_bytes("v1.wasm");
    let wasm_hash: [u8; 32] = {
        let mut arr = [0u8; 32];
        arr[0] = 42; // arbitrary distinct hash
        arr
    };

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);
    let (addr, _listener) = start_mock_rpc(instance_xdr, code_xdr);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
        ])
        .arg(wasm_fixture("v1.wasm")) // same as on-chain
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));

    assert_eq!(json["is_safe"], Value::Bool(true));
    assert_eq!(output.status.code().unwrap(), 0);
}

#[test]
fn rpc_fetch_contract_not_found_produces_clear_error() {
    let (addr, _listener) = start_mock_rpc_not_found();

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            &format!("http://{}", addr),
        ])
        .arg(wasm_fixture("v1.wasm"))
        .output()
        .expect("failed to run binary");

    let code = output.status.code().unwrap();
    assert_ne!(code, 0, "not-found must produce a non-zero exit");

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("not found") || stderr.contains("not found on-chain"),
        "error message should mention 'not found', got: {stderr}"
    );
}

#[test]
fn rpc_fetch_network_failure_produces_clear_error() {
    // Point at a port that nothing is listening on
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--contract-id",
            TEST_CONTRACT_ID,
            "--rpc-url",
            "http://127.0.0.1:1", // almost certainly nobody is listening here
        ])
        .arg(wasm_fixture("v1.wasm"))
        .output()
        .expect("failed to run binary");

    let code = output.status.code().unwrap();
    assert_ne!(code, 0, "network failure must produce a non-zero exit");

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("RPC request failed") || stderr.contains("Connection refused"),
        "error message should mention RPC failure, got: {stderr}"
    );
}

#[test]
fn local_two_file_mode_still_works() {
    // Smoke test: the original two-file positional usage is unchanged
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm_fixture("v1.wasm"))
        .arg(wasm_fixture("v2.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));

    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(output.status.code().unwrap(), 1);
}

// ---------------------------------------------------------------------------
// Direct `fetch_wasm_from_rpc` unit tests
// ---------------------------------------------------------------------------

#[test]
fn fetch_wasm_from_rpc_happy_path() {
    let code = wasm_bytes("v1.wasm");
    let wasm_hash = [42u8; 32];

    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);

    let network_passphrase = "Test SDF Network ; September 2015";
    let (addr, _listener) = start_mock_rpc_with(vec![
        build_rpc_success(&instance_xdr),
        build_rpc_success(&code_xdr),
        build_network_response(network_passphrase),
    ]);

    let module = fetch_wasm_from_rpc(TEST_CONTRACT_ID, &format!("http://{}", addr))
        .expect("happy path should succeed");

    assert_eq!(module.path, format!("stellar://{}", TEST_CONTRACT_ID));
    assert_eq!(module.bytes, code);
    assert_eq!(
        module
            .rpc_provenance
            .expect("provenance should be set")
            .network,
        network_passphrase
    );
}

#[test]
fn fetch_wasm_from_rpc_contract_not_found() {
    let (addr, _listener) = start_mock_rpc_with(vec![build_rpc_empty_entries()]);

    let err = fetch_wasm_from_rpc(TEST_CONTRACT_ID, &format!("http://{}", addr))
        .expect_err("should fail when contract is not found");

    assert_eq!(err.kind(), ErrorKind::RpcProtocol);
    let msg = err.to_string();
    assert!(
        msg.contains("not found"),
        "expected error to mention 'not found', got: {msg}"
    );
}

#[test]
fn fetch_wasm_from_rpc_stellar_asset() {
    let instance_xdr = build_stellar_asset_entry_xdr();

    // For StellarAsset the function returns before making the second call.
    let (addr, _listener) = start_mock_rpc_with(vec![build_rpc_success(&instance_xdr)]);

    let err = fetch_wasm_from_rpc(TEST_CONTRACT_ID, &format!("http://{}", addr))
        .expect_err("should fail for StellarAsset contracts");

    assert_eq!(err.kind(), ErrorKind::UnsupportedContract);
    let msg = err.to_string();
    assert!(
        msg.contains("Stellar Asset"),
        "expected error to mention 'Stellar Asset', got: {msg}"
    );
}

#[test]
fn fetch_wasm_from_rpc_code_entry_missing() {
    let wasm_hash = [42u8; 32];
    let instance_xdr = build_instance_entry_xdr(&wasm_hash);

    // First call returns the instance, second call returns empty entries.
    let (addr, _listener) = start_mock_rpc_with(vec![
        build_rpc_success(&instance_xdr),
        build_rpc_empty_entries(),
    ]);

    let err = fetch_wasm_from_rpc(TEST_CONTRACT_ID, &format!("http://{}", addr))
        .expect_err("should fail when code entry is missing");

    assert_eq!(err.kind(), ErrorKind::RpcProtocol);
    let msg = err.to_string();
    assert!(
        msg.contains("WASM code not found"),
        "expected error to mention 'WASM code not found', got: {msg}"
    );
}

#[test]
fn fetch_wasm_from_rpc_malformed_xdr() {
    let (addr, _listener) = start_mock_rpc_with(vec![serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "latestLedger": 200,
            "entries": [{
                "xdr": "this-is-not-valid-base64-xdr",
                "key": "ignored"
            }]
        }
    })]);

    let err = fetch_wasm_from_rpc(TEST_CONTRACT_ID, &format!("http://{}", addr))
        .expect_err("should fail on malformed XDR");

    assert_eq!(err.kind(), ErrorKind::XdrDecoding);
}

#[test]
fn fetch_wasm_from_rpc_json_rpc_error() {
    let (addr, _listener) = start_mock_rpc_with(vec![build_rpc_error(-32000, "ledger not found")]);

    let err = fetch_wasm_from_rpc(TEST_CONTRACT_ID, &format!("http://{}", addr))
        .expect_err("should fail on JSON-RPC error");

    assert_eq!(err.kind(), ErrorKind::RpcProtocol);
    let msg = err.to_string();
    assert!(
        msg.contains("ledger not found"),
        "expected error to contain the RPC error message, got: {msg}"
    );
}

#[test]
fn authenticated_header_is_applied_to_every_rpc_request() {
    let code = wasm_bytes("v1.wasm");
    let wasm_hash = [42u8; 32];
    let responses = vec![
        build_rpc_success(&build_instance_entry_xdr(&wasm_hash)),
        build_rpc_success(&build_code_entry_xdr(&wasm_hash, &code)),
    ];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);

    let server = thread::spawn(move || {
        for body in responses {
            let (mut stream, _) = listener.accept().unwrap();
            captured
                .lock()
                .unwrap()
                .push(read_http_request(&mut stream));
            let body = serde_json::to_string(&body).unwrap();
            let response = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            finish_http_response(&mut stream, response.as_bytes());
        }
    });

    std::env::set_var("SAFEGUARD_RPC_AUTH_TEST", "Bearer test-secret");
    let config = RpcClientConfig::new(format!("http://{addr}"))
        .unwrap()
        .with_env_header("Authorization", "SAFEGUARD_RPC_AUTH_TEST")
        .unwrap();
    fetch_wasm_from_rpc_with_config(TEST_CONTRACT_ID, &config).unwrap();
    server.join().unwrap();
    std::env::remove_var("SAFEGUARD_RPC_AUTH_TEST");

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| request.contains("Authorization: Bearer test-secret")));
}

#[test]
fn authenticated_request_does_not_follow_cross_origin_redirect() {
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    sink.set_nonblocking(true).unwrap();
    let sink_addr = sink.local_addr().unwrap();
    let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
    let redirect_addr = redirect.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (mut stream, _) = redirect.accept().unwrap();
        let _ = read_http_request(&mut stream);
        let response = format!(
            "HTTP/1.0 302 Found\r\nLocation: http://{sink_addr}/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        finish_http_response(&mut stream, response.as_bytes());
    });

    std::env::set_var("SAFEGUARD_RPC_REDIRECT_TEST", "redirect-secret");
    let config = RpcClientConfig::new(format!("http://{redirect_addr}"))
        .unwrap()
        .with_env_header("X-Api-Key", "SAFEGUARD_RPC_REDIRECT_TEST")
        .unwrap();
    let error = fetch_wasm_from_rpc_with_config(TEST_CONTRACT_ID, &config).unwrap_err();
    server.join().unwrap();
    std::env::remove_var("SAFEGUARD_RPC_REDIRECT_TEST");

    assert_eq!(error.kind(), ErrorKind::RpcTransport);
    thread::sleep(Duration::from_millis(50));
    assert!(sink.accept().is_err(), "redirect target received a request");
}

// ---------------------------------------------------------------------------
// Snapshot consistency tests
// ---------------------------------------------------------------------------

/// Build a JSON-RPC success response with a specific `latestLedger` value.
fn build_rpc_success_with_ledger(xdr: &str, ledger: u64) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "latestLedger": ledger,
            "entries": [{
                "key": "ignored",
                "xdr": xdr,
                "lastModifiedLedgerSeq": 100
            }]
        }
    })
}

/// Build a mock `getNetwork` JSON-RPC response.
fn build_network_response(passphrase: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "passphrase": passphrase
        }
    })
}

#[test]
fn snapshot_consistent_reads_succeed_with_provenance() {
    // Both instance and code reads return the same latestLedger → should succeed.
    let code = wasm_bytes("v1.wasm");
    let wasm_hash = [99u8; 32];
    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);

    let ledger_seq = 500u64;
    let network_passphrase = "Test SDF Network ; September 2015";

    // The loader issues: 1) getLedgerEntries (instance), 2) getLedgerEntries (code),
    // 3) getNetwork (for passphrase).
    let (addr, _listener) = start_mock_rpc_with(vec![
        build_rpc_success_with_ledger(&instance_xdr, ledger_seq),
        build_rpc_success_with_ledger(&code_xdr, ledger_seq),
        build_network_response(network_passphrase),
    ]);

    let module = fetch_wasm_from_rpc(TEST_CONTRACT_ID, &format!("http://{}", addr))
        .expect("consistent snapshot should succeed");

    assert_eq!(module.bytes, code);
    assert_eq!(module.path, format!("stellar://{}", TEST_CONTRACT_ID));

    // Verify provenance is populated.
    let prov = module
        .rpc_provenance
        .expect("rpc_provenance should be set on RPC fetch");
    assert_eq!(prov.ledger_sequence, ledger_seq);
    assert_eq!(prov.network, network_passphrase);
    assert_eq!(prov.code_hash, hex::encode(wasm_hash));
    assert!(
        !prov.rpc_endpoint.is_empty(),
        "rpc_endpoint should be populated"
    );
}

#[test]
fn snapshot_mismatch_retries_then_succeeds() {
    // First attempt: instance returns ledger 100, code returns ledger 101 → mismatch.
    // Retry: both return ledger 101 → success.
    let code = wasm_bytes("v1.wasm");
    let wasm_hash = [77u8; 32];
    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);

    let network_passphrase = "Test SDF Network ; September 2015";

    let (addr, _listener) = start_mock_rpc_with(vec![
        // Attempt 1: instance at ledger 100
        build_rpc_success_with_ledger(&instance_xdr, 100),
        // Attempt 1: code at ledger 101 → mismatch triggers retry
        build_rpc_success_with_ledger(&code_xdr, 101),
        // Attempt 2: instance at ledger 101
        build_rpc_success_with_ledger(&instance_xdr, 101),
        // Attempt 2: code at ledger 101 → consistent → success
        build_rpc_success_with_ledger(&code_xdr, 101),
        // getNetwork
        build_network_response(network_passphrase),
    ]);

    let module = fetch_wasm_from_rpc(TEST_CONTRACT_ID, &format!("http://{}", addr))
        .expect("should succeed after retry");

    assert_eq!(module.bytes, code);
    let prov = module.rpc_provenance.expect("rpc_provenance should be set");
    assert_eq!(prov.ledger_sequence, 101);
}

#[test]
fn snapshot_mismatch_exhaustion_fails() {
    // Every attempt has mismatched ledgers. After max_retries (1), should fail
    // with RpcSnapshotConsistency error.
    let code = wasm_bytes("v1.wasm");
    let wasm_hash = [88u8; 32];
    let instance_xdr = build_instance_entry_xdr(&wasm_hash);
    let code_xdr = build_code_entry_xdr(&wasm_hash, &code);

    // With max_retries=1, the loader tries: attempt 0 (initial) + attempt 1 (1 retry)
    // = 2 total rounds. Each round needs instance + code responses.
    let (addr, _listener) = start_mock_rpc_with(vec![
        // Attempt 0: instance at ledger 100, code at ledger 101
        build_rpc_success_with_ledger(&instance_xdr, 100),
        build_rpc_success_with_ledger(&code_xdr, 101),
        // Attempt 1 (retry): instance at ledger 102, code at ledger 103
        build_rpc_success_with_ledger(&instance_xdr, 102),
        build_rpc_success_with_ledger(&code_xdr, 103),
    ]);

    let config = RpcClientConfig::new(format!("http://{addr}"))
        .unwrap()
        .with_max_retries(1);

    let err = fetch_wasm_from_rpc_with_config(TEST_CONTRACT_ID, &config)
        .expect_err("should exhaust retries");

    assert_eq!(
        err.kind(),
        ErrorKind::RpcSnapshotConsistency,
        "error should be RpcSnapshotConsistency, got: {err}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("Inconsistent ledger sequence"),
        "error should mention ledger sequence inconsistency, got: {msg}"
    );
}

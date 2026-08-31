//! Tests for ledger-entry expiration (`liveUntilLedgerSeq`) metadata surfaced
//! by the RPC loader's empirical storage fetch.
//!
//! Mirrors the mock-server pattern in `tests/rpc_fetch.rs`: a hand-rolled
//! HTTP server returns pre-built JSON-RPC responses so the fetch→parse
//! pipeline can be exercised without touching a real network.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use soroban_upgrade_safeguard::loader::fetch_instance_storage_from_rpc_with_provenance;
use soroban_upgrade_safeguard::rpc::RpcClientConfig;

use stellar_xdr::curr::{
    ContractDataDurability, ContractDataEntry, ContractExecutable, ExtensionPoint, Hash,
    LedgerEntry, LedgerEntryData, LedgerEntryExt, Limits, ScAddress, ScContractInstance, ScVal,
    WriteXdr,
};

/// Contract ID used in tests (a valid C... strkey for 32 zero bytes).
const TEST_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

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

/// A generic mock RPC server that returns the given JSON-RPC response bodies
/// in order, one per incoming connection.
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

/// Build LedgerEntry XDR (base64) for a contract instance entry with the
/// given durability. `liveUntilLedgerSeq` is a sibling JSON field on the
/// `getLedgerEntries` response entry, not part of the XDR itself, so the
/// durability here only affects the scenario being described.
fn build_instance_entry_xdr(wasm_hash: &[u8; 32], durability: ContractDataDurability) -> String {
    let entry = LedgerEntry {
        last_modified_ledger_seq: 100,
        data: LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(Hash([0u8; 32])),
            key: ScVal::LedgerKeyContractInstance,
            durability,
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

/// Build a `getLedgerEntries` JSON-RPC success response for one entry,
/// optionally attaching a `liveUntilLedgerSeq` value of any JSON shape.
fn build_rpc_entries_response(
    xdr: &str,
    live_until: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "key": "ignored",
        "xdr": xdr,
        "lastModifiedLedgerSeq": 100
    });
    if let Some(value) = live_until {
        entry["liveUntilLedgerSeq"] = value;
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "latestLedger": 200,
            "entries": [entry]
        }
    })
}

fn build_network_response(passphrase: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "passphrase": passphrase }
    })
}

#[test]
fn persistent_entry_expiration_is_surfaced() {
    let xdr = build_instance_entry_xdr(&[7u8; 32], ContractDataDurability::Persistent);
    let (addr, _listener) = start_mock_rpc_with(vec![
        build_rpc_entries_response(&xdr, Some(serde_json::json!(600000))),
        build_network_response("Test SDF Network ; September 2015"),
    ]);

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let (_entries, provenance) =
        fetch_instance_storage_from_rpc_with_provenance(TEST_CONTRACT_ID, &config)
            .expect("fetch should succeed");

    assert_eq!(provenance.live_until_ledger_seq, Some(600000));
}

#[test]
fn temporary_entry_expiration_is_surfaced() {
    let xdr = build_instance_entry_xdr(&[8u8; 32], ContractDataDurability::Temporary);
    let (addr, _listener) = start_mock_rpc_with(vec![
        build_rpc_entries_response(&xdr, Some(serde_json::json!(400000))),
        build_network_response("Test SDF Network ; September 2015"),
    ]);

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let (_entries, provenance) =
        fetch_instance_storage_from_rpc_with_provenance(TEST_CONTRACT_ID, &config)
            .expect("fetch should succeed");

    assert_eq!(provenance.live_until_ledger_seq, Some(400000));
}

#[test]
fn missing_expiration_field_yields_none_without_error() {
    let xdr = build_instance_entry_xdr(&[9u8; 32], ContractDataDurability::Persistent);
    let (addr, _listener) = start_mock_rpc_with(vec![
        build_rpc_entries_response(&xdr, None),
        build_network_response("Test SDF Network ; September 2015"),
    ]);

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let (_entries, provenance) =
        fetch_instance_storage_from_rpc_with_provenance(TEST_CONTRACT_ID, &config)
            .expect("fetch should succeed even without expiration metadata");

    assert_eq!(provenance.live_until_ledger_seq, None);
}

#[test]
fn malformed_expiration_field_yields_none_without_error() {
    let xdr = build_instance_entry_xdr(&[10u8; 32], ContractDataDurability::Persistent);
    let (addr, _listener) = start_mock_rpc_with(vec![
        build_rpc_entries_response(&xdr, Some(serde_json::json!({ "not": "a number" }))),
        build_network_response("Test SDF Network ; September 2015"),
    ]);

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let (_entries, provenance) =
        fetch_instance_storage_from_rpc_with_provenance(TEST_CONTRACT_ID, &config)
            .expect("malformed expiration metadata should not fail the fetch");

    assert_eq!(provenance.live_until_ledger_seq, None);
}

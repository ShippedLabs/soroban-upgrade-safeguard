//! Tests for JSON-RPC response `Content-Type` acceptance.
//!
//! Mirrors the mock-server pattern in `tests/rpc_fetch.rs`: a hand-rolled
//! HTTP server returns responses with caller-controlled headers and bodies
//! so the transport layer's content-type gate can be exercised end to end
//! without touching a real network.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use soroban_upgrade_safeguard::error::ErrorKind;
use soroban_upgrade_safeguard::loader::fetch_instance_storage_from_rpc_with_provenance;
use soroban_upgrade_safeguard::rpc::RpcClientConfig;

use stellar_xdr::curr::{
    ContractDataDurability, ContractDataEntry, ContractExecutable, ExtensionPoint, Hash,
    LedgerEntry, LedgerEntryData, LedgerEntryExt, Limits, ScAddress, ScContractInstance, ScVal,
    WriteXdr,
};

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
    let _ = stream.write_all(response);
    let _ = stream.flush();
}

/// One canned raw HTTP response body plus an optional `Content-Type` header
/// value (`None` omits the header entirely).
struct MockResponse {
    body: String,
    content_type: Option<String>,
}

/// A mock RPC server that returns the given raw responses in order, one per
/// incoming connection, each with its own (possibly absent) Content-Type.
fn start_mock_rpc_sequence(responses: Vec<MockResponse>) -> (String, Arc<TcpListener>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let l = Arc::clone(&listener);

    thread::spawn(move || {
        for resp in responses {
            if let Ok((mut stream, _)) = l.accept() {
                let _ = read_http_request(&mut stream);
                let content_type_header = match &resp.content_type {
                    Some(ct) => format!("Content-Type: {ct}\r\n"),
                    None => String::new(),
                };
                let response = format!(
                    "HTTP/1.0 200 OK\r\n{content_type_header}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp.body.len(),
                    resp.body
                );
                finish_http_response(&mut stream, response.as_bytes());
            }
        }
    });

    (addr, listener)
}

fn build_instance_entry_xdr() -> String {
    let entry = LedgerEntry {
        last_modified_ledger_seq: 100,
        data: LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(Hash([0u8; 32])),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(Hash([1u8; 32])),
                storage: None,
            }),
        }),
        ext: LedgerEntryExt::V0,
    };
    entry
        .to_xdr_base64(Limits::none())
        .expect("failed to encode instance entry")
}

fn entries_response_body(xdr: &str) -> String {
    serde_json::to_string(&serde_json::json!({
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
    }))
    .unwrap()
}

fn network_response_body() -> String {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "passphrase": "Test SDF Network ; September 2015" }
    }))
    .unwrap()
}

/// Run the two-request `fetch_instance_storage_from_rpc_with_provenance`
/// flow against a mock server whose first response uses `content_type`.
fn fetch_with_first_response_content_type(
    content_type: Option<&str>,
) -> Result<(), soroban_upgrade_safeguard::error::Error> {
    let xdr = build_instance_entry_xdr();
    let (addr, _listener) = start_mock_rpc_sequence(vec![
        MockResponse {
            body: entries_response_body(&xdr),
            content_type: content_type.map(str::to_string),
        },
        MockResponse {
            body: network_response_body(),
            content_type: Some("application/json".to_string()),
        },
    ]);

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    fetch_instance_storage_from_rpc_with_provenance(TEST_CONTRACT_ID, &config).map(|_| ())
}

#[test]
fn accepts_standard_json_content_type() {
    fetch_with_first_response_content_type(Some("application/json"))
        .expect("standard application/json should be accepted");
}

#[test]
fn accepts_json_content_type_with_charset_parameter() {
    fetch_with_first_response_content_type(Some("application/json; charset=utf-8"))
        .expect("application/json with a charset parameter should be accepted");
}

#[test]
fn accepts_json_content_type_case_insensitively() {
    fetch_with_first_response_content_type(Some("APPLICATION/JSON"))
        .expect("content type matching should be case-insensitive");
}

#[test]
fn accepts_vendor_json_content_type() {
    fetch_with_first_response_content_type(Some("application/vnd.api+json"))
        .expect("a documented vendor +json content type should be accepted");
}

#[test]
fn accepts_missing_content_type_header() {
    fetch_with_first_response_content_type(None)
        .expect("a missing Content-Type header should be accepted leniently");
}

#[test]
fn rejects_html_content_type_with_clear_error() {
    let (addr, _listener) = start_mock_rpc_sequence(vec![MockResponse {
        body: "<html><body>502 Bad Gateway</body></html>".to_string(),
        content_type: Some("text/html".to_string()),
    }]);

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let err = fetch_instance_storage_from_rpc_with_provenance(TEST_CONTRACT_ID, &config)
        .expect_err("an HTML response must be rejected");

    assert_eq!(err.kind(), ErrorKind::RpcTransport);
    let msg = err.to_string();
    assert!(
        msg.contains("Content-Type") && msg.contains("text/html"),
        "expected a clear Content-Type error, got: {msg}"
    );
}

#[test]
fn rejects_binary_content_type_with_clear_error() {
    let (addr, _listener) = start_mock_rpc_sequence(vec![MockResponse {
        body: "\u{0}\u{1}\u{2}not-json-binary-data".to_string(),
        content_type: Some("application/octet-stream".to_string()),
    }]);

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let err = fetch_instance_storage_from_rpc_with_provenance(TEST_CONTRACT_ID, &config)
        .expect_err("a binary response must be rejected");

    assert_eq!(err.kind(), ErrorKind::RpcTransport);
    let msg = err.to_string();
    assert!(
        msg.contains("Content-Type") && msg.contains("application/octet-stream"),
        "expected a clear Content-Type error, got: {msg}"
    );
}

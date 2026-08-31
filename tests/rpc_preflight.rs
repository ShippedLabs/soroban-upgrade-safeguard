//! Tests for the RPC connectivity preflight check.
//!
//! These exercise `soroban_upgrade_safeguard::preflight::run_preflight_with_timeout`
//! directly against a hand-rolled mock HTTP server (mirroring the pattern in
//! `tests/rpc_fetch.rs`), plus one end-to-end test through the compiled
//! binary's `preflight` subcommand.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use soroban_upgrade_safeguard::preflight::run_preflight_with_timeout;
use soroban_upgrade_safeguard::rpc::RpcClientConfig;

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];

    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(_) => return String::new(),
        };
        if n == 0 {
            return String::new();
        }
        request.extend_from_slice(&buf[..n]);
    }

    String::from_utf8_lossy(&request).into_owned()
}

fn finish_http_response(stream: &mut std::net::TcpStream, response: &[u8]) {
    let _ = stream.write_all(response);
    let _ = stream.flush();
}

/// Start a mock server that replies to exactly one request with an arbitrary
/// raw HTTP response (status line, headers, and body all caller-controlled).
fn start_mock_response(status_line: &str, headers: &str, body: &str) -> (String, Arc<TcpListener>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let l = Arc::clone(&listener);

    let status_line = status_line.to_string();
    let headers = headers.to_string();
    let body = body.to_string();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = l.accept() {
            read_http_request(&mut stream);
            let response = format!(
                "{status_line}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            finish_http_response(&mut stream, response.as_bytes());
        }
    });

    (addr, listener)
}

/// Start a mock server that accepts the connection but never writes a
/// response, to exercise the request timeout path.
fn start_mock_stall() -> (String, Arc<TcpListener>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock server");
    let addr = listener.local_addr().unwrap().to_string();
    let listener = Arc::new(listener);
    let l = Arc::clone(&listener);

    thread::spawn(move || {
        if let Ok((mut stream, _)) = l.accept() {
            // Read the request so the client isn't blocked writing it, then
            // simply hold the connection open without ever responding.
            read_http_request(&mut stream);
            thread::sleep(Duration::from_secs(5));
        }
    });

    (addr, listener)
}

#[test]
fn preflight_success_reports_all_checks_passing() {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "status": "healthy",
            "latestLedger": 123456
        }
    })
    .to_string();
    let (addr, _listener) = start_mock_response(
        "HTTP/1.0 200 OK",
        "Content-Type: application/json\r\n",
        &body,
    );

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let report = run_preflight_with_timeout(&config, Duration::from_secs(5));

    assert!(report.transport.success, "{:?}", report.transport);
    assert_eq!(report.transport.status_code, Some(200));
    assert!(report.protocol.success, "{:?}", report.protocol);
    assert_eq!(report.protocol.id_matches, Some(true));
    assert!(report.capability.success, "{:?}", report.capability);
    assert_eq!(report.capability.latest_ledger, Some(123456));
    assert!(report.all_passed());
}

#[test]
fn preflight_timeout_reports_transport_failure() {
    let (addr, _listener) = start_mock_stall();

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let report = run_preflight_with_timeout(&config, Duration::from_millis(300));

    assert!(!report.transport.success);
    assert!(report.transport.error.is_some());
    assert!(!report.protocol.success);
    assert!(!report.capability.success);
    assert!(!report.all_passed());
}

#[test]
fn preflight_malformed_response_reports_protocol_failure() {
    let (addr, _listener) = start_mock_response(
        "HTTP/1.0 200 OK",
        "Content-Type: application/json\r\n",
        "this is not json",
    );

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let report = run_preflight_with_timeout(&config, Duration::from_secs(5));

    assert!(report.transport.success);
    assert_eq!(report.transport.status_code, Some(200));
    assert!(!report.protocol.success);
    assert!(
        report
            .protocol
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("not valid JSON"),
        "{:?}",
        report.protocol
    );
    assert!(!report.capability.success);
    assert!(!report.all_passed());
}

#[test]
fn preflight_authentication_failure_reports_transport_ok_but_protocol_and_capability_fail() {
    let (addr, _listener) = start_mock_response(
        "HTTP/1.0 401 Unauthorized",
        "Content-Type: application/json\r\n",
        r#"{"message":"invalid API key"}"#,
    );

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let report = run_preflight_with_timeout(&config, Duration::from_secs(5));

    assert!(report.transport.success);
    assert_eq!(report.transport.status_code, Some(401));
    assert!(!report.protocol.success);
    assert!(
        report
            .protocol
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("authentication failed"),
        "{:?}",
        report.protocol
    );
    assert!(!report.capability.success);
    assert!(
        report
            .capability
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("authentication failed"),
        "{:?}",
        report.capability
    );
    assert!(!report.all_passed());
}

#[test]
fn preflight_id_mismatch_reports_protocol_failure() {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 999,
        "result": { "status": "healthy" }
    })
    .to_string();
    let (addr, _listener) = start_mock_response(
        "HTTP/1.0 200 OK",
        "Content-Type: application/json\r\n",
        &body,
    );

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let report = run_preflight_with_timeout(&config, Duration::from_secs(5));

    assert!(report.transport.success);
    assert_eq!(report.protocol.id_matches, Some(false));
    assert!(!report.protocol.success);
    assert!(!report.all_passed());
}

#[test]
fn preflight_rpc_error_response_passes_protocol_but_fails_capability() {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": { "code": -32601, "message": "method not found" }
    })
    .to_string();
    let (addr, _listener) = start_mock_response(
        "HTTP/1.0 200 OK",
        "Content-Type: application/json\r\n",
        &body,
    );

    let config = RpcClientConfig::new(format!("http://{addr}")).unwrap();
    let report = run_preflight_with_timeout(&config, Duration::from_secs(5));

    assert!(report.transport.success);
    assert!(report.protocol.success, "{:?}", report.protocol);
    assert!(!report.capability.success);
    assert!(
        report
            .capability
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("method not found"),
        "{:?}",
        report.capability
    );
    assert!(!report.all_passed());
}

#[test]
fn preflight_cli_subcommand_exits_zero_on_success() {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "status": "healthy", "latestLedger": 42 }
    })
    .to_string();
    let (addr, _listener) = start_mock_response(
        "HTTP/1.0 200 OK",
        "Content-Type: application/json\r\n",
        &body,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["preflight", "--rpc-url", &format!("http://{addr}")])
        .output()
        .expect("failed to run binary");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    assert!(stdout.contains("Preflight check"));
    assert!(stdout.contains("PASS"));
}

#[test]
fn preflight_cli_subcommand_exits_nonzero_on_auth_failure() {
    let (addr, _listener) = start_mock_response(
        "HTTP/1.0 401 Unauthorized",
        "Content-Type: application/json\r\n",
        r#"{"message":"invalid API key"}"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["preflight", "--rpc-url", &format!("http://{addr}")])
        .output()
        .expect("failed to run binary");

    assert_ne!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout not UTF-8");
    assert!(stdout.contains("FAIL"));
}

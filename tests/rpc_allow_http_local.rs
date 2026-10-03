//! `--allow-http-local` permits plain HTTP for `--rpc-url` only when the
//! host is a loopback address (`localhost`, `127.0.0.1`, `::1`) — a
//! non-local `http://` endpoint must still be rejected even with the
//! flag set, and the rejection must happen before any network request
//! (see `src/rpc.rs`'s `enforce_rpc_url_scheme_policy`, called from
//! `main.rs`'s `rpc_config`).
//!
//! These exercise the comparison mode's "`--contract-id`+`--rpc-url`
//! supplies the OLD build" path (a single WASM positional argument), the
//! same invocation shape `tests/rpc_incomplete_pair.rs` uses for the
//! same flags.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// A contract ID shaped like a real one; never dereferenced in the
/// rejection tests since the scheme policy must fail before any RPC
/// call is attempted.
const TEST_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// An address in the TEST-NET-1 block (RFC 5737): guaranteed
/// non-routable, so an *attempted* connection to it would hang rather
/// than fail instantly. Used to distinguish "rejected before any
/// network request" (fast) from "a request was attempted" (would hang
/// past [`NO_NETWORK_BUDGET`]).
const UNROUTABLE_NON_LOCAL_HTTP_URL: &str = "http://192.0.2.1:1/rpc";

/// Generous upper bound on how long scheme-policy rejection alone
/// should take. An actual attempted connection to
/// [`UNROUTABLE_NON_LOCAL_HTTP_URL`] would not fail this fast.
const NO_NETWORK_BUDGET: Duration = Duration::from_secs(5);

fn wasm_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn allow_http_local_still_rejects_a_non_local_http_endpoint() {
    let start = Instant::now();
    let output = bin()
        .args(["--contract-id", TEST_CONTRACT_ID])
        .args(["--rpc-url", UNROUTABLE_NON_LOCAL_HTTP_URL])
        .arg("--allow-http-local")
        .arg(wasm_fixture("v2.wasm"))
        .output()
        .expect("failed to run binary");
    let elapsed = start.elapsed();

    assert_ne!(
        output.status.code(),
        Some(0),
        "a non-local http:// RPC URL must be rejected even with --allow-http-local"
    );
    assert!(
        elapsed < NO_NETWORK_BUDGET,
        "rejection took {elapsed:?}, long enough that a real network request may have been \
         attempted against {UNROUTABLE_NON_LOCAL_HTTP_URL}; the scheme policy should reject \
         this before any I/O"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("allow-http-local") && stderr.to_lowercase().contains("loopback"),
        "error should explain that --allow-http-local only permits loopback hosts, got: {stderr}"
    );
}

#[test]
fn without_the_flag_a_non_local_http_endpoint_is_also_rejected() {
    // The documented default: no flag at all means HTTPS-only,
    // regardless of host.
    let output = bin()
        .args(["--contract-id", TEST_CONTRACT_ID])
        .args(["--rpc-url", UNROUTABLE_NON_LOCAL_HTTP_URL])
        .arg(wasm_fixture("v2.wasm"))
        .output()
        .expect("failed to run binary");

    assert_ne!(
        output.status.code(),
        Some(0),
        "a plain http:// RPC URL must be rejected by default"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.to_lowercase().contains("https"),
        "error should point at the https:// requirement, got: {stderr}"
    );
}

#[test]
fn allow_http_local_accepts_a_localhost_http_endpoint() {
    // Nothing listens on this port, so once the scheme policy lets the
    // URL through, the CLI will still fail -- but it must fail with a
    // *connection* error (proof an actual attempt was made), not the
    // scheme-policy rejection the two tests above check for.
    let output = bin()
        .args(["--contract-id", TEST_CONTRACT_ID])
        .args(["--rpc-url", "http://localhost:1/rpc"])
        .arg("--allow-http-local")
        .arg(wasm_fixture("v2.wasm"))
        .output()
        .expect("failed to run binary");

    assert_ne!(
        output.status.code(),
        Some(0),
        "nothing listens on this port, so the overall run still fails"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        !stderr.contains("allow-http-local"),
        "a localhost endpoint must not be rejected by the scheme policy, got: {stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("loopback"),
        "a localhost endpoint must not be rejected by the scheme policy, got: {stderr}"
    );
}

#[test]
fn allow_http_local_accepts_a_127_0_0_1_http_endpoint() {
    let output = bin()
        .args(["--contract-id", TEST_CONTRACT_ID])
        .args(["--rpc-url", "http://127.0.0.1:1/rpc"])
        .arg("--allow-http-local")
        .arg(wasm_fixture("v2.wasm"))
        .output()
        .expect("failed to run binary");

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        !stderr.contains("allow-http-local") && !stderr.to_lowercase().contains("loopback"),
        "a 127.0.0.1 endpoint must not be rejected by the scheme policy, got: {stderr}"
    );
}

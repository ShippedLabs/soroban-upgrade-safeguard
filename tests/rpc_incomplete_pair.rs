//! Integration tests for incomplete `--contract-id` / `--rpc-url` pairs.
//!
//! Both flags are required together (`clap`'s `requires` attribute enforces
//! this at argument-parsing time, before any subcommand body runs), but a
//! user can still type only one of the two. These tests check that giving
//! just one half of the pair produces a clear, immediate diagnostic — in
//! both the default comparison mode and `extract` — and, crucially, that no
//! network request is attempted before that diagnostic is produced.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// A contract ID shaped like a real one, but never dereferenced in these
/// tests since the missing half of the pair must fail validation first.
const TEST_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// An address in the TEST-NET-1 block (RFC 5737): guaranteed non-routable, so
/// any attempt to actually connect to it would hang until a connect timeout
/// rather than fail instantly. Used to distinguish "rejected before any
/// network request" from "a request was attempted."
const UNROUTABLE_RPC_URL: &str = "http://192.0.2.1:1";

/// Generous upper bound on how long argument validation alone should take.
/// A real (attempted) connection to [`UNROUTABLE_RPC_URL`] would not fail
/// this fast, so staying under this bound is evidence no request was sent.
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

/// Run `cmd`, asserting it fails quickly (well under [`NO_NETWORK_BUDGET`])
/// with a non-zero exit and stderr that names the missing flag. Returns
/// stderr for any additional, case-specific assertions.
fn assert_rejected_before_any_network_request(mut cmd: Command, missing_flag: &str) -> String {
    let start = Instant::now();
    let output = cmd.output().expect("failed to run binary");
    let elapsed = start.elapsed();

    assert_ne!(
        output.status.code(),
        Some(0),
        "an incomplete --contract-id/--rpc-url pair must not succeed"
    );
    assert!(
        elapsed < NO_NETWORK_BUDGET,
        "rejecting an incomplete pair took {elapsed:?}, which is long enough that a real \
         network request may have been attempted against {UNROUTABLE_RPC_URL}; validation \
         should happen before any I/O"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains(missing_flag),
        "error should name the missing flag '{missing_flag}', got: {stderr}"
    );

    // Belt-and-suspenders: none of the network-layer error messages used
    // elsewhere in this suite (see tests/rpc_fetch.rs) should appear here —
    // their presence would mean a request was actually attempted.
    for telltale in ["RPC request failed", "Connection refused", "timed out"] {
        assert!(
            !stderr.contains(telltale),
            "stderr should not show evidence of an attempted network request \
             (found '{telltale}'), got: {stderr}"
        );
    }

    stderr
}

#[test]
fn comparison_mode_rejects_contract_id_without_rpc_url() {
    let mut cmd = bin();
    cmd.args(["--contract-id", TEST_CONTRACT_ID])
        .arg(wasm_fixture("v2.wasm"));
    assert_rejected_before_any_network_request(cmd, "--rpc-url");
}

#[test]
fn comparison_mode_rejects_rpc_url_without_contract_id() {
    let mut cmd = bin();
    cmd.args(["--rpc-url", UNROUTABLE_RPC_URL])
        .arg(wasm_fixture("v2.wasm"));
    assert_rejected_before_any_network_request(cmd, "--contract-id");
}

#[test]
fn extract_mode_rejects_contract_id_without_rpc_url() {
    let mut cmd = bin();
    cmd.arg("extract").args(["--contract-id", TEST_CONTRACT_ID]);
    assert_rejected_before_any_network_request(cmd, "--rpc-url");
}

#[test]
fn extract_mode_rejects_rpc_url_without_contract_id() {
    let mut cmd = bin();
    cmd.arg("extract").args(["--rpc-url", UNROUTABLE_RPC_URL]);
    assert_rejected_before_any_network_request(cmd, "--contract-id");
}

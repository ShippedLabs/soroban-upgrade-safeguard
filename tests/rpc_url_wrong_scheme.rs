// SPDX-License-Identifier: MIT
//! Integration test that verifies an RPC URL with a non-HTTP scheme is rejected.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

#[test]
fn rpc_url_with_non_http_scheme_is_rejected() {
    let output = bin()
        .arg("--contract-id")
        .arg("CABCD1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890")
        .arg("--rpc-url")
        .arg("ftp://example.org")
        .arg(wasm("v1.wasm"))
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "command must exit with code 1 when RPC URL has non-HTTP scheme"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must use http:// or https://"),
        "stderr must contain the scheme validation error message, got: {stderr}"
    );
}

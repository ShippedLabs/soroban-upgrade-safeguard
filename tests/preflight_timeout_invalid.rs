//! Integration test for a non-numeric `--timeout-secs` passed to `preflight`.
//!
//! Clap validates the value type before any network connection is attempted,
//! exiting with code 2 on parse error.

use std::process::Command;

#[test]
fn preflight_rejects_non_numeric_timeout_secs() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "preflight",
            "--rpc-url",
            "https://example.org",
            "--timeout-secs",
            "abc",
        ])
        .output()
        .expect("failed to run binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "clap must exit 2 when --timeout-secs is not a valid integer"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr not UTF-8");
    assert!(
        stderr.contains("--timeout-secs"),
        "stderr should name the invalid flag '--timeout-secs', got: {stderr}"
    );
    assert!(
        stderr.contains("abc"),
        "stderr should quote the invalid value 'abc', got: {stderr}"
    );
}

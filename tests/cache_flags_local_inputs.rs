// SPDX-License-Identifier: MIT
//! `--no-remote-cache` and `--no-oci-cache` only apply to `https://` and
//! `oci://` inputs, so they must have no effect on local files.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Compare v1.wasm with itself, returning (parsed JSON report, exit code).
fn compare_v1_with_itself(extra_args: &[&str]) -> (Value, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(["--format", "json", "--no-timestamp"])
        .args(extra_args)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));
    (
        json,
        output.status.code().expect("process terminated by signal"),
    )
}

#[test]
fn cache_bypass_flags_do_not_affect_local_inputs() {
    let (with_flags, code) = compare_v1_with_itself(&["--no-remote-cache", "--no-oci-cache"]);
    assert_eq!(code, 0, "identical local inputs must pass with the flags");

    let (without_flags, code) = compare_v1_with_itself(&[]);
    assert_eq!(
        code, 0,
        "identical local inputs must pass without the flags"
    );

    assert_eq!(
        with_flags, without_flags,
        "the cache flags must not change the report for local inputs"
    );
}

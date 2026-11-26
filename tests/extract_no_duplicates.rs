// SPDX-License-Identifier: MIT
//! Integration test covering the `extract --no-duplicates` flag.

use serde_json::Value;
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

fn extract(args: &[&str]) -> (String, i32) {
    let output = bin()
        .arg("extract")
        .args(args)
        .output()
        .expect("failed to run binary");

    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

#[test]
fn extract_no_duplicates_omits_duplicates_field() {
    let path = wasm("v1.wasm");
    let path_str = path.to_str().expect("valid path string");

    // 1. Without --no-duplicates, duplicates must be present
    let (stdout_default, code_default) = extract(&[path_str]);
    assert_eq!(code_default, 0, "extract must succeed on v1.wasm");
    let json_default: Value =
        serde_json::from_str(&stdout_default).expect("stdout must be valid JSON");
    assert!(
        json_default.get("duplicates").is_some(),
        "default extraction must include duplicates key"
    );

    // 2. With --no-duplicates, duplicates is absent while env_meta and scope are present
    let (stdout_no_duplicates, code_no_duplicates) = extract(&[path_str, "--no-duplicates"]);
    assert_eq!(
        code_no_duplicates, 0,
        "extract --no-duplicates must succeed on v1.wasm"
    );
    let json_no_duplicates: Value =
        serde_json::from_str(&stdout_no_duplicates).expect("stdout must be valid JSON");

    assert!(
        json_no_duplicates.get("duplicates").is_none(),
        "extract --no-duplicates must omit duplicates"
    );
    assert!(
        json_no_duplicates.get("env_meta").is_some(),
        "extract --no-duplicates must preserve env_meta"
    );
    assert!(
        json_no_duplicates.get("scope").is_some(),
        "extract --no-duplicates must preserve scope"
    );
}

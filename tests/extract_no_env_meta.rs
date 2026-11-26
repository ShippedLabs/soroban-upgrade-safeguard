// SPDX-License-Identifier: MIT
//! Integration test covering the `extract --no-env-meta` flag.

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
fn extract_no_env_meta_omits_env_meta_field() {
    let path = wasm("v1.wasm");
    let path_str = path.to_str().expect("valid path string");

    // 1. Without --no-env-meta, env_meta must be present
    let (stdout_default, code_default) = extract(&[path_str]);
    assert_eq!(code_default, 0, "extract must succeed on v1.wasm");
    let json_default: Value =
        serde_json::from_str(&stdout_default).expect("stdout must be valid JSON");
    assert!(
        json_default.get("env_meta").is_some(),
        "default extraction must include env_meta key"
    );

    // 2. With --no-env-meta, env_meta is absent while scope and duplicates are present
    let (stdout_no_meta, code_no_meta) = extract(&[path_str, "--no-env-meta"]);
    assert_eq!(
        code_no_meta, 0,
        "extract --no-env-meta must succeed on v1.wasm"
    );
    let json_no_meta: Value =
        serde_json::from_str(&stdout_no_meta).expect("stdout must be valid JSON");

    assert!(
        json_no_meta.get("env_meta").is_none(),
        "extract --no-env-meta must omit env_meta"
    );
    assert!(
        json_no_meta.get("scope").is_some(),
        "extract --no-env-meta must preserve scope"
    );
    assert!(
        json_no_meta.get("duplicates").is_some(),
        "extract --no-env-meta must preserve duplicates"
    );
}

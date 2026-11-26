// SPDX-License-Identifier: MIT
//! Integration coverage for environment metadata findings and exit codes.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run_json(old: &str, new: &str) -> (Value, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("stdout was not valid JSON");
    let code = output.status.code().expect("process terminated by signal");

    (json, code)
}

#[test]
fn identical_fixtures_have_no_environment_findings() {
    let (json, code) = run_json("v1.wasm", "v1.wasm");

    assert_eq!(code, 0);
    assert!(
        json["findings_by_category"]["Environment"].is_null(),
        "identical env metadata must not produce Environment findings"
    );
}

#[test]
fn breaking_upgrade_exit_code_is_driven_by_critical_findings() {
    let (json, code) = run_json("v1.wasm", "v2.wasm");

    assert_eq!(code, 1, "breaking spec changes must still exit 1");
    assert!(
        json["counts"]["critical"].as_u64().unwrap() >= 1,
        "breaking upgrade must report critical findings"
    );
}

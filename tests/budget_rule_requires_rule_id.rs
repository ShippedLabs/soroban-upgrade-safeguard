// SPDX-License-Identifier: MIT
//! Test that a [[budget]] with scope rule requires a rule_id.

use std::fs;
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

fn temp_config(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "safeguard-budget-test-{}-{}.toml",
        name,
        std::process::id()
    ))
}

#[test]
fn budget_with_scope_rule_requires_rule_id() {
    let config_path = temp_config("rule-no-id");
    let config_content = r#"
[[budget]]
scope = "rule"
metric = "raw"
limit = 1
"#;
    fs::write(&config_path, config_content).expect("failed to write test config");

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "budget with scope=rule and no rule_id must exit 1, stderr: {stderr}"
    );
    assert!(
        stderr.contains("rule_id") && (stderr.contains("required") || stderr.contains("requires")),
        "stderr must mention rule_id is required, got: {stderr}"
    );

    fs::remove_file(&config_path).ok();
}

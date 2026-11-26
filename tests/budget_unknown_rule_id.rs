// SPDX-License-Identifier: MIT
//! Test that a [[budget]] with an unknown rule_id is rejected.

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
fn budget_with_unknown_rule_id_is_rejected() {
    let config_path = temp_config("unknown-rule");
    let config_content = r#"
[[budget]]
scope = "rule"
rule_id = "not_a_real_rule_id"
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
        "comparison with unknown rule_id must exit 1, stderr: {stderr}"
    );
    assert!(
        stderr.contains("unknown rule_id") || stderr.contains("unknown rule"),
        "stderr must mention unknown rule_id, got: {stderr}"
    );

    fs::remove_file(&config_path).ok();
}

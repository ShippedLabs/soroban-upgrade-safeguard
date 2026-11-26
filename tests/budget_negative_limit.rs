// SPDX-License-Identifier: MIT
//! Test that a negative [[budget]] limit is rejected by --validate-config.
//!
//! A config with `limit = -1` must exit 1 with an error message stating
//! "budget #1: limit must not be negative (got -1)".

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn temp_config_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "safeguard-budget-negative-{name}-{}.toml",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn negative_budget_limit_is_rejected() {
    let config_path = temp_config_path("limit");

    // Create a config with a negative budget limit
    let config_content = r#"
[[budget]]
scope = "global"
limit = -1
"#;

    fs::write(&config_path, config_content).expect("failed to write config file");

    let output = bin()
        .arg("--validate-config")
        .arg(&config_path)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert_eq!(
        output.status.code(),
        Some(1),
        "negative budget limit must exit 1, output: {combined}"
    );

    assert!(
        combined.contains("limit must not be negative"),
        "error must mention 'limit must not be negative', got: {combined}"
    );

    assert!(
        combined.contains("-1"),
        "error must mention the negative value -1, got: {combined}"
    );

    let _ = fs::remove_file(&config_path);
}

#[test]
fn multiple_negative_budget_limits_all_reported() {
    let config_path = temp_config_path("multiple");

    // Create a config with multiple negative budget limits
    let config_content = r#"
[[budget]]
scope = "global"
limit = -1

[[budget]]
scope = "axis"
axis = "storage_layout"
limit = -5

[[budget]]
scope = "global"
limit = -10
"#;

    fs::write(&config_path, config_content).expect("failed to write config file");

    let output = bin()
        .arg("--validate-config")
        .arg(&config_path)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert_eq!(
        output.status.code(),
        Some(1),
        "multiple negative budget limits must exit 1, output: {combined}"
    );

    // All three negative limits should be reported
    assert!(
        combined.contains("budget #1") && combined.contains("-1"),
        "error must mention budget #1 with value -1, got: {combined}"
    );

    assert!(
        combined.contains("budget #2") && combined.contains("-5"),
        "error must mention budget #2 with value -5, got: {combined}"
    );

    assert!(
        combined.contains("budget #3") && combined.contains("-10"),
        "error must mention budget #3 with value -10, got: {combined}"
    );

    let _ = fs::remove_file(&config_path);
}

#[test]
fn zero_budget_limit_is_accepted() {
    let config_path = temp_config_path("zero");

    // Zero should be a valid limit (means no findings allowed)
    let config_content = r#"
[[budget]]
scope = "global"
limit = 0
"#;

    fs::write(&config_path, config_content).expect("failed to write config file");

    let output = bin()
        .arg("--validate-config")
        .arg(&config_path)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(0),
        "zero budget limit must be valid, stderr: {stderr}"
    );

    assert!(
        stdout.contains("Config is valid") || stdout.contains("valid"),
        "must confirm config is valid, got: {stdout}"
    );

    let _ = fs::remove_file(&config_path);
}

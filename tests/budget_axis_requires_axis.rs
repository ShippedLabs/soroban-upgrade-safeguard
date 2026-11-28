// SPDX-License-Identifier: MIT
//! Test that a [[budget]] with scope = "axis" requires an axis field.

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
        "safeguard-budget-{}-{}.toml",
        name,
        std::process::id()
    ))
}

#[test]
fn budget_axis_scope_without_axis_field_is_rejected() {
    let config_path = temp_config("axis-no-field");
    
    // Write a config with an axis budget that is missing the axis field
    let config_content = r#"
[[budget]]
scope = "axis"
metric = "raw"
limit = 1
"#;
    
    fs::write(&config_path, config_content).expect("failed to write config");
    
    // Run a comparison with this config
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("failed to run binary");
    
    // Should exit with code 1
    assert_eq!(
        output.status.code(),
        Some(1),
        "comparison with an axis budget missing axis field must fail"
    );
    
    // Error message should say an axis field is required
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("axis") && stderr.contains("requires") && stderr.contains("axis"),
        "error should mention that axis scope requires an axis field, got: {stderr}"
    );
    
    // Clean up
    let _ = fs::remove_file(&config_path);
}

#[test]
fn budget_axis_scope_with_axis_field_is_accepted() {
    let config_path = temp_config("axis-with-field");
    
    // Write a config with an axis budget that includes the axis field
    let config_content = r#"
[[budget]]
scope = "axis"
axis = "storage_layout"
metric = "raw"
limit = 100
"#;
    
    fs::write(&config_path, config_content).expect("failed to write config");
    
    // Run a comparison with this config
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--config")
        .arg(&config_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run binary");
    
    // Should succeed (exit code depends on findings, but config should be valid)
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("axis") || !stderr.contains("requires"),
        "should not complain about missing axis field when it is present, got: {stderr}"
    );
    
    // Clean up
    let _ = fs::remove_file(&config_path);
}

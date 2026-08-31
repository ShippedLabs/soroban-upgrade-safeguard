//! Integration tests for multi-format output (`--output` flag).
//!
//! These verify that the binary correctly emits the same analysis to
//! multiple formats and destinations in a single run.

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn multi_format_output_to_files() {
    let tmp = std::env::temp_dir().join(format!("safeguard_multi_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let json_path = tmp.join("report.json");
    let md_path = tmp.join("report.md");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--output", &format!("json:{}", json_path.display())])
        .args(["--output", &format!("markdown:{}", md_path.display())])
        .output()
        .expect("failed to run binary");

    // Should exit with failure (breaking changes)
    assert_eq!(output.status.code(), Some(1));

    // Verify JSON file was written
    assert!(
        json_path.exists(),
        "JSON report file should exist at {:?}",
        json_path
    );
    let json_content = std::fs::read_to_string(&json_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_content).unwrap();
    assert_eq!(json["is_safe"], serde_json::Value::Bool(false));
    assert!(json["recommended_bump"].as_str().unwrap_or("") == "major");

    // Verify Markdown file was written
    assert!(
        md_path.exists(),
        "Markdown report file should exist at {:?}",
        md_path
    );
    let md_content = std::fs::read_to_string(&md_path).unwrap();
    assert!(md_content.contains("# Soroban Upgrade Safety Report"));
    assert!(md_content.contains("### Summary Table"));

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn multi_format_with_stdout_and_file() {
    let tmp = std::env::temp_dir().join(format!(
        "safeguard_multi_stdout_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let json_path = tmp.join("report.json");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "markdown"])
        .args(["--output", &format!("json:{}", json_path.display())])
        .output()
        .expect("failed to run binary");

    // Should exit with failure
    assert_eq!(output.status.code(), Some(1));

    // stdout should have markdown
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("# Soroban Upgrade Safety Report"),
        "stdout should contain markdown report"
    );

    // JSON file should exist
    assert!(json_path.exists());
    let json_content = std::fs::read_to_string(&json_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_content).unwrap();
    assert_eq!(json["is_safe"], serde_json::Value::Bool(false));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn output_flag_invalid_format_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--output", "invalid:path.txt"])
        .output()
        .expect("failed to run binary");

    // Should fail with parse error
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("Invalid format"),
        "stderr should mention invalid format: {stderr}"
    );
}

#[test]
fn output_flag_format_only_to_stdout() {
    // --output json (no path) should write JSON to stdout
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(["--output", "json"])
        .output()
        .expect("failed to run binary");

    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["is_safe"], serde_json::Value::Bool(true));
}

#[test]
fn default_format_is_text_to_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .output()
        .expect("failed to run binary");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("SOROBAN UPGRADE SAFETY REPORT"));
    assert!(stdout.contains("Critical:"));
    assert!(stdout.contains("Warnings:"));
}

#[test]
fn output_spec_multiple_separators_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--output", "json:report:extra.json"])
        .output()
        .expect("failed to run binary");

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("contains multiple format separators"),
        "stderr should explain that multiple format separators are rejected: {stderr}"
    );
    assert!(
        stderr.contains("json:report:extra.json"),
        "stderr should identify the malformed value: {stderr}"
    );
    assert!(
        stderr.contains("FORMAT:PATH"),
        "stderr should show valid format example: {stderr}"
    );
}

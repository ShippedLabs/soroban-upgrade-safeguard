//! Integration tests for provenance metadata embedded in reports.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn json_output_contains_provenance() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));

    // Check provenance field exists
    let provenance = json
        .get("provenance")
        .expect("JSON output must contain a 'provenance' field");
    assert!(
        provenance.get("tool_version").is_some(),
        "provenance must have tool_version"
    );
    assert!(
        provenance.get("timestamp").is_some(),
        "provenance must have timestamp"
    );
    assert!(
        provenance.get("inputs").is_some(),
        "provenance must have inputs"
    );
}

#[test]
fn json_output_no_timestamp_suppresses_timestamp() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json", "--no-timestamp"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));

    let provenance = json.get("provenance").expect("provenance must exist");
    let timestamp = provenance
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        timestamp.is_empty(),
        "timestamp should be empty with --no-timestamp, got: '{timestamp}'"
    );

    // Tool version should still be present
    let tool_version = provenance
        .get("tool_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        !tool_version.is_empty(),
        "tool_version should be present even with --no-timestamp"
    );
}

#[test]
fn markdown_output_contains_provenance() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "markdown"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        stdout.contains("###### Provenance"),
        "Markdown output should contain Provenance heading"
    );
    assert!(
        stdout.contains("soroban-upgrade-safeguard v"),
        "Markdown output should contain tool version"
    );
    assert!(
        stdout.contains("**Tool**"),
        "Markdown output should contain Tool label"
    );
}

#[test]
fn text_output_contains_provenance() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "text"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        stdout.contains("Tool:"),
        "Text output should contain Tool label"
    );
    assert!(
        stdout.contains("v0.") || stdout.contains("v1."),
        "Text output should contain tool version"
    );
}

#[test]
fn deterministic_json_produces_identical_output() {
    // Run twice with --no-timestamp and verify JSON output is identical
    let run = |strict: bool| -> String {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
        cmd.args([wasm("v1.wasm"), wasm("v2.wasm")])
            .args(["--format", "json", "--no-timestamp"]);
        if strict {
            cmd.arg("--strict");
        }
        let output = cmd.output().expect("failed to run binary");
        String::from_utf8(output.stdout).unwrap()
    };

    let first = run(false);
    let second = run(false);

    assert_eq!(
        first, second,
        "JSON output with --no-timestamp should be deterministic"
    );
}

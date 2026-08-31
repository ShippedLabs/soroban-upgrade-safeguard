use serde_json::Value;
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
fn text_explain_mode_attaches_remediation_guidance() {
    // 1. Without --explain
    let output_no_explain = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .output()
        .expect("failed to run binary");

    let stdout_no_explain = String::from_utf8(output_no_explain.stdout).unwrap();
    assert!(
        !stdout_no_explain.contains("↳ guidance:"),
        "Without --explain, output should not contain guidance"
    );

    // 2. With --explain
    let output_explain = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--explain")
        .output()
        .expect("failed to run binary");

    let stdout_explain = String::from_utf8(output_explain.stdout).unwrap();
    assert!(
        stdout_explain.contains("↳ guidance:"),
        "With --explain, output should contain guidance"
    );
    assert!(
        stdout_explain.contains("Removing fields breaks serialized storage layouts. Restore the field or perform a state migration."),
        "Should show remediation message"
    );

    // 3. Exit codes must be identical
    assert_eq!(
        output_no_explain.status.code(),
        output_explain.status.code()
    );
}

#[test]
fn json_explain_mode_includes_remediation_field() {
    // 1. Without --explain
    let output_no_explain = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout_no_explain = String::from_utf8(output_no_explain.stdout).unwrap();
    let json_no_explain: Value = serde_json::from_str(&stdout_no_explain).unwrap();

    // 2. With --explain
    let output_explain = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json", "--explain"])
        .output()
        .expect("failed to run binary");

    let stdout_explain = String::from_utf8(output_explain.stdout).unwrap();
    let json_explain: Value = serde_json::from_str(&stdout_explain).unwrap();

    // Check that without --explain, no findings have "remediation" key.
    let categories_no_explain = json_no_explain["findings_by_category"]
        .as_object()
        .expect("findings_by_category must be an object");
    for (_cat, findings) in categories_no_explain {
        for finding in findings.as_array().unwrap() {
            assert!(
                finding.get("remediation").is_none(),
                "Should not have remediation key without --explain"
            );
        }
    }

    // Check that with --explain, findings have the "remediation" key populated.
    let categories_explain = json_explain["findings_by_category"]
        .as_object()
        .expect("findings_by_category must be an object");
    let mut saw_remediation = false;
    for (_cat, findings) in categories_explain {
        for finding in findings.as_array().unwrap() {
            if let Some(rem) = finding.get("remediation") {
                assert!(rem.is_string());
                assert!(!rem.as_str().unwrap().is_empty());
                saw_remediation = true;
            }
            // Ensure the stable rule identifier is present in explain JSON too.
            assert!(
                finding.get("rule_id").is_some(),
                "explain JSON finding missing rule_id"
            );
            assert!(finding["rule_id"].is_string());
        }
    }
    assert!(
        saw_remediation,
        "At least one finding must have remediation populated with --explain"
    );
}

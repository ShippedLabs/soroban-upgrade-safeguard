//! Integration tests for the `--format json` machine-readable output.
//!
//! These run the compiled binary against the checked-in WASM fixtures and
//! assert on the parsed JSON structure and exit code, mirroring how a CI
//! system would consume the tool.

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

/// Run the binary with `--format json` on the given pair and return
/// (parsed JSON, exit code, raw stdout).
fn run_json(old: &str, new: &str) -> (Value, i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));
    let code = output.status.code().expect("process terminated by signal");

    (json, code, stdout)
}

#[test]
fn json_breaking_upgrade_reports_critical_and_exits_one() {
    let (json, code, stdout) = run_json("v1.wasm", "v2.wasm");

    // Exit code must signal failure when a Critical finding exists.
    assert_eq!(code, 1, "breaking upgrade must exit 1");

    // Stable top-level structure.
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert!(json["counts"]["critical"].as_u64().unwrap() >= 1);
    assert_eq!(
        json["total_findings"].as_u64().unwrap(),
        json["counts"]["critical"].as_u64().unwrap()
            + json["counts"]["warning"].as_u64().unwrap()
            + json["counts"]["info"].as_u64().unwrap(),
        "total_findings must equal the sum of severity counts"
    );

    // Every finding carries severity, category, and message; at least one is
    // critical and severities use the lowercase wire format.
    let categories = json["findings_by_category"]
        .as_object()
        .expect("findings_by_category must be an object");
    let mut saw_critical = false;
    for (_category, findings) in categories {
        for finding in findings.as_array().expect("findings must be an array") {
            let severity = finding["severity"]
                .as_str()
                .expect("severity must be a string");
            assert!(
                matches!(severity, "critical" | "warning" | "info"),
                "unexpected severity: {severity}"
            );
            assert!(
                finding["category"].is_string(),
                "finding must have a category"
            );
            assert!(
                finding["message"].is_string(),
                "finding must have a message"
            );
            if severity == "critical" {
                saw_critical = true;
            }
        }
    }
    assert!(
        saw_critical,
        "breaking upgrade must contain a critical finding"
    );

    // JSON stdout must be free of ANSI color codes.
    assert!(
        !stdout.contains('\u{1b}'),
        "JSON output must not contain ANSI codes"
    );
}

#[test]
fn json_identical_upgrade_is_safe_and_exits_zero() {
    let (json, code, stdout) = run_json("v1.wasm", "v1.wasm");

    assert_eq!(code, 0, "non-breaking upgrade must exit 0");
    assert_eq!(json["is_safe"], Value::Bool(true));
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 0);
    assert!(
        !stdout.contains('\u{1b}'),
        "JSON output must not contain ANSI codes"
    );
}

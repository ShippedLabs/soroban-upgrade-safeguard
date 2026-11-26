// SPDX-License-Identifier: MIT
//! Integration tests for the `lint` subcommand CLI surface.

use std::path::PathBuf;
use std::process::Command;

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn lint(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("lint")
        .args(args)
        .output()
        .expect("failed to run lint subcommand")
}

#[test]
fn lint_help_lists_github_actions_format() {
    let output = lint(&["--help"]);
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("github-actions"));
}

#[test]
fn lint_github_actions_emits_warning_annotations() {
    let wasm = fixture("tests/wasm/v1.wasm");
    let schema = fixture("tests/fixtures/lint/warning_only_storage_schema.json");
    let output = lint(&[
        wasm.to_str().unwrap(),
        "--storage-schema",
        schema.to_str().unwrap(),
        "--format",
        "github-actions",
    ]);
    let annotations = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success());
    assert!(annotations.lines().any(|line| line.starts_with("::warning::")));
    assert!(annotations.lines().all(|line| line.starts_with("::")));
}

#[test]
fn lint_errors_clearly_when_no_input_is_given() {
    let output = lint(&[]);

    assert!(
        !output.status.success(),
        "lint with neither a WASM path nor an RPC source must fail"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    assert!(
        stderr.contains("Missing WASM path"),
        "error must clearly state that the WASM path is missing. stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("--contract-id"),
        "error must mention the RPC alternative (--contract-id). stderr:\n{stderr}"
    );
}

#[test]
fn lint_exits_zero_on_clean_valid_spec() {
    let wasm = fixture("tests/wasm/v1.wasm");

    let output = lint(&[wasm.to_str().unwrap(), "--format", "json"]);

    assert!(
        output.status.success(),
        "lint on a structurally clean spec must exit zero. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format json output must be valid JSON");

    assert_eq!(
        report["summary"]["errors"], 0,
        "a clean spec must report no error-severity findings. report:\n{stdout}"
    );
    assert!(
        report["findings"]
            .as_array()
            .expect("report must have a findings array")
            .is_empty(),
        "a clean spec must report no findings at all. report:\n{stdout}"
    );
}

#[test]
fn lint_exits_with_error_code_on_invalid_spec() {
    let wasm = fixture("tests/wasm/v1.wasm");
    let schema = fixture("tests/fixtures/lint/empty_declaration_name.json");

    let output = lint(&[
        wasm.to_str().unwrap(),
        "--storage-schema",
        schema.to_str().unwrap(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "lint must exit with the documented lint-error status (2) on a structurally invalid input. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    assert!(
        stdout.contains("[ERROR]") && stdout.contains("storage-schema-invalid"),
        "the error-severity finding must be reported in the output. stdout:\n{stdout}"
    );
}

#[test]
fn lint_strict_exits_with_strict_code_on_warnings_only() {
    let wasm = fixture("tests/wasm/v1.wasm");
    let schema = fixture("tests/fixtures/lint/warning_only_storage_schema.json");

    let output = lint(&[
        wasm.to_str().unwrap(),
        "--storage-schema",
        schema.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(
        output.status.success(),
        "lint without --strict must exit zero when only warning/info findings are present. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format json output must be valid JSON");
    assert_eq!(
        report["summary"]["errors"], 0,
        "fixture must produce no error-severity findings. report:\n{stdout}"
    );
    assert!(
        report["summary"]["warnings"].as_u64().unwrap_or(0) > 0,
        "fixture must produce at least one warning-severity finding. report:\n{stdout}"
    );

    let strict_output = lint(&[
        wasm.to_str().unwrap(),
        "--storage-schema",
        schema.to_str().unwrap(),
        "--strict",
    ]);
    assert_eq!(
        strict_output.status.code(),
        Some(3),
        "lint --strict must exit with the documented strict status (3) when only warning/info findings are present. stderr:\n{}",
        String::from_utf8_lossy(&strict_output.stderr)
    );
}

#[test]
fn lint_validates_declared_storage_schema_against_spec() {
    let wasm = fixture("tests/wasm/v1.wasm");
    let schema = fixture("tests/fixtures/lint/invalid_storage_schema.json");

    let output = lint(&[
        wasm.to_str().unwrap(),
        "--storage-schema",
        schema.to_str().unwrap(),
        "--format",
        "json",
    ]);

    // A structurally invalid declared schema is surfaced as an error-severity
    // lint finding (LINT_EXIT_ERROR), not a hard CLI failure: see the comment
    // in `run_lint` explaining this is deliberate.
    assert_eq!(
        output.status.code(),
        Some(2),
        "lint must exit with the lint-error status when the declared schema is invalid. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format json output must be valid JSON");

    let findings = report["findings"]
        .as_array()
        .expect("report must have a findings array");
    assert!(
        findings
            .iter()
            .any(|f| f["rule_id"] == "storage-schema-invalid"),
        "an invalid declared storage schema must produce a storage-schema-invalid finding. report:\n{stdout}"
    );
}

#[test]
fn lint_format_json_emits_parseable_json_carrying_the_findings() {
    let wasm = fixture("tests/wasm/v1.wasm");
    let schema = fixture("tests/fixtures/lint/warning_only_storage_schema.json");

    let output = lint(&[
        wasm.to_str().unwrap(),
        "--storage-schema",
        schema.to_str().unwrap(),
        "--format",
        "json",
    ]);

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("--format json output must be valid, parseable JSON");

    let findings = report["findings"]
        .as_array()
        .expect("report must have a findings array");
    assert!(
        !findings.is_empty(),
        "fixture must produce at least one finding. report:\n{stdout}"
    );
    assert_eq!(
        findings.len(),
        report["summary"]["warnings"].as_u64().unwrap() as usize
            + report["summary"]["errors"].as_u64().unwrap() as usize
            + report["summary"]["infos"].as_u64().unwrap() as usize,
        "findings array length must match the summary counts. report:\n{stdout}"
    );

    for finding in findings {
        assert!(
            finding["rule_id"].is_string(),
            "each finding must carry a rule_id. report:\n{stdout}"
        );
        assert!(
            finding["severity"].is_string(),
            "each finding must carry a severity. report:\n{stdout}"
        );
        assert!(
            finding["message"].is_string() && !finding["message"].as_str().unwrap().is_empty(),
            "each finding must carry a non-empty message. report:\n{stdout}"
        );
    }
}

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

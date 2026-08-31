//! Integration tests for the `upgrade-report` subcommand and the report
//! migration framework, exercised end-to-end through the built binary.
//!
//! Fixtures live under `tests/fixtures/report_migrations/`, one file per
//! schema version, frozen so a future schema change cannot silently alter
//! what "a version 0 report" means for these tests.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("report_migrations")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture '{}': {e}", path.display()))
}

/// Feed a document to `upgrade-report` over stdin, returning (stdout, stderr,
/// exit code).
fn upgrade(json: &str) -> (String, String, i32) {
    let mut child = bin()
        .arg("upgrade-report")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(json.as_bytes())
        .expect("failed to write report to stdin");

    let output = child.wait_with_output().expect("failed to wait for binary");
    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

// ── Frozen fixtures ──────────────────────────────────────────────────────────

#[test]
fn version_0_fixture_has_no_report_schema_version_field() {
    let json: serde_json::Value = serde_json::from_str(&fixture("v0_legacy.json")).unwrap();
    assert!(
        json.as_object()
            .unwrap()
            .get("report_schema_version")
            .is_none(),
        "the v0 fixture must not carry the field at all — that absence is what makes it v0"
    );
}

#[test]
fn version_1_fixture_declares_schema_version_1() {
    let json: serde_json::Value = serde_json::from_str(&fixture("v1_current.json")).unwrap();
    assert_eq!(json["report_schema_version"], 1);
}

// ── upgrade-report: migration ────────────────────────────────────────────────

#[test]
fn a_version_0_fixture_migrates_to_current_with_recorded_history() {
    let (stdout, stderr, code) = upgrade(&fixture("v0_legacy.json"));
    assert_eq!(code, 0, "stderr: {stderr}");

    let upgraded: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(upgraded["report_schema_version"], 1);

    let migration = &upgraded["migration"];
    assert_eq!(migration["original_schema_version"], 0);
    assert_eq!(migration["migrated_to"], 1);
    assert_eq!(migration["steps"].as_array().unwrap().len(), 1);
    assert_eq!(migration["steps"][0]["from"], 0);
    assert_eq!(migration["steps"][0]["to"], 1);
    assert!(migration["migration_tool_version"].is_string());

    assert!(
        stderr.contains("Migrated from schema version 0 to 1"),
        "got: {stderr}"
    );
}

#[test]
fn a_version_1_fixture_is_a_no_op() {
    let (stdout, stderr, code) = upgrade(&fixture("v1_current.json"));
    assert_eq!(code, 0, "stderr: {stderr}");

    let upgraded: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(upgraded["report_schema_version"], 1);
    assert!(
        upgraded.get("migration").is_none(),
        "an already-current, never-migrated document must not gain a migration record"
    );
    assert!(stderr.contains("nothing to migrate"), "got: {stderr}");
}

#[test]
fn upgrading_twice_is_byte_for_byte_idempotent() {
    let (once, _, code1) = upgrade(&fixture("v0_legacy.json"));
    assert_eq!(code1, 0);
    let (twice, stderr2, code2) = upgrade(&once);
    assert_eq!(code2, 0, "stderr: {stderr2}");

    assert_eq!(once, twice);
    assert!(stderr2.contains("nothing to migrate"), "got: {stderr2}");
}

#[test]
fn migration_preserves_findings_and_axis_verdicts_from_the_v0_fixture() {
    let (stdout, _, code) = upgrade(&fixture("v0_legacy.json"));
    assert_eq!(code, 0);
    let upgraded: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let original: serde_json::Value = serde_json::from_str(&fixture("v0_legacy.json")).unwrap();

    assert_eq!(
        upgraded["findings_by_category"], original["findings_by_category"],
        "findings, rule IDs, targets, and suppressions must survive migration unchanged"
    );
    assert_eq!(upgraded["axis_verdicts"], original["axis_verdicts"]);
    assert_eq!(upgraded["scope"], original["scope"]);
    assert_eq!(
        upgraded["old_interface_hash"],
        original["old_interface_hash"]
    );
    assert_eq!(
        upgraded["new_interface_hash"],
        original["new_interface_hash"]
    );
}

#[test]
fn upgrade_report_writes_to_a_file_with_output_flag() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let out_path = dir.join("upgraded_report.json");

    let mut child = bin()
        .arg("upgrade-report")
        .arg("-")
        .args(["--output", out_path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(fixture("v0_legacy.json").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8(output.stdout).unwrap().is_empty(),
        "with --output, the report body goes to the file, not stdout"
    );

    let written = std::fs::read_to_string(&out_path).unwrap();
    let upgraded: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(upgraded["report_schema_version"], 1);
}

// ── upgrade-report: errors ───────────────────────────────────────────────────

#[test]
fn an_unsupported_future_version_fails_with_a_clear_error() {
    let mut v: serde_json::Value = serde_json::from_str(&fixture("v1_current.json")).unwrap();
    v["report_schema_version"] = serde_json::json!(9999);

    let (stdout, stderr, code) = upgrade(&v.to_string());
    assert_ne!(code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.contains("9999"), "got: {stderr}");
}

#[test]
fn malformed_json_fails_with_a_clear_error() {
    let (stdout, stderr, code) = upgrade("{ not json");
    assert_ne!(code, 0);
    assert!(stdout.is_empty());
    assert!(!stderr.is_empty(), "expected an error message on stderr");
}

#[test]
fn a_non_report_json_document_fails_with_a_clear_error() {
    let (stdout, stderr, code) = upgrade(r#"{"hello": "world"}"#);
    assert_ne!(code, 0);
    assert!(stdout.is_empty());
    assert!(!stderr.is_empty(), "expected an error message on stderr");
}

#[test]
fn a_missing_report_file_fails_with_a_clear_error() {
    let output = bin()
        .arg("upgrade-report")
        .arg("/nonexistent/path/report.json")
        .output()
        .expect("failed to run binary");
    assert_ne!(output.status.code(), Some(0));
}

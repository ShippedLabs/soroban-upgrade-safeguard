//! Regression coverage for zero-byte WASM file diagnostics.
//!
//! An empty file is a common artifact-path mistake and should produce a clear
//! validation error. This test verifies the command fails without a panic and
//! that the diagnostic is distinct from missing-file handling.

use std::path::{Path, PathBuf};
use std::process::Command;

fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

struct Run {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

impl Run {
    fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn run(old: &Path, new: &Path) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(old)
        .arg(new)
        .output()
        .expect("failed to run binary");

    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        code: output.status.code(),
    }
}

#[test]
fn zero_byte_old_wasm_fails_with_validation_error() {
    let dir = temp_dir("zero-byte-old");
    let zero_byte = dir.join("empty.wasm");
    std::fs::write(&zero_byte, b"").expect("failed to write zero-byte file");

    let run = run(&zero_byte, &wasm("v1.wasm"));

    assert_ne!(
        run.code,
        Some(0),
        "zero-byte WASM must fail, not succeed: {}",
        run.combined()
    );

    let combined = run.combined();

    // Must identify the file path
    assert!(
        combined.contains(&zero_byte.display().to_string()) || combined.contains("empty.wasm"),
        "error must name the zero-byte file path, got: {combined}"
    );

    // Must indicate it's a WASM validation problem, not just "file not found"
    assert!(
        combined.contains("WASM") || combined.contains("wasm") || combined.contains("magic"),
        "error must mention WASM validation or magic bytes, got: {combined}"
    );

    // Must not be a file-not-found error (the file exists, it's just invalid)
    assert!(
        !combined.to_lowercase().contains("not found")
            && !combined.to_lowercase().contains("no such file"),
        "error must not be a file-not-found error, got: {combined}"
    );
}

#[test]
fn zero_byte_new_wasm_fails_with_validation_error() {
    let dir = temp_dir("zero-byte-new");
    let zero_byte = dir.join("empty.wasm");
    std::fs::write(&zero_byte, b"").expect("failed to write zero-byte file");

    let run = run(&wasm("v1.wasm"), &zero_byte);

    assert_ne!(
        run.code,
        Some(0),
        "zero-byte WASM must fail, not succeed: {}",
        run.combined()
    );

    let combined = run.combined();

    // Must identify the file path
    assert!(
        combined.contains(&zero_byte.display().to_string()) || combined.contains("empty.wasm"),
        "error must name the zero-byte file path, got: {combined}"
    );

    // Must indicate it's a WASM validation problem
    assert!(
        combined.contains("WASM") || combined.contains("wasm") || combined.contains("magic"),
        "error must mention WASM validation or magic bytes, got: {combined}"
    );
}

#[test]
fn zero_byte_wasm_error_is_distinct_from_missing_file() {
    let dir = temp_dir("zero-vs-missing");

    // Test 1: zero-byte file (exists but invalid)
    let zero_byte = dir.join("zero.wasm");
    std::fs::write(&zero_byte, b"").expect("failed to write zero-byte file");
    let zero_run = run(&zero_byte, &wasm("v1.wasm"));

    // Test 2: missing file (does not exist)
    let missing = dir.join("does_not_exist.wasm");
    let missing_run = run(&missing, &wasm("v1.wasm"));

    // Both must fail
    assert_ne!(zero_run.code, Some(0), "zero-byte must fail");
    assert_ne!(missing_run.code, Some(0), "missing file must fail");

    let zero_combined = zero_run.combined();
    let missing_combined = missing_run.combined();

    // Zero-byte error must mention validation/WASM
    assert!(
        zero_combined.contains("WASM")
            || zero_combined.contains("wasm")
            || zero_combined.contains("magic")
            || zero_combined.contains("valid"),
        "zero-byte error must indicate validation failure, got: {zero_combined}"
    );

    // Missing file error must mention not found
    assert!(
        missing_combined.to_lowercase().contains("not found")
            || missing_combined.to_lowercase().contains("no such file")
            || missing_combined.to_lowercase().contains("does not exist"),
        "missing file error must indicate file not found, got: {missing_combined}"
    );

    // The two errors should be clearly different
    let zero_lower = zero_combined.to_lowercase();
    let missing_lower = missing_combined.to_lowercase();

    // Zero-byte should not say "not found"
    assert!(
        !zero_lower.contains("not found"),
        "zero-byte error must not say 'not found', got: {zero_combined}"
    );

    // Missing should not mention magic bytes (it never got that far)
    assert!(
        !missing_lower.contains("magic"),
        "missing file error must not mention magic bytes, got: {missing_combined}"
    );
}

#[test]
fn both_zero_byte_wasms_fail_with_clear_error() {
    let dir = temp_dir("both-zero");
    let old_zero = dir.join("old_empty.wasm");
    let new_zero = dir.join("new_empty.wasm");

    std::fs::write(&old_zero, b"").expect("failed to write old zero-byte");
    std::fs::write(&new_zero, b"").expect("failed to write new zero-byte");

    let run = run(&old_zero, &new_zero);

    assert_ne!(
        run.code,
        Some(0),
        "both zero-byte must fail: {}",
        run.combined()
    );

    let combined = run.combined();

    // Should mention WASM validation
    assert!(
        combined.contains("WASM") || combined.contains("wasm") || combined.contains("magic"),
        "error must mention WASM validation, got: {combined}"
    );

    // Should identify at least one of the files (may fail on old before checking new)
    assert!(
        combined.contains("old_empty.wasm") || combined.contains("new_empty.wasm"),
        "error must identify a zero-byte file, got: {combined}"
    );
}

#[test]
fn one_byte_wasm_also_fails_with_validation_error() {
    // Not a zero-byte file, but still too short to be valid WASM (header is 4 bytes)
    let dir = temp_dir("one-byte");
    let one_byte = dir.join("truncated.wasm");
    std::fs::write(&one_byte, b"x").expect("failed to write one-byte file");

    let run = run(&one_byte, &wasm("v1.wasm"));

    assert_ne!(
        run.code,
        Some(0),
        "one-byte WASM must fail: {}",
        run.combined()
    );

    let combined = run.combined();

    assert!(
        combined.contains(&one_byte.display().to_string()) || combined.contains("truncated.wasm"),
        "error must name the invalid file, got: {combined}"
    );

    assert!(
        combined.contains("WASM") || combined.contains("wasm") || combined.contains("magic"),
        "error must mention WASM validation, got: {combined}"
    );
}

#[test]
fn three_byte_wasm_fails_validation() {
    // Still one byte short of a complete magic header
    let dir = temp_dir("three-byte");
    let three_byte = dir.join("partial.wasm");
    std::fs::write(&three_byte, b"\0as").expect("failed to write three-byte file");

    let run = run(&three_byte, &wasm("v1.wasm"));

    assert_ne!(
        run.code,
        Some(0),
        "three-byte WASM must fail: {}",
        run.combined()
    );

    let combined = run.combined();

    assert!(
        combined.contains(&three_byte.display().to_string()) || combined.contains("partial.wasm"),
        "error must name the invalid file, got: {combined}"
    );

    assert!(
        combined.contains("WASM") || combined.contains("wasm") || combined.contains("magic"),
        "error must mention WASM validation, got: {combined}"
    );
}

#[test]
fn valid_wasm_does_not_trigger_zero_byte_error() {
    // Regression check: a valid WASM must not be confused with a zero-byte file
    let run = run(&wasm("v1.wasm"), &wasm("v2.wasm"));

    // v1->v2 is breaking, so exit code is 1, but it's a successful run that
    // produced findings, not a file-loading failure
    assert_eq!(
        run.code,
        Some(1),
        "valid WASM comparison must complete (exit 1 for breaking): {}",
        run.combined()
    );

    let combined = run.combined();

    // Must not contain the zero-byte / magic error
    assert!(
        !combined.contains("magic bytes"),
        "valid WASM must not trigger magic byte error, got: {combined}"
    );

    // Must produce actual comparison output
    assert!(
        combined.contains("Function")
            || combined.contains("findings")
            || combined.contains("CRITICAL"),
        "valid WASM comparison must produce findings, got: {combined}"
    );
}

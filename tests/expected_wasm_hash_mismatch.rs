// SPDX-License-Identifier: MIT
//! Integration tests for --expected-wasm-hash validation.
//!
//! --expected-wasm-hash asserts the SHA-256 of the baseline WASM. A mismatch
//! must fail with a clear error naming expected and actual values, while a
//! matching hash allows the comparison to proceed.

use std::path::PathBuf;
use std::process::Command;

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

fn run(args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");

    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout not utf8"),
        stderr: String::from_utf8(output.stderr).expect("stderr not utf8"),
        code: output.status.code(),
    }
}

/// Get the actual SHA-256 hash of a fixture WASM by hashing the file bytes
/// directly — the same digest `--expected-wasm-hash` checks against.
fn get_wasm_sha256(wasm_path: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(wasm_path).expect("fixture wasm must be readable");
    hex::encode(Sha256::digest(&bytes))
}

#[test]
fn mismatching_expected_wasm_hash_fails_with_clear_error() {
    let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        wrong_hash,
    ]);

    assert_ne!(
        run.code,
        Some(0),
        "mismatching hash must fail, combined output:\n{}",
        run.combined()
    );

    let combined = run.combined();

    // Must mention it's a hash mismatch
    assert!(
        combined.to_lowercase().contains("mismatch")
            || combined.to_lowercase().contains("expected"),
        "error must indicate hash mismatch, got:\n{}",
        combined
    );

    // Must show the expected hash
    assert!(
        combined.contains(wrong_hash),
        "error must show expected hash, got:\n{}",
        combined
    );

    // Must show the actual hash (first few chars at least)
    // We don't know the exact hash, but it should appear in the error
    assert!(
        combined.contains("actual"),
        "error must show actual hash label, got:\n{}",
        combined
    );
}

#[test]
fn matching_expected_wasm_hash_allows_comparison_to_proceed() {
    let actual_hash = get_wasm_sha256(wasm("v1.wasm").to_str().unwrap());

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        &actual_hash,
        "--format",
        "json",
    ]);

    assert_eq!(
        run.code,
        Some(1),
        "v1->v2 is breaking, should exit 1, stderr:\n{}",
        run.stderr
    );

    // Must have performed the comparison (produced findings)
    let json: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("output must be valid JSON when hash matches");

    assert!(
        json.get("findings_by_category").is_some(),
        "comparison must have run and produced findings"
    );

    assert!(
        json.get("is_safe").is_some(),
        "comparison must have produced a verdict"
    );

    assert_eq!(json["is_safe"], false, "v1->v2 comparison must be unsafe");
}

#[test]
fn expected_wasm_hash_error_shows_both_expected_and_actual_values() {
    let actual_hash = get_wasm_sha256(wasm("v1.wasm").to_str().unwrap());
    let wrong_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        wrong_hash,
    ]);

    assert_ne!(run.code, Some(0), "mismatch must fail");

    let combined = run.combined();

    // Must show the expected hash (what was passed to --expected-wasm-hash)
    assert!(
        combined.contains(wrong_hash),
        "error must show expected hash '{wrong_hash}', got:\n{}",
        combined
    );

    // Must show the actual hash (from the loaded WASM)
    assert!(
        combined.contains(&actual_hash),
        "error must show actual hash '{actual_hash}', got:\n{}",
        combined
    );
}

#[test]
fn expected_wasm_hash_is_case_insensitive() {
    let actual_hash = get_wasm_sha256(wasm("v1.wasm").to_str().unwrap());
    let uppercase_hash = actual_hash.to_uppercase();

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        &uppercase_hash,
        "--format",
        "json",
    ]);

    assert_eq!(
        run.code,
        Some(1),
        "uppercase hash should match, stderr:\n{}",
        run.stderr
    );

    // Comparison should have run successfully
    let json: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("output must be valid JSON");

    assert!(
        json.get("findings_by_category").is_some(),
        "comparison must have run"
    );
}

#[test]
fn malformed_expected_wasm_hash_is_rejected_as_config_error() {
    // Too short
    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        "abc123",
    ]);

    assert_ne!(run.code, Some(0), "malformed hash must fail");

    let combined = run.combined();

    assert!(
        combined.contains("64") || combined.contains("character"),
        "error must mention required length, got:\n{}",
        combined
    );
}

#[test]
fn non_hex_expected_wasm_hash_is_rejected() {
    let non_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        non_hex,
    ]);

    assert_ne!(run.code, Some(0), "non-hex hash must fail");

    let combined = run.combined();

    assert!(
        combined.to_lowercase().contains("hex")
            || combined.to_lowercase().contains("sha")
            || combined.to_lowercase().contains("digest"),
        "error must indicate hash format issue, got:\n{}",
        combined
    );
}

#[test]
fn expected_wasm_hash_mismatch_error_identifies_baseline_path() {
    let wrong_hash = "1111111111111111111111111111111111111111111111111111111111111111";

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        wrong_hash,
    ]);

    assert_ne!(run.code, Some(0));

    let combined = run.combined();

    // Must identify which file had the mismatch (the baseline)
    assert!(
        combined.contains("v1.wasm"),
        "error must identify the baseline file, got:\n{}",
        combined
    );
}

#[test]
fn expected_wasm_hash_with_correct_hash_exits_with_comparison_verdict() {
    let actual_hash = get_wasm_sha256(wasm("v1.wasm").to_str().unwrap());

    // v1->v1 is safe (exit 0)
    let run_safe = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        &actual_hash,
    ]);

    assert_eq!(
        run_safe.code,
        Some(0),
        "v1->v1 with correct hash should exit 0"
    );

    // v1->v2 is breaking (exit 1)
    let run_breaking = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        &actual_hash,
    ]);

    assert_eq!(
        run_breaking.code,
        Some(1),
        "v1->v2 with correct hash should exit 1"
    );
}

#[test]
fn expected_wasm_hash_fails_before_performing_comparison() {
    let wrong_hash = "2222222222222222222222222222222222222222222222222222222222222222";

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        wrong_hash,
        "--format",
        "json",
    ]);

    assert_ne!(run.code, Some(0), "hash mismatch must fail");

    // Output should NOT be valid comparison JSON (error occurred before comparison)
    let parse_result = serde_json::from_str::<serde_json::Value>(&run.stdout);

    if let Ok(json) = parse_result {
        // If it parsed as JSON, it should not have comparison fields
        assert!(
            json.get("findings_by_category").is_none(),
            "must fail before producing findings, got: {}",
            json
        );
    }

    // Error should be in stderr (or stdout if not JSON mode)
    let combined = run.combined();
    assert!(
        combined.contains("mismatch") || combined.contains("expected"),
        "must show hash mismatch error, got:\n{}",
        combined
    );
}

#[test]
fn expected_wasm_hash_with_mixed_case_matches() {
    let actual_hash = get_wasm_sha256(wasm("v1.wasm").to_str().unwrap());

    // Mix upper and lower case
    let mut mixed_case = String::new();
    for (i, c) in actual_hash.chars().enumerate() {
        if i % 2 == 0 {
            mixed_case.push(c.to_ascii_uppercase());
        } else {
            mixed_case.push(c.to_ascii_lowercase());
        }
    }

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        &mixed_case,
        "--format",
        "json",
    ]);

    assert_eq!(
        run.code,
        Some(1),
        "mixed case hash should match, stderr:\n{}",
        run.stderr
    );

    let json: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("comparison should have run");

    assert!(json.get("findings_by_category").is_some());
}

#[test]
fn expected_wasm_hash_mismatch_provides_helpful_context() {
    let wrong_hash = "3333333333333333333333333333333333333333333333333333333333333333";

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap(),
        "--expected-wasm-hash",
        wrong_hash,
    ]);

    assert_ne!(run.code, Some(0));

    let combined = run.combined().to_lowercase();

    // Error should explain why this matters (wrong build, etc.)
    assert!(
        combined.contains("baseline") || combined.contains("build") || combined.contains("bytes"),
        "error should explain the security/correctness concern, got:\n{}",
        run.combined()
    );
}

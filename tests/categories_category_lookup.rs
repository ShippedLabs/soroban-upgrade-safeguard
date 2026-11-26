// SPDX-License-Identifier: MIT
//! Integration tests for `categories --category <NAME>` single-category lookup.
//!
//! When `--category` is supplied the binary prints one JSON object (not an
//! array) with keys `category`, `severity`, `trigger_description`, and
//! `remediation`, then exits 0.  An unknown name exits non-zero.

use serde_json::Value;
use std::process::Command;

fn categories(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("categories")
        .args(args)
        .output()
        .expect("failed to run categories subcommand")
}

// ---------------------------------------------------------------------------
// Acceptance criteria from issue #1005
// ---------------------------------------------------------------------------

/// `categories --category "Function Removed" --format json` exits 0 and
/// returns a single JSON object whose `category` is `"Function Removed"` and
/// whose `severity` is `"critical"`.
#[test]
fn category_lookup_returns_single_object_with_correct_fields() {
    let output = categories(&["--category", "Function Removed", "--format", "json"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "exit code must be 0 for a known category:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be valid UTF-8");

    // The output is a single JSON object, not an array.
    let entry: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON: {e}\n---stdout---\n{stdout}"));

    assert!(
        entry.is_object(),
        "--category lookup must return a JSON object, not an array or other value"
    );

    assert_eq!(
        entry["category"].as_str(),
        Some("Function Removed"),
        "category field must be 'Function Removed'"
    );

    assert_eq!(
        entry["severity"].as_str(),
        Some("critical"),
        "severity field must be 'critical'"
    );

    // Structural sanity: the remaining required keys must be present and non-empty.
    assert!(
        entry["trigger_description"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "trigger_description must be a non-empty string"
    );
    assert!(
        entry["remediation"].as_str().is_some_and(|s| !s.is_empty()),
        "remediation must be a non-empty string"
    );
}

// ---------------------------------------------------------------------------
// Additional coverage
// ---------------------------------------------------------------------------

/// An unknown category name exits non-zero and prints a helpful error.
#[test]
fn unknown_category_exits_nonzero_with_error_message() {
    let output = categories(&["--category", "No Such Category", "--format", "json"]);

    assert_ne!(
        output.status.code(),
        Some(0),
        "an unknown category name must not exit 0"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No Such Category"),
        "stderr must echo the unknown name, got: {stderr}"
    );
}

/// The lookup is case-insensitive: `"function removed"` resolves to the
/// canonical `"Function Removed"` entry and exits 0.
#[test]
fn category_lookup_is_case_insensitive() {
    let output = categories(&["--category", "function removed", "--format", "json"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "case-insensitive lookup must succeed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be valid UTF-8");
    let entry: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON: {e}\n---stdout---\n{stdout}"));

    // The canonical casing is returned regardless of the query casing.
    assert_eq!(
        entry["category"].as_str(),
        Some("Function Removed"),
        "canonical category name must be returned even when query uses different casing"
    );
    assert_eq!(
        entry["severity"].as_str(),
        Some("critical"),
        "severity must be 'critical'"
    );
}

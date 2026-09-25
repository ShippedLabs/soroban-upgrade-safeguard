//! Integration tests for the `categories` subcommand.
//!
//! The subcommand must list every finding category with its severity and
//! remediation, in both `text` and `json` form, generated from the exact same
//! source of truth the analysis uses ([`FindingCategory::all`]) so the two
//! cannot drift.

use std::process::Command;

use serde_json::Value;
use soroban_upgrade_safeguard::category::FindingCategory;
use soroban_upgrade_safeguard::Severity;

fn categories(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("categories")
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .expect("failed to run categories subcommand")
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::Warning => "Warning",
        Severity::Info => "Info",
    }
}

fn severity_json(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

/// Collapse every run of whitespace into a single space so wrapped output and
/// source-of-truth strings can be compared regardless of line breaks.
fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn text_lists_every_category_with_severity_and_remediation() {
    let output = categories(&["--no-color"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "categories (text) must exit 0:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = normalized(&String::from_utf8(output.stdout).unwrap());

    for cat in FindingCategory::all() {
        assert!(
            stdout.contains(normalized(cat.as_str()).as_str()),
            "text listing must mention category '{}'",
            cat.as_str()
        );
        assert!(
            stdout.contains(normalized(cat.remediation()).as_str()),
            "text listing must include remediation for '{}'",
            cat.as_str()
        );
        // The severity is printed immediately under the category heading, so
        // the "name Severity: <label>" pattern pins it to the right row.
        assert!(
            stdout.contains(
                normalized(&format!(
                    "{} Severity: {}",
                    cat.as_str(),
                    severity_label(cat.severity())
                ))
                .as_str()
            ),
            "text listing must show severity '{}' for '{}'",
            severity_label(cat.severity()),
            cat.as_str()
        );
    }
}

#[test]
fn json_lists_every_category_from_source_of_truth() {
    let output = categories(&["--format", "json", "--no-color"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "categories --format json must exit 0:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let entries: Vec<Value> =
        serde_json::from_str(&stdout).expect("--format json output must be valid JSON");

    let source_of_truth: Vec<FindingCategory> = FindingCategory::all().to_vec();
    assert_eq!(
        entries.len(),
        source_of_truth.len(),
        "JSON listing must contain exactly the categories in FindingCategory::all()"
    );

    for (entry, cat) in entries.iter().zip(source_of_truth.iter()) {
        assert_eq!(
            entry["category"].as_str(),
            Some(cat.as_str()),
            "JSON category must match the source-of-truth string"
        );
        assert_eq!(
            entry["severity"].as_str(),
            Some(severity_json(cat.severity())),
            "JSON severity for '{}' must match the source of truth",
            cat.as_str()
        );
        let trigger = entry["trigger_description"]
            .as_str()
            .unwrap_or_else(|| panic!("'{}' missing trigger_description", cat.as_str()));
        assert_eq!(
            trigger,
            cat.trigger_description(),
            "trigger_description for '{}' must match the source of truth",
            cat.as_str()
        );
        let remediation = entry["remediation"]
            .as_str()
            .unwrap_or_else(|| panic!("'{}' missing remediation", cat.as_str()));
        assert_eq!(
            remediation,
            cat.remediation(),
            "remediation for '{}' must match the source of truth",
            cat.as_str()
        );
    }
}

#[test]
fn output_is_deterministic() {
    let first = categories(&["--no-color"]);
    let second = categories(&["--no-color"]);
    assert_eq!(
        first.status.code(),
        Some(0),
        "categories (text) must exit 0 regardless of run order"
    );
    assert_eq!(
        first.stdout, second.stdout,
        "categories output must be deterministic"
    );
}

#[test]
fn help_lists_categories_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["categories", "--help"])
        .output()
        .expect("failed to run categories --help");
    assert_eq!(
        output.status.code(),
        Some(0),
        "categories --help must exit 0"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("categories"),
        "--help must mention the categories subcommand:\n{stdout}"
    );
    assert!(
        stdout.contains("--format"),
        "--help must document --format:\n{stdout}"
    );
}

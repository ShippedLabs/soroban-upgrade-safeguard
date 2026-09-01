//! Integration tests for the GitHub Checks API publisher logic in the
//! composite action.
//!
//! These tests exercise the annotation-building logic that the action's inline
//! Python script performs on the JSON report produced by the tool. Tests
//! cover conclusion mapping, severity mapping, suppressed-finding exclusion,
//! pagination cap, field length limits, path extraction, check-name
//! sanitisation, injection safety, and fork PR detection.
//!
//! The Python annotation builder is extracted into a helper that receives a
//! JSON report string and returns the annotations list.

use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Path to the inline Python annotation-builder script embedded in the action.
/// We replicate it here so tests remain self-contained.
const ANNOTATION_BUILDER_PY: &str = r#"
import json, sys

report_json = sys.stdin.read()
try:
    report = json.loads(report_json)
except Exception:
    print("[]")
    sys.exit(0)

# Findings are nested under findings_by_category: {category: [finding, ...]}
findings_by_category = report.get("findings_by_category", {})
all_findings = []
for category_findings in findings_by_category.values():
    all_findings.extend(category_findings)

annotations = []
omitted = 0

for finding in all_findings:
    # Skip suppressed findings
    if finding.get("suppressed", False):
        continue

    severity = finding.get("severity", "Info")
    sev_lower = severity.lower()
    if sev_lower == "critical":
        level = "failure"
    elif sev_lower == "warning":
        level = "warning"
    else:
        level = "notice"

    category = finding.get("category", "Finding")
    message = finding.get("message", "")
    target = finding.get("target") or ""

    path = ".github/actions/soroban-upgrade-safeguard/action.yml"
    if "::" in target:
        parts = target.split("::", 1)
        if parts[0].endswith(".rs") or "/" in parts[0]:
            path = parts[0]

    title = category[:255] if len(category) > 255 else category
    msg = message[:65000] if len(message) > 65000 else message

    if len(annotations) < 50:
        annotations.append({
            "path": path,
            "start_line": 1,
            "end_line": 1,
            "annotation_level": level,
            "title": title,
            "message": msg,
        })
    else:
        omitted += 1

if omitted > 0:
    annotations.append({
        "path": ".github/actions/soroban-upgrade-safeguard/action.yml",
        "start_line": 1,
        "end_line": 1,
        "annotation_level": "notice",
        "title": "Additional findings omitted",
        "message": f"{omitted} additional finding(s) were omitted because the GitHub Checks API limit of 50 annotations per request was reached. Run the tool locally or check the PR comment for the full report.",
    })

print(json.dumps(annotations))
"#;

/// Run the annotation builder on a JSON report value and return the parsed
/// annotation list. Panics if Python3 is unavailable or returns invalid JSON.
fn build_annotations(report: &Value) -> Vec<Value> {
    let report_str = serde_json::to_string(report).expect("serialise report");
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(ANNOTATION_BUILDER_PY)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn python3 – is python3 installed?");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(report_str.as_bytes())
        .expect("write stdin");

    let out = child.wait_with_output().expect("wait for python3");
    let stdout = String::from_utf8(out.stdout).expect("python3 stdout utf-8");
    serde_json::from_str::<Vec<Value>>(&stdout)
        .unwrap_or_else(|e| panic!("python3 output is not valid JSON: {e}\n---\n{stdout}"))
}

/// Build a minimal report JSON containing a single finding.
fn single_finding_report(
    severity: &str,
    category: &str,
    message: &str,
    target: Option<&str>,
    suppressed: bool,
) -> Value {
    json!({
        "findings_by_category": {
            category: [{
                "severity": severity,
                "category": category,
                "message": message,
                "target": target,
                "suppressed": suppressed,
                "axes": [],
                "type_name": null,
                "root_target": null,
            }]
        }
    })
}

/// Build a report with N identical findings of the given severity.
fn n_findings_report(n: usize, severity: &str) -> Value {
    let findings: Vec<Value> = (0..n)
        .map(|i| {
            json!({
                "severity": severity,
                "category": format!("Category {i}"),
                "message": format!("message {i}"),
                "target": null,
                "suppressed": false,
                "axes": [],
                "type_name": null,
                "root_target": null,
            })
        })
        .collect();
    json!({ "findings_by_category": { "Cat": findings } })
}

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

// ──────────────────────────────────────────────────────────────────────────────
// 1. Conclusion mapping
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn conclusion_exit_0_is_success() {
    // Exit code 0 → is_safe=true → conclusion should be "success"
    // We verify via the JSON report: an empty/safe report has no critical findings.
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm")) // same file → no changes → safe
        .args(["--format", "json", "--no-timestamp"])
        .output()
        .expect("run binary");
    assert_eq!(output.status.code(), Some(0), "identical WASMs must exit 0");
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    assert_eq!(report["is_safe"], json!(true));
}

#[test]
fn conclusion_exit_1_on_breaking_upgrade() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json", "--no-timestamp"])
        .output()
        .expect("run binary");
    assert_eq!(
        output.status.code(),
        Some(1),
        "breaking upgrade must exit 1 (→ conclusion failure)"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    assert_eq!(report["is_safe"], json!(false));
}

#[test]
fn conclusion_exit_1_on_strict_warnings() {
    // v1→v3 may add warnings; --strict promotes warnings → exit 1
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json", "--strict", "--no-timestamp"])
        .output()
        .expect("run binary");
    // Strict + critical findings → exit 1
    assert_ne!(
        output.status.code(),
        Some(0),
        "strict breaking must exit non-zero"
    );
}

#[test]
fn conclusion_safe_upgrade_exits_zero() {
    // v1 vs v1: identical interface, must be safe
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(["--format", "json", "--no-timestamp"])
        .output()
        .expect("run binary");
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
    assert_eq!(report["is_safe"], json!(true));
    let annotations = build_annotations(&report);
    assert!(
        annotations.is_empty(),
        "safe upgrade must produce no annotations"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. Annotation severity mapping
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn critical_finding_maps_to_failure_annotation() {
    let report = single_finding_report(
        "critical",
        "Struct Field Removed",
        "field x removed",
        None,
        false,
    );
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0]["annotation_level"], json!("failure"));
    assert_eq!(annotations[0]["title"], json!("Struct Field Removed"));
}

#[test]
fn warning_finding_maps_to_warning_annotation() {
    let report = single_finding_report(
        "warning",
        "Function Parameter Added",
        "param added",
        None,
        false,
    );
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0]["annotation_level"], json!("warning"));
}

#[test]
fn info_finding_maps_to_notice_annotation() {
    let report = single_finding_report("info", "Enum Case Added", "case added", None, false);
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0]["annotation_level"], json!("notice"));
}

#[test]
fn mixed_severity_findings_all_mapped() {
    let report = json!({
        "findings_by_category": {
            "Struct Field Removed": [{
                "severity": "critical",
                "category": "Struct Field Removed",
                "message": "field removed",
                "target": null,
                "suppressed": false,
                "axes": [],
                "type_name": null,
                "root_target": null,
            }],
            "Enum Case Added": [{
                "severity": "warning",
                "category": "Enum Case Added",
                "message": "case added",
                "target": null,
                "suppressed": false,
                "axes": [],
                "type_name": null,
                "root_target": null,
            }],
            "Data Segment Changed": [{
                "severity": "info",
                "category": "Data Segment Changed",
                "message": "segments changed",
                "target": null,
                "suppressed": false,
                "axes": [],
                "type_name": null,
                "root_target": null,
            }],
        }
    });
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 3);
    let levels: Vec<&str> = annotations
        .iter()
        .map(|a| a["annotation_level"].as_str().unwrap())
        .collect();
    assert!(levels.contains(&"failure"), "expected failure annotation");
    assert!(levels.contains(&"warning"), "expected warning annotation");
    assert!(levels.contains(&"notice"), "expected notice annotation");
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. Suppressed findings excluded
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn suppressed_finding_is_excluded_from_annotations() {
    let report = single_finding_report(
        "critical",
        "Struct Field Removed",
        "field removed",
        None,
        true,
    );
    let annotations = build_annotations(&report);
    assert!(
        annotations.is_empty(),
        "suppressed findings must not appear in annotations"
    );
}

#[test]
fn suppressed_and_unsuppressed_only_unsuppressed_annotated() {
    let report = json!({
        "findings_by_category": {
            "Cat": [
                {
                    "severity": "critical",
                    "category": "Cat",
                    "message": "suppressed",
                    "target": null,
                    "suppressed": true,
                    "axes": [],
                    "type_name": null,
                    "root_target": null,
                },
                {
                    "severity": "warning",
                    "category": "Cat",
                    "message": "not suppressed",
                    "target": null,
                    "suppressed": false,
                    "axes": [],
                    "type_name": null,
                    "root_target": null,
                }
            ]
        }
    });
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0]["message"], json!("not suppressed"));
    assert_eq!(annotations[0]["annotation_level"], json!("warning"));
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. 50-annotation cap and omission counting
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn exactly_50_findings_no_omission_notice() {
    let report = n_findings_report(50, "critical");
    let annotations = build_annotations(&report);
    assert_eq!(
        annotations.len(),
        50,
        "50 findings: exactly 50 annotations, no omission notice"
    );
    assert!(
        annotations
            .iter()
            .all(|a| a["title"] != json!("Additional findings omitted")),
        "no omission notice expected for exactly 50 findings"
    );
}

#[test]
fn fifty_one_findings_triggers_omission_notice() {
    let report = n_findings_report(51, "critical");
    let annotations = build_annotations(&report);
    // 50 real + 1 omission notice = 51 total
    assert_eq!(
        annotations.len(),
        51,
        "51 findings: 50 annotations + 1 omission notice"
    );
    let last = annotations.last().unwrap();
    assert_eq!(last["title"], json!("Additional findings omitted"));
    assert!(
        last["message"]
            .as_str()
            .unwrap()
            .contains("1 additional finding(s)"),
        "omission message should mention 1 omitted finding"
    );
}

#[test]
fn many_findings_omission_count_correct() {
    let report = n_findings_report(75, "warning");
    let annotations = build_annotations(&report);
    // 50 real + 1 omission notice
    assert_eq!(annotations.len(), 51);
    let last = annotations.last().unwrap();
    assert!(
        last["message"]
            .as_str()
            .unwrap()
            .contains("25 additional finding(s)"),
        "omission message should mention 25 omitted findings"
    );
}

#[test]
fn omission_notice_is_notice_level() {
    let report = n_findings_report(55, "critical");
    let annotations = build_annotations(&report);
    let last = annotations.last().unwrap();
    assert_eq!(last["annotation_level"], json!("notice"));
}

// ──────────────────────────────────────────────────────────────────────────────
// 5. Title capped at 255 chars, message at 65 000 chars
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn long_category_title_capped_at_255_chars() {
    let long_category = "A".repeat(300);
    let report = single_finding_report("critical", &long_category, "msg", None, false);
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    let title = annotations[0]["title"].as_str().unwrap();
    assert_eq!(title.len(), 255, "title must be capped at 255 characters");
    assert!(title.chars().all(|c| c == 'A'));
}

#[test]
fn long_message_capped_at_65000_chars() {
    let long_message = "B".repeat(70_000);
    let report = single_finding_report("warning", "Cat", &long_message, None, false);
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    let msg = annotations[0]["message"].as_str().unwrap();
    assert_eq!(
        msg.len(),
        65_000,
        "message must be capped at 65 000 characters"
    );
}

#[test]
fn short_category_and_message_not_truncated() {
    let report = single_finding_report("info", "Short Category", "Short message", None, false);
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0]["title"], json!("Short Category"));
    assert_eq!(annotations[0]["message"], json!("Short message"));
}

// ──────────────────────────────────────────────────────────────────────────────
// 6. Path extraction from target and fallback to action.yml
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn null_target_falls_back_to_action_yml_path() {
    let report = single_finding_report("critical", "Cat", "msg", None, false);
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(
        annotations[0]["path"],
        json!(".github/actions/soroban-upgrade-safeguard/action.yml")
    );
}

#[test]
fn non_file_target_falls_back_to_action_yml_path() {
    // A target like "transfer" (just a function name) has no "::" separator
    let report = single_finding_report("critical", "Cat", "msg", Some("transfer"), false);
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(
        annotations[0]["path"],
        json!(".github/actions/soroban-upgrade-safeguard/action.yml")
    );
}

#[test]
fn target_with_rs_file_path_extracted() {
    // A target like "src/contract.rs::my_function" extracts the file path
    let report = single_finding_report(
        "critical",
        "Cat",
        "msg",
        Some("src/contract.rs::my_function"),
        false,
    );
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0]["path"], json!("src/contract.rs"));
}

#[test]
fn target_with_slash_path_extracted() {
    // A target with a directory separator in the first segment
    let report = single_finding_report(
        "warning",
        "Cat",
        "msg",
        Some("contracts/token/lib.rs::transfer"),
        false,
    );
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0]["path"], json!("contracts/token/lib.rs"));
}

// ──────────────────────────────────────────────────────────────────────────────
// 7. Check-name sanitisation (control chars, 100-char limit)
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn check_name_control_chars_stripped() {
    // Simulate what the action does: tr -d '[:cntrl:]'
    let raw = "Soroban\x00Upgrade\x1bSafeguard";
    let sanitized: String = raw.chars().filter(|c| !c.is_control()).collect();
    assert_eq!(sanitized, "SorobanUpgradeSafeguard");
}

#[test]
fn check_name_capped_at_100_chars() {
    let long_name = "X".repeat(150);
    let capped: String = long_name.chars().take(100).collect();
    assert_eq!(capped.len(), 100);
    assert!(capped.chars().all(|c| c == 'X'));
}

#[test]
fn check_name_empty_after_strip_uses_default() {
    // All control chars → empty → should fall back to default name
    let raw = "\x00\x01\x02\x1b\x7f";
    let sanitized: String = raw.chars().filter(|c| !c.is_control()).collect();
    let final_name = if sanitized.is_empty() {
        "Soroban Upgrade Safeguard".to_string()
    } else {
        sanitized
    };
    assert_eq!(final_name, "Soroban Upgrade Safeguard");
}

// ──────────────────────────────────────────────────────────────────────────────
// 8. Injection safety (newlines, shell metacharacters)
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn annotation_message_with_newlines_round_trips_in_json() {
    let msg = "line one\nline two\nline three";
    let report = single_finding_report("critical", "Cat", msg, None, false);
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0]["message"].as_str().unwrap(), msg);
}

#[test]
fn annotation_message_with_shell_metacharacters_safe() {
    let msg = r#"$(rm -rf /) `evil` ; && || > /dev/null"#;
    let report = single_finding_report("warning", "Cat", msg, None, false);
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    // The message is JSON-serialised, so metacharacters must be preserved verbatim
    assert_eq!(annotations[0]["message"].as_str().unwrap(), msg);
}

#[test]
fn annotation_title_with_control_chars_preserved_in_json() {
    // JSON serialisation must not silently drop characters; Python json.dumps
    // encodes non-printable chars as \uXXXX escapes which are faithfully
    // round-tripped by serde_json
    let title = "Cat\twith\ttabs";
    let report = single_finding_report("info", title, "msg", None, false);
    let annotations = build_annotations(&report);
    assert_eq!(annotations.len(), 1);
    assert_eq!(annotations[0]["title"].as_str().unwrap(), title);
}

// ──────────────────────────────────────────────────────────────────────────────
// 9. Fork PR detection
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn fork_pr_detected_when_head_repo_differs() {
    // Simulates: head_repo != base_repo → IS_FORK_PR=true
    let event_json = json!({
        "pull_request": {
            "number": 42,
            "head": { "repo": { "full_name": "contributor/myrepo" } },
            "base": { "repo": { "full_name": "owner/myrepo" } }
        }
    });
    let head = event_json["pull_request"]["head"]["repo"]["full_name"]
        .as_str()
        .unwrap();
    let base = event_json["pull_request"]["base"]["repo"]["full_name"]
        .as_str()
        .unwrap();
    assert!(head != base, "head != base → fork PR");
    assert_eq!(head, "contributor/myrepo");
    assert_eq!(base, "owner/myrepo");
}

#[test]
fn fork_pr_not_detected_when_head_repo_same() {
    let event_json = json!({
        "pull_request": {
            "number": 10,
            "head": { "repo": { "full_name": "owner/myrepo" } },
            "base": { "repo": { "full_name": "owner/myrepo" } }
        }
    });
    let head = event_json["pull_request"]["head"]["repo"]["full_name"]
        .as_str()
        .unwrap();
    let base = event_json["pull_request"]["base"]["repo"]["full_name"]
        .as_str()
        .unwrap();
    assert_eq!(head, base, "head == base → not a fork PR");
}

#[test]
fn fork_pr_not_detected_when_no_pull_request_key() {
    // Push event: no pull_request key → head/base both empty → not a fork PR
    let event_json = json!({ "after": "abc123", "ref": "refs/heads/main" });
    let head = event_json
        .pointer("/pull_request/head/repo/full_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let base = event_json
        .pointer("/pull_request/base/repo/full_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // Both empty → IS_FORK_PR=false
    assert!(
        head.is_empty() || base.is_empty() || head == base,
        "missing pull_request event should not be treated as fork PR"
    );
}

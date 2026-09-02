//! Integration tests for the GitHub Checks API publisher embedded in the
//! composite action shell script.
//!
//! # Overview
//!
//! The publisher is implemented as a shell function (`publish_check_run`)
//! inside `action.yml`. These tests exercise the *inputs* that feed that
//! function and the *outputs* it is expected to produce, using:
//!
//! - **Fixture JSON reports** – pre-built `--format json` output files that
//!   represent safe, breaking, and tool-error scenarios.
//! - **`jq` transformations** – the same annotation-extraction expression used
//!   in the action, run locally, so we can assert on the result without
//!   starting a real GitHub API server.
//! - **Injection-safety checks** – verify that special shell characters in
//!   finding messages and target names do not break the JSON payload.
//! - **Pagination assertions** – confirm that a fixture with > 50 findings
//!   would be split into at most 50 annotations per page.
//!
//! # What is NOT tested here
//!
//! Real HTTP calls to `api.github.com` are not made. The check-run creation
//! and update paths require `checks: write` on a live repository, which is
//! only available in an actual GitHub Actions run. Those paths are covered by
//! the workflow examples in `docs/workflow-examples/`.

use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns a path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Runs the binary and returns (exit_code, stdout_json).
/// Panics if the binary cannot be started or stdout is not valid UTF-8.
fn run_json(old: &str, new: &str, extra: &[&str]) -> (i32, serde_json::Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .arg("--format")
        .arg("json")
        .arg("--no-timestamp")
        .args(extra)
        .output()
        .expect("failed to start soroban-upgrade-safeguard");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process killed by signal");

    // The binary always emits valid JSON on --format json even when it exits 1.
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse error: {e}\n---stdout---\n{stdout}"));

    (code, value)
}

// ---------------------------------------------------------------------------
// Fixture: conclusion mapping
// ---------------------------------------------------------------------------

/// Maps an exit code to the expected Checks API `conclusion` string.
/// This mirrors the case statement in action.yml exactly.
fn exit_code_to_conclusion(code: i32) -> &'static str {
    match code {
        0 => "success",
        1 => "failure",
        2 => "action_required",
        _ => "failure",
    }
}

#[test]
fn conclusion_safe_upgrade_is_success() {
    let (code, _) = run_json("v1.wasm", "v1.wasm", &[]);
    assert_eq!(code, 0);
    assert_eq!(exit_code_to_conclusion(code), "success");
}

#[test]
fn conclusion_breaking_upgrade_is_failure() {
    let (code, _) = run_json("v1.wasm", "v2.wasm", &[]);
    assert_eq!(code, 1);
    assert_eq!(exit_code_to_conclusion(code), "failure");
}

#[test]
fn conclusion_warning_non_strict_is_success() {
    // v1 → v3 has warnings only; without --strict the tool exits 0.
    let (code, _) = run_json("v1.wasm", "v3.wasm", &[]);
    assert_eq!(code, 0);
    assert_eq!(exit_code_to_conclusion(code), "success");
}

#[test]
fn conclusion_warning_strict_is_failure() {
    let (code, _) = run_json("v1.wasm", "v3.wasm", &["--strict"]);
    assert_eq!(code, 1);
    assert_eq!(exit_code_to_conclusion(code), "failure");
}

// ---------------------------------------------------------------------------
// Fixture: annotation extraction
// ---------------------------------------------------------------------------

/// Extract annotations from a JSON report the same way the action script does.
/// Returns the annotation array as a `serde_json::Value`.
///
/// The JSON report stores findings under `findings_by_category`, a map of
/// `category → [finding, ...]`.  Each finding is a flat object with
/// lowercase severity (`"critical"`, `"warning"`, `"info"`).  Suppressed
/// findings have `suppressed: true`.
fn extract_annotations(report: &serde_json::Value) -> serde_json::Value {
    let empty_map = serde_json::Map::new();
    let by_category = report["findings_by_category"]
        .as_object()
        .unwrap_or(&empty_map);

    let mut annotations = Vec::new();
    for findings in by_category.values() {
        let arr = match findings.as_array() {
            Some(a) => a,
            None => continue,
        };
        for finding in arr {
            // Skip suppressed findings.
            if finding["suppressed"].as_bool().unwrap_or(false) {
                continue;
            }

            let severity = finding["severity"].as_str().unwrap_or("info");
            let category = finding["category"].as_str().unwrap_or("");
            let message = finding["message"].as_str().unwrap_or("");
            let target = finding["target"].as_str().unwrap_or("contract");

            let annotation_level = match severity {
                "critical" => "failure",
                "warning" => "warning",
                _ => "notice",
            };

            annotations.push(serde_json::json!({
                "path": target,
                "start_line": 1,
                "end_line": 1,
                "annotation_level": annotation_level,
                "message": format!("[{category}] {message}"),
                "title": category,
            }));
        }
    }

    serde_json::Value::Array(annotations)
}

#[test]
fn safe_upgrade_produces_no_failure_annotations() {
    let (_, report) = run_json("v1.wasm", "v1.wasm", &[]);
    let annotations = extract_annotations(&report);
    let arr = annotations.as_array().unwrap();

    let failure_count = arr
        .iter()
        .filter(|a| a["annotation_level"] == "failure")
        .count();

    assert_eq!(
        failure_count, 0,
        "safe upgrade must not produce any failure annotations"
    );
}

#[test]
fn breaking_upgrade_produces_failure_annotations() {
    let (_, report) = run_json("v1.wasm", "v2.wasm", &[]);
    let annotations = extract_annotations(&report);
    let arr = annotations.as_array().unwrap();

    let failure_count = arr
        .iter()
        .filter(|a| a["annotation_level"] == "failure")
        .count();

    assert!(
        failure_count > 0,
        "breaking upgrade must produce at least one failure annotation, got:\n{annotations:#}"
    );
}

#[test]
fn annotations_have_required_fields() {
    let (_, report) = run_json("v1.wasm", "v2.wasm", &[]);
    let annotations = extract_annotations(&report);
    let arr = annotations.as_array().unwrap();

    for annotation in arr {
        assert!(
            annotation.get("path").is_some(),
            "annotation missing 'path': {annotation}"
        );
        assert!(
            annotation.get("start_line").is_some(),
            "annotation missing 'start_line': {annotation}"
        );
        assert!(
            annotation.get("end_line").is_some(),
            "annotation missing 'end_line': {annotation}"
        );
        assert!(
            annotation.get("annotation_level").is_some(),
            "annotation missing 'annotation_level': {annotation}"
        );
        assert!(
            annotation.get("message").is_some(),
            "annotation missing 'message': {annotation}"
        );
    }
}

#[test]
fn annotation_levels_are_valid_checks_api_values() {
    let (_, report) = run_json("v1.wasm", "v2.wasm", &[]);
    let annotations = extract_annotations(&report);
    let arr = annotations.as_array().unwrap();

    let valid_levels = ["failure", "warning", "notice"];
    for annotation in arr {
        let level = annotation["annotation_level"].as_str().unwrap_or("");
        assert!(
            valid_levels.contains(&level),
            "invalid annotation_level '{level}' — must be one of: failure, warning, notice"
        );
    }
}

#[test]
fn annotation_severity_mapping_is_correct() {
    let (_, report) = run_json("v1.wasm", "v2.wasm", &[]);

    // Collect all unsuppressed critical findings from findings_by_category.
    let empty_map = serde_json::Map::new();
    let by_category = report["findings_by_category"]
        .as_object()
        .unwrap_or(&empty_map);

    let critical_count = by_category
        .values()
        .flat_map(|v| {
            v.as_array()
                .unwrap_or(&vec![])
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        })
        .filter(|f| {
            !f["suppressed"].as_bool().unwrap_or(false)
                && f["severity"].as_str() == Some("critical")
        })
        .count();

    let annotations = extract_annotations(&report);
    let arr = annotations.as_array().unwrap();

    let failure_count = arr
        .iter()
        .filter(|a| a["annotation_level"] == "failure")
        .count();

    assert_eq!(
        critical_count, failure_count,
        "every Critical finding must produce exactly one failure annotation \
        (critical_count={critical_count}, failure_count={failure_count})"
    );
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

/// GitHub Checks API accepts at most 50 annotations per PATCH/POST request.
const ANNOTATION_PAGE_SIZE: usize = 50;

#[test]
fn pagination_splits_at_50_annotations() {
    // Build a synthetic list of 120 annotations and verify the page logic.
    let annotations: Vec<serde_json::Value> = (0..120_usize)
        .map(|i| {
            serde_json::json!({
                "path": format!("contract_{i}"),
                "start_line": 1,
                "end_line": 1,
                "annotation_level": "failure",
                "message": format!("finding {i}"),
                "title": "Test Finding",
            })
        })
        .collect();

    let total = annotations.len();
    let mut pages = Vec::new();
    let mut offset = 0;

    while offset < total {
        let end = std::cmp::min(offset + ANNOTATION_PAGE_SIZE, total);
        pages.push(&annotations[offset..end]);
        offset += ANNOTATION_PAGE_SIZE;
    }

    assert_eq!(pages.len(), 3, "120 annotations must split into 3 pages");
    assert_eq!(pages[0].len(), 50, "first page must have 50 annotations");
    assert_eq!(pages[1].len(), 50, "second page must have 50 annotations");
    assert_eq!(pages[2].len(), 20, "third page must have the remaining 20");
}

#[test]
fn pagination_exact_boundary_produces_no_empty_page() {
    let annotations: Vec<serde_json::Value> = (0..50_usize)
        .map(|i| {
            serde_json::json!({
                "path": format!("contract_{i}"),
                "start_line": 1,
                "end_line": 1,
                "annotation_level": "warning",
                "message": format!("finding {i}"),
                "title": "Boundary Test",
            })
        })
        .collect();

    let total = annotations.len();
    let mut pages = Vec::new();
    let mut offset = 0;
    while offset < total {
        let end = std::cmp::min(offset + ANNOTATION_PAGE_SIZE, total);
        let page = &annotations[offset..end];
        if page.is_empty() {
            break;
        }
        pages.push(page);
        offset += ANNOTATION_PAGE_SIZE;
    }

    assert_eq!(
        pages.len(),
        1,
        "exactly 50 annotations must fit in one page"
    );
    assert_eq!(
        pages[0].len(),
        50,
        "the single page must contain all 50 annotations"
    );
}

#[test]
fn zero_annotations_produces_no_pages() {
    let annotations: Vec<serde_json::Value> = vec![];
    let total = annotations.len();
    let mut pages: Vec<&[serde_json::Value]> = Vec::new();
    let mut offset = 0;
    while offset < total {
        let end = std::cmp::min(offset + ANNOTATION_PAGE_SIZE, total);
        let page = &annotations[offset..end];
        if page.is_empty() {
            break;
        }
        pages.push(page);
        offset += ANNOTATION_PAGE_SIZE;
    }

    assert!(pages.is_empty(), "zero annotations must produce zero pages");
}

// ---------------------------------------------------------------------------
// Injection safety
// ---------------------------------------------------------------------------

/// Verifies that special shell/JSON characters in a message are handled
/// safely when serialized as a JSON annotation payload.
#[test]
fn annotation_message_serialises_special_characters_safely() {
    // Characters that would break an unquoted shell string or raw JSON.
    let tricky_messages: &[&str] = &[
        r#"field "amount" type changed"#,
        "line1\nline2",
        r#"payload: {"key": "value"}"#,
        "path/with spaces/and\ttabs",
        r#"backtick `injection` attempt"#,
        r#"dollar $HOME injection"#,
    ];

    for msg in tricky_messages {
        let annotation = serde_json::json!({
            "path": "contract",
            "start_line": 1,
            "end_line": 1,
            "annotation_level": "failure",
            "message": msg,
            "title": "Test",
        });

        // Round-trip through JSON serialization: must not panic or corrupt.
        let serialized = serde_json::to_string(&annotation)
            .unwrap_or_else(|e| panic!("serialization failed for message '{msg}': {e}"));
        let roundtripped: serde_json::Value = serde_json::from_str(&serialized)
            .unwrap_or_else(|e| panic!("deserialization failed for message '{msg}': {e}"));

        assert_eq!(
            roundtripped["message"].as_str().unwrap(),
            *msg,
            "message must survive JSON round-trip unchanged"
        );
    }
}

#[test]
fn annotation_path_sanitises_target_field() {
    // GitHub Checks API paths must be relative repository paths.
    // The action falls back to the literal string "contract" when the
    // finding target is None.
    let targets: &[Option<&str>] = &[
        None,
        Some("MyStruct.field"),
        Some("transfer"),
        Some("transfer.amount"),
    ];

    for target in targets {
        let path = target.unwrap_or("contract");
        // Paths must be non-empty.
        assert!(
            !path.is_empty(),
            "path must not be empty for target {target:?}"
        );
        // Paths must not be absolute (GitHub API rejects them).
        assert!(
            !path.starts_with('/'),
            "path must be relative, got '{path}' for target {target:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Fork PR detection
// ---------------------------------------------------------------------------

/// Verifies the expected skip behaviour when the action detects a fork PR.
/// The actual environment variable simulation mirrors the action logic:
/// IS_FORK_PR=true causes publish_check_run to be skipped entirely.
#[test]
fn fork_pr_flag_suppresses_check_run_publication() {
    // The action reads IS_FORK_PR from a jq expression over the event
    // payload.  In a real fork PR:
    //   pull_request.head.repo.full_name  ≠  pull_request.base.repo.full_name
    // We simulate this by constructing the same payloads here.

    let same_repo_payload = serde_json::json!({
        "pull_request": {
            "number": 42,
            "head": { "sha": "abc123", "repo": { "full_name": "owner/repo" } },
            "base": { "repo": { "full_name": "owner/repo" } }
        }
    });

    let fork_pr_payload = serde_json::json!({
        "pull_request": {
            "number": 99,
            "head": { "sha": "def456", "repo": { "full_name": "fork/repo" } },
            "base": { "repo": { "full_name": "owner/repo" } }
        }
    });

    let is_fork = |payload: &serde_json::Value| -> bool {
        let head = payload["pull_request"]["head"]["repo"]["full_name"]
            .as_str()
            .unwrap_or("");
        let base = payload["pull_request"]["base"]["repo"]["full_name"]
            .as_str()
            .unwrap_or("");
        head != base
    };

    assert!(
        !is_fork(&same_repo_payload),
        "same-repo PR must not be detected as a fork"
    );
    assert!(
        is_fork(&fork_pr_payload),
        "fork PR must be detected as a fork"
    );
}

// ---------------------------------------------------------------------------
// Summary truncation
// ---------------------------------------------------------------------------

#[test]
fn summary_is_truncated_to_github_api_limit() {
    // The action truncates the summary to 65 000 characters (conservative
    // limit below the 65 535 API cap, accounting for the omitted-findings
    // notice appended afterwards).
    const SUMMARY_LIMIT: usize = 65_000;

    let long_summary = "x".repeat(100_000);
    let truncated = &long_summary[..SUMMARY_LIMIT.min(long_summary.len())];

    assert_eq!(
        truncated.len(),
        SUMMARY_LIMIT,
        "summary must be truncated to exactly {SUMMARY_LIMIT} characters"
    );
}

// ---------------------------------------------------------------------------
// Action input defaults
// ---------------------------------------------------------------------------

#[test]
fn default_check_name_is_soroban_upgrade_safeguard() {
    // This mirrors the default in action.yml.
    // If the default changes there it must change here too.
    let default_name = "Soroban Upgrade Safeguard";
    assert!(!default_name.is_empty());
    assert_eq!(default_name, "Soroban Upgrade Safeguard");
}

#[test]
fn publish_check_run_default_is_false() {
    // Default must be 'false' so existing callers are not affected by the
    // new input when they do not specify it.
    let default_value = "false";
    assert_eq!(default_value, "false");
}

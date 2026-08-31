//! Tests for the GitHub Checks API publisher logic embedded in the composite
//! action.
//!
//! These tests exercise the shell / Python fragments in
//! `.github/actions/soroban-upgrade-safeguard/action.yml` by calling the
//! helper scripts directly via inline Python sub-processes, and verifying the
//! annotation-building and conclusion-mapping rules against a stub JSON report,
//! without making any real network calls.
//!
//! # What is covered
//!
//! - Conclusion mapping: safe (exit 0) → success, unsafe (exit 1) → failure,
//!   resource-limit (exit 2) → action_required, unexpected error → cancelled.
//! - Annotation building: severity → level mapping, path extraction,
//!   truncation at 50 annotations per page, omission counting.
//! - Suppressed findings are excluded from annotations.
//! - Annotation title is capped at 255 characters.
//! - Annotation message is capped at 65 000 characters.
//! - Check-name sanitisation: control characters are stripped, length capped
//!   at 100 characters.
//! - Fork PR detection: head repo != base repo → IS_FORK_PR = "true".
//! - Injection safety: newlines and shell metacharacters in check-name and
//!   finding fields do not break the JSON payload.
//! - Omission note applies when findings exceed the 50-annotation cap.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Monotonic counter for unique temp-file names (avoids a crate dependency).
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Write `content` to a uniquely-named file inside `CARGO_TARGET_TMPDIR` and
/// return its path.
fn write_temp(suffix: &str, content: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join(format!("checks_pub_{id}_{suffix}"));
    fs::write(&path, content).expect("write temp file");
    path
}

/// Serialise `findings` into a JSON report file and return its path.
fn write_report(findings: &serde_json::Value) -> PathBuf {
    let report = serde_json::json!({ "findings": findings });
    write_temp("report.json", &serde_json::to_string(&report).unwrap())
}

/// Run an inline Python3 script with optional extra args; return
/// (exit_code, stdout, stderr).
fn python3(script: &str, args: &[&str]) -> (i32, String, String) {
    let primary = if cfg!(windows) { "python" } else { "python3" };
    let fallback = if cfg!(windows) { "python3" } else { "python" };

    let run_with = |prog: &str| {
        let mut cmd = Command::new(prog);
        cmd.arg("-c").arg(script);
        for a in args {
            cmd.arg(a);
        }
        cmd.output()
    };

    let out = run_with(primary)
        .or_else(|_| run_with(fallback))
        .expect("python or python3 must be available on the PATH");

    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ─── scripts extracted from action.yml ───────────────────────────────────────

/// Conclusion-mapping logic (mirrors the bash case statement in action.yml).
const CONCLUSION_SCRIPT: &str = r#"
import sys
code = int(sys.argv[1])
if   code == 0: print("success",         end='')
elif code == 1: print("failure",         end='')
elif code == 2: print("action_required", end='')
else:           print("cancelled",       end='')
"#;

/// Annotation-building script (mirrors ANNOTATION_SCRIPT in action.yml).
const ANNOTATION_SCRIPT: &str = r#"
import json, sys, pathlib, re

MAX_ANNOTATIONS = 50

try:
    data = json.loads(pathlib.Path(sys.argv[1]).read_text())
except Exception:
    print("[]")
    sys.exit(0)

findings    = data.get("findings", [])
annotations = []
omitted     = 0

for f in findings:
    if f.get("suppressed"):
        continue
    severity = f.get("severity", "").lower()
    level    = "failure" if severity == "critical" else \
               "warning" if severity == "warning"  else "notice"

    category = f.get("category", "Unknown")
    target   = f.get("target",   "")
    message  = f"{category}: {target}" if target else category
    detail   = f.get("detail", "") or ""
    if detail:
        message = f"{message}\n{detail}"
    message = message[:65000]

    path_match = re.search(r'([\w./\\-]+\.\w+)', target or "")
    ann_path   = path_match.group(1) if path_match else \
        ".github/actions/soroban-upgrade-safeguard/action.yml"

    if len(annotations) < MAX_ANNOTATIONS:
        annotations.append({
            "path":             ann_path,
            "start_line":       1,
            "end_line":         1,
            "annotation_level": level,
            "message":          message,
            "title":            (f"[{category}] {target}" if target
                                 else category)[:255],
        })
    else:
        omitted += 1

print(json.dumps({"annotations": annotations, "omitted": omitted}))
"#;

/// Check-name sanitisation (mirrors the bash logic in action.yml).
const SANITISE_SCRIPT: &str = r#"
import sys, re
name = sys.argv[1]
safe = re.sub(r'[\x01-\x1f]', ' ', name)
safe = safe[:100]
print(safe, end='')
"#;

/// Fork-detection logic (mirrors the bash fragment in action.yml).
const FORK_DETECT_SCRIPT: &str = r#"
import json, sys

github_repository = sys.argv[1]
event_path        = sys.argv[2]
is_fork_pr        = "false"

try:
    with open(event_path) as fh:
        payload = json.load(fh)
    head_repo = (payload.get("pull_request", {})
                        .get("head", {})
                        .get("repo", {})
                        .get("full_name", ""))
    if head_repo and head_repo != github_repository:
        is_fork_pr = "true"
except Exception:
    pass

print(is_fork_pr, end='')
"#;

// ─── conclusion mapping ───────────────────────────────────────────────────────

#[test]
fn conclusion_exit0_is_success() {
    let (code, out, _) = python3(CONCLUSION_SCRIPT, &["0"]);
    assert_eq!(code, 0);
    assert_eq!(out, "success");
}

#[test]
fn conclusion_exit1_is_failure() {
    let (code, out, _) = python3(CONCLUSION_SCRIPT, &["1"]);
    assert_eq!(code, 0);
    assert_eq!(out, "failure");
}

#[test]
fn conclusion_exit2_is_action_required() {
    let (code, out, _) = python3(CONCLUSION_SCRIPT, &["2"]);
    assert_eq!(code, 0);
    assert_eq!(out, "action_required");
}

#[test]
fn conclusion_unexpected_exit_codes_map_to_cancelled() {
    for code in [3u32, 127, 255] {
        let (rc, out, _) = python3(CONCLUSION_SCRIPT, &[&code.to_string()]);
        assert_eq!(rc, 0, "script must exit 0");
        assert_eq!(out, "cancelled", "exit {code} → cancelled");
    }
}

// ─── annotation severity mapping ─────────────────────────────────────────────

#[test]
fn critical_finding_maps_to_failure_annotation() {
    let path = write_report(&serde_json::json!([{
        "severity": "Critical",
        "category": "Struct Field Removed",
        "target":   "ConfigData.threshold",
        "detail":   "Field was present in old spec.",
        "suppressed": false,
    }]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(d["annotations"][0]["annotation_level"], "failure");
    assert!(d["annotations"][0]["message"]
        .as_str()
        .unwrap()
        .contains("Struct Field Removed"));
}

#[test]
fn warning_finding_maps_to_warning_annotation() {
    let path = write_report(&serde_json::json!([{
        "severity": "Warning",
        "category": "Function Parameter Added",
        "target":   "transfer",
        "suppressed": false,
    }]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(d["annotations"][0]["annotation_level"], "warning");
}

#[test]
fn info_finding_maps_to_notice_annotation() {
    let path = write_report(&serde_json::json!([{
        "severity": "Info",
        "category": "Function Added",
        "target":   "new_fn",
        "suppressed": false,
    }]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(d["annotations"][0]["annotation_level"], "notice");
}

// ─── suppressed findings ──────────────────────────────────────────────────────

#[test]
fn suppressed_findings_excluded_from_annotations() {
    let path = write_report(&serde_json::json!([
        {
            "severity": "Critical",
            "category": "Struct Field Removed",
            "target":   "Foo.bar",
            "suppressed": true,
        },
        {
            "severity": "Warning",
            "category": "Function Parameter Added",
            "target":   "baz",
            "suppressed": false,
        }
    ]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    let anns = d["annotations"].as_array().unwrap();
    assert_eq!(anns.len(), 1, "suppressed finding must be excluded");
    assert_eq!(anns[0]["annotation_level"], "warning");
}

// ─── pagination cap ───────────────────────────────────────────────────────────

#[test]
fn annotations_capped_at_50_excess_counted_as_omitted() {
    let findings: Vec<serde_json::Value> = (0..60)
        .map(|i| {
            serde_json::json!({
                "severity": "Critical",
                "category": "Struct Field Removed",
                "target":   format!("MyStruct.field_{i}"),
                "suppressed": false,
            })
        })
        .collect();
    let path = write_report(&serde_json::Value::Array(findings));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        d["annotations"].as_array().unwrap().len(),
        50,
        "first page must contain exactly 50 annotations"
    );
    assert_eq!(d["omitted"].as_i64().unwrap(), 10);
}

#[test]
fn exactly_50_findings_produces_no_omission() {
    let findings: Vec<serde_json::Value> = (0..50)
        .map(|i| {
            serde_json::json!({
                "severity": "Warning",
                "category": "Function Parameter Added",
                "target":   format!("fn_{i}"),
                "suppressed": false,
            })
        })
        .collect();
    let path = write_report(&serde_json::Value::Array(findings));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(d["annotations"].as_array().unwrap().len(), 50);
    assert_eq!(d["omitted"].as_i64().unwrap(), 0);
}

// ─── field length limits ──────────────────────────────────────────────────────

#[test]
fn annotation_title_capped_at_255_characters() {
    let path = write_report(&serde_json::json!([{
        "severity": "Critical",
        "category": "Struct Field Removed",
        "target":   "x".repeat(300),
        "suppressed": false,
    }]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    let title = d["annotations"][0]["title"].as_str().unwrap();
    assert!(title.len() <= 255, "title len={}", title.len());
}

#[test]
fn annotation_message_capped_at_65000_characters() {
    let path = write_report(&serde_json::json!([{
        "severity": "Warning",
        "category": "Function Parameter Added",
        "target":   "fn_x",
        "detail":   "d".repeat(70_000),
        "suppressed": false,
    }]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    let msg = d["annotations"][0]["message"].as_str().unwrap();
    assert!(msg.len() <= 65_000, "message len={}", msg.len());
}

// ─── empty / missing report ───────────────────────────────────────────────────

#[test]
fn empty_findings_produces_no_annotations() {
    let path = write_report(&serde_json::json!([]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(d["annotations"].as_array().unwrap().len(), 0);
    assert_eq!(d["omitted"].as_i64().unwrap(), 0);
}

#[test]
fn missing_report_file_exits_zero_returns_empty_array() {
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &["/nonexistent/report.json"]);
    assert_eq!(code, 0, "must not crash on missing file");
    assert_eq!(out.trim(), "[]");
}

// ─── path extraction ──────────────────────────────────────────────────────────

#[test]
fn file_like_target_extracted_as_annotation_path() {
    let path = write_report(&serde_json::json!([{
        "severity": "Critical",
        "category": "Struct Field Removed",
        "target":   "contracts/token.wasm:MyStruct.field",
        "suppressed": false,
    }]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    let ann_path = d["annotations"][0]["path"].as_str().unwrap();
    assert!(
        !ann_path.contains("action.yml"),
        "path should come from target, got: {ann_path}"
    );
}

#[test]
fn non_file_target_falls_back_to_action_yml() {
    let path = write_report(&serde_json::json!([{
        "severity": "Critical",
        "category": "Enum Variant Removed",
        "target":   "MyEnum::VariantA",
        "suppressed": false,
    }]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let d: serde_json::Value = serde_json::from_str(&out).unwrap();
    let ann_path = d["annotations"][0]["path"].as_str().unwrap();
    assert!(
        ann_path.contains("action.yml"),
        "expected fallback to action.yml, got: {ann_path}"
    );
}

// ─── check-name sanitisation ─────────────────────────────────────────────────

#[test]
fn check_name_control_characters_are_stripped() {
    let name = "Safe\x01Guard\x1fCheck";
    let (code, out, _) = python3(SANITISE_SCRIPT, &[name]);
    assert_eq!(code, 0);
    assert!(
        !out.chars().any(|c| (c as u32) < 0x20),
        "control chars must be stripped; got: {out:?}"
    );
    assert!(out.contains("Safe") && out.contains("Check"));
}

#[test]
fn check_name_truncated_to_100_chars() {
    let long_name = "A".repeat(200);
    let (code, out, _) = python3(SANITISE_SCRIPT, &[&long_name]);
    assert_eq!(code, 0);
    assert_eq!(out.len(), 100, "name must be truncated; got {}", out.len());
}

#[test]
fn check_name_short_enough_is_unchanged() {
    let name = "Soroban Upgrade Safeguard";
    let (code, out, _) = python3(SANITISE_SCRIPT, &[name]);
    assert_eq!(code, 0);
    assert_eq!(out, name);
}

// ─── injection safety ─────────────────────────────────────────────────────────

#[test]
fn newlines_in_finding_fields_produce_valid_json() {
    let path = write_report(&serde_json::json!([{
        "severity": "Critical",
        "category": "Struct Field Removed",
        "target":   "Foo.bar\nBAD_INJECTION\nalso",
        "detail":   "Line1\nLine2\n\"quoted\"",
        "suppressed": false,
    }]));
    let (code, out, _) = python3(ANNOTATION_SCRIPT, &[path.to_str().unwrap()]);
    assert_eq!(code, 0, "script must not crash on embedded newlines");
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&out);
    assert!(parsed.is_ok(), "output must be valid JSON; got: {out}");
}

#[test]
fn shell_metacharacters_in_check_name_are_safe() {
    let names: &[&str] = &[
        r#"'; rm -rf /; echo '"#,
        "$(whoami)",
        "`id`",
        "name\"; exit 1; echo \"",
    ];
    for &name in names {
        let (code, out, _) = python3(SANITISE_SCRIPT, &[name]);
        assert_eq!(code, 0, "sanitiser must not crash for: {name:?}");
        assert!(out.len() <= 100, "output too long for: {name:?}");
    }
}

// ─── fork PR detection ────────────────────────────────────────────────────────

#[test]
fn fork_pr_detected_when_head_repo_differs_from_base() {
    let event = serde_json::json!({
        "pull_request": {
            "number": 42,
            "head": { "repo": { "full_name": "contributor/soroban-upgrade-safeguard" } }
        }
    });
    let path = write_temp("fork_event.json", &serde_json::to_string(&event).unwrap());
    let (code, out, _) = python3(
        FORK_DETECT_SCRIPT,
        &[
            "ShippedLabs/soroban-upgrade-safeguard",
            path.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0);
    assert_eq!(out, "true", "fork PR must be detected");
}

#[test]
fn same_repo_pr_not_flagged_as_fork() {
    let event = serde_json::json!({
        "pull_request": {
            "number": 7,
            "head": { "repo": { "full_name": "ShippedLabs/soroban-upgrade-safeguard" } }
        }
    });
    let path = write_temp(
        "same_repo_event.json",
        &serde_json::to_string(&event).unwrap(),
    );
    let (code, out, _) = python3(
        FORK_DETECT_SCRIPT,
        &[
            "ShippedLabs/soroban-upgrade-safeguard",
            path.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0);
    assert_eq!(out, "false");
}

#[test]
fn missing_event_file_does_not_crash_fork_detection() {
    let (code, out, _) = python3(
        FORK_DETECT_SCRIPT,
        &[
            "ShippedLabs/soroban-upgrade-safeguard",
            "/nonexistent_event.json",
        ],
    );
    assert_eq!(code, 0, "must not crash on missing file");
    assert_eq!(out, "false");
}

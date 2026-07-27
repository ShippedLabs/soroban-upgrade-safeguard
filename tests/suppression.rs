//! Integration tests for the suppression config (`.safeguard.toml`).
//!
//! These drive the compiled binary with `--config` against the checked-in
//! `v1 -> v2` fixtures, which produce three Critical findings:
//!
//! - `Enum Case Value Changed`    on `StatusEvent.Paused`
//! - `Function Signature Changed` on `initialize`
//! - `Struct Field Removed`       on `ConfigData.threshold`
//!
//! and assert that suppressions flip the failing set without hiding findings.
//!
//! Note the category for `StatusEvent.Paused` is the structural
//! `Enum Case Value Changed`, not an event-specific key. Categories (and thus
//! suppression keys) are purely structural; whether a type reads as an "event"
//! is separate classification metadata that never changes the category. So even
//! though `StatusEvent` contains the substring "event", with the default
//! classification (no `[classification]` table, name heuristic off) it is a
//! plain storage type and its suppression key is the structural one.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Write `contents` to a uniquely named TOML file in the per-test temp dir and
/// return its path. `CARGO_TARGET_TMPDIR` is provided to integration tests.
fn write_config(name: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}.safeguard.toml"));
    std::fs::write(&path, contents).expect("failed to write temp config");
    path
}

/// Run the binary, optionally with a config.
/// Returns (stdout, stderr, exit code).
fn run_raw(config: Option<&PathBuf>, format_json: bool) -> (String, String, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm("v1.wasm")).arg(wasm("v2.wasm"));
    if format_json {
        cmd.args(["--format", "json"]);
    }
    if let Some(path) = config {
        cmd.args(["--config".as_ref(), path.as_os_str()]);
    }

    let output = cmd.output().expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    (stdout, stderr, code)
}

/// Run the binary in JSON mode comparing `v1 -> v2`, optionally with a config.
/// Returns (parsed JSON, exit code).
fn run(config: Option<&PathBuf>) -> (Value, i32) {
    let (stdout, _, code) = run_raw(config, true);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));
    (json, code)
}

/// Helper to get all Critical findings and their computed fingerprints.
fn get_findings_with_fingerprints() -> Vec<(String, Option<String>, String)> {
    let (json, _) = run(None);
    json["findings_by_category"]
        .as_object()
        .expect("findings_by_category must be an object")
        .values()
        .flat_map(|arr| arr.as_array().expect("findings must be an array"))
        .filter(|f| f["severity"].as_str().unwrap() == "critical")
        .map(|f| {
            (
                f["category"].as_str().unwrap().to_string(),
                f["target"].as_str().map(str::to_string),
                f["fingerprint"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// Collect every finding across all categories as (category, target, suppressed).
fn findings(json: &Value) -> Vec<(String, Option<String>, bool)> {
    json["findings_by_category"]
        .as_object()
        .expect("findings_by_category must be an object")
        .values()
        .flat_map(|arr| arr.as_array().expect("findings must be an array"))
        .map(|f| {
            (
                f["category"].as_str().unwrap().to_string(),
                f["target"].as_str().map(str::to_string),
                f["suppressed"].as_bool().unwrap_or(false),
            )
        })
        .collect()
}

#[test]
fn rule_id_based_suppression_matches_stable_identifier() {
    let config = write_config(
        "rule-id",
        r#"
        [[suppress]]
        rule_id = "struct_field_removed"
        target  = "ConfigData.threshold"
        reason  = "Reviewed storage migration"

        [[suppress]]
        rule_id = "enum_case_value_changed"
        target   = "StatusEvent.Paused"
        reason   = "Reviewed"

        [[suppress]]
        rule_id = "function_signature_changed"
        target   = "initialize"
        reason   = "Reviewed"
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(code, 0, "suppressing by rule_id should pass the run");
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 3);
    assert!(
        findings(&json).iter().any(|(c, t, s)| c == "Struct Field Removed"
            && t.as_deref() == Some("ConfigData.threshold")
            && *s),
        "the removed field must appear as suppressed when matched by rule_id"
    );
}

#[test]
fn suppressing_all_criticals_passes_but_still_lists_them() {
    let config = write_config(
        "all",
        r#"
        [[suppress]]
        category = "Enum Case Value Changed"
        target   = "StatusEvent.Paused"
        reason   = "Reviewed: indexers already updated."

        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"
        reason   = "Planned re-init for the v2 migration."

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        "#,
    );

    let (json, code) = run(Some(&config));

    // A suppressed Critical no longer fails the run...
    assert_eq!(code, 0, "all criticals suppressed -> must exit 0");
    assert_eq!(json["is_safe"], Value::Bool(true));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 3);

    // ...but the criticals are still counted and still listed, just marked.
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 3);
    let all = findings(&json);
    let suppressed: Vec<_> = all.iter().filter(|(_, _, s)| *s).collect();
    assert_eq!(
        suppressed.len(),
        3,
        "all three criticals must be listed as suppressed"
    );
    assert!(
        all.iter().any(|(c, t, s)| c == "Struct Field Removed"
            && t.as_deref() == Some("ConfigData.threshold")
            && *s),
        "the removed field must appear, flagged suppressed"
    );
}

#[test]
fn non_matching_suppression_leaves_run_failing() {
    // Right category, wrong target -> exact match means it must NOT apply.
    let config = write_config(
        "wrong-target",
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.some_other_field"
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(code, 1, "a non-matching rule must not rescue the run");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
    assert!(findings(&json).iter().all(|(_, _, s)| !s));
}

#[test]
fn partial_suppression_still_fails_on_remaining_critical() {
    // Suppress two of the three criticals; the third must still fail the run.
    let config = write_config(
        "partial",
        r#"
        [[suppress]]
        category = "Enum Case Value Changed"
        target   = "StatusEvent.Paused"

        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(code, 1, "one unsuppressed critical must still fail");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 2);
}

#[test]
fn no_config_behaves_exactly_as_today() {
    // No --config and (by virtue of the temp cwd) no default file -> the run
    // fails on the criticals with nothing suppressed, exactly as before.
    let (json, code) = run(None);

    assert_eq!(code, 1);
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 3);
}

#[test]
fn missing_explicit_config_is_an_error() {
    // An explicitly named config that does not exist must be a hard error,
    // so typos are never silently treated as "no suppressions".
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("does-not-exist.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--config".as_ref(), missing.as_os_str()])
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "missing explicit config must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("suppression config"),
        "error should mention the suppression config: {stderr}"
    );
}

#[test]
fn test_new_format_suppression_success() {
    let findings = get_findings_with_fingerprints();
    assert_eq!(findings.len(), 3, "sanity check: expect 3 findings");

    let mut toml_str = String::from("allow_targetless = false\n");
    for (cat, target, fp) in &findings {
        toml_str.push_str("\n[[suppress]]\n");
        toml_str.push_str(&format!("category = \"{}\"\n", cat));
        if let Some(t) = target {
            toml_str.push_str(&format!("target = \"{}\"\n", t));
        }
        toml_str.push_str("author = \"test-author\"\n");
        toml_str.push_str("expiry = \"2099-12-31\"\n");
        toml_str.push_str(&format!("fingerprint = \"{}\"\n", fp));
    }

    let config = write_config("new-format-success", &toml_str);
    let (stdout, stderr, code) = run_raw(Some(&config), true);

    assert_eq!(code, 0, "all findings suppressed -> must exit 0");
    assert!(
        stderr.contains(
            "SECURITY NOTICE: The gate passed because 3 Critical breaking changes were suppressed"
        ),
        "stderr must contain the security notice. Stderr: {}",
        stderr
    );

    let json: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 3);
}

#[test]
fn test_fingerprint_mismatch_fails() {
    let findings = get_findings_with_fingerprints();
    let mut toml_str = String::from("allow_targetless = false\n");
    for (i, (cat, target, fp)) in findings.iter().enumerate() {
        toml_str.push_str("\n[[suppress]]\n");
        toml_str.push_str(&format!("category = \"{}\"\n", cat));
        if let Some(t) = target {
            toml_str.push_str(&format!("target = \"{}\"\n", t));
        }
        toml_str.push_str("author = \"test-author\"\n");
        toml_str.push_str("expiry = \"2099-12-31\"\n");
        if i == 0 {
            toml_str.push_str("fingerprint = \"wrongfingerprint12345\"\n");
        } else {
            toml_str.push_str(&format!("fingerprint = \"{}\"\n", fp));
        }
    }

    let config = write_config("fingerprint-mismatch", &toml_str);
    let (_, _, code) = run_raw(Some(&config), true);
    assert_eq!(code, 1, "mismatched fingerprint must not suppress finding");
}

#[test]
fn test_expiry_check_fails() {
    let findings = get_findings_with_fingerprints();
    let mut toml_str = String::from("allow_targetless = false\n");
    for (i, (cat, target, fp)) in findings.iter().enumerate() {
        toml_str.push_str("\n[[suppress]]\n");
        toml_str.push_str(&format!("category = \"{}\"\n", cat));
        if let Some(t) = target {
            toml_str.push_str(&format!("target = \"{}\"\n", t));
        }
        toml_str.push_str("author = \"test-author\"\n");
        if i == 0 {
            toml_str.push_str("expiry = \"2020-01-01\"\n"); // expired
        } else {
            toml_str.push_str("expiry = \"2099-12-31\"\n");
        }
        toml_str.push_str(&format!("fingerprint = \"{}\"\n", fp));
    }

    let config = write_config("expired-rule", &toml_str);
    let (_, stderr, code) = run_raw(Some(&config), true);
    assert_ne!(code, 0, "expired rule must cause validation error");
    assert!(
        stderr.contains("expired on 2020-01-01"),
        "stderr should mention the expiration error: {}",
        stderr
    );
}

#[test]
fn test_max_suppressions_fails() {
    let findings = get_findings_with_fingerprints();
    let mut toml_str = String::from("max_suppressions = 2\nallow_targetless = false\n");
    for (cat, target, fp) in &findings {
        toml_str.push_str("\n[[suppress]]\n");
        toml_str.push_str(&format!("category = \"{}\"\n", cat));
        if let Some(t) = target {
            toml_str.push_str(&format!("target = \"{}\"\n", t));
        }
        toml_str.push_str("author = \"test-author\"\n");
        toml_str.push_str("expiry = \"2099-12-31\"\n");
        toml_str.push_str(&format!("fingerprint = \"{}\"\n", fp));
    }

    let config = write_config("max-suppressions", &toml_str);
    let (_, stderr, code) = run_raw(Some(&config), true);
    assert_ne!(code, 0, "exceeding max_suppressions must fail");
    assert!(
        stderr.contains("exceed the maximum limit of 2"),
        "stderr should mention max suppressions: {}",
        stderr
    );
}

#[test]
fn test_allow_targetless_disabled_fails() {
    let mut toml_str = String::from("allow_targetless = false\n");
    toml_str.push_str("\n[[suppress]]\n");
    toml_str.push_str("category = \"Environment\"\n"); // targetless

    let config = write_config("targetless-disabled", &toml_str);
    let (_, stderr, code) = run_raw(Some(&config), true);
    assert_ne!(
        code, 0,
        "targetless with allow_targetless = false must fail"
    );
    assert!(
        stderr.contains("Targetless wildcard suppressions are disabled"),
        "stderr should mention targetless disabled: {}",
        stderr
    );
}

#[test]
fn test_old_format_warning_output() {
    let config = write_config(
        "old-format-warning",
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        "#,
    );
    let (_, stderr, _) = run_raw(Some(&config), true);
    assert!(
        stderr.contains("Warning: Deprecated old-format suppression rule detected"),
        "stderr must warn about old format: {}",
        stderr
    );
}

#[test]
fn unmatched_suppression_rule_is_reported_to_stderr() {
    // One rule that WILL match (Struct Field Removed / ConfigData.threshold)
    // and one rule with a deliberate typo in the target that will NOT match.
    // The mismatched rule must appear in stderr; the matching one must not.
    let config = write_config(
        "unmatched-rule",
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "Reviewed"

        [[suppress]]
        category = "Function Removed"
        target   = "does_not_exist_typo"
        reason   = "Stale rule"
        "#,
    );

    let (_, stderr, _code) = run_raw(Some(&config), false);

    // The unmatched rule (typo target) must be reported on stderr.
    assert!(
        stderr.contains("does_not_exist_typo") || stderr.contains("never matched"),
        "stderr should mention the unmatched suppression rule: {stderr}"
    );

    // The matched rule (ConfigData.threshold) must NOT generate a notice.
    assert!(
        !stderr.contains("ConfigData.threshold"),
        "stderr must not warn about a rule that did match: {stderr}"
    );
}

#[test]
fn matched_suppression_produces_no_unmatched_notice() {
    // All three critical findings are suppressed; no rule is unused,
    // so no unmatched-rule notice should appear on stderr.
    let config = write_config(
        "all-matched",
        r#"
        [[suppress]]
        category = "Enum Case Value Changed"
        target   = "StatusEvent.Paused"
        reason   = "Reviewed"

        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"
        reason   = "Reviewed"

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "Reviewed"
        "#,
    );

    let (_, stderr, code) = run_raw(Some(&config), false);

    assert_eq!(code, 0, "all criticals suppressed -> must exit 0");
    assert!(
        !stderr.contains("never matched"),
        "stderr must not warn about matched rules, got: {stderr}"
    );
}

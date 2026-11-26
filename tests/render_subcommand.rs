// SPDX-License-Identifier: MIT
//! Integration tests for the `render` subcommand — the round trip that lets a
//! stored JSON report stand in for the original WASM files.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

/// Run a live comparison and return its stdout in the requested format.
fn live(format: &str) -> String {
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", format])
        .arg("--no-color")
        .arg("--no-timestamp")
        .output()
        .expect("failed to run binary");
    String::from_utf8(output.stdout).expect("stdout was not valid UTF-8")
}

/// Feed a saved report to `render` over stdin, returning (stdout, exit code).
fn render(report: &str, args: &[&str]) -> (String, i32) {
    let mut child = bin()
        .arg("render")
        .arg("-")
        .args(args)
        .arg("--no-color")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(report.as_bytes())
        .expect("failed to write report to stdin");

    let output = child.wait_with_output().expect("failed to wait for binary");
    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

/// The acceptance criterion: a saved report renders to what the live run would
/// have produced, without the original inputs.
#[test]
fn rendered_markdown_matches_a_live_run() {
    let report = live("json");
    let (rendered, code) = render(&report, &["--format", "markdown"]);

    assert_eq!(rendered, live("markdown"));
    assert_eq!(
        code, 1,
        "the stored verdict was a failure, so must the exit be"
    );
}

#[test]
fn rendered_text_matches_a_live_run() {
    let report = live("json");
    let (rendered, _) = render(&report, &["--format", "text"]);

    // The live text run prefixes decorative progress lines on stdout; the
    // report body itself is what must match.
    let live_text = live("text");
    let body_start = live_text
        .find("========================================")
        .expect("live text output should contain the report banner");

    assert!(
        rendered.contains(&live_text[body_start..]),
        "re-rendered text must reproduce the live report body"
    );
}

#[test]
fn text_is_the_default_format() {
    let report = live("json");
    let (explicit, _) = render(&report, &["--format", "text"]);
    let (default, _) = render(&report, &[]);
    assert_eq!(default, explicit);
}

#[test]
fn render_min_severity_hides_info_details_but_keeps_counts() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/real_world_corpus/wasm");
    let output = bin()
        .arg(corpus.join("blend_pool_v1.wasm"))
        .arg(corpus.join("blend_pool_v2.wasm"))
        .args(["--format", "json", "--no-timestamp"])
        .output()
        .unwrap();
    let report = String::from_utf8(output.stdout).unwrap();

    let (all, _) = render(&report, &["--plain"]);
    let (warnings, _) = render(&report, &["--plain", "--min-severity", "warning"]);
    assert!(all.contains("[INFO]"));
    assert!(!warnings.contains("[INFO]"));
    assert!(warnings.contains("Info:     2"));
}

#[test]
fn render_help_lists_min_severity() {
    let output = bin().args(["render", "--help"]).output().unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--min-severity"));
    assert!(help.contains("warning"));
}

#[test]
fn a_safe_report_round_trips_and_exits_zero() {
    // Comparing a build against itself yields a passing verdict, which the
    // re-render must preserve — verdict included.
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");
    assert_eq!(output.status.code(), Some(0));

    let report = String::from_utf8(output.stdout).unwrap();
    let (rendered, code) = render(&report, &["--format", "markdown"]);

    assert_eq!(code, 0, "a passing report must re-render with exit 0");
    assert!(rendered.contains("PASSED"));
}

#[test]
fn render_no_color_produces_no_ansi_escape_sequences() {
    let report = live("json");
    let mut child = bin()
        .arg("render")
        .arg("-")
        .arg("--no-color")
        .env("CLICOLOR_FORCE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn binary");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(report.as_bytes())
        .expect("failed to write report to stdin");

    let output = child.wait_with_output().expect("failed to wait for binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");

    assert!(
        !stdout.contains('\u{1b}'),
        "render --no-color output must not contain ANSI escape sequences. Got:\n{stdout}"
    );
    assert!(
        stdout.contains("SOROBAN UPGRADE SAFETY REPORT"),
        "rendered report must contain report header"
    );
    assert!(
        stdout.contains("FAILED") || stdout.contains("PASSED"),
        "rendered report must contain its verdict"
    );
}

#[test]
fn rendering_from_a_file_works() {
    let report = live("json");
    let dir = std::env::temp_dir().join("sus-render-test");
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    let path = dir.join("report.json");
    std::fs::write(&path, &report).expect("failed to write report");

    let output = bin()
        .arg("render")
        .arg(&path)
        .args(["--format", "markdown"])
        .arg("--no-color")
        .output()
        .expect("failed to run binary");

    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        live("markdown"),
        "reading from a file must match reading from stdin"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn render_output_writes_each_format_and_preserves_the_verdict() {
    let report = live("json");
    let dir = std::env::temp_dir().join(format!("sus-render-output-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("report.txt");

    for format in ["text", "markdown", "github-actions"] {
        std::fs::write(&path, "previous report").unwrap();
        let (expected, expected_code) = render(&report, &["--format", format]);
        let (stdout, code) = render(
            &report,
            &["--format", format, "--output", path.to_str().unwrap()],
        );
        assert!(stdout.is_empty());
        assert_eq!(code, expected_code);
        assert_eq!(code, 1, "the failing verdict must be preserved");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
        assert!(!path.with_extension("txt.tmp").exists());
    }

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn render_help_documents_output() {
    let output = bin().args(["render", "--help"]).output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--output <PATH>"));
}

#[test]
fn the_report_carries_the_interface_hashes() {
    let report: serde_json::Value = serde_json::from_str(&live("json")).unwrap();

    let old = report["old_interface_hash"].as_str().expect("old hash");
    let new = report["new_interface_hash"].as_str().expect("new hash");
    assert_eq!(old.len(), 64);
    assert_ne!(old, new, "the fixtures have different interfaces");

    // And they surface in the rendered human output.
    let (markdown, _) = render(&live("json"), &["--format", "markdown"]);
    assert!(markdown.contains(old));
    assert!(markdown.contains(new));
}

// --- Error handling ----------------------------------------------------------

#[test]
fn render_ignores_unknown_additive_json_fields() {
    let report: serde_json::Value = serde_json::from_str(&live("json")).unwrap();
    let mut unknown = report.clone();

    unknown["future_top_level_field"] = serde_json::json!({
        "note": "ignored by older renderers",
        "nested": {"still_unknown": true}
    });
    unknown["provenance"]["future_nested_field"] = serde_json::json!({
        "extra": "ignored by older renderers"
    });

    let (rendered, code) = render(&unknown.to_string(), &["--format", "markdown"]);

    assert_eq!(
        code, 1,
        "the stored verdict was a failure, so must the exit be"
    );
    assert!(rendered.contains("# Soroban Upgrade Safety Report"));
    assert!(
        rendered.contains("Critical") || rendered.contains("Warning") || rendered.contains("Info")
    );
    assert!(
        rendered.contains("Storage Layout Compatibility")
            || rendered.contains("Call ABI Compatibility")
    );
}

#[test]
fn whitespace_only_render_input_fails_with_a_clear_error() {
    let (_, code) = render("   \n\t  ", &[]);
    assert_ne!(code, 0);

    let mut child = bin()
        .arg("render")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"   \n\t  ")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("saved JSON report"),
        "error should mention the expected saved JSON report, got: {stderr}"
    );
}

#[test]
fn a_malformed_report_fails_with_a_clear_error() {
    let (_, code) = render("{ this is not json", &[]);
    assert_ne!(code, 0);

    let mut child = bin()
        .arg("render")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{ this is not json")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a valid Soroban Upgrade Safeguard JSON report"),
        "error should explain what was expected, got: {stderr}"
    );
}

#[test]
fn an_incompatible_schema_version_fails_with_a_clear_error() {
    let mut report: serde_json::Value = serde_json::from_str(&live("json")).unwrap();
    report["report_schema_version"] = serde_json::json!(9999);
    report["tool_version"] = serde_json::json!("99.0.0");

    let mut child = bin()
        .arg("render")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(report.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("schema version 9999"),
        "error should name the unsupported version, got: {stderr}"
    );
    assert!(
        stderr.contains("99.0.0"),
        "error should name the writing tool version, got: {stderr}"
    );
}

#[test]
fn a_missing_report_file_fails_with_a_clear_error() {
    let output = bin()
        .arg("render")
        .arg("/nonexistent/report.json")
        .output()
        .expect("failed to run binary");

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to inspect report path"),
        "got: {stderr}"
    );
}

#[test]
fn empty_report_rendering_regression_test() {
    // Produce an empty report (identical upgrade with zero findings)
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");
    assert_eq!(output.status.code(), Some(0));

    let empty_report_json = String::from_utf8(output.stdout).unwrap();
    assert!(empty_report_json.contains("\"total_findings\": 0"));

    // 1. Text format path
    let (text_out, text_code) = render(&empty_report_json, &["--format", "text"]);
    assert_eq!(text_code, 0, "text render must exit 0");
    assert!(
        text_out.contains("✅ PASSED"),
        "text output communicates passing verdict"
    );
    assert!(
        text_out.contains("Critical: 0"),
        "text output shows zero critical findings"
    );
    assert!(
        text_out.contains("No relevant changes detected."),
        "text output communicates successful outcome"
    );
    assert!(
        !text_out.contains("--- ["),
        "no empty category headings in text output"
    );
    assert!(
        !text_out.contains("🔴") && !text_out.contains("🟡"),
        "no placeholder finding rows in text output"
    );

    // 2. Markdown format path
    let (md_out, md_code) = render(&empty_report_json, &["--format", "markdown"]);
    assert_eq!(md_code, 0, "markdown render must exit 0");
    assert!(
        md_out.contains("## Status: ✅ PASSED"),
        "markdown output communicates passing verdict"
    );
    assert!(
        md_out.contains("| **Critical** | 0 |"),
        "markdown output shows zero critical findings"
    );
    assert!(
        md_out.contains("No relevant changes detected."),
        "markdown output communicates successful outcome"
    );
    assert!(
        !md_out.contains("### Storage Layout Compatibility"),
        "no empty category headings in markdown output"
    );
    assert!(
        !md_out.contains("### Call ABI Compatibility"),
        "no empty category headings in markdown output"
    );
    assert!(
        !md_out.contains("- 🔴") && !md_out.contains("- 🟡"),
        "no placeholder finding rows in markdown output"
    );
}

// --- --format github-actions -------------------------------------------------

/// Helper: run a live comparison and return its stdout in the requested format,
/// without color and without a timestamp so output is deterministic.
fn live_gha() -> String {
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "github-actions"])
        .output()
        .expect("failed to run binary");
    String::from_utf8(output.stdout).expect("stdout was not valid UTF-8")
}

#[test]
fn render_github_actions_appears_in_help() {
    let output = bin()
        .arg("render")
        .arg("--help")
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("github-actions"),
        "`github-actions` must appear in `render --help`\n---stdout---\n{stdout}"
    );
}

#[test]
fn render_github_actions_matches_live_run() {
    // Capture the live github-actions output and a JSON report from the same
    // comparison, then verify that re-rendering the JSON reproduces it.
    let live_annotations = live_gha();
    let json_report = live("json");

    let (rendered, _) = render(&json_report, &["--format", "github-actions"]);

    assert_eq!(
        rendered, live_annotations,
        "render --format github-actions must reproduce the live annotation output"
    );
}

#[test]
fn render_github_actions_breaking_upgrade_exits_one() {
    let json_report = live("json");
    let (_, code) = render(&json_report, &["--format", "github-actions"]);
    assert_eq!(
        code, 1,
        "a stored failing report must exit 1 under github-actions format"
    );
}

#[test]
fn render_github_actions_passing_report_exits_zero() {
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");
    let json_report = String::from_utf8(output.stdout).unwrap();

    let (rendered, code) = render(&json_report, &["--format", "github-actions"]);

    assert_eq!(code, 0, "a passing report must exit 0");
    assert!(
        rendered.contains("Soroban Upgrade Safeguard: PASSED"),
        "rendered output must contain PASSED summary\n---stdout---\n{rendered}"
    );
}

#[test]
fn render_github_actions_emits_error_annotations_for_critical_findings() {
    let json_report = live("json");
    let (rendered, _) = render(&json_report, &["--format", "github-actions"]);

    assert!(
        rendered.lines().any(|l| l.starts_with("::error::")),
        "render github-actions must emit ::error:: for critical findings\n---stdout---\n{rendered}"
    );
    assert!(
        !rendered.contains('\u{1b}'),
        "github-actions output must not contain ANSI escape codes"
    );
}

#[test]
fn render_github_actions_reuses_existing_renderer_not_a_duplicate() {
    // The live --format github-actions output and the re-rendered output must
    // be identical byte-for-byte, confirming a single shared code path.
    let json_report = live("json");
    let (rendered, _) = render(&json_report, &["--format", "github-actions"]);
    let live_direct = live_gha();

    assert_eq!(
        rendered, live_direct,
        "render and live github-actions output must be byte-identical (shared renderer)"
    );
}

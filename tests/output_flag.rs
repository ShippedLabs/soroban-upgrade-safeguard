//! Integration tests for the `--output` flag (Feature 4).
//!
//! Verifies that `--output PATH` writes the report to the given file,
//! that the file contains only the report (no progress lines), and that
//! without the flag output goes to stdout as before.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn tmp(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name)
}

/// Run the binary with optional `--output`, `--format`, returning
/// (stdout, stderr, exit_code, file_contents_if_output_path_given).
fn run_with_output(
    old: &str,
    new: &str,
    format: &str,
    output_path: Option<&PathBuf>,
) -> (String, String, i32, Option<String>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm(old)).arg(wasm(new));
    cmd.args(["--format", format]);
    if let Some(path) = output_path {
        cmd.args(["--output", path.to_str().unwrap()]);
    }

    let output = cmd.output().expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout not utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr not utf8");
    let code = output.status.code().expect("process killed by signal");

    let file_contents = output_path.map(|p| {
        if p.exists() {
            std::fs::read_to_string(p).expect("failed to read output file")
        } else {
            String::new()
        }
    });

    (stdout, stderr, code, file_contents)
}

// ──────────────────────────────────────────────────────────────────
// JSON format with --output
// ──────────────────────────────────────────────────────────────────

#[test]
fn output_flag_json_writes_to_file_not_stdout() {
    let out = tmp("output_flag_json.json");
    let (stdout, stderr, _code, file) = run_with_output("v1.wasm", "v2.wasm", "json", Some(&out));

    let contents = file.expect("output file should exist");

    // The file must contain valid JSON with the expected structure.
    let json: serde_json::Value = serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("output file not valid JSON: {e}\n{contents}"));
    assert!(json.get("is_safe").is_some(), "JSON must have 'is_safe'");
    assert!(json.get("counts").is_some(), "JSON must have 'counts'");

    // stdout must be empty — report went to the file.
    assert!(
        stdout.trim().is_empty(),
        "stdout must be empty when --output is used, got: {stdout}"
    );

    // stderr should contain the "report written" confirmation.
    assert!(
        stderr.contains("Report written to") || stderr.contains("report written"),
        "stderr must confirm the file was written, got: {stderr}"
    );

    // The file must not contain ANSI escape codes.
    assert!(
        !contents.contains('\u{1b}'),
        "output file must not contain ANSI codes"
    );
}

// ──────────────────────────────────────────────────────────────────
// Markdown format with --output
// ──────────────────────────────────────────────────────────────────

#[test]
fn output_flag_markdown_writes_to_file_not_stdout() {
    let out = tmp("output_flag_markdown.md");
    let (stdout, _stderr, _code, file) =
        run_with_output("v1.wasm", "v2.wasm", "markdown", Some(&out));

    let contents = file.expect("output file should exist");

    assert!(
        contents.contains("# Soroban Upgrade Safety Report"),
        "markdown output must contain heading, got: {contents}"
    );

    // No progress lines (like the loading banner) in the file.
    assert!(
        !contents.contains("Loading and Parsing"),
        "output file must not contain progress lines, got start: {}",
        &contents[..contents.len().min(200)]
    );

    assert!(
        stdout.trim().is_empty(),
        "stdout must be empty when --output is used, got: {stdout}"
    );
}

// ──────────────────────────────────────────────────────────────────
// Text format with --output  (the hard case — progress used to go
// to stdout in text mode, so --output must separate them cleanly)
// ──────────────────────────────────────────────────────────────────

#[test]
fn output_flag_text_writes_report_only_no_progress_lines() {
    let out = tmp("output_flag_text.txt");
    let (stdout, _stderr, _code, file) = run_with_output("v1.wasm", "v2.wasm", "text", Some(&out));

    let contents = file.expect("output file should exist");

    // The report section header must be present.
    assert!(
        contents.contains("SOROBAN UPGRADE SAFETY REPORT"),
        "text output must contain the report header"
    );

    // stdout must be empty.
    assert!(
        stdout.trim().is_empty(),
        "stdout must be empty when --output is used, got: {stdout}"
    );
}

// ──────────────────────────────────────────────────────────────────
// Without --output, stdout receives the report as before
// ──────────────────────────────────────────────────────────────────

#[test]
fn without_output_flag_report_goes_to_stdout() {
    let (stdout, _stderr, _code, _file) = run_with_output("v1.wasm", "v2.wasm", "json", None);

    // stdout must contain valid JSON when no --output is given.
    assert!(
        !stdout.trim().is_empty(),
        "stdout must contain the report when --output is not used"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout not valid JSON: {e}\n{stdout}"));
    assert!(json.get("is_safe").is_some());
}

// ──────────────────────────────────────────────────────────────────
// Safe upgrade also writes correctly to file
// ──────────────────────────────────────────────────────────────────

#[test]
fn output_flag_safe_upgrade_writes_file_and_exits_zero() {
    let out = tmp("output_flag_safe.json");
    let (_stdout, _stderr, code, file) = run_with_output("v1.wasm", "v1.wasm", "json", Some(&out));

    assert_eq!(code, 0, "identical upgrade must exit 0");
    let contents = file.expect("output file should exist");
    let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(json["is_safe"], serde_json::Value::Bool(true));
}

// ──────────────────────────────────────────────────────────────────
// Atomic Writing & Permissions Integration Tests
// ──────────────────────────────────────────────────────────────────

// Permission bit modes are Unix-only; the equivalent behavior on Windows is
// governed by ACLs, so this test is gated like the other `cfg(unix)` tests.
#[cfg(unix)]
#[test]
fn output_flag_atomic_replacement_and_permissions() {
    use std::os::unix::fs::PermissionsExt;

    // `tmp()` paths persist across runs (CI caches `target/`), and this test
    // leaves each file at a read-only 0o400 on success — reset it first so a
    // prior successful run doesn't break this run's initial write.
    fn reset_perms(path: &std::path::Path) {
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o644);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    // Test for Text output replacement & permissions
    let text_out = tmp("atomic_replace_text.txt");
    reset_perms(&text_out);
    std::fs::write(&text_out, b"old content").unwrap();
    let mut perms = std::fs::metadata(&text_out).unwrap().permissions();
    perms.set_mode(0o400);
    std::fs::set_permissions(&text_out, perms).unwrap();

    let (_stdout, _stderr, _code, file) =
        run_with_output("v1.wasm", "v2.wasm", "text", Some(&text_out));
    let text_contents = file.expect("text output file should exist");
    assert!(
        text_contents.contains("SOROBAN UPGRADE SAFETY REPORT"),
        "should contain report"
    );
    let final_perms = std::fs::metadata(&text_out).unwrap().permissions();
    assert_eq!(final_perms.mode() & 0o777, 0o400);

    // Test for Markdown output replacement & permissions
    let md_out = tmp("atomic_replace_markdown.md");
    reset_perms(&md_out);
    std::fs::write(&md_out, b"old content").unwrap();
    let mut perms = std::fs::metadata(&md_out).unwrap().permissions();
    perms.set_mode(0o400);
    std::fs::set_permissions(&md_out, perms).unwrap();

    let (_stdout, _stderr, _code, file) =
        run_with_output("v1.wasm", "v2.wasm", "markdown", Some(&md_out));
    let md_contents = file.expect("markdown output file should exist");
    assert!(
        md_contents.contains("# Soroban Upgrade Safety Report"),
        "should contain report"
    );
    let final_perms = std::fs::metadata(&md_out).unwrap().permissions();
    assert_eq!(final_perms.mode() & 0o777, 0o400);

    // Test for JSON output replacement & permissions
    let json_out = tmp("atomic_replace_json.json");
    reset_perms(&json_out);
    std::fs::write(&json_out, b"old content").unwrap();
    let mut perms = std::fs::metadata(&json_out).unwrap().permissions();
    perms.set_mode(0o400);
    std::fs::set_permissions(&json_out, perms).unwrap();

    let (_stdout, _stderr, _code, file) =
        run_with_output("v1.wasm", "v2.wasm", "json", Some(&json_out));
    let json_contents = file.expect("json output file should exist");
    let json: serde_json::Value = serde_json::from_str(&json_contents).unwrap();
    assert!(json.get("is_safe").is_some());
    let final_perms = std::fs::metadata(&json_out).unwrap().permissions();
    assert_eq!(final_perms.mode() & 0o777, 0o400);
}

// ──────────────────────────────────────────────────────────────────
// Report paths containing spaces (#451)
// ──────────────────────────────────────────────────────────────────

#[test]
fn output_flag_supports_path_with_spaces() {
    let dir = std::env::temp_dir().join(format!(
        "safeguard report path with spaces {}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("failed to create directory with spaces");
    let out = dir.join("report file with spaces.json");

    let (stdout, _stderr, _code, file) = run_with_output("v1.wasm", "v2.wasm", "json", Some(&out));

    let contents = file.expect("output file beneath path with spaces should exist");

    // The file must contain valid JSON report format and can be parsed or inspected
    let json: serde_json::Value = serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("output file not valid JSON: {e}\n{contents}"));
    assert!(
        json.get("is_safe").is_some(),
        "JSON report must contain 'is_safe'"
    );
    assert!(
        json.get("counts").is_some(),
        "JSON report must contain 'counts'"
    );

    assert!(
        stdout.trim().is_empty(),
        "stdout must be empty when --output is used"
    );

    // Verify no extra files were created from split path components
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("read_dir failed")
        .filter_map(|res| res.ok())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "only the expected report file should exist in destination directory, found: {:?}",
        entries.iter().map(|e| e.path()).collect::<Vec<_>>()
    );

    // Clean up temporary test directory
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_dir(&dir);
}

//! Integration tests for the `md` output-format alias.
//!
//! `md` is accepted as a shorthand for `markdown` in `--output` specifications
//! (e.g. `--output md` for stdout, `--output md:report.md` for a file).
//! These tests verify that the alias produces output identical in structure to
//! the canonical `--format markdown` spelling and that no terminal is required.

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

/// Run the binary with `--format markdown` and return (exit_code, stdout, stderr).
fn run_canonical_markdown(old: &str, new: &str) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--format", "markdown"])
        .env_remove("NO_COLOR")
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout not utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr not utf8");
    let code = output.status.code().expect("process killed by signal");
    (code, stdout, stderr)
}

/// Run the binary with `--output md` (alias via stdout) and return
/// (exit_code, stdout, stderr).
fn run_md_alias_stdout(old: &str, new: &str) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--output", "md"])
        .env_remove("NO_COLOR")
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout not utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr not utf8");
    let code = output.status.code().expect("process killed by signal");
    (code, stdout, stderr)
}

/// Run with `--output md:PATH` and return (exit_code, stdout, stderr,
/// file_contents).
fn run_md_alias_file(old: &str, new: &str, path: &PathBuf) -> (i32, String, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .arg(format!("--output=md:{}", path.display()))
        .env_remove("NO_COLOR")
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout not utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr not utf8");
    let code = output.status.code().expect("process killed by signal");
    let file = std::fs::read_to_string(path).unwrap_or_default();
    (code, stdout, stderr, file)
}

// ── alias exits with the same code as the canonical spelling ─────────────────

#[test]
fn md_alias_stdout_exits_same_as_markdown_on_safe_upgrade() {
    let (canonical_code, _, _) = run_canonical_markdown("v1.wasm", "v1.wasm");
    let (alias_code, _, _) = run_md_alias_stdout("v1.wasm", "v1.wasm");
    assert_eq!(
        alias_code, canonical_code,
        "--output md must exit with the same code as --format markdown on a safe upgrade"
    );
    assert_eq!(alias_code, 0, "safe upgrade must exit 0");
}

#[test]
fn md_alias_stdout_exits_same_as_markdown_on_breaking_upgrade() {
    let (canonical_code, _, _) = run_canonical_markdown("v1.wasm", "v2.wasm");
    let (alias_code, _, _) = run_md_alias_stdout("v1.wasm", "v2.wasm");
    assert_eq!(
        alias_code, canonical_code,
        "--output md must exit with the same code as --format markdown on a breaking upgrade"
    );
    assert_eq!(alias_code, 1, "breaking upgrade must exit 1");
}

// ── alias produces valid Markdown with the report heading ────────────────────

#[test]
fn md_alias_stdout_output_is_valid_markdown_with_heading() {
    let (_, stdout, _) = run_md_alias_stdout("v1.wasm", "v1.wasm");
    assert!(
        stdout.contains("# Soroban Upgrade Safety Report"),
        "--output md must produce a Markdown document with the report heading; got:\n{stdout}"
    );
}

#[test]
fn md_alias_stdout_breaking_upgrade_has_failed_status() {
    let (_, stdout, _) = run_md_alias_stdout("v1.wasm", "v2.wasm");
    assert!(
        stdout.contains("# Soroban Upgrade Safety Report"),
        "--output md must include the report heading"
    );
    assert!(
        stdout.contains("❌ FAILED") || stdout.contains("FAILED"),
        "--output md must report FAILED status for a breaking upgrade; got:\n{stdout}"
    );
}

#[test]
fn md_alias_stdout_safe_upgrade_has_passed_status() {
    let (_, stdout, _) = run_md_alias_stdout("v1.wasm", "v1.wasm");
    assert!(
        stdout.contains("# Soroban Upgrade Safety Report"),
        "--output md must include the report heading"
    );
    assert!(
        stdout.contains("✅ PASSED") || stdout.contains("PASSED"),
        "--output md must report PASSED status for a safe upgrade; got:\n{stdout}"
    );
}

// ── alias output is free of ANSI escape codes ────────────────────────────────

#[test]
fn md_alias_stdout_output_has_no_ansi_codes() {
    let (_, stdout, _) = run_md_alias_stdout("v1.wasm", "v2.wasm");
    assert!(
        !stdout.contains('\u{1b}'),
        "--output md must not emit ANSI escape codes in the Markdown output"
    );
}

// ── alias does not require a terminal (non-interactive) ──────────────────────

#[test]
fn md_alias_works_without_terminal() {
    // Confirm the command succeeds when stdin/stdout are not a tty, which is
    // the standard condition in CI environments.  The env_remove("TERM")
    // ensures no terminal type is advertised.
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v1.wasm"))
        .args(["--output", "md"])
        .env_remove("TERM")
        .env_remove("COLORTERM")
        .env_remove("NO_COLOR")
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout not utf8");
    let code = output.status.code().expect("process killed by signal");

    assert_eq!(code, 0, "--output md must succeed without a terminal");
    assert!(
        stdout.contains("# Soroban Upgrade Safety Report"),
        "--output md without a terminal must still produce a Markdown report"
    );
}

// ── alias via file path: --output md:report.md ───────────────────────────────

#[test]
fn md_alias_file_writes_markdown_to_disk() {
    let path = tmp("md_alias_output.md");
    let (code, stdout, _stderr, file) = run_md_alias_file("v1.wasm", "v1.wasm", &path);

    assert_eq!(code, 0, "--output md:FILE must exit 0 for a safe upgrade");

    // Report went to the file, not stdout.
    assert!(
        stdout.trim().is_empty(),
        "stdout must be empty when --output md:FILE is used; got: {stdout}"
    );

    // The file must contain the Markdown report.
    assert!(
        file.contains("# Soroban Upgrade Safety Report"),
        "--output md:FILE must write a Markdown report to the file"
    );
    assert!(
        !file.contains('\u{1b}'),
        "file written by --output md:FILE must not contain ANSI codes"
    );
}

#[test]
fn md_alias_file_breaking_upgrade_exits_one_and_writes_file() {
    let path = tmp("md_alias_breaking.md");
    let (code, _stdout, _stderr, file) = run_md_alias_file("v1.wasm", "v2.wasm", &path);

    assert_eq!(
        code, 1,
        "--output md:FILE must exit 1 for a breaking upgrade"
    );
    assert!(
        file.contains("# Soroban Upgrade Safety Report"),
        "--output md:FILE must write the report even when the upgrade is unsafe"
    );
    assert!(
        file.contains("❌ FAILED") || file.contains("FAILED"),
        "--output md:FILE must include the FAILED verdict"
    );
}

// ── alias output matches canonical markdown output structurally ──────────────

#[test]
fn md_alias_stdout_output_matches_canonical_markdown_structure() {
    let (_, canonical, _) = run_canonical_markdown("v1.wasm", "v1.wasm");
    let (_, alias_out, _) = run_md_alias_stdout("v1.wasm", "v1.wasm");

    // Both must start with the same report heading.
    assert!(canonical.contains("# Soroban Upgrade Safety Report"));
    assert!(alias_out.contains("# Soroban Upgrade Safety Report"));

    // Key structural sections must be present in both.
    for section in &[
        "## Status:",
        "### Summary Table",
        "### Compatibility Verdicts",
    ] {
        assert!(
            canonical.contains(section),
            "canonical markdown missing section: {section}"
        );
        assert!(
            alias_out.contains(section),
            "--output md missing section: {section}"
        );
    }
}

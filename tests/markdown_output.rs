//! Integration tests for the `--format markdown` PR-comment output.

use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run_markdown(old: &str, new: &str) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--format", "markdown"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    (code, stdout)
}

#[test]
fn markdown_breaking_upgrade_is_grouped_and_exits_one() {
    let (code, stdout) = run_markdown("v1.wasm", "v2.wasm");

    assert_eq!(code, 1, "breaking upgrade must exit 1");
    assert!(stdout.starts_with("# Soroban Upgrade Safety Report\n"));
    assert!(stdout.contains("**Status:** FAILED (critical breaking changes detected)"));
    assert!(stdout.contains("| Severity | Count |"));
    assert!(stdout.contains("| Critical | 3 |"));
    assert!(stdout.contains("| Warning | 0 |"));
    assert!(stdout.contains("| Info | 1 |"));
    assert!(stdout.contains("| Total | 4 |"));
    assert!(stdout.contains("## Findings by Category"));
    assert!(stdout.contains("### Function Signature Changed"));
    assert!(stdout
        .contains("- **Critical:** Function 'initialize': parameter count changed from 1 to 2."));
    assert!(stdout.contains("### Event Enum Case Added"));
    assert!(stdout.contains("- **Info:** Event enum 'StatusEvent': new case 'Archived'"));
    assert!(
        !stdout.contains('\u{1b}'),
        "Markdown output must not contain ANSI codes"
    );
}

#[test]
fn markdown_identical_upgrade_is_safe_and_exits_zero() {
    let (code, stdout) = run_markdown("v1.wasm", "v1.wasm");

    assert_eq!(code, 0, "non-breaking upgrade must exit 0");
    assert!(stdout.contains("**Status:** PASSED (no breaking changes detected)"));
    assert!(stdout.contains("| Critical | 0 |"));
    assert!(stdout.contains("| Total | 0 |"));
    assert!(stdout.contains("No relevant changes detected."));
    assert!(
        !stdout.contains('\u{1b}'),
        "Markdown output must not contain ANSI codes"
    );
}

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// Run the binary with `--format markdown` on the given pair and return
/// (exit code, raw stdout, raw stderr).
fn run_markdown(old: &str, new: &str) -> (i32, String, String) {
    run_markdown_ext(old, new, false)
}

/// Same as `run_markdown`, optionally passing `--strict`.
fn run_markdown_ext(old: &str, new: &str, strict: bool) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm(old)).arg(wasm(new)).args(["--format", "markdown"]);
    if strict {
        cmd.arg("--strict");
    }
    let output = cmd.output().expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    (code, stdout, stderr)
}

#[test]
fn markdown_breaking_upgrade_reports_critical_and_exits_one() {
    let (code, stdout, stderr) = run_markdown("v1.wasm", "v2.wasm");

    // Exit code must signal failure when a Critical finding exists.
    assert_eq!(code, 1, "breaking upgrade must exit 1");

    // Verify Markdown format and sections
    assert!(
        stdout.contains("# Soroban Upgrade Safety Report"),
        "Missing title"
    );
    assert!(
        stdout.contains("## Status: ❌ FAILED (Critical breaking changes detected)"),
        "Missing status"
    );
    assert!(
        stdout.contains("### Summary Table"),
        "Missing summary table heading"
    );
    assert!(
        stdout.contains("| Finding Severity | Count |"),
        "Missing table columns"
    );
    assert!(stdout.contains("| **Critical** |"), "Missing critical row");
    assert!(
        stdout.contains("**Recommended SemVer Bump**: `major`"),
        "Missing recommended bump"
    );

    // Grouping and finding listing checks
    assert!(
        stdout.contains("### Function Signature Changed"),
        "Should group functions under signature changed"
    );
    assert!(
        stdout.contains("### Struct Field Removed"),
        "Should group structs under struct field removed"
    );
    assert!(
        stdout.contains("🔴"),
        "Should use red circle emoji for critical findings"
    );

    // Output must be free of ANSI color codes.
    assert!(
        !stdout.contains('\u{1b}'),
        "Markdown output must not contain ANSI codes"
    );

    // Decorative progress should go to stderr
    assert!(
        stderr.contains("🔍 Soroban Upgrade Safeguard"),
        "Decorative progress should be in stderr"
    );
}

#[test]
fn markdown_identical_upgrade_is_safe_and_exits_zero() {
    let (code, stdout, stderr) = run_markdown("v1.wasm", "v1.wasm");

    assert_eq!(code, 0, "non-breaking upgrade must exit 0");
    assert!(
        stdout.contains("# Soroban Upgrade Safety Report"),
        "Missing title"
    );
    assert!(
        stdout.contains("## Status: ✅ PASSED (No breaking changes detected)"),
        "Missing status"
    );
    assert!(
        stdout.contains("No relevant changes detected."),
        "Missing no changes message"
    );
    assert!(
        stdout.contains("**Recommended SemVer Bump**: `patch`"),
        "Missing recommended bump"
    );

    assert!(
        !stdout.contains('\u{1b}'),
        "Markdown output must not contain ANSI codes"
    );

    assert!(
        stderr.contains("🔍 Soroban Upgrade Safeguard"),
        "Decorative progress should be in stderr"
    );
}

#[test]
fn markdown_strict_warning_only_indicates_strict_mode() {
    let (code, stdout, _stderr) = run_markdown_ext("v1.wasm", "v3.wasm", true);

    assert_eq!(
        code, 1,
        "warning-only upgrade under strict mode must exit 1"
    );
    assert!(
        stdout.contains("[STRICT MODE ACTIVE]"),
        "Markdown report must indicate strict mode is active"
    );
    assert!(
        stdout.contains("## Status: ❌ FAILED (Warnings detected in strict mode)"),
        "A warnings-only strict failure must not be labelled a critical breaking change"
    );
    assert!(
        !stdout.contains("Critical breaking changes detected"),
        "Must not contradict the zero critical count in the summary table"
    );
}

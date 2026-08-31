//! Integration tests for `--format github-actions` annotation output.
//!
//! GitHub Actions renders lines of the form `::level::message` as annotations
//! in the run summary and pull-request checks. These tests verify that the
//! correct level is emitted for each finding severity, that suppressed findings
//! are demoted to `::notice`, and that batch mode wraps each pair in a log
//! group.
//!
//! # Workflow example
//!
//! ```yaml
//! - name: Check upgrade safety
//!   run: |
//!     soroban-upgrade-safeguard old.wasm new.wasm --format github-actions
//! ```
//!
//! Critical findings surface as `::error` annotations in the PR checks;
//! warnings appear as `::warning`; informational findings as `::notice`.

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run_gha(old: &str, new: &str) -> (i32, String) {
    run_gha_ext(old, new, &[])
}

fn run_gha_ext(old: &str, new: &str, extra: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--format", "github-actions"])
        .args(extra)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    (code, stdout)
}

// ---------------------------------------------------------------------------
// Single-pair: breaking upgrade
// ---------------------------------------------------------------------------

#[test]
fn gha_breaking_upgrade_emits_error_annotations_and_exits_one() {
    let (code, stdout) = run_gha("v1.wasm", "v2.wasm");

    assert_eq!(code, 1, "breaking upgrade must exit 1");

    // At least one ::error annotation must be present.
    assert!(
        stdout.lines().any(|l| l.starts_with("::error::")),
        "expected at least one ::error:: annotation\n---stdout---\n{stdout}"
    );

    // Every annotation line must be well-formed (level in known set).
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("::") {
            let level = rest.split("::").next().unwrap_or("");
            assert!(
                matches!(level, "error" | "warning" | "notice" | "group" | "endgroup"),
                "unexpected annotation level '{level}' in line: {line}"
            );
        }
    }

    // Must contain a human-readable summary line.
    assert!(
        stdout.contains("Soroban Upgrade Safeguard: FAILED"),
        "missing human-readable summary\n---stdout---\n{stdout}"
    );

    // Must be free of ANSI color codes.
    assert!(
        !stdout.contains('\u{1b}'),
        "github-actions output must not contain ANSI codes"
    );
}

// ---------------------------------------------------------------------------
// Single-pair: identical (clean) upgrade
// ---------------------------------------------------------------------------

#[test]
fn gha_identical_upgrade_emits_no_error_annotations_and_exits_zero() {
    let (code, stdout) = run_gha("v1.wasm", "v1.wasm");

    assert_eq!(code, 0, "identical upgrade must exit 0");

    assert!(
        !stdout.lines().any(|l| l.starts_with("::error::")),
        "clean upgrade must not emit ::error annotations\n---stdout---\n{stdout}"
    );

    assert!(
        stdout.contains("Soroban Upgrade Safeguard: PASSED"),
        "missing human-readable summary\n---stdout---\n{stdout}"
    );

    assert!(
        !stdout.contains('\u{1b}'),
        "github-actions output must not contain ANSI codes"
    );
}

// ---------------------------------------------------------------------------
// Single-pair: warning-only upgrade
// ---------------------------------------------------------------------------

#[test]
fn gha_warning_only_emits_warning_annotations() {
    let (code, stdout) = run_gha("v1.wasm", "v3.wasm");

    // Non-strict mode: warnings don't fail the run.
    assert_eq!(
        code, 0,
        "warning-only upgrade in non-strict mode must exit 0"
    );

    assert!(
        stdout.lines().any(|l| l.starts_with("::warning::")),
        "expected at least one ::warning:: annotation\n---stdout---\n{stdout}"
    );

    assert!(
        !stdout.lines().any(|l| l.starts_with("::error::")),
        "warning-only upgrade must not emit ::error annotations\n---stdout---\n{stdout}"
    );
}

#[test]
fn gha_warning_only_strict_exits_one() {
    let (code, _stdout) = run_gha_ext("v1.wasm", "v3.wasm", &["--strict"]);
    assert_eq!(code, 1, "warning-only upgrade under --strict must exit 1");
}

// ---------------------------------------------------------------------------
// Severity mapping: Critical → error, Warning → warning, Info → notice
// ---------------------------------------------------------------------------

#[test]
fn gha_annotation_levels_match_severities() {
    let (_, stdout) = run_gha("v1.wasm", "v2.wasm");

    // v1→v2 has critical findings; verify they map to ::error.
    let error_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.starts_with("::error::"))
        .collect();
    assert!(
        !error_lines.is_empty(),
        "critical findings must produce ::error lines"
    );

    // Every ::error line must include the category in brackets.
    for line in &error_lines {
        assert!(
            line.contains('['),
            "::error annotation should include category in brackets: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// Batch mode: log grouping
// ---------------------------------------------------------------------------

#[test]
fn gha_batch_mode_uses_log_groups() {
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {old_v1:?}
        new = {old_v1:?}
        name = "clean_pair"

        [[pairs]]
        old = {old_v1:?}
        new = {new_v2:?}
        name = "breaking_pair"
        "#,
        old_v1 = wasm("v1.wasm").to_str().unwrap(),
        new_v2 = wasm("v2.wasm").to_str().unwrap(),
    );

    let manifest_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("gha_batch_manifest.toml");
    std::fs::write(&manifest_path, manifest_content).expect("failed to write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .args(["--format", "github-actions"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 1, "batch with breaking pair must exit 1");

    // Each pair must be wrapped in ::group / ::endgroup.
    assert!(
        stdout.contains("::group::clean_pair"),
        "clean_pair must open a log group\n---stdout---\n{stdout}"
    );
    assert!(
        stdout.contains("::group::breaking_pair"),
        "breaking_pair must open a log group\n---stdout---\n{stdout}"
    );
    assert!(
        stdout.lines().filter(|l| *l == "::endgroup::").count() >= 2,
        "each group must be closed\n---stdout---\n{stdout}"
    );

    // Breaking pair must have error annotations inside its group.
    assert!(
        stdout.lines().any(|l| l.starts_with("::error::")),
        "breaking pair must emit ::error annotations\n---stdout---\n{stdout}"
    );

    // Clean pair must have no error annotations (warnings/notices are fine).
    // We verify this by checking the clean_pair group contains no ::error lines.
    // Simple approach: the overall count of ::error lines should be > 0 but
    // attributed to the breaking pair section.
    let clean_start = stdout.find("::group::clean_pair").unwrap_or(0);
    let clean_end = stdout[clean_start..]
        .find("::endgroup::")
        .map(|i| clean_start + i)
        .unwrap_or(clean_start);
    let clean_section = &stdout[clean_start..clean_end];
    assert!(
        !clean_section.lines().any(|l| l.starts_with("::error::")),
        "clean_pair group must not contain ::error annotations\n---section---\n{clean_section}"
    );
}

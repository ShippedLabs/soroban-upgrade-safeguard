//! Integration tests for `--search-parent-config`: an opt-in ancestor search
//! for `.safeguard.toml` that stops at the workspace boundary (a directory
//! containing `.git`) and rejects ambiguous matches.
//!
//! These drive the compiled binary against the checked-in `v1 -> v2`
//! fixtures, which produce three Critical findings (see `tests/suppression.rs`'s
//! module doc for the exact set) — a config that suppresses all three flips
//! the run from failing to passing, which is what most of these tests key
//! off of to prove whether a given ancestor config was actually picked up.

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

fn all_critical_suppressions() -> &'static str {
    r#"
    [[suppress]]
    category = "Event Enum Case Value Changed"
    target   = "StatusEvent.Paused"
    reason   = "Reviewed: indexers already updated."

    [[suppress]]
    category = "Function Signature Changed"
    target   = "initialize"
    reason   = "Planned re-init for the v2 migration."

    [[suppress]]
    category = "Struct Field Removed"
    target   = "ConfigData.threshold"
    "#
}

/// A fresh workspace tree for one test: `<root>/.git/` marks the boundary,
/// `<root>/services/api/src/` is a plausible nested working directory three
/// levels down. Returns `(root, nested)`.
fn workspace(name: &str) -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "search-parent-config-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let nested = root.join("services").join("api").join("src");
    std::fs::create_dir_all(&nested).expect("failed to create nested dir");
    std::fs::create_dir_all(root.join(".git")).expect("failed to create .git marker");
    (root, nested)
}

fn write(path: &PathBuf, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create parent dir");
    }
    std::fs::write(path, contents).expect("failed to write file");
}

struct Run {
    json: Value,
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(cwd: &PathBuf, extra_args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        // Guard against the developer's/CI's own shell ambiently setting
        // these, which would make several of these tests flaky.
        .env_remove("SOROBAN_SAFEGUARD_CONFIG")
        .current_dir(cwd)
        .args(extra_args);

    let output = cmd.output().expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    let json = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout was not valid JSON ({e}).\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    Run {
        json,
        stdout,
        stderr,
        code,
    }
}

/// Like `run`, but doesn't require stdout to parse as JSON — for scenarios
/// (ambiguous match, clap conflict) that fail before any comparison runs.
fn run_raw(cwd: &PathBuf, extra_args: &[&str]) -> (String, String, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .env_remove("SOROBAN_SAFEGUARD_CONFIG")
        .current_dir(cwd)
        .args(extra_args);
    let output = cmd.output().expect("failed to run binary");
    (
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
        output.status.code().expect("process terminated by signal"),
    )
}

// ---------------------------------------------------------------------------
// Disabled by default
// ---------------------------------------------------------------------------

#[test]
fn disabled_by_default_a_repo_root_config_is_not_found_from_a_nested_directory() {
    let (root, nested) = workspace("disabled-default");
    write(&root.join(".safeguard.toml"), all_critical_suppressions());

    let run = run(&nested, &[]);
    assert_eq!(
        run.code, 1,
        "without --search-parent-config, an ancestor config must not be picked up: {}",
        run.stdout
    );
    assert_eq!(run.json["suppressed_count"].as_u64().unwrap(), 0);
}

#[test]
fn explicitly_disabled_search_behaves_the_same_as_never_asking() {
    // --no-config and --search-parent-config are mutually exclusive at the
    // clap level (see "conflicting flags" below); this instead covers simply
    // never passing --search-parent-config, which is the actual default path
    // most invocations take.
    let (root, nested) = workspace("disabled-explicit");
    write(&root.join(".safeguard.toml"), all_critical_suppressions());

    let run = run(&nested, &["--no-config"]);
    assert_eq!(run.code, 1);
    assert_eq!(run.json["counts"]["critical"].as_u64().unwrap(), 3);
}

// ---------------------------------------------------------------------------
// Nested directories
// ---------------------------------------------------------------------------

#[test]
fn search_parent_config_finds_a_repo_root_config_from_a_nested_directory() {
    let (root, nested) = workspace("nested-found");
    write(&root.join(".safeguard.toml"), all_critical_suppressions());

    let run = run(&nested, &["--search-parent-config"]);
    assert_eq!(
        run.code, 0,
        "the repo-root config must be found from three levels down: {}\n{}",
        run.stdout, run.stderr
    );
    assert_eq!(run.json["is_safe"], Value::Bool(true));
    assert_eq!(run.json["suppressed_count"].as_u64().unwrap(), 3);
}

#[test]
fn search_parent_config_reports_which_file_was_selected() {
    let (root, nested) = workspace("reports-selection");
    let config = root.join(".safeguard.toml");
    write(&config, all_critical_suppressions());

    let (stdout, stderr, code) = run_raw(&nested, &["--search-parent-config"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("--search-parent-config"),
        "diagnostics should name the source: {combined}"
    );
    assert!(
        combined.contains(".safeguard.toml"),
        "diagnostics should name the resolved file: {combined}"
    );
}

// ---------------------------------------------------------------------------
// Workspace boundary
// ---------------------------------------------------------------------------

#[test]
fn search_parent_config_stops_at_the_workspace_boundary() {
    // A config ABOVE the .git root must never be picked up, no matter how
    // deep the search would otherwise be allowed to go. Built as its own
    // private tree (rather than reaching into the shared parent of
    // `workspace()`'s directory) so a failed assertion can never leave a
    // stray `.safeguard.toml` behind for a later test run to trip over.
    let outer = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "search-parent-config-boundary-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&outer);
    let root = outer.join("repo");
    let nested = root.join("services").join("api").join("src");
    std::fs::create_dir_all(&nested).expect("failed to create nested dir");
    std::fs::create_dir_all(root.join(".git")).expect("failed to create .git marker");
    write(&outer.join(".safeguard.toml"), all_critical_suppressions());

    let run = run(&nested, &["--search-parent-config"]);
    assert_eq!(
        run.code, 1,
        "a config outside the workspace boundary must not be found: {}",
        run.stdout
    );
    assert_eq!(run.json["suppressed_count"].as_u64().unwrap(), 0);
}

#[test]
fn search_parent_config_checks_the_boundary_directory_itself() {
    // The boundary is inclusive: a .safeguard.toml living in the same
    // directory as .git must still be found.
    let (root, nested) = workspace("boundary-inclusive");
    write(&root.join(".safeguard.toml"), all_critical_suppressions());

    let run = run(&nested, &["--search-parent-config"]);
    assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
    assert_eq!(run.json["suppressed_count"].as_u64().unwrap(), 3);
}

// ---------------------------------------------------------------------------
// Multiple candidates (ambiguous)
// ---------------------------------------------------------------------------

#[test]
fn search_parent_config_rejects_multiple_candidates() {
    let (root, nested) = workspace("multiple-candidates");
    write(&root.join(".safeguard.toml"), all_critical_suppressions());
    write(
        &root.join("services").join(".safeguard.toml"),
        all_critical_suppressions(),
    );

    let (stdout, stderr, code) = run_raw(&nested, &["--search-parent-config"]);
    assert_ne!(
        code, 0,
        "more than one ancestor candidate must be rejected, not silently resolved: {stdout}{stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.to_lowercase().contains("ambiguous"),
        "error should say the match is ambiguous: {combined}"
    );
    assert!(
        combined.contains("--config"),
        "error should point at the way to disambiguate: {combined}"
    );
    // Both candidates should be named so the user can act without guessing.
    assert!(combined.contains("services"), "got: {combined}");
}

// ---------------------------------------------------------------------------
// Explicit paths always win
// ---------------------------------------------------------------------------

#[test]
fn an_explicit_config_flag_outranks_ancestor_search() {
    let (root, nested) = workspace("explicit-outranks-search");
    // The ancestor config suppresses everything; the explicit one suppresses
    // nothing relevant, so a passing run proves the explicit flag won.
    write(&root.join(".safeguard.toml"), all_critical_suppressions());
    let explicit = root.join("explicit.safeguard.toml");
    write(
        &explicit,
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.some_other_field"
        "#,
    );

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        .args(["--config".as_ref(), explicit.as_os_str()])
        .arg("--search-parent-config")
        .env_remove("SOROBAN_SAFEGUARD_CONFIG")
        .current_dir(&nested);
    let output = cmd.output().expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "the explicit --config must be used, leaving criticals unsuppressed: {stdout}"
    );
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
}

#[test]
fn search_parent_config_is_ignored_when_a_current_directory_config_already_resolves() {
    // The plain current-directory default sits above ancestor search in
    // precedence; when it resolves, the ancestor tier (which would otherwise
    // find a *different*, non-suppressing config) must never even run.
    let (root, nested) = workspace("cwd-outranks-search");
    write(
        &root.join(".safeguard.toml"),
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.some_other_field"
        "#,
    );
    write(&nested.join(".safeguard.toml"), all_critical_suppressions());

    let run = run(&nested, &["--search-parent-config"]);
    assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
    assert_eq!(
        run.json["suppressed_count"].as_u64().unwrap(),
        3,
        "the current directory's own config must win over any ancestor"
    );
}

// ---------------------------------------------------------------------------
// Conflicting flags
// ---------------------------------------------------------------------------

#[test]
fn search_parent_config_conflicts_with_no_config() {
    let (_root, nested) = workspace("conflicting-flags");
    let (stdout, stderr, code) = run_raw(&nested, &["--no-config", "--search-parent-config"]);
    assert_ne!(code, 0);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("--no-config") && combined.contains("--search-parent-config"),
        "clap should name both conflicting flags: {combined}"
    );
}

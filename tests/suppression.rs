//! Integration tests for the suppression config (`.safeguard.toml`).
//!
//! These drive the compiled binary with `--config` against the checked-in
//! `v1 -> v2` fixtures, which produce three Critical findings:
//!
//! - `Event Enum Case Value Changed` on `StatusEvent.Paused`
//! - `Function Signature Changed`     on `initialize`
//! - `Struct Field Removed`           on `ConfigData.threshold`
//!
//! and assert that suppressions flip the failing set without hiding findings.

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

fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

/// Run the binary in JSON mode comparing `v1 -> v2`, optionally with a config.
/// Returns (parsed JSON, exit code).
fn run(config: Option<&PathBuf>) -> (Value, i32) {
    run_ext(config, &[], None)
}

fn run_ext(config: Option<&PathBuf>, extra_args: &[&str], cwd: Option<&PathBuf>) -> (Value, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        // Guard against the developer's/CI's own shell ambiently setting this,
        // which would make every "no config" test below flaky.
        .env_remove("SOROBAN_SAFEGUARD_CONFIG");
    if let Some(path) = config {
        cmd.args(["--config".as_ref(), path.as_os_str()]);
    }
    cmd.args(extra_args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let output = cmd.output().expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));
    let code = output.status.code().expect("process terminated by signal");
    (json, code)
}

/// Like `run_ext`, but sets `SOROBAN_SAFEGUARD_CONFIG` for the child process
/// instead of (or alongside) `--config`.
fn run_with_env_config(
    config: Option<&PathBuf>,
    env_config: Option<&PathBuf>,
    extra_args: &[&str],
    cwd: Option<&PathBuf>,
) -> (Value, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"]);
    match env_config {
        Some(path) => {
            cmd.env("SOROBAN_SAFEGUARD_CONFIG", path);
        }
        None => {
            cmd.env_remove("SOROBAN_SAFEGUARD_CONFIG");
        }
    }
    if let Some(path) = config {
        cmd.args(["--config".as_ref(), path.as_os_str()]);
    }
    cmd.args(extra_args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let output = cmd.output().expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));
    let code = output.status.code().expect("process terminated by signal");
    (json, code)
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
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(
        code, 1,
        "unrelated critical findings must still fail the run"
    );
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 1);
    assert!(
        findings(&json)
            .iter()
            .any(|(c, t, s)| c == "Struct Field Removed"
                && t.as_deref() == Some("ConfigData.threshold")
                && *s),
        "the removed field must appear as suppressed when matched by rule_id"
    );
}

#[test]
fn suppressing_all_criticals_passes_but_still_lists_them() {
    let config = write_config("all", all_critical_suppressions());

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
fn default_config_is_auto_loaded_without_no_config() {
    let cwd = temp_dir("auto-load-default-config");
    std::fs::write(cwd.join(".safeguard.toml"), all_critical_suppressions())
        .expect("failed to write default config");

    let (json, code) = run_ext(None, &[], Some(&cwd));

    assert_eq!(code, 0, "default .safeguard.toml should still load");
    assert_eq!(json["is_safe"], Value::Bool(true));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 3);
}

#[test]
fn no_config_ignores_auto_loaded_default_config() {
    let cwd = temp_dir("no-config-ignores-default");
    std::fs::write(cwd.join(".safeguard.toml"), all_critical_suppressions())
        .expect("failed to write default config");

    let (json, code) = run_ext(None, &["--no-config"], Some(&cwd));

    assert_eq!(code, 1, "--no-config should expose unsuppressed criticals");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 3);
}

#[test]
fn no_config_conflicts_with_explicit_config() {
    let config = write_config("conflict", all_critical_suppressions());
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        .args(["--config".as_ref(), config.as_os_str()])
        .arg("--no-config")
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "--no-config and --config should be rejected together"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--config") && stderr.contains("--no-config"),
        "conflict error should mention both flags: {stderr}"
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
        category = "Event Enum Case Value Changed"
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

// ---------------------------------------------------------------------------
// SOROBAN_SAFEGUARD_CONFIG environment variable
// ---------------------------------------------------------------------------

#[test]
fn env_var_missing_entirely_falls_back_to_current_default_behavior() {
    // No --config, no SOROBAN_SAFEGUARD_CONFIG, and (via the temp cwd) no
    // auto-discovered .safeguard.toml -> behaves exactly as before this
    // feature existed: criticals fail the run, nothing suppressed.
    let cwd = temp_dir("env-var-absent");
    let (json, code) = run_with_env_config(None, None, &[], Some(&cwd));

    assert_eq!(code, 1);
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 3);
}

#[test]
fn env_var_is_used_when_cli_flag_is_absent() {
    let config = write_config("env-var-basic", all_critical_suppressions());
    let cwd = temp_dir("env-var-basic-cwd");

    let (json, code) = run_with_env_config(None, Some(&config), &[], Some(&cwd));

    assert_eq!(
        code, 0,
        "SOROBAN_SAFEGUARD_CONFIG should be read when --config is absent"
    );
    assert_eq!(json["is_safe"], Value::Bool(true));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 3);
}

#[test]
fn explicit_cli_config_outranks_env_var() {
    // The env var names a config that suppresses everything; --config names
    // one that suppresses nothing relevant. The explicit flag must win.
    let env_config = write_config("env-var-precedence-env", all_critical_suppressions());
    let cli_config = write_config(
        "env-var-precedence-cli",
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.some_other_field"
        "#,
    );
    let cwd = temp_dir("env-var-precedence-cwd");

    let (json, code) = run_with_env_config(Some(&cli_config), Some(&env_config), &[], Some(&cwd));

    assert_eq!(
        code, 1,
        "--config must win over SOROBAN_SAFEGUARD_CONFIG, leaving criticals unsuppressed"
    );
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
}

#[test]
fn explicit_cli_config_overrides_discovery_and_env_and_keeps_loaded_rules() {
    let cwd = temp_dir("explicit-config-precedence");
    let discovered = cwd.join(".safeguard.toml");
    std::fs::write(
        &discovered,
        r#"
        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"
        reason   = "auto-discovered suppression"
        "#,
    )
    .expect("failed to write discovered config");

    let env_config = write_config(
        "explicit-precedence-env",
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "env suppression"
        "#,
    );

    let cli_config = write_config(
        "explicit-precedence-cli",
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.some_other_field"
        reason   = "explicit file suppression"
        "#,
    );

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json"])
        .args(["--config", cli_config.to_str().unwrap()])
        .env("SOROBAN_SAFEGUARD_CONFIG", env_config)
        .current_dir(&cwd);

    let output = cmd.output().expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"));
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(
        code, 1,
        "the explicit config must win over both discovery and env: {stdout}"
    );
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 3);
    assert!(json["findings_by_category"].is_object());
    assert_eq!(
        json["findings_by_category"]["Struct Field Removed"][0]["target"],
        Value::String("ConfigData.threshold".to_string())
    );
    assert!(
        json["findings_by_category"]["Struct Field Removed"][0]["suppressed"]
            .as_bool()
            .unwrap_or(false)
            == false,
        "the explicit file should be the source of truth, not the env/discovered configs"
    );
}

#[test]
fn env_var_outranks_auto_discovered_default_config() {
    // The cwd has its own .safeguard.toml (would normally auto-load and
    // suppress everything); the env var names a config that suppresses
    // nothing relevant. The env var must win over auto-discovery.
    let cwd = temp_dir("env-var-outranks-default");
    std::fs::write(cwd.join(".safeguard.toml"), all_critical_suppressions())
        .expect("failed to write default config");
    let env_config = write_config(
        "env-var-outranks-default-env",
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.some_other_field"
        "#,
    );

    let (json, code) = run_with_env_config(None, Some(&env_config), &[], Some(&cwd));

    assert_eq!(
        code, 1,
        "SOROBAN_SAFEGUARD_CONFIG must outrank the auto-discovered .safeguard.toml"
    );
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
}

#[test]
fn no_config_flag_outranks_env_var() {
    let config = write_config("env-var-no-config", all_critical_suppressions());
    let cwd = temp_dir("env-var-no-config-cwd");

    let (json, code) = run_with_env_config(None, Some(&config), &["--no-config"], Some(&cwd));

    assert_eq!(
        code, 1,
        "--no-config must override SOROBAN_SAFEGUARD_CONFIG entirely"
    );
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 0);
    assert_eq!(json["counts"]["critical"].as_u64().unwrap(), 3);
}

#[test]
fn missing_env_var_config_is_an_error() {
    // A path named by SOROBAN_SAFEGUARD_CONFIG that does not exist must be a
    // hard error, exactly like a missing --config path: a typo in a CI
    // pipeline's env var must never be silently treated as "no suppressions".
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("env-does-not-exist.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .env("SOROBAN_SAFEGUARD_CONFIG", &missing)
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "missing SOROBAN_SAFEGUARD_CONFIG-named config must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("suppression config"),
        "error should mention the suppression config: {stderr}"
    );
}

#[test]
fn malformed_env_var_config_is_an_error() {
    let malformed = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("env-malformed.safeguard.toml");
    std::fs::write(&malformed, "this is not valid toml {{{").expect("failed to write file");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .env("SOROBAN_SAFEGUARD_CONFIG", &malformed)
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "malformed SOROBAN_SAFEGUARD_CONFIG-named config must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("suppression config"),
        "error should mention the suppression config: {stderr}"
    );
}

#[test]
fn env_var_source_is_reported_in_diagnostics() {
    let config = write_config("env-var-diagnostics", all_critical_suppressions());
    let cwd = temp_dir("env-var-diagnostics-cwd");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .env("SOROBAN_SAFEGUARD_CONFIG", &config)
        .current_dir(&cwd)
        .output()
        .expect("failed to run binary");

    // Default text format keeps progress on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SOROBAN_SAFEGUARD_CONFIG")
            && stdout.contains(&config.display().to_string()),
        "diagnostics should name both the env var and the resolved path: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// require_reason policy
// ---------------------------------------------------------------------------

#[test]
fn require_reason_policy_disabled_leaves_existing_configs_unaffected() {
    // No [require_reason] table: a suppression with no reason must load and
    // apply exactly as it always has.
    let config = write_config(
        "require-reason-disabled",
        r#"
        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(code, 1, "the other two unsuppressed criticals still fail");
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 1);
    assert!(findings(&json)
        .iter()
        .any(|(c, t, s)| c == "Struct Field Removed"
            && t.as_deref() == Some("ConfigData.threshold")
            && *s));
}

#[test]
fn require_reason_policy_enabled_rejects_a_missing_reason() {
    let config = write_config(
        "require-reason-enabled-missing",
        r#"
        [require_reason]
        rule_ids = ["struct_field_removed"]

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--config".as_ref(), config.as_os_str()])
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "a gated rule with no reason must be rejected, not silently applied"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("require_reason"),
        "error should name the policy: {stderr}"
    );
    assert!(
        stderr.contains("rule #1") && stderr.contains("Struct Field Removed"),
        "error should point at the offending rule as its source location: {stderr}"
    );
}

#[test]
fn require_reason_policy_enabled_rejects_a_whitespace_only_reason() {
    let config = write_config(
        "require-reason-enabled-whitespace",
        r#"
        [require_reason]
        rule_ids = ["struct_field_removed"]

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "   "
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--config".as_ref(), config.as_os_str()])
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "a whitespace-only reason must be rejected exactly like a missing one"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("require_reason"), "{stderr}");
}

#[test]
fn require_reason_policy_enabled_accepts_a_real_reason() {
    let config = write_config(
        "require-reason-enabled-present",
        r#"
        [require_reason]
        rule_ids = ["struct_field_removed"]

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "Planned migration, reviewed in #123."
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(code, 1);
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 1);
    assert!(findings(&json)
        .iter()
        .any(|(c, t, s)| c == "Struct Field Removed"
            && t.as_deref() == Some("ConfigData.threshold")
            && *s));
}

#[test]
fn require_reason_policy_by_axis_rejects_a_missing_reason() {
    // "Function Signature Changed" is a call_abi finding; gate the whole
    // axis rather than naming the rule_id directly.
    let config = write_config(
        "require-reason-axis",
        r#"
        [require_reason]
        axes = ["call_abi"]

        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--config".as_ref(), config.as_os_str()])
        .output()
        .expect("failed to run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("require_reason"), "{stderr}");
    assert!(stderr.contains("Function Signature Changed"), "{stderr}");
}

#[test]
fn require_reason_policy_mixed_config_only_enforces_gated_rules() {
    // Three suppressions, matching the fixture's three known criticals:
    //   - "Struct Field Removed" is gated by rule_id, and has a reason -> ok.
    //   - "Function Signature Changed" is gated by axis (call_abi), and has a
    //     reason -> ok.
    //   - "Event Enum Case Value Changed" is entirely ungated -> no reason
    //     required, must still apply.
    let config = write_config(
        "require-reason-mixed",
        r#"
        [require_reason]
        rule_ids = ["struct_field_removed"]
        axes     = ["call_abi"]

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "Planned migration, reviewed in #123."

        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"
        reason   = "Planned re-init for the v2 migration."

        [[suppress]]
        category = "Event Enum Case Value Changed"
        target   = "StatusEvent.Paused"
        "#,
    );

    let (json, code) = run(Some(&config));

    assert_eq!(
        code, 0,
        "all three criticals are suppressed (two reasoned, one ungated) -> exit 0"
    );
    assert_eq!(json["is_safe"], Value::Bool(true));
    assert_eq!(json["suppressed_count"].as_u64().unwrap(), 3);
}

#[test]
fn require_reason_policy_mixed_config_still_rejects_the_unreasoned_gated_rule() {
    // Same as above, but the axis-gated rule's reason is dropped: only that
    // one rule should be flagged, even though three rules are configured and
    // one of them (event indexer) was never gated at all.
    let config = write_config(
        "require-reason-mixed-rejected",
        r#"
        [require_reason]
        rule_ids = ["struct_field_removed"]
        axes     = ["call_abi"]

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        reason   = "Planned migration, reviewed in #123."

        [[suppress]]
        category = "Function Signature Changed"
        target   = "initialize"

        [[suppress]]
        category = "Event Enum Case Value Changed"
        target   = "StatusEvent.Paused"
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--config".as_ref(), config.as_os_str()])
        .output()
        .expect("failed to run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("require_reason"), "{stderr}");
    // Points at rule #2 specifically, not the other two configured rules.
    assert!(stderr.contains("rule #2"), "{stderr}");
    assert!(!stderr.contains("rule #1"), "{stderr}");
    assert!(!stderr.contains("rule #3"), "{stderr}");
}

#[test]
fn validate_config_reports_require_reason_violations() {
    let config = write_config(
        "require-reason-validate",
        r#"
        [require_reason]
        rule_ids = ["struct_field_removed"]

        [[suppress]]
        category = "Struct Field Removed"
        target   = "ConfigData.threshold"
        "#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--validate-config".as_ref(), config.as_os_str()])
        .output()
        .expect("failed to run binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("require_reason"), "{stderr}");
}

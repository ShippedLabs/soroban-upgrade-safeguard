// SPDX-License-Identifier: MIT

//! Integration and acceptance tests for configuration and manifest JSON Schema,
//! editor completion catalog, runtime schema validation, and artifact drift checks.

use std::path::{Path, PathBuf};
use std::process::Command;

use soroban_upgrade_safeguard::config_schema::{
    config_schema, generate_config_completion, manifest_schema, validate_batch_manifest,
    validate_safeguard_config,
};

fn run_binary(args: &[&str]) -> (String, String, Option<i32>) {
    let bin = env!("CARGO_BIN_EXE_soroban-upgrade-safeguard");
    let output = Command::new(bin)
        .args(args)
        .output()
        .expect("failed to execute binary");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code(),
    )
}

// ── Canonical Artifact Drift Checks ──────────────────────────────────────────

#[test]
fn config_schema_matches_committed_artifact() {
    let in_memory = config_schema();
    let in_memory_json = serde_json::to_string_pretty(&in_memory).expect("serialize config schema");

    let committed_path = Path::new("schemas/v1/safeguard-config.schema.json");
    assert!(
        committed_path.exists(),
        "schemas/v1/safeguard-config.schema.json must exist in repo root"
    );
    let committed_raw = std::fs::read_to_string(committed_path)
        .expect("read schemas/v1/safeguard-config.schema.json");

    let committed_json: serde_json::Value =
        serde_json::from_str(&committed_raw).expect("parse committed schema");
    let in_memory_val: serde_json::Value =
        serde_json::from_str(&in_memory_json).expect("parse in-memory schema");

    assert_eq!(
        in_memory_val, committed_json,
        "In-memory config schema drifted from committed schemas/v1/safeguard-config.schema.json! Run target/debug/soroban-upgrade-safeguard print-schema --config > schemas/v1/safeguard-config.schema.json"
    );
}

#[test]
fn manifest_schema_matches_committed_artifact() {
    let in_memory = manifest_schema();
    let in_memory_json =
        serde_json::to_string_pretty(&in_memory).expect("serialize manifest schema");

    let committed_path = Path::new("schemas/v1/batch-manifest.schema.json");
    assert!(
        committed_path.exists(),
        "schemas/v1/batch-manifest.schema.json must exist in repo root"
    );
    let committed_raw = std::fs::read_to_string(committed_path)
        .expect("read schemas/v1/batch-manifest.schema.json");

    let committed_json: serde_json::Value =
        serde_json::from_str(&committed_raw).expect("parse committed schema");
    let in_memory_val: serde_json::Value =
        serde_json::from_str(&in_memory_json).expect("parse in-memory schema");

    assert_eq!(
        in_memory_val, committed_json,
        "In-memory manifest schema drifted from committed schemas/v1/batch-manifest.schema.json! Run target/debug/soroban-upgrade-safeguard print-schema --manifest > schemas/v1/batch-manifest.schema.json"
    );
}

#[test]
fn completion_catalog_matches_committed_artifact() {
    let in_memory = generate_config_completion();
    let in_memory_json =
        serde_json::to_string_pretty(&in_memory).expect("serialize completion catalog");

    let committed_path = Path::new("schemas/v1/safeguard-completion.json");
    assert!(
        committed_path.exists(),
        "schemas/v1/safeguard-completion.json must exist in repo root"
    );
    let committed_raw =
        std::fs::read_to_string(committed_path).expect("read schemas/v1/safeguard-completion.json");

    let committed_json: serde_json::Value =
        serde_json::from_str(&committed_raw).expect("parse committed catalog");
    let in_memory_val: serde_json::Value =
        serde_json::from_str(&in_memory_json).expect("parse in-memory catalog");

    assert_eq!(
        in_memory_val, committed_json,
        "In-memory completion catalog drifted from committed schemas/v1/safeguard-completion.json!"
    );
}

// ── CLI Subcommand Options ───────────────────────────────────────────────────

#[test]
fn cli_print_schema_config_outputs_valid_schema() {
    let (stdout, stderr, code) = run_binary(&["print-schema", "--config"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output must be valid JSON");
    assert_eq!(
        parsed.get("title").and_then(|v| v.as_str()),
        Some("Soroban Safeguard Configuration")
    );
    assert!(parsed.get("definitions").is_some());
}

#[test]
fn cli_print_schema_manifest_outputs_valid_schema() {
    let (stdout, stderr, code) = run_binary(&["print-schema", "--manifest"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output must be valid JSON");
    assert_eq!(
        parsed.get("title").and_then(|v| v.as_str()),
        Some("Soroban Safeguard Batch Manifest")
    );
}

#[test]
fn cli_print_schema_completion_outputs_catalog() {
    let (stdout, stderr, code) = run_binary(&["print-schema", "--config", "--completion"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output must be valid JSON");
    assert!(parsed.get("completions").is_some());
    assert!(parsed.get("hovers").is_some());
}

#[test]
fn cli_print_schema_markdown_outputs_documentation() {
    let (stdout, stderr, code) = run_binary(&["print-schema", "--config", "--markdown"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("# Soroban Upgrade Safeguard Configuration Reference"));
    assert!(stdout.contains("| `$schema` |"));
    assert!(stdout.contains("### `[limits]`"));
}

#[test]
fn cli_print_schema_compact_flag_produces_single_line() {
    let (stdout, stderr, code) = run_binary(&["print-schema", "--config", "--compact"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        !stdout.trim_end().contains('\n'),
        "compact output should be on a single line"
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.get("$schema").is_some());
}

// ── Invalid Configuration Fixtures & Schema Diagnostics ──────────────────────

#[test]
fn rejects_unknown_key_toml_with_line_column_and_path() {
    let path = PathBuf::from("tests/fixtures/invalid_configs/unknown_key.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_safeguard_config(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    let d = &diags[0];
    assert_eq!(d.line, Some(3));
    assert!(d
        .field_path
        .as_deref()
        .unwrap()
        .contains("unknown_feature_flag"));
    assert!(d.message.contains("unknown field"));
}

#[test]
fn rejects_unknown_key_json_with_diagnostics() {
    let path = PathBuf::from("tests/fixtures/invalid_configs/unknown_key.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_safeguard_config(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    let d = &diags[0];
    assert!(d.message.contains("unknown field"));
}

#[test]
fn rejects_invalid_type_toml_with_diagnostics() {
    let path = PathBuf::from("tests/fixtures/invalid_configs/invalid_type.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_safeguard_config(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    let d = &diags[0];
    assert_eq!(d.line, Some(2));
    assert!(d.message.contains("invalid type"));
}

#[test]
fn rejects_invalid_type_json_with_diagnostics() {
    let path = PathBuf::from("tests/fixtures/invalid_configs/invalid_type.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_safeguard_config(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
}

#[test]
fn rejects_out_of_range_limits_with_diagnostics() {
    let path = PathBuf::from("tests/fixtures/invalid_configs/out_of_range.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_safeguard_config(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    assert!(diags
        .iter()
        .any(|d| d.message.contains("max_xdr_depth must be >= 1")));
}

#[test]
fn rejects_invalid_enum_with_diagnostics() {
    let path = PathBuf::from("tests/fixtures/invalid_configs/invalid_enum.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_safeguard_config(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    assert!(diags
        .iter()
        .any(|d| d.message.contains("unknown variant") || d.message.contains("format")));
}

#[test]
fn rejects_mutually_exclusive_fields_with_diagnostics() {
    let path = PathBuf::from("tests/fixtures/invalid_configs/mutually_exclusive.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_safeguard_config(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    assert!(diags
        .iter()
        .any(|d| d.message.contains("mutually exclusive")));
}

#[test]
fn rejects_profile_cycle_with_diagnostics() {
    let path = PathBuf::from("tests/fixtures/invalid_configs/profile_cycle.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_safeguard_config(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    assert!(diags.iter().any(|d| d.message.contains("cycle")));
}

#[test]
fn rejects_missing_reason_with_diagnostics() {
    let path = PathBuf::from("tests/fixtures/invalid_configs/missing_reason.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_safeguard_config(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    assert!(diags
        .iter()
        .any(|d| d.message.contains("require_reason") || d.message.contains("missing reason")));
}

// ── Invalid Manifest Fixtures ────────────────────────────────────────────────

#[test]
fn rejects_invalid_manifest_unknown_key() {
    let path = PathBuf::from("tests/fixtures/invalid_manifests/unknown_key.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_batch_manifest(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    assert!(diags.iter().any(|d| d.message.contains("unknown field")));
}

#[test]
fn rejects_invalid_manifest_unsupported_version() {
    let path = PathBuf::from("tests/fixtures/invalid_manifests/invalid_version.toml");
    let content = std::fs::read_to_string(&path).unwrap();
    let diags = validate_batch_manifest(&content, &path).unwrap_err();
    assert!(!diags.is_empty());
    assert!(diags.iter().any(|d| d.message.contains("version")));
}

// ── CLI --validate-config Integration ────────────────────────────────────────

#[test]
fn cli_validate_config_rejects_invalid_file_with_diagnostics() {
    let (stdout, stderr, code) = run_binary(&[
        "--validate-config",
        "tests/fixtures/invalid_configs/unknown_key.toml",
    ]);
    assert_ne!(code, Some(0), "must fail on invalid config");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("unknown_feature_flag"),
        "expected error to mention unknown_feature_flag, got:\n{combined}"
    );
    assert!(
        combined.contains("error at"),
        "expected schema diagnostic format, got:\n{combined}"
    );
}

#[test]
fn cli_validate_config_accepts_valid_config() {
    let temp_dir = std::env::temp_dir().join(format!("safeguard-valid-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let valid_path = temp_dir.join(".safeguard.toml");
    let valid_toml = r#"
strict = false
explain = true
format = "text"

[limits]
max_xdr_depth = 32

[[suppress]]
category = "Struct Field Removed"
target = "Config.value"
reason = "Intentional field deprecation."
"#;
    std::fs::write(&valid_path, valid_toml).unwrap();

    let (stdout, stderr, code) = run_binary(&["--validate-config", valid_path.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&temp_dir);

    assert_eq!(code, Some(0), "valid config must exit 0; stderr: {stderr}");
    assert!(
        stdout.contains("Config is valid") || stdout.contains("Parsed 1 rule(s)"),
        "expected success output, got:\n{stdout}"
    );
}

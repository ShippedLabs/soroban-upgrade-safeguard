// SPDX-License-Identifier: MIT
//! Integration tests for the `doctor` subcommand.
//!
//! The `doctor` subcommand reports environment, version, enabled features,
//! cache locations, and resolved configuration without analyzing any WASM inputs.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run_doctor(args: &[&str]) -> Run {
    let mut cmd = bin();
    cmd.arg("doctor");
    cmd.args(args);
    let output = cmd.output().expect("failed to run binary");
    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout not utf8"),
        stderr: String::from_utf8(output.stderr).expect("stderr not utf8"),
        code: output.status.code().expect("process killed by signal"),
    }
}

#[test]
fn doctor_exits_successfully_without_wasm_inputs() {
    let run = run_doctor(&[]);
    assert_eq!(run.code, 0, "doctor must exit 0, stderr:\n{}", run.stderr);
    assert!(
        !run.stdout.is_empty(),
        "doctor must produce output on stdout"
    );
}

#[test]
fn doctor_text_output_includes_version() {
    let run = run_doctor(&[]);
    assert_eq!(run.code, 0);
    assert!(
        run.stdout.contains("Version:") || run.stdout.contains("version"),
        "text output must show version, got:\n{}",
        run.stdout
    );
}

#[test]
fn doctor_text_output_includes_enabled_features() {
    let run = run_doctor(&[]);
    assert_eq!(run.code, 0);
    assert!(
        run.stdout.contains("Features:") || run.stdout.contains("Enabled Features"),
        "text output must show enabled features, got:\n{}",
        run.stdout
    );
}

#[test]
fn doctor_text_output_includes_cache_directories() {
    let run = run_doctor(&[]);
    assert_eq!(run.code, 0);
    let output = run.stdout.to_lowercase();
    assert!(
        output.contains("cache") && output.contains("director"),
        "text output must show cache directories, got:\n{}",
        run.stdout
    );
}

#[test]
fn doctor_text_output_includes_configuration_status() {
    let run = run_doctor(&[]);
    assert_eq!(run.code, 0);
    assert!(
        run.stdout.contains("Configuration:") || run.stdout.contains("Config"),
        "text output must show configuration status, got:\n{}",
        run.stdout
    );
}

#[test]
fn doctor_json_output_is_valid_json() {
    let run = run_doctor(&["--format", "json"]);
    assert_eq!(run.code, 0, "doctor --format json must exit 0");

    let json: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("output must be valid JSON");

    assert!(
        json.is_object(),
        "JSON output must be an object, got: {}",
        json
    );
}

#[test]
fn doctor_json_includes_version_field() {
    let run = run_doctor(&["--format", "json"]);
    assert_eq!(run.code, 0);

    let json: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    assert!(
        json.get("version").is_some(),
        "JSON must have 'version' field, got: {}",
        json
    );
    assert!(
        json["version"].is_string(),
        "'version' must be a string, got: {}",
        json["version"]
    );
}

#[test]
fn doctor_json_includes_enabled_features_field() {
    let run = run_doctor(&["--format", "json"]);
    assert_eq!(run.code, 0);

    let json: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    assert!(
        json.get("enabled_features").is_some(),
        "JSON must have 'enabled_features' field, got: {}",
        json
    );
    assert!(
        json["enabled_features"].is_array(),
        "'enabled_features' must be an array, got: {}",
        json["enabled_features"]
    );
}

#[test]
fn doctor_json_includes_cache_section() {
    let run = run_doctor(&["--format", "json"]);
    assert_eq!(run.code, 0);

    let json: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    assert!(
        json.get("cache").is_some(),
        "JSON must have 'cache' field, got: {}",
        json
    );

    let cache = &json["cache"];
    assert!(
        cache.is_object(),
        "'cache' must be an object, got: {}",
        cache
    );

    assert!(
        cache.get("remote_cache_dir").is_some(),
        "'cache' must have 'remote_cache_dir', got: {}",
        cache
    );
    assert!(
        cache.get("oci_cache_dir").is_some(),
        "'cache' must have 'oci_cache_dir', got: {}",
        cache
    );
    assert!(
        cache.get("metadata_cache_dir").is_some(),
        "'cache' must have 'metadata_cache_dir', got: {}",
        cache
    );
}

#[test]
fn doctor_json_includes_configuration_section() {
    let run = run_doctor(&["--format", "json"]);
    assert_eq!(run.code, 0);

    let json: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    assert!(
        json.get("configuration").is_some(),
        "JSON must have 'configuration' field, got: {}",
        json
    );

    let config = &json["configuration"];
    assert!(
        config.is_object(),
        "'configuration' must be an object, got: {}",
        config
    );

    assert!(
        config.get("config_file").is_some(),
        "'configuration' must have 'config_file', got: {}",
        config
    );
    assert!(
        config.get("suppression_count").is_some(),
        "'configuration' must have 'suppression_count', got: {}",
        config
    );
}

#[test]
fn doctor_with_no_config_flag_reports_no_config() {
    let run = run_doctor(&["--no-config"]);
    assert_eq!(run.code, 0);

    let output = run.stdout.to_lowercase();
    assert!(
        output.contains("none") || output.contains("not found") || output.contains("default"),
        "doctor --no-config must indicate no config loaded, got:\n{}",
        run.stdout
    );
}

#[test]
fn doctor_with_explicit_config_reports_config_file() {
    let temp = std::env::temp_dir().join(format!("doctor-test-{}", std::process::id()));
    std::fs::create_dir_all(&temp).expect("failed to create temp dir");
    let config_path = temp.join(".safeguard.toml");
    std::fs::write(&config_path, "# empty config\n").expect("failed to write config");

    let run = run_doctor(&["--config", config_path.to_str().unwrap()]);
    assert_eq!(run.code, 0, "doctor with explicit config must exit 0");

    assert!(
        run.stdout.contains(&config_path.display().to_string())
            || run
                .stdout
                .contains(config_path.file_name().unwrap().to_str().unwrap()),
        "doctor must report the explicit config path, got:\n{}",
        run.stdout
    );

    // Clean up
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_dir(&temp);
}

#[test]
fn doctor_does_not_analyze_wasm_or_produce_findings() {
    let run = run_doctor(&[]);
    assert_eq!(run.code, 0);

    let combined = format!("{}{}", run.stdout, run.stderr).to_lowercase();

    // Should not contain typical comparison output
    assert!(
        !combined.contains("finding")
            && !combined.contains("critical")
            && !combined.contains("baseline"),
        "doctor must not analyze WASM or produce findings, got:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn doctor_does_not_leak_secret_values() {
    // Run doctor with environment variables that might contain secrets
    std::env::set_var("TEST_DOCTOR_SECRET", "super_secret_value_12345");

    let run = run_doctor(&[]);
    assert_eq!(run.code, 0);

    let combined = format!("{}{}", run.stdout, run.stderr);

    // Should not contain the secret value
    assert!(
        !combined.contains("super_secret_value_12345"),
        "doctor must not leak secret values, got:\n{}",
        combined
    );

    std::env::remove_var("TEST_DOCTOR_SECRET");
}

#[test]
fn doctor_no_color_flag_disables_color() {
    let run = run_doctor(&["--no-color"]);
    assert_eq!(run.code, 0);

    // ANSI escape sequences start with ESC character (0x1B)
    assert!(
        !run.stdout.contains('\u{1b}'),
        "doctor --no-color must not contain ANSI escape codes"
    );
}

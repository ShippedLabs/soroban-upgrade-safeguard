//! `--show-config` resolves and prints configuration exactly as a normal
//! run would, then exits without touching any WASM input — see
//! `run_show_config` in `src/main.rs`. These confirm it needs no WASM
//! paths, that an RPC header's secret value is never printed (only the
//! environment variable name that would supply it), and that
//! `--format json` produces parseable JSON.

use std::process::Command;

fn run(args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    cmd.args(args);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let output = cmd.output().expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    (code, stdout, stderr)
}

#[test]
fn show_config_with_no_wasm_inputs_succeeds_and_prints_a_listing() {
    // No OLD_WASM/NEW_WASM positional arguments at all: --show-config must
    // not require them.
    let (code, stdout, stderr) = run(&["--show-config"], &[]);

    assert_eq!(
        code, 0,
        "--show-config with no WASM inputs should succeed, stderr: {stderr}"
    );
    assert!(
        stdout.contains("output.format"),
        "text listing should show dotted setting paths, got:\n{stdout}"
    );
    assert!(
        stdout.contains("suppression_policy"),
        "listing should include the suppression policy section, got:\n{stdout}"
    );
}

#[test]
fn show_config_redacts_an_rpc_header_secret_but_names_its_env_var() {
    let (code, stdout, stderr) = run(
        &[
            "--show-config",
            "--rpc-header",
            "X-Api-Key=SHOW_CONFIG_TEST_SECRET_ENV",
        ],
        &[("SHOW_CONFIG_TEST_SECRET_ENV", "super-secret-token-value")],
    );

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        !stdout.contains("super-secret-token-value"),
        "the secret value itself must never be printed, got:\n{stdout}"
    );
    assert!(
        stdout.contains("SHOW_CONFIG_TEST_SECRET_ENV"),
        "the env var *name* that supplies the header should still be shown, got:\n{stdout}"
    );
    assert!(
        stdout.contains("X-Api-Key"),
        "the header name itself should still be shown, got:\n{stdout}"
    );
    assert!(
        stdout.contains("redacted"),
        "the listing should mark the value as redacted, got:\n{stdout}"
    );
}

#[test]
fn show_config_format_json_is_parseable_and_redacts_the_same_way() {
    let (code, stdout, stderr) = run(
        &[
            "--show-config",
            "--format",
            "json",
            "--rpc-header",
            "X-Api-Key=SHOW_CONFIG_TEST_SECRET_ENV_JSON",
        ],
        &[(
            "SHOW_CONFIG_TEST_SECRET_ENV_JSON",
            "super-secret-token-value-json",
        )],
    );

    assert_eq!(code, 0, "stderr: {stderr}");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout was not valid JSON ({e}):\n{stdout}"));

    assert!(!stdout.contains("super-secret-token-value-json"));

    let headers = json["input"]["rpc_headers"]
        .as_array()
        .expect("input.rpc_headers should be an array");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0]["name"], "X-Api-Key");
    assert_eq!(
        headers[0]["value_from_env"],
        "SHOW_CONFIG_TEST_SECRET_ENV_JSON"
    );
    assert_eq!(headers[0]["value"], "<redacted>");

    // Sanity check a couple of ordinary (non-secret) settings are present
    // too, so this doesn't just degenerate into an empty object passing
    // every assertion above vacuously.
    assert_eq!(json["output"]["format"]["value"], "json");
    assert!(json["suppression_policy"].is_object());
}

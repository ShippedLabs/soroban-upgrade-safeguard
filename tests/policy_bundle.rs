//! CLI-level coverage for `--policy-bundle`: opt-in application, rejection
//! before any WASM is loaded, and the batch-mode restriction.
//!
//! Deterministic signing vectors, tampering rejections, and precedence
//! (OR-union / most-restrictive-wins merge) are covered at the unit level
//! in `src/policy_bundle.rs`'s own test suite, which also constructs
//! bundles and signatures directly rather than through the CLI. These
//! tests instead drive the compiled binary, and separately cover the
//! offline-cache behavior a *remote* `--policy-bundle` source shares with
//! `https://` WASM inputs (`remote::fetch_verified`).

use std::path::PathBuf;
use std::process::Command;

use soroban_upgrade_safeguard::attestation::Ed25519Signer;
use soroban_upgrade_safeguard::policy_bundle::{sign_bundle, PolicyBundle};
use soroban_upgrade_safeguard::suppression::{PolicyConfig, RequireReasonPolicy};

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn temp_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "safeguard-policy-bundle-test-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn sample_bundle(gate_source_level: bool) -> PolicyBundle {
    PolicyBundle {
        version: soroban_upgrade_safeguard::policy_bundle::POLICY_BUNDLE_SCHEMA_VERSION,
        bundle_id: "test-org-baseline".to_string(),
        issued_at: None,
        expires_at: None,
        policy: PolicyConfig {
            gate_storage_layout: true,
            gate_call_abi: true,
            gate_event_indexer: false,
            gate_source_level,
            gate_runtime_surface: true,
        },
        require_reason: RequireReasonPolicy::default(),
        limits: Default::default(),
        rule_metadata: Default::default(),
        capability_overrides: Vec::new(),
    }
}

/// Writes a signed bundle envelope and the signer's raw public key to
/// temp files, returning (envelope_path, trusted_key_arg).
fn write_signed_bundle(label: &str, bundle: &PolicyBundle) -> (PathBuf, String) {
    let rng = ring::rand::SystemRandom::new();
    let private_key_der = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("failed to generate test key")
        .as_ref()
        .to_vec();
    let signer = Ed25519Signer::from_pkcs8("test-signer", &private_key_der).expect("valid key");
    let envelope = sign_bundle(bundle, &signer).expect("failed to sign bundle");

    let bundle_path = temp_path(&format!("{label}-bundle.json"));
    std::fs::write(&bundle_path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let key_path = temp_path(&format!("{label}-key.raw"));
    std::fs::write(&key_path, signer.public_key()).unwrap();

    (bundle_path, format!("test-signer={}", key_path.display()))
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    (code, stdout, stderr)
}

#[test]
fn a_verified_bundle_is_applied_and_recorded_in_provenance() {
    let bundle = sample_bundle(true); // asks for gate_source_level, which v1/v3 don't otherwise trip
    let (bundle_path, trusted_arg) = write_signed_bundle("applied", &bundle);

    let old = wasm("v1.wasm").display().to_string();
    let new = wasm("v3.wasm").display().to_string();
    let bundle_path_str = bundle_path.display().to_string();

    let (code, stdout, stderr) = run(&[
        &old,
        &new,
        "--policy-bundle",
        &bundle_path_str,
        "--trusted-bundle-key",
        &trusted_arg,
        "--format",
        "json",
        "--no-timestamp",
    ]);

    std::fs::remove_file(&bundle_path).ok();

    assert_eq!(code, 0, "a verified bundle run should itself succeed, stderr: {stderr}");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout was not valid JSON ({e}):\n{stdout}"));

    let recorded = &json["policy_bundle"];
    assert_eq!(recorded["bundle_id"], "test-org-baseline");
    assert_eq!(recorded["verified"], true);
    assert_eq!(recorded["signer_identities"], serde_json::json!(["test-signer"]));
    assert!(recorded["digest"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn a_bundle_with_no_trusted_key_is_rejected_before_any_wasm_is_loaded() {
    let bundle = sample_bundle(false);
    let (bundle_path, _unused_trusted_arg) = write_signed_bundle("untrusted", &bundle);

    let bundle_path_str = bundle_path.display().to_string();
    // Nonexistent WASM paths: if the bundle check didn't run first, the
    // failure would instead be about a missing file, not verification.
    let (code, stdout, stderr) = run(&[
        "/nonexistent/old.wasm",
        "/nonexistent/new.wasm",
        "--policy-bundle",
        &bundle_path_str,
        // No --trusted-bundle-key at all: every signature is untrusted.
    ]);

    std::fs::remove_file(&bundle_path).ok();

    assert_ne!(code, 0, "an unverifiable bundle must be rejected");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("verification") || combined.contains("trusted"),
        "error should explain the bundle failed verification, got: {combined}"
    );
    assert!(
        !combined.to_lowercase().contains("no such file") && !combined.to_lowercase().contains("not found"),
        "the bundle must be rejected before any WASM path is opened, got: {combined}"
    );
}

#[test]
fn policy_bundle_is_rejected_in_batch_mode() {
    let bundle = sample_bundle(false);
    let (bundle_path, trusted_arg) = write_signed_bundle("batch-mode", &bundle);
    let bundle_path_str = bundle_path.display().to_string();

    let (code, stdout, stderr) = run(&[
        "--manifest",
        "/nonexistent/manifest.toml",
        "--policy-bundle",
        &bundle_path_str,
        "--trusted-bundle-key",
        &trusted_arg,
    ]);

    std::fs::remove_file(&bundle_path).ok();

    assert_ne!(code, 0);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("--policy-bundle") && combined.contains("batch mode"),
        "error should name both --policy-bundle and batch mode, got: {combined}"
    );
    assert!(
        !combined.to_lowercase().contains("no such file") && !combined.to_lowercase().contains("not found"),
        "the conflict must be caught before the manifest is ever opened, got: {combined}"
    );
}

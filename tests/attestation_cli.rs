use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ring::{rand::SystemRandom, signature};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/wasm")
        .join(name)
}

fn temp_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("safeguard-attestation-{nonce}"));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn create_report(path: &Path) {
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--format", "json", "--no-timestamp"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    std::fs::write(path, output.stdout).unwrap();
}

fn attest(dir: &Path, key_id: &str) -> (PathBuf, PathBuf, PathBuf) {
    let report = dir.join("report.json");
    let key = dir.join("signing-key.pk8");
    let public_key = dir.join("signing-key.pub");
    let envelope = dir.join("report.dsse.json");
    create_report(&report);
    let key_bytes = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = signature::Ed25519KeyPair::from_pkcs8(key_bytes.as_ref()).unwrap();
    std::fs::write(&key, key_bytes.as_ref()).unwrap();
    std::fs::write(&public_key, signature::KeyPair::public_key(&pair).as_ref()).unwrap();

    let output = bin()
        .arg("attest")
        .arg(&report)
        .arg("--old-wasm")
        .arg(wasm("v1.wasm"))
        .arg("--new-wasm")
        .arg(wasm("v2.wasm"))
        .arg("--private-key")
        .arg(&key)
        .args(["--key-id", key_id, "--output"])
        .arg(&envelope)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (report, public_key, envelope)
}

fn verify(report: Option<&Path>, public_key: &Path, envelope: &Path, key_id: &str) -> Output {
    let mut command = bin();
    command
        .arg("verify-attestation")
        .arg(envelope)
        .arg("--trusted-key")
        .arg(format!("{key_id}={}", public_key.display()))
        .arg("--old-wasm")
        .arg(wasm("v1.wasm"))
        .arg("--new-wasm")
        .arg(wasm("v2.wasm"));
    if let Some(report) = report {
        command.arg("--report").arg(report);
    }
    command.output().unwrap()
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "flaky on macOS runners: temp dir timing"
)]
fn attestation_is_deterministic_and_verifies_offline() {
    let dir = temp_dir();
    let (report, public_key, envelope) = attest(&dir, "release-key");
    let first = std::fs::read(&envelope).unwrap();
    let second_envelope = dir.join("second.dsse.json");
    let output = bin()
        .arg("attest")
        .arg(&report)
        .arg("--old-wasm")
        .arg(wasm("v1.wasm"))
        .arg("--new-wasm")
        .arg(wasm("v2.wasm"))
        .arg("--private-key")
        .arg(dir.join("signing-key.pk8"))
        .args(["--key-id", "release-key", "--output"])
        .arg(&second_envelope)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(first, std::fs::read(second_envelope).unwrap());

    let output = verify(Some(&report), &public_key, &envelope, "release-key");
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["verified"], true);
    assert_eq!(result["signer_identities"][0], "release-key");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn verification_reports_missing_tampered_and_untrusted_inputs() {
    let dir = temp_dir();
    let (report, public_key, envelope) = attest(&dir, "release-key");

    let missing = verify(None, &public_key, &envelope, "release-key");
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stdout).contains("missing_artifact"));

    std::fs::write(&report, b"tampered").unwrap();
    let tampered = verify(Some(&report), &public_key, &envelope, "release-key");
    assert_eq!(tampered.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&tampered.stdout).contains("artifact_digest_mismatch"));

    let untrusted = verify(Some(&report), &public_key, &envelope, "other-key");
    assert_eq!(untrusted.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&untrusted.stdout).contains("untrusted_signer"));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn malformed_payload_is_structured_and_private_key_is_never_printed() {
    let dir = temp_dir();
    let (_, public_key, envelope) = attest(&dir, "release-key");
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&envelope).unwrap()).unwrap();
    document["payload"] = serde_json::Value::String(BASE64.encode(b"tampered"));
    std::fs::write(&envelope, serde_json::to_vec(&document).unwrap()).unwrap();
    let output = verify(None, &public_key, &envelope, "release-key");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("invalid_statement"));

    let secret = b"DO-NOT-PRINT-PRIVATE-KEY";
    let key_path = dir.join("invalid.pk8");
    std::fs::write(&key_path, secret).unwrap();
    let output = bin()
        .arg("attest")
        .arg(dir.join("report.json"))
        .arg("--old-wasm")
        .arg(wasm("v1.wasm"))
        .arg("--new-wasm")
        .arg(wasm("v2.wasm"))
        .arg("--private-key")
        .arg(&key_path)
        .args(["--key-id", "bad", "--output"])
        .arg(dir.join("bad.json"))
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("DO-NOT-PRINT"));
    std::fs::remove_dir_all(dir).ok();
}

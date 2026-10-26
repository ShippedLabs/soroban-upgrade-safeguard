use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn empty_manifest_reports_that_a_comparison_pair_is_required() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    let manifest = std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-empty-manifest-{}-{nonce}.toml",
        std::process::id()
    ));
    fs::write(&manifest, "").expect("create empty manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest)
        .output()
        .expect("run CLI");

    let _ = fs::remove_file(&manifest);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("must declare at least one comparison pair"),
        "stderr should explain why an empty manifest is invalid: {stderr}"
    );
}

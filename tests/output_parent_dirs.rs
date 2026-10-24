use std::fs;
use std::process::Command;

#[test]
fn output_creates_missing_parent_directories() {
    let tmp = std::env::temp_dir().join(format!(
        "sus-output-parent-dirs-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create temp root");

    let report = tmp.join("a").join("b").join("report.json");
    assert!(!report.parent().unwrap().exists(), "parent dirs must not exist yet");

    let output_arg = format!("json:{}", report.display());

    let status = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("tests/wasm/v1.wasm")
        .arg("tests/wasm/v1.wasm")
        .arg("--output")
        .arg(&output_arg)
        .status()
        .expect("failed to spawn soroban-upgrade-safeguard");

    assert_eq!(status.code(), Some(0), "expected exit code 0");
    assert!(report.is_file(), "report file should exist at {}", report.display());

    let contents = fs::read_to_string(&report).expect("read report");
    let _: serde_json::Value =
        serde_json::from_str(&contents).expect("report should be valid JSON");

    let _ = fs::remove_dir_all(&tmp);
}

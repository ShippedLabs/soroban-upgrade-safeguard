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

/// Helper to write manifest content to a temp file and return its path.
fn write_manifest(name: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, contents).expect("failed to write manifest file");
    path
}

#[test]
fn batch_manifest_toml_mode_fails_and_exits_one() {
    // Generate a TOML manifest
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "clean_contract"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "breaking_contract"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap()
    );

    let manifest_path = write_manifest("manifest_test.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 1, "batch run with breaking contract must exit 1");

    // Assert stdout/stderr output details
    assert!(
        stdout.contains("SOROBAN BATCH SAFETY REPORT"),
        "Missing batch report header"
    );
    assert!(
        stdout.contains("Overall Status: ❌ FAILED"),
        "Missing failed status"
    );
    assert!(
        stdout.contains("clean_contract: ✅ PASSED"),
        "Missing passed contract summary"
    );
    assert!(
        stdout.contains("breaking_contract: ❌ FAILED"),
        "Missing failed contract summary"
    );

    // Progress messages go to stdout in default text mode.
    assert!(
        stdout.contains("Loaded 2 pair(s) for comparison."),
        "Missing loading message"
    );
    assert!(
        stdout.contains("Comparing contract pair: clean_contract"),
        "Missing clean contract progress"
    );
    assert!(
        stdout.contains("Comparing contract pair: breaking_contract"),
        "Missing breaking contract progress"
    );
}

#[test]
fn batch_manifest_all_clean_exits_zero() {
    // Generate a TOML manifest with all clean pairs
    let manifest_content = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "clean_1"

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "clean_2"
        "#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap()
    );

    let manifest_path = write_manifest("manifest_clean.toml", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 0, "batch run with all clean contracts must exit 0");
    assert!(
        stdout.contains("Overall Status: ✅ PASSED"),
        "Missing passed status"
    );
}

#[test]
fn batch_manifest_json_mode_json_output() {
    // Generate a JSON manifest
    let manifest_content = format!(
        r#"{{
            "pairs": [
                {{
                    "old": {:?},
                    "new": {:?},
                    "name": "clean_json"
                }},
                {{
                    "old": {:?},
                    "new": {:?},
                    "name": "breaking_json"
                }}
            ]
        }}"#,
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v2.wasm").to_str().unwrap()
    );

    let manifest_path = write_manifest("manifest_test.json", &manifest_content);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--manifest")
        .arg(&manifest_path)
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 1, "batch run with breaking contract must exit 1");

    let json: Value = serde_json::from_str(&stdout).expect("output must be valid JSON");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(json["recommended_bump"], "major");
    assert_eq!(json["total_pairs"].as_u64().unwrap(), 2);

    // Check results object
    let results = json["results"]
        .as_object()
        .expect("results must be an object");
    assert!(results.contains_key("clean_json"));
    assert!(results.contains_key("breaking_json"));

    assert_eq!(results["clean_json"]["is_safe"], Value::Bool(true));
    assert_eq!(results["clean_json"]["recommended_bump"], "patch");
    assert_eq!(results["breaking_json"]["is_safe"], Value::Bool(false));
    assert_eq!(results["breaking_json"]["recommended_bump"], "major");
}

#[test]
fn batch_directory_scanning_fails_on_breaking_contract() {
    let tmp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dir_test");
    let old_dir = tmp_dir.join("old");
    let new_dir = tmp_dir.join("new");

    std::fs::create_dir_all(&old_dir).ok();
    std::fs::create_dir_all(&new_dir).ok();

    // Copy fixtures:
    // a.wasm: clean (v1 -> v1)
    std::fs::copy(wasm("v1.wasm"), old_dir.join("a.wasm")).expect("copy");
    std::fs::copy(wasm("v1.wasm"), new_dir.join("a.wasm")).expect("copy");

    // b.wasm: breaking (v1 -> v2)
    std::fs::copy(wasm("v1.wasm"), old_dir.join("b.wasm")).expect("copy");
    std::fs::copy(wasm("v2.wasm"), new_dir.join("b.wasm")).expect("copy");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--old-dir")
        .arg(&old_dir)
        .arg("--new-dir")
        .arg(&new_dir)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 1);
    assert!(stdout.contains("Overall Status: ❌ FAILED"));
    assert!(stdout.contains("a: ✅ PASSED"));
    assert!(stdout.contains("b: ❌ FAILED"));
}

#[test]
fn batch_conflicting_options_exit_with_error() {
    // 1. Both manifest and old-dir/new-dir
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--manifest",
            "dummy.toml",
            "--old-dir",
            "dummy_old",
            "--new-dir",
            "dummy_new",
        ])
        .output()
        .expect("failed to run binary");

    assert!(
        !output.status.success(),
        "conflicting batch options must fail"
    );

    // 2. Positional args + manifest
    let output2 = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .args(["--manifest", "dummy.toml"])
        .output()
        .expect("failed to run binary");

    assert!(
        !output2.status.success(),
        "positional args + manifest must fail"
    );
}

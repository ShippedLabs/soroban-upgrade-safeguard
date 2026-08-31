use serde_json::Value;
use std::path::{Path, PathBuf};
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

fn write_file(relative_name: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(relative_name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create parent directory");
    }
    std::fs::write(&path, contents).expect("failed to write file");
    path
}

fn portable(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
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
    assert!(
        stdout.contains("interface-only"),
        "Text output must identify interface-only coverage"
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
    assert_eq!(json["total_pairs"].as_u64().unwrap(), 2);

    let results = json["results"]
        .as_array()
        .expect("results must be an ordered array");
    assert_eq!(results[0]["name"], "clean_json");
    assert_eq!(results[1]["name"], "breaking_json");
    assert_eq!(results[0]["report"]["is_safe"], Value::Bool(true));
    assert_eq!(results[1]["report"]["is_safe"], Value::Bool(false));
}

#[test]
fn batch_manifest_mixed_coverage_is_isolated_and_ordered() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mixed");
    std::fs::create_dir_all(&root).expect("failed to create mixed manifest directory");
    write_file("mixed/schemas/old.json", r#"{"declarations": []}"#);
    write_file("mixed/schemas/new.json", r#"{"declarations": []}"#);
    let invalid_schema = write_file("mixed/schemas/invalid.json", "not valid json");
    let manifest_path = root.join("manifest.json");
    let manifest = format!(
        r#"{{
            "pairs": [
                {{"old": "{}", "new": "{}", "name": "interface_first"}},
                {{"old": "{}", "new": "{}", "name": "schema_second",
                 "old-storage-schema": "{}", "new-storage-schema": "{}"}},
                {{"old": "{}", "new": "{}", "name": "invalid_third",
                 "old_storage_schema": "{}", "new_storage_schema": "{}"}}
            ]
        }}"#,
        portable(&wasm("v1.wasm")),
        portable(&wasm("v1.wasm")),
        portable(&wasm("v1.wasm")),
        portable(&wasm("v1.wasm")),
        "schemas/old.json",
        "schemas/new.json",
        portable(&wasm("v1.wasm")),
        portable(&wasm("v1.wasm")),
        portable(&invalid_schema),
        portable(&invalid_schema),
    );
    std::fs::write(&manifest_path, manifest).expect("failed to write mixed manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run binary");
    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "output must be JSON: {error}\n---stderr---\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let results = json["results"].as_array().expect("results must be ordered");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["name"], "interface_first");
    assert_eq!(results[0]["coverage"], "interface-only");
    assert_eq!(results[1]["name"], "schema_second");
    assert_eq!(results[1]["coverage"], "schema-backed");
    assert_eq!(results[2]["name"], "invalid_third");
    assert_eq!(results[2]["coverage"], "error");
    assert!(results[2]["error"].as_str().unwrap().contains("invalid"));
}

#[test]
fn batch_manifest_partial_schema_is_pair_error_without_aborting_next_pair() {
    let schema = write_file("partial/old.json", r#"{"declarations": []}"#);
    let manifest = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "partial"
        old_storage_schema = {:?}

        [[pairs]]
        old = {:?}
        new = {:?}
        name = "after_partial"
        "#,
        wasm("v1.wasm").display().to_string(),
        wasm("v1.wasm").display().to_string(),
        schema.display().to_string(),
        wasm("v1.wasm").display().to_string(),
        wasm("v1.wasm").display().to_string(),
    );
    let manifest_path = write_manifest("partial_manifest.toml", &manifest);
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run binary");
    let json: Value = serde_json::from_slice(&output.stdout).expect("output must be JSON");
    let results = json["results"].as_array().expect("results must be ordered");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(results[0]["name"], "partial");
    assert_eq!(results[0]["coverage"], "error");
    assert!(results[0]["error"].as_str().unwrap().contains("partial"));
    assert_eq!(results[1]["name"], "after_partial");
    assert_eq!(results[1]["coverage"], "interface-only");
}

#[test]
fn committed_mixed_manifest_fixture_resolves_relative_paths() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("batch")
        .join("mixed.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["--manifest", manifest.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("failed to run committed fixture");
    let json: Value = serde_json::from_slice(&output.stdout).expect("output must be JSON");
    let results = json["results"].as_array().expect("results must be ordered");
    assert_eq!(results.len(), 4);
    assert_eq!(results[0]["coverage"], "schema-backed");
    assert_eq!(results[1]["coverage"], "interface-only");
    assert_eq!(results[2]["coverage"], "error");
    assert_eq!(results[3]["coverage"], "error");
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn batch_markdown_output_shows_scope_and_coverage_columns() {
    let manifest = format!(
        r#"
        [[pairs]]
        old = {:?}
        new = {:?}
        name = "markdown_contract"
        "#,
        wasm("v1.wasm").to_string_lossy(),
        wasm("v1.wasm").to_string_lossy(),
    );
    let manifest_path = write_manifest("markdown_manifest.toml", &manifest);
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args([
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--format",
            "markdown",
        ])
        .output()
        .expect("failed to run binary");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");

    assert_eq!(output.status.code(), Some(0));
    assert!(stdout.contains("| Scope | Coverage |"));
    assert!(stdout.contains("interface-only"));
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
fn batch_directory_scanning_accepts_uppercase_wasm_extension() {
    let tmp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dir_upper_test");
    let old_dir = tmp_dir.join("old");
    let new_dir = tmp_dir.join("new");

    std::fs::create_dir_all(&old_dir).ok();
    std::fs::create_dir_all(&new_dir).ok();

    // Copy fixtures with uppercase .WASM extensions:
    // a.WASM: clean (v1 -> v1)
    std::fs::copy(wasm("v1.wasm"), old_dir.join("a.WASM")).expect("copy");
    std::fs::copy(wasm("v1.wasm"), new_dir.join("a.WASM")).expect("copy");

    // b.WASM: breaking (v1 -> v2)
    std::fs::copy(wasm("v1.wasm"), old_dir.join("b.WASM")).expect("copy");
    std::fs::copy(wasm("v2.wasm"), new_dir.join("b.WASM")).expect("copy");

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

#[test]
fn batch_directory_ignores_unrelated_files() {
    let tmp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dir_ignore_test");
    let old_dir = tmp_dir.join("old");
    let new_dir = tmp_dir.join("new");

    std::fs::create_dir_all(&old_dir).ok();
    std::fs::create_dir_all(&new_dir).ok();

    std::fs::copy(wasm("v1.wasm"), old_dir.join("a.wasm")).expect("copy wasm");
    std::fs::copy(wasm("v1.wasm"), new_dir.join("a.wasm")).expect("copy wasm");

    std::fs::write(old_dir.join("readme.txt"), "project notes").expect("write readme");
    std::fs::write(old_dir.join("config.json"), "{}").expect("write json");
    std::fs::write(old_dir.join("Makefile"), "build:\n\tcargo build").expect("write makefile");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--old-dir")
        .arg(&old_dir)
        .arg("--new-dir")
        .arg(&new_dir)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");

    assert_eq!(code, 0, "all-safe batch must exit 0");
    assert!(
        stdout.contains("Overall Status: ✅ PASSED"),
        "stdout must show overall passed"
    );
    assert!(
        stdout.contains("a: ✅ PASSED"),
        "stdout must list the valid WASM pair"
    );
    assert!(
        !stdout.contains("readme.txt"),
        "unrelated readme.txt must not appear in output"
    );
    assert!(
        !stdout.contains("config.json"),
        "unrelated config.json must not appear in output"
    );
    assert!(
        !stdout.contains("Makefile"),
        "unrelated Makefile must not appear in output"
    );
    assert!(
        !stderr.contains('⚠'),
        "stderr must not contain warnings for non-WASM files"
    );
    assert!(
        !stderr.contains("readme.txt"),
        "stderr must not mention unrelated files"
    );
}

#[test]
fn batch_directory_ignores_unrelated_files_json() {
    let tmp_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dir_ignore_json_test");
    let old_dir = tmp_dir.join("old");
    let new_dir = tmp_dir.join("new");

    std::fs::create_dir_all(&old_dir).ok();
    std::fs::create_dir_all(&new_dir).ok();

    std::fs::copy(wasm("v1.wasm"), old_dir.join("a.wasm")).expect("copy wasm");
    std::fs::copy(wasm("v1.wasm"), new_dir.join("a.wasm")).expect("copy wasm");

    std::fs::write(old_dir.join("notes.txt"), "some notes").expect("write txt");
    std::fs::write(old_dir.join("data.json"), "{}").expect("write json");
    std::fs::write(old_dir.join("script"), "echo hello").expect("write script");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg("--old-dir")
        .arg(&old_dir)
        .arg("--new-dir")
        .arg(&new_dir)
        .args(["--format", "json"])
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr was not valid UTF-8");
    let code = output.status.code().expect("process terminated by signal");
    let json: Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");

    assert_eq!(code, 0);
    assert_eq!(json["is_safe"], Value::Bool(true), "JSON must report safe");

    let results = json["results"]
        .as_array()
        .expect("results must be an array");
    let contract_a = results
        .iter()
        .find(|r| r["name"] == "a")
        .expect("JSON results must contain the valid WASM pair 'a'");
    assert_eq!(
        contract_a["report"]["is_safe"],
        Value::Bool(true),
        "contract 'a' must be safe"
    );

    assert!(
        !stdout.contains("notes.txt"),
        "JSON must not contain unrelated txt file"
    );
    assert!(
        !stdout.contains("data.json"),
        "JSON must not contain unrelated json file"
    );
    assert!(
        !stdout.contains("script"),
        "JSON must not contain unrelated extensionless file"
    );
    assert!(
        !stderr.contains('⚠'),
        "stderr must not contain warnings for non-WASM files"
    );
}

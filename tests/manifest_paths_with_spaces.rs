//! Regression coverage for manifest paths containing spaces.
//!
//! Batch manifests may reference artifacts stored beneath directories whose
//! names contain spaces. This test protects manifest resolution from quoting
//! and tokenization regressions by verifying that both TOML and JSON manifests
//! can load and compare such paths.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create parent dir");
    }
    std::fs::write(path, contents).expect("failed to write file");
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout was not valid JSON ({e}).\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

fn run_manifest(manifest: &Path, extra: &[&str]) -> Run {
    let mut args = vec![
        "--manifest",
        manifest.to_str().unwrap(),
        "--format",
        "json",
        "--no-timestamp",
    ];
    args.extend_from_slice(extra);

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(&args)
        .output()
        .expect("failed to run binary");

    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        code: output.status.code().expect("process terminated by signal"),
    }
}

#[test]
fn toml_manifest_resolves_paths_with_spaces() {
    let dir = temp_dir("toml-paths-with-spaces");
    let artifacts_dir = dir.join("build artifacts");
    std::fs::create_dir_all(&artifacts_dir).expect("failed to create artifacts dir");

    // Copy fixture WASMs to directory with spaces
    std::fs::copy(wasm("v1.wasm"), artifacts_dir.join("v1.wasm")).expect("failed to copy v1.wasm");
    std::fs::copy(wasm("v2.wasm"), artifacts_dir.join("v2.wasm")).expect("failed to copy v2.wasm");
    std::fs::copy(wasm("v3.wasm"), artifacts_dir.join("v3.wasm")).expect("failed to copy v3.wasm");

    let manifest_content = format!(
        r#"
[[pairs]]
old = "build artifacts/v1.wasm"
new = "build artifacts/v3.wasm"
name = "safe_pair"

[[pairs]]
old = "build artifacts/v1.wasm"
new = "build artifacts/v2.wasm"
name = "breaking_pair"
"#
    );

    let manifest = dir.join("manifest.toml");
    write_file(&manifest, &manifest_content);

    let run = run_manifest(&manifest, &[]);

    assert_eq!(
        run.code, 1,
        "batch with breaking pair must exit 1, stderr:\n{}",
        run.stderr
    );

    let json = run.json();
    assert_eq!(json["total_pairs"].as_u64().unwrap(), 2);

    let results = json["results"]
        .as_array()
        .expect("results must be an array");
    assert_eq!(results.len(), 2);

    // Verify provenance preserves the full path with spaces
    let safe_pair = &results[0];
    assert_eq!(safe_pair["name"], "safe_pair");
    assert_eq!(safe_pair["report"]["is_safe"], true);
    let old_path = safe_pair["old"]
        .as_str()
        .expect("old path must be a string");
    assert!(
        old_path.contains("build artifacts"),
        "path provenance must preserve spaces: {old_path}"
    );

    let breaking_pair = &results[1];
    assert_eq!(breaking_pair["name"], "breaking_pair");
    assert_eq!(breaking_pair["report"]["is_safe"], false);
    let new_path = breaking_pair["new"]
        .as_str()
        .expect("new path must be a string");
    assert!(
        new_path.contains("build artifacts"),
        "path provenance must preserve spaces: {new_path}"
    );
}

#[test]
fn json_manifest_resolves_paths_with_spaces() {
    let dir = temp_dir("json-paths-with-spaces");
    let artifacts_dir = dir.join("release artifacts");
    std::fs::create_dir_all(&artifacts_dir).expect("failed to create artifacts dir");

    // Copy fixture WASMs to directory with spaces
    std::fs::copy(wasm("v1.wasm"), artifacts_dir.join("v1.wasm")).expect("failed to copy v1.wasm");
    std::fs::copy(wasm("v3.wasm"), artifacts_dir.join("v3.wasm")).expect("failed to copy v3.wasm");

    let manifest_content = format!(
        r#"{{
    "pairs": [
        {{
            "old": "release artifacts/v1.wasm",
            "new": "release artifacts/v3.wasm",
            "name": "safe_json_pair"
        }},
        {{
            "old": "release artifacts/v1.wasm",
            "new": "release artifacts/v3.wasm",
            "name": "warning_json_pair"
        }}
    ]
}}"#
    );

    let manifest = dir.join("manifest.json");
    write_file(&manifest, &manifest_content);

    let run = run_manifest(&manifest, &[]);

    assert_eq!(
        run.code, 0,
        "batch with warning-only pair must exit 0, stderr:\n{}",
        run.stderr
    );

    let json = run.json();
    assert_eq!(json["total_pairs"].as_u64().unwrap(), 2);

    let results = json["results"]
        .as_array()
        .expect("results must be an array");
    assert_eq!(results.len(), 2);

    // Verify both pairs resolved and compared successfully
    for result in results {
        let name = result["name"].as_str().unwrap();
        let old_path = result["old"].as_str().expect("old path must be a string");
        let new_path = result["new"].as_str().expect("new path must be a string");

        assert!(
            old_path.contains("release artifacts"),
            "path provenance for {name} must preserve spaces in old path: {old_path}"
        );
        assert!(
            new_path.contains("release artifacts"),
            "path provenance for {name} must preserve spaces in new path: {new_path}"
        );
    }
}

#[test]
fn error_messages_preserve_unsplit_paths_with_spaces() {
    let dir = temp_dir("error-paths-with-spaces");
    let artifacts_dir = dir.join("my build output");
    std::fs::create_dir_all(&artifacts_dir).expect("failed to create artifacts dir");

    // Create a non-WASM file in a directory with spaces
    let bad_file = artifacts_dir.join("not_wasm.bin");
    std::fs::write(&bad_file, b"this is not a WASM file").expect("failed to write bad file");

    let manifest_content = format!(
        r#"
[[pairs]]
old = "my build output/not_wasm.bin"
new = "my build output/not_wasm.bin"
name = "invalid_wasm"
"#
    );

    let manifest = dir.join("manifest.toml");
    write_file(&manifest, &manifest_content);

    let run = run_manifest(&manifest, &[]);

    assert_ne!(
        run.code, 0,
        "manifest with invalid WASM must fail, stdout:\n{}",
        run.stdout
    );

    let combined = format!("{}{}", run.stdout, run.stderr);
    assert!(
        combined.contains("my build output"),
        "error message must preserve the full unsplit path: {combined}"
    );
}

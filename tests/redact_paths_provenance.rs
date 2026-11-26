// SPDX-License-Identifier: MIT
//! Integration tests for --redact-paths with symlink target path redaction.
//!
//! --redact-paths replaces resolved symlink target paths in report provenance
//! with a stable, non-identifying label while keeping non-path identifiers intact.
//!
//! Gated to `cfg(unix)` for the same reason as `tests/symlink_input.rs`:
//! creating symlinks on Windows CI typically requires elevated privileges.

#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

struct Run {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

impl Run {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout was not valid JSON ({e}).\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(args)
        .output()
        .expect("failed to run binary");

    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout not utf8"),
        stderr: String::from_utf8(output.stderr).expect("stderr not utf8"),
        code: output.status.code(),
    }
}

fn symlinks_in(json: &serde_json::Value) -> &[serde_json::Value] {
    json["provenance"]["symlinks"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

#[test]
fn redact_paths_replaces_symlink_target_in_provenance() {
    let dir = temp_dir("redact-symlink-target");
    let link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--redact-paths",
        "--format",
        "json",
    ]);

    assert_eq!(
        run.code,
        Some(0),
        "comparison must succeed, stderr:\n{}",
        run.stderr
    );

    let json = run.json();
    let symlinks = symlinks_in(&json);

    assert_eq!(
        symlinks.len(),
        1,
        "must have one symlink entry in provenance"
    );

    let resolved = symlinks[0]["resolved"].as_str().unwrap();
    let requested = symlinks[0]["requested"].as_str().unwrap();

    // The resolved target path must be redacted
    assert!(
        resolved.starts_with("<redacted>/"),
        "resolved symlink target must be redacted, got: {resolved}"
    );

    // The requested path must also be redacted
    assert!(
        requested.starts_with("<redacted>/"),
        "requested symlink path must be redacted, got: {requested}"
    );

    // The file name should still be present
    assert!(
        resolved.ends_with(".wasm"),
        "file name must be preserved, got: {resolved}"
    );
}

#[test]
fn redact_paths_removes_absolute_directory_from_symlink_target() {
    let dir = temp_dir("redact-absolute-symlink");
    let link = dir.join("candidate.wasm");
    symlink(wasm("v2.wasm"), &link).expect("failed to create symlink");

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--redact-paths",
        "--format",
        "json",
    ]);

    assert_eq!(run.code, Some(1), "v1->v2 is breaking");

    let json = run.json();
    let symlinks = symlinks_in(&json);

    assert_eq!(symlinks.len(), 1);
    let resolved = symlinks[0]["resolved"].as_str().unwrap();

    // Must not contain the actual directory path
    let actual_target = std::fs::canonicalize(wasm("v2.wasm")).unwrap();
    let actual_dir = actual_target.parent().unwrap().to_string_lossy();

    assert!(
        !resolved.contains(&*actual_dir),
        "redacted path must not contain actual directory: {resolved} should not contain {actual_dir}"
    );

    // Must use the redacted label
    assert!(
        resolved.contains("<redacted>"),
        "must contain redacted label, got: {resolved}"
    );
}

#[test]
fn without_redact_paths_symlink_target_is_present() {
    let dir = temp_dir("no-redact-symlink");
    let link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(run.code, Some(0));

    let json = run.json();
    let symlinks = symlinks_in(&json);

    assert_eq!(symlinks.len(), 1);
    let resolved = symlinks[0]["resolved"].as_str().unwrap();

    // Without --redact-paths, the full path should be present
    assert!(
        !resolved.starts_with("<redacted>"),
        "without --redact-paths, path must not be redacted, got: {resolved}"
    );

    // It should contain the actual resolved path
    let actual_target = std::fs::canonicalize(wasm("v1.wasm")).unwrap();
    let normalized_actual = crate::loader::normalize_path_display(&actual_target.to_string_lossy());

    assert_eq!(
        resolved, normalized_actual,
        "without --redact-paths, resolved path must be the actual target"
    );
}

#[test]
fn redact_paths_handles_both_sides_symlinked() {
    let dir = temp_dir("redact-both-symlinks");
    let old_link = dir.join("baseline.wasm");
    let new_link = dir.join("candidate.wasm");

    symlink(wasm("v1.wasm"), &old_link).expect("failed to create old symlink");
    symlink(wasm("v2.wasm"), &new_link).expect("failed to create new symlink");

    let run = run(&[
        old_link.to_str().unwrap(),
        new_link.to_str().unwrap(),
        "--redact-paths",
        "--format",
        "json",
    ]);

    assert_eq!(run.code, Some(1), "v1->v2 is breaking");

    let json = run.json();
    let symlinks = symlinks_in(&json);

    assert_eq!(
        symlinks.len(),
        2,
        "must have two symlink entries for both sides"
    );

    // Both symlink targets must be redacted
    for (i, symlink_entry) in symlinks.iter().enumerate() {
        let resolved = symlink_entry["resolved"].as_str().unwrap();
        let requested = symlink_entry["requested"].as_str().unwrap();

        assert!(
            resolved.starts_with("<redacted>/"),
            "symlink {i} resolved must be redacted, got: {resolved}"
        );
        assert!(
            requested.starts_with("<redacted>/"),
            "symlink {i} requested must be redacted, got: {requested}"
        );
    }
}

#[test]
fn redact_paths_preserves_interface_hashes() {
    let dir = temp_dir("redact-preserves-hashes");
    let link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    let run_redacted = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--redact-paths",
        "--format",
        "json",
    ]);

    let run_unredacted = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(run_redacted.code, Some(0));
    assert_eq!(run_unredacted.code, Some(0));

    let redacted_json = run_redacted.json();
    let unredacted_json = run_unredacted.json();

    // Interface hashes must be identical
    assert_eq!(
        redacted_json["old"]["interface_hash"], unredacted_json["old"]["interface_hash"],
        "interface hash must not be affected by --redact-paths"
    );

    assert_eq!(
        redacted_json["new"]["interface_hash"], unredacted_json["new"]["interface_hash"],
        "interface hash must not be affected by --redact-paths"
    );
}

#[test]
fn redact_paths_preserves_wasm_sha256() {
    let dir = temp_dir("redact-preserves-sha");
    let link = dir.join("new.wasm");
    symlink(wasm("v2.wasm"), &link).expect("failed to create symlink");

    let run_redacted = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--redact-paths",
        "--format",
        "json",
    ]);

    let run_unredacted = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(run_redacted.code, Some(1));
    assert_eq!(run_unredacted.code, Some(1));

    let redacted_json = run_redacted.json();
    let unredacted_json = run_unredacted.json();

    // SHA-256 hashes must be identical
    assert_eq!(
        redacted_json["old"]["wasm_sha256"], unredacted_json["old"]["wasm_sha256"],
        "WASM SHA-256 must not be affected by --redact-paths"
    );

    assert_eq!(
        redacted_json["new"]["wasm_sha256"], unredacted_json["new"]["wasm_sha256"],
        "WASM SHA-256 must not be affected by --redact-paths"
    );
}

#[test]
fn redact_paths_preserves_findings() {
    let dir = temp_dir("redact-preserves-findings");
    let link = dir.join("new.wasm");
    symlink(wasm("v2.wasm"), &link).expect("failed to create symlink");

    let run_redacted = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--redact-paths",
        "--format",
        "json",
    ]);

    let run_unredacted = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(run_redacted.code, Some(1));
    assert_eq!(run_unredacted.code, Some(1));

    let redacted_json = run_redacted.json();
    let unredacted_json = run_unredacted.json();

    // Findings must be identical
    assert_eq!(
        redacted_json["findings"], unredacted_json["findings"],
        "findings must not be affected by --redact-paths"
    );

    // Counts must be identical
    assert_eq!(
        redacted_json["counts"], unredacted_json["counts"],
        "finding counts must not be affected by --redact-paths"
    );

    // Verdict must be identical
    assert_eq!(
        redacted_json["is_safe"], unredacted_json["is_safe"],
        "safety verdict must not be affected by --redact-paths"
    );
}

#[test]
fn redact_paths_with_symlink_chain_redacts_final_target() {
    let dir = temp_dir("redact-chain");
    let hop1 = dir.join("hop1.wasm");
    let hop2 = dir.join("hop2.wasm");
    let entry = dir.join("entry.wasm");

    // entry -> hop2 -> hop1 -> tests/wasm/v1.wasm
    symlink(wasm("v1.wasm"), &hop1).expect("failed to create symlink");
    symlink(&hop1, &hop2).expect("failed to create symlink");
    symlink(&hop2, &entry).expect("failed to create symlink");

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        entry.to_str().unwrap(),
        "--redact-paths",
        "--format",
        "json",
    ]);

    assert_eq!(run.code, Some(0));

    let json = run.json();
    let symlinks = symlinks_in(&json);

    assert_eq!(symlinks.len(), 1);
    let resolved = symlinks[0]["resolved"].as_str().unwrap();

    // The final resolved target must be redacted
    assert!(
        resolved.starts_with("<redacted>/"),
        "chained symlink target must be redacted, got: {resolved}"
    );

    // Must not contain the actual absolute path to v1.wasm
    let actual_target = std::fs::canonicalize(wasm("v1.wasm")).unwrap();
    let actual_dir = actual_target.parent().unwrap().to_string_lossy();

    assert!(
        !resolved.contains(&*actual_dir),
        "redacted path must not expose directory structure, got: {resolved}"
    );
}

#[test]
fn redact_paths_in_text_output_also_redacts_symlinks() {
    let dir = temp_dir("redact-text-output");
    let link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--redact-paths",
        "--quiet",
        "--format",
        "text",
    ]);

    assert_eq!(run.code, Some(0));

    // Text output should also show redacted symlink information
    assert!(
        run.stdout.contains("<redacted>"),
        "text output must show redacted paths, got:\n{}",
        run.stdout
    );

    // Must not contain actual directory paths
    let actual_target = std::fs::canonicalize(wasm("v1.wasm")).unwrap();
    let actual_dir = actual_target.parent().unwrap().to_string_lossy();

    assert!(
        !run.stdout.contains(&*actual_dir),
        "text output must not contain actual directory paths"
    );
}

// Add module path for normalize_path_display helper
mod loader {
    pub fn normalize_path_display(path: &str) -> String {
        path.replace('\\', "/")
    }
}

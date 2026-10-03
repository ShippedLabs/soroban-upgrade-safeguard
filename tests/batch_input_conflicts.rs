//! Manifest mode (`--manifest`), directory mode (`--old-dir`/`--new-dir`),
//! and positional `<OLD_WASM> <NEW_WASM>` inputs are mutually exclusive —
//! exactly one way of supplying a comparison's inputs may be used per run.
//! `src/main.rs` enforces this with two checks, both before `build_batch`
//! or any WASM loading runs:
//!
//! - `--manifest` together with `--old-dir` and/or `--new-dir`
//! - batch mode (either form) together with a positional WASM path
//!
//! Every test below points the *losing* combination's paths at locations
//! that don't exist, so a pass can only mean the conflict check fired
//! before any of them were read — if the tool had instead tried to open
//! one of these paths, the error would be a file-not-found/parse failure
//! naming that path, not the conflict message asserted here.

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
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

// ---------------------------------------------------------------------------
// --manifest + --old-dir/--new-dir
// ---------------------------------------------------------------------------

#[test]
fn manifest_plus_old_and_new_dir_is_rejected() {
    let (code, stdout, stderr) = run(&[
        "--manifest",
        "/nonexistent/manifest.toml",
        "--old-dir",
        "/nonexistent/old",
        "--new-dir",
        "/nonexistent/new",
    ]);

    assert_ne!(code, 0, "manifest + directory mode must be rejected");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("--manifest") && combined.contains("--old-dir") && combined.contains("--new-dir"),
        "diagnostic should name all three conflicting flags, got: {combined}"
    );
    assert!(
        !combined.to_lowercase().contains("no such file")
            && !combined.to_lowercase().contains("not found"),
        "the conflict must be caught before any path is actually opened, got: {combined}"
    );
}

#[test]
fn manifest_plus_old_dir_only_is_rejected() {
    // --old-dir alone requires --new-dir at the clap level, so pairing it
    // with a real, satisfiable --new-dir isolates this case to "does
    // --manifest conflict with just one of the two directory flags".
    let (code, stdout, stderr) = run(&[
        "--manifest",
        "/nonexistent/manifest.toml",
        "--old-dir",
        "/nonexistent/old",
        "--new-dir",
        wasm("v1.wasm").to_str().unwrap(),
    ]);

    assert_ne!(code, 0);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("--manifest") && combined.contains("--old-dir"),
        "got: {combined}"
    );
}

// ---------------------------------------------------------------------------
// batch mode + positional WASM paths
// ---------------------------------------------------------------------------

#[test]
fn manifest_plus_positional_wasm_paths_is_rejected() {
    let (code, stdout, stderr) = run(&[
        "--manifest",
        "/nonexistent/manifest.toml",
        "/nonexistent/old.wasm",
        "/nonexistent/new.wasm",
    ]);

    assert_ne!(
        code, 0,
        "batch mode (manifest) plus positional WASM paths must be rejected"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("--manifest") && combined.contains("positional"),
        "diagnostic should identify batch mode and the positional-path conflict, got: {combined}"
    );
    assert!(
        !combined.to_lowercase().contains("no such file")
            && !combined.to_lowercase().contains("not found"),
        "the conflict must be caught before any path is actually opened, got: {combined}"
    );
}

#[test]
fn directory_mode_plus_positional_wasm_paths_is_rejected() {
    let (code, stdout, stderr) = run(&[
        "--old-dir",
        "/nonexistent/old",
        "--new-dir",
        "/nonexistent/new",
        "/nonexistent/old.wasm",
        "/nonexistent/new.wasm",
    ]);

    assert_ne!(
        code, 0,
        "batch mode (directories) plus a positional WASM path must be rejected"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("--old-dir") && combined.contains("--new-dir") && combined.contains("positional"),
        "diagnostic should identify batch mode and the positional-path conflict, got: {combined}"
    );
    assert!(
        !combined.to_lowercase().contains("no such file")
            && !combined.to_lowercase().contains("not found"),
        "the conflict must be caught before any path is actually opened, got: {combined}"
    );
}

#[test]
fn directory_mode_plus_a_single_stray_positional_wasm_path_is_rejected() {
    // Even one stray positional argument (not a full OLD_WASM/NEW_WASM
    // pair) alongside batch mode must be rejected the same way as a full
    // pair of positional paths.
    let (code, stdout, stderr) = run(&[
        "--old-dir",
        "/nonexistent/old",
        "--new-dir",
        "/nonexistent/new",
        "/nonexistent/stray.wasm",
    ]);

    assert_ne!(code, 0);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("positional"), "got: {combined}");
}

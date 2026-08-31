//! Integration tests for the symlink input policy: detection + provenance by
//! default, and `--no-symlinks` to reject them outright.
//!
//! Gated to `cfg(unix)` — creating symlinks on `windows-latest` CI typically
//! requires elevated privileges/Developer Mode that GitHub-hosted runners
//! don't have, so there is no reliable way to exercise symlink creation
//! there. `std::os::unix::fs::symlink` is used directly rather than a
//! `tempfile`-style crate, matching this repo's existing "no extra test
//! dependencies" convention (see `tests/manifest_composition.rs`'s hand
//! rolled temp-dir helper).
#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// A fresh directory for one test, isolated by test name and process id.
fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

struct Run {
    stdout: String,
    stderr: String,
    code: Option<i32>,
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

    fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn run(args: &[&str]) -> Run {
    run_in(None, args)
}

fn run_in(cwd: Option<&Path>, args: &[&str]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"));
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    let output = command.output().expect("failed to run binary");
    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not valid UTF-8"),
        code: output.status.code(),
    }
}

fn symlinks_in(json: &Value) -> &[Value] {
    json["provenance"]["symlinks"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

// ---------------------------------------------------------------------------
// Normal files
// ---------------------------------------------------------------------------

#[test]
fn a_normal_file_has_no_symlink_provenance() {
    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(run.code, Some(0));
    let json = run.json();
    assert!(
        symlinks_in(&json).is_empty(),
        "a direct file must record no symlink provenance: {}",
        json["provenance"]
    );
}

#[test]
fn no_symlinks_flag_does_not_affect_a_normal_file() {
    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        "--no-symlinks",
        "--format",
        "json",
    ]);
    assert_eq!(
        run.code,
        Some(0),
        "--no-symlinks must not reject a direct file: {}",
        run.combined()
    );
}

// ---------------------------------------------------------------------------
// Direct symlinks
// ---------------------------------------------------------------------------

#[test]
fn a_direct_symlink_is_followed_and_recorded_in_provenance() {
    let dir = temp_dir("symlink-direct");
    let link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(run.code, Some(0), "{}", run.combined());
    let json = run.json();

    let symlinks = symlinks_in(&json);
    assert_eq!(
        symlinks.len(),
        1,
        "exactly the 'new' side is a symlink: {symlinks:?}"
    );
    let resolved = symlinks[0]["resolved"].as_str().unwrap();
    let expected = std::fs::canonicalize(wasm("v1.wasm")).unwrap();
    assert_eq!(
        PathBuf::from(resolved),
        expected,
        "resolved path must be the real target, not the link"
    );
    let requested = symlinks[0]["requested"].as_str().unwrap();
    assert!(
        requested.ends_with("new.wasm"),
        "requested path should be what was given on the command line: {requested}"
    );
}

#[test]
fn a_relative_symlink_input_reports_a_relative_requested_path() {
    // The `requested`/`resolved` split exists precisely so a relative input
    // doesn't gain the whole directory chain above it just because it's
    // being recorded for provenance: `requested` is the path exactly as
    // given (here, relative to the run's cwd), never canonicalized;
    // `resolved` is necessarily absolute, since a symlink target has to be
    // unambiguous to be useful as provenance at all.
    let dir = temp_dir("symlink-relative-input");
    let link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    // "old" is given as an absolute path (its relativeness isn't what's under
    // test); "new" is the relative symlink under test, resolved against
    // `--cwd`-equivalent `dir` since the process runs with that as its
    // current directory.
    let run = run_in(
        Some(&dir),
        &[
            wasm("v1.wasm").to_str().unwrap(),
            "new.wasm",
            "--format",
            "json",
        ],
    );
    assert_eq!(run.code, Some(0), "{}", run.combined());
    let json = run.json();

    let symlinks = symlinks_in(&json);
    assert_eq!(symlinks.len(), 1);
    let requested = symlinks[0]["requested"].as_str().unwrap();
    assert_eq!(
        requested, "new.wasm",
        "a relative input must be reported relative, not expanded to an absolute path"
    );
    let resolved = symlinks[0]["resolved"].as_str().unwrap();
    assert!(
        PathBuf::from(resolved).is_absolute(),
        "the resolved target must still be unambiguous: {resolved}"
    );
}

#[test]
fn both_sides_symlinked_records_two_entries() {
    let dir = temp_dir("symlink-both");
    let old_link = dir.join("old.wasm");
    let new_link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &old_link).expect("failed to create symlink");
    symlink(wasm("v2.wasm"), &new_link).expect("failed to create symlink");

    let run = run(&[
        old_link.to_str().unwrap(),
        new_link.to_str().unwrap(),
        "--format",
        "json",
    ]);
    // v1 -> v2 is a breaking change; exit 1 either way, but provenance must
    // still be populated for a failing comparison.
    assert_eq!(run.code, Some(1), "{}", run.combined());
    let json = run.json();
    assert_eq!(symlinks_in(&json).len(), 2);
}

#[test]
fn a_non_utf8_path_component_is_reported_lossily_in_provenance() {
    let dir = temp_dir("non-utf8-path");
    let filename = OsString::from_vec(b"v1-\xFF.wasm".to_vec());
    let path = dir.join(&filename);
    std::fs::copy(wasm("v1.wasm"), &path).expect("failed to create WASM with a non-UTF-8 name");

    let module = soroban_upgrade_safeguard::loader::load_wasm(&path)
        .expect("a valid WASM file with a non-UTF-8 path component must still load");

    assert_eq!(module.path, path.to_string_lossy().to_string());
    assert!(module.path.contains("\u{FFFD}") || path.as_os_str().as_bytes().contains(&0xFF));
}

// ---------------------------------------------------------------------------
// Chained symlinks
// ---------------------------------------------------------------------------

#[test]
fn a_chain_of_symlinks_resolves_to_the_final_real_file() {
    let dir = temp_dir("symlink-chain");
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
        "--format",
        "json",
    ]);
    assert_eq!(run.code, Some(0), "{}", run.combined());
    let json = run.json();

    let symlinks = symlinks_in(&json);
    assert_eq!(symlinks.len(), 1);
    let resolved = symlinks[0]["resolved"].as_str().unwrap();
    let expected = std::fs::canonicalize(wasm("v1.wasm")).unwrap();
    assert_eq!(
        PathBuf::from(resolved),
        expected,
        "a chain must resolve all the way to the real file, not an intermediate link"
    );

    // The comparison itself must have actually run against real bytes
    // (v1 vs v1 is safe), not failed or been skipped.
    assert_eq!(json["is_safe"], Value::Bool(true));
}

// ---------------------------------------------------------------------------
// Broken links
// ---------------------------------------------------------------------------

#[test]
fn a_broken_symlink_is_a_clear_error() {
    let dir = temp_dir("symlink-broken");
    let link = dir.join("new.wasm");
    symlink(dir.join("does-not-exist.wasm"), &link).expect("failed to create symlink");

    let run = run(&[wasm("v1.wasm").to_str().unwrap(), link.to_str().unwrap()]);
    assert_ne!(run.code, Some(0), "a broken link must fail the run");
    let combined = run.combined();
    assert!(
        combined.to_lowercase().contains("symlink"),
        "error should mention the symlink, got: {combined}"
    );
}

#[test]
fn a_broken_link_in_the_middle_of_a_chain_is_a_clear_error() {
    let dir = temp_dir("symlink-broken-chain");
    let dangling = dir.join("dangling.wasm");
    let entry = dir.join("entry.wasm");
    symlink(dir.join("does-not-exist.wasm"), &dangling).expect("failed to create symlink");
    symlink(&dangling, &entry).expect("failed to create symlink");

    let run = run(&[wasm("v1.wasm").to_str().unwrap(), entry.to_str().unwrap()]);
    assert_ne!(run.code, Some(0));
    assert!(run.combined().to_lowercase().contains("symlink"));
}

// ---------------------------------------------------------------------------
// Cycles
// ---------------------------------------------------------------------------

#[test]
fn a_symlink_cycle_is_a_clear_error_not_a_hang() {
    let dir = temp_dir("symlink-cycle");
    let a = dir.join("a.wasm");
    let b = dir.join("b.wasm");
    // a -> b -> a
    symlink(&b, &a).expect("failed to create symlink");
    symlink(&a, &b).expect("failed to create symlink");

    let run = run(&[wasm("v1.wasm").to_str().unwrap(), a.to_str().unwrap()]);
    assert_ne!(run.code, Some(0), "a symlink cycle must fail, not hang");
    assert!(run.combined().to_lowercase().contains("symlink"));
}

// ---------------------------------------------------------------------------
// --no-symlinks
// ---------------------------------------------------------------------------

#[test]
fn no_symlinks_rejects_a_symlinked_input() {
    let dir = temp_dir("symlink-rejected");
    let link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    let run = run(&[
        wasm("v1.wasm").to_str().unwrap(),
        link.to_str().unwrap(),
        "--no-symlinks",
    ]);
    assert_ne!(
        run.code,
        Some(0),
        "--no-symlinks must reject a symlinked input"
    );
    let combined = run.combined();
    assert!(
        combined.to_lowercase().contains("symlink"),
        "error should mention the symlink: {combined}"
    );
}

#[test]
fn the_same_symlinked_input_succeeds_without_no_symlinks() {
    // Sanity check that --no-symlinks is what made the difference above, not
    // something else about the fixture.
    let dir = temp_dir("symlink-allowed-by-default");
    let link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    let run = run(&[wasm("v1.wasm").to_str().unwrap(), link.to_str().unwrap()]);
    assert_eq!(run.code, Some(0), "{}", run.combined());
}

#[test]
fn no_symlinks_rejects_the_old_side_too() {
    let dir = temp_dir("symlink-rejected-old-side");
    let link = dir.join("old.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    let run = run(&[
        link.to_str().unwrap(),
        wasm("v1.wasm").to_str().unwrap(),
        "--no-symlinks",
    ]);
    assert_ne!(run.code, Some(0));
    assert!(run.combined().to_lowercase().contains("symlink"));
}

#[test]
fn no_symlinks_rejects_a_symlink_in_manifest_mode() {
    let dir = temp_dir("symlink-manifest");
    let link = dir.join("new.wasm");
    symlink(wasm("v1.wasm"), &link).expect("failed to create symlink");

    let manifest = dir.join("manifest.toml");
    std::fs::write(
        &manifest,
        format!(
            "[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"token\"\n",
            wasm("v1.wasm").to_str().unwrap(),
            link.to_str().unwrap(),
        ),
    )
    .expect("failed to write manifest");

    let run = run(&[
        "--manifest",
        manifest.to_str().unwrap(),
        "--no-symlinks",
        "--format",
        "json",
    ]);
    assert_ne!(
        run.code,
        Some(0),
        "--no-symlinks must reject a symlinked pair in batch mode too: {}",
        run.combined()
    );
    assert!(run.combined().to_lowercase().contains("symlink"));
}

#[test]
fn a_symlink_in_manifest_mode_is_recorded_without_no_symlinks() {
    let dir = temp_dir("symlink-manifest-allowed");
    let link = dir.join("new.wasm");
    symlink(wasm("v3.wasm"), &link).expect("failed to create symlink");

    let manifest = dir.join("manifest.toml");
    std::fs::write(
        &manifest,
        format!(
            "[[pairs]]\nold = {:?}\nnew = {:?}\nname = \"token\"\n",
            wasm("v1.wasm").to_str().unwrap(),
            link.to_str().unwrap(),
        ),
    )
    .expect("failed to write manifest");

    let run = run(&["--manifest", manifest.to_str().unwrap(), "--format", "json"]);
    assert_eq!(run.code, Some(0), "{}", run.combined());
    let json = run.json();
    let report = json["results"][0]["report"].clone();
    assert_eq!(
        symlinks_in(&report).len(),
        1,
        "batch per-pair report must record the symlink too: {report}"
    );
}

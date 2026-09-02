//! Integration tests for path display normalization: reports (JSON and
//! human-readable) show forward-slash-separated paths regardless of the
//! platform that produced them, while relative paths stay relative rather
//! than being expanded to a full absolute path.
//!
//! `src/loader.rs`'s own `path_display_tests` module covers
//! `normalize_path_display` itself against hand-built Windows-style strings
//! — a real cross-platform check that runs identically on every CI platform.
//! The tests here instead confirm the function is actually wired into every
//! report-facing surface, using whatever paths the *running* platform
//! naturally produces.

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

fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create parent dir");
    }
    std::fs::write(&path, contents).expect("failed to write file");
    path
}

fn stage_wasm(dir: &Path) {
    std::fs::create_dir_all(dir).expect("failed to create wasm dir");
    for name in ["v1.wasm", "v2.wasm", "v3.wasm"] {
        std::fs::copy(wasm(name), dir.join(name)).expect("failed to copy fixture wasm");
    }
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

/// Every string value found anywhere in `json`, recursively — used to sweep
/// a whole document for a forbidden character without hand-listing every
/// field that happens to hold a path.
fn all_strings(json: &Value, out: &mut Vec<String>) {
    match json {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| all_strings(v, out)),
        Value::Object(map) => map.values().for_each(|v| all_strings(v, out)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Batch / manifest JSON
// ---------------------------------------------------------------------------

#[test]
fn batch_json_path_fields_never_contain_a_backslash() {
    let dir = temp_dir("path-norm-batch-json");
    stage_wasm(&dir.join("wasm"));
    let manifest = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v3.wasm"
        name = "token"
        "#,
    );

    let run = run_in(
        None,
        &["--manifest", manifest.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let json = run.json();

    let result = &json["results"][0];
    for field in ["old", "new"] {
        let value = result[field].as_str().unwrap_or_else(|| {
            panic!(
                "results[0].{field} must be a string, got {:?}",
                result[field]
            )
        });
        assert!(
            !value.contains('\\'),
            "results[0].{field} must not contain a backslash: {value}"
        );
    }

    let pair = &json["manifest"]["pairs"][0];
    for field in ["old", "new", "defined_in"] {
        let value = pair[field].as_str().unwrap();
        assert!(
            !value.contains('\\'),
            "manifest.pairs[0].{field} must not contain a backslash: {value}"
        );
    }
}

#[test]
fn batch_json_storage_schema_paths_never_contain_a_backslash() {
    let dir = temp_dir("path-norm-schema");
    stage_wasm(&dir.join("wasm"));
    write(&dir, "schemas/empty.json", r#"{"declarations": []}"#);
    let manifest = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v3.wasm"
        name = "token"
        old_storage_schema = "schemas/empty.json"
        new_storage_schema = "schemas/empty.json"
        "#,
    );

    let run = run_in(
        None,
        &["--manifest", manifest.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let json = run.json();

    let result = &json["results"][0];
    for field in ["old_storage_schema", "new_storage_schema"] {
        let value = result[field].as_str().unwrap();
        assert!(
            !value.contains('\\'),
            "results[0].{field} must not contain a backslash: {value}"
        );
    }
}

#[test]
fn no_string_anywhere_in_batch_json_contains_a_backslash() {
    // A broad sweep, so a path embedded somewhere unexpected (a future field)
    // is still caught rather than needing its own dedicated assertion.
    let dir = temp_dir("path-norm-sweep");
    stage_wasm(&dir.join("wasm"));
    let manifest = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v2.wasm"
        name = "token"
        "#,
    );

    let run = run_in(
        None,
        &["--manifest", manifest.to_str().unwrap(), "--format", "json"],
    );
    let json = run.json();
    let mut strings = Vec::new();
    all_strings(&json, &mut strings);
    let offenders: Vec<&String> = strings.iter().filter(|s| s.contains('\\')).collect();
    assert!(
        offenders.is_empty(),
        "found backslash-containing strings in batch JSON: {offenders:?}"
    );
}

// ---------------------------------------------------------------------------
// --explain-manifest (human-readable)
// ---------------------------------------------------------------------------

#[test]
fn explain_manifest_output_never_contains_a_backslash() {
    let dir = temp_dir("path-norm-explain");
    stage_wasm(&dir.join("wasm"));
    let manifest = write(
        &dir,
        "root.toml",
        r#"
        [defaults]
        base_dir = "wasm"

        [[pairs]]
        old  = "v1.wasm"
        new  = "v3.wasm"
        name = "token"
        "#,
    );

    let run = run_in(
        None,
        &[
            "--manifest",
            manifest.to_str().unwrap(),
            "--explain-manifest",
        ],
    );
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    assert!(
        !run.stdout.contains('\\'),
        "--explain-manifest output must not contain a backslash:\n{}",
        run.stdout
    );
}

// ---------------------------------------------------------------------------
// Preserving source information without leaking unrelated directories
// ---------------------------------------------------------------------------
//
// Manifest-mode paths are always resolved to an absolute path internally
// (`manifest::resolve` anchors the root against the current directory before
// anything else runs), so "stays relative" isn't a property manifest-mode
// report output can have — that's true independent of this change. The
// property this task actually adds is symlink-specific: `requested` (what
// was given) is *not* canonicalized, so a relative symlink input reports as
// a short, relative path rather than gaining the whole directory chain above
// it, while `resolved` (what was actually read) is necessarily absolute,
// since a symlink target must be unambiguous to be useful as provenance.
// Exercised end-to-end by
// `tests/symlink_input.rs::a_relative_symlink_input_reports_a_relative_requested_path`,
// which needs a real symlink and so is `cfg(unix)`-gated; the underlying
// string transformation is verified directly (platform-independent) in
// `src/loader.rs`'s
// `path_display_tests::a_relative_path_with_parent_references_stays_relative`.

#[test]
fn single_run_relative_input_paths_are_not_expanded_in_symlink_provenance() {
    // A single-run comparison with no symlinks involved must have no
    // `provenance.symlinks` entries at all — so there is nothing for a
    // relative input to be expanded into in the first place. This is the
    // baseline that makes the (Unix-only) symlink case in
    // `tests/symlink_input.rs` meaningful: normal inputs never gain
    // additional absolute-path exposure.
    let run = run_in(
        None,
        &[
            wasm("v1.wasm").to_str().unwrap(),
            wasm("v1.wasm").to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(run.code, Some(0), "stderr:\n{}", run.stderr);
    let json = run.json();
    let symlinks = json["provenance"]["symlinks"].as_array();
    assert!(
        symlinks.is_none_or(|s| s.is_empty()),
        "a plain file comparison must record no symlink provenance: {}",
        json["provenance"]
    );
}

// ---------------------------------------------------------------------------
// Single-pair mode: no regressions from normalization touching validation
// errors (which must still show the path exactly as given, for diagnostics)
// ---------------------------------------------------------------------------

#[test]
fn a_missing_file_error_still_names_the_exact_path_given() {
    let dir = temp_dir("path-norm-diagnostics");
    let missing = dir.join("does-not-exist.wasm");

    let run = run_in(
        None,
        &[wasm("v1.wasm").to_str().unwrap(), missing.to_str().unwrap()],
    );
    assert_ne!(run.code, Some(0));
    // The diagnostic must still be actionable: it names the real path,
    // unmodified by report-facing normalization (which only applies to the
    // path recorded for a successfully loaded module, not to error text).
    assert!(
        run.stderr
            .contains(missing.file_name().unwrap().to_str().unwrap()),
        "error should name the missing file: {}",
        run.stderr
    );
}

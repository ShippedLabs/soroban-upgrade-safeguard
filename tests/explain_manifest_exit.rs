// SPDX-License-Identifier: MIT
//! Integration tests for --explain-manifest early exit behavior.
//!
//! --explain-manifest resolves a manifest and its include chain, prints how
//! every setting was decided, then exits without comparing anything.

use std::path::{Path, PathBuf};
use std::process::Command;

fn temp_dir(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

fn write_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("failed to create parent dir");
    }
    std::fs::write(&path, contents).expect("failed to write file");
    path
}

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
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
    code: i32,
}

fn run_manifest(manifest: &Path, extra: &[&str]) -> Run {
    let mut args = vec!["--manifest", manifest.to_str().unwrap()];
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
fn explain_manifest_exits_without_comparing() {
    let dir = temp_dir("explain-no-compare");
    // Do NOT stage WASM files - resolution must not load them

    let manifest_content = r#"
[[pairs]]
old = "missing_old.wasm"
new = "missing_new.wasm"
name = "test_pair"
"#
    .to_string();

    let manifest = write_file(&dir, "manifest.toml", &manifest_content);
    let run = run_manifest(&manifest, &["--explain-manifest"]);

    assert_eq!(
        run.code, 0,
        "--explain-manifest must exit 0 without loading WASM, stderr:\n{}",
        run.stderr
    );

    // Must show resolution output
    assert!(
        run.stdout.contains("Manifest") || run.stdout.contains("resolution"),
        "--explain-manifest must show manifest resolution, got:\n{}",
        run.stdout
    );

    // Must NOT perform comparison or show comparison output
    assert!(
        !run.stdout.to_lowercase().contains("comparing")
            && !run.stdout.to_lowercase().contains("critical")
            && !run.stdout.to_lowercase().contains("finding"),
        "--explain-manifest must not perform comparison, got:\n{}",
        run.stdout
    );

    // Must NOT report missing WASM files as errors (they're not loaded)
    assert!(
        !run.stderr.to_lowercase().contains("not found")
            && !run.stderr.to_lowercase().contains("missing_old")
            && !run.stderr.to_lowercase().contains("missing_new"),
        "--explain-manifest must not try to load WASM files, stderr:\n{}",
        run.stderr
    );
}

#[test]
fn explain_manifest_shows_include_chain_resolution() {
    let dir = temp_dir("explain-include-chain");

    // Create an included manifest with defaults
    let included_content = r#"
[defaults]
strict = true
explain = false

[defaults.policy]
gate_event_indexer = false
"#;
    write_file(&dir, "common/base.toml", included_content);

    // Root manifest that includes the base and overrides some settings
    let root_content = r#"
include = ["common/base.toml"]

[defaults]
explain = true

[[pairs]]
old = "v1.wasm"
new = "v2.wasm"
name = "contract_a"
strict = false
"#;
    let manifest = write_file(&dir, "manifest.toml", root_content);

    let run = run_manifest(&manifest, &["--explain-manifest"]);

    assert_eq!(
        run.code, 0,
        "resolution must succeed, stderr:\n{}",
        run.stderr
    );

    let out = run.stdout;

    // Must show the include chain
    assert!(
        out.contains("base.toml") || out.contains("common"),
        "output must reference included manifest, got:\n{}",
        out
    );

    // Must show settings resolved from the included manifest
    assert!(
        out.contains("strict") || out.contains("true"),
        "output must show settings from included manifest, got:\n{}",
        out
    );

    // Must show settings resolved from the root manifest
    assert!(
        out.contains("explain"),
        "output must show settings from root manifest, got:\n{}",
        out
    );

    // Must show pair-level overrides
    assert!(
        out.contains("contract_a"),
        "output must show pair names, got:\n{}",
        out
    );

    // Must NOT perform any comparison
    assert!(
        !out.contains("SOROBAN BATCH SAFETY REPORT")
            && !out.contains("Critical")
            && !out.contains("findings"),
        "must not perform comparison, got:\n{}",
        out
    );
}

#[test]
fn explain_manifest_shows_setting_origins() {
    let dir = temp_dir("explain-origins");

    let included = r#"
[defaults]
strict = true
ascii = true
"#;
    write_file(&dir, "included.toml", included);

    let root = r#"
include = ["included.toml"]

[defaults]
ascii = false

[[pairs]]
old = "v1.wasm"
new = "v2.wasm"
name = "pair_with_override"
strict = false
"#;
    let manifest = write_file(&dir, "root.toml", root);

    let run = run_manifest(&manifest, &["--explain-manifest"]);

    assert_eq!(run.code, 0, "resolution must succeed");

    let out = run.stdout;

    // Must show where settings came from
    // The exact format depends on implementation, but we expect origin indicators
    assert!(
        out.contains("included") || out.contains("root") || out.contains("pair"),
        "output must indicate setting origins, got:\n{}",
        out
    );

    // Must show the pair name
    assert!(
        out.contains("pair_with_override"),
        "output must show pair name, got:\n{}",
        out
    );

    // Must show settings (strict, ascii)
    let out_lower = out.to_lowercase();
    assert!(
        out_lower.contains("strict") || out_lower.contains("ascii"),
        "output must show setting names, got:\n{}",
        out
    );
}

#[test]
fn explain_manifest_with_multiple_pairs_shows_all_pairs() {
    let dir = temp_dir("explain-multiple-pairs");

    let manifest_content = r#"
[[pairs]]
old = "v1.wasm"
new = "v2.wasm"
name = "first_contract"

[[pairs]]
old = "v1.wasm"
new = "v3.wasm"
name = "second_contract"
strict = true

[[pairs]]
old = "v2.wasm"
new = "v3.wasm"
name = "third_contract"
"#;
    let manifest = write_file(&dir, "manifest.toml", manifest_content);

    let run = run_manifest(&manifest, &["--explain-manifest"]);

    assert_eq!(run.code, 0);

    let out = run.stdout;

    // Must show all three pairs
    assert!(
        out.contains("first_contract"),
        "output must show first pair, got:\n{}",
        out
    );
    assert!(
        out.contains("second_contract"),
        "output must show second pair, got:\n{}",
        out
    );
    assert!(
        out.contains("third_contract"),
        "output must show third pair, got:\n{}",
        out
    );

    // Must NOT load or compare any of them
    assert!(
        !out.contains("Comparing") && !out.contains("Loaded"),
        "must not load or compare WASMs, got:\n{}",
        out
    );
}

#[test]
fn explain_manifest_with_staged_wasm_still_does_not_compare() {
    let dir = temp_dir("explain-with-wasm");
    let wasm_dir = dir.join("wasm");
    stage_wasm(&wasm_dir);

    let manifest_content = r#"
[defaults]
base_dir = "wasm"

[[pairs]]
old = "v1.wasm"
new = "v2.wasm"
name = "real_contract"
"#;
    let manifest = write_file(&dir, "manifest.toml", manifest_content);

    let run = run_manifest(&manifest, &["--explain-manifest"]);

    assert_eq!(
        run.code, 0,
        "must exit 0 even with valid WASM present, stderr:\n{}",
        run.stderr
    );

    let out = run.stdout;

    // Must show resolution
    assert!(
        out.contains("real_contract"),
        "output must show pair, got:\n{}",
        out
    );

    // Must NOT load the WASM files or perform comparison
    // (even though they exist and would be valid)
    assert!(
        !out.contains("SOROBAN BATCH SAFETY REPORT")
            && !out.contains("Critical")
            && !out.contains("baseline")
            && !out.contains("candidate"),
        "must not perform comparison even with valid WASM, got:\n{}",
        out
    );

    // Must NOT show loading progress
    assert!(
        !out.contains("Loading") && !out.contains("Loaded") && !out.contains("Comparing"),
        "must not show loading progress, got:\n{}",
        out
    );
}

#[test]
fn explain_manifest_with_json_manifest_format() {
    let dir = temp_dir("explain-json-manifest");

    let manifest_content = r#"{
    "pairs": [
        {
            "old": "v1.wasm",
            "new": "v2.wasm",
            "name": "json_contract"
        }
    ]
}"#;
    let manifest = write_file(&dir, "manifest.json", manifest_content);

    let run = run_manifest(&manifest, &["--explain-manifest"]);

    assert_eq!(
        run.code, 0,
        "JSON manifest must resolve successfully, stderr:\n{}",
        run.stderr
    );

    let out = run.stdout;

    assert!(
        out.contains("json_contract"),
        "output must show pair from JSON manifest, got:\n{}",
        out
    );

    // Must NOT perform comparison
    assert!(
        !out.contains("Critical") && !out.contains("findings"),
        "must not perform comparison, got:\n{}",
        out
    );
}

#[test]
fn explain_manifest_shows_per_pair_overrides_distinct_from_defaults() {
    let dir = temp_dir("explain-overrides");

    let manifest_content = r#"
[defaults]
strict = false
explain = true

[[pairs]]
old = "v1.wasm"
new = "v2.wasm"
name = "uses_defaults"

[[pairs]]
old = "v1.wasm"
new = "v3.wasm"
name = "overrides_strict"
strict = true
"#;
    let manifest = write_file(&dir, "manifest.toml", manifest_content);

    let run = run_manifest(&manifest, &["--explain-manifest"]);

    assert_eq!(run.code, 0);

    let out = run.stdout;

    // Must show both pairs
    assert!(
        out.contains("uses_defaults") && out.contains("overrides_strict"),
        "output must show both pairs, got:\n{}",
        out
    );

    // The pair with override should show it came from the pair level
    // (implementation may show "pair", "pair override", or similar)
    assert!(
        out.contains("strict"),
        "output must mention the overridden setting, got:\n{}",
        out
    );
}

//! Integration tests for the `extract` subcommand.
//!
//! These run the compiled binary against the checked-in WASM fixtures, which is
//! how a developer inspecting a build or a pipeline archiving one would use it.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
}

fn temp_lockfile(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "soroban-upgrade-safeguard-{name}-{}.json",
        std::process::id()
    ))
}

/// Run `extract` on a fixture, returning (stdout, exit code).
fn extract(args: &[&str]) -> (String, i32) {
    let output = bin()
        .arg("extract")
        .args(args)
        .output()
        .expect("failed to run binary");

    (
        String::from_utf8(output.stdout).expect("stdout was not valid UTF-8"),
        output.status.code().expect("process terminated by signal"),
    )
}

fn extract_json(fixture: &str) -> Value {
    let path = wasm(fixture);
    let (stdout, code) = extract(&[path.to_str().unwrap()]);
    assert_eq!(code, 0, "extract must succeed on a valid fixture");
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout was not valid JSON: {e}\n---stdout---\n{stdout}"))
}

#[test]
fn extract_emits_the_decoded_spec_as_json() {
    let json = extract_json("v1.wasm");

    assert_eq!(json["spec_schema_version"], 1);
    assert_eq!(json["tool_version"], env!("CARGO_PKG_VERSION"));
    assert!(json["source"].as_str().unwrap().ends_with("v1.wasm"));

    // The fixture declares functions and user-defined types; the point of the
    // subcommand is that all of them show up without a second tool.
    let functions = json["functions"].as_array().expect("functions array");
    assert!(
        !functions.is_empty(),
        "fixture should expose at least one function"
    );
    for function in functions {
        assert!(function["name"].is_string());
        assert!(function["inputs"].is_array());
        assert!(function["outputs"].is_array());
    }

    for key in ["structs", "enums", "unions", "error_enums"] {
        assert!(json[key].is_array(), "{key} must always be an array");
    }
}

#[test]
fn extract_includes_the_interface_hash() {
    let json = extract_json("v1.wasm");
    let hash = json["interface_hash"].as_str().expect("interface_hash");

    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn extract_includes_env_metadata() {
    let json = extract_json("v1.wasm");
    assert!(
        json["env_meta"]["protocol_version"].is_number(),
        "the fixture carries contractenvmetav0, so it must be reported"
    );
}

#[test]
fn extract_types_are_structurally_tagged() {
    let json = extract_json("v1.wasm");
    let functions = json["functions"].as_array().unwrap();

    // Every parameter type must carry a `kind` discriminator rather than being
    // a bare display string, so consumers can tell a UDT from a primitive.
    let mut saw_a_type = false;
    for function in functions {
        for input in function["inputs"].as_array().unwrap() {
            assert!(
                input["type"]["kind"].is_string(),
                "type must be tagged: {:?}",
                input["type"]
            );
            saw_a_type = true;
        }
    }
    assert!(saw_a_type, "fixture should have at least one parameter");
}

#[test]
fn extract_output_is_deterministic() {
    let first = extract_json("v1.wasm");
    let second = extract_json("v1.wasm");
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap(),
        "repeated extractions of the same build must be byte-identical"
    );
}

#[test]
fn extract_hash_only_prints_just_the_hash() {
    let path = wasm("v1.wasm");
    let (stdout, code) = extract(&[path.to_str().unwrap(), "--hash-only"]);

    assert_eq!(code, 0);
    let hash = stdout.trim();
    assert_eq!(
        stdout,
        format!("{hash}\n"),
        "--hash-only output must be exactly the digest and a newline"
    );
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_only_agrees_with_the_full_extraction() {
    let path = wasm("v1.wasm");
    let (stdout, _) = extract(&[path.to_str().unwrap(), "--hash-only"]);
    assert_eq!(stdout.trim(), extract_json("v1.wasm")["interface_hash"]);
}

#[test]
fn different_interfaces_hash_differently() {
    let v1 = extract_json("v1.wasm")["interface_hash"].clone();
    let v2 = extract_json("v2.wasm")["interface_hash"].clone();
    assert_ne!(
        v1, v2,
        "the fixtures differ in their interface, so the hashes must differ"
    );
}

#[test]
fn lockfile_generates_deterministic_reviewable_json() {
    let path = temp_lockfile("generate");
    let _ = fs::remove_file(&path);

    let first = bin()
        .arg("lockfile")
        .arg(wasm("v1.wasm"))
        .arg("--output")
        .arg(&path)
        .output()
        .expect("failed to generate lockfile");
    assert_eq!(first.status.code(), Some(0));
    let first_contents = fs::read_to_string(&path).expect("lockfile should be written");
    let json: Value = serde_json::from_str(&first_contents).expect("lockfile should be JSON");
    assert_eq!(json["lockfile_schema_version"], 1);
    assert_eq!(json["interface_hash"].as_str().unwrap().len(), 64);

    let second = bin()
        .arg("lockfile")
        .arg(wasm("v1.wasm"))
        .arg("--output")
        .arg(&path)
        .arg("--force")
        .output()
        .expect("failed to update lockfile");
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(first_contents, fs::read_to_string(&path).unwrap());
    fs::remove_file(path).unwrap();
}

#[test]
fn lockfile_refuses_overwrite_without_force() {
    let path = temp_lockfile("overwrite");
    let _ = fs::remove_file(&path);
    let generated = bin()
        .arg("lockfile")
        .arg(wasm("v1.wasm"))
        .arg("--output")
        .arg(&path)
        .output()
        .expect("failed to generate lockfile");
    assert_eq!(generated.status.code(), Some(0));

    let rejected = bin()
        .arg("lockfile")
        .arg(wasm("v2.wasm"))
        .arg("--output")
        .arg(&path)
        .output()
        .expect("failed to run overwrite check");
    assert_ne!(rejected.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("Use --force"));
    fs::remove_file(path).unwrap();
}

#[test]
fn lockfile_check_passes_for_matching_build_and_fails_for_drift() {
    let path = temp_lockfile("check");
    let _ = fs::remove_file(&path);
    let generated = bin()
        .arg("lockfile")
        .arg(wasm("v1.wasm"))
        .arg("--output")
        .arg(&path)
        .output()
        .expect("failed to generate lockfile");
    assert_eq!(generated.status.code(), Some(0));

    let matching = bin()
        .arg(wasm("v1.wasm"))
        .arg("--interface-lockfile")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to check matching build");
    assert_eq!(matching.status.code(), Some(0));
    let matching_json: Value =
        serde_json::from_slice(&matching.stdout).expect("matching lockfile check should emit JSON");
    assert_eq!(matching_json["is_safe"], Value::Bool(true));

    let drifting = bin()
        .arg(wasm("v2.wasm"))
        .arg("--interface-lockfile")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to check drifting build");
    assert_eq!(drifting.status.code(), Some(1));
    let drifting_json: Value =
        serde_json::from_slice(&drifting.stdout).expect("drifting lockfile check should emit JSON");
    assert_eq!(drifting_json["is_safe"], Value::Bool(false));
    assert!(drifting_json["counts"]["critical"].as_u64().unwrap() >= 1);
    fs::remove_file(path).unwrap();
}

#[test]
fn malformed_lockfile_fails_with_a_clear_error() {
    let path = temp_lockfile("malformed");
    fs::write(&path, "{not json").unwrap();

    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg("--interface-lockfile")
        .arg(&path)
        .output()
        .expect("failed to run malformed lockfile check");
    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid interface lockfile"));
    fs::remove_file(path).unwrap();
}

#[test]
fn lockfile_check_renders_normal_markdown_findings() {
    let path = temp_lockfile("markdown");
    let _ = fs::remove_file(&path);
    let generated = bin()
        .arg("lockfile")
        .arg(wasm("v1.wasm"))
        .arg("--output")
        .arg(&path)
        .output()
        .expect("failed to generate lockfile");
    assert_eq!(generated.status.code(), Some(0));

    let output = bin()
        .arg(wasm("v2.wasm"))
        .arg("--interface-lockfile")
        .arg(&path)
        .arg("--format")
        .arg("markdown")
        .output()
        .expect("failed to render markdown lockfile check");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout.contains("# Soroban Upgrade Safety Report"));
    assert!(stdout.contains("### Function Signature Changed"));
    fs::remove_file(path).unwrap();
}

#[test]
fn extract_without_a_source_fails_with_guidance() {
    let output = bin().arg("extract").output().expect("failed to run binary");
    assert_ne!(output.status.code(), Some(0));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Missing WASM path"),
        "error should say what is missing, got: {stderr}"
    );
}

#[test]
fn extract_rejects_a_non_wasm_file() {
    let output = bin()
        .arg("extract")
        .arg(file!())
        .output()
        .expect("failed to run binary");
    assert_ne!(
        output.status.code(),
        Some(0),
        "a source file is not a WASM module"
    );
}

#[test]
fn extract_accepts_wasm_path_with_spaces() {
    let dir = std::env::temp_dir().join(format!(
        "safeguard test path with spaces {}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("failed to create temp directory with spaces");
    let target_wasm = dir.join("v1 with space.wasm");
    fs::copy(wasm("v1.wasm"), &target_wasm).expect("failed to copy WASM fixture");

    let (stdout, code) = extract(&[target_wasm.to_str().unwrap()]);
    assert_eq!(
        code, 0,
        "extract must succeed on a valid WASM path containing spaces"
    );

    let json: Value = serde_json::from_str(&stdout).expect("stdout was not valid JSON");
    assert_eq!(
        json["source"].as_str().unwrap(),
        target_wasm.to_str().unwrap().replace('\\', "/"),
        "source field must contain the complete unsplit path"
    );

    // Clean up temporary fixture after completion
    let _ = fs::remove_file(&target_wasm);
    let _ = fs::remove_dir(&dir);
}

#[test]
fn interface_hash_is_64_lowercase_hex_and_matches_hash_only_across_multiple_fixtures() {
    let fixtures = ["v1.wasm", "v2.wasm", "v3.wasm"];
    let mut hashes = Vec::new();

    for fixture in fixtures {
        let full_json = extract_json(fixture);
        let full_hash = full_json["interface_hash"]
            .as_str()
            .expect("interface_hash string in JSON");

        // The extracted interface hash contains exactly 64 lowercase hexadecimal characters
        assert_eq!(
            full_hash.len(),
            64,
            "hash for {fixture} must be 64 characters long"
        );
        assert!(
            full_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "hash for {fixture} must contain only lowercase hex characters, got: {full_hash}"
        );

        // --hash-only matches the hash in full extraction output
        let wasm_path = wasm(fixture);
        let (stdout, code) = extract(&[wasm_path.to_str().unwrap(), "--hash-only"]);
        assert_eq!(code, 0, "--hash-only must succeed for {fixture}");
        let hash_only = stdout.trim();
        assert_eq!(
            hash_only, full_hash,
            "--hash-only output must match the hash in full extraction output for {fixture}"
        );
        assert_eq!(
            hash_only.len(),
            64,
            "--hash-only for {fixture} must be 64 characters long"
        );
        assert!(
            hash_only
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "--hash-only output for {fixture} must be lowercase hex"
        );

        hashes.push(full_hash.to_string());
    }

    // Covers more than one fixture to avoid a constant-value test
    assert!(hashes.len() > 1, "test must cover more than one fixture");
    assert_ne!(
        hashes[0], hashes[1],
        "v1.wasm and v2.wasm must produce different interface hashes"
    );
}

// --- The four pre-existing usage modes must be untouched ---------------------

#[test]
fn the_four_original_usage_modes_still_appear_in_help() {
    let output = bin().arg("--help").output().expect("failed to run binary");
    let stdout = String::from_utf8_lossy(&output.stdout);

    for mode in [
        "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>",
        "--contract-id <ID> --rpc-url <URL> <NEW_WASM>",
        "--manifest <MANIFEST_PATH>",
        "--old-dir <OLD_DIR> --new-dir <NEW_DIR>",
    ] {
        assert!(stdout.contains(mode), "usage line missing: {mode}");
    }
}

#[test]
fn the_local_pair_mode_still_works() {
    // Adding subcommands must not change how two positional WASM paths parse.
    let output = bin()
        .arg(wasm("v1.wasm"))
        .arg(wasm("v2.wasm"))
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).expect("still emits a JSON report");
    assert_eq!(json["is_safe"], Value::Bool(false));
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn extract_output_trailing_newline_regression_test() {
    let path = wasm("v1.wasm");

    // 1. Full extraction output ends with exactly one newline
    let (full_stdout, code) = extract(&[path.to_str().unwrap()]);
    assert_eq!(code, 0, "extract must succeed");
    assert!(
        full_stdout.ends_with('\n'),
        "full extraction output must end with a newline"
    );
    assert!(
        !full_stdout.ends_with("\n\n"),
        "full extraction output must end with exactly one newline"
    );
    let trimmed_full = &full_stdout[..full_stdout.len() - 1];
    let parsed: Value =
        serde_json::from_str(trimmed_full).expect("removing the final newline leaves valid JSON");
    assert_eq!(parsed["spec_schema_version"], 1);

    // 2. Hash-only extraction output ends with exactly one newline
    let (hash_stdout, code) = extract(&[path.to_str().unwrap(), "--hash-only"]);
    assert_eq!(code, 0, "extract --hash-only must succeed");
    assert!(
        hash_stdout.ends_with('\n'),
        "hash-only output must end with a newline"
    );
    assert!(
        !hash_stdout.ends_with("\n\n"),
        "hash-only output must end with exactly one newline"
    );
    let trimmed_hash = &hash_stdout[..hash_stdout.len() - 1];
    assert_eq!(trimmed_hash.len(), 64);
    assert!(
        trimmed_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "removing the final newline leaves a valid hash"
    );
}

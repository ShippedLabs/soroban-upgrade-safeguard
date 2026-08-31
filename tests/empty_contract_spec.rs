//! Regression coverage for empty contract spec section diagnostics.
//!
//! A present but empty contractspecv0 section is different from a section
//! that is absent. This test verifies that the parser detects this condition
//! and provides a clear diagnostic message.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_dir(name: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{}-{}-{}", name, std::process::id(), id));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

/// Build a minimal WASM module with a present but empty contractspecv0
/// custom section (zero bytes of section data).
fn minimal_wasm_with_empty_contractspec() -> Vec<u8> {
    // WASM header: magic + version
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    // Custom section (id=0): contractspecv0 with zero bytes of data
    let section_name = b"contractspecv0";
    let section_size = 1 + section_name.len(); // name length byte + name
    wasm.push(0); // section id: custom
    wasm.push(section_size as u8); // section size
    wasm.push(section_name.len() as u8); // name length
    wasm.extend_from_slice(section_name); // name
                                          // No data bytes follow — this is the empty section

    wasm
}

/// Build a minimal WASM module with no contractspecv0 section at all.
fn minimal_wasm_without_contractspec() -> Vec<u8> {
    // WASM header: magic + version
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run_comparison(old: &[u8], new: &[u8]) -> Run {
    let dir = temp_dir("empty-spec-test");
    let old_path = dir.join("old.wasm");
    let new_path = dir.join("new.wasm");

    std::fs::write(&old_path, old).expect("failed to write old.wasm");
    std::fs::write(&new_path, new).expect("failed to write new.wasm");

    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(&old_path)
        .arg(&new_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run binary");

    Run {
        stdout: String::from_utf8(output.stdout).expect("stdout not utf8"),
        stderr: String::from_utf8(output.stderr).expect("stderr not utf8"),
        code: output.status.code().expect("process killed by signal"),
    }
}

#[test]
fn empty_contractspec_section_produces_diagnostic() {
    let old = minimal_wasm_with_empty_contractspec();
    let new = minimal_wasm_with_empty_contractspec();

    let run = run_comparison(&old, &new);

    // The comparison should succeed (both empty interfaces match)
    assert_eq!(
        run.code, 0,
        "empty spec comparison must exit 0, stderr:\n{}",
        run.stderr
    );

    // stderr must contain the diagnostic for empty spec section
    assert!(
        run.stderr
            .contains("contractspecv0 section is present but empty"),
        "diagnostic must explain the empty section, stderr:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("no spec entries"),
        "diagnostic must mention no entries, stderr:\n{}",
        run.stderr
    );
}

#[test]
fn missing_contractspec_section_does_not_produce_empty_diagnostic() {
    let old = minimal_wasm_without_contractspec();
    let new = minimal_wasm_without_contractspec();

    let run = run_comparison(&old, &new);

    // The comparison should succeed (no spec to compare)
    assert_eq!(
        run.code, 0,
        "no-spec comparison must exit 0, stderr:\n{}",
        run.stderr
    );

    // stderr must NOT contain the empty section diagnostic (section is absent)
    assert!(
        !run.stderr
            .contains("contractspecv0 section is present but empty"),
        "missing section must not trigger empty-section diagnostic, stderr:\n{}",
        run.stderr
    );
}

#[test]
fn empty_spec_distinguishes_from_valid_nonempty_spec() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm");
    let valid_wasm_path = dir.join("v1.wasm");

    // v1.wasm has a valid non-empty spec
    let valid_wasm = std::fs::read(&valid_wasm_path).expect("v1.wasm fixture must exist");

    let empty_wasm = minimal_wasm_with_empty_contractspec();

    let run = run_comparison(&valid_wasm, &empty_wasm);

    // This comparison should fail (functions removed)
    assert_ne!(
        run.code, 0,
        "valid -> empty must detect breaking changes, stderr:\n{}",
        run.stderr
    );

    // stderr should contain the empty section diagnostic for new
    assert!(
        run.stderr
            .contains("contractspecv0 section is present but empty"),
        "empty section diagnostic must appear for the new WASM, stderr:\n{}",
        run.stderr
    );

    // stdout should contain the comparison findings
    let json: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("output must be valid JSON");
    assert_eq!(json["is_safe"], false);
    assert!(
        json["total_findings"].as_u64().unwrap_or(0) > 0,
        "comparison must report removed functions"
    );
}

fn extract_contractspec_bytes() -> Vec<u8> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm");
    let valid_wasm_path = dir.join("v1.wasm");
    let wasm = std::fs::read(&valid_wasm_path).expect("v1.wasm fixture must exist");

    for payload in wasmparser::Parser::new(0).parse_all(&wasm) {
        if let wasmparser::Payload::CustomSection(section) = payload.expect("valid wasm payload") {
            if section.name() == "contractspecv0" {
                return section.data().to_vec();
            }
        }
    }
    panic!("v1.wasm must contain contractspecv0 section");
}

fn wasm_with_custom_section(name: &str, data: &[u8]) -> Vec<u8> {
    let mut section_content = Vec::new();
    section_content.push(name.len() as u8);
    section_content.extend_from_slice(name.as_bytes());
    section_content.extend_from_slice(data);

    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    wasm.push(0); // custom section
    let mut val = section_content.len();
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            wasm.push(byte);
            break;
        } else {
            wasm.push(byte | 0x80);
        }
    }
    wasm.extend(section_content);
    wasm
}

#[test]
fn empty_to_nonempty_spec_is_a_valid_upgrade() {
    let spec_bytes = extract_contractspec_bytes();
    let empty_wasm = minimal_wasm_with_empty_contractspec();
    let nonempty_wasm = wasm_with_custom_section("contractspecv0", &spec_bytes);

    let run = run_comparison(&empty_wasm, &nonempty_wasm);

    // Adding functions to an empty interface is safe
    assert_eq!(
        run.code, 0,
        "empty -> valid (adding functions) must exit 0, stdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );

    // stderr should contain the empty section diagnostic for old
    assert!(
        run.stderr
            .contains("contractspecv0 section is present but empty"),
        "empty section diagnostic must appear for the old WASM, stderr:\n{}",
        run.stderr
    );

    let json: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("output must be valid JSON");
    assert_eq!(json["is_safe"], true);
}

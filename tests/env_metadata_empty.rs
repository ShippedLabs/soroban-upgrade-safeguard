//! Regression coverage distinguishing a missing `contractenvmetav0` section
//! from a present-but-empty one, at the whole-report level. See
//! `src/parser.rs` and `src/diff.rs` for the equivalent decode/compare unit
//! coverage; these tests exercise the same distinction through the public
//! `compare_wasm_bytes_with_options` entry point, including the
//! `AnalysisScope` bookkeeping that downstream renderers rely on to describe
//! what was actually analyzed.

use soroban_upgrade_safeguard::{compare_wasm_bytes_with_options, CompareOptions};

fn uleb(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

fn wasm_string(s: &str) -> Vec<u8> {
    let mut out = uleb(s.len() as u32);
    out.extend_from_slice(s.as_bytes());
    out
}

fn wasm_section(id: u8, body: Vec<u8>) -> Vec<u8> {
    let mut out = vec![id];
    out.extend(uleb(body.len() as u32));
    out.extend(body);
    out
}

/// A minimal valid WASM module with no sections beyond the header.
fn wasm_without_env_meta_section() -> Vec<u8> {
    Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])
}

/// A minimal WASM module carrying a `contractenvmetav0` custom section with
/// zero bytes of data: present, valid, and empty.
fn wasm_with_empty_env_meta_section() -> Vec<u8> {
    let mut wasm = wasm_without_env_meta_section();
    let custom_body = wasm_string("contractenvmetav0");
    wasm.extend(wasm_section(0, custom_body));
    wasm
}

#[test]
fn scope_env_metadata_is_false_when_neither_side_has_a_section() {
    let old = wasm_without_env_meta_section();
    let new = wasm_without_env_meta_section();

    let report = compare_wasm_bytes_with_options(&old, &new, &CompareOptions::default())
        .expect("comparison of minimal modules should succeed");

    assert!(
        !report.scope().env_metadata,
        "scope must not claim env metadata was analyzed when no section exists on either side"
    );
    assert!(
        !report
            .findings_by_category()
            .contains_key(soroban_upgrade_safeguard::diff::ENVIRONMENT_CATEGORY),
        "no section on either side must never produce an Environment finding"
    );
}

#[test]
fn scope_env_metadata_is_true_when_a_present_but_empty_section_exists() {
    let old = wasm_without_env_meta_section();
    let new = wasm_with_empty_env_meta_section();

    let report = compare_wasm_bytes_with_options(&old, &new, &CompareOptions::default())
        .expect("comparison of minimal modules should succeed");

    assert!(
        report.scope().env_metadata,
        "scope must record that env metadata was analyzed once a section is present, even if empty"
    );
}

#[test]
fn matching_empty_env_meta_sections_on_both_sides_is_a_safe_legacy_artifact() {
    // Two builds that both emit an empty `contractenvmetav0` section (an
    // older toolchain behavior) must compare cleanly: no findings, no
    // failure, and the scope must still honestly report that a section was
    // present.
    let old = wasm_with_empty_env_meta_section();
    let new = wasm_with_empty_env_meta_section();

    let report = compare_wasm_bytes_with_options(&old, &new, &CompareOptions::default())
        .expect("comparison of minimal modules should succeed");

    assert!(report.is_safe());
    assert!(report.scope().env_metadata);
    assert!(
        !report
            .findings_by_category()
            .contains_key(soroban_upgrade_safeguard::diff::ENVIRONMENT_CATEGORY),
        "identical empty sections on both sides must not be reported as a change"
    );
}

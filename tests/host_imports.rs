//! Integration coverage for host-import protocol capability classification.
//!
//! These hand-craft minimal WASM modules (a type section, an import
//! section, and an optional `contractenvmetav0` custom section) rather than
//! reusing the checked-in fixtures under `tests/wasm/`: those fixtures all
//! import the exact same single host function across every version, so they
//! never naturally exercise a newly-required, removed, unknown, or
//! protocol-boundary-crossing import. See `src/capability.rs` for where the
//! `(module, name)` wire codes used below come from.

use std::io::Cursor;

use stellar_xdr::curr::{Limited, Limits, ScEnvMetaEntry, WriteXdr};

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

fn encode_interface_version(protocol: u32, pre_release: u32) -> Vec<u8> {
    let version = ((protocol as u64) << 32) | (pre_release as u64);
    let entry = ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(version);
    let cursor = Cursor::new(Vec::new());
    let mut limited = Limited::new(cursor, Limits::none());
    entry.write_xdr(&mut limited).unwrap();
    limited.inner.into_inner()
}

/// A minimal WASM module declaring `imports` as `(module, name)` function
/// imports (all sharing a trivial `() -> ()` type), plus an optional
/// declared Soroban protocol version in a `contractenvmetav0` section.
fn wasm_module(imports: &[(&str, &str)], protocol: Option<u32>) -> Vec<u8> {
    let mut type_body = uleb(1);
    type_body.push(0x60); // func type tag
    type_body.extend(uleb(0)); // 0 params
    type_body.extend(uleb(0)); // 0 results

    let mut import_body = uleb(imports.len() as u32);
    for &(module, name) in imports {
        import_body.extend(wasm_string(module));
        import_body.extend(wasm_string(name));
        import_body.push(0x00); // external kind: func
        import_body.extend(uleb(0)); // type index 0
    }

    let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    wasm.extend(wasm_section(1, type_body));
    wasm.extend(wasm_section(2, import_body));
    if let Some(protocol) = protocol {
        let mut custom_body = wasm_string("contractenvmetav0");
        custom_body.extend(encode_interface_version(protocol, 0));
        wasm.extend(wasm_section(0, custom_body));
    }
    wasm
}

fn category_present(report: &soroban_upgrade_safeguard::SafetyReport, category: &str) -> bool {
    report
        .findings_by_category()
        .get(category)
        .is_some_and(|findings| !findings.is_empty())
}

#[test]
fn unrecognized_import_is_surfaced_and_never_assigned_a_protocol() {
    let old = wasm_module(&[], None);
    let new = wasm_module(&[("z", "mystery_provider_hook")], None);

    let report = compare_wasm_bytes_with_options(&old, &new, &CompareOptions::default())
        .expect("comparison of minimal modules should succeed");

    assert!(
        category_present(&report, "Unknown Host Import"),
        "an unrecognized import must be surfaced, not silently dropped"
    );
    assert!(
        !category_present(&report, "Protocol Requirement Raised"),
        "an unrecognized import must never imply a protocol requirement"
    );
    assert!(!category_present(&report, "Host Import Added"));

    let finding = &report.findings_by_category()["Unknown Host Import"][0];
    assert_eq!(finding.finding().target(), Some("z::mystery_provider_hook"));
}

#[test]
fn crossing_a_protocol_boundary_is_reported() {
    // "l"/"_" (put_contract_data) has been available since the Soroban
    // baseline protocol (20). "c"/"3" (verify_sig_ecdsa_secp256r1) requires
    // protocol 21+.
    let old = wasm_module(&[("l", "_")], None);
    let new = wasm_module(&[("l", "_"), ("c", "3")], None);

    let report = compare_wasm_bytes_with_options(&old, &new, &CompareOptions::default())
        .expect("comparison of minimal modules should succeed");

    assert!(category_present(&report, "Host Import Added"));
    assert!(category_present(&report, "Protocol Requirement Raised"));

    let finding = &report.findings_by_category()["Protocol Requirement Raised"][0];
    assert!(finding.finding().message().contains("20"));
    assert!(finding.finding().message().contains("21"));
}

#[test]
fn removing_a_recognized_capability_is_informational_only() {
    let old = wasm_module(&[("l", "_"), ("c", "3")], None);
    let new = wasm_module(&[("l", "_")], None);

    let report = compare_wasm_bytes_with_options(&old, &new, &CompareOptions::default())
        .expect("comparison of minimal modules should succeed");

    assert!(category_present(&report, "Host Import Removed"));
    let finding = &report.findings_by_category()["Host Import Removed"][0];
    assert_eq!(
        *finding.finding().severity(),
        soroban_upgrade_safeguard::Severity::Info
    );
    assert!(!category_present(&report, "Protocol Requirement Raised"));
}

#[test]
fn declared_protocol_below_required_capability_is_flagged_critical() {
    // Declares protocol 20 but imports a protocol-21 capability.
    let old = wasm_module(&[], Some(20));
    let new = wasm_module(&[("c", "3")], Some(20));

    let report = compare_wasm_bytes_with_options(&old, &new, &CompareOptions::default())
        .expect("comparison of minimal modules should succeed");

    assert!(category_present(&report, "Protocol Environment Mismatch"));
    let finding = &report.findings_by_category()["Protocol Environment Mismatch"][0];
    assert_eq!(
        *finding.finding().severity(),
        soroban_upgrade_safeguard::Severity::Critical
    );
}

#[test]
fn declared_protocol_meeting_required_capability_is_not_flagged() {
    let old = wasm_module(&[], Some(21));
    let new = wasm_module(&[("c", "3")], Some(21));

    let report = compare_wasm_bytes_with_options(&old, &new, &CompareOptions::default())
        .expect("comparison of minimal modules should succeed");

    assert!(!category_present(&report, "Protocol Environment Mismatch"));
}

#[test]
fn identical_imports_produce_no_host_import_findings() {
    let module = wasm_module(&[("l", "_"), ("z", "custom")], Some(21));

    let report = compare_wasm_bytes_with_options(&module, &module, &CompareOptions::default())
        .expect("comparison of minimal modules should succeed");

    for category in [
        "Host Import Added",
        "Host Import Removed",
        "Host Import Signature Changed",
        "Unknown Host Import",
        "Protocol Requirement Raised",
        "Protocol Environment Mismatch",
    ] {
        assert!(
            !category_present(&report, category),
            "identical builds must not produce a {category} finding"
        );
    }
}

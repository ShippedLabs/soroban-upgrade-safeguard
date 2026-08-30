//! Integration tests for the public library API.
//!
//! Unlike `json_output.rs`, these never spawn the CLI binary — they link the
//! library crate directly and call the top-level comparison helpers, proving
//! the core loading/parsing/diffing logic is reusable by external Rust tools.

use std::path::PathBuf;

use soroban_upgrade_safeguard::diff::{compare, Severity};
use soroban_upgrade_safeguard::report::SafetyReport;
use soroban_upgrade_safeguard::spec::ContractSpec;
use soroban_upgrade_safeguard::{compare_wasm_bytes, compare_wasm_files};
use stellar_xdr::curr::{
    ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtStructFieldV0, ScSpecUdtStructV0, StringM, VecM,
};

/// Absolute path to a fixture WASM under `tests/wasm/`.
fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn library_detects_breaking_upgrade_from_files() {
    let report = compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm"))
        .expect("comparison should succeed on valid fixtures");

    assert!(!report.is_safe, "v1 -> v2 must be flagged as unsafe");
    assert!(
        report.critical_count >= 1,
        "v1 -> v2 must report at least one critical finding"
    );
    assert_eq!(
        report.total_findings,
        report.critical_count + report.warning_count + report.info_count,
        "total findings must equal the sum of severity counts"
    );
}

#[test]
fn library_identical_upgrade_is_safe_from_files() {
    let report = compare_wasm_files(&wasm("v1.wasm"), &wasm("v1.wasm"))
        .expect("comparison should succeed on valid fixtures");

    assert!(report.is_safe, "identical builds must be safe");
    assert_eq!(
        report.critical_count, 0,
        "identical builds have no criticals"
    );
}

#[test]
fn library_compares_in_memory_bytes() {
    let old = std::fs::read(wasm("v1.wasm")).expect("read v1 fixture");
    let new = std::fs::read(wasm("v2.wasm")).expect("read v2 fixture");

    let report =
        compare_wasm_bytes(&old, &new).expect("comparison should succeed on in-memory bytes");

    assert!(!report.is_safe);
    assert!(report.critical_count >= 1);

    // The byte-slice and file-path entry points must agree.
    let from_files = compare_wasm_files(&wasm("v1.wasm"), &wasm("v2.wasm")).unwrap();
    assert_eq!(report.critical_count, from_files.critical_count);
    assert_eq!(report.total_findings, from_files.total_findings);
}

#[test]
fn library_detects_parameter_reordering() {
    use soroban_upgrade_safeguard::diff::{compare, Severity};
    use soroban_upgrade_safeguard::spec::ContractSpec;
    use stellar_xdr::curr::{
        ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, StringM, VecM,
    };

    let mut old_spec = ContractSpec::default();
    let old_inputs = vec![
        ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: "a".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
        ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: "b".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
    ];
    old_spec.functions.insert(
        "test_fn".to_string(),
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "test_fn".try_into().unwrap(),
            inputs: VecM::try_from(old_inputs).unwrap(),
            outputs: VecM::default(),
        },
    );

    let mut new_spec = ContractSpec::default();
    let new_inputs = vec![
        ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: "b".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
        ScSpecFunctionInputV0 {
            doc: StringM::default(),
            name: "a".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
    ];
    new_spec.functions.insert(
        "test_fn".to_string(),
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "test_fn".try_into().unwrap(),
            inputs: VecM::try_from(new_inputs).unwrap(),
            outputs: VecM::default(),
        },
    );

    let diff_report = compare(&old_spec, &new_spec);
    let reorder_finding = diff_report
        .findings
        .iter()
        .find(|f| f.category == "Parameter Reordered");

    assert!(
        reorder_finding.is_some(),
        "Integration: Expected a Parameter Reordered finding"
    );
    let f = reorder_finding.unwrap();
    assert_eq!(f.severity, Severity::Critical);
}

#[test]
fn library_unicode_function_name_renders_correctly() {
    let mut old_spec = ContractSpec::default();
    old_spec.functions.insert(
        "関数".to_string(),
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "関数".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        },
    );

    let new_spec = ContractSpec::default();

    let diff_report = compare(&old_spec, &new_spec);
    let removal = diff_report
        .findings
        .iter()
        .find(|f| f.category == "Function Removed");

    assert!(removal.is_some(), "Expected a Function Removed finding");
    let finding = removal.unwrap();
    assert_eq!(finding.severity, Severity::Critical);
    assert!(
        finding.message.contains("関数"),
        "Finding message must contain the Unicode function name"
    );

    let report = SafetyReport::new(&diff_report);

    let text = report.generate_summary_text(false);
    assert!(
        String::from_utf8(text.as_bytes().to_vec()).is_ok(),
        "text output must be valid UTF-8"
    );
    assert!(
        text.contains("関数"),
        "text output must preserve the Unicode function name"
    );

    let markdown = report.generate_summary_markdown();
    assert!(
        String::from_utf8(markdown.as_bytes().to_vec()).is_ok(),
        "markdown output must be valid UTF-8"
    );
    assert!(
        markdown.contains("関数"),
        "markdown output must preserve the Unicode function name"
    );

    let json = report.to_json();
    let json_str = serde_json::to_string(&json).expect("JSON serialization must not fail");
    assert!(
        String::from_utf8(json_str.as_bytes().to_vec()).is_ok(),
        "JSON output must be valid UTF-8"
    );
    assert!(
        json_str.contains("関数"),
        "JSON output must preserve the Unicode function name"
    );
}

#[test]
fn library_unicode_struct_field_renders_correctly() {
    let mut old_spec = ContractSpec::default();
    let fields = vec![ScSpecUdtStructFieldV0 {
        doc: StringM::default(),
        name: "フィールド".try_into().unwrap(),
        type_: ScSpecTypeDef::U32,
    }];
    old_spec.structs.insert(
        "データ".to_string(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "データ".try_into().unwrap(),
            fields: VecM::try_from(fields).unwrap(),
        },
    );

    let mut new_spec = ContractSpec::default();
    let empty_fields: Vec<ScSpecUdtStructFieldV0> = Vec::new();
    new_spec.structs.insert(
        "データ".to_string(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "データ".try_into().unwrap(),
            fields: VecM::try_from(empty_fields).unwrap(),
        },
    );

    let diff_report = compare(&old_spec, &new_spec);
    let removal = diff_report
        .findings
        .iter()
        .find(|f| f.category == "Struct Field Removed");

    assert!(removal.is_some(), "Expected a Struct Field Removed finding");
    let finding = removal.unwrap();
    assert!(
        finding.message.contains("データ") || finding.message.contains("フィールド"),
        "Finding message must contain the Unicode struct or field name"
    );

    let report = SafetyReport::new(&diff_report);

    let text = report.generate_summary_text(false);
    assert!(
        String::from_utf8(text.as_bytes().to_vec()).is_ok(),
        "text output must be valid UTF-8"
    );
    assert!(
        text.contains("データ") || text.contains("フィールド"),
        "text output must preserve the Unicode struct or field name"
    );

    let markdown = report.generate_summary_markdown();
    assert!(
        String::from_utf8(markdown.as_bytes().to_vec()).is_ok(),
        "markdown output must be valid UTF-8"
    );
    assert!(
        markdown.contains("データ") || markdown.contains("フィールド"),
        "markdown output must preserve the Unicode struct or field name"
    );

    let json = report.to_json();
    let json_str = serde_json::to_string(&json).expect("JSON serialization must not fail");
    assert!(
        String::from_utf8(json_str.as_bytes().to_vec()).is_ok(),
        "JSON output must be valid UTF-8"
    );
    assert!(
        json_str.contains("データ") || json_str.contains("フィールド"),
        "JSON output must preserve the Unicode struct or field name"
    );
}

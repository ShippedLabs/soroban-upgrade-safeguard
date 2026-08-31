//! Compile and integration test exercising the advanced/unstable pipeline API.
//!
//! This test is conditionalized on the `unstable` feature gate and verifies
//! that advanced users can manually link and run individual stages (loading,
//! parsing, spec generation, type mapping, diffing, and report filtering).

#![cfg(feature = "unstable")]

use std::path::PathBuf;

use soroban_upgrade_safeguard::diff::compare;
use soroban_upgrade_safeguard::loader::load_wasm;
use soroban_upgrade_safeguard::mapper::type_to_string;
use soroban_upgrade_safeguard::parser::extract_metadata;
use soroban_upgrade_safeguard::report::SafetyReport;
use soroban_upgrade_safeguard::spec::ContractSpec;

/// Resolve a test WASM fixture path.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

#[test]
fn test_custom_unstable_pipeline_flow() {
    // 1. Stage: Loader
    // Load WASM files from disk into memory and perform integrity checks.
    let old_wasm = load_wasm(&fixture("v1.wasm")).expect("Load old WASM");
    let new_wasm = load_wasm(&fixture("v2.wasm")).expect("Load new WASM");

    assert!(!old_wasm.bytes.is_empty());
    assert!(!new_wasm.bytes.is_empty());

    // 2. Stage: Parser
    // Extract raw custom sections (contractspecv0 and contractenvmetav0).
    let old_meta = extract_metadata(&old_wasm.bytes).expect("Parse old metadata");
    let new_meta = extract_metadata(&new_wasm.bytes).expect("Parse new metadata");

    // 3. Stage: Spec Generation
    // Organise the raw XDR spec entries into keyed ContractSpec structures.
    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);

    // Verify some functions are parsed
    assert!(!old_spec.functions.is_empty());
    assert!(!new_spec.functions.is_empty());

    // 4. Stage: Type Mapping / Walking
    // Walk spec type definitions to assert layout representation.
    for function in old_spec.functions.values() {
        for input in function.inputs.iter() {
            let rendered = type_to_string(&input.type_);
            assert!(!rendered.is_empty());
        }
    }

    // 5. Stage: Diffing
    // Run structural comparison between old and new specs to produce raw findings.
    let diff_report = compare(&old_spec, &new_spec);

    // 6. Stage: Safety Report
    // Aggregate raw findings and apply suppression rules into a final report.
    let safety_report = SafetyReport::new_with_specs(&diff_report, &old_spec, &new_spec);

    // Assert findings were generated from the comparison
    assert!(!safety_report.is_safe());
    assert!(safety_report.critical_count() >= 1);
}

#[test]
fn test_unstable_contract_spec_diff() {
    // 1. Setup mock old and new contract specs
    let old_spec = ContractSpec::default();
    let mut new_spec = ContractSpec::default();

    // 2. Create a mock function definition
    let func = stellar_xdr::curr::ScSpecFunctionV0 {
        doc: stellar_xdr::curr::StringM::default(),
        name: "hello".try_into().unwrap(),
        inputs: stellar_xdr::curr::VecM::default(),
        outputs: stellar_xdr::curr::VecM::default(),
    };

    new_spec.functions.insert("hello".to_string(), func);

    // 3. Run unstable comparison
    let diff_report = compare(&old_spec, &new_spec);

    assert!(!diff_report.findings.is_empty());

    let finding = &diff_report.findings[0];
    assert_eq!(finding.category(), "Function Added");
    assert_eq!(finding.target(), Some("hello"));
    assert_eq!(
        *finding.severity(),
        soroban_upgrade_safeguard::diff::Severity::Info
    );
}

#[test]
fn test_unstable_suppression_config_construction() {
    use soroban_upgrade_safeguard::suppression::{SuppressionConfig, SuppressionRule};

    let mut config = SuppressionConfig::default();

    let rule = SuppressionRule::new(
        "Function Removed",
        Some("old_fn"),
        Some("Legacy function cleanup"),
    );

    config.rules.push(rule);

    assert_eq!(config.rules().len(), 1);
    let rule_ref = &config.rules()[0];
    assert_eq!(rule_ref.category(), "Function Removed");
    assert_eq!(rule_ref.target(), Some("old_fn"));
    assert_eq!(rule_ref.reason(), Some("Legacy function cleanup"));
}

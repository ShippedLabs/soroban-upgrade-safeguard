//! Fixture-pair tests for union and error-enum diff coverage.

use soroban_upgrade_safeguard::diff::{compare, Severity};
use soroban_upgrade_safeguard::report::SafetyReport;
use soroban_upgrade_safeguard::spec::ContractSpec;
use stellar_xdr::curr::{
    ScSpecTypeDef, ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtUnionCaseTupleV0,
    ScSpecUdtUnionCaseV0, ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0, StringM, VecM,
};

fn union_spec(name: &str, cases: Vec<ScSpecUdtUnionCaseV0>) -> ContractSpec {
    let mut spec = ContractSpec::default();
    spec.unions.insert(
        name.to_string(),
        ScSpecUdtUnionV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::try_from(cases).unwrap(),
        },
    );
    spec
}

fn error_enum_spec(name: &str, cases: Vec<(&str, u32)>) -> ContractSpec {
    let mut spec = ContractSpec::default();
    let xdr_cases: Vec<ScSpecUdtErrorEnumCaseV0> = cases
        .into_iter()
        .map(|(case_name, value)| ScSpecUdtErrorEnumCaseV0 {
            doc: StringM::default(),
            name: case_name.try_into().unwrap(),
            value,
        })
        .collect();
    spec.error_enums.insert(
        name.to_string(),
        ScSpecUdtErrorEnumV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::try_from(xdr_cases).unwrap(),
        },
    );
    spec
}

#[test]
fn fixture_pair_union_variant_type_change_is_unsafe() {
    let old = union_spec(
        "PaymentAction",
        vec![ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
            doc: StringM::default(),
            name: "Pay".try_into().unwrap(),
            type_: VecM::try_from(vec![ScSpecTypeDef::U32]).unwrap(),
        })],
    );
    let new = union_spec(
        "PaymentAction",
        vec![ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
            doc: StringM::default(),
            name: "Pay".try_into().unwrap(),
            type_: VecM::try_from(vec![ScSpecTypeDef::U64]).unwrap(),
        })],
    );

    let report = compare(&old, &new);
    let safety = SafetyReport::new(&report);

    assert!(!safety.is_safe());
    assert!(report.findings.iter().any(|f| {
        *f.severity() == Severity::Critical && f.category() == "Union Case Type Changed"
    }));
}

#[test]
fn fixture_pair_new_union_variant_is_info_only() {
    let old = union_spec(
        "PaymentAction",
        vec![ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
            doc: StringM::default(),
            name: "Cancel".try_into().unwrap(),
        })],
    );
    let new = union_spec(
        "PaymentAction",
        vec![
            ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                doc: StringM::default(),
                name: "Cancel".try_into().unwrap(),
            }),
            ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                doc: StringM::default(),
                name: "Pay".try_into().unwrap(),
                type_: VecM::try_from(vec![ScSpecTypeDef::U32]).unwrap(),
            }),
        ],
    );

    let report = compare(&old, &new);
    let safety = SafetyReport::new(&report);

    assert!(safety.is_safe());
    assert_eq!(safety.critical_count(), 0);
    assert!(report
        .findings
        .iter()
        .any(|f| { *f.severity() == Severity::Info && f.category() == "Union Case Added" }));
}

#[test]
fn fixture_pair_error_enum_value_change_is_unsafe() {
    let old = error_enum_spec("VaultError", vec![("InsufficientFunds", 10)]);
    let new = error_enum_spec("VaultError", vec![("InsufficientFunds", 11)]);

    let report = compare(&old, &new);
    let safety = SafetyReport::new(&report);

    assert!(!safety.is_safe());
    assert!(report.findings.iter().any(|f| {
        *f.severity() == Severity::Critical && f.category() == "Error Enum Case Value Changed"
    }));
}

//! Integration tests for map-key compatibility (Issue: Classify map-key
//! compatibility and ordering changes).
//!
//! These tests verify that the compatibility engine:
//!
//! 1. Distinguishes map key changes from map value changes in nested type
//!    comparisons.
//! 2. Detects key-type changes, key-container changes, and changes to
//!    canonical ordering semantics.
//! 3. Treats key-domain changes as storage or call-ABI breaks.
//! 4. Reports precise nested targets and stable rule IDs.
//! 5. Avoids duplicate generic outer-container findings when a map-specific
//!    finding explains the change.
//! 6. Renders map key and value paths consistently across output formats.
//!
//! The test fixtures cover:
//! - Primitive key types (u32, u64, i128, bool)
//! - Lexicographic key types (String, Symbol, Bytes, BytesN)
//! - Address keys
//! - User-defined type (UDT) keys — unsupported/opaque ordering
//! - Nested container keys (Vec<…>, Tuple<…>) — unsupported ordering
//! - Value-only changes (key unchanged)
//! - Both key and value changed simultaneously
//! - Unchanged maps (no findings expected)
//! - Maps in struct fields, function parameters, and return types

use soroban_upgrade_safeguard::diff::{compare, Severity};
use soroban_upgrade_safeguard::spec::ContractSpec;
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeBytesN, ScSpecTypeDef, ScSpecTypeMap,
    ScSpecTypeOption, ScSpecTypeTuple, ScSpecTypeUdt, ScSpecTypeVec, ScSpecUdtStructFieldV0,
    ScSpecUdtStructV0, StringM, VecM,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn map_field(key: ScSpecTypeDef, value: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
        key_type: Box::new(key),
        value_type: Box::new(value),
    }))
}

fn udt(name: &str) -> ScSpecTypeDef {
    ScSpecTypeDef::Udt(ScSpecTypeUdt {
        name: name.try_into().expect("UDT name fits"),
    })
}

fn bytesn(n: u32) -> ScSpecTypeDef {
    ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n })
}

fn spec_with_map_field(
    struct_name: &str,
    field_name: &str,
    old_map: ScSpecTypeDef,
) -> ContractSpec {
    let mut spec = ContractSpec::default();
    spec.structs.insert(
        struct_name.to_string(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: struct_name.try_into().expect("name fits"),
            fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
                doc: StringM::default(),
                name: field_name.try_into().expect("field name fits"),
                type_: old_map,
            }])
            .expect("fields fit"),
        },
    );
    spec
}

fn spec_with_fn_param(fn_name: &str, param_name: &str, param_type: ScSpecTypeDef) -> ContractSpec {
    let mut spec = ContractSpec::default();
    spec.functions.insert(
        fn_name.to_string(),
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: fn_name.try_into().expect("fn name fits"),
            inputs: VecM::try_from(vec![ScSpecFunctionInputV0 {
                doc: StringM::default(),
                name: param_name.try_into().expect("param name fits"),
                type_: param_type,
            }])
            .expect("inputs fit"),
            outputs: VecM::default(),
        },
    );
    spec
}

// ---------------------------------------------------------------------------
// 1. Map key vs. value distinction
// ---------------------------------------------------------------------------

#[test]
fn map_key_change_emits_key_finding_not_value() {
    // Map<Symbol, u64> → Map<String, u64>: key changed, value unchanged
    let old = spec_with_map_field(
        "Store",
        "balances",
        map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64),
    );
    let new = spec_with_map_field(
        "Store",
        "balances",
        map_field(ScSpecTypeDef::String, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);

    let key_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.category == "Map Key Type Changed")
        .collect();
    let val_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.category == "Map Value Type Changed")
        .collect();

    assert_eq!(key_findings.len(), 1, "expected exactly one MapKeyTypeChanged");
    assert_eq!(val_findings.len(), 0, "no MapValueTypeChanged when only key changed");
    assert_eq!(key_findings[0].target.as_deref(), Some("Store.balances"));
    assert_eq!(key_findings[0].severity, Severity::Critical);
}

#[test]
fn map_value_change_emits_value_finding_not_key() {
    // Map<Address, u32> → Map<Address, u64>: value changed, key unchanged
    let old = spec_with_map_field(
        "Store",
        "ledger",
        map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U32),
    );
    let new = spec_with_map_field(
        "Store",
        "ledger",
        map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);

    let key_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.category == "Map Key Type Changed")
        .collect();
    let val_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.category == "Map Value Type Changed")
        .collect();

    assert_eq!(key_findings.len(), 0, "no MapKeyTypeChanged when only value changed");
    assert_eq!(val_findings.len(), 1, "expected exactly one MapValueTypeChanged");
    assert_eq!(val_findings[0].target.as_deref(), Some("Store.ledger"));
    assert_eq!(val_findings[0].severity, Severity::Critical);
}

#[test]
fn both_key_and_value_changed_emits_two_findings() {
    // Map<Symbol, u32> → Map<String, u64>: both positions changed
    let old = spec_with_map_field(
        "Config",
        "settings",
        map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U32),
    );
    let new = spec_with_map_field(
        "Config",
        "settings",
        map_field(ScSpecTypeDef::String, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);

    let key_count = report
        .findings
        .iter()
        .filter(|f| f.category == "Map Key Type Changed")
        .count();
    let val_count = report
        .findings
        .iter()
        .filter(|f| f.category == "Map Value Type Changed")
        .count();

    assert_eq!(key_count, 1);
    assert_eq!(val_count, 1);
    // Generic outer finding must be suppressed
    assert!(
        !report.findings.iter().any(|f| f.category == "Struct Field Type Changed"),
        "generic outer finding must be suppressed"
    );
}

// ---------------------------------------------------------------------------
// 2. Ordering semantics
// ---------------------------------------------------------------------------

#[test]
fn numeric_to_lexicographic_key_notes_ordering_change() {
    // Map<u32, u64> → Map<Symbol, u64>: numeric → lexicographic ordering class
    let old = spec_with_map_field(
        "Data",
        "idx",
        map_field(ScSpecTypeDef::U32, ScSpecTypeDef::U64),
    );
    let new = spec_with_map_field(
        "Data",
        "idx",
        map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .expect("expected MapKeyTypeChanged");
    assert!(
        f.message.contains("numeric") || f.message.contains("ordering"),
        "ordering class change must be noted, got: {}",
        f.message
    );
}

#[test]
fn same_ordering_class_no_ordering_note() {
    // Map<Symbol, u64> → Map<String, u64>: both lexicographic, no ordering note
    let old = spec_with_map_field(
        "Data",
        "tags",
        map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64),
    );
    let new = spec_with_map_field(
        "Data",
        "tags",
        map_field(ScSpecTypeDef::String, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .expect("expected MapKeyTypeChanged");
    // Both lexicographic — no ordering-class change note
    assert!(
        !f.message.contains("ordering changed from"),
        "no ordering note expected when class unchanged, got: {}",
        f.message
    );
    // Still reports the key-domain change
    assert!(
        f.message.contains("Symbol") || f.message.contains("String"),
        "must mention old and new key types, got: {}",
        f.message
    );
}

#[test]
fn lexicographic_to_numeric_key_notes_ordering_change() {
    // Map<Bytes, u128> → Map<U128, u128>: lexicographic → numeric
    let old = spec_with_map_field(
        "Pool",
        "amounts",
        map_field(ScSpecTypeDef::Bytes, ScSpecTypeDef::U128),
    );
    let new = spec_with_map_field(
        "Pool",
        "amounts",
        map_field(ScSpecTypeDef::U128, ScSpecTypeDef::U128),
    );
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .expect("expected MapKeyTypeChanged");
    assert!(
        f.message.contains("lexicographic") || f.message.contains("ordering") || f.message.contains("numeric"),
        "ordering class change must be noted, got: {}",
        f.message
    );
}

// ---------------------------------------------------------------------------
// 3. Key-domain change treated as storage + call-ABI break
// ---------------------------------------------------------------------------

#[test]
fn key_domain_change_is_critical_severity() {
    let old = spec_with_map_field(
        "Registry",
        "entries",
        map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64),
    );
    let new = spec_with_map_field(
        "Registry",
        "entries",
        map_field(ScSpecTypeDef::String, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .expect("expected MapKeyTypeChanged");
    assert_eq!(f.severity, Severity::Critical);
}

#[test]
fn key_domain_change_has_storage_and_call_abi_axes() {
    use soroban_upgrade_safeguard::diff::CompatibilityAxis;
    let old = spec_with_fn_param(
        "lookup",
        "index",
        map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64),
    );
    let new = spec_with_fn_param(
        "lookup",
        "index",
        map_field(ScSpecTypeDef::String, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .expect("expected MapKeyTypeChanged");
    // MapKeyTypeChanged is a call-ABI break when it appears in a function param
    assert!(
        f.axes.contains(&CompatibilityAxis::CallAbi),
        "MapKeyTypeChanged on function param must include CallAbi axis, axes: {:?}",
        f.axes
    );
}

// ---------------------------------------------------------------------------
// 4. Precise nested targets and stable rule IDs
// ---------------------------------------------------------------------------

#[test]
fn map_key_finding_target_is_field_path() {
    let old = spec_with_map_field(
        "Ledger",
        "balances",
        map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U64),
    );
    let new = spec_with_map_field(
        "Ledger",
        "balances",
        map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .unwrap();
    assert_eq!(f.target.as_deref(), Some("Ledger.balances"));
}

#[test]
fn map_value_finding_target_is_field_path() {
    let old = spec_with_map_field(
        "Ledger",
        "allowances",
        map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U32),
    );
    let new = spec_with_map_field(
        "Ledger",
        "allowances",
        map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Value Type Changed")
        .unwrap();
    assert_eq!(f.target.as_deref(), Some("Ledger.allowances"));
}

#[test]
fn map_key_finding_on_fn_param_has_correct_target() {
    let old = spec_with_fn_param("transfer", "opts", map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U32));
    let new = spec_with_fn_param("transfer", "opts", map_field(ScSpecTypeDef::String, ScSpecTypeDef::U32));
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .unwrap();
    assert_eq!(f.target.as_deref(), Some("transfer.opts"));
}

#[test]
fn map_key_finding_category_string_is_stable() {
    let old = spec_with_map_field("A", "f", map_field(ScSpecTypeDef::U32, ScSpecTypeDef::U64));
    let new = spec_with_map_field("A", "f", map_field(ScSpecTypeDef::U64, ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .unwrap();
    // The category string must be the exact stable ID
    assert_eq!(f.category, "Map Key Type Changed");
}

#[test]
fn map_value_finding_category_string_is_stable() {
    let old = spec_with_map_field("A", "f", map_field(ScSpecTypeDef::U32, ScSpecTypeDef::U32));
    let new = spec_with_map_field("A", "f", map_field(ScSpecTypeDef::U32, ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Value Type Changed")
        .unwrap();
    assert_eq!(f.category, "Map Value Type Changed");
}

// ---------------------------------------------------------------------------
// 5. No duplicate outer-container findings
// ---------------------------------------------------------------------------

#[test]
fn map_key_change_suppresses_generic_struct_field_type_changed() {
    let old = spec_with_map_field("S", "m", map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64));
    let new = spec_with_map_field("S", "m", map_field(ScSpecTypeDef::String, ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    assert!(
        !report.findings.iter().any(|f| f.category == "Struct Field Type Changed"),
        "generic Struct Field Type Changed must be suppressed when map-specific finding exists"
    );
}

#[test]
fn map_value_change_suppresses_generic_struct_field_type_changed() {
    let old = spec_with_map_field("S", "m", map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U32));
    let new = spec_with_map_field("S", "m", map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    assert!(
        !report.findings.iter().any(|f| f.category == "Struct Field Type Changed"),
        "generic Struct Field Type Changed must be suppressed when map-specific finding exists"
    );
}

#[test]
fn map_key_change_on_param_suppresses_generic_parameter_type_changed() {
    let old = spec_with_fn_param("fn1", "arg", map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64));
    let new = spec_with_fn_param("fn1", "arg", map_field(ScSpecTypeDef::String, ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    assert!(
        !report.findings.iter().any(|f| f.category == "Parameter Type Changed"),
        "generic Parameter Type Changed must be suppressed"
    );
}

// ---------------------------------------------------------------------------
// 6. Fixtures: primitive, UDT, nested, and unsupported key types
// ---------------------------------------------------------------------------

#[test]
fn map_with_bool_key_change_detected() {
    // Map<bool, u64> → Map<u32, u64>
    let old = spec_with_map_field("X", "f", map_field(ScSpecTypeDef::Bool, ScSpecTypeDef::U64));
    let new = spec_with_map_field("X", "f", map_field(ScSpecTypeDef::U32, ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    assert!(
        report.findings.iter().any(|f| f.category == "Map Key Type Changed"),
        "expected MapKeyTypeChanged for bool→u32"
    );
}

#[test]
fn map_with_bytesn_key_change_detected() {
    // Map<BytesN<32>, Address> → Map<BytesN<64>, Address>: both are
    // lexicographic (Bytes class) but the sizes differ — still a key change.
    let old = spec_with_map_field("X", "f", map_field(bytesn(32), ScSpecTypeDef::Address));
    let new = spec_with_map_field("X", "f", map_field(bytesn(64), ScSpecTypeDef::Address));
    let report = compare(&old, &new);
    assert!(
        report.findings.iter().any(|f| f.category == "Map Key Type Changed"),
        "expected MapKeyTypeChanged for BytesN<32>→BytesN<64>"
    );
    // Both BytesN → same ordering class (lexicographic) — no ordering note expected
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .unwrap();
    assert!(
        !f.message.contains("ordering changed from"),
        "no ordering class change note expected for BytesN size change, got: {}",
        f.message
    );
}

#[test]
fn map_with_udt_key_notes_unsupported_ordering() {
    // Map<u32, u64> → Map<TokenId, u64>: UDT key has opaque/unsupported ordering
    let old = spec_with_map_field("X", "f", map_field(ScSpecTypeDef::U32, ScSpecTypeDef::U64));
    let new = spec_with_map_field("X", "f", map_field(udt("TokenId"), ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .expect("expected MapKeyTypeChanged");
    assert!(
        f.message.contains("unsupported") || f.message.contains("opaque"),
        "UDT key must note unsupported ordering, got: {}",
        f.message
    );
}

#[test]
fn map_with_nested_vec_key_notes_unsupported_ordering() {
    // Map<Vec<u32>, u64> → Map<u32, u64>: Vec key has opaque ordering
    let vec_key = ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
        element_type: Box::new(ScSpecTypeDef::U32),
    }));
    let old = spec_with_map_field("X", "f", map_field(vec_key, ScSpecTypeDef::U64));
    let new = spec_with_map_field("X", "f", map_field(ScSpecTypeDef::U32, ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .expect("expected MapKeyTypeChanged");
    assert!(
        f.message.contains("unsupported") || f.message.contains("opaque"),
        "Vec key must note unsupported ordering, got: {}",
        f.message
    );
}

#[test]
fn map_with_tuple_key_notes_unsupported_ordering() {
    // Map<(Address, u32), u64> → Map<Address, u64>: Tuple key has opaque ordering
    let tuple_key = ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
        value_types: VecM::try_from(vec![ScSpecTypeDef::Address, ScSpecTypeDef::U32])
            .expect("fits"),
    }));
    let old = spec_with_map_field("X", "f", map_field(tuple_key, ScSpecTypeDef::U64));
    let new = spec_with_map_field("X", "f", map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .expect("expected MapKeyTypeChanged");
    assert!(
        f.message.contains("unsupported") || f.message.contains("opaque"),
        "Tuple key must note unsupported ordering, got: {}",
        f.message
    );
}

#[test]
fn map_with_i128_key_changed_to_u128_detected() {
    // Both numeric but different signedness/size — still a key-domain change
    let old = spec_with_map_field("X", "f", map_field(ScSpecTypeDef::I128, ScSpecTypeDef::Address));
    let new = spec_with_map_field("X", "f", map_field(ScSpecTypeDef::U128, ScSpecTypeDef::Address));
    let report = compare(&old, &new);
    assert!(
        report.findings.iter().any(|f| f.category == "Map Key Type Changed"),
        "expected MapKeyTypeChanged for i128→u128"
    );
    // Both numeric — no ordering class note
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .unwrap();
    assert!(
        !f.message.contains("ordering changed from"),
        "same ordering class: no ordering note expected, got: {}",
        f.message
    );
}

// ---------------------------------------------------------------------------
// 7. Unchanged maps produce no findings
// ---------------------------------------------------------------------------

#[test]
fn unchanged_map_produces_no_map_findings() {
    let old = spec_with_map_field(
        "Store",
        "data",
        map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U64),
    );
    let new = spec_with_map_field(
        "Store",
        "data",
        map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U64),
    );
    let report = compare(&old, &new);
    assert!(
        !report.findings.iter().any(|f| {
            f.category == "Map Key Type Changed" || f.category == "Map Value Type Changed"
        }),
        "no map findings expected for unchanged map"
    );
}

// ---------------------------------------------------------------------------
// 8. Map key path rendered consistently in messages
// ---------------------------------------------------------------------------

#[test]
fn map_key_message_contains_old_and_new_key_types() {
    let old = spec_with_map_field("S", "m", map_field(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64));
    let new = spec_with_map_field("S", "m", map_field(ScSpecTypeDef::String, ScSpecTypeDef::U64));
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Key Type Changed")
        .unwrap();
    assert!(
        f.message.contains("Symbol"),
        "message must contain old key type, got: {}",
        f.message
    );
    assert!(
        f.message.contains("String"),
        "message must contain new key type, got: {}",
        f.message
    );
}

#[test]
fn map_value_message_contains_old_and_new_value_types() {
    let old = spec_with_map_field("S", "m", map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U32));
    let new = spec_with_map_field("S", "m", map_field(ScSpecTypeDef::Address, ScSpecTypeDef::U128));
    let report = compare(&old, &new);
    let f = report
        .findings
        .iter()
        .find(|f| f.category == "Map Value Type Changed")
        .unwrap();
    assert!(
        f.message.contains("u32"),
        "message must contain old value type, got: {}",
        f.message
    );
    assert!(
        f.message.contains("u128"),
        "message must contain new value type, got: {}",
        f.message
    );
}

#[test]
fn nested_map_in_option_key_change_detected() {
    // Option<Map<Symbol, u64>> → Option<Map<String, u64>>:
    // The nested map key change should still be reported at the field level.
    use stellar_xdr::curr::ScSpecTypeOption;
    let opt_map = |key: ScSpecTypeDef| {
        ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
            value_type: Box::new(map_field(key, ScSpecTypeDef::U64)),
        }))
    };
    let old = spec_with_map_field("S", "wrapped", opt_map(ScSpecTypeDef::Symbol));
    let new = spec_with_map_field("S", "wrapped", opt_map(ScSpecTypeDef::String));
    let report = compare(&old, &new);
    // The type changed (Option<Map<Symbol,u64>> → Option<Map<String,u64>>):
    // Since the outer type is Option not Map, it goes through StructFieldTypeChanged
    // but the message should describe the inner map key change via describe_nested_type_change.
    assert!(
        report.findings.iter().any(|f| {
            f.category == "Struct Field Type Changed" || f.category == "Map Key Type Changed"
        }),
        "expected a finding for the nested map key change"
    );
}

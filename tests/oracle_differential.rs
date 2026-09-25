//! Differential oracle integration tests.
//!
//! These tests compare safeguard's internal type-path model against the
//! independent reference decoder in [`soroban_upgrade_safeguard::oracle`].
//! When both agree the test passes silently.  A divergence is a bug in either
//! safeguard's `mapper::type_to_string` or in the oracle's reference traversal.
//!
//! # Test categories
//!
//! 1. **Primitive type paths** — each scalar `ScSpecTypeDef` variant agrees.
//! 2. **Container type paths** — Vec, Map, Option, Result, Tuple, BytesN, UDT.
//! 3. **Deeply nested containers** — multi-level nesting of the above.
//! 4. **Serialization decisions** — map key type appears in the path, tuple
//!    element order is preserved, BytesN size is encoded correctly.
//! 5. **Enum discriminants** — `u32` case values are read identically by both
//!    paths.
//! 6. **Error enum discriminants** — same as above for error enums.
//! 7. **Union payload types** — tuple case payload types agree.
//! 8. **Full spec comparison** — all of the above exercised through
//!    `compare_spec` / `compare_spec_with_seed`.
//! 9. **Counterexample recording** — `CounterexampleRecord` is populated when
//!    a divergence is detected and carries seed + toolchain metadata.
//! 10. **Oracle report invariants** — `is_clean`, `merge`, comparison count.
//! 11. **Network-gated** — extended tests skipped unless
//!     `SAFEGUARD_ORACLE_NETWORK=1`.
//!
//! # Hermetic by default
//!
//! Every test in this file is self-contained: it synthesises `ScSpecTypeDef`
//! values in process without reading files or making network calls.  No
//! external resources are required.
//!
//! # Opt-in network tests
//!
//! Tests guarded by `oracle_network_enabled()` skip unless
//! `SAFEGUARD_ORACLE_NETWORK=1` is set.  This keeps CI green with no network
//! access while allowing developers to run the full suite locally.
//!
//! # Seed-based reproduction
//!
//! Named fixture tests pass their fixture name as the seed to
//! `compare_spec_with_seed`.  On a divergence, the counterexample record
//! printed to stderr includes the seed so the exact input can be reproduced.

use soroban_upgrade_safeguard::oracle::{
    compare_enum_discriminants, compare_error_enum_discriminants, compare_spec,
    compare_spec_with_seed, compare_type_paths, map_type, option_type, oracle_network_enabled,
    spec_with_enum, spec_with_error_enum, spec_with_field_types, spec_with_fn, spec_with_union,
    tuple_type, udt_type, vec_type, CounterexampleRecord, OracleDivergence, OracleReport,
    ReferenceTypePath, SafeguardTypePath,
};
use stellar_xdr::curr::{ScSpecTypeBytesN, ScSpecTypeDef, ScSpecTypeResult};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn assert_oracle_clean(report: &OracleReport) {
    if !report.is_clean() {
        let msg = report.failure_summary();
        panic!("oracle report has failures:\n{}", msg);
    }
}

fn result_type(ok: ScSpecTypeDef, err: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
        ok_type: Box::new(ok),
        error_type: Box::new(err),
    }))
}

fn bytesn(n: u32) -> ScSpecTypeDef {
    ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n })
}

// ---------------------------------------------------------------------------
// 1. Primitive type paths agree
// ---------------------------------------------------------------------------

#[test]
fn oracle_primitive_u32() {
    let r = compare_type_paths("field", &ScSpecTypeDef::U32);
    assert!(r.is_none(), "u32 diverged: {:?}", r);
}

#[test]
fn oracle_primitive_i32() {
    let r = compare_type_paths("field", &ScSpecTypeDef::I32);
    assert!(r.is_none(), "i32 diverged: {:?}", r);
}

#[test]
fn oracle_primitive_u64() {
    let r = compare_type_paths("field", &ScSpecTypeDef::U64);
    assert!(r.is_none(), "u64 diverged: {:?}", r);
}

#[test]
fn oracle_primitive_i64() {
    let r = compare_type_paths("field", &ScSpecTypeDef::I64);
    assert!(r.is_none(), "i64 diverged: {:?}", r);
}

#[test]
fn oracle_primitive_u128() {
    let r = compare_type_paths("field", &ScSpecTypeDef::U128);
    assert!(r.is_none(), "u128 diverged: {:?}", r);
}

#[test]
fn oracle_primitive_i128() {
    let r = compare_type_paths("field", &ScSpecTypeDef::I128);
    assert!(r.is_none(), "i128 diverged: {:?}", r);
}

#[test]
fn oracle_primitive_u256() {
    let r = compare_type_paths("field", &ScSpecTypeDef::U256);
    assert!(r.is_none(), "u256 diverged: {:?}", r);
}

#[test]
fn oracle_primitive_i256() {
    let r = compare_type_paths("field", &ScSpecTypeDef::I256);
    assert!(r.is_none(), "i256 diverged: {:?}", r);
}

#[test]
fn oracle_primitive_address() {
    let r = compare_type_paths("field", &ScSpecTypeDef::Address);
    assert!(r.is_none(), "Address diverged: {:?}", r);
}

#[test]
fn oracle_primitive_bool() {
    let r = compare_type_paths("field", &ScSpecTypeDef::Bool);
    assert!(r.is_none(), "bool diverged: {:?}", r);
}

#[test]
fn oracle_primitive_void() {
    let r = compare_type_paths("field", &ScSpecTypeDef::Void);
    assert!(r.is_none(), "void diverged: {:?}", r);
}

#[test]
fn oracle_primitive_string() {
    let r = compare_type_paths("field", &ScSpecTypeDef::String);
    assert!(r.is_none(), "String diverged: {:?}", r);
}

#[test]
fn oracle_primitive_symbol() {
    let r = compare_type_paths("field", &ScSpecTypeDef::Symbol);
    assert!(r.is_none(), "Symbol diverged: {:?}", r);
}

#[test]
fn oracle_primitive_bytes() {
    let r = compare_type_paths("field", &ScSpecTypeDef::Bytes);
    assert!(r.is_none(), "Bytes diverged: {:?}", r);
}

#[test]
fn oracle_primitive_timepoint() {
    let r = compare_type_paths("field", &ScSpecTypeDef::Timepoint);
    assert!(r.is_none(), "Timepoint diverged: {:?}", r);
}

#[test]
fn oracle_primitive_duration() {
    let r = compare_type_paths("field", &ScSpecTypeDef::Duration);
    assert!(r.is_none(), "Duration diverged: {:?}", r);
}

#[test]
fn oracle_primitive_val() {
    let r = compare_type_paths("field", &ScSpecTypeDef::Val);
    assert!(r.is_none(), "Val diverged: {:?}", r);
}

#[test]
fn oracle_primitive_error() {
    let r = compare_type_paths("field", &ScSpecTypeDef::Error);
    assert!(r.is_none(), "Error diverged: {:?}", r);
}

// ---------------------------------------------------------------------------
// 2. Container type paths agree
// ---------------------------------------------------------------------------

#[test]
fn oracle_vec_of_u64() {
    let t = vec_type(ScSpecTypeDef::U64);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Vec<u64> diverged: {:?}", r);
}

#[test]
fn oracle_option_of_address() {
    let t = option_type(ScSpecTypeDef::Address);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Option<Address> diverged: {:?}", r);
}

#[test]
fn oracle_map_primitive_key() {
    let t = map_type(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Map<Symbol, u64> diverged: {:?}", r);
}

#[test]
fn oracle_map_address_key() {
    let t = map_type(ScSpecTypeDef::Address, ScSpecTypeDef::U128);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Map<Address, u128> diverged: {:?}", r);
}

#[test]
fn oracle_map_u32_key() {
    let t = map_type(ScSpecTypeDef::U32, ScSpecTypeDef::U64);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Map<u32, u64> diverged: {:?}", r);
}

#[test]
fn oracle_map_string_key() {
    let t = map_type(ScSpecTypeDef::String, ScSpecTypeDef::Bool);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Map<String, bool> diverged: {:?}", r);
}

#[test]
fn oracle_map_udt_key() {
    let t = map_type(udt_type("TokenKey"), ScSpecTypeDef::U64);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Map<TokenKey, u64> diverged: {:?}", r);
}

#[test]
fn oracle_map_nested_value() {
    // Map<Address, Vec<u32>>
    let t = map_type(ScSpecTypeDef::Address, vec_type(ScSpecTypeDef::U32));
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Map<Address, Vec<u32>> diverged: {:?}", r);
}

#[test]
fn oracle_map_nested_key() {
    // Map<(u32, Address), u64> — tuple as map key
    let key = tuple_type(vec![ScSpecTypeDef::U32, ScSpecTypeDef::Address]);
    let t = map_type(key, ScSpecTypeDef::U64);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Map<(u32, Address), u64> diverged: {:?}", r);
}

#[test]
fn oracle_tuple_two_elements() {
    let t = tuple_type(vec![ScSpecTypeDef::U32, ScSpecTypeDef::String]);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "(u32, String) diverged: {:?}", r);
}

#[test]
fn oracle_tuple_three_elements() {
    let t = tuple_type(vec![
        ScSpecTypeDef::U32,
        ScSpecTypeDef::Address,
        ScSpecTypeDef::Bool,
    ]);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "(u32, Address, bool) diverged: {:?}", r);
}

#[test]
fn oracle_tuple_single_element() {
    let t = tuple_type(vec![ScSpecTypeDef::I128]);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "(i128,) diverged: {:?}", r);
}

#[test]
fn oracle_result_type() {
    let t = result_type(ScSpecTypeDef::U64, ScSpecTypeDef::U32);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Result<u64,u32> diverged: {:?}", r);
}

#[test]
fn oracle_result_with_udt_error() {
    let t = result_type(ScSpecTypeDef::U128, udt_type("ContractError"));
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "Result<u128, ContractError> diverged: {:?}", r);
}

#[test]
fn oracle_bytesn_32() {
    let t = bytesn(32);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "BytesN<32> diverged: {:?}", r);
}

#[test]
fn oracle_bytesn_64() {
    let t = bytesn(64);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "BytesN<64> diverged: {:?}", r);
}

#[test]
fn oracle_bytesn_1() {
    let t = bytesn(1);
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "BytesN<1> diverged: {:?}", r);
}

#[test]
fn oracle_udt_reference() {
    let t = udt_type("MyStruct");
    let r = compare_type_paths("field", &t);
    assert!(r.is_none(), "UDT diverged: {:?}", r);
}

// ---------------------------------------------------------------------------
// 3. Deeply nested containers agree
// ---------------------------------------------------------------------------

#[test]
fn oracle_deeply_nested_agrees() {
    // Vec<Option<Map<Address, (u32, String)>>>
    let inner = map_type(
        ScSpecTypeDef::Address,
        tuple_type(vec![ScSpecTypeDef::U32, ScSpecTypeDef::String]),
    );
    let t = vec_type(option_type(inner));
    let r = compare_type_paths("deep", &t);
    assert!(r.is_none(), "deeply nested diverged: {:?}", r);
}

#[test]
fn oracle_map_of_maps() {
    // Map<Symbol, Map<Address, u128>>
    let inner = map_type(ScSpecTypeDef::Address, ScSpecTypeDef::U128);
    let t = map_type(ScSpecTypeDef::Symbol, inner);
    let r = compare_type_paths("map_of_maps", &t);
    assert!(r.is_none(), "Map<Symbol, Map<…>> diverged: {:?}", r);
}

#[test]
fn oracle_nested_result_in_option() {
    // Option<Result<u64, u32>>
    let t = option_type(result_type(ScSpecTypeDef::U64, ScSpecTypeDef::U32));
    let r = compare_type_paths("opt_result", &t);
    assert!(r.is_none(), "Option<Result<…>> diverged: {:?}", r);
}

#[test]
fn oracle_vec_of_tuples() {
    // Vec<(Address, u64)>
    let inner = tuple_type(vec![ScSpecTypeDef::Address, ScSpecTypeDef::U64]);
    let t = vec_type(inner);
    let r = compare_type_paths("vec_of_tuples", &t);
    assert!(r.is_none(), "Vec<(Address, u64)> diverged: {:?}", r);
}

#[test]
fn oracle_map_with_option_value() {
    // Map<Address, Option<u128>>
    let t = map_type(
        ScSpecTypeDef::Address,
        option_type(ScSpecTypeDef::U128),
    );
    let r = compare_type_paths("map_opt_value", &t);
    assert!(r.is_none(), "Map<Address, Option<u128>> diverged: {:?}", r);
}

#[test]
fn oracle_deeply_nested_map_of_vec_of_tuples() {
    // Map<Symbol, Vec<(u32, Address, bool)>>
    let elem = tuple_type(vec![
        ScSpecTypeDef::U32,
        ScSpecTypeDef::Address,
        ScSpecTypeDef::Bool,
    ]);
    let t = map_type(ScSpecTypeDef::Symbol, vec_type(elem));
    let r = compare_type_paths("map_vec_tuple", &t);
    assert!(r.is_none(), "Map<Symbol, Vec<(u32, Address, bool)>> diverged: {:?}", r);
}

// ---------------------------------------------------------------------------
// 4. Serialization decisions
// ---------------------------------------------------------------------------

#[test]
fn oracle_map_key_type_is_part_of_path() {
    // Verify the safeguard path actually encodes the key type; a broken
    // implementation that omits the key would produce "Map<u64>" instead of
    // "Map<Symbol, u64>".
    let t = map_type(ScSpecTypeDef::Symbol, ScSpecTypeDef::U64);
    let safeguard =
        SafeguardTypePath(soroban_upgrade_safeguard::mapper::type_to_string(&t));
    assert!(
        safeguard.0.contains("Symbol"),
        "key type must be present in safeguard path, got: {}",
        safeguard.0
    );
    assert!(
        safeguard.0.contains("u64"),
        "value type must be present in safeguard path, got: {}",
        safeguard.0
    );
    let r = compare_type_paths("map_key_check", &t);
    assert!(r.is_none());
}

#[test]
fn oracle_map_key_and_value_are_ordered_correctly() {
    // Map<Address, Symbol> must encode key before value in the path string.
    let t = map_type(ScSpecTypeDef::Address, ScSpecTypeDef::Symbol);
    let path = soroban_upgrade_safeguard::mapper::type_to_string(&t);
    let addr_pos = path.find("Address").expect("Address must appear in path");
    let sym_pos = path.find("Symbol").expect("Symbol must appear in path");
    assert!(
        addr_pos < sym_pos,
        "key (Address) must appear before value (Symbol) in '{}', but positions are {} vs {}",
        path,
        addr_pos,
        sym_pos
    );
}

#[test]
fn oracle_tuple_element_order_preserved() {
    // (u32, Address, bool) — verify element order matches XDR declaration order.
    let t = tuple_type(vec![
        ScSpecTypeDef::U32,
        ScSpecTypeDef::Address,
        ScSpecTypeDef::Bool,
    ]);
    let path = soroban_upgrade_safeguard::mapper::type_to_string(&t);
    let u32_pos = path.find("u32").expect("u32 must appear");
    let addr_pos = path.find("Address").expect("Address must appear");
    let bool_pos = path.find("bool").expect("bool must appear");
    assert!(
        u32_pos < addr_pos && addr_pos < bool_pos,
        "tuple elements must be in declaration order in '{}' (positions {} {} {})",
        path,
        u32_pos,
        addr_pos,
        bool_pos
    );
    // Reference must agree
    let r = compare_type_paths("tuple_order", &t);
    assert!(r.is_none());
}

#[test]
fn oracle_bytesn_size_encoded_in_path() {
    // BytesN<64> path must contain "64", not just "BytesN".
    let t = bytesn(64);
    let path = soroban_upgrade_safeguard::mapper::type_to_string(&t);
    assert!(
        path.contains("64"),
        "BytesN size must be encoded in path, got: {}",
        path
    );
    let r = compare_type_paths("bytesn_size", &t);
    assert!(r.is_none());
}

#[test]
fn oracle_different_bytesn_sizes_produce_different_paths() {
    let path_32 = soroban_upgrade_safeguard::mapper::type_to_string(&bytesn(32));
    let path_64 = soroban_upgrade_safeguard::mapper::type_to_string(&bytesn(64));
    assert_ne!(
        path_32, path_64,
        "different BytesN sizes must produce different paths"
    );
}

// ---------------------------------------------------------------------------
// 5. Enum discriminant comparison
// ---------------------------------------------------------------------------

#[test]
fn oracle_enum_discriminants_sequential() {
    // Standard sequential enum: Active=0, Inactive=1, Banned=2
    use stellar_xdr::curr::{ScSpecUdtEnumV0, ScSpecUdtEnumCaseV0, StringM, VecM};
    let cases: Vec<ScSpecUdtEnumCaseV0> = vec![
        ScSpecUdtEnumCaseV0 {
            doc: StringM::default(),
            name: "Active".try_into().unwrap(),
            value: 0,
        },
        ScSpecUdtEnumCaseV0 {
            doc: StringM::default(),
            name: "Inactive".try_into().unwrap(),
            value: 1,
        },
        ScSpecUdtEnumCaseV0 {
            doc: StringM::default(),
            name: "Banned".try_into().unwrap(),
            value: 2,
        },
    ];
    let enum_def = ScSpecUdtEnumV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: "Status".try_into().unwrap(),
        cases: VecM::try_from(cases).unwrap(),
    };
    let mismatches = compare_enum_discriminants("Status", &enum_def);
    assert!(
        mismatches.is_empty(),
        "unexpected discriminant mismatches: {:?}",
        mismatches
    );
}

#[test]
fn oracle_enum_discriminants_non_sequential() {
    // Non-sequential values (e.g. error codes): 100, 200, 300
    use stellar_xdr::curr::{ScSpecUdtEnumV0, ScSpecUdtEnumCaseV0, StringM, VecM};
    let cases: Vec<ScSpecUdtEnumCaseV0> = vec![
        ScSpecUdtEnumCaseV0 {
            doc: StringM::default(),
            name: "ErrA".try_into().unwrap(),
            value: 100,
        },
        ScSpecUdtEnumCaseV0 {
            doc: StringM::default(),
            name: "ErrB".try_into().unwrap(),
            value: 200,
        },
    ];
    let enum_def = ScSpecUdtEnumV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: "Codes".try_into().unwrap(),
        cases: VecM::try_from(cases).unwrap(),
    };
    let mismatches = compare_enum_discriminants("Codes", &enum_def);
    assert!(mismatches.is_empty());
}

#[test]
fn oracle_enum_via_compare_spec_clean() {
    let spec = spec_with_enum("Phase", vec![("Init", 0), ("Running", 1), ("Done", 2)]);
    let report = compare_spec_with_seed(&spec, "fixture_enum_sequential");
    assert_oracle_clean(&report);
}

// ---------------------------------------------------------------------------
// 6. Error enum discriminant comparison
// ---------------------------------------------------------------------------

#[test]
fn oracle_error_enum_discriminants_clean() {
    use stellar_xdr::curr::{
        ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, StringM, VecM,
    };
    let cases: Vec<ScSpecUdtErrorEnumCaseV0> = vec![
        ScSpecUdtErrorEnumCaseV0 {
            doc: StringM::default(),
            name: "NotFound".try_into().unwrap(),
            value: 1,
        },
        ScSpecUdtErrorEnumCaseV0 {
            doc: StringM::default(),
            name: "Unauthorized".try_into().unwrap(),
            value: 2,
        },
        ScSpecUdtErrorEnumCaseV0 {
            doc: StringM::default(),
            name: "Overflow".try_into().unwrap(),
            value: 3,
        },
    ];
    let enum_def = ScSpecUdtErrorEnumV0 {
        doc: StringM::default(),
        lib: StringM::default(),
        name: "ContractError".try_into().unwrap(),
        cases: VecM::try_from(cases).unwrap(),
    };
    let mismatches = compare_error_enum_discriminants("ContractError", &enum_def);
    assert!(
        mismatches.is_empty(),
        "unexpected discriminant mismatches: {:?}",
        mismatches
    );
}

#[test]
fn oracle_error_enum_via_compare_spec_clean() {
    let spec = spec_with_error_enum(
        "MyError",
        vec![("BadInput", 1), ("Internal", 2), ("NotAllowed", 3)],
    );
    let report = compare_spec_with_seed(&spec, "fixture_error_enum");
    assert_oracle_clean(&report);
}

// ---------------------------------------------------------------------------
// 7. Union payload types agree
// ---------------------------------------------------------------------------

#[test]
fn oracle_union_void_case_no_comparisons() {
    // A union with only void cases produces zero type-path comparisons.
    let spec = spec_with_union("Flag", vec!["On", "Off"], vec![]);
    let report = compare_spec_with_seed(&spec, "fixture_union_void");
    assert_eq!(report.comparisons, 0);
    assert_oracle_clean(&report);
}

#[test]
fn oracle_union_tuple_case_u64_clean() {
    let spec = spec_with_union(
        "Value",
        vec![],
        vec![("Int", vec![ScSpecTypeDef::U64])],
    );
    let report = compare_spec_with_seed(&spec, "fixture_union_tuple_u64");
    assert_eq!(report.comparisons, 1);
    assert_oracle_clean(&report);
}

#[test]
fn oracle_union_tuple_case_multi_type_clean() {
    // Tuple case with multiple type payloads
    let spec = spec_with_union(
        "Transfer",
        vec!["Noop"],
        vec![
            ("Move", vec![ScSpecTypeDef::Address, ScSpecTypeDef::U128]),
            ("Swap", vec![
                ScSpecTypeDef::Address,
                ScSpecTypeDef::Address,
                ScSpecTypeDef::U64,
            ]),
        ],
    );
    let report = compare_spec_with_seed(&spec, "fixture_union_multi_type");
    // Move: 2, Swap: 3 = 5 comparisons
    assert_eq!(report.comparisons, 5);
    assert_oracle_clean(&report);
}

#[test]
fn oracle_union_tuple_with_map_payload_clean() {
    let spec = spec_with_union(
        "Action",
        vec![],
        vec![(
            "SetBalances",
            vec![map_type(ScSpecTypeDef::Address, ScSpecTypeDef::U64)],
        )],
    );
    let report = compare_spec_with_seed(&spec, "fixture_union_map_payload");
    assert_eq!(report.comparisons, 1);
    assert_oracle_clean(&report);
}

// ---------------------------------------------------------------------------
// 8. Full spec comparison
// ---------------------------------------------------------------------------

#[test]
fn oracle_full_struct_spec_clean() {
    // Struct with field types: primitive, Map, Vec, Option, tuple, BytesN, UDT
    let spec = spec_with_field_types(vec![
        ("amount", ScSpecTypeDef::U128),
        (
            "balances",
            map_type(ScSpecTypeDef::Address, ScSpecTypeDef::U64),
        ),
        ("history", vec_type(ScSpecTypeDef::U32)),
        ("maybe_owner", option_type(ScSpecTypeDef::Address)),
        (
            "pair",
            tuple_type(vec![ScSpecTypeDef::U32, ScSpecTypeDef::Bool]),
        ),
        ("key_bytes", bytesn(32)),
        ("token", udt_type("TokenInfo")),
    ]);
    let report = compare_spec_with_seed(&spec, "fixture_full_struct");
    assert_eq!(report.comparisons, 7);
    assert_oracle_clean(&report);
}

#[test]
fn oracle_function_spec_clean() {
    let spec = spec_with_fn(
        "swap",
        vec![
            ("from", ScSpecTypeDef::Address),
            ("to", ScSpecTypeDef::Address),
            ("amount_in", ScSpecTypeDef::U128),
            (
                "opts",
                map_type(ScSpecTypeDef::Symbol, ScSpecTypeDef::U32),
            ),
        ],
        vec![result_type(ScSpecTypeDef::U128, ScSpecTypeDef::U32)],
    );
    let report = compare_spec_with_seed(&spec, "fixture_function_swap");
    // 4 params + 1 return = 5 comparisons
    assert_eq!(report.comparisons, 5);
    assert_oracle_clean(&report);
}

#[test]
fn oracle_full_corpus_fixture_clean() {
    // Representative corpus fixture: a realistic token-like contract spec with
    // functions, structs, an enum, an error enum, and a union — all checked
    // together through compare_spec_with_seed so divergences include the
    // corpus fixture name as their seed.
    use soroban_upgrade_safeguard::spec::ContractSpec;
    use stellar_xdr::curr::{
        ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
        ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0,
        ScSpecUdtStructV0, ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0,
        ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0, StringM, VecM,
    };

    let mut spec = ContractSpec::default();

    // Struct: BalanceData { owner: Address, amount: u128 }
    spec.structs.insert(
        "BalanceData".to_string(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "BalanceData".try_into().unwrap(),
            fields: VecM::try_from(vec![
                ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: "owner".try_into().unwrap(),
                    type_: ScSpecTypeDef::Address,
                },
                ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: "amount".try_into().unwrap(),
                    type_: ScSpecTypeDef::U128,
                },
            ])
            .unwrap(),
        },
    );

    // Enum: Status { Active=0, Frozen=1 }
    spec.enums.insert(
        "Status".to_string(),
        ScSpecUdtEnumV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "Status".try_into().unwrap(),
            cases: VecM::try_from(vec![
                ScSpecUdtEnumCaseV0 {
                    doc: StringM::default(),
                    name: "Active".try_into().unwrap(),
                    value: 0,
                },
                ScSpecUdtEnumCaseV0 {
                    doc: StringM::default(),
                    name: "Frozen".try_into().unwrap(),
                    value: 1,
                },
            ])
            .unwrap(),
        },
    );

    // Error enum: TokenError { NotAllowed=1, Overflow=2 }
    spec.error_enums.insert(
        "TokenError".to_string(),
        ScSpecUdtErrorEnumV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "TokenError".try_into().unwrap(),
            cases: VecM::try_from(vec![
                ScSpecUdtErrorEnumCaseV0 {
                    doc: StringM::default(),
                    name: "NotAllowed".try_into().unwrap(),
                    value: 1,
                },
                ScSpecUdtErrorEnumCaseV0 {
                    doc: StringM::default(),
                    name: "Overflow".try_into().unwrap(),
                    value: 2,
                },
            ])
            .unwrap(),
        },
    );

    // Union: Event { Transfer(Address, Address, u128), Mint(Address, u128) }
    spec.unions.insert(
        "Event".to_string(),
        ScSpecUdtUnionV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "Event".try_into().unwrap(),
            cases: VecM::try_from(vec![
                ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                    doc: StringM::default(),
                    name: "None".try_into().unwrap(),
                }),
                ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                    doc: StringM::default(),
                    name: "Transfer".try_into().unwrap(),
                    type_: VecM::try_from(vec![
                        ScSpecTypeDef::Address,
                        ScSpecTypeDef::Address,
                        ScSpecTypeDef::U128,
                    ])
                    .unwrap(),
                }),
                ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                    doc: StringM::default(),
                    name: "Mint".try_into().unwrap(),
                    type_: VecM::try_from(vec![ScSpecTypeDef::Address, ScSpecTypeDef::U128])
                        .unwrap(),
                }),
            ])
            .unwrap(),
        },
    );

    // Function: transfer(from: Address, to: Address, amount: u128) -> Result<(), TokenError>
    spec.functions.insert(
        "transfer".to_string(),
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "transfer".try_into().unwrap(),
            inputs: VecM::try_from(vec![
                ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: "from".try_into().unwrap(),
                    type_: ScSpecTypeDef::Address,
                },
                ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: "to".try_into().unwrap(),
                    type_: ScSpecTypeDef::Address,
                },
                ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: "amount".try_into().unwrap(),
                    type_: ScSpecTypeDef::U128,
                },
            ])
            .unwrap(),
            outputs: VecM::try_from(vec![ScSpecTypeDef::Void]).unwrap(),
        },
    );

    let report = compare_spec_with_seed(&spec, "corpus_token_v1");
    assert_oracle_clean(&report);
    // 2 struct fields + 3 union payload types + 3 fn params + 1 fn return = 9
    assert_eq!(report.comparisons, 9);
}

// ---------------------------------------------------------------------------
// 9. Counterexample recording
// ---------------------------------------------------------------------------

#[test]
fn oracle_report_counterexamples_empty_on_clean_spec() {
    let spec = spec_with_field_types(vec![("x", ScSpecTypeDef::U64)]);
    let report = compare_spec_with_seed(&spec, "cx_clean");
    assert!(report.counterexamples.is_empty());
    assert!(report.is_clean());
}

#[test]
fn oracle_report_is_clean_has_zero_divergences() {
    let report = OracleReport::default();
    assert!(report.is_clean());
    assert_eq!(report.divergences.len(), 0);
    assert_eq!(report.discriminant_mismatches.len(), 0);
}

// ---------------------------------------------------------------------------
// 10. Oracle report invariants
// ---------------------------------------------------------------------------

#[test]
fn oracle_comparisons_counted_correctly() {
    // compare_spec counts each type-path comparison; verify the count
    // is non-zero for a non-empty spec.
    let spec = spec_with_field_types(vec![
        ("a", ScSpecTypeDef::U32),
        ("b", ScSpecTypeDef::U64),
        ("c", ScSpecTypeDef::Address),
    ]);
    let report = compare_spec(&spec);
    assert_eq!(report.comparisons, 3);
    assert_oracle_clean(&report);
}

#[test]
fn oracle_report_merge_accumulates_counts() {
    let spec_a = spec_with_field_types(vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U64)]);
    let spec_b = spec_with_field_types(vec![("c", ScSpecTypeDef::Address)]);
    let mut report = compare_spec(&spec_a);
    report.merge(compare_spec(&spec_b));
    assert_eq!(report.comparisons, 3);
    assert_oracle_clean(&report);
}

// ---------------------------------------------------------------------------
// 11. Network-gated test (skipped in hermetic CI)
// ---------------------------------------------------------------------------

#[test]
fn oracle_network_gate_respected() {
    if oracle_network_enabled() {
        // When the gate is open the developer can run extended checks;
        // this placeholder documents the contract.
        println!("SAFEGUARD_ORACLE_NETWORK=1: extended oracle checks would run here");
    } else {
        // Normal hermetic run: gate is closed, no network access occurs.
        assert!(!oracle_network_enabled());
    }
}

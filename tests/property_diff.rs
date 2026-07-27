//! Property-based tests for the diff rules (issue #130).
//!
//! Generates random spec pairs with nested and cyclic dependencies, and verifies
//! self-comparison, mirroring, target validity, target convention, and cascade termination.

use std::collections::HashMap;
use proptest::prelude::*;
use soroban_upgrade_safeguard::diff::{compare, compare_with_policy};
use soroban_upgrade_safeguard::limits::ResourcePolicy;
use soroban_upgrade_safeguard::spec::ContractSpec;
use stellar_xdr::curr::{
    ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtEnumV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructV0,
    ScSpecUdtUnionV0, ScSpecUdtUnionCaseV0,
};

fn leaf_type_strategy() -> impl Strategy<Value = ScSpecTypeDef> {
    prop_oneof![
        Just(ScSpecTypeDef::Val),
        Just(ScSpecTypeDef::Bool),
        Just(ScSpecTypeDef::Void),
        Just(ScSpecTypeDef::Error),
        Just(ScSpecTypeDef::U32),
        Just(ScSpecTypeDef::I32),
        Just(ScSpecTypeDef::U64),
        Just(ScSpecTypeDef::I64),
        Just(ScSpecTypeDef::U128),
        Just(ScSpecTypeDef::I128),
        Just(ScSpecTypeDef::U256),
        Just(ScSpecTypeDef::I256),
        Just(ScSpecTypeDef::Bytes),
        Just(ScSpecTypeDef::String),
        Just(ScSpecTypeDef::Timepoint),
        Just(ScSpecTypeDef::Duration),
        Just(ScSpecTypeDef::Address),
    ]
}

fn type_def_strategy(udt_names: Vec<String>) -> impl Strategy<Value = ScSpecTypeDef> {
    let leaf = leaf_type_strategy();
    let udt_strategy = if udt_names.is_empty() {
        leaf.boxed()
    } else {
        prop_oneof![
            leaf,
            prop::sample::select(udt_names).prop_map(|name| ScSpecTypeDef::Udt(stellar_xdr::curr::ScSpecTypeUdt {
                name: name.try_into().unwrap()
            }))
        ].boxed()
    };

    udt_strategy.prop_recursive(
        3,   // Max depth (bounded to run fast in CI)
        32,  // Max size
        3,   // Max branching factor
        move |inner| {
            prop_oneof![
                inner.clone().prop_map(|t| ScSpecTypeDef::Option(Box::new(stellar_xdr::curr::ScSpecTypeOption {
                    value_type: Box::new(t)
                }))),
                inner.clone().prop_map(|t| ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
                    element_type: Box::new(t)
                }))),
                (inner.clone(), inner.clone()).prop_map(|(k, v)| ScSpecTypeDef::Map(Box::new(stellar_xdr::curr::ScSpecTypeMap {
                    key_type: Box::new(k),
                    value_type: Box::new(v)
                }))),
                prop::collection::vec(inner.clone(), 0..3).prop_map(|types| ScSpecTypeDef::Tuple(Box::new(stellar_xdr::curr::ScSpecTypeTuple {
                    value_types: types.try_into().unwrap()
                }))),
            ]
        }
    )
}

fn functions_map_strategy(udt_names: Vec<String>) -> impl Strategy<Value = HashMap<String, ScSpecFunctionV0>> {
    let function_strategy = (
        "[a-z][a-z0-9_]{0,10}", // name
        prop::collection::vec(
            (
                "[a-z][a-z0-9_]{0,10}", // param name
                type_def_strategy(udt_names.clone())
            ).prop_map(|(name, type_)| stellar_xdr::curr::ScSpecFunctionInputV0 {
                doc: stellar_xdr::curr::StringM::default(),
                name: name.try_into().unwrap(),
                type_,
            }),
            0..3
        ),
        prop::collection::vec(type_def_strategy(udt_names.clone()), 0..2)
    ).prop_map(|(name, inputs, outputs)| (
        name.clone(),
        ScSpecFunctionV0 {
            doc: stellar_xdr::curr::StringM::default(),
            name: name.try_into().unwrap(),
            inputs: inputs.try_into().unwrap(),
            outputs: outputs.try_into().unwrap(),
        }
    ));

    prop::collection::vec(function_strategy, 0..3)
        .prop_map(|list| list.into_iter().collect::<HashMap<_, _>>())
}

fn structs_map_strategy(
    struct_names: Vec<String>,
    udt_names: Vec<String>,
) -> impl Strategy<Value = HashMap<String, ScSpecUdtStructV0>> {
    let udt_names_clone = udt_names.clone();
    let list_strategy = struct_names.into_iter().map(move |name| {
        let udt_names_for_fields = udt_names_clone.clone();
        prop::collection::vec(
            (
                "[a-z][a-z0-9_]{0,10}", // field name
                type_def_strategy(udt_names_for_fields)
            ).prop_map(|(fname, type_)| stellar_xdr::curr::ScSpecUdtStructFieldV0 {
                doc: stellar_xdr::curr::StringM::default(),
                name: fname.try_into().unwrap(),
                type_,
            }),
            0..3
        ).prop_map(move |fields| {
            (
                name.clone(),
                ScSpecUdtStructV0 {
                    doc: stellar_xdr::curr::StringM::default(),
                    lib: stellar_xdr::curr::StringM::default(),
                    name: name.clone().try_into().unwrap(),
                    fields: fields.try_into().unwrap(),
                }
            )
        })
    }).collect::<Vec<_>>();

    if list_strategy.is_empty() {
        Just(HashMap::new()).boxed()
    } else {
        list_strategy.into_iter()
            .fold(Just(Vec::new()).boxed(), |acc, item| {
                (acc, item).prop_map(|(mut list, val)| {
                    list.push(val);
                    list
                }).boxed()
            })
            .prop_map(|list| list.into_iter().collect::<HashMap<_, _>>())
            .boxed()
    }
}

fn enums_map_strategy(
    enum_names: Vec<String>,
) -> impl Strategy<Value = HashMap<String, ScSpecUdtEnumV0>> {
    let list_strategy = enum_names.into_iter().map(|name| {
        prop::collection::vec(
            (
                "[A-Z][a-zA-Z0-9_]{0,10}", // case name
                any::<u32>()
            ).prop_map(|(cname, value)| stellar_xdr::curr::ScSpecUdtEnumCaseV0 {
                doc: stellar_xdr::curr::StringM::default(),
                name: cname.try_into().unwrap(),
                value,
            }),
            1..3
        ).prop_map(move |cases| {
            (
                name.clone(),
                ScSpecUdtEnumV0 {
                    doc: stellar_xdr::curr::StringM::default(),
                    lib: stellar_xdr::curr::StringM::default(),
                    name: name.clone().try_into().unwrap(),
                    cases: cases.try_into().unwrap(),
                }
            )
        })
    }).collect::<Vec<_>>();

    if list_strategy.is_empty() {
        Just(HashMap::new()).boxed()
    } else {
        list_strategy.into_iter()
            .fold(Just(Vec::new()).boxed(), |acc, item| {
                (acc, item).prop_map(|(mut list, val)| {
                    list.push(val);
                    list
                }).boxed()
            })
            .prop_map(|list| list.into_iter().collect::<HashMap<_, _>>())
            .boxed()
    }
}

fn unions_map_strategy(
    union_names: Vec<String>,
    udt_names: Vec<String>,
) -> impl Strategy<Value = HashMap<String, ScSpecUdtUnionV0>> {
    let udt_names_clone = udt_names.clone();
    let list_strategy = union_names.into_iter().map(move |name| {
        let udt_names_for_cases = udt_names_clone.clone();
        prop::collection::vec(
            prop_oneof![
                "[A-Z][a-zA-Z0-9_]{0,10}".prop_map(|cname| ScSpecUdtUnionCaseV0::VoidV0(stellar_xdr::curr::ScSpecUdtUnionCaseVoidV0 {
                    doc: stellar_xdr::curr::StringM::default(),
                    name: cname.try_into().unwrap(),
                })),
                (
                    "[A-Z][a-zA-Z0-9_]{0,10}",
                    prop::collection::vec(type_def_strategy(udt_names_for_cases.clone()), 0..2)
                ).prop_map(|(cname, types)| ScSpecUdtUnionCaseV0::TupleV0(stellar_xdr::curr::ScSpecUdtUnionCaseTupleV0 {
                    doc: stellar_xdr::curr::StringM::default(),
                    name: cname.try_into().unwrap(),
                    type_: types.try_into().unwrap(),
                }))
            ],
            1..3
        ).prop_map(move |cases| {
            (
                name.clone(),
                ScSpecUdtUnionV0 {
                    doc: stellar_xdr::curr::StringM::default(),
                    lib: stellar_xdr::curr::StringM::default(),
                    name: name.clone().try_into().unwrap(),
                    cases: cases.try_into().unwrap(),
                }
            )
        })
    }).collect::<Vec<_>>();

    if list_strategy.is_empty() {
        Just(HashMap::new()).boxed()
    } else {
        list_strategy.into_iter()
            .fold(Just(Vec::new()).boxed(), |acc, item| {
                (acc, item).prop_map(|(mut list, val)| {
                    list.push(val);
                    list
                }).boxed()
            })
            .prop_map(|list| list.into_iter().collect::<HashMap<_, _>>())
            .boxed()
    }
}

fn error_enums_map_strategy(
    error_names: Vec<String>,
) -> impl Strategy<Value = HashMap<String, ScSpecUdtErrorEnumV0>> {
    let list_strategy = error_names.into_iter().map(|name| {
        prop::collection::vec(
            (
                "[A-Z][a-zA-Z0-9_]{0,10}", // case name
                any::<u32>()
            ).prop_map(|(cname, value)| stellar_xdr::curr::ScSpecUdtErrorEnumCaseV0 {
                doc: stellar_xdr::curr::StringM::default(),
                name: cname.try_into().unwrap(),
                value,
            }),
            1..3
        ).prop_map(move |cases| {
            (
                name.clone(),
                ScSpecUdtErrorEnumV0 {
                    doc: stellar_xdr::curr::StringM::default(),
                    lib: stellar_xdr::curr::StringM::default(),
                    name: name.clone().try_into().unwrap(),
                    cases: cases.try_into().unwrap(),
                }
            )
        })
    }).collect::<Vec<_>>();

    if list_strategy.is_empty() {
        Just(HashMap::new()).boxed()
    } else {
        list_strategy.into_iter()
            .fold(Just(Vec::new()).boxed(), |acc, item| {
                (acc, item).prop_map(|(mut list, val)| {
                    list.push(val);
                    list
                }).boxed()
            })
            .prop_map(|list| list.into_iter().collect::<HashMap<_, _>>())
            .boxed()
    }
}

fn contract_spec_strategy() -> impl Strategy<Value = ContractSpec> {
    let udt_names_strategy = prop::collection::hash_set("[A-Z][a-zA-Z0-9_]{0,10}", 1..6);

    udt_names_strategy.prop_flat_map(|names| {
        let names_list: Vec<String> = names.into_iter().collect();
        let name_assignments = prop::collection::vec(
            (
                prop::sample::select(names_list.clone()),
                prop_oneof![Just(0), Just(1), Just(2), Just(3)]
            ),
            1..names_list.len() + 1
        );

        name_assignments.prop_flat_map(move |assignments| {
            let mut struct_names = Vec::new();
            let mut enum_names = Vec::new();
            let mut union_names = Vec::new();
            let mut error_names = Vec::new();

            for (name, kind) in assignments {
                match kind {
                    0 => struct_names.push(name),
                    1 => enum_names.push(name),
                    2 => union_names.push(name),
                    _ => error_names.push(name),
                }
            }
            struct_names.sort(); struct_names.dedup();
            enum_names.sort(); enum_names.dedup();
            union_names.sort(); union_names.dedup();
            error_names.sort(); error_names.dedup();

            let functions_strategy = functions_map_strategy(names_list.clone());
            let structs_strategy = structs_map_strategy(struct_names, names_list.clone());
            let enums_strategy = enums_map_strategy(enum_names);
            let unions_strategy = unions_map_strategy(union_names, names_list.clone());
            let error_enums_strategy = error_enums_map_strategy(error_names);

            (functions_strategy, structs_strategy, enums_strategy, unions_strategy, error_enums_strategy)
                .prop_map(|(functions, structs, enums, unions, error_enums)| ContractSpec {
                    functions,
                    structs,
                    enums,
                    unions,
                    error_enums,
                })
        })
    })
}

fn mirror_category(category: &str) -> &str {
    match category {
        "Function Removed" => "Function Added",
        "Function Added" => "Function Removed",
        "Struct Removed" => "Struct Added",
        "Struct Added" => "Struct Removed",
        "Enum Removed" => "Enum Added",
        "Enum Added" => "Enum Removed",
        "Union Removed" => "Union Added",
        "Union Added" => "Union Removed",
        "Error Enum Removed" => "Error Enum Added",
        "Error Enum Added" => "Error Enum Removed",

        "Struct Field Removed" => "Struct Field Added",
        "Struct Field Added" => "Struct Field Removed",
        "Enum Case Removed" => "Enum Case Added",
        "Enum Case Added" => "Enum Case Removed",
        "Union Case Removed" => "Union Case Added",
        "Union Case Added" => "Union Case Removed",
        "Error Enum Case Removed" => "Error Enum Case Added",
        "Error Enum Case Added" => "Error Enum Case Removed",
        other => other,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_diff_properties(
        spec_a in contract_spec_strategy(),
        spec_b in contract_spec_strategy(),
    ) {
        // --- Property 1: Self-comparison produces no findings ---
        let report_aa = compare(&spec_a, &spec_a);
        assert!(
            report_aa.findings.is_empty(),
            "Comparing spec_a to itself must produce no findings, got: {:?}",
            report_aa.findings
        );

        let report_bb = compare(&spec_b, &spec_b);
        assert!(
            report_bb.findings.is_empty(),
            "Comparing spec_b to itself must produce no findings, got: {:?}",
            report_bb.findings
        );

        // --- Property 2: Mirroring / Directionality ---
        let report_ab = compare(&spec_a, &spec_b);
        let report_ba = compare(&spec_b, &spec_a);

        for f_ab in &report_ab.findings {
            if f_ab.category == "Cascading Layout Break" {
                continue;
            }
            let mirrored_cat = mirror_category(&f_ab.category);
            let found = report_ba.findings.iter().any(|f_ba| {
                let base_cat_ba = &f_ba.category;
                let cat_matches = base_cat_ba == mirrored_cat ||
                    (f_ab.category.starts_with("Parameter Type") && base_cat_ba.starts_with("Parameter Type")) ||
                    (f_ab.category.starts_with("Return Type") && base_cat_ba.starts_with("Return Type")) ||
                    (f_ab.category.starts_with("Struct Field Type") && base_cat_ba.starts_with("Struct Field Type")) ||
                    (f_ab.category.starts_with("Union Case Type") && base_cat_ba.starts_with("Union Case Type"));

                let target_matches = match (&f_ab.target, &f_ba.target) {
                    (Some(t_ab), Some(t_ba)) => {
                        if f_ab.category.contains("Renamed") {
                            true
                        } else if t_ab == t_ba {
                            true
                        } else {
                            let suffix_ab = t_ab.split_once('.').map(|(_, s)| s).unwrap_or(t_ab);
                            let suffix_ba = t_ba.split_once('.').map(|(_, s)| s).unwrap_or(t_ba);
                            suffix_ab == suffix_ba
                        }
                    }
                    (None, None) => true,
                    _ => false,
                };

                cat_matches && target_matches
            });
            assert!(
                found,
                "Finding {:?} in A->B not found mirrored in B->A. Findings in B->A: {:?}",
                f_ab,
                report_ba.findings
            );
        }

        // --- Property 3: Target validity ---
        // Every finding with a type_name must name a type that exists in one of the specs.
        for f in report_ab.findings.iter().chain(report_ba.findings.iter()) {
            if let Some(ref type_name) = f.type_name {
                let exists = spec_a.structs.contains_key(type_name) || spec_b.structs.contains_key(type_name) ||
                    spec_a.enums.contains_key(type_name) || spec_b.enums.contains_key(type_name) ||
                    spec_a.unions.contains_key(type_name) || spec_b.unions.contains_key(type_name) ||
                    spec_a.error_enums.contains_key(type_name) || spec_b.error_enums.contains_key(type_name);
                assert!(
                    exists,
                    "Finding has type_name '{}' which does not exist in either spec! Finding: {:?}",
                    type_name,
                    f
                );
            }
        }

        // --- Property 4: Target convention ---
        // Verify target format (e.g. member level findings contain a dot).
        for f in report_ab.findings.iter().chain(report_ba.findings.iter()) {
            if let Some(ref target) = f.target {
                if f.category.contains("Parameter") || f.category.contains("Field") || f.category.contains("Case") {
                    if !f.category.contains("Added") && !f.category.contains("Removed") && !f.category.contains("Renamed") {
                        assert!(
                            target.contains('.'),
                            "Member-level finding target '{}' must contain '.'! Category: {}",
                            target,
                            f.category
                        );
                    }
                }
            }
        }

        // --- Property 5: Cascade termination ---
        // Run compare with default policy to verify cascade detection terminates on cyclic graphs.
        let policy = ResourcePolicy::default();
        let _ = compare_with_policy(&spec_a, &spec_b, &policy);
    }
}

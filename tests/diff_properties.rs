//! Property-based tests for the diff rules (issue #130).
//!
//! The diff rules in `src/diff.rs` are tested by example: each unit test
//! constructs a specific pair of specs and asserts on a specific finding. These
//! tests instead generate arbitrary `ContractSpec` pairs and assert the
//! properties that should hold for *every* input pair:
//!
//! 1. Comparing a spec against itself produces no findings.
//! 2. Comparing A to B and then B to A produces mirrored findings for every
//!    name-addressed entity: a removal in one direction is an addition in the
//!    other, and a modification is reported in both directions.
//! 3. Every finding with a `type_name` names a type that exists in one of the
//!    two specs.
//! 4. Every finding's `target` follows the documented suppression convention
//!    for its category: a bare entity name for whole-entity findings, or
//!    `Entity.member` for member-level findings, with both parts resolvable to
//!    a real entity in one of the specs.
//! 5. Cascade detection terminates, including on cyclic type graphs, and every
//!    cascade finding is internally consistent.
//!
//! On failure, proptest prints a reproducible seed; rerun the failing test with
//! that seed to investigate the counterexample.
//!
//! ## Deliberate generator restriction
//!
//! Function parameters and return types are generated from primitive types only,
//! never user-defined types. `classify_finding_axes` walks user-defined types
//! recursively via `is_type_used_in_functions`/`is_type_used_in_events`, and a
//! mutually recursive type graph makes that walk recurse forever (stack
//! overflow). Type-level nesting and cycles are therefore exercised through
//! struct fields and union case payloads, which the cascade detector visits with
//! an explicit visited-set guard. The recursion defect itself is tracked as
//! issue #431 rather than worked around here.

use std::collections::{BTreeMap, HashSet};

use proptest::prelude::*;
use soroban_upgrade_safeguard::diff::{compare, DiffReport};
use soroban_upgrade_safeguard::spec::ContractSpec;
use soroban_upgrade_safeguard::Finding;
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeBytesN, ScSpecTypeDef, ScSpecTypeMap,
    ScSpecTypeOption, ScSpecTypeResult, ScSpecTypeTuple, ScSpecTypeUdt, ScSpecTypeVec,
    ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0, ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0,
    ScSpecUdtStructFieldV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0,
    ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0, StringM, VecM,
};

// ---------------------------------------------------------------------------
// Deterministic helpers shared with the hand-written cycle tests.
// ---------------------------------------------------------------------------

fn udt(name: &str) -> ScSpecTypeDef {
    ScSpecTypeDef::Udt(ScSpecTypeUdt {
        name: name.try_into().expect("generated type name fits"),
    })
}

fn option_of(inner: ScSpecTypeDef) -> ScSpecTypeDef {
    ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
        value_type: Box::new(inner),
    }))
}

fn insert_struct(spec: &mut ContractSpec, name: &str, fields: Vec<(&str, ScSpecTypeDef)>) {
    let xdr_fields: Vec<ScSpecUdtStructFieldV0> = fields
        .into_iter()
        .map(|(field_name, type_)| ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: field_name.try_into().expect("field name fits"),
            type_,
        })
        .collect();
    spec.structs.insert(
        name.to_string(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().expect("type name fits"),
            fields: VecM::try_from(xdr_fields).expect("field count within XDR limit"),
        },
    );
}

// ---------------------------------------------------------------------------
// ContractSpec generators.
// ---------------------------------------------------------------------------

/// The definition generated for one named type. The name itself is implied by
/// the slot's index in the generated pool.
#[derive(Debug, Clone)]
enum TypeShape {
    Struct(Vec<ScSpecUdtStructFieldV0>),
    Enum(Vec<ScSpecUdtEnumCaseV0>),
    Union(Vec<ScSpecUdtUnionCaseV0>),
    ErrorEnum(Vec<ScSpecUdtErrorEnumCaseV0>),
}

/// A bare primitive `ScSpecTypeDef`, never a user-defined type reference.
fn primitive_type() -> BoxedStrategy<ScSpecTypeDef> {
    prop_oneof![
        Just(ScSpecTypeDef::Val),
        Just(ScSpecTypeDef::Bool),
        Just(ScSpecTypeDef::Void),
        Just(ScSpecTypeDef::Error),
        Just(ScSpecTypeDef::U32),
        Just(ScSpecTypeDef::I32),
        Just(ScSpecTypeDef::U64),
        Just(ScSpecTypeDef::I64),
        Just(ScSpecTypeDef::Timepoint),
        Just(ScSpecTypeDef::Duration),
        Just(ScSpecTypeDef::U128),
        Just(ScSpecTypeDef::I128),
        Just(ScSpecTypeDef::U256),
        Just(ScSpecTypeDef::I256),
        Just(ScSpecTypeDef::Bytes),
        Just(ScSpecTypeDef::String),
        Just(ScSpecTypeDef::Symbol),
        Just(ScSpecTypeDef::Address),
        (1u32..=32).prop_map(|n| ScSpecTypeDef::BytesN(ScSpecTypeBytesN { n })),
    ]
    .boxed()
}

/// A `ScSpecTypeDef` that may nest containers and reference any of the
/// `reachable` user-defined type names. `depth` bounds the container nesting so
/// generated specs stay small enough for CI.
fn any_type_def(reachable: Vec<String>, depth: u32) -> BoxedStrategy<ScSpecTypeDef> {
    let leaf = primitive_type();
    let udt = if reachable.is_empty() {
        leaf.clone()
    } else {
        prop::sample::select(reachable.clone())
            .prop_map(|name| {
                ScSpecTypeDef::Udt(ScSpecTypeUdt {
                    name: name.try_into().expect("type name fits"),
                })
            })
            .boxed()
    };
    let base = prop_oneof![leaf, udt].boxed();

    if depth == 0 {
        base
    } else {
        let inner = any_type_def(reachable.clone(), depth - 1);
        prop_oneof![
            base,
            inner
                .clone()
                .prop_map(
                    |value_type| ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
                        value_type: Box::new(value_type),
                    }))
                ),
            inner
                .clone()
                .prop_map(|element_type| ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                    element_type: Box::new(element_type),
                }))),
            (inner.clone(), inner.clone()).prop_map(|(key_type, value_type)| {
                ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
                    key_type: Box::new(key_type),
                    value_type: Box::new(value_type),
                }))
            }),
            (inner.clone(), inner.clone()).prop_map(|(ok_type, error_type)| {
                ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
                    ok_type: Box::new(ok_type),
                    error_type: Box::new(error_type),
                }))
            }),
            prop::collection::vec(inner, 0..=2).prop_map(|value_types| {
                ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
                    value_types: VecM::try_from(value_types).expect("tuple size within XDR limit"),
                }))
            }),
        ]
        .boxed()
    }
}

/// The definition for the type at `type_index`. `reachable` is the set of type
/// names this type may reference; the caller passes the names defined so far
/// (including the type's own name), which keeps the reference graph free of
/// mutually recursive edges while still allowing self-cycles and arbitrary
/// nesting.
fn type_shape_strategy(
    type_index: usize,
    reachable: Vec<String>,
) -> impl Strategy<Value = TypeShape> {
    let struct_reachable = reachable.clone();
    let union_reachable = reachable;
    prop_oneof![
        // Struct with fields.
        (0..=3usize).prop_flat_map(move |num_fields| {
            prop::collection::vec(any_type_def(struct_reachable.clone(), 3), num_fields).prop_map(
                move |field_types| {
                    TypeShape::Struct(
                        field_types
                            .into_iter()
                            .enumerate()
                            .map(|(i, type_)| ScSpecUdtStructFieldV0 {
                                doc: StringM::default(),
                                name: format!("Field_{}_{}", type_index, i)
                                    .try_into()
                                    .expect("field name fits"),
                                type_,
                            })
                            .collect(),
                    )
                },
            )
        }),
        // Enum with cases.
        (1..=3usize).prop_flat_map(move |num_cases| {
            prop::collection::vec(any::<u32>(), num_cases).prop_map(move |values| {
                let cases: Vec<ScSpecUdtEnumCaseV0> = values
                    .into_iter()
                    .enumerate()
                    .map(|(i, value)| ScSpecUdtEnumCaseV0 {
                        doc: StringM::default(),
                        name: format!("Case_{}_{}", type_index, i)
                            .try_into()
                            .expect("case name fits"),
                        value,
                    })
                    .collect();
                TypeShape::Enum(cases)
            })
        }),
        // Union with void and tuple cases.
        (1..=3usize).prop_flat_map(move |num_cases| {
            prop::collection::vec(
                prop::collection::vec(any_type_def(union_reachable.clone(), 3), 0..=2),
                num_cases,
            )
            .prop_map(move |case_payloads| {
                let cases: Vec<ScSpecUdtUnionCaseV0> = case_payloads
                    .into_iter()
                    .enumerate()
                    .map(|(i, payload)| {
                        let case_name: StringM<60> = format!("UCase_{}_{}", type_index, i)
                            .try_into()
                            .expect("case name fits");
                        if payload.is_empty() {
                            ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                                doc: StringM::default(),
                                name: case_name,
                            })
                        } else {
                            ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                                doc: StringM::default(),
                                name: case_name,
                                type_: VecM::try_from(payload)
                                    .expect("case payload within XDR limit"),
                            })
                        }
                    })
                    .collect();
                TypeShape::Union(cases)
            })
        }),
        // Error enum with cases.
        (1..=3usize).prop_flat_map(move |num_cases| {
            prop::collection::vec(any::<u32>(), num_cases).prop_map(move |values| {
                let cases: Vec<ScSpecUdtErrorEnumCaseV0> = values
                    .into_iter()
                    .enumerate()
                    .map(|(i, value)| ScSpecUdtErrorEnumCaseV0 {
                        doc: StringM::default(),
                        name: format!("ECase_{}_{}", type_index, i)
                            .try_into()
                            .expect("case name fits"),
                        value,
                    })
                    .collect();
                TypeShape::ErrorEnum(cases)
            })
        }),
    ]
}

/// The function at `function_index`, named `func{function_index}` with a small
/// number of primitive parameters and at most one primitive return value.
fn function_strategy(function_index: usize) -> impl Strategy<Value = (String, ScSpecFunctionV0)> {
    (0..=3usize).prop_flat_map(move |num_inputs| {
        (
            prop::collection::vec(primitive_type(), num_inputs),
            prop::collection::vec(primitive_type(), 0..=1),
        )
            .prop_map(move |(input_types, output_types)| {
                let name = format!("func{}", function_index);
                let inputs: Vec<ScSpecFunctionInputV0> = input_types
                    .into_iter()
                    .enumerate()
                    .map(|(i, type_)| ScSpecFunctionInputV0 {
                        doc: StringM::default(),
                        name: format!("arg{}", i).try_into().expect("arg name fits"),
                        type_,
                    })
                    .collect();
                let function = ScSpecFunctionV0 {
                    doc: StringM::default(),
                    name: name.clone().try_into().expect("function name fits"),
                    inputs: VecM::try_from(inputs).expect("input count within XDR limit"),
                    outputs: VecM::try_from(output_types).expect("output count within XDR limit"),
                };
                (name, function)
            })
    })
}

/// Combine a list of strategies producing `T` into a single strategy producing
/// a `Vec<T>` of the same length, in order.
fn vec_of_strategies<T: std::fmt::Debug + Clone + 'static>(
    strategies: Vec<BoxedStrategy<T>>,
) -> impl Strategy<Value = Vec<T>> {
    strategies
        .into_iter()
        .fold(Just(Vec::new()).boxed(), |acc, item| {
            (acc, item)
                .prop_map(|(mut list, value)| {
                    list.push(value);
                    list
                })
                .boxed()
        })
}

/// A strategy for a complete `ContractSpec`: 0-4 user-defined types (each an
/// independent kind) plus 0-2 functions.
fn contract_spec_strategy() -> impl Strategy<Value = ContractSpec> {
    (0..=4usize).prop_flat_map(|num_types| {
        let pool: Vec<String> = (0..num_types).map(|i| format!("Type{}", i)).collect();
        // Type i may reference Type 0..=i, so the reference graph is acyclic
        // except for self-references.
        let shape_strategies: Vec<BoxedStrategy<TypeShape>> = (0..num_types)
            .map(|i| type_shape_strategy(i, pool[..=i].to_vec()).boxed())
            .collect();
        let shapes_strategy = vec_of_strategies(shape_strategies);
        let functions_strategy = (0..=2usize).prop_flat_map(|num_functions| {
            let functions: Vec<BoxedStrategy<(String, ScSpecFunctionV0)>> = (0..num_functions)
                .map(function_strategy)
                .map(|s| s.boxed())
                .collect();
            vec_of_strategies(functions)
        });
        (shapes_strategy, functions_strategy)
            .prop_map(move |(shapes, functions)| assemble_spec(&pool, &shapes, functions))
    })
}

fn assemble_spec(
    pool: &[String],
    shapes: &[TypeShape],
    functions: Vec<(String, ScSpecFunctionV0)>,
) -> ContractSpec {
    let mut spec = ContractSpec::default();
    for (name, shape) in pool.iter().zip(shapes.iter()) {
        let name_m: StringM<60> = name.clone().try_into().expect("type name fits");
        match shape {
            TypeShape::Struct(fields) => {
                spec.structs.insert(
                    name.clone(),
                    ScSpecUdtStructV0 {
                        doc: StringM::default(),
                        lib: StringM::default(),
                        name: name_m,
                        fields: VecM::try_from(fields.clone())
                            .expect("field count within XDR limit"),
                    },
                );
            }
            TypeShape::Enum(cases) => {
                spec.enums.insert(
                    name.clone(),
                    ScSpecUdtEnumV0 {
                        doc: StringM::default(),
                        lib: StringM::default(),
                        name: name_m,
                        cases: VecM::try_from(cases.clone()).expect("case count within XDR limit"),
                    },
                );
            }
            TypeShape::Union(cases) => {
                spec.unions.insert(
                    name.clone(),
                    ScSpecUdtUnionV0 {
                        doc: StringM::default(),
                        lib: StringM::default(),
                        name: name_m,
                        cases: VecM::try_from(cases.clone()).expect("case count within XDR limit"),
                    },
                );
            }
            TypeShape::ErrorEnum(cases) => {
                spec.error_enums.insert(
                    name.clone(),
                    ScSpecUdtErrorEnumV0 {
                        doc: StringM::default(),
                        lib: StringM::default(),
                        name: name_m,
                        cases: VecM::try_from(cases.clone()).expect("case count within XDR limit"),
                    },
                );
            }
        }
    }
    spec.functions = functions.into_iter().collect();
    spec
}

// ---------------------------------------------------------------------------
// Property helpers.
// ---------------------------------------------------------------------------

/// How a finding's category participates in the mirroring property.
///
/// Add/remove categories address an entity by name and therefore mirror
/// exactly between directions. The "same" categories also address a stable,
/// name-addressed entity and must be reported identically in both directions.
/// Categories that report a *positional* entity (struct fields, union cases,
/// renamed/retargeted parameters) or that are asymmetric by construction
/// (cascades) are intentionally excluded: their targets are direction-dependent
/// by design. They are still covered by the target-convention property.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MirrorClass {
    Added,
    Removed,
    Same,
}

fn mirror_class(category: &str) -> Option<MirrorClass> {
    match category {
        "Function Added"
        | "Struct Added"
        | "Enum Added"
        | "Union Added"
        | "Error Enum Added"
        | "Enum Case Added"
        | "Error Enum Case Added" => Some(MirrorClass::Added),
        "Function Removed"
        | "Struct Removed"
        | "Enum Removed"
        | "Union Removed"
        | "Error Enum Removed"
        | "Enum Case Removed"
        | "Error Enum Case Removed" => Some(MirrorClass::Removed),
        "Function Documentation Changed"
        | "Function Signature Changed"
        | "Parameter Reordered"
        | "Return Type Changed"
        | "Struct Documentation Changed"
        | "Enum Documentation Changed"
        | "Enum Case Value Changed"
        | "Error Enum Case Value Changed"
        | "Type Kind Changed" => Some(MirrorClass::Same),
        _ => None,
    }
}

fn mirrored_class(class: MirrorClass) -> MirrorClass {
    match class {
        MirrorClass::Added => MirrorClass::Removed,
        MirrorClass::Removed => MirrorClass::Added,
        MirrorClass::Same => MirrorClass::Same,
    }
}

/// The multiset of `(class, target)` for the name-addressed findings in a
/// report.
fn stable_signature(report: &DiffReport) -> BTreeMap<(MirrorClass, String), usize> {
    let mut signature = BTreeMap::new();
    for finding in &report.findings {
        if let Some(class) = mirror_class(&finding.category) {
            let target = finding
                .target
                .clone()
                .expect("name-addressed findings always carry a target");
            *signature.entry((class, target)).or_insert(0) += 1;
        }
    }
    signature
}

fn type_exists(spec: &ContractSpec, name: &str) -> bool {
    spec.structs().contains_key(name)
        || spec.enums().contains_key(name)
        || spec.unions().contains_key(name)
        || spec.error_enums().contains_key(name)
}

fn function_exists(spec: &ContractSpec, name: &str) -> bool {
    spec.functions().contains_key(name)
}

fn type_has_member(spec: &ContractSpec, type_name: &str, member: &str) -> bool {
    if let Some(struct_def) = spec.structs().get(type_name) {
        return struct_def
            .fields
            .iter()
            .any(|f| f.name.to_string() == member);
    }
    if let Some(enum_def) = spec.enums().get(type_name) {
        return enum_def.cases.iter().any(|c| c.name.to_string() == member);
    }
    if let Some(union_def) = spec.unions().get(type_name) {
        return union_def.cases.iter().any(|c| match c {
            ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string() == member,
            ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string() == member,
        });
    }
    if let Some(error_def) = spec.error_enums().get(type_name) {
        return error_def.cases.iter().any(|c| c.name.to_string() == member);
    }
    false
}

fn function_has_param(spec: &ContractSpec, fn_name: &str, param: &str) -> bool {
    spec.functions()
        .get(fn_name)
        .map(|f| f.inputs.iter().any(|i| i.name.to_string() == param))
        .unwrap_or(false)
}

/// A `target` is well-formed when it is either a bare function/type name that
/// exists in one of the specs, or `Entity.member` where `Entity` is a real
/// function or type and `member` is one of its parameters, fields, or cases.
fn target_is_well_formed(target: &str, old: &ContractSpec, new: &ContractSpec) -> bool {
    match target.split_once('.') {
        None => {
            function_exists(old, target)
                || function_exists(new, target)
                || type_exists(old, target)
                || type_exists(new, target)
        }
        Some((entity, member)) => {
            if function_exists(old, entity) || function_exists(new, entity) {
                function_has_param(old, entity, member) || function_has_param(new, entity, member)
            } else {
                (type_exists(old, entity) && type_has_member(old, entity, member))
                    || (type_exists(new, entity) && type_has_member(new, entity, member))
            }
        }
    }
}

/// All cascade findings must be critical, name types that exist in one of the
/// specs, and carry a unique `(type_name, root_target)` key.
fn cascade_findings_are_consistent(
    report: &DiffReport,
    old: &ContractSpec,
    new: &ContractSpec,
) -> bool {
    let cascades: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.category == "Cascading Layout Break")
        .collect();
    let mut keys = HashSet::new();
    for finding in &cascades {
        if finding.severity != soroban_upgrade_safeguard::Severity::Critical {
            return false;
        }
        let (Some(type_name), Some(root_target)) = (&finding.type_name, &finding.root_target)
        else {
            return false;
        };
        if !type_exists(old, type_name) && !type_exists(new, type_name) {
            return false;
        }
        if !type_exists(old, root_target) && !type_exists(new, root_target) {
            return false;
        }
        if !keys.insert((type_name.clone(), root_target.clone())) {
            return false;
        }
    }
    true
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        .. ProptestConfig::default()
    })]

    #[test]
    fn diff_properties_hold(
        spec_a in contract_spec_strategy(),
        spec_b in contract_spec_strategy(),
    ) {
        // Property 1: comparing a spec against itself produces no findings.
        let report_aa = compare(&spec_a, &spec_a);
        assert!(
            report_aa.findings.is_empty(),
            "comparing spec_a to itself produced findings: {:?}",
            report_aa.findings
        );
        let report_bb = compare(&spec_b, &spec_b);
        assert!(
            report_bb.findings.is_empty(),
            "comparing spec_b to itself produced findings: {:?}",
            report_bb.findings
        );

        let report_ab = compare(&spec_a, &spec_b);
        let report_ba = compare(&spec_b, &spec_a);

        // Property 2: name-addressed findings mirror between directions. A
        // removal in one direction is an addition in the other, and a
        // modification is reported identically in both directions.
        let forward = stable_signature(&report_ab);
        let backward = stable_signature(&report_ba)
            .into_iter()
            .map(|((class, target), count)| ((mirrored_class(class), target), count))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            forward, backward,
            "A->B and B->A disagree on name-addressed findings"
        );

        // Property 3: every finding's type_name names a type that exists in one
        // of the two specs.
        for finding in report_ab.findings.iter().chain(report_ba.findings.iter()) {
            if let Some(type_name) = finding.type_name() {
                assert!(
                    type_exists(&spec_a, type_name) || type_exists(&spec_b, type_name),
                    "finding {:?} has type_name '{}' absent from both specs",
                    finding,
                    type_name
                );
            }
        }

        // Property 4: every finding's target follows the suppression-key
        // convention for its category.
        for finding in report_ab.findings.iter().chain(report_ba.findings.iter()) {
            if let Some(target) = finding.target() {
                assert!(
                    target_is_well_formed(target, &spec_a, &spec_b),
                    "finding {:?} has ill-formed target '{}'",
                    finding,
                    target
                );
            }
        }

        // Property 5: cascade detection terminates (compare returns) and every
        // cascade finding is internally consistent.
        assert!(
            cascade_findings_are_consistent(&report_ab, &spec_a, &spec_b),
            "A->B produced inconsistent cascade findings: {:?}",
            report_ab.findings
        );
        assert!(
            cascade_findings_are_consistent(&report_ba, &spec_b, &spec_a),
            "B->A produced inconsistent cascade findings: {:?}",
            report_ba.findings
        );
    }
}

// ---------------------------------------------------------------------------
// Deterministic tests for cascade termination on cyclic type graphs. The
// property test above reaches cycles through self-referential generated types;
// these tests pin the two canonical shapes down explicitly.
// ---------------------------------------------------------------------------

#[test]
fn self_referential_cycle_terminates() {
    // Node { value: u32, next: Option<Node> } -> value becomes u64.
    let mut old = ContractSpec::default();
    insert_struct(
        &mut old,
        "Node",
        vec![
            ("value", ScSpecTypeDef::U32),
            ("next", option_of(udt("Node"))),
        ],
    );
    let mut new = ContractSpec::default();
    insert_struct(
        &mut new,
        "Node",
        vec![
            ("value", ScSpecTypeDef::U64),
            ("next", option_of(udt("Node"))),
        ],
    );

    let report = compare(&old, &new);

    // Node's self-reference must be traversed exactly once, and the
    // (type_name, root_target) keys must be unique.
    let cascades: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.category == "Cascading Layout Break")
        .collect();
    assert!(
        cascades
            .iter()
            .any(|f| f.type_name() == Some("Node") && f.root_target() == Some("Node")),
        "expected a self-cascade for Node, got: {:?}",
        report.findings
    );
    let keys: HashSet<(&str, &str)> = cascades
        .iter()
        .map(|f| (f.type_name().unwrap(), f.root_target().unwrap()))
        .collect();
    assert_eq!(keys.len(), cascades.len(), "duplicate cascade keys");
}

#[test]
fn mutually_recursive_cycle_terminates() {
    // A { value: u32, b: B }, B { a: A }. Breaking A must propagate to B and
    // terminate despite the A <-> B cycle.
    let mut old = ContractSpec::default();
    insert_struct(
        &mut old,
        "A",
        vec![("value", ScSpecTypeDef::U32), ("b", udt("B"))],
    );
    insert_struct(&mut old, "B", vec![("a", udt("A"))]);
    let mut new = ContractSpec::default();
    insert_struct(
        &mut new,
        "A",
        vec![("value", ScSpecTypeDef::U64), ("b", udt("B"))],
    );
    insert_struct(&mut new, "B", vec![("a", udt("A"))]);

    let report = compare(&old, &new);

    let b_cascade = report.findings.iter().any(|f| {
        f.category == "Cascading Layout Break"
            && f.type_name() == Some("B")
            && f.root_target() == Some("A")
    });
    assert!(
        b_cascade,
        "expected B to cascade from A, got: {:?}",
        report.findings
    );

    let cascades: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.category == "Cascading Layout Break")
        .collect();
    let keys: HashSet<(&str, &str)> = cascades
        .iter()
        .map(|f| (f.type_name().unwrap(), f.root_target().unwrap()))
        .collect();
    assert_eq!(keys.len(), cascades.len(), "duplicate cascade keys");
}

use std::collections::{HashMap, HashSet};

use crate::spec::ContractSpec;
use stellar_xdr::curr::{ScSpecTypeDef, ScSpecUdtUnionCaseV0};

/// Convert an ScSpecTypeDef into a human-readable Rust-like string signature.
pub fn type_to_string(type_def: &ScSpecTypeDef) -> String {
    match type_def {
        ScSpecTypeDef::Val => "Val".to_string(),
        ScSpecTypeDef::Bool => "bool".to_string(),
        ScSpecTypeDef::Void => "()".to_string(),
        ScSpecTypeDef::Error => "Error".to_string(),
        ScSpecTypeDef::U32 => "u32".to_string(),
        ScSpecTypeDef::I32 => "i32".to_string(),
        ScSpecTypeDef::U64 => "u64".to_string(),
        ScSpecTypeDef::I64 => "i64".to_string(),
        ScSpecTypeDef::Timepoint => "Timepoint".to_string(),
        ScSpecTypeDef::Duration => "Duration".to_string(),
        ScSpecTypeDef::U128 => "u128".to_string(),
        ScSpecTypeDef::I128 => "i128".to_string(),
        ScSpecTypeDef::U256 => "u256".to_string(),
        ScSpecTypeDef::I256 => "i256".to_string(),
        ScSpecTypeDef::Bytes => "Bytes".to_string(),
        ScSpecTypeDef::String => "String".to_string(),
        ScSpecTypeDef::Symbol => "Symbol".to_string(),
        ScSpecTypeDef::Address => "Address".to_string(),
        ScSpecTypeDef::Option(opt) => format!("Option<{}>", type_to_string(&opt.value_type)),
        ScSpecTypeDef::Result(res) => format!(
            "Result<{}, {}>",
            type_to_string(&res.ok_type),
            type_to_string(&res.error_type)
        ),
        ScSpecTypeDef::Vec(vec) => format!("Vec<{}>", type_to_string(&vec.element_type)),
        ScSpecTypeDef::Map(map) => format!(
            "Map<{}, {}>",
            type_to_string(&map.key_type),
            type_to_string(&map.value_type)
        ),
        ScSpecTypeDef::Tuple(tuple) => {
            let inner: Vec<String> = tuple.value_types.iter().map(type_to_string).collect();
            format!("({})", inner.join(", "))
        }
        ScSpecTypeDef::BytesN(b) => format!("BytesN<{}>", b.n),
        ScSpecTypeDef::Udt(udt) => udt.name.to_string(),
    }
}

/// A LayoutMapper extracts all User-Defined Types (UDT) that a specific type depends on.
pub struct LayoutMapper<'a> {
    spec: &'a ContractSpec,
}

impl<'a> LayoutMapper<'a> {
    pub fn new(spec: &'a ContractSpec) -> Self {
        Self { spec }
    }

    /// Recursively find all `Udt` names the given TypeDef depends on.
    ///
    /// When `type_def` is itself a bare `Udt` reference, that type's own name
    /// is deliberately excluded from the result (it is the subject being
    /// expanded, not one of its own dependencies) *unless* a cycle leads back
    /// to it, in which case it legitimately is one of its own transitive
    /// dependencies.
    pub fn get_udt_dependencies(&self, type_def: &ScSpecTypeDef) -> HashSet<String> {
        let mut deps = HashSet::new();
        let mut visited = HashSet::new();
        if let ScSpecTypeDef::Udt(udt) = type_def {
            let name = udt.name.to_string();
            visited.insert(name.clone());
            self.expand_udt_members(&name, &mut deps, &mut visited);
        } else {
            self.extract_udts(type_def, &mut deps, &mut visited);
        }
        deps
    }

    /// Builds a graph mapping each UDT name to the list of other UDT names
    /// that directly (one hop, after unwrapping containers) reference it as
    /// a field or case-payload type. Unlike [`Self::get_udt_dependencies`],
    /// this is intentionally *not* transitive: [`crate::diff`]'s cascade
    /// detection walks this graph itself to propagate a break through
    /// multiple hops, and a transitive edge set here would wrongly fold a
    /// UDT that merely participates in a cycle into its own reverse entry.
    pub fn build_reverse_dependencies(&self) -> HashMap<String, Vec<String>> {
        let mut reverse_deps: HashMap<String, Vec<String>> = HashMap::new();

        for (name, struct_def) in &self.spec.structs {
            let fields: &[stellar_xdr::curr::ScSpecUdtStructFieldV0] = struct_def.fields.as_ref();
            for field in fields {
                let mut deps = HashSet::new();
                self.direct_udt_refs(&field.type_, &mut deps);
                for dep in deps {
                    reverse_deps.entry(dep).or_default().push(name.clone());
                }
            }
        }

        for (name, union_def) in &self.spec.unions {
            let cases: &[stellar_xdr::curr::ScSpecUdtUnionCaseV0] = union_def.cases.as_ref();
            for case in cases {
                if let ScSpecUdtUnionCaseV0::TupleV0(tuple) = case {
                    let types: &[stellar_xdr::curr::ScSpecTypeDef] = tuple.type_.as_ref();
                    for t in types {
                        let mut deps = HashSet::new();
                        self.direct_udt_refs(t, &mut deps);
                        for dep in deps {
                            reverse_deps.entry(dep).or_default().push(name.clone());
                        }
                    }
                }
            }
        }

        for deps in reverse_deps.values_mut() {
            deps.sort();
            deps.dedup();
        }

        reverse_deps
    }

    /// Unwrap containers (`Option`/`Result`/`Vec`/`Map`/`Tuple`) to find the
    /// `Udt` names directly present in `type_def`'s own signature, without
    /// expanding into any referenced UDT's body. Used for one-hop edges; see
    /// [`Self::build_reverse_dependencies`].
    fn direct_udt_refs(&self, type_def: &ScSpecTypeDef, out: &mut HashSet<String>) {
        match type_def {
            ScSpecTypeDef::Option(opt) => self.direct_udt_refs(&opt.value_type, out),
            ScSpecTypeDef::Result(res) => {
                self.direct_udt_refs(&res.ok_type, out);
                self.direct_udt_refs(&res.error_type, out);
            }
            ScSpecTypeDef::Vec(vec) => self.direct_udt_refs(&vec.element_type, out),
            ScSpecTypeDef::Map(map) => {
                self.direct_udt_refs(&map.key_type, out);
                self.direct_udt_refs(&map.value_type, out);
            }
            ScSpecTypeDef::Tuple(tuple) => {
                let types: &[stellar_xdr::curr::ScSpecTypeDef] = tuple.value_types.as_ref();
                for t in types {
                    self.direct_udt_refs(t, out);
                }
            }
            ScSpecTypeDef::Udt(udt) => {
                out.insert(udt.name.to_string());
            }
            _ => {} // Primitive types
        }
    }

    /// Expand the members of the UDT named `name` (a struct's fields or a
    /// union's tuple-case payloads), recording every `Udt` reference found —
    /// including `name` itself, should a cycle lead back to it.
    fn expand_udt_members(
        &self,
        name: &str,
        deps: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) {
        if let Some(struct_def) = self.spec.structs.get(name) {
            let fields: &[stellar_xdr::curr::ScSpecUdtStructFieldV0] = struct_def.fields.as_ref();
            for field in fields {
                self.extract_udts(&field.type_, deps, visited);
            }
        } else if let Some(union_def) = self.spec.unions.get(name) {
            let cases: &[stellar_xdr::curr::ScSpecUdtUnionCaseV0] = union_def.cases.as_ref();
            for case in cases {
                match case {
                    ScSpecUdtUnionCaseV0::TupleV0(tuple) => {
                        let types: &[stellar_xdr::curr::ScSpecTypeDef] = tuple.type_.as_ref();
                        for t in types {
                            self.extract_udts(t, deps, visited);
                        }
                    }
                    ScSpecUdtUnionCaseV0::VoidV0(_) => {}
                }
            }
        }
        // Enums and ErrorEnums are primitives, no nested types.
    }

    fn extract_udts(
        &self,
        type_def: &ScSpecTypeDef,
        deps: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) {
        match type_def {
            ScSpecTypeDef::Option(opt) => self.extract_udts(&opt.value_type, deps, visited),
            ScSpecTypeDef::Result(res) => {
                self.extract_udts(&res.ok_type, deps, visited);
                self.extract_udts(&res.error_type, deps, visited);
            }
            ScSpecTypeDef::Vec(vec) => self.extract_udts(&vec.element_type, deps, visited),
            ScSpecTypeDef::Map(map) => {
                self.extract_udts(&map.key_type, deps, visited);
                self.extract_udts(&map.value_type, deps, visited);
            }
            ScSpecTypeDef::Tuple(tuple) => {
                let types: &[stellar_xdr::curr::ScSpecTypeDef] = tuple.value_types.as_ref();
                for t in types {
                    self.extract_udts(t, deps, visited);
                }
            }
            ScSpecTypeDef::Udt(udt) => {
                let name = udt.name.to_string();
                deps.insert(name.clone());
                // Prevent infinite recursion if types are cyclic
                if visited.insert(name.clone()) {
                    self.expand_udt_members(&name, deps, visited);
                }
            }
            _ => {} // Primitive types
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ContractSpec;
    use stellar_xdr::curr::{
        ScSpecTypeDef, ScSpecTypeMap, ScSpecTypeOption, ScSpecTypeResult, ScSpecTypeTuple,
        ScSpecTypeUdt, ScSpecTypeVec, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
        ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseV0, ScSpecUdtUnionCaseVoidV0,
        ScSpecUdtUnionV0, StringM, VecM,
    };

    fn udt(name: &str) -> ScSpecTypeDef {
        ScSpecTypeDef::Udt(ScSpecTypeUdt {
            name: name.try_into().unwrap(),
        })
    }

    fn insert_struct(spec: &mut ContractSpec, name: &str, fields: Vec<(&str, ScSpecTypeDef)>) {
        let xdr_fields: Vec<ScSpecUdtStructFieldV0> = fields
            .into_iter()
            .map(|(n, t)| ScSpecUdtStructFieldV0 {
                doc: StringM::default(),
                name: n.try_into().unwrap(),
                type_: t,
            })
            .collect();
        spec.structs.insert(
            name.to_string(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: name.try_into().unwrap(),
                fields: VecM::try_from(xdr_fields).unwrap(),
            },
        );
    }

    fn insert_union(spec: &mut ContractSpec, name: &str, cases: Vec<(&str, Vec<ScSpecTypeDef>)>) {
        let mut xdr_cases: Vec<ScSpecUdtUnionCaseV0> = Vec::new();
        for (case_name, payloads) in cases {
            if payloads.is_empty() {
                xdr_cases.push(ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
                    doc: StringM::default(),
                    name: case_name.try_into().unwrap(),
                }));
            } else {
                xdr_cases.push(ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                    doc: StringM::default(),
                    name: case_name.try_into().unwrap(),
                    type_: VecM::try_from(payloads).unwrap(),
                }));
            }
        }
        spec.unions.insert(
            name.to_string(),
            ScSpecUdtUnionV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: name.try_into().unwrap(),
                cases: VecM::try_from(xdr_cases).unwrap(),
            },
        );
    }

    fn build_graph_spec() -> ContractSpec {
        let mut spec = ContractSpec::default();

        insert_struct(&mut spec, "Leaf", vec![("v", ScSpecTypeDef::U32)]);

        insert_struct(
            &mut spec,
            "Mid",
            vec![
                ("direct", udt("Leaf")),
                (
                    "wrapped_opt",
                    ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
                        value_type: Box::new(udt("Leaf")),
                    })),
                ),
                (
                    "wrapped_vec",
                    ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                        element_type: Box::new(udt("Leaf")),
                    })),
                ),
            ],
        );

        insert_struct(
            &mut spec,
            "Root",
            vec![
                ("mid", udt("Mid")),
                (
                    "map_of_leaf_to_mid",
                    ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
                        key_type: Box::new(udt("Leaf")),
                        value_type: Box::new(udt("Mid")),
                    })),
                ),
                (
                    "result_leaf_mid",
                    ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
                        ok_type: Box::new(udt("Leaf")),
                        error_type: Box::new(udt("Mid")),
                    })),
                ),
                (
                    "tuple_mid_leaf",
                    ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
                        value_types: VecM::try_from(vec![udt("Mid"), udt("Leaf")]).unwrap(),
                    })),
                ),
            ],
        );

        insert_struct(&mut spec, "CycleA", vec![("b", udt("CycleB"))]);
        insert_struct(&mut spec, "CycleB", vec![("a", udt("CycleA"))]);

        insert_union(
            &mut spec,
            "U",
            vec![
                ("Empty", vec![]),
                ("HasMid", vec![udt("Mid")]),
                ("Pair", vec![udt("CycleA"), udt("Root")]),
            ],
        );

        spec
    }

    fn sorted<'a, I: IntoIterator<Item = &'a String>>(iter: I) -> Vec<String> {
        let mut v: Vec<String> = iter.into_iter().cloned().collect();
        v.sort();
        v
    }

    #[test]
    fn dependency_graph_direct_and_transitive_closure() {
        let spec = build_graph_spec();
        let mapper = LayoutMapper::new(&spec);

        let leaf_deps = mapper.get_udt_dependencies(&udt("Leaf"));
        assert!(
            leaf_deps.is_empty(),
            "Leaf only contains u32, must have no UDT deps, got {:?}",
            leaf_deps
        );

        let mid_deps = mapper.get_udt_dependencies(&udt("Mid"));
        assert_eq!(sorted(&mid_deps), vec!["Leaf".to_string()]);

        let root_deps = mapper.get_udt_dependencies(&udt("Root"));
        assert_eq!(
            sorted(&root_deps),
            vec!["Leaf".to_string(), "Mid".to_string()],
            "Root transitively depends on both Mid and Leaf via every container variant"
        );
    }

    #[test]
    fn dependency_graph_cycle_terminates_and_returns_both_nodes() {
        let spec = build_graph_spec();
        let mapper = LayoutMapper::new(&spec);

        let a_deps = mapper.get_udt_dependencies(&udt("CycleA"));
        assert_eq!(
            sorted(&a_deps),
            vec!["CycleA".to_string(), "CycleB".to_string()],
            "Cycle walk must include both nodes of the 2-cycle and terminate"
        );

        let b_deps = mapper.get_udt_dependencies(&udt("CycleB"));
        assert_eq!(
            sorted(&b_deps),
            vec!["CycleA".to_string(), "CycleB".to_string()],
            "Entering from either side of the cycle yields the same closure"
        );

        let u_deps = mapper.get_udt_dependencies(&udt("U"));
        let mut u_sorted = sorted(&u_deps);
        u_sorted.sort();
        assert_eq!(
            u_sorted,
            vec![
                "CycleA".to_string(),
                "CycleB".to_string(),
                "Leaf".to_string(),
                "Mid".to_string(),
                "Root".to_string(),
            ],
            "Union walk must cover void case (skipped), tuple case, and transitive closure"
        );
    }

    #[test]
    fn dependency_graph_reverse_dependencies_nodes_and_edges_with_stable_ordering() {
        let spec = build_graph_spec();
        let mapper = LayoutMapper::new(&spec);
        let reverse = mapper.build_reverse_dependencies();

        let reverse_keys = sorted(reverse.keys());
        assert_eq!(
            reverse_keys,
            vec![
                "CycleA".to_string(),
                "CycleB".to_string(),
                "Leaf".to_string(),
                "Mid".to_string(),
                "Root".to_string(),
            ],
            "Every UDT used as a field type anywhere must appear as a reverse key"
        );

        assert_eq!(
            reverse["CycleA"],
            vec!["CycleB".to_string(), "U".to_string()],
            "CycleA is referenced from CycleB's field and from union case Pair"
        );
        assert_eq!(reverse["CycleB"], vec!["CycleA".to_string()]);

        assert_eq!(
            reverse["Mid"],
            vec!["Root".to_string(), "U".to_string()],
            "Mid is referenced from Root (direct + containers) and union case HasMid; deduped and sorted"
        );

        assert_eq!(
            reverse["Leaf"],
            vec!["Mid".to_string(), "Root".to_string()],
            "Leaf is referenced from Mid directly and via containers; then Root transitively maps/results/tuples carry Leaf payloads; deduped sorted"
        );

        assert_eq!(reverse["Root"], vec!["U".to_string()]);

        for (key, value) in &reverse {
            let mut expected = value.clone();
            expected.sort();
            expected.dedup();
            assert_eq!(
                value, &expected,
                "reverse edge list for '{key}' must be sorted and deduped for stable output"
            );
        }
    }

    #[test]
    fn dependency_graph_structured_metadata_is_required() {
        // Negative control: a spec with actual dependencies must produce a
        // non-trivial graph. If someone naively refactors get_udt_dependencies
        // to always return HashSet::new(), this test fails alongside the
        // others, catching an accidental graph-stripping regression.
        let spec = build_graph_spec();
        let mapper = LayoutMapper::new(&spec);

        assert!(
            !mapper.get_udt_dependencies(&udt("Root")).is_empty(),
            "get_udt_dependencies(Root) must be non-empty — structured metadata is required"
        );
        assert!(
            !mapper.get_udt_dependencies(&udt("U")).is_empty(),
            "get_udt_dependencies(U) must be non-empty — union case payloads must contribute edges"
        );
        assert!(
            !mapper.build_reverse_dependencies().is_empty(),
            "build_reverse_dependencies() must produce entries — structured metadata is required"
        );
    }

    #[test]
    fn primitive_types_produce_empty_dependency_set() {
        let spec = ContractSpec::default();
        let mapper = LayoutMapper::new(&spec);

        // Primitive types should produce no UDT dependencies
        let primitives = vec![
            ScSpecTypeDef::U32,
            ScSpecTypeDef::I32,
            ScSpecTypeDef::U64,
            ScSpecTypeDef::I64,
            ScSpecTypeDef::U128,
            ScSpecTypeDef::I128,
            ScSpecTypeDef::Bool,
            ScSpecTypeDef::Void,
            ScSpecTypeDef::Symbol,
            ScSpecTypeDef::String,
            ScSpecTypeDef::Bytes,
            ScSpecTypeDef::Address,
        ];

        for primitive in primitives {
            let deps = mapper.get_udt_dependencies(&primitive);
            assert!(
                deps.is_empty(),
                "Primitive type {:?} must produce empty dependency set, got {:?}",
                type_to_string(&primitive),
                deps
            );
        }
    }

    #[test]
    fn container_of_primitives_produces_no_udt_dependency() {
        let spec = ContractSpec::default();
        let mapper = LayoutMapper::new(&spec);

        // Vec<u32> should have no UDT dependencies
        let vec_u32 = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::U32),
        }));
        let deps = mapper.get_udt_dependencies(&vec_u32);
        assert!(
            deps.is_empty(),
            "Vec<u32> must produce empty dependency set, got {:?}",
            deps
        );

        // Option<bool> should have no UDT dependencies
        let option_bool = ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
            value_type: Box::new(ScSpecTypeDef::Bool),
        }));
        let deps = mapper.get_udt_dependencies(&option_bool);
        assert!(
            deps.is_empty(),
            "Option<bool> must produce empty dependency set, got {:?}",
            deps
        );

        // Map<String, u64> should have no UDT dependencies
        let map_string_u64 = ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::String),
            value_type: Box::new(ScSpecTypeDef::U64),
        }));
        let deps = mapper.get_udt_dependencies(&map_string_u64);
        assert!(
            deps.is_empty(),
            "Map<String, u64> must produce empty dependency set, got {:?}",
            deps
        );

        // Result<i32, bool> should have no UDT dependencies
        let result_i32_bool = ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
            ok_type: Box::new(ScSpecTypeDef::I32),
            error_type: Box::new(ScSpecTypeDef::Bool),
        }));
        let deps = mapper.get_udt_dependencies(&result_i32_bool);
        assert!(
            deps.is_empty(),
            "Result<i32, bool> must produce empty dependency set, got {:?}",
            deps
        );

        // Tuple (u32, String, bool) should have no UDT dependencies
        let tuple_primitives = ScSpecTypeDef::Tuple(Box::new(ScSpecTypeTuple {
            value_types: VecM::try_from(vec![
                ScSpecTypeDef::U32,
                ScSpecTypeDef::String,
                ScSpecTypeDef::Bool,
            ])
            .unwrap(),
        }));
        let deps = mapper.get_udt_dependencies(&tuple_primitives);
        assert!(
            deps.is_empty(),
            "Tuple of primitives must produce empty dependency set, got {:?}",
            deps
        );
    }

    #[test]
    fn nested_container_of_primitives_produces_no_udt_dependency() {
        let spec = ContractSpec::default();
        let mapper = LayoutMapper::new(&spec);

        // Vec<Option<u32>> should have no UDT dependencies
        let vec_option_u32 = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
                value_type: Box::new(ScSpecTypeDef::U32),
            }))),
        }));
        let deps = mapper.get_udt_dependencies(&vec_option_u32);
        assert!(
            deps.is_empty(),
            "Vec<Option<u32>> must produce empty dependency set, got {:?}",
            deps
        );
    }

    #[test]
    fn container_containing_udt_reports_that_udt() {
        let mut spec = ContractSpec::default();
        insert_struct(&mut spec, "MyType", vec![("value", ScSpecTypeDef::U32)]);

        let mapper = LayoutMapper::new(&spec);

        // Vec<MyType> should report MyType as a dependency
        let vec_mytype = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(udt("MyType")),
        }));
        let deps = mapper.get_udt_dependencies(&vec_mytype);
        assert_eq!(
            sorted(&deps),
            vec!["MyType".to_string()],
            "Vec<MyType> must report MyType as a dependency"
        );

        // Option<MyType> should report MyType as a dependency
        let option_mytype = ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
            value_type: Box::new(udt("MyType")),
        }));
        let deps = mapper.get_udt_dependencies(&option_mytype);
        assert_eq!(
            sorted(&deps),
            vec!["MyType".to_string()],
            "Option<MyType> must report MyType as a dependency"
        );

        // Map<u32, MyType> should report MyType as a dependency
        let map_u32_mytype = ScSpecTypeDef::Map(Box::new(ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::U32),
            value_type: Box::new(udt("MyType")),
        }));
        let deps = mapper.get_udt_dependencies(&map_u32_mytype);
        assert_eq!(
            sorted(&deps),
            vec!["MyType".to_string()],
            "Map<u32, MyType> must report MyType as a dependency"
        );
    }
}

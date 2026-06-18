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

    /// Recursively find all `Udt` names referenced by the given TypeDef.
    pub fn get_udt_dependencies(&self, type_def: &ScSpecTypeDef) -> HashSet<String> {
        let mut deps = HashSet::new();
        self.extract_udts(type_def, &mut deps);
        deps
    }

    /// Builds a graph mapping each UDT name to a list of other UDT names that depend on it.
    pub fn build_reverse_dependencies(&self) -> HashMap<String, Vec<String>> {
        let mut reverse_deps: HashMap<String, Vec<String>> = HashMap::new();

        for (name, struct_def) in &self.spec.structs {
            let fields: &[stellar_xdr::curr::ScSpecUdtStructFieldV0] = struct_def.fields.as_ref();
            for field in fields {
                let deps = self.get_udt_dependencies(&field.type_);
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
                        let deps = self.get_udt_dependencies(t);
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

    fn extract_udts(&self, type_def: &ScSpecTypeDef, deps: &mut HashSet<String>) {
        match type_def {
            ScSpecTypeDef::Option(opt) => self.extract_udts(&opt.value_type, deps),
            ScSpecTypeDef::Result(res) => {
                self.extract_udts(&res.ok_type, deps);
                self.extract_udts(&res.error_type, deps);
            }
            ScSpecTypeDef::Vec(vec) => self.extract_udts(&vec.element_type, deps),
            ScSpecTypeDef::Map(map) => {
                self.extract_udts(&map.key_type, deps);
                self.extract_udts(&map.value_type, deps);
            }
            ScSpecTypeDef::Tuple(tuple) => {
                let types: &[stellar_xdr::curr::ScSpecTypeDef] = tuple.value_types.as_ref();
                for t in types {
                    self.extract_udts(t, deps);
                }
            }
            ScSpecTypeDef::Udt(udt) => {
                let name = udt.name.to_string();
                // Prevent infinite recursion if types are cyclic
                if deps.insert(name.clone()) {
                    // It's a new UDT we haven't seen. Let's recursively find its members.
                    if let Some(struct_def) = self.spec.structs.get(&name) {
                        let fields: &[stellar_xdr::curr::ScSpecUdtStructFieldV0] =
                            struct_def.fields.as_ref();
                        for field in fields {
                            self.extract_udts(&field.type_, deps);
                        }
                    } else if let Some(union_def) = self.spec.unions.get(&name) {
                        let cases: &[stellar_xdr::curr::ScSpecUdtUnionCaseV0] =
                            union_def.cases.as_ref();
                        for case in cases {
                            match case {
                                ScSpecUdtUnionCaseV0::TupleV0(tuple) => {
                                    let types: &[stellar_xdr::curr::ScSpecTypeDef] =
                                        tuple.type_.as_ref();
                                    for t in types {
                                        self.extract_udts(t, deps);
                                    }
                                }
                                ScSpecUdtUnionCaseV0::VoidV0(_) => {}
                            }
                        }
                    }
                    // Enums and ErrorEnums are primitives, no nested types.
                }
            }
            _ => {} // Primitive types
        }
    }
}

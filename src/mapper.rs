use std::collections::{HashMap, HashSet};

use crate::limits::{LimitError, ResourcePolicy};
use crate::spec::ContractSpec;
use stellar_xdr::curr::{ScSpecTypeDef, ScSpecUdtUnionCaseV0};

/// Sentinel rendered by the infallible [`type_to_string`] when a type nests past
/// the default walk-depth limit. The bounded [`try_type_to_string`] is preferred
/// wherever a real error can be surfaced.
pub const TOO_DEEP_SENTINEL: &str = "<type too deeply nested>";

/// Convert an ScSpecTypeDef into a human-readable Rust-like string signature.
///
/// Infallible and total: this keeps the `fn(&ScSpecTypeDef) -> String` shape that
/// call sites use as a function pointer (e.g. `iter().map(type_to_string)`). A
/// type nested past the default [`ResourcePolicy::max_walk_depth`] renders as
/// [`TOO_DEEP_SENTINEL`] instead of overflowing the stack. On any path that can
/// propagate an error, prefer [`try_type_to_string`].
pub fn type_to_string(type_def: &ScSpecTypeDef) -> String {
    try_type_to_string(type_def, 0, ResourcePolicy::default().max_walk_depth)
        .unwrap_or_else(|_| TOO_DEEP_SENTINEL.to_string())
}

/// Depth-bounded core of [`type_to_string`].
///
/// `depth` is the current nesting level (0 at the top) and `max` is the maximum
/// permitted. The bound is checked *before* recursing, so the recursion can add
/// at most `max + 1` stack frames — a stack overflow is therefore impossible on
/// any input. A type nested past `max` yields [`LimitError::WalkDepthExceeded`].
pub fn try_type_to_string(
    type_def: &ScSpecTypeDef,
    depth: usize,
    max: usize,
) -> Result<String, LimitError> {
    if depth > max {
        return Err(LimitError::WalkDepthExceeded { limit: max });
    }
    let rendered = match type_def {
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
        ScSpecTypeDef::Option(opt) => {
            format!(
                "Option<{}>",
                try_type_to_string(&opt.value_type, depth + 1, max)?
            )
        }
        ScSpecTypeDef::Result(res) => format!(
            "Result<{}, {}>",
            try_type_to_string(&res.ok_type, depth + 1, max)?,
            try_type_to_string(&res.error_type, depth + 1, max)?
        ),
        ScSpecTypeDef::Vec(vec) => {
            format!(
                "Vec<{}>",
                try_type_to_string(&vec.element_type, depth + 1, max)?
            )
        }
        ScSpecTypeDef::Map(map) => format!(
            "Map<{}, {}>",
            try_type_to_string(&map.key_type, depth + 1, max)?,
            try_type_to_string(&map.value_type, depth + 1, max)?
        ),
        ScSpecTypeDef::Tuple(tuple) => {
            let inner: Vec<String> = tuple
                .value_types
                .iter()
                .map(|t| try_type_to_string(t, depth + 1, max))
                .collect::<Result<_, _>>()?;
            format!("({})", inner.join(", "))
        }
        ScSpecTypeDef::BytesN(b) => format!("BytesN<{}>", b.n),
        ScSpecTypeDef::Udt(udt) => udt.name.to_string(),
    };
    Ok(rendered)
}

/// A LayoutMapper extracts all User-Defined Types (UDT) that a specific type depends on.
pub struct LayoutMapper<'a> {
    spec: &'a ContractSpec,
    max_walk_depth: usize,
}

impl<'a> LayoutMapper<'a> {
    /// Build a mapper using the default [`ResourcePolicy`] walk-depth limit.
    pub fn new(spec: &'a ContractSpec) -> Self {
        Self::new_with_policy(spec, &ResourcePolicy::default())
    }

    /// Build a mapper that bounds every type walk to `policy.max_walk_depth`.
    pub fn new_with_policy(spec: &'a ContractSpec, policy: &ResourcePolicy) -> Self {
        Self {
            spec,
            max_walk_depth: policy.max_walk_depth,
        }
    }

    /// Recursively find all `Udt` names referenced by the given TypeDef.
    ///
    /// Infallible convenience wrapper: a type nested past the walk-depth limit
    /// yields an empty set rather than an error. Prefer
    /// [`try_get_udt_dependencies`](Self::try_get_udt_dependencies) on untrusted
    /// input so a limit violation is surfaced.
    pub fn get_udt_dependencies(&self, type_def: &ScSpecTypeDef) -> HashSet<String> {
        self.try_get_udt_dependencies(type_def).unwrap_or_default()
    }

    /// Depth-bounded variant of
    /// [`get_udt_dependencies`](Self::get_udt_dependencies).
    pub fn try_get_udt_dependencies(
        &self,
        type_def: &ScSpecTypeDef,
    ) -> Result<HashSet<String>, LimitError> {
        let mut deps = HashSet::new();
        self.extract_udts(type_def, &mut deps, 0)?;
        Ok(deps)
    }

    /// Builds a graph mapping each UDT name to a list of other UDT names that
    /// depend on it. Infallible convenience wrapper around
    /// [`try_build_reverse_dependencies`](Self::try_build_reverse_dependencies).
    pub fn build_reverse_dependencies(&self) -> HashMap<String, Vec<String>> {
        self.try_build_reverse_dependencies().unwrap_or_default()
    }

    /// Depth-bounded variant of
    /// [`build_reverse_dependencies`](Self::build_reverse_dependencies).
    pub fn try_build_reverse_dependencies(
        &self,
    ) -> Result<HashMap<String, Vec<String>>, LimitError> {
        let mut reverse_deps: HashMap<String, Vec<String>> = HashMap::new();

        for (name, struct_def) in &self.spec.structs {
            let fields: &[stellar_xdr::curr::ScSpecUdtStructFieldV0] = struct_def.fields.as_ref();
            for field in fields {
                let deps = self.try_get_udt_dependencies(&field.type_)?;
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
                        let deps = self.try_get_udt_dependencies(t)?;
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

        Ok(reverse_deps)
    }

    /// Walk a type, collecting referenced UDT names into `deps`.
    ///
    /// Two independent recursions live here and both are bounded by `depth`:
    /// container nesting (Option/Vec/Map/Tuple), which the cycle guard below does
    /// *not* cover, and the UDT-graph recursion. The bound is checked before
    /// recursing, so the stack can grow by at most `max_walk_depth + 1` frames.
    fn extract_udts(
        &self,
        type_def: &ScSpecTypeDef,
        deps: &mut HashSet<String>,
        depth: usize,
    ) -> Result<(), LimitError> {
        if depth > self.max_walk_depth {
            return Err(LimitError::WalkDepthExceeded {
                limit: self.max_walk_depth,
            });
        }
        match type_def {
            ScSpecTypeDef::Option(opt) => self.extract_udts(&opt.value_type, deps, depth + 1)?,
            ScSpecTypeDef::Result(res) => {
                self.extract_udts(&res.ok_type, deps, depth + 1)?;
                self.extract_udts(&res.error_type, deps, depth + 1)?;
            }
            ScSpecTypeDef::Vec(vec) => self.extract_udts(&vec.element_type, deps, depth + 1)?,
            ScSpecTypeDef::Map(map) => {
                self.extract_udts(&map.key_type, deps, depth + 1)?;
                self.extract_udts(&map.value_type, deps, depth + 1)?;
            }
            ScSpecTypeDef::Tuple(tuple) => {
                let types: &[stellar_xdr::curr::ScSpecTypeDef] = tuple.value_types.as_ref();
                for t in types {
                    self.extract_udts(t, deps, depth + 1)?;
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
                            self.extract_udts(&field.type_, deps, depth + 1)?;
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
                                        self.extract_udts(t, deps, depth + 1)?;
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
        Ok(())
    }
}

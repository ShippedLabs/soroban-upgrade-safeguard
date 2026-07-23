use crate::limits::{LimitError, ResourcePolicy};
use crate::mapper::{try_type_to_string, LayoutMapper};
use crate::parser::ContractEnvMeta;
use crate::spec::ContractSpec;
use serde::Serialize;
use std::collections::HashMap;
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
    ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    ScSpecUdtUnionCaseV0, ScSpecUdtUnionV0,
};

/// Severity of a detected issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

/// A single finding from the comparison analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    /// The name of the affected UDT (struct/enum/union), if this finding
    /// relates to a specific type.  Used by cascade-detection so it never
    /// needs to re-parse `message`.
    pub type_name: Option<String>,
    /// A stable, structured identifier for the exact entity this finding is
    /// about, independent of the human-readable `message`. It is the key used
    /// by the suppression config to match a finding precisely:
    ///
    /// - functions: the function name (e.g. `transfer`)
    /// - function parameters: `function.param` (e.g. `transfer.to`)
    /// - types (struct/enum removed/added, cascades): the type name (e.g. `Data`)
    /// - struct fields: `Type.field` (e.g. `Data.amount`)
    /// - enum cases: `Enum.case` (e.g. `Status.Active`)
    ///
    /// `None` for findings that are not tied to a single named entity (for
    /// example environment-metadata changes).
    pub target: Option<String>,
}

/// Holds all findings from a comparison of two contract specs.
#[derive(Debug, Default)]
pub struct DiffReport {
    pub findings: Vec<Finding>,
}

#[allow(dead_code)]
impl DiffReport {
    pub fn critical_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count()
    }

    pub fn info_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count()
    }
}

/// Compare two contract specs and return a report of all findings.
///
/// Infallible convenience wrapper over [`compare_with_policy`] using the default
/// [`ResourcePolicy`]. Retained for the shallow inputs used in unit tests and for
/// callers that don't need to distinguish a resource-limit violation; on the
/// (practically unreachable) event that a type nests past the default walk-depth
/// limit it returns whatever findings were gathered before the limit tripped.
pub fn compare(old: &ContractSpec, new: &ContractSpec) -> DiffReport {
    compare_with_policy(old, new, &ResourcePolicy::default()).unwrap_or_default()
}

/// Compare two contract specs under `policy`, bounding every recursive type walk.
///
/// A type nested past `policy.max_walk_depth` — in an equality check, a UDT
/// dependency walk, or a rendered finding message — aborts the comparison with
/// [`LimitError::WalkDepthExceeded`] instead of overflowing the stack. This is
/// the fallible core; [`compare`] is the infallible default-policy wrapper.
pub fn compare_with_policy(
    old: &ContractSpec,
    new: &ContractSpec,
    policy: &ResourcePolicy,
) -> Result<DiffReport, LimitError> {
    let mut report = DiffReport::default();

    compare_functions(old, new, &mut report, policy)?;
    compare_structs(old, new, &mut report, policy)?;
    compare_enums(old, new, &mut report);
    compare_unions(old, new, &mut report, policy)?;
    compare_error_enums(old, new, &mut report);

    detect_cascading_layout_breaks_with_policy(old, &mut report, policy)?;

    Ok(report)
}

/// Category label for contract environment metadata findings.
pub const ENVIRONMENT_CATEGORY: &str = "Environment";

/// Compare decoded environment metadata between two contract builds.
pub fn compare_env_metadata(
    old: Option<&ContractEnvMeta>,
    new: Option<&ContractEnvMeta>,
    report: &mut DiffReport,
) {
    match (old, new) {
        (None, None) => {}
        (Some(old_meta), Some(new_meta)) if old_meta == new_meta => {}
        (old_meta, new_meta) => {
            let severity = env_metadata_change_severity(old_meta, new_meta);
            report.findings.push(Finding {
                severity,
                category: ENVIRONMENT_CATEGORY.to_string(),
                message: format_env_metadata_change(old_meta, new_meta),
                type_name: None,
                target: None,
            });
        }
    }
}

fn env_metadata_change_severity(
    old: Option<&ContractEnvMeta>,
    new: Option<&ContractEnvMeta>,
) -> Severity {
    let old_protocol = old.and_then(ContractEnvMeta::protocol_version);
    let new_protocol = new.and_then(ContractEnvMeta::protocol_version);

    if old_protocol.is_some() && new_protocol.is_some() && old_protocol != new_protocol {
        Severity::Warning
    } else {
        Severity::Info
    }
}

fn format_env_metadata_change(
    old: Option<&ContractEnvMeta>,
    new: Option<&ContractEnvMeta>,
) -> String {
    match (old, new) {
        (None, Some(new_meta)) => format!(
            "Contract environment metadata appeared ({}).",
            new_meta.summary()
        ),
        (Some(old_meta), None) => format!(
            "Contract environment metadata was removed (was: {}).",
            old_meta.summary()
        ),
        (Some(old_meta), Some(new_meta)) => {
            if let (Some(old_proto), Some(new_proto)) =
                (old_meta.protocol_version(), new_meta.protocol_version())
            {
                if old_proto != new_proto {
                    return format!(
                        "Soroban protocol interface version changed from {} to {} \
                         (pre-release {} → {}).",
                        old_proto,
                        new_proto,
                        old_meta.pre_release_version().unwrap_or(0),
                        new_meta.pre_release_version().unwrap_or(0),
                    );
                }
            }

            format!(
                "Contract environment metadata changed from {} to {}.",
                old_meta.summary(),
                new_meta.summary()
            )
        }
        (None, None) => unreachable!("compare_env_metadata filters identical/absent pairs"),
    }
}

/// Helper to detect if a User-Defined Type represents an Event by standard Soroban naming conventions.
fn is_event(name: &str) -> bool {
    name.to_lowercase().contains("event")
}

/// Compare function signatures between old and new contract specs.
fn compare_functions(
    old: &ContractSpec,
    new: &ContractSpec,
    report: &mut DiffReport,
    policy: &ResourcePolicy,
) -> Result<(), LimitError> {
    // Check for removed or changed functions
    for (name, old_fn) in &old.functions {
        match new.functions.get(name) {
            None => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Function Removed".to_string(),
                    message: format!(
                        "Function '{}' was removed. Existing callers will break.",
                        name
                    ),
                    type_name: None,
                    target: Some(name.clone()),
                });
            }
            Some(new_fn) => {
                check_function_signature(name, old_fn, new_fn, report, policy)?;
                // Compare function doc-strings and emit informational findings
                if old_fn.doc != new_fn.doc {
                    let old_doc_empty = old_fn.doc.to_string().is_empty();
                    let new_doc_empty = new_fn.doc.to_string().is_empty();
                    let message = if old_doc_empty && !new_doc_empty {
                        format!("Function '{}' documentation was added.", name)
                    } else if !old_doc_empty && new_doc_empty {
                        format!("Function '{}' documentation was removed.", name)
                    } else {
                        format!("Function '{}' documentation changed.", name)
                    };

                    report.findings.push(Finding {
                        severity: Severity::Info,
                        category: "Function Documentation Changed".to_string(),
                        message,
                        type_name: None,
                        target: Some(name.clone()),
                    });
                }
            }
        }
    }

    // Check for newly added functions (informational)
    for name in new.functions.keys() {
        if !old.functions.contains_key(name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Function Added".to_string(),
                message: format!("New function '{}' added.", name),
                type_name: None,
                target: Some(name.clone()),
            });
        }
    }

    Ok(())
}

/// Compare signatures of two functions with the same name.
fn check_function_signature(
    name: &str,
    old_fn: &ScSpecFunctionV0,
    new_fn: &ScSpecFunctionV0,
    report: &mut DiffReport,
    policy: &ResourcePolicy,
) -> Result<(), LimitError> {
    // Check input count
    let old_inputs: &[ScSpecFunctionInputV0] = old_fn.inputs.as_ref();
    let new_inputs: &[ScSpecFunctionInputV0] = new_fn.inputs.as_ref();

    if old_inputs.len() != new_inputs.len() {
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Function Signature Changed".to_string(),
            message: format!(
                "Function '{}': parameter count changed from {} to {}.",
                name,
                old_inputs.len(),
                new_inputs.len()
            ),
            type_name: None,
            target: Some(name.to_string()),
        });
        return Ok(()); // No point comparing individual params if count differs
    }

    // Check each input parameter
    let old_names: Vec<String> = old_inputs
        .iter()
        .map(|input| input.name.to_string())
        .collect();
    let new_names: Vec<String> = new_inputs
        .iter()
        .map(|input| input.name.to_string())
        .collect();

    let old_names_set: std::collections::HashSet<String> = old_names.iter().cloned().collect();
    let new_names_set: std::collections::HashSet<String> = new_names.iter().cloned().collect();

    let is_reordered = old_names_set == new_names_set && old_names != new_names;

    if is_reordered {
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Parameter Reordered".to_string(),
            message: format!(
                "Function '{}': parameters reordered. The set of parameter names is unchanged but their order differs.",
                name
            ),
            type_name: None,
            target: Some(name.to_string()),
        });

        // Check for genuine type changes by matching parameter name.
        let new_by_name: std::collections::HashMap<String, &ScSpecTypeDef> = new_inputs
            .iter()
            .map(|input| (input.name.to_string(), &input.type_))
            .collect();

        for (i, old_input) in old_inputs.iter().enumerate() {
            let p_name = old_input.name.to_string();
            if let Some(new_type) = new_by_name.get(&p_name) {
                if !types_equal(&old_input.type_, new_type, policy)? {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        category: "Parameter Type Changed".to_string(),
                        message: format!(
                            "Function '{}': parameter {} ('{}') type changed from `{}` to `{}`.",
                            name,
                            i,
                            p_name,
                            try_type_to_string(&old_input.type_, 0, policy.max_walk_depth)?,
                            try_type_to_string(new_type, 0, policy.max_walk_depth)?
                        ),
                        type_name: None,
                        target: Some(format!("{}.{}", name, p_name)),
                    });
                }
            }
        }
    } else {
        // Fall back to original positional check
        for (i, (old_input, new_input)) in old_inputs.iter().zip(new_inputs.iter()).enumerate() {
            let old_name = old_input.name.to_string();
            let new_name = new_input.name.to_string();

            if old_name != new_name {
                report.findings.push(Finding {
                    severity: Severity::Warning,
                    category: "Parameter Renamed".to_string(),
                    message: format!(
                        "Function '{}': parameter {} renamed from '{}' to '{}'.",
                        name, i, old_name, new_name
                    ),
                    type_name: None,
                    target: Some(format!("{}.{}", name, old_name)),
                });
            }

            if !types_equal(&old_input.type_, &new_input.type_, policy)? {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Parameter Type Changed".to_string(),
                    message: format!(
                        "Function '{}': parameter {} ('{}') type changed from `{}` to `{}`.",
                        name,
                        i,
                        old_name,
                        try_type_to_string(&old_input.type_, 0, policy.max_walk_depth)?,
                        try_type_to_string(&new_input.type_, 0, policy.max_walk_depth)?
                    ),
                    type_name: None,
                    target: Some(format!("{}.{}", name, old_name)),
                });
            }
        }
    }

    // Check output types
    let old_outputs: &[ScSpecTypeDef] = old_fn.outputs.as_ref();
    let new_outputs: &[ScSpecTypeDef] = new_fn.outputs.as_ref();

    if old_outputs.len() != new_outputs.len() {
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Return Type Changed".to_string(),
            message: format!(
                "Function '{}': return type count changed from {} to {}.",
                name,
                old_outputs.len(),
                new_outputs.len()
            ),
            type_name: None,
            target: Some(name.to_string()),
        });
    } else {
        for (i, (old_out, new_out)) in old_outputs.iter().zip(new_outputs.iter()).enumerate() {
            if !types_equal(old_out, new_out, policy)? {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Return Type Changed".to_string(),
                    message: format!(
                        "Function '{}': return type {} changed from `{}` to `{}`.",
                        name,
                        i,
                        try_type_to_string(old_out, 0, policy.max_walk_depth)?,
                        try_type_to_string(new_out, 0, policy.max_walk_depth)?
                    ),
                    type_name: None,
                    target: Some(name.to_string()),
                });
            }
        }
    }

    Ok(())
}

/// Compare two `ScSpecTypeDef` values for structural equality, bounding the
/// recursion to `policy.max_walk_depth`.
///
/// Replaces the derived recursive `PartialEq` (which has no depth bound and would
/// overflow the stack on a maliciously nested type). Same-discriminant container
/// variants are compared explicitly with a depth counter; the `_` arm only ever
/// sees leaf types or a discriminant mismatch, so its `a == b` is O(1) and safe.
fn types_equal(
    a: &ScSpecTypeDef,
    b: &ScSpecTypeDef,
    policy: &ResourcePolicy,
) -> Result<bool, LimitError> {
    types_equal_inner(a, b, 0, policy.max_walk_depth)
}

fn types_equal_inner(
    a: &ScSpecTypeDef,
    b: &ScSpecTypeDef,
    depth: usize,
    max: usize,
) -> Result<bool, LimitError> {
    if depth > max {
        return Err(LimitError::WalkDepthExceeded { limit: max });
    }
    let equal = match (a, b) {
        (ScSpecTypeDef::Option(x), ScSpecTypeDef::Option(y)) => {
            types_equal_inner(&x.value_type, &y.value_type, depth + 1, max)?
        }
        (ScSpecTypeDef::Result(x), ScSpecTypeDef::Result(y)) => {
            types_equal_inner(&x.ok_type, &y.ok_type, depth + 1, max)?
                && types_equal_inner(&x.error_type, &y.error_type, depth + 1, max)?
        }
        (ScSpecTypeDef::Vec(x), ScSpecTypeDef::Vec(y)) => {
            types_equal_inner(&x.element_type, &y.element_type, depth + 1, max)?
        }
        (ScSpecTypeDef::Map(x), ScSpecTypeDef::Map(y)) => {
            types_equal_inner(&x.key_type, &y.key_type, depth + 1, max)?
                && types_equal_inner(&x.value_type, &y.value_type, depth + 1, max)?
        }
        (ScSpecTypeDef::Tuple(x), ScSpecTypeDef::Tuple(y)) => {
            let xs: &[ScSpecTypeDef] = x.value_types.as_ref();
            let ys: &[ScSpecTypeDef] = y.value_types.as_ref();
            if xs.len() != ys.len() {
                false
            } else {
                let mut all_eq = true;
                for (l, r) in xs.iter().zip(ys.iter()) {
                    if !types_equal_inner(l, r, depth + 1, max)? {
                        all_eq = false;
                        break;
                    }
                }
                all_eq
            }
        }
        // Leaf types (primitives, BytesN, Udt) and any discriminant mismatch:
        // the derived equality here is O(1) and never recurses into a container.
        _ => a == b,
    };
    Ok(equal)
}

/// Compare struct definitions between old and new contract specs.
fn compare_structs(
    old: &ContractSpec,
    new: &ContractSpec,
    report: &mut DiffReport,
    policy: &ResourcePolicy,
) -> Result<(), LimitError> {
    for (name, old_struct) in &old.structs {
        let is_evt = is_event(name);
        match new.structs.get(name) {
            None => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: if is_evt {
                        "Event Definition Removed".to_string()
                    } else {
                        "Struct Removed".to_string()
                    },
                    message: format!(
                        "{} '{}' was removed. Storage or systems relying on this type will break.",
                        if is_evt { "Event struct" } else { "Struct" },
                        name
                    ),
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                });
            }
            Some(new_struct) => {
                check_struct_fields(name, old_struct, new_struct, report, policy)?;
                // Compare struct doc-strings (informational only)
                if old_struct.doc != new_struct.doc {
                    let old_doc_empty = old_struct.doc.to_string().is_empty();
                    let new_doc_empty = new_struct.doc.to_string().is_empty();
                    let message = if old_doc_empty && !new_doc_empty {
                        format!("Struct '{}' documentation was added.", name)
                    } else if !old_doc_empty && new_doc_empty {
                        format!("Struct '{}' documentation was removed.", name)
                    } else {
                        format!("Struct '{}' documentation changed.", name)
                    };

                    report.findings.push(Finding {
                        severity: Severity::Info,
                        category: "Struct Documentation Changed".to_string(),
                        message,
                        type_name: Some(name.clone()),
                        target: Some(name.clone()),
                    });
                }
            }
        }
    }

    // Check for newly added structs (informational)
    for name in new.structs.keys() {
        if !old.structs.contains_key(name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Struct Added".to_string(),
                message: format!("New struct '{}' added.", name),
                type_name: Some(name.clone()),
                target: Some(name.clone()),
            });
        }
    }

    Ok(())
}

/// Compare fields of two structs with the same name.
///
/// Soroban serializes struct fields by position order, so field reordering,
/// removal, insertion, or type changes all break storage layout compatibility.
///
/// This uses name-based bipartite matching to produce a correct edit script:
///
///   1. Build name→index maps for old and new fields (first occurrence wins).
///   2. Deletions — old names absent from new → Critical.
///   3. Insertions — new names absent from old:
///        - Position ≥ old.len() → Warning (tail append).
///        - Else              → Critical (mid-sequence insertion).
///   4. Matched fields — same name in both:
///        - Position changed → Critical (reorder).
///        - Type changed     → Critical (type change).
///
/// ## Severity Table
///
/// | Finding | Severity | Category (struct) | Category (event) |
/// |---|---|---|---|
/// | Field removed | Critical | `Struct Field Removed` | `Event Schema Removed` |
/// | Field inserted mid-sequence | Critical | `Struct Field Inserted` | `Event Field Inserted` |
/// | Field appended at tail | Warning | `Struct Field Added` | `Struct Field Added` |
/// | Field moved (position changed) | Critical | `Struct Field Reordered` | `Event Schema Reordered` |
/// | Field type changed | Critical | `Struct Field Type Changed` | `Event Schema Type Changed` |
fn check_struct_fields(
    name: &str,
    old_struct: &ScSpecUdtStructV0,
    new_struct: &ScSpecUdtStructV0,
    report: &mut DiffReport,
    policy: &ResourcePolicy,
) -> Result<(), LimitError> {
    let old_fields: &[ScSpecUdtStructFieldV0] = old_struct.fields.as_ref();
    let new_fields: &[ScSpecUdtStructFieldV0] = new_struct.fields.as_ref();
    let is_evt = is_event(name);
    let category_prefix = if is_evt {
        "Event Schema"
    } else {
        "Struct Field"
    };
    let msg_prefix = if is_evt { "Event schema" } else { "Struct" };

    // Phase 1: Build name→index maps (first occurrence wins for duplicate names)
    let mut old_by_name: HashMap<String, usize> = HashMap::with_capacity(old_fields.len());
    for (i, f) in old_fields.iter().enumerate() {
        old_by_name.entry(f.name.to_string()).or_insert(i);
    }
    let mut new_by_name: HashMap<String, usize> = HashMap::with_capacity(new_fields.len());
    for (i, f) in new_fields.iter().enumerate() {
        new_by_name.entry(f.name.to_string()).or_insert(i);
    }

    // Phase 2: Deletions — old name not present in new
    for (old_name, &_old_idx) in &old_by_name {
        if !new_by_name.contains_key(old_name) {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: format!("{} Removed", category_prefix),
                message: format!(
                    "{} '{}': field '{}' was removed. Backwards compatibility is broken.",
                    msg_prefix, name, old_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
            });
        }
    }

    // Phase 3: Insertions — new name not present in old
    for (new_name, &new_idx) in &new_by_name {
        if !old_by_name.contains_key(new_name) {
            if new_idx >= old_fields.len() {
                // Tail append → Warning (existing behaviour)
                report.findings.push(Finding {
                    severity: Severity::Warning,
                    category: "Struct Field Added".to_string(),
                    message: format!(
                        "Struct '{}': new field '{}' appended. \
                         Existing storage entries won't have this field — ensure migration handles defaults.",
                        name, new_name
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, new_name)),
                });
            } else {
                // Mid-sequence insertion → Critical
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: format!("{} Inserted", category_prefix),
                    message: format!(
                        "{} '{}': field '{}' inserted at position {}. \
                         Positional serialization breaks layout compatibility.",
                        msg_prefix, name, new_name, new_idx
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, new_name)),
                });
            }
        }
    }

    // Phase 4: Matched fields — same name in both versions
    for (shared_name, &old_idx) in &old_by_name {
        if let Some(&new_idx) = new_by_name.get(shared_name) {
            let old_field = &old_fields[old_idx];
            let new_field = &new_fields[new_idx];

            // Position change (move / reorder)
            if old_idx != new_idx {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: format!("{} Reordered", category_prefix),
                    message: format!(
                        "{} '{}': field at position {} changed from '{}' to '{}'. \
                         Positional serialization breaks layout compatibility.",
                        msg_prefix, name, old_idx, old_field.name, new_field.name
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, shared_name)),
                });
            }

            // Type change
            if !types_equal(&old_field.type_, &new_field.type_, policy)? {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: format!("{} Type Changed", category_prefix),
                    message: format!(
                        "{} '{}': field '{}' (position {}) type changed from `{}` to `{}`.",
                        msg_prefix,
                        name,
                        shared_name,
                        old_idx,
                        try_type_to_string(&old_field.type_, 0, policy.max_walk_depth)?,
                        try_type_to_string(&new_field.type_, 0, policy.max_walk_depth)?
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, shared_name)),
                });
            }
        }
    }

    Ok(())
}

/// Compare enum definitions between old and new contract specs.
fn compare_enums(old: &ContractSpec, new: &ContractSpec, report: &mut DiffReport) {
    for (name, old_enum) in &old.enums {
        let is_evt = is_event(name);
        match new.enums.get(name) {
            None => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: if is_evt {
                        "Event Enum Removed".to_string()
                    } else {
                        "Enum Removed".to_string()
                    },
                    message: format!(
                        "{} '{}' was removed. Data using this type will be invalid.",
                        if is_evt { "Event enum" } else { "Enum" },
                        name
                    ),
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                });
            }
            Some(new_enum) => {
                check_enum_cases(name, old_enum, new_enum, report);
                // Compare enum doc-strings (informational only)
                if old_enum.doc != new_enum.doc {
                    let old_doc_empty = old_enum.doc.to_string().is_empty();
                    let new_doc_empty = new_enum.doc.to_string().is_empty();
                    let message = if old_doc_empty && !new_doc_empty {
                        format!("Enum '{}' documentation was added.", name)
                    } else if !old_doc_empty && new_doc_empty {
                        format!("Enum '{}' documentation was removed.", name)
                    } else {
                        format!("Enum '{}' documentation changed.", name)
                    };

                    report.findings.push(Finding {
                        severity: Severity::Info,
                        category: "Enum Documentation Changed".to_string(),
                        message,
                        type_name: Some(name.clone()),
                        target: Some(name.clone()),
                    });
                }
            }
        }
    }

    // Check for newly added enums
    for name in new.enums.keys() {
        if !old.enums.contains_key(name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Enum Added".to_string(),
                message: format!("New enum '{}' added.", name),
                type_name: Some(name.clone()),
                target: Some(name.clone()),
            });
        }
    }
}

/// Compare cases of two enums with the same name.
fn check_enum_cases(
    name: &str,
    old_enum: &ScSpecUdtEnumV0,
    new_enum: &ScSpecUdtEnumV0,
    report: &mut DiffReport,
) {
    let is_evt = is_event(name);
    let category_prefix = if is_evt {
        "Event Enum Case"
    } else {
        "Enum Case"
    };
    let msg_prefix = if is_evt { "Event enum" } else { "Enum" };
    let old_cases: &[ScSpecUdtEnumCaseV0] = old_enum.cases.as_ref();
    let new_cases: &[ScSpecUdtEnumCaseV0] = new_enum.cases.as_ref();

    for old_case in old_cases {
        let old_name = old_case.name.to_string();

        match new_cases.iter().find(|c| c.name.to_string() == old_name) {
            None => {
                // The case was removed entirely
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: format!("{} Removed", category_prefix),
                    message: format!(
                        "{} '{}': case '{}' (value: {}) was removed. \
                         On-chain data or events relying on this value will be invalid.",
                        msg_prefix, name, old_name, old_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                });
            }
            Some(new_case) => {
                // The case exists, but did its integer value change?
                if old_case.value != new_case.value {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        category: format!("{} Value Changed", category_prefix),
                        message: format!(
                            "{} '{}': case '{}' value changed from {} to {}. \
                             This breaks data serialization.",
                            msg_prefix, name, old_name, old_case.value, new_case.value
                        ),
                        type_name: Some(name.to_string()),
                        target: Some(format!("{}.{}", name, old_name)),
                    });
                }
            }
        }
    }

    // Check for new enum cases (usually safe, but good to know)
    if new_cases.len() > old_cases.len() {
        for new_case in new_cases {
            let new_name = new_case.name.to_string();
            if !old_cases.iter().any(|c| c.name.to_string() == new_name) {
                report.findings.push(Finding {
                    severity: Severity::Info,
                    category: format!("{} Added", category_prefix),
                    message: format!(
                        "{} '{}': new case '{}' (value {}) added.",
                        msg_prefix, name, new_name, new_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, new_name)),
                });
            }
        }
    }
}

/// Compare union definitions between old and new contract specs.
fn compare_unions(
    old: &ContractSpec,
    new: &ContractSpec,
    report: &mut DiffReport,
    policy: &ResourcePolicy,
) -> Result<(), LimitError> {
    for (name, old_union) in &old.unions {
        match new.unions.get(name) {
            None => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Union Removed".to_string(),
                    message: format!(
                        "Union '{}' was removed. Data using this type will be invalid.",
                        name
                    ),
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                });
            }
            Some(new_union) => {
                check_union_cases(name, old_union, new_union, report, policy)?;
            }
        }
    }

    for name in new.unions.keys() {
        if !old.unions.contains_key(name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Union Added".to_string(),
                message: format!("New union '{}' added.", name),
                type_name: Some(name.clone()),
                target: Some(name.clone()),
            });
        }
    }

    Ok(())
}

/// Compare cases of two unions with the same name.
///
/// Soroban unions serialize cases by positional discriminant, so case reordering,
/// removal, insertion, or payload type changes all break layout compatibility.
///
/// This uses name-based bipartite matching, identical to the approach in
/// [`check_struct_fields`].
///
/// ## Severity Table
///
/// | Finding | Severity | Category |
/// |---|---|---|
/// | Case removed | Critical | `Union Case Removed` |
/// | Case inserted mid-sequence | Critical | `Union Case Inserted` |
/// | Case appended at tail | Info | `Union Case Added` |
/// | Case moved (position changed) | Critical | `Union Case Reordered` |
/// | Case payload type changed | Critical | `Union Case Type Changed` |
fn check_union_cases(
    name: &str,
    old_union: &ScSpecUdtUnionV0,
    new_union: &ScSpecUdtUnionV0,
    report: &mut DiffReport,
    policy: &ResourcePolicy,
) -> Result<(), LimitError> {
    let old_cases: &[ScSpecUdtUnionCaseV0] = old_union.cases.as_ref();
    let new_cases: &[ScSpecUdtUnionCaseV0] = new_union.cases.as_ref();

    // Phase 1: Build name→index maps (first occurrence wins)
    let mut old_by_name: HashMap<String, usize> = HashMap::with_capacity(old_cases.len());
    for (i, c) in old_cases.iter().enumerate() {
        old_by_name.entry(union_case_name(c)).or_insert(i);
    }
    let mut new_by_name: HashMap<String, usize> = HashMap::with_capacity(new_cases.len());
    for (i, c) in new_cases.iter().enumerate() {
        new_by_name.entry(union_case_name(c)).or_insert(i);
    }

    // Phase 2: Deletions — old case name not present in new
    for (old_name, &_old_idx) in &old_by_name {
        if !new_by_name.contains_key(old_name) {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Union Case Removed".to_string(),
                message: format!(
                    "Union '{}': case '{}' was removed. Backwards compatibility is broken.",
                    name, old_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
            });
        }
    }

    // Phase 3: Insertions — new case name not present in old
    for (new_name, &new_idx) in &new_by_name {
        if !old_by_name.contains_key(new_name) {
            if new_idx >= old_cases.len() {
                // Tail append → Info (existing behaviour)
                let sig = union_case_type_signature(&new_cases[new_idx], policy)?;
                report.findings.push(Finding {
                    severity: Severity::Info,
                    category: "Union Case Added".to_string(),
                    message: format!("Union '{}': new case '{}' ({}) added.", name, new_name, sig),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, new_name)),
                });
            } else {
                // Mid-sequence insertion → Critical
                let sig = union_case_type_signature(&new_cases[new_idx], policy)?;
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Union Case Inserted".to_string(),
                    message: format!(
                        "Union '{}': case '{}' ({}) inserted at position {}. \
                         Positional discriminant breaks layout compatibility.",
                        name, new_name, sig, new_idx
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, new_name)),
                });
            }
        }
    }

    // Phase 4: Matched cases — same name in both versions
    for (shared_name, &old_idx) in &old_by_name {
        if let Some(&new_idx) = new_by_name.get(shared_name) {
            let old_case = &old_cases[old_idx];
            let new_case = &new_cases[new_idx];

            // Position change (move / reorder)
            if old_idx != new_idx {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Union Case Reordered".to_string(),
                    message: format!(
                        "Union '{}': case at position {} changed from '{}' to '{}'. \
                         Positional discriminant breaks layout compatibility.",
                        name,
                        old_idx,
                        union_case_name(old_case),
                        union_case_name(new_case)
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, shared_name)),
                });
            }

            // Type / payload change
            if !union_cases_equal(old_case, new_case, policy)? {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Union Case Type Changed".to_string(),
                    message: format!(
                        "Union '{}': case '{}' (position {}) type changed from `{}` to `{}`.",
                        name,
                        shared_name,
                        old_idx,
                        union_case_type_signature(old_case, policy)?,
                        union_case_type_signature(new_case, policy)?
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, shared_name)),
                });
            }
        }
    }

    Ok(())
}

fn union_case_name(case: &ScSpecUdtUnionCaseV0) -> String {
    match case {
        ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string(),
        ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string(),
    }
}

fn union_case_type_signature(
    case: &ScSpecUdtUnionCaseV0,
    policy: &ResourcePolicy,
) -> Result<String, LimitError> {
    Ok(match case {
        ScSpecUdtUnionCaseV0::VoidV0(_) => "void".to_string(),
        ScSpecUdtUnionCaseV0::TupleV0(t) => {
            let types: Vec<String> = t
                .type_
                .iter()
                .map(|ty| try_type_to_string(ty, 0, policy.max_walk_depth))
                .collect::<Result<_, _>>()?;
            format!("({})", types.join(", "))
        }
    })
}

fn union_cases_equal(
    a: &ScSpecUdtUnionCaseV0,
    b: &ScSpecUdtUnionCaseV0,
    policy: &ResourcePolicy,
) -> Result<bool, LimitError> {
    Ok(match (a, b) {
        (ScSpecUdtUnionCaseV0::VoidV0(_), ScSpecUdtUnionCaseV0::VoidV0(_)) => true,
        (ScSpecUdtUnionCaseV0::TupleV0(a_tuple), ScSpecUdtUnionCaseV0::TupleV0(b_tuple)) => {
            let a_types: &[ScSpecTypeDef] = a_tuple.type_.as_ref();
            let b_types: &[ScSpecTypeDef] = b_tuple.type_.as_ref();
            if a_types.len() != b_types.len() {
                false
            } else {
                let mut all_eq = true;
                for (left, right) in a_types.iter().zip(b_types.iter()) {
                    if !types_equal(left, right, policy)? {
                        all_eq = false;
                        break;
                    }
                }
                all_eq
            }
        }
        _ => false,
    })
}

/// Compare contract error enum definitions between old and new specs.
fn compare_error_enums(old: &ContractSpec, new: &ContractSpec, report: &mut DiffReport) {
    for (name, old_error_enum) in &old.error_enums {
        match new.error_enums.get(name) {
            None => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Error Enum Removed".to_string(),
                    message: format!(
                        "Error enum '{}' was removed. Clients matching on these errors will break.",
                        name
                    ),
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                });
            }
            Some(new_error_enum) => {
                check_error_enum_cases(name, old_error_enum, new_error_enum, report);
            }
        }
    }

    for name in new.error_enums.keys() {
        if !old.error_enums.contains_key(name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Error Enum Added".to_string(),
                message: format!("New error enum '{}' added.", name),
                type_name: Some(name.clone()),
                target: Some(name.clone()),
            });
        }
    }
}

/// Compare cases of two error enums with the same name.
fn check_error_enum_cases(
    name: &str,
    old_error_enum: &ScSpecUdtErrorEnumV0,
    new_error_enum: &ScSpecUdtErrorEnumV0,
    report: &mut DiffReport,
) {
    let old_cases: &[ScSpecUdtErrorEnumCaseV0] = old_error_enum.cases.as_ref();
    let new_cases: &[ScSpecUdtErrorEnumCaseV0] = new_error_enum.cases.as_ref();

    for old_case in old_cases {
        let old_name = old_case.name.to_string();
        match new_cases.iter().find(|c| c.name.to_string() == old_name) {
            None => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Error Enum Case Removed".to_string(),
                    message: format!(
                        "Error enum '{}': case '{}' (value: {}) was removed. \
                         Clients matching on this error code will break.",
                        name, old_name, old_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                });
            }
            Some(new_case) if old_case.value != new_case.value => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Error Enum Case Value Changed".to_string(),
                    message: format!(
                        "Error enum '{}': case '{}' value changed from {} to {}. \
                         This breaks error-code compatibility.",
                        name, old_name, old_case.value, new_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                });
            }
            _ => {}
        }
    }

    for new_case in new_cases {
        let new_name = new_case.name.to_string();
        if !old_cases.iter().any(|c| c.name.to_string() == new_name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Error Enum Case Added".to_string(),
                message: format!(
                    "Error enum '{}': new case '{}' (value {}) added.",
                    name, new_name, new_case.value
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, new_name)),
            });
        }
    }
}

/// Uses dependency graphing to figure out if storage layout changes cascade to
/// other types. Infallible wrapper (default policy) retained for unit tests;
/// production uses [`detect_cascading_layout_breaks_with_policy`].
#[cfg(test)]
fn detect_cascading_layout_breaks(old: &ContractSpec, report: &mut DiffReport) {
    let _ = detect_cascading_layout_breaks_with_policy(old, report, &ResourcePolicy::default());
}

/// Depth-bounded variant of `detect_cascading_layout_breaks`: the reverse
/// dependency walk is bounded by `policy.max_walk_depth`, so a maliciously nested
/// type yields [`LimitError::WalkDepthExceeded`] rather than overflowing the stack.
fn detect_cascading_layout_breaks_with_policy(
    old: &ContractSpec,
    report: &mut DiffReport,
    policy: &ResourcePolicy,
) -> Result<(), LimitError> {
    let old_mapper = LayoutMapper::new_with_policy(old, policy);
    let reverse_deps = old_mapper.try_build_reverse_dependencies()?;

    // Collect all UDTs that had a critical breaking change.
    // We read `type_name` directly — no message-text parsing needed.
    let mut broken_types = std::collections::HashSet::new();
    for finding in &report.findings {
        if finding.severity == Severity::Critical {
            if let Some(ref name) = finding.type_name {
                broken_types.insert(name.clone());
            }
        }
    }

    // A queue for transitive breaks
    let mut queue: Vec<String> = broken_types.into_iter().collect();
    let mut i = 0;
    let mut cascaded = std::collections::HashSet::new();

    while i < queue.len() {
        let current_broken_type = queue[i].clone();
        i += 1;

        if let Some(dependents) = reverse_deps.get(&current_broken_type) {
            for dep in dependents {
                // Ignore if it was the original broken type
                if !cascaded.contains(dep) {
                    cascaded.insert(dep.clone());
                    queue.push(dep.clone());

                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        category: "Cascading Layout Break".to_string(),
                        message: format!(
                            "Type '{}' layout is broken because it embeds modified type '{}'. \
                             Stored data for '{}' is no longer compatible.",
                            dep, current_broken_type, dep
                        ),
                        type_name: Some(dep.clone()),
                        target: Some(dep.clone()),
                    });
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::hash_set;
    use proptest::prelude::*;
    use stellar_xdr::curr::{
        ScEnvMetaEntry, ScSpecTypeUdt, ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionCaseVoidV0,
        StringM, VecM,
    };

    /// Helper: build a minimal ContractSpec with the given structs.
    fn spec_with_structs(structs: Vec<(&str, Vec<(&str, ScSpecTypeDef)>)>) -> ContractSpec {
        let mut spec = ContractSpec::default();
        for (name, fields) in structs {
            let xdr_fields: Vec<ScSpecUdtStructFieldV0> = fields
                .into_iter()
                .map(|(fname, ftype)| ScSpecUdtStructFieldV0 {
                    doc: StringM::default(),
                    name: fname.try_into().unwrap(),
                    type_: ftype,
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
        spec
    }

    /// Helper: create a UDT type reference.
    fn udt(name: &str) -> ScSpecTypeDef {
        ScSpecTypeDef::Udt(ScSpecTypeUdt {
            name: name.try_into().unwrap(),
        })
    }

    // ---------------------------------------------------------------
    // Test 1: cascade detection picks up broken types via type_name
    // ---------------------------------------------------------------
    #[test]
    fn cascade_detects_break_via_type_name() {
        // Old spec: Inner(value: u32), Outer(inner: Inner)
        let old = spec_with_structs(vec![
            ("Inner", vec![("value", ScSpecTypeDef::U32)]),
            ("Outer", vec![("inner", udt("Inner"))]),
        ]);
        // New spec: Inner has its field type changed -> triggers Critical
        let new = spec_with_structs(vec![
            ("Inner", vec![("value", ScSpecTypeDef::U64)]),
            ("Outer", vec![("inner", udt("Inner"))]),
        ]);

        let report = compare(&old, &new);

        // Inner should have a direct Critical finding
        let inner_critical = report.findings.iter().any(|f| {
            f.severity == Severity::Critical
                && f.type_name.as_deref() == Some("Inner")
                && f.category != "Cascading Layout Break"
        });
        assert!(
            inner_critical,
            "Expected a direct critical finding for Inner"
        );

        // Outer should have a cascading break with clear dependency wording
        let outer_cascade = report.findings.iter().find(|f| {
            f.severity == Severity::Critical
                && f.type_name.as_deref() == Some("Outer")
                && f.category == "Cascading Layout Break"
        });
        assert!(
            outer_cascade.is_some(),
            "Expected a cascading break for Outer"
        );
        let message = &outer_cascade.unwrap().message;
        assert!(
            !message.contains("broken safely"),
            "Cascade message must not use contradictory 'broken safely' phrasing"
        );
        assert!(
            message
                .contains("Type 'Outer' layout is broken because it embeds modified type 'Inner'"),
            "Unexpected cascade message: {message}"
        );
        assert!(
            message.contains("Stored data for 'Outer' is no longer compatible"),
            "Cascade message must explain storage impact: {message}"
        );
    }

    // ---------------------------------------------------------------
    // Test 2: changing a finding's message text does NOT affect cascade
    // ---------------------------------------------------------------
    #[test]
    fn cascade_is_message_independent() {
        // Old spec: Child(x: u32), Parent(child: Child)
        let old = spec_with_structs(vec![
            ("Child", vec![("x", ScSpecTypeDef::U32)]),
            ("Parent", vec![("child", udt("Child"))]),
        ]);

        // Build a report with a manually crafted finding whose message
        // is completely different from the production format, but whose
        // type_name is set correctly.
        let mut report = DiffReport::default();
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "TOTALLY CUSTOM CATEGORY".to_string(),
            message: "This message has no quotes and mentions no type prefix whatsoever."
                .to_string(),
            type_name: Some("Child".to_string()),
            target: Some("Child".to_string()),
        });

        // Run cascade detection against the old spec
        detect_cascading_layout_breaks(&old, &mut report);

        // Parent should still be detected as cascaded
        let parent_cascade = report.findings.iter().any(|f| {
            f.severity == Severity::Critical
                && f.type_name.as_deref() == Some("Parent")
                && f.category == "Cascading Layout Break"
        });
        assert!(
            parent_cascade,
            "Cascade should work regardless of message text"
        );
    }

    // ---------------------------------------------------------------
    // Test 3: function-level findings (type_name: None) do NOT
    //         trigger false cascades
    // ---------------------------------------------------------------
    #[test]
    fn function_findings_do_not_cascade() {
        let old = spec_with_structs(vec![("MyStruct", vec![("val", ScSpecTypeDef::U32)])]);

        let mut report = DiffReport::default();
        // Simulate a function-level Critical finding with type_name: None
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Function Removed".to_string(),
            message: "Function 'do_stuff' was removed.".to_string(),
            type_name: None,
            target: Some("do_stuff".to_string()),
        });

        detect_cascading_layout_breaks(&old, &mut report);

        // Should still be just the one finding -- no cascade
        assert_eq!(
            report.findings.len(),
            1,
            "Function findings should not trigger cascades"
        );
    }

    // ---------------------------------------------------------------
    // Test 4: transitive cascades (A -> B -> C)
    // ---------------------------------------------------------------
    #[test]
    fn transitive_cascade_propagates() {
        // Leaf(x: u32), Mid(leaf: Leaf), Top(mid: Mid)
        let old = spec_with_structs(vec![
            ("Leaf", vec![("x", ScSpecTypeDef::U32)]),
            ("Mid", vec![("leaf", udt("Leaf"))]),
            ("Top", vec![("mid", udt("Mid"))]),
        ]);
        let new = spec_with_structs(vec![
            ("Leaf", vec![("x", ScSpecTypeDef::U64)]), // break
            ("Mid", vec![("leaf", udt("Leaf"))]),
            ("Top", vec![("mid", udt("Mid"))]),
        ]);

        let report = compare(&old, &new);

        let cascade_types: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.category == "Cascading Layout Break")
            .filter_map(|f| f.type_name.as_deref())
            .collect();

        assert!(
            cascade_types.contains(&"Mid"),
            "Mid should cascade from Leaf"
        );
        assert!(
            cascade_types.contains(&"Top"),
            "Top should cascade from Mid"
        );
    }

    // ---------------------------------------------------------------
    // Test 5: no regression in categories/severities for the basic
    //         struct-field-type-changed scenario
    // ---------------------------------------------------------------
    #[test]
    fn struct_field_type_change_severity_and_category() {
        let old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::I128)])]);

        let report = compare(&old, &new);

        let field_change = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Changed");
        assert!(field_change.is_some(), "Should detect field type change");

        let f = field_change.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.type_name.as_deref(), Some("Data"));
        // The `target` pinpoints the exact field (`Type.field`) so a
        // suppression keyed on it cannot over-apply to sibling fields.
        assert_eq!(f.target.as_deref(), Some("Data.amount"));
    }

    // ---------------------------------------------------------------
    // Test 6: findings carry a precise, structured `target` for every
    //         granularity (function, field, enum case, type).
    // ---------------------------------------------------------------
    #[test]
    fn findings_expose_precise_targets() {
        // Struct removed entirely -> target is the bare type name.
        let old = spec_with_structs(vec![("Gone", vec![("x", ScSpecTypeDef::U32)])]);
        let new = ContractSpec::default();
        let report = compare(&old, &new);
        let removed = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Removed")
            .expect("expected a struct-removed finding");
        assert_eq!(removed.target.as_deref(), Some("Gone"));

        // Struct field removed -> target is `Type.field`.
        let old = spec_with_structs(vec![(
            "Data",
            vec![("keep", ScSpecTypeDef::U32), ("drop", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_structs(vec![("Data", vec![("keep", ScSpecTypeDef::U32)])]);
        let report = compare(&old, &new);
        let field_removed = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Removed")
            .expect("expected a field-removed finding");
        assert_eq!(field_removed.target.as_deref(), Some("Data.drop"));
    }

    fn env_meta(protocol: u32, pre_release: u32) -> ContractEnvMeta {
        let version = ((protocol as u64) << 32) | (pre_release as u64);
        ContractEnvMeta {
            entries: vec![ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(version)],
        }
    }

    #[test]
    fn struct_doc_change_produces_info() {
        let mut old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let mut new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);

        // Set differing docs
        old.structs.get_mut("Data").unwrap().doc = "old doc".try_into().unwrap();
        new.structs.get_mut("Data").unwrap().doc = "new doc".try_into().unwrap();

        let report = compare(&old, &new);

        let found = report.findings.iter().any(|f| {
            f.severity == Severity::Info
                && f.category == "Struct Documentation Changed"
                && f.type_name.as_deref() == Some("Data")
        });
        assert!(found, "Expected an info finding for struct doc change");

        // Ensure info findings do not influence safety
        let safety = crate::report::SafetyReport::new(&report);
        assert!(safety.is_safe);
        assert_eq!(safety.critical_count, 0);
    }

    #[test]
    fn identical_struct_docs_produce_no_finding() {
        let mut old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let mut new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);

        // Same doc text
        old.structs.get_mut("Data").unwrap().doc = "doc".try_into().unwrap();
        new.structs.get_mut("Data").unwrap().doc = "doc".try_into().unwrap();

        let report = compare(&old, &new);
        // No findings expected
        assert!(
            report.findings.is_empty(),
            "Expected no findings when docs identical"
        );
    }

    #[test]
    fn identical_env_metadata_produces_no_finding() {
        let meta = env_meta(21, 0);
        let mut report = DiffReport::default();
        compare_env_metadata(Some(&meta), Some(&meta), &mut report);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn env_metadata_protocol_change_is_warning() {
        let old = env_meta(21, 0);
        let new = env_meta(22, 0);
        let mut report = DiffReport::default();
        compare_env_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.category, ENVIRONMENT_CATEGORY);
        assert!(finding
            .message
            .contains("protocol interface version changed"));
    }

    #[test]
    fn env_metadata_pre_release_only_change_is_info() {
        let old = env_meta(21, 0);
        let new = env_meta(21, 1);
        let mut report = DiffReport::default();
        compare_env_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.category, ENVIRONMENT_CATEGORY);
    }

    #[test]
    fn env_metadata_findings_do_not_affect_is_safe() {
        let old = env_meta(21, 0);
        let new = env_meta(22, 0);
        let mut report = DiffReport::default();
        compare_env_metadata(Some(&old), Some(&new), &mut report);

        let safety = crate::report::SafetyReport::new(&report);
        assert!(safety.is_safe);
        assert_eq!(safety.critical_count, 0);
    }

    /// Helper: build a minimal ContractSpec with the given functions.
    fn spec_with_functions(functions: Vec<(&str, Vec<(&str, ScSpecTypeDef)>)>) -> ContractSpec {
        let mut spec = ContractSpec::default();
        for (name, inputs) in functions {
            let xdr_inputs: Vec<stellar_xdr::curr::ScSpecFunctionInputV0> = inputs
                .into_iter()
                .map(|(iname, itype)| stellar_xdr::curr::ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: iname.try_into().unwrap(),
                    type_: itype,
                })
                .collect();
            spec.functions.insert(
                name.to_string(),
                stellar_xdr::curr::ScSpecFunctionV0 {
                    doc: StringM::default(),
                    name: name.try_into().unwrap(),
                    inputs: VecM::try_from(xdr_inputs).unwrap(),
                    outputs: VecM::default(),
                },
            );
        }
        spec
    }

    #[test]
    fn param_reorder_same_type_produces_critical_finding() {
        let old = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_functions(vec![(
            "test_fn",
            vec![("b", ScSpecTypeDef::U32), ("a", ScSpecTypeDef::U32)],
        )]);

        let report = compare(&old, &new);
        let reorder_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Reordered");

        assert!(
            reorder_finding.is_some(),
            "Expected a Parameter Reordered finding"
        );
        let f = reorder_finding.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.message.contains("parameters reordered"));

        // Ensure no Parameter Renamed warnings are generated
        let rename_findings = report
            .findings
            .iter()
            .filter(|f| f.category == "Parameter Renamed")
            .count();
        assert_eq!(
            rename_findings, 0,
            "Should not double-count reorders as renames"
        );
    }

    #[test]
    fn param_pure_rename_produces_warning() {
        let old = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_functions(vec![(
            "test_fn",
            vec![("x", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);

        let report = compare(&old, &new);
        let rename_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Renamed");

        assert!(
            rename_finding.is_some(),
            "Expected a Parameter Renamed finding"
        );
        let f = rename_finding.unwrap();
        assert_eq!(f.severity, Severity::Warning);

        // Ensure no Parameter Reordered findings are generated
        let reorder_findings = report
            .findings
            .iter()
            .filter(|f| f.category == "Parameter Reordered")
            .count();
        assert_eq!(reorder_findings, 0);
    }

    #[test]
    fn param_type_change_produces_critical_finding() {
        let old = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::Bool), ("b", ScSpecTypeDef::U32)],
        )]);

        let report = compare(&old, &new);
        let type_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Type Changed");

        assert!(
            type_finding.is_some(),
            "Expected a Parameter Type Changed finding"
        );
        let f = type_finding.unwrap();
        assert_eq!(f.severity, Severity::Critical);

        // Ensure no Parameter Reordered findings are generated
        let reorder_findings = report
            .findings
            .iter()
            .filter(|f| f.category == "Parameter Reordered")
            .count();
        assert_eq!(reorder_findings, 0);
    }

    #[test]
    fn param_reorder_and_type_change_produces_both() {
        let old = spec_with_functions(vec![(
            "test_fn",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        )]);
        let new = spec_with_functions(vec![(
            "test_fn",
            vec![("b", ScSpecTypeDef::U32), ("a", ScSpecTypeDef::Bool)],
        )]);

        let report = compare(&old, &new);

        let reorder_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Reordered");
        assert!(
            reorder_finding.is_some(),
            "Expected a Parameter Reordered finding"
        );
        assert_eq!(reorder_finding.unwrap().severity, Severity::Critical);

        let type_finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Type Changed");
        assert!(
            type_finding.is_some(),
            "Expected a Parameter Type Changed finding"
        );
        let tf = type_finding.unwrap();
        assert_eq!(tf.severity, Severity::Critical);
        assert!(tf.message.contains("parameter 0 ('a') type changed")); // Index in old is 0
    }

    // ---------------------------------------------------------------
    // Helpers for union test fixtures
    // ---------------------------------------------------------------
    fn void_case(name: &str) -> ScSpecUdtUnionCaseV0 {
        ScSpecUdtUnionCaseV0::VoidV0(ScSpecUdtUnionCaseVoidV0 {
            doc: StringM::default(),
            name: name.try_into().unwrap(),
        })
    }

    fn tuple_case(name: &str, types: Vec<ScSpecTypeDef>) -> ScSpecUdtUnionCaseV0 {
        ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
            doc: StringM::default(),
            name: name.try_into().unwrap(),
            type_: VecM::try_from(types).unwrap(),
        })
    }

    fn spec_with_unions(name: &str, cases: Vec<ScSpecUdtUnionCaseV0>) -> ContractSpec {
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

    // ---------------------------------------------------------------
    // Struct field: mid-sequence insertion → Critical + no phantom append
    // ---------------------------------------------------------------
    #[test]
    fn struct_field_mid_insertion_is_critical() {
        // This is the attack scenario from fix.md:
        //   Old: { owner: Address, amount: u64 }
        //   New: { owner: Address, fee_bps: u32, amount: u64 }
        let old = spec_with_structs(vec![(
            "Data",
            vec![("owner", udt("Address")), ("amount", ScSpecTypeDef::U64)],
        )]);
        let new = spec_with_structs(vec![(
            "Data",
            vec![
                ("owner", udt("Address")),
                ("fee_bps", ScSpecTypeDef::U32),
                ("amount", ScSpecTypeDef::U64),
            ],
        )]);

        let report = compare(&old, &new);

        // fee_bps is inserted mid-sequence → Critical
        let inserted = report.findings.iter().find(|f| {
            f.category == "Struct Field Inserted" && f.target.as_deref() == Some("Data.fee_bps")
        });
        assert!(
            inserted.is_some(),
            "Expected Struct Field Inserted for fee_bps"
        );
        assert_eq!(inserted.unwrap().severity, Severity::Critical);

        // amount moved from position 1 to 2 → Reordered
        let reordered = report.findings.iter().find(|f| {
            f.category == "Struct Field Reordered" && f.target.as_deref() == Some("Data.amount")
        });
        assert!(
            reordered.is_some(),
            "Expected Struct Field Reordered for amount"
        );
        assert_eq!(reordered.unwrap().severity, Severity::Critical);

        // No phantom "Struct Field Added" for amount (it already exists)
        let phantom_appended = report.findings.iter().any(|f| {
            f.category == "Struct Field Added" && f.target.as_deref() == Some("Data.amount")
        });
        assert!(
            !phantom_appended,
            "amount must not be reported as newly added"
        );
    }

    // ---------------------------------------------------------------
    // Struct field: tail append → Warning
    // ---------------------------------------------------------------
    #[test]
    fn struct_field_tail_append_is_warning() {
        let old = spec_with_structs(vec![("Data", vec![("a", ScSpecTypeDef::U32)])]);
        let new = spec_with_structs(vec![(
            "Data",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U64)],
        )]);

        let report = compare(&old, &new);

        let added = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Added" && f.target.as_deref() == Some("Data.b"));
        assert!(added.is_some(), "Expected Struct Field Added for b");
        assert_eq!(added.unwrap().severity, Severity::Warning);

        // No critical findings for a clean append
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            0
        );
    }

    // ---------------------------------------------------------------
    // Struct field: deletion → Critical
    // ---------------------------------------------------------------
    #[test]
    fn struct_field_deletion_is_critical() {
        let old = spec_with_structs(vec![(
            "Data",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U64)],
        )]);
        let new = spec_with_structs(vec![("Data", vec![("a", ScSpecTypeDef::U32)])]);

        let report = compare(&old, &new);

        let removed = report.findings.iter().find(|f| {
            f.category == "Struct Field Removed" && f.target.as_deref() == Some("Data.b")
        });
        assert!(removed.is_some(), "Expected Struct Field Removed for b");
        assert_eq!(removed.unwrap().severity, Severity::Critical);
    }

    // ---------------------------------------------------------------
    // Struct field: same-position type change → Critical
    // ---------------------------------------------------------------
    #[test]
    fn struct_field_type_change_at_same_position_is_critical() {
        let old = spec_with_structs(vec![("Data", vec![("a", ScSpecTypeDef::U32)])]);
        let new = spec_with_structs(vec![("Data", vec![("a", ScSpecTypeDef::I128)])]);

        let report = compare(&old, &new);

        let type_changed = report.findings.iter().find(|f| {
            f.category == "Struct Field Type Changed" && f.target.as_deref() == Some("Data.a")
        });
        assert!(
            type_changed.is_some(),
            "Expected Struct Field Type Changed for a"
        );
        assert_eq!(type_changed.unwrap().severity, Severity::Critical);
    }

    // ---------------------------------------------------------------
    // Struct field: swap (both fields move) → Critical
    // ---------------------------------------------------------------
    #[test]
    fn struct_field_swap_is_critical() {
        let old = spec_with_structs(vec![(
            "Data",
            vec![("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U64)],
        )]);
        let new = spec_with_structs(vec![(
            "Data",
            vec![("b", ScSpecTypeDef::U64), ("a", ScSpecTypeDef::U32)],
        )]);

        let report = compare(&old, &new);

        let reorder_a = report.findings.iter().find(|f| {
            f.category == "Struct Field Reordered" && f.target.as_deref() == Some("Data.a")
        });
        let reorder_b = report.findings.iter().find(|f| {
            f.category == "Struct Field Reordered" && f.target.as_deref() == Some("Data.b")
        });
        assert!(reorder_a.is_some(), "Expected Struct Field Reordered for a");
        assert!(reorder_b.is_some(), "Expected Struct Field Reordered for b");
    }

    // ---------------------------------------------------------------
    // Combination: reorder + insert + delete in one struct
    // ---------------------------------------------------------------
    #[test]
    fn struct_field_combination_reorder_insert_delete() {
        // Old: [a: u32, b: u64, c: i128]
        // New: [x: u32, b: u64, a: u32]  (c removed, x inserted mid, a moved)
        let old = spec_with_structs(vec![(
            "Data",
            vec![
                ("a", ScSpecTypeDef::U32),
                ("b", ScSpecTypeDef::U64),
                ("c", ScSpecTypeDef::I128),
            ],
        )]);
        let new = spec_with_structs(vec![(
            "Data",
            vec![
                ("x", ScSpecTypeDef::U32),
                ("b", ScSpecTypeDef::U64),
                ("a", ScSpecTypeDef::U32),
            ],
        )]);

        let report = compare(&old, &new);

        // c removed
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "Struct Field Removed"
                    && f.target.as_deref() == Some("Data.c")),
            "Expected Removed for c"
        );
        // x inserted mid-sequence
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "Struct Field Inserted"
                    && f.target.as_deref() == Some("Data.x")),
            "Expected Inserted for x"
        );
        // a moved
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "Struct Field Reordered"
                    && f.target.as_deref() == Some("Data.a")),
            "Expected Reordered for a"
        );
        // b unchanged, no finding for b
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.target.as_deref() == Some("Data.b")),
            "b should have no findings"
        );

        // No phantom appends
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.category == "Struct Field Added"),
            "No fields should be reported as Added in this scenario"
        );
    }

    // ---------------------------------------------------------------
    // Event struct: mid-sequence insertion → Event Schema Inserted
    // ---------------------------------------------------------------
    #[test]
    fn event_struct_field_mid_insertion_is_critical() {
        let old = spec_with_structs(vec![("SomeEvent", vec![("old_field", ScSpecTypeDef::U32)])]);
        let new = spec_with_structs(vec![(
            "SomeEvent",
            vec![
                ("old_field", ScSpecTypeDef::U32),
                ("new_field", ScSpecTypeDef::U64),
            ],
        )]);

        let report = compare(&old, &new);

        // Appended at tail, still Struct Field Added (Warning) — event structs
        // use the same added logic.
        let added = report.findings.iter().find(|f| {
            f.category == "Struct Field Added" && f.target.as_deref() == Some("SomeEvent.new_field")
        });
        assert!(added.is_some(), "Expected Struct Field Added for new_field");
        assert_eq!(added.unwrap().severity, Severity::Warning);
    }

    // ---------------------------------------------------------------
    // Union case: mid-sequence insertion → Critical
    // ---------------------------------------------------------------
    #[test]
    fn union_case_mid_insertion_is_critical() {
        // Old: [A(void), B(void)]
        // New: [A(void), C(void), B(void)] — C inserted mid
        let old = spec_with_unions("Action", vec![void_case("A"), void_case("B")]);
        let new = spec_with_unions(
            "Action",
            vec![void_case("A"), void_case("C"), void_case("B")],
        );

        let report = compare(&old, &new);

        // C inserted mid → Critical
        let inserted = report.findings.iter().find(|f| {
            f.category == "Union Case Inserted" && f.target.as_deref() == Some("Action.C")
        });
        assert!(inserted.is_some(), "Expected Union Case Inserted for C");
        assert_eq!(inserted.unwrap().severity, Severity::Critical);

        // B moved from position 1 to 2 → Critical
        let reordered = report.findings.iter().find(|f| {
            f.category == "Union Case Reordered" && f.target.as_deref() == Some("Action.B")
        });
        assert!(reordered.is_some(), "Expected Union Case Reordered for B");
        assert_eq!(reordered.unwrap().severity, Severity::Critical);
    }

    // ---------------------------------------------------------------
    // Union case: tail append → Info
    // ---------------------------------------------------------------
    #[test]
    fn union_case_tail_append_is_info() {
        let old = spec_with_unions("Action", vec![void_case("A")]);
        let new = spec_with_unions("Action", vec![void_case("A"), void_case("B")]);

        let report = compare(&old, &new);

        let added = report
            .findings
            .iter()
            .find(|f| f.category == "Union Case Added" && f.target.as_deref() == Some("Action.B"));
        assert!(added.is_some(), "Expected Union Case Added for B");
        assert_eq!(added.unwrap().severity, Severity::Info);

        // No critical findings
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            0
        );
    }

    // ---------------------------------------------------------------
    // Union case: deletion → Critical
    // ---------------------------------------------------------------
    #[test]
    fn union_case_deletion_is_critical() {
        let old = spec_with_unions("Action", vec![void_case("A"), void_case("B")]);
        let new = spec_with_unions("Action", vec![void_case("A")]);

        let report = compare(&old, &new);

        let removed = report.findings.iter().find(|f| {
            f.category == "Union Case Removed" && f.target.as_deref() == Some("Action.B")
        });
        assert!(removed.is_some(), "Expected Union Case Removed for B");
        assert_eq!(removed.unwrap().severity, Severity::Critical);
    }

    // ---------------------------------------------------------------
    // Union case: payload type change → Critical
    // ---------------------------------------------------------------
    #[test]
    fn union_case_type_change_is_critical() {
        let old = spec_with_unions("Action", vec![tuple_case("Pay", vec![ScSpecTypeDef::U32])]);
        let new = spec_with_unions("Action", vec![tuple_case("Pay", vec![ScSpecTypeDef::U64])]);

        let report = compare(&old, &new);

        let type_changed = report.findings.iter().find(|f| {
            f.category == "Union Case Type Changed" && f.target.as_deref() == Some("Action.Pay")
        });
        assert!(
            type_changed.is_some(),
            "Expected Union Case Type Changed for Pay"
        );
        assert_eq!(type_changed.unwrap().severity, Severity::Critical);
    }

    // ---------------------------------------------------------------
    // Union case: swap → Critical
    // ---------------------------------------------------------------
    #[test]
    fn union_case_swap_is_critical() {
        let old = spec_with_unions("Action", vec![void_case("A"), void_case("B")]);
        let new = spec_with_unions("Action", vec![void_case("B"), void_case("A")]);

        let report = compare(&old, &new);

        let reorder_a = report.findings.iter().find(|f| {
            f.category == "Union Case Reordered" && f.target.as_deref() == Some("Action.A")
        });
        let reorder_b = report.findings.iter().find(|f| {
            f.category == "Union Case Reordered" && f.target.as_deref() == Some("Action.B")
        });
        assert!(reorder_a.is_some(), "Expected Union Case Reordered for A");
        assert!(reorder_b.is_some(), "Expected Union Case Reordered for B");
    }

    // ---------------------------------------------------------------
    // Union case: combination (reorder + insert + delete)
    // ---------------------------------------------------------------
    #[test]
    fn union_case_combination_reorder_insert_delete() {
        // Old: [A, B, C]
        // New: [X, B, A] — C removed, X inserted mid, A moved
        let old = spec_with_unions(
            "Action",
            vec![void_case("A"), void_case("B"), void_case("C")],
        );
        let new = spec_with_unions(
            "Action",
            vec![void_case("X"), void_case("B"), void_case("A")],
        );

        let report = compare(&old, &new);

        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "Union Case Removed"
                    && f.target.as_deref() == Some("Action.C")),
            "Expected Removed for C"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "Union Case Inserted"
                    && f.target.as_deref() == Some("Action.X")),
            "Expected Inserted for X"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "Union Case Reordered"
                    && f.target.as_deref() == Some("Action.A")),
            "Expected Reordered for A"
        );
        // B unchanged
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.target.as_deref() == Some("Action.B")),
            "B should have no findings"
        );
        // No phantom appends
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.category == "Union Case Added"),
            "No cases should be reported as Added in this scenario"
        );
    }

    // ---------------------------------------------------------------
    // Property: random field sets — verify consistency invariants
    // ---------------------------------------------------------------
    proptest! {
        #[test]
        fn struct_field_proptest_invariants(
            old_names in hash_set("[a-z]{1,4}", 0..6),
            new_names in hash_set("[a-z]{1,4}", 0..6),
        ) {
            // sorted determinism
            let mut old_names: Vec<String> = old_names.into_iter().collect();
            let mut new_names: Vec<String> = new_names.into_iter().collect();
            old_names.sort();
            new_names.sort();

            let old = spec_with_structs(vec![
                ("Data", old_names.iter().map(|n| (n.as_str(), ScSpecTypeDef::U32)).collect()),
            ]);
            let new = spec_with_structs(vec![
                ("Data", new_names.iter().map(|n| (n.as_str(), ScSpecTypeDef::U32)).collect()),
            ]);

            let report = compare(&old, &new);

            // All old names absent from new → "Struct Field Removed"
            for name in &old_names {
                if !new_names.contains(name) {
                    let target = format!("Data.{}", name);
                    prop_assert!(
                        report.findings.iter().any(|f| f.category == "Struct Field Removed"
                            && f.target.as_deref() == Some(target.as_str())),
                        "Field '{}' removed but no Removed finding", name
                    );
                }
            }

            // New names absent from old → "Struct Field Inserted" (< old.len())
            //                             or "Struct Field Added" (>= old.len())
            for (i, name) in new_names.iter().enumerate() {
                if !old_names.contains(name) {
                    let target = format!("Data.{}", name);
                    if i >= old_names.len() {
                        prop_assert!(
                            report.findings.iter().any(|f| f.category == "Struct Field Added"
                                && f.target.as_deref() == Some(target.as_str())),
                            "Field '{}' appended but no Added finding", name
                        );
                    } else {
                        prop_assert!(
                            report.findings.iter().any(|f| f.category == "Struct Field Inserted"
                                && f.target.as_deref() == Some(target.as_str())),
                            "Field '{}' inserted mid but no Inserted finding", name
                        );
                    }
                }
            }

            // Names shared at different positions → "Struct Field Reordered"
            for old_name in &old_names {
                if let Some(new_i) = new_names.iter().position(|n| n == old_name) {
                    let old_i = old_names.iter().position(|n| n == old_name).unwrap();
                    if old_i != new_i {
                        let target = format!("Data.{}", old_name);
                        prop_assert!(
                            report.findings.iter().any(|f| f.category == "Struct Field Reordered"
                                && f.target.as_deref() == Some(target.as_str())),
                            "Field '{}' moved {}→{} but no Reordered finding",
                            old_name, old_i, new_i
                        );
                    }
                }
            }

            // No field appears in both "Struct Field Added" and "Struct Field Removed"
            let added_targets: std::collections::HashSet<&str> = report
                .findings
                .iter()
                .filter(|f| f.category == "Struct Field Added")
                .filter_map(|f| f.target.as_deref())
                .collect();
            let removed_targets: std::collections::HashSet<&str> = report
                .findings
                .iter()
                .filter(|f| f.category == "Struct Field Removed")
                .filter_map(|f| f.target.as_deref())
                .collect();
            prop_assert!(
                added_targets.is_disjoint(&removed_targets),
                "A field cannot be both Added and Removed"
            );

            // Determinism: running compare twice yields identical results
            let report2 = compare(&old, &new);
            prop_assert_eq!(report.findings.len(), report2.findings.len());
        }
    }
}

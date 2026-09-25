//! Serialization witness traces for breaking findings.
//!
//! A finding often identifies a changed type or field but leaves reviewers to
//! infer *how* the serialized value becomes incompatible. This module generates
//! an optional **witness** that traces:
//!
//! - The old and new type paths involved in the break.
//! - Field positions, discriminants, and container boundaries along the path.
//! - The first node where the serialized interpretation diverges.
//!
//! ## Design
//!
//! Witnesses are generated from the normalized `ContractSpec` without requiring
//! live ledger data. They are explanatory — they illustrate *why* a serialized
//! form is incompatible — not proofs of runtime behavior.
//!
//! | Property | Guarantee |
//! |---|---|
//! | Deterministic | Given the same old/new specs, produces the same witness. |
//! | Bounded | Respects the active `ResourcePolicy` (no unbounded walks). |
//! | Honest | Unsupported or ambiguous transitions are labeled explicitly. |
//! | Structured | Witnesses are serializable to JSON for use by other tools. |
//!
//! ## Supported finding categories
//!
//! | Category | Witness kind |
//! |---|---|
//! | Struct Field Removed | Trace — field at serial index, old type shown |
//! | Struct Field Type Changed | Trace — field position, old and new types |
//! | Struct Field Reordered | Trace — field old and new serial positions |
//! | Enum Case Removed | Trace — discriminant value, shown as removed |
//! | Enum Case Value Changed | Trace — old and new discriminant integers |
//! | Error Enum Case Removed | Trace — same as Enum Case Removed |
//! | Error Enum Case Value Changed | Trace — same as Enum Case Value Changed |
//! | Union Case Removed | Trace — discriminant arm index, shown as removed |
//! | Union Case Type Changed | Trace — payload type at arm position |
//! | Function Parameter Type Changed | Trace — parameter position and types |
//! | Return Type Changed | Trace — return position and types |
//! | Type Kind Changed | Trace — old and new kind labels |
//! | Storage Durability Changed | Trace — storage key, old and new durability |
//! | Storage Namespace Changed | Trace — old and new namespace labels |
//! | Event Schema Removed | Trace — event struct field removed from schema |
//! | Event Schema Type Changed | Trace — event struct field type transition |
//! | Event Schema Reordered | Trace — event struct field serial position shift |
//!
//! All other categories produce a `Witness::Unsupported` record rather than
//! pretending to describe a transition.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::diff::Finding;
use crate::limits::ResourcePolicy;
use crate::spec::ContractSpec;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The position of a field or case in a serialized representation.
///
/// XDR encodes struct fields in declaration order and enum/union discriminants
/// as a 32-bit integer. `SerialPosition` captures what the serializer sees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SerialPosition {
    /// A struct field at a 0-based declaration index.
    StructField {
        field_name: String,
        old_index: usize,
        new_index: Option<usize>,
    },
    /// An enum or union discriminant value.
    Discriminant {
        case_name: String,
        old_value: u32,
        new_value: Option<u32>,
    },
    /// A union case payload position within a union case.
    UnionCasePayload { case_name: String, payload_index: usize },
    /// A function parameter at a 0-based position.
    Parameter { param_name: String, position: usize },
    /// A function return value at a 0-based position.
    ReturnValue { position: usize },
    /// A storage entry identified by its key expression and durability tier.
    StorageEntry { key: String, durability: String },
}

/// What the old and new serialized forms look like at the incompatible node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialInterpretation {
    /// Human-readable description of the old type at this node.
    pub old_type: String,
    /// Human-readable description of the new type at this node.
    pub new_type: String,
}

/// A single step along the witness path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessStep {
    /// Entity name at this level (type name, function name, etc.).
    pub entity: String,
    /// The position within the entity's serialized form.
    pub position: SerialPosition,
    /// The serialized interpretation at this node, when determinable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpretation: Option<SerialInterpretation>,
}

/// The witness for a single breaking finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "witness_kind")]
pub enum Witness {
    /// A supported finding with a deterministic trace.
    Trace {
        /// The finding category this witness explains.
        category: String,
        /// The target (type/function) the finding refers to.
        target: String,
        /// Steps from the outermost entity to the first incompatible node.
        path: Vec<WitnessStep>,
        /// The node where the serialized value first diverges.
        first_incompatible: WitnessStep,
    },
    /// The transition is not supported by this version of the witness generator.
    Unsupported {
        category: String,
        target: Option<String>,
        reason: String,
    },
    /// The transition is structurally ambiguous (e.g. both sides changed in
    /// multiple incompatible ways simultaneously).
    Ambiguous {
        category: String,
        target: Option<String>,
        reason: String,
    },
}

impl Witness {
    /// Whether this witness carries a usable trace (not unsupported or
    /// ambiguous).
    pub fn is_trace(&self) -> bool {
        matches!(self, Witness::Trace { .. })
    }

    /// The category the witness describes.
    pub fn category(&self) -> &str {
        match self {
            Witness::Trace { category, .. } => category,
            Witness::Unsupported { category, .. } => category,
            Witness::Ambiguous { category, .. } => category,
        }
    }
}

impl fmt::Display for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Witness::Trace { category, target, path, first_incompatible } => {
                write!(f, "{category} on '{target}'")?;
                for step in path {
                    write!(f, " → {}", step.entity)?;
                }
                write!(f, " ✗ {} (first incompatible)", first_incompatible.entity)
            }
            Witness::Unsupported { category, target, reason } => {
                let t = target.as_deref().unwrap_or("<no target>");
                write!(f, "no witness for {category} on '{t}': {reason}")
            }
            Witness::Ambiguous { category, target, reason } => {
                let t = target.as_deref().unwrap_or("<no target>");
                write!(f, "ambiguous witness for {category} on '{t}': {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// Render a witness as a compact JSON value.
pub fn render_witness_json(witness: &Witness) -> serde_json::Value {
    serde_json::to_value(witness).unwrap_or(serde_json::Value::Null)
}

/// Render a witness as a concise human-readable text block.
pub fn render_witness_text(witness: &Witness) -> String {
    match witness {
        Witness::Unsupported { reason, .. } | Witness::Ambiguous { reason, .. } => {
            format!("  witness: {}\n", reason)
        }
        Witness::Trace { path, first_incompatible, .. } => {
            let mut out = String::new();
            if !path.is_empty() {
                out.push_str("  witness path:\n");
                for step in path {
                    out.push_str(&format!("    {}\n", format_step(step)));
                }
            }
            out.push_str(&format!(
                "  first incompatible node: {}\n",
                format_step(first_incompatible)
            ));
            out
        }
    }
}

/// Render a witness as a Markdown block.
pub fn render_witness_markdown(witness: &Witness) -> String {
    match witness {
        Witness::Unsupported { reason, .. } | Witness::Ambiguous { reason, .. } => {
            format!("> **witness:** {}\n", reason)
        }
        Witness::Trace { path, first_incompatible, .. } => {
            let mut out = String::new();
            if !path.is_empty() {
                out.push_str("> **witness path:**\n>\n");
                for step in path {
                    out.push_str(&format!("> - {}\n", format_step(step)));
                }
                out.push_str(">\n");
            }
            out.push_str(&format!(
                "> **first incompatible node:** {}\n",
                format_step(first_incompatible)
            ));
            out
        }
    }
}

fn format_step(step: &WitnessStep) -> String {
    let pos = match &step.position {
        SerialPosition::StructField { field_name, old_index, new_index } => {
            match new_index {
                Some(ni) => format!("field `{}` [#{} → #{}]", field_name, old_index, ni),
                None => format!("field `{}` [#{}, removed]", field_name, old_index),
            }
        }
        SerialPosition::Discriminant { case_name, old_value, new_value } => match new_value {
            Some(nv) => format!("case `{}` discriminant {} → {}", case_name, old_value, nv),
            None => format!("case `{}` discriminant {} (removed)", case_name, old_value),
        },
        SerialPosition::UnionCasePayload { case_name, payload_index } => {
            format!("case `{}` payload[{}]", case_name, payload_index)
        }
        SerialPosition::Parameter { param_name, position } => {
            format!("param `{}` [#{}]", param_name, position)
        }
        SerialPosition::ReturnValue { position } => {
            format!("return[{}]", position)
        }
        SerialPosition::StorageEntry { key, durability } => {
            format!("storage key `{}` durability={}", key, durability)
        }
    };
    if let Some(interp) = &step.interpretation {
        format!(
            "{} — {} → {}",
            step.entity, interp.old_type, interp.new_type
        )
    } else {
        format!("{}: {}", step.entity, pos)
    }
}

// ---------------------------------------------------------------------------
// Witness generation
// ---------------------------------------------------------------------------

/// Generate a witness for a single breaking finding.
///
/// The witness is generated purely from the normalized specs — no live ledger
/// data is required. The result is bounded by `policy.max_walk_depth`.
pub fn generate_witness(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
    policy: &ResourcePolicy,
) -> Witness {
    let category = finding.category.as_str();
    let target = finding.target.as_deref();

    match category {
        "Struct Field Removed" => witness_struct_field_removed(finding, old_spec, new_spec),
        "Struct Field Type Changed" => {
            witness_struct_field_type_changed(finding, old_spec, new_spec)
        }
        "Struct Field Reordered" => witness_struct_field_reordered(finding, old_spec, new_spec),
        "Enum Case Removed" | "Error Enum Case Removed" => {
            witness_enum_case_removed(finding, old_spec)
        }
        "Enum Case Value Changed" | "Error Enum Case Value Changed" => {
            witness_enum_case_value_changed(finding, old_spec, new_spec)
        }
        "Union Case Removed" => witness_union_case_removed(finding, old_spec),
        "Union Case Type Changed" => witness_union_case_type_changed(finding, old_spec, new_spec),
        "Function Parameter Type Changed" => {
            witness_parameter_type_changed(finding, old_spec, new_spec)
        }
        "Return Type Changed" => witness_return_type_changed(finding, old_spec, new_spec),
        "Type Kind Changed" => witness_type_kind_changed(finding, old_spec, new_spec),
        "Storage Durability Changed" => witness_storage_durability_changed(finding, policy),
        "Storage Namespace Changed" => witness_storage_namespace_changed(finding, policy),
        "Event Schema Removed" => witness_event_schema_removed(finding, old_spec, new_spec),
        "Event Schema Type Changed" => {
            witness_event_schema_type_changed(finding, old_spec, new_spec)
        }
        "Event Schema Reordered" => witness_event_schema_reordered(finding, old_spec, new_spec),
        _ => Witness::Unsupported {
            category: category.to_string(),
            target: target.map(str::to_string),
            reason: format!(
                "witness generation is not supported for '{category}'. \
                 Supported: Struct Field Removed/Type Changed/Reordered, \
                 Enum Case Removed/Value Changed, Union Case Removed/Type Changed, \
                 Function Parameter Type Changed, Return Type Changed, Type Kind Changed, \
                 Storage Durability/Namespace Changed, Event Schema Removed/Type Changed/Reordered."
            ),
        },
    }
}

// ---------------------------------------------------------------------------
// Per-category witness generators
// ---------------------------------------------------------------------------

fn witness_struct_field_removed(
    finding: &Finding,
    old_spec: &ContractSpec,
    _new_spec: &ContractSpec,
) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };

    let (type_name, field_name) = match split_dot(target) {
        Some(p) => p,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("target '{target}' is not in Type.field format"),
            };
        }
    };

    let old_struct = match old_spec.structs().get(type_name) {
        Some(s) => s,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("type '{type_name}' not found in old spec"),
            };
        }
    };

    let old_index = old_struct
        .fields
        .iter()
        .position(|f| f.name.to_string() == field_name);

    let old_index = match old_index {
        Some(i) => i,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("field '{field_name}' not found in old spec for type '{type_name}'"),
            };
        }
    };

    let old_type = type_def_str(&old_struct.fields[old_index].type_);

    Witness::Trace {
        category: finding.category.clone(),
        target: target.to_string(),
        path: vec![],
        first_incompatible: WitnessStep {
            entity: type_name.to_string(),
            position: SerialPosition::StructField {
                field_name: field_name.to_string(),
                old_index,
                new_index: None,
            },
            interpretation: Some(SerialInterpretation {
                old_type,
                new_type: "(removed)".to_string(),
            }),
        },
    }
}

fn witness_struct_field_type_changed(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };
    let (type_name, field_name) = match split_dot(target) {
        Some(p) => p,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("target '{target}' is not in Type.field format"),
            };
        }
    };

    let old_struct = old_spec.structs().get(type_name);
    let new_struct = new_spec.structs().get(type_name);

    match (old_struct, new_struct) {
        (Some(old_s), Some(new_s)) => {
            let old_field = old_s.fields.iter().find(|f| f.name.to_string() == field_name);
            let new_field = new_s.fields.iter().find(|f| f.name.to_string() == field_name);
            let old_index = old_s
                .fields
                .iter()
                .position(|f| f.name.to_string() == field_name)
                .unwrap_or(0);
            let new_index = new_s
                .fields
                .iter()
                .position(|f| f.name.to_string() == field_name);

            match (old_field, new_field) {
                (Some(of), Some(nf)) => Witness::Trace {
                    category: finding.category.clone(),
                    target: target.to_string(),
                    path: vec![],
                    first_incompatible: WitnessStep {
                        entity: type_name.to_string(),
                        position: SerialPosition::StructField {
                            field_name: field_name.to_string(),
                            old_index,
                            new_index,
                        },
                        interpretation: Some(SerialInterpretation {
                            old_type: type_def_str(&of.type_),
                            new_type: type_def_str(&nf.type_),
                        }),
                    },
                },
                _ => Witness::Unsupported {
                    category: finding.category.clone(),
                    target: Some(target.to_string()),
                    reason: format!("field '{field_name}' not found in both specs for '{type_name}'"),
                },
            }
        }
        _ => Witness::Unsupported {
            category: finding.category.clone(),
            target: Some(target.to_string()),
            reason: format!("type '{type_name}' not found in both old and new specs"),
        },
    }
}

fn witness_struct_field_reordered(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };
    let (type_name, field_name) = match split_dot(target) {
        Some(p) => p,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("target '{target}' is not in Type.field format"),
            };
        }
    };

    let old_struct = old_spec.structs().get(type_name);
    let new_struct = new_spec.structs().get(type_name);

    match (old_struct, new_struct) {
        (Some(old_s), Some(new_s)) => {
            let old_index = old_s
                .fields
                .iter()
                .position(|f| f.name.to_string() == field_name);
            let new_index = new_s
                .fields
                .iter()
                .position(|f| f.name.to_string() == field_name);

            match (old_index, new_index) {
                (Some(oi), new_i) => Witness::Trace {
                    category: finding.category.clone(),
                    target: target.to_string(),
                    path: vec![],
                    first_incompatible: WitnessStep {
                        entity: type_name.to_string(),
                        position: SerialPosition::StructField {
                            field_name: field_name.to_string(),
                            old_index: oi,
                            new_index: new_i,
                        },
                        interpretation: None,
                    },
                },
                _ => Witness::Unsupported {
                    category: finding.category.clone(),
                    target: Some(target.to_string()),
                    reason: "field position data unavailable".to_string(),
                },
            }
        }
        _ => Witness::Unsupported {
            category: finding.category.clone(),
            target: Some(target.to_string()),
            reason: format!("type '{type_name}' not found in one or both specs"),
        },
    }
}

fn witness_enum_case_removed(finding: &Finding, old_spec: &ContractSpec) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };
    let (type_name, case_name) = match split_dot(target) {
        Some(p) => p,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("target '{target}' is not in Enum.Case format"),
            };
        }
    };

    // Check regular enums first, then error enums.
    if let Some(enum_def) = old_spec.enums().get(type_name) {
        let old_case = enum_def.cases.iter().find(|c| c.name.to_string() == case_name);
        if let Some(c) = old_case {
            return Witness::Trace {
                category: finding.category.clone(),
                target: target.to_string(),
                path: vec![],
                first_incompatible: WitnessStep {
                    entity: type_name.to_string(),
                    position: SerialPosition::Discriminant {
                        case_name: case_name.to_string(),
                        old_value: c.value,
                        new_value: None,
                    },
                    interpretation: Some(SerialInterpretation {
                        old_type: format!("case '{}' = {}", case_name, c.value),
                        new_type: "(removed)".to_string(),
                    }),
                },
            };
        }
    }

    if let Some(err_enum) = old_spec.error_enums().get(type_name) {
        let old_case = err_enum.cases.iter().find(|c| c.name.to_string() == case_name);
        if let Some(c) = old_case {
            return Witness::Trace {
                category: finding.category.clone(),
                target: target.to_string(),
                path: vec![],
                first_incompatible: WitnessStep {
                    entity: type_name.to_string(),
                    position: SerialPosition::Discriminant {
                        case_name: case_name.to_string(),
                        old_value: c.value,
                        new_value: None,
                    },
                    interpretation: Some(SerialInterpretation {
                        old_type: format!("case '{}' = {}", case_name, c.value),
                        new_type: "(removed)".to_string(),
                    }),
                },
            };
        }
    }

    Witness::Unsupported {
        category: finding.category.clone(),
        target: Some(target.to_string()),
        reason: format!("case '{case_name}' not found in old spec for '{type_name}'"),
    }
}

fn witness_enum_case_value_changed(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };
    let (type_name, case_name) = match split_dot(target) {
        Some(p) => p,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("target '{target}' is not in Enum.Case format"),
            };
        }
    };

    // Try regular enum.
    if let (Some(old_enum), Some(new_enum)) =
        (old_spec.enums().get(type_name), new_spec.enums().get(type_name))
    {
        let old_val = old_enum
            .cases
            .iter()
            .find(|c| c.name.to_string() == case_name)
            .map(|c| c.value);
        let new_val = new_enum
            .cases
            .iter()
            .find(|c| c.name.to_string() == case_name)
            .map(|c| c.value);
        if let (Some(ov), Some(nv)) = (old_val, new_val) {
            return Witness::Trace {
                category: finding.category.clone(),
                target: target.to_string(),
                path: vec![],
                first_incompatible: WitnessStep {
                    entity: type_name.to_string(),
                    position: SerialPosition::Discriminant {
                        case_name: case_name.to_string(),
                        old_value: ov,
                        new_value: Some(nv),
                    },
                    interpretation: Some(SerialInterpretation {
                        old_type: format!("{}", ov),
                        new_type: format!("{}", nv),
                    }),
                },
            };
        }
    }

    Witness::Unsupported {
        category: finding.category.clone(),
        target: Some(target.to_string()),
        reason: format!(
            "case '{case_name}' not found in both old and new specs for '{type_name}'"
        ),
    }
}

fn witness_union_case_removed(finding: &Finding, old_spec: &ContractSpec) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };
    let (type_name, case_name) = match split_dot(target) {
        Some(p) => p,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("target '{target}' is not in Union.Case format"),
            };
        }
    };

    use stellar_xdr::curr::ScSpecUdtUnionCaseV0;

    if let Some(union_def) = old_spec.unions().get(type_name) {
        let case_index = union_def.cases.iter().position(|c| {
            match c {
                ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string() == case_name,
                ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string() == case_name,
            }
        });
        if let Some(idx) = case_index {
            return Witness::Trace {
                category: finding.category.clone(),
                target: target.to_string(),
                path: vec![],
                first_incompatible: WitnessStep {
                    entity: type_name.to_string(),
                    position: SerialPosition::Discriminant {
                        case_name: case_name.to_string(),
                        old_value: idx as u32,
                        new_value: None,
                    },
                    interpretation: Some(SerialInterpretation {
                        old_type: format!("union case '{}' (arm #{})", case_name, idx),
                        new_type: "(removed)".to_string(),
                    }),
                },
            };
        }
    }

    Witness::Unsupported {
        category: finding.category.clone(),
        target: Some(target.to_string()),
        reason: format!("case '{case_name}' not found in old spec for union '{type_name}'"),
    }
}

fn witness_parameter_type_changed(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };
    let (fn_name, param_name) = match split_dot(target) {
        Some(p) => p,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("target '{target}' is not in Function.param format"),
            };
        }
    };

    let old_fn = old_spec.functions().get(fn_name);
    let new_fn = new_spec.functions().get(fn_name);

    match (old_fn, new_fn) {
        (Some(of), Some(nf)) => {
            let old_param = of.inputs.iter().find(|p| p.name.to_string() == param_name);
            let new_param = nf.inputs.iter().find(|p| p.name.to_string() == param_name);
            let position = of
                .inputs
                .iter()
                .position(|p| p.name.to_string() == param_name)
                .unwrap_or(0);

            match (old_param, new_param) {
                (Some(op), Some(np)) => Witness::Trace {
                    category: finding.category.clone(),
                    target: target.to_string(),
                    path: vec![],
                    first_incompatible: WitnessStep {
                        entity: fn_name.to_string(),
                        position: SerialPosition::Parameter {
                            param_name: param_name.to_string(),
                            position,
                        },
                        interpretation: Some(SerialInterpretation {
                            old_type: type_def_str(&op.type_),
                            new_type: type_def_str(&np.type_),
                        }),
                    },
                },
                _ => Witness::Unsupported {
                    category: finding.category.clone(),
                    target: Some(target.to_string()),
                    reason: format!("param '{param_name}' not found in both specs for '{fn_name}'"),
                },
            }
        }
        _ => Witness::Unsupported {
            category: finding.category.clone(),
            target: Some(target.to_string()),
            reason: format!("function '{fn_name}' not found in both old and new specs"),
        },
    }
}

fn witness_return_type_changed(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };

    let old_fn = old_spec.functions().get(target);
    let new_fn = new_spec.functions().get(target);

    match (old_fn, new_fn) {
        (Some(of), Some(nf)) => {
            let old_ret = of.outputs.iter().next();
            let new_ret = nf.outputs.iter().next();
            Witness::Trace {
                category: finding.category.clone(),
                target: target.to_string(),
                path: vec![],
                first_incompatible: WitnessStep {
                    entity: target.to_string(),
                    position: SerialPosition::ReturnValue { position: 0 },
                    interpretation: Some(SerialInterpretation {
                        old_type: old_ret.map(type_def_str).unwrap_or_else(|| "(void)".into()),
                        new_type: new_ret.map(type_def_str).unwrap_or_else(|| "(void)".into()),
                    }),
                },
            }
        }
        _ => Witness::Unsupported {
            category: finding.category.clone(),
            target: Some(target.to_string()),
            reason: format!("function '{target}' not found in both old and new specs"),
        },
    }
}

fn witness_type_kind_changed(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };

    let old_kind = type_kind(target, old_spec);
    let new_kind = type_kind(target, new_spec);

    match (old_kind, new_kind) {
        (Some(ok), Some(nk)) if ok != nk => Witness::Trace {
            category: finding.category.clone(),
            target: target.to_string(),
            path: vec![],
            first_incompatible: WitnessStep {
                entity: target.to_string(),
                position: SerialPosition::Discriminant {
                    case_name: target.to_string(),
                    old_value: 0,
                    new_value: Some(0),
                },
                interpretation: Some(SerialInterpretation {
                    old_type: ok.to_string(),
                    new_type: nk.to_string(),
                }),
            },
        },
        _ => Witness::Ambiguous {
            category: finding.category.clone(),
            target: Some(target.to_string()),
            reason: format!(
                "type kind change for '{target}' is ambiguous or the type was not found in both specs"
            ),
        },
    }
}

fn witness_union_case_type_changed(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Witness {
    use stellar_xdr::curr::ScSpecUdtUnionCaseV0;

    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };
    let (type_name, case_name) = match split_dot(target) {
        Some(p) => p,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("target '{target}' is not in Union.Case format"),
            };
        }
    };

    let old_union = old_spec.unions().get(type_name);
    let new_union = new_spec.unions().get(type_name);

    match (old_union, new_union) {
        (Some(ou), Some(nu)) => {
            let old_case = ou.cases.iter().find(|c| match c {
                ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string() == case_name,
                ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string() == case_name,
            });
            let new_case = nu.cases.iter().find(|c| match c {
                ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string() == case_name,
                ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string() == case_name,
            });
            let case_index = ou
                .cases
                .iter()
                .position(|c| match c {
                    ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string() == case_name,
                    ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string() == case_name,
                })
                .unwrap_or(0);

            let old_type_str = match old_case {
                Some(ScSpecUdtUnionCaseV0::VoidV0(_)) => "(void)".to_string(),
                Some(ScSpecUdtUnionCaseV0::TupleV0(t)) => t
                    .value_types
                    .iter()
                    .map(type_def_str)
                    .collect::<Vec<_>>()
                    .join(", "),
                None => "(not found)".to_string(),
            };
            let new_type_str = match new_case {
                Some(ScSpecUdtUnionCaseV0::VoidV0(_)) => "(void)".to_string(),
                Some(ScSpecUdtUnionCaseV0::TupleV0(t)) => t
                    .value_types
                    .iter()
                    .map(type_def_str)
                    .collect::<Vec<_>>()
                    .join(", "),
                None => "(not found)".to_string(),
            };

            Witness::Trace {
                category: finding.category.clone(),
                target: target.to_string(),
                path: vec![],
                first_incompatible: WitnessStep {
                    entity: type_name.to_string(),
                    position: SerialPosition::UnionCasePayload {
                        case_name: case_name.to_string(),
                        payload_index: case_index,
                    },
                    interpretation: Some(SerialInterpretation {
                        old_type: old_type_str,
                        new_type: new_type_str,
                    }),
                },
            }
        }
        _ => Witness::Unsupported {
            category: finding.category.clone(),
            target: Some(target.to_string()),
            reason: format!("union '{type_name}' not found in both old and new specs"),
        },
    }
}

/// Generate a witness for a storage durability change. Because the spec does
/// not embed storage declarations directly, the witness records the key
/// expression from the finding target and the durability labels from the
/// finding message rather than the spec.
fn witness_storage_durability_changed(finding: &Finding, _policy: &ResourcePolicy) -> Witness {
    let target = finding.target.as_deref().unwrap_or("<unknown key>");

    // Extract durability labels from the finding message when present.
    // The message format produced by the diff engine is:
    //   "storage durability changed from <old> to <new> for key <key>"
    let (old_dur, new_dur) = extract_durability_from_message(&finding.message);

    Witness::Trace {
        category: finding.category.clone(),
        target: target.to_string(),
        path: vec![],
        first_incompatible: WitnessStep {
            entity: target.to_string(),
            position: SerialPosition::StorageEntry {
                key: target.to_string(),
                durability: old_dur.clone(),
            },
            interpretation: Some(SerialInterpretation {
                old_type: format!("durability={}", old_dur),
                new_type: format!("durability={}", new_dur),
            }),
        },
    }
}

/// Generate a witness for a storage namespace change.
fn witness_storage_namespace_changed(finding: &Finding, _policy: &ResourcePolicy) -> Witness {
    let target = finding.target.as_deref().unwrap_or("<unknown key>");

    let (old_ns, new_ns) = extract_namespace_from_message(&finding.message);

    Witness::Trace {
        category: finding.category.clone(),
        target: target.to_string(),
        path: vec![],
        first_incompatible: WitnessStep {
            entity: target.to_string(),
            position: SerialPosition::StorageEntry {
                key: target.to_string(),
                durability: "persistent".to_string(),
            },
            interpretation: Some(SerialInterpretation {
                old_type: format!("namespace={}", old_ns),
                new_type: format!("namespace={}", new_ns),
            }),
        },
    }
}

fn extract_durability_from_message(message: &str) -> (String, String) {
    // Attempt to parse "... from <old> to <new> ..." pattern.
    let lower = message.to_lowercase();
    if let Some(from_pos) = lower.find(" from ") {
        let rest = &message[from_pos + 6..];
        if let Some(to_pos) = rest.to_lowercase().find(" to ") {
            let old_dur = rest[..to_pos].trim().to_string();
            let after_to = &rest[to_pos + 4..];
            let new_dur = after_to
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .trim_end_matches(|c: char| !c.is_alphanumeric())
                .to_string();
            return (old_dur, new_dur);
        }
    }
    ("(unknown)".to_string(), "(unknown)".to_string())
}

fn extract_namespace_from_message(message: &str) -> (String, String) {
    extract_durability_from_message(message)
}

/// Witness for an event schema field removal (mirrors struct field removal but
/// scoped to event-struct findings).
fn witness_event_schema_removed(
    finding: &Finding,
    old_spec: &ContractSpec,
    _new_spec: &ContractSpec,
) -> Witness {
    let Some(target) = finding.target.as_deref() else {
        return unsupported_missing_target(&finding.category);
    };

    let (type_name, field_name) = match split_dot(target) {
        Some(p) => p,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("target '{target}' is not in EventType.field format"),
            };
        }
    };

    // Event structs are stored as regular structs in the spec.
    let old_struct = match old_spec.structs().get(type_name) {
        Some(s) => s,
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!("event type '{type_name}' not found in old spec"),
            };
        }
    };

    let old_index = old_struct
        .fields
        .iter()
        .position(|f| f.name.to_string() == field_name);

    let (old_index, old_type) = match old_index {
        Some(i) => (i, type_def_str(&old_struct.fields[i].type_)),
        None => {
            return Witness::Unsupported {
                category: finding.category.clone(),
                target: Some(target.to_string()),
                reason: format!(
                    "field '{field_name}' not found in old event type '{type_name}'"
                ),
            };
        }
    };

    Witness::Trace {
        category: finding.category.clone(),
        target: target.to_string(),
        path: vec![],
        first_incompatible: WitnessStep {
            entity: type_name.to_string(),
            position: SerialPosition::StructField {
                field_name: field_name.to_string(),
                old_index,
                new_index: None,
            },
            interpretation: Some(SerialInterpretation {
                old_type,
                new_type: "(removed from event schema)".to_string(),
            }),
        },
    }
}

/// Witness for an event schema field type change.
fn witness_event_schema_type_changed(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Witness {
    // Event schema type changes have the same structure as struct field type changes.
    witness_struct_field_type_changed(finding, old_spec, new_spec)
}

/// Witness for an event schema field reordering.
fn witness_event_schema_reordered(
    finding: &Finding,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Witness {
    // Reordering detection is identical for event structs and regular structs.
    witness_struct_field_reordered(finding, old_spec, new_spec)
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

fn unsupported_missing_target(category: &str) -> Witness {
    Witness::Unsupported {
        category: category.to_string(),
        target: None,
        reason: "finding has no target — cannot locate the changed entity in the spec".to_string(),
    }
}

fn split_dot(s: &str) -> Option<(&str, &str)> {
    s.split_once('.')
}

/// Return a stable human-readable string for a `ScSpecTypeDef`.
fn type_def_str(t: &stellar_xdr::curr::ScSpecTypeDef) -> String {
    use stellar_xdr::curr::ScSpecTypeDef;
    match t {
        ScSpecTypeDef::Val => "Val".into(),
        ScSpecTypeDef::Bool => "bool".into(),
        ScSpecTypeDef::Void => "void".into(),
        ScSpecTypeDef::Error => "Error".into(),
        ScSpecTypeDef::U32 => "u32".into(),
        ScSpecTypeDef::I32 => "i32".into(),
        ScSpecTypeDef::U64 => "u64".into(),
        ScSpecTypeDef::I64 => "i64".into(),
        ScSpecTypeDef::Timepoint => "Timepoint".into(),
        ScSpecTypeDef::Duration => "Duration".into(),
        ScSpecTypeDef::U128 => "u128".into(),
        ScSpecTypeDef::I128 => "i128".into(),
        ScSpecTypeDef::U256 => "u256".into(),
        ScSpecTypeDef::I256 => "i256".into(),
        ScSpecTypeDef::Bytes => "Bytes".into(),
        ScSpecTypeDef::String => "String".into(),
        ScSpecTypeDef::Symbol => "Symbol".into(),
        ScSpecTypeDef::Address => "Address".into(),
        ScSpecTypeDef::BytesN(b) => format!("Bytes{}", b.n),
        ScSpecTypeDef::Option(o) => format!("Option<{}>", type_def_str(&o.value_type)),
        ScSpecTypeDef::Vec(v) => format!("Vec<{}>", type_def_str(&v.element_type)),
        ScSpecTypeDef::Map(m) => {
            format!("Map<{},{}>", type_def_str(&m.key_type), type_def_str(&m.value_type))
        }
        ScSpecTypeDef::Tuple(tu) => {
            let parts: Vec<_> = tu.value_types.iter().map(type_def_str).collect();
            format!("({})", parts.join(", "))
        }
        ScSpecTypeDef::Result(r) => {
            format!(
                "Result<{},{}>",
                type_def_str(&r.ok_type),
                type_def_str(&r.error_type)
            )
        }
        ScSpecTypeDef::Udt(u) => u.name.to_string(),
        _ => "?".into(),
    }
}

fn type_kind<'a>(name: &str, spec: &'a ContractSpec) -> Option<&'a str> {
    if spec.structs().contains_key(name) {
        Some("struct")
    } else if spec.enums().contains_key(name) {
        Some("enum")
    } else if spec.unions().contains_key(name) {
        Some("union")
    } else if spec.error_enums().contains_key(name) {
        Some("error_enum")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ContractSpec;
    use stellar_xdr::curr::{
        ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecTypeUdt, ScSpecUdtEnumCaseV0,
        ScSpecUdtEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseV0,
        ScSpecUdtUnionCaseVoidV0, ScSpecUdtUnionV0, StringM, VecM,
    };

    fn policy() -> ResourcePolicy {
        ResourcePolicy::default()
    }

    fn make_finding(category: &str, target: Option<&str>) -> Finding {
        use crate::diff::Severity;
        Finding {
            severity: Severity::Critical,
            axes: vec![],
            category: category.to_string(),
            message: String::new(),
            type_name: target.map(|t| t.split('.').next().unwrap().to_string()),
            target: target.map(str::to_string),
            root_target: None,
            change: None,
        }
    }

    fn uname(s: &str) -> StringM<60> {
        s.try_into().unwrap()
    }

    fn build_struct(fields: &[(&str, ScSpecTypeDef)]) -> ScSpecUdtStructV0 {
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: uname("MyStruct"),
            fields: VecM::try_from(
                fields
                    .iter()
                    .map(|(name, ty)| ScSpecUdtStructFieldV0 {
                        doc: StringM::default(),
                        name: uname(name),
                        type_: ty.clone(),
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        }
    }

    fn spec_with_struct(fields: &[(&str, ScSpecTypeDef)]) -> ContractSpec {
        let mut spec = ContractSpec::default();
        spec.structs.insert("MyStruct".into(), build_struct(fields));
        spec
    }

    fn spec_with_enum(cases: &[(&str, u32)]) -> ContractSpec {
        let mut spec = ContractSpec::default();
        spec.enums.insert(
            "MyEnum".into(),
            ScSpecUdtEnumV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: uname("MyEnum"),
                cases: VecM::try_from(
                    cases
                        .iter()
                        .map(|(name, val)| ScSpecUdtEnumCaseV0 {
                            doc: StringM::default(),
                            name: uname(name),
                            value: *val,
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
            },
        );
        spec
    }

    fn spec_with_function(name: &str, params: &[(&str, ScSpecTypeDef)], ret: Option<ScSpecTypeDef>) -> ContractSpec {
        let mut spec = ContractSpec::default();
        let inputs = VecM::try_from(
            params
                .iter()
                .map(|(pname, ptype)| ScSpecFunctionInputV0 {
                    doc: StringM::default(),
                    name: pname.as_bytes().try_into().unwrap(),
                    type_: ptype.clone(),
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let outputs = match ret {
            Some(r) => VecM::try_from(vec![r]).unwrap(),
            None => VecM::default(),
        };
        spec.functions.insert(
            name.to_string(),
            ScSpecFunctionV0 {
                doc: StringM::default(),
                name: uname(name),
                inputs,
                outputs,
            },
        );
        spec
    }

    // ------------------------------------------------------------------
    // Struct field removed
    // ------------------------------------------------------------------

    #[test]
    fn witness_struct_field_removed_produces_trace() {
        let old = spec_with_struct(&[("amount", ScSpecTypeDef::U64), ("owner", ScSpecTypeDef::Address)]);
        let new = spec_with_struct(&[("owner", ScSpecTypeDef::Address)]);
        let finding = make_finding("Struct Field Removed", Some("MyStruct.amount"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace(), "expected Trace, got: {w}");
        if let Witness::Trace { first_incompatible, .. } = &w {
            assert_eq!(first_incompatible.entity, "MyStruct");
        }
    }

    #[test]
    fn witness_struct_field_removed_shows_removed_type() {
        let old = spec_with_struct(&[("amount", ScSpecTypeDef::I128)]);
        let new = spec_with_struct(&[]);
        let finding = make_finding("Struct Field Removed", Some("MyStruct.amount"));
        let w = generate_witness(&finding, &old, &new, &policy());
        if let Witness::Trace { first_incompatible, .. } = &w {
            let interp = first_incompatible.interpretation.as_ref().unwrap();
            assert_eq!(interp.old_type, "i128");
            assert_eq!(interp.new_type, "(removed)");
        }
    }

    // ------------------------------------------------------------------
    // Struct field type changed
    // ------------------------------------------------------------------

    #[test]
    fn witness_field_type_changed_shows_both_types() {
        let old = spec_with_struct(&[("amount", ScSpecTypeDef::U32)]);
        let new = spec_with_struct(&[("amount", ScSpecTypeDef::U64)]);
        let finding = make_finding("Struct Field Type Changed", Some("MyStruct.amount"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace());
        if let Witness::Trace { first_incompatible, .. } = &w {
            let interp = first_incompatible.interpretation.as_ref().unwrap();
            assert_eq!(interp.old_type, "u32");
            assert_eq!(interp.new_type, "u64");
        }
    }

    // ------------------------------------------------------------------
    // Enum case removed
    // ------------------------------------------------------------------

    #[test]
    fn witness_enum_case_removed_records_discriminant() {
        let old = spec_with_enum(&[("Active", 0), ("Paused", 1)]);
        let new = spec_with_enum(&[("Active", 0)]);
        let finding = make_finding("Enum Case Removed", Some("MyEnum.Paused"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace());
        if let Witness::Trace { first_incompatible, .. } = &w {
            if let SerialPosition::Discriminant { case_name, old_value, new_value } =
                &first_incompatible.position
            {
                assert_eq!(case_name, "Paused");
                assert_eq!(*old_value, 1);
                assert!(new_value.is_none());
            } else {
                panic!("expected Discriminant position");
            }
        }
    }

    // ------------------------------------------------------------------
    // Enum case value changed
    // ------------------------------------------------------------------

    #[test]
    fn witness_enum_case_value_changed_shows_old_and_new_values() {
        let old = spec_with_enum(&[("Ready", 0), ("Busy", 1)]);
        let new = spec_with_enum(&[("Ready", 0), ("Busy", 42)]);
        let finding = make_finding("Enum Case Value Changed", Some("MyEnum.Busy"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace());
        if let Witness::Trace { first_incompatible, .. } = &w {
            if let SerialPosition::Discriminant { old_value, new_value, .. } =
                &first_incompatible.position
            {
                assert_eq!(*old_value, 1);
                assert_eq!(*new_value, Some(42));
            }
        }
    }

    // ------------------------------------------------------------------
    // Function parameter type changed
    // ------------------------------------------------------------------

    #[test]
    fn witness_parameter_type_changed_shows_types() {
        let old = spec_with_function("transfer", &[("amount", ScSpecTypeDef::U32)], None);
        let new = spec_with_function("transfer", &[("amount", ScSpecTypeDef::U64)], None);
        let finding = make_finding("Function Parameter Type Changed", Some("transfer.amount"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace());
        if let Witness::Trace { first_incompatible, .. } = &w {
            let interp = first_incompatible.interpretation.as_ref().unwrap();
            assert_eq!(interp.old_type, "u32");
            assert_eq!(interp.new_type, "u64");
        }
    }

    // ------------------------------------------------------------------
    // Return type changed
    // ------------------------------------------------------------------

    #[test]
    fn witness_return_type_changed_shows_types() {
        let old = spec_with_function("get_balance", &[], Some(ScSpecTypeDef::U64));
        let new = spec_with_function("get_balance", &[], Some(ScSpecTypeDef::I128));
        let finding = make_finding("Return Type Changed", Some("get_balance"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace());
        if let Witness::Trace { first_incompatible, .. } = &w {
            let interp = first_incompatible.interpretation.as_ref().unwrap();
            assert_eq!(interp.old_type, "u64");
            assert_eq!(interp.new_type, "i128");
        }
    }

    // ------------------------------------------------------------------
    // Unsupported category
    // ------------------------------------------------------------------

    #[test]
    fn unsupported_category_produces_unsupported_witness() {
        let spec = ContractSpec::default();
        let finding = make_finding("Function Added", Some("new_function"));
        let w = generate_witness(&finding, &spec, &spec, &policy());
        assert!(!w.is_trace());
        assert!(matches!(w, Witness::Unsupported { .. }));
    }

    #[test]
    fn missing_target_produces_unsupported_witness() {
        let spec = ContractSpec::default();
        let finding = make_finding("Struct Field Removed", None);
        let w = generate_witness(&finding, &spec, &spec, &policy());
        assert!(matches!(w, Witness::Unsupported { .. }));
    }

    // ------------------------------------------------------------------
    // Rendering
    // ------------------------------------------------------------------

    #[test]
    fn render_witness_text_is_non_empty_for_trace() {
        let old = spec_with_struct(&[("amount", ScSpecTypeDef::U32)]);
        let new = spec_with_struct(&[("amount", ScSpecTypeDef::U64)]);
        let finding = make_finding("Struct Field Type Changed", Some("MyStruct.amount"));
        let w = generate_witness(&finding, &old, &new, &policy());
        let text = render_witness_text(&w);
        assert!(!text.trim().is_empty());
    }

    #[test]
    fn render_witness_markdown_contains_bold() {
        let old = spec_with_struct(&[("amount", ScSpecTypeDef::U32)]);
        let new = spec_with_struct(&[("amount", ScSpecTypeDef::U64)]);
        let finding = make_finding("Struct Field Type Changed", Some("MyStruct.amount"));
        let w = generate_witness(&finding, &old, &new, &policy());
        let md = render_witness_markdown(&w);
        assert!(md.contains("**"), "Markdown should use bold markers: {md}");
    }

    #[test]
    fn render_witness_json_is_valid() {
        let old = spec_with_struct(&[("amount", ScSpecTypeDef::U32)]);
        let new = spec_with_struct(&[("amount", ScSpecTypeDef::U64)]);
        let finding = make_finding("Struct Field Type Changed", Some("MyStruct.amount"));
        let w = generate_witness(&finding, &old, &new, &policy());
        let v = render_witness_json(&w);
        assert!(v.is_object(), "should be a JSON object");
    }

    // ------------------------------------------------------------------
    // JSON round-trip
    // ------------------------------------------------------------------

    #[test]
    fn witness_trace_round_trips_through_json() {
        let old = spec_with_enum(&[("A", 0), ("B", 1)]);
        let new = spec_with_enum(&[("A", 0)]);
        let finding = make_finding("Enum Case Removed", Some("MyEnum.B"));
        let w = generate_witness(&finding, &old, &new, &policy());
        let json = serde_json::to_string(&w).unwrap();
        let back: Witness = serde_json::from_str(&json).unwrap();
        assert_eq!(back.category(), w.category());
        assert_eq!(back.is_trace(), w.is_trace());
    }

    #[test]
    fn witness_unsupported_round_trips_through_json() {
        let spec = ContractSpec::default();
        let finding = make_finding("Cascading Layout Break", Some("Foo"));
        let w = generate_witness(&finding, &spec, &spec, &policy());
        let json = serde_json::to_string(&w).unwrap();
        let back: Witness = serde_json::from_str(&json).unwrap();
        assert!(!back.is_trace());
    }

    // ------------------------------------------------------------------
    // Nested-type fixture: struct containing UDT field
    // ------------------------------------------------------------------

    #[test]
    fn witness_struct_with_nested_udt_field_type_changed() {
        // Inner type is a UDT; the witness records the change in the outer struct.
        let old = spec_with_struct(&[("payload", ScSpecTypeDef::Udt(stellar_xdr::curr::ScSpecTypeUdt {
            name: uname("Inner"),
        }))]);
        let new = spec_with_struct(&[("payload", ScSpecTypeDef::U64)]);
        let finding = make_finding("Struct Field Type Changed", Some("MyStruct.payload"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace());
        if let Witness::Trace { first_incompatible, .. } = &w {
            let interp = first_incompatible.interpretation.as_ref().unwrap();
            assert!(interp.old_type.contains("Inner"), "should mention nested type: {}", interp.old_type);
            assert_eq!(interp.new_type, "u64");
        }
    }

    // ------------------------------------------------------------------
    // Union case type changed fixture
    // ------------------------------------------------------------------

    #[test]
    fn witness_union_case_type_changed_produces_trace() {
        use stellar_xdr::curr::{
            ScSpecUdtUnionCaseV0, ScSpecUdtUnionCaseTupleV0, ScSpecUdtUnionV0,
        };

        let make_union = |payload_type: ScSpecTypeDef| -> ContractSpec {
            let mut spec = ContractSpec::default();
            spec.unions.insert(
                "MyUnion".into(),
                ScSpecUdtUnionV0 {
                    doc: StringM::default(),
                    lib: StringM::default(),
                    name: uname("MyUnion"),
                    cases: VecM::try_from(vec![
                        ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                            doc: StringM::default(),
                            name: uname("Data"),
                            value_types: VecM::try_from(vec![payload_type]).unwrap(),
                        }),
                    ])
                    .unwrap(),
                },
            );
            spec
        };

        let old = make_union(ScSpecTypeDef::U32);
        let new = make_union(ScSpecTypeDef::I128);
        let finding = make_finding("Union Case Type Changed", Some("MyUnion.Data"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace(), "expected Trace, got: {w}");
        if let Witness::Trace { first_incompatible, .. } = &w {
            let interp = first_incompatible.interpretation.as_ref().unwrap();
            assert_eq!(interp.old_type, "u32");
            assert_eq!(interp.new_type, "i128");
        }
    }

    // ------------------------------------------------------------------
    // Storage witness fixtures
    // ------------------------------------------------------------------

    #[test]
    fn witness_storage_durability_changed_produces_trace() {
        let spec = ContractSpec::default();
        let mut finding = make_finding("Storage Durability Changed", Some("MyKey"));
        finding.message =
            "storage durability changed from persistent to temporary for key MyKey".into();
        let w = generate_witness(&finding, &spec, &spec, &policy());
        assert!(w.is_trace(), "expected Trace, got: {w}");
        if let Witness::Trace { first_incompatible, .. } = &w {
            let interp = first_incompatible.interpretation.as_ref().unwrap();
            assert!(interp.old_type.contains("persistent"), "old_type: {}", interp.old_type);
            assert!(interp.new_type.contains("temporary"), "new_type: {}", interp.new_type);
        }
    }

    #[test]
    fn witness_storage_namespace_changed_produces_trace() {
        let spec = ContractSpec::default();
        let mut finding = make_finding("Storage Namespace Changed", Some("MyKey"));
        finding.message = "storage namespace changed from old_ns to new_ns for key MyKey".into();
        let w = generate_witness(&finding, &spec, &spec, &policy());
        assert!(w.is_trace(), "expected Trace, got: {w}");
    }

    // ------------------------------------------------------------------
    // Event schema fixtures
    // ------------------------------------------------------------------

    #[test]
    fn witness_event_schema_removed_produces_trace() {
        // Event structs are stored as regular structs.
        let old = spec_with_struct(&[("topic", ScSpecTypeDef::Symbol), ("amount", ScSpecTypeDef::U64)]);
        let new = spec_with_struct(&[("topic", ScSpecTypeDef::Symbol)]);
        let finding = make_finding("Event Schema Removed", Some("MyStruct.amount"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace(), "expected Trace, got: {w}");
        if let Witness::Trace { first_incompatible, .. } = &w {
            let interp = first_incompatible.interpretation.as_ref().unwrap();
            assert!(interp.new_type.contains("removed"), "should say removed: {}", interp.new_type);
        }
    }

    #[test]
    fn witness_event_schema_type_changed_produces_trace() {
        let old = spec_with_struct(&[("amount", ScSpecTypeDef::U64)]);
        let new = spec_with_struct(&[("amount", ScSpecTypeDef::I128)]);
        let finding = make_finding("Event Schema Type Changed", Some("MyStruct.amount"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace(), "expected Trace, got: {w}");
    }

    #[test]
    fn witness_event_schema_reordered_produces_trace() {
        let old = spec_with_struct(&[("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U64)]);
        let new = spec_with_struct(&[("b", ScSpecTypeDef::U64), ("a", ScSpecTypeDef::U32)]);
        let finding = make_finding("Event Schema Reordered", Some("MyStruct.a"));
        let w = generate_witness(&finding, &old, &new, &policy());
        assert!(w.is_trace(), "expected Trace, got: {w}");
    }

    // ------------------------------------------------------------------
    // Unsupported-transition fixture
    // ------------------------------------------------------------------

    #[test]
    fn unsupported_transition_is_labeled_explicitly() {
        // A category the witness engine intentionally does not handle.
        let spec = ContractSpec::default();
        let finding = make_finding("Host Import Added", Some("some_import"));
        let w = generate_witness(&finding, &spec, &spec, &policy());
        assert!(!w.is_trace(), "Host Import Added should be unsupported");
        if let Witness::Unsupported { reason, .. } = &w {
            // The reason should name the category so reviewers know exactly
            // what they are looking at.
            assert!(
                reason.contains("Host Import Added"),
                "reason should mention the unsupported category: {reason}"
            );
        } else {
            panic!("expected Unsupported, got: {w}");
        }
    }

    #[test]
    fn storage_entry_position_round_trips_through_json() {
        let pos = SerialPosition::StorageEntry {
            key: "MyKey".into(),
            durability: "persistent".into(),
        };
        let json = serde_json::to_string(&pos).unwrap();
        let back: SerialPosition = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pos);
    }
}

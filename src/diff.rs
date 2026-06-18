use crate::mapper::LayoutMapper;
use crate::spec::ContractSpec;
use serde::Serialize;
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
    ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
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
pub fn compare(old: &ContractSpec, new: &ContractSpec) -> DiffReport {
    let mut report = DiffReport::default();

    compare_functions(old, new, &mut report);
    compare_structs(old, new, &mut report);
    compare_enums(old, new, &mut report);

    detect_cascading_layout_breaks(old, &mut report);

    report
}

/// Helper to detect if a User-Defined Type represents an Event by standard Soroban naming conventions.
fn is_event(name: &str) -> bool {
    name.to_lowercase().contains("event")
}

/// Compare function signatures between old and new contract specs.
fn compare_functions(old: &ContractSpec, new: &ContractSpec, report: &mut DiffReport) {
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
                });
            }
            Some(new_fn) => {
                check_function_signature(name, old_fn, new_fn, report);
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
            });
        }
    }
}

/// Compare signatures of two functions with the same name.
fn check_function_signature(
    name: &str,
    old_fn: &ScSpecFunctionV0,
    new_fn: &ScSpecFunctionV0,
    report: &mut DiffReport,
) {
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
        });
        return; // No point comparing individual params if count differs
    }

    // Check each input parameter
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
            });
        }

        if !types_equal(&old_input.type_, &new_input.type_) {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Parameter Type Changed".to_string(),
                message: format!(
                    "Function '{}': parameter {} ('{}') type changed from `{}` to `{}`.",
                    name,
                    i,
                    old_name,
                    crate::mapper::type_to_string(&old_input.type_),
                    crate::mapper::type_to_string(&new_input.type_)
                ),
                type_name: None,
            });
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
        });
    } else {
        for (i, (old_out, new_out)) in old_outputs.iter().zip(new_outputs.iter()).enumerate() {
            if !types_equal(old_out, new_out) {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Return Type Changed".to_string(),
                    message: format!(
                        "Function '{}': return type {} changed from `{}` to `{}`.",
                        name,
                        i,
                        crate::mapper::type_to_string(old_out),
                        crate::mapper::type_to_string(new_out)
                    ),
                    type_name: None,
                });
            }
        }
    }
}

/// Compare two ScSpecTypeDef values for equality.
/// We use the PartialEq derive on the XDR types.
fn types_equal(a: &ScSpecTypeDef, b: &ScSpecTypeDef) -> bool {
    a == b
}

/// Compare struct definitions between old and new contract specs.
fn compare_structs(old: &ContractSpec, new: &ContractSpec, report: &mut DiffReport) {
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
                });
            }
            Some(new_struct) => {
                check_struct_fields(name, old_struct, new_struct, report);
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
            });
        }
    }
}

/// Compare fields of two structs with the same name.
///
/// Soroban serializes struct fields by position order, so field reordering,
/// removal, or type changes all break storage layout compatibility.
fn check_struct_fields(
    name: &str,
    old_struct: &ScSpecUdtStructV0,
    new_struct: &ScSpecUdtStructV0,
    report: &mut DiffReport,
) {
    let old_fields: &[ScSpecUdtStructFieldV0] = old_struct.fields.as_ref();
    let new_fields: &[ScSpecUdtStructFieldV0] = new_struct.fields.as_ref();
    let is_evt = is_event(name);
    let category_prefix = if is_evt {
        "Event Schema"
    } else {
        "Struct Field"
    };
    let msg_prefix = if is_evt { "Event schema" } else { "Struct" };

    // Check for removed fields
    for old_field in old_fields {
        let old_name = old_field.name.to_string();
        let still_exists = new_fields.iter().any(|f| f.name.to_string() == old_name);
        if !still_exists {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: format!("{} Removed", category_prefix),
                message: format!(
                    "{} '{}': field '{}' was removed. Backwards compatibility is broken.",
                    msg_prefix, name, old_name
                ),
                type_name: Some(name.to_string()),
            });
        }
    }

    // Check fields that exist in both versions, by position
    for (i, (old_field, new_field)) in old_fields.iter().zip(new_fields.iter()).enumerate() {
        let old_name = old_field.name.to_string();
        let new_name = new_field.name.to_string();

        // Field at the same position has a different name — reordering detected
        if old_name != new_name {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: format!("{} Reordered", category_prefix),
                message: format!(
                    "{} '{}': field at position {} changed from '{}' to '{}'. \
                     Positional serialization breaks layout compatibility.",
                    msg_prefix, name, i, old_name, new_name
                ),
                type_name: Some(name.to_string()),
            });
        }

        // Field type changed
        if !types_equal(&old_field.type_, &new_field.type_) {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: format!("{} Type Changed", category_prefix),
                message: format!(
                    "{} '{}': field '{}' (position {}) type changed from `{}` to `{}`.",
                    msg_prefix,
                    name,
                    old_name,
                    i,
                    crate::mapper::type_to_string(&old_field.type_),
                    crate::mapper::type_to_string(&new_field.type_)
                ),
                type_name: Some(name.to_string()),
            });
        }
    }

    // Check for new fields appended at the end
    if new_fields.len() > old_fields.len() {
        for new_field in &new_fields[old_fields.len()..] {
            report.findings.push(Finding {
                severity: Severity::Warning,
                category: "Struct Field Added".to_string(),
                message: format!(
                    "Struct '{}': new field '{}' appended. \
                     Existing storage entries won't have this field — ensure migration handles defaults.",
                    name,
                    new_field.name
                ),
                type_name: Some(name.to_string()),
            });
        }
    }
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
                });
            }
            Some(new_enum) => {
                check_enum_cases(name, old_enum, new_enum, report);
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
                });
            }
        }
    }
}

/// Uses dependency graphing to figure out if storage layout changes cascade to other types.
fn detect_cascading_layout_breaks(old: &ContractSpec, report: &mut DiffReport) {
    let old_mapper = LayoutMapper::new(old);
    let reverse_deps = old_mapper.build_reverse_dependencies();

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
                            "Type '{}' layout is implicitly broken safely because it contains modified type '{}'. \
                             This breaks backwards compatibility for storage.",
                            dep, current_broken_type
                        ),
                        type_name: Some(dep.clone()),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{ScSpecTypeUdt, StringM, VecM};

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

        // Outer should have a cascading break
        let outer_cascade = report.findings.iter().any(|f| {
            f.severity == Severity::Critical
                && f.type_name.as_deref() == Some("Outer")
                && f.category == "Cascading Layout Break"
        });
        assert!(outer_cascade, "Expected a cascading break for Outer");
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
    }
}

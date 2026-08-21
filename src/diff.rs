use crate::capability;
use crate::category::FindingCategory;
use crate::mapper::LayoutMapper;
use crate::parser::{ContractEnvMeta, ImportedFunction};
use crate::spec::ContractSpec;
use serde::{Deserialize, Serialize};
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
    ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    ScSpecUdtUnionCaseV0, ScSpecUdtUnionV0,
};

/// Severity of a detected issue.
///
/// `Deserialize` is derived so a previously emitted JSON report can be read
/// back and re-rendered (see [`crate::render`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

/// A compatibility axis along which findings can be categorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityAxis {
    StorageLayout,
    CallAbi,
    EventIndexer,
    SourceLevel,
}

impl CompatibilityAxis {
    pub fn default_severity(&self) -> Severity {
        match self {
            CompatibilityAxis::StorageLayout => Severity::Critical,
            CompatibilityAxis::CallAbi => Severity::Critical,
            CompatibilityAxis::EventIndexer => Severity::Warning,
            CompatibilityAxis::SourceLevel => Severity::Info,
        }
    }
}

/// A single finding from the comparison analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[cfg(feature = "unstable")]
    pub severity: Severity,
    #[cfg(not(feature = "unstable"))]
    pub(crate) severity: Severity,

    /// The compatibility axes this finding was classified under.
    #[cfg(feature = "unstable")]
    pub axes: Vec<CompatibilityAxis>,
    /// The compatibility axes this finding was classified under.
    #[cfg(not(feature = "unstable"))]
    pub(crate) axes: Vec<CompatibilityAxis>,

    #[cfg(feature = "unstable")]
    pub category: String,
    #[cfg(not(feature = "unstable"))]
    pub(crate) category: String,

    #[cfg(feature = "unstable")]
    pub message: String,
    #[cfg(not(feature = "unstable"))]
    pub(crate) message: String,

    /// The name of the affected UDT (struct/enum/union), if this finding
    /// relates to a specific type.  Used by cascade-detection so it never
    /// needs to re-parse `message`.
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub type_name: Option<String>,
    /// The name of the affected UDT (struct/enum/union), if this finding
    /// relates to a specific type.  Used by cascade-detection so it never
    /// needs to re-parse `message`.
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) type_name: Option<String>,

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
    #[serde(default)]
    #[cfg(feature = "unstable")]
    pub target: Option<String>,
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
    #[serde(default)]
    #[cfg(not(feature = "unstable"))]
    pub(crate) target: Option<String>,

    /// For cascade findings, the `target` of the root cause finding.
    /// `None` for direct (non-cascade) findings.
    #[cfg(feature = "unstable")]
    pub root_target: Option<String>,
    /// For cascade findings, the `target` of the root cause finding.
    /// `None` for direct (non-cascade) findings.
    #[cfg(not(feature = "unstable"))]
    pub(crate) root_target: Option<String>,
}

impl Finding {
    /// Get the severity of the finding.
    pub fn severity(&self) -> &Severity {
        &self.severity
    }

    /// Get the category of the finding.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Get the message of the finding.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the type name associated with this finding, if any.
    pub fn type_name(&self) -> Option<&str> {
        self.type_name.as_deref()
    }

    /// Get the stable, structured target identifier of the finding, if any.
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Get the root target of the cascading break, if any.
    pub fn root_target(&self) -> Option<&str> {
        self.root_target.as_deref()
    }
}

impl Finding {
    pub fn new(
        axes: Vec<CompatibilityAxis>,
        category: String,
        message: String,
        type_name: Option<String>,
        target: Option<String>,
        root_target: Option<String>,
    ) -> Self {
        let severity = axes
            .iter()
            .map(|a| a.default_severity())
            .max_by_key(|s| match s {
                Severity::Critical => 3,
                Severity::Warning => 2,
                Severity::Info => 1,
            })
            .unwrap_or(Severity::Info);

        Self {
            severity,
            axes,
            category,
            message,
            type_name,
            target,
            root_target,
        }
    }
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
    compare_unions(old, new, &mut report);
    compare_error_enums(old, new, &mut report);

    // Must run after the per-kind passes, which each see only their own map and
    // so mistake a kind change for an unrelated removal plus addition, and
    // before cascade detection, so a type that changed kind still propagates to
    // everything embedding it.
    detect_type_kind_changes(old, new, &mut report);

    detect_cascading_layout_breaks(old, &mut report);

    // Post-process to assign axes and legacy severity
    for finding in &mut report.findings {
        finding.axes =
            classify_finding_axes(&finding.category, finding.type_name.as_deref(), old, new);
    }

    report
}

/// Compute directional call-ABI verdicts without changing the legacy finding
/// stream consumed by existing callers.
pub fn compare_call_abi(
    old: &ContractSpec,
    new: &ContractSpec,
) -> crate::call_abi::CallAbiCompatibility {
    crate::call_abi::compare(old, new)
}

/// Recursively check if type_def references target_name directly or transitively in spec.
fn references_type(type_def: &ScSpecTypeDef, target_name: &str, spec: &ContractSpec) -> bool {
    match type_def {
        ScSpecTypeDef::Udt(udt) => {
            let udt_name = udt.name.to_string();
            if udt_name == target_name {
                return true;
            }
            if let Some(st) = spec.structs.get(&udt_name) {
                for field in st.fields.iter() {
                    if let ScSpecTypeDef::Udt(ref f_udt) = field.type_ {
                        if f_udt.name.to_string() == udt_name {
                            continue;
                        }
                    }
                    if references_type(&field.type_, target_name, spec) {
                        return true;
                    }
                }
            }
            if let Some(un) = spec.unions.get(&udt_name) {
                for case in un.cases.iter() {
                    if let stellar_xdr::curr::ScSpecUdtUnionCaseV0::TupleV0(t) = case {
                        for ty in t.type_.iter() {
                            if let ScSpecTypeDef::Udt(ref f_udt) = ty {
                                if f_udt.name.to_string() == udt_name {
                                    continue;
                                }
                            }
                            if references_type(ty, target_name, spec) {
                                return true;
                            }
                        }
                    }
                }
            }
            false
        }
        ScSpecTypeDef::Option(opt) => references_type(&opt.value_type, target_name, spec),
        ScSpecTypeDef::Result(res) => {
            references_type(&res.ok_type, target_name, spec)
                || references_type(&res.error_type, target_name, spec)
        }
        ScSpecTypeDef::Vec(v) => references_type(&v.element_type, target_name, spec),
        ScSpecTypeDef::Map(m) => {
            references_type(&m.key_type, target_name, spec)
                || references_type(&m.value_type, target_name, spec)
        }
        ScSpecTypeDef::Tuple(t) => t
            .value_types
            .iter()
            .any(|ty| references_type(ty, target_name, spec)),
        _ => false,
    }
}

/// Helper to check if type_name is used in any function signatures.
fn is_type_used_in_functions(type_name: &str, spec: &ContractSpec) -> bool {
    for func in spec.functions.values() {
        for input in func.inputs.iter() {
            if references_type(&input.type_, type_name, spec) {
                return true;
            }
        }
        for output in func.outputs.iter() {
            if references_type(output, type_name, spec) {
                return true;
            }
        }
    }
    false
}

/// Helper to check if type_name is used in any events.
fn is_type_used_in_events(type_name: &str, spec: &ContractSpec) -> bool {
    if type_name.to_lowercase().contains("event") {
        return true;
    }
    for name in spec.structs.keys() {
        if name.to_lowercase().contains("event")
            && references_type(
                &ScSpecTypeDef::Udt(stellar_xdr::curr::ScSpecTypeUdt {
                    name: name.try_into().unwrap(),
                }),
                type_name,
                spec,
            )
        {
            return true;
        }
    }
    for name in spec.unions.keys() {
        if name.to_lowercase().contains("event")
            && references_type(
                &ScSpecTypeDef::Udt(stellar_xdr::curr::ScSpecTypeUdt {
                    name: name.try_into().unwrap(),
                }),
                type_name,
                spec,
            )
        {
            return true;
        }
    }
    false
}

/// Classify a finding into explicit compatibility axes based on its category and type usage.
pub fn classify_finding_axes(
    category: &str,
    type_name: Option<&str>,
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Vec<CompatibilityAxis> {
    let mut axes = Vec::new();

    match category {
        "Environment"
        | "Host Import Added"
        | "Host Import Removed"
        | "Host Import Signature Changed"
        | "Unknown Host Import"
        | "Protocol Requirement Raised"
        | "Protocol Environment Mismatch" => {
            axes.push(CompatibilityAxis::CallAbi);
        }

        "Function Removed"
        | "Function Added"
        | "Function Signature Changed"
        | "Parameter Reordered"
        | "Parameter Type Changed"
        | "Return Type Changed" => {
            axes.push(CompatibilityAxis::CallAbi);
        }

        "Parameter Renamed" => {
            axes.push(CompatibilityAxis::SourceLevel);
        }

        "Event Definition Removed"
        | "Event Field Removed"
        | "Event Field Reordered"
        | "Event Field Type Changed"
        | "Event Enum Removed"
        | "Event Enum Case Removed"
        | "Event Enum Case Value Changed"
        | "Event Enum Case Added" => {
            axes.push(CompatibilityAxis::EventIndexer);
        }

        "Error Enum Removed"
        | "Error Enum Added"
        | "Error Enum Case Removed"
        | "Error Enum Case Value Changed"
        | "Error Enum Case Added" => {
            axes.push(CompatibilityAxis::CallAbi);
        }

        _ => {
            if let Some(t_name) = type_name {
                let is_used_in_abi = is_type_used_in_functions(t_name, old_spec)
                    || is_type_used_in_functions(t_name, new_spec);
                let is_used_in_event = is_type_used_in_events(t_name, old_spec)
                    || is_type_used_in_events(t_name, new_spec);

                if is_used_in_abi {
                    axes.push(CompatibilityAxis::CallAbi);
                }
                if is_used_in_event {
                    axes.push(CompatibilityAxis::EventIndexer);
                }

                let is_layout_break = matches!(
                    category,
                    "Struct Removed"
                        | "Struct Field Removed"
                        | "Struct Field Reordered"
                        | "Struct Field Type Changed"
                        | "Enum Removed"
                        | "Enum Case Removed"
                        | "Enum Case Value Changed"
                        | "Union Removed"
                        | "Union Case Removed"
                        | "Union Case Reordered"
                        | "Union Case Type Changed"
                        | "Cascading Layout Break"
                        | "Type Kind Changed"
                );

                if is_layout_break {
                    axes.push(CompatibilityAxis::StorageLayout);
                }

                if category.contains("Documentation Changed") {
                    axes.push(CompatibilityAxis::SourceLevel);
                }
            } else {
                axes.push(CompatibilityAxis::StorageLayout);
            }
        }
    }

    if axes.is_empty() {
        axes.push(CompatibilityAxis::StorageLayout);
    }

    axes
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
                axes: Vec::new(),
                severity,
                category: FindingCategory::Environment.as_str().to_string(),
                message: format_env_metadata_change(old_meta, new_meta),
                type_name: None,
                target: None,
                root_target: None,
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

/// Compute the minimum Stellar protocol version implied by the recognized
/// host capabilities a contract imports, using the [`capability`] registry.
///
/// Returns `None` when none of `imports` resolve to a recognized capability
/// — that is not the same as "protocol 0"; it means there is no basis for a
/// number, and callers must not invent one. Unrecognized imports never
/// contribute to this computation.
pub fn minimum_required_protocol(imports: &[ImportedFunction]) -> Option<u32> {
    imports
        .iter()
        .filter_map(|import| capability::lookup(&import.module, &import.name))
        .map(|cap| cap.min_protocol)
        .max()
}

fn describe_import_signature(import: &ImportedFunction) -> String {
    match &import.signature {
        Some(sig) => format!(
            "({}) -> ({})",
            sig.params
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            sig.results
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        None => "unresolved".to_string(),
    }
}

fn push_unknown_host_import(module: &str, name: &str, added: bool, report: &mut DiffReport) {
    report.findings.push(Finding {
        severity: Severity::Warning,
        axes: Vec::new(),
        category: FindingCategory::UnknownHostImport.as_str().to_string(),
        message: format!(
            "{} import `{module}::{name}` is not present in the host import capability \
             registry, so its Soroban protocol requirement cannot be determined \
             automatically. Verify it manually against the SDK or provider that defines it.",
            if added { "A newly added" } else { "A removed" },
        ),
        type_name: None,
        target: Some(format!("{module}::{name}")),
        root_target: None,
    });
}

/// Compare the host imports of two contract builds and push structured
/// findings classifying newly required, removed, signature-changed, and
/// unknown imports, plus protocol-requirement findings cross-checked
/// against each build's declared `contractenvmetav0` environment metadata.
///
/// Unrecognized `(module, name)` import pairs are always surfaced via
/// [`FindingCategory::UnknownHostImport`] rather than silently classified —
/// see `docs/capability-registry.md`.
pub fn compare_host_imports(
    old_imports: &[ImportedFunction],
    new_imports: &[ImportedFunction],
    old_env: Option<&ContractEnvMeta>,
    new_env: Option<&ContractEnvMeta>,
    report: &mut DiffReport,
) {
    use std::collections::BTreeMap;

    let old_by_key: BTreeMap<(&str, &str), &ImportedFunction> = old_imports
        .iter()
        .map(|import| ((import.module.as_str(), import.name.as_str()), import))
        .collect();
    let new_by_key: BTreeMap<(&str, &str), &ImportedFunction> = new_imports
        .iter()
        .map(|import| ((import.module.as_str(), import.name.as_str()), import))
        .collect();

    for &(module, name) in new_by_key.keys() {
        if old_by_key.contains_key(&(module, name)) {
            continue;
        }
        match capability::lookup(module, name) {
            Some(cap) => {
                report.findings.push(Finding {
                    severity: Severity::Warning,
                    axes: Vec::new(),
                    category: FindingCategory::HostImportAdded.as_str().to_string(),
                    message: format!(
                        "New host import requires the `{}` capability ({module}::{name}, \
                         available since protocol {}): {}",
                        cap.capability_id, cap.min_protocol, cap.docs
                    ),
                    type_name: None,
                    target: Some(cap.capability_id.to_string()),
                    root_target: None,
                });
            }
            None => push_unknown_host_import(module, name, true, report),
        }
    }

    for &(module, name) in old_by_key.keys() {
        if new_by_key.contains_key(&(module, name)) {
            continue;
        }
        match capability::lookup(module, name) {
            Some(cap) => {
                report.findings.push(Finding {
                    severity: Severity::Info,
                    axes: Vec::new(),
                    category: FindingCategory::HostImportRemoved.as_str().to_string(),
                    message: format!(
                        "The `{}` capability ({module}::{name}) is no longer imported.",
                        cap.capability_id
                    ),
                    type_name: None,
                    target: Some(cap.capability_id.to_string()),
                    root_target: None,
                });
            }
            None => push_unknown_host_import(module, name, false, report),
        }
    }

    for (&(module, name), new_import) in &new_by_key {
        let Some(old_import) = old_by_key.get(&(module, name)) else {
            continue;
        };
        let (Some(old_sig), Some(new_sig)) = (&old_import.signature, &new_import.signature) else {
            // One or both sides could not be resolved against the type
            // section; never guess at a signature change from that.
            continue;
        };
        if old_sig == new_sig {
            continue;
        }

        let recognized = capability::lookup(module, name);
        let severity = if recognized.is_some() {
            Severity::Critical
        } else {
            Severity::Warning
        };
        let target = recognized
            .map(|cap| cap.capability_id.to_string())
            .unwrap_or_else(|| format!("{module}::{name}"));

        report.findings.push(Finding {
            severity,
            axes: Vec::new(),
            category: FindingCategory::HostImportSignatureChanged
                .as_str()
                .to_string(),
            message: format!(
                "Host import `{module}::{name}` signature changed from {} to {}.",
                describe_import_signature(old_import),
                describe_import_signature(new_import),
            ),
            type_name: None,
            target: Some(target),
            root_target: None,
        });
    }

    let old_min_protocol = minimum_required_protocol(old_imports);
    let new_min_protocol = minimum_required_protocol(new_imports);

    if let (Some(old_min), Some(new_min)) = (old_min_protocol, new_min_protocol) {
        if new_min > old_min {
            report.findings.push(Finding {
                severity: Severity::Warning,
                axes: Vec::new(),
                category: FindingCategory::ProtocolRequirementRaised
                    .as_str()
                    .to_string(),
                message: format!(
                    "The upgraded contract now requires Soroban protocol {new_min} or later \
                     (previously {old_min}), based on the host capabilities it imports. \
                     Verify the target network has activated protocol {new_min} before deploying."
                ),
                type_name: None,
                target: None,
                root_target: None,
            });
        }
    }

    check_protocol_environment_mismatch(
        "old",
        old_min_protocol,
        old_env.and_then(ContractEnvMeta::protocol_version),
        report,
    );
    check_protocol_environment_mismatch(
        "new",
        new_min_protocol,
        new_env.and_then(ContractEnvMeta::protocol_version),
        report,
    );
}

fn check_protocol_environment_mismatch(
    label: &str,
    computed_min_protocol: Option<u32>,
    declared_protocol: Option<u32>,
    report: &mut DiffReport,
) {
    let (Some(computed), Some(declared)) = (computed_min_protocol, declared_protocol) else {
        return;
    };
    if computed <= declared {
        return;
    }

    report.findings.push(Finding {
        severity: Severity::Critical,
        axes: Vec::new(),
        category: FindingCategory::ProtocolEnvironmentMismatch
            .as_str()
            .to_string(),
        message: format!(
            "The {label} contract's environment metadata declares protocol {declared}, but it \
             imports host capabilities that require protocol {computed} or later. This is an \
             internal inconsistency in the build; verify the toolchain and SDK version used to \
             compile it."
        ),
        type_name: None,
        target: None,
        root_target: None,
    });
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
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category: FindingCategory::FunctionRemoved.as_str().to_string(),
                    message: format!(
                        "Function '{}' was removed. Existing callers will break.",
                        name
                    ),
                    type_name: None,
                    target: Some(name.clone()),
                    root_target: None,
                });
            }
            Some(new_fn) => {
                check_function_signature(name, old_fn, new_fn, report);
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
                        axes: Vec::new(),
                        severity: Severity::Info,
                        category: FindingCategory::FunctionDocumentationChanged
                            .as_str()
                            .to_string(),
                        message,
                        type_name: None,
                        target: Some(name.clone()),
                        root_target: None,
                    });
                }
            }
        }
    }

    // Check for newly added functions (informational)
    for name in new.functions.keys() {
        if !old.functions.contains_key(name) {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Info,
                category: FindingCategory::FunctionAdded.as_str().to_string(),
                message: format!("New function '{}' added.", name),
                type_name: None,
                target: Some(name.clone()),
                root_target: None,
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
            axes: Vec::new(),
            severity: Severity::Critical,
            category: FindingCategory::FunctionSignatureChanged
                .as_str()
                .to_string(),
            message: format!(
                "Function '{}': parameter count changed from {} to {}.",
                name,
                old_inputs.len(),
                new_inputs.len()
            ),
            type_name: None,
            target: Some(name.to_string()),
            root_target: None,
        });
        return; // No point comparing individual params if count differs
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
            axes: Vec::new(),
            severity: Severity::Critical,
            category: FindingCategory::ParameterReordered.as_str().to_string(),
            message: format!(
                "Function '{}': parameters reordered. The set of parameter names is unchanged but their order differs.",
                name
            ),
            type_name: None,
            target: Some(name.to_string()),
            root_target: None,
        });

        // Check for genuine type changes by matching parameter name.
        let new_by_name: std::collections::HashMap<String, &ScSpecTypeDef> = new_inputs
            .iter()
            .map(|input| (input.name.to_string(), &input.type_))
            .collect();

        for (i, old_input) in old_inputs.iter().enumerate() {
            let p_name = old_input.name.to_string();
            if let Some(new_type) = new_by_name.get(&p_name) {
                if !types_equal(&old_input.type_, new_type) {
                    let (category, detail) = if let Some(bytesn_msg) =
                        describe_bytesn_size_change(&old_input.type_, new_type)
                    {
                        (
                            FindingCategory::BytesNSizeChanged.as_str().to_string(),
                            bytesn_msg,
                        )
                    } else {
                        (
                            FindingCategory::ParameterTypeChanged.as_str().to_string(),
                            describe_nested_type_change(&old_input.type_, new_type).unwrap_or_else(
                                || {
                                    format!(
                                        "type changed from `{}` to `{}`",
                                        crate::mapper::type_to_string(&old_input.type_),
                                        crate::mapper::type_to_string(new_type)
                                    )
                                },
                            ),
                        )
                    };
                    report.findings.push(Finding {
                        axes: Vec::new(),
                        severity: Severity::Critical,
                        category,
                        message: format!(
                            "Function '{}': parameter {} ('{}') {}.",
                            name, i, p_name, detail
                        ),
                        type_name: None,
                        target: Some(format!("{}.{}", name, p_name)),
                        root_target: None,
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
                    axes: Vec::new(),
                    severity: Severity::Warning,
                    category: FindingCategory::ParameterRenamed.as_str().to_string(),
                    message: format!(
                        "Function '{}': parameter {} renamed from '{}' to '{}'.",
                        name, i, old_name, new_name
                    ),
                    type_name: None,
                    target: Some(format!("{}.{}", name, old_name)),
                    root_target: None,
                });
            }

            if !types_equal(&old_input.type_, &new_input.type_) {
                let (category, detail) = if let Some(bytesn_msg) =
                    describe_bytesn_size_change(&old_input.type_, &new_input.type_)
                {
                    (
                        FindingCategory::BytesNSizeChanged.as_str().to_string(),
                        bytesn_msg,
                    )
                } else {
                    (
                        FindingCategory::ParameterTypeChanged.as_str().to_string(),
                        describe_nested_type_change(&old_input.type_, &new_input.type_)
                            .unwrap_or_else(|| {
                                format!(
                                    "type changed from `{}` to `{}`",
                                    crate::mapper::type_to_string(&old_input.type_),
                                    crate::mapper::type_to_string(&new_input.type_)
                                )
                            }),
                    )
                };
                report.findings.push(Finding {
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category,
                    message: format!(
                        "Function '{}': parameter {} ('{}') {}.",
                        name, i, old_name, detail
                    ),
                    type_name: None,
                    target: Some(format!("{}.{}", name, old_name)),
                    root_target: None,
                });
            }
        }
    }

    // Check output types
    let old_outputs: &[ScSpecTypeDef] = old_fn.outputs.as_ref();
    let new_outputs: &[ScSpecTypeDef] = new_fn.outputs.as_ref();

    if old_outputs.len() != new_outputs.len() {
        report.findings.push(Finding {
            axes: Vec::new(),
            severity: Severity::Critical,
            category: FindingCategory::ReturnTypeChanged.as_str().to_string(),
            message: format!(
                "Function '{}': return type count changed from {} to {}.",
                name,
                old_outputs.len(),
                new_outputs.len()
            ),
            type_name: None,
            target: Some(name.to_string()),
            root_target: None,
        });
    } else {
        for (i, (old_out, new_out)) in old_outputs.iter().zip(new_outputs.iter()).enumerate() {
            if !types_equal(old_out, new_out) {
                let (category, detail) =
                    if let Some(bytesn_msg) = describe_bytesn_size_change(old_out, new_out) {
                        (
                            FindingCategory::BytesNSizeChanged.as_str().to_string(),
                            bytesn_msg,
                        )
                    } else {
                        (
                            FindingCategory::ReturnTypeChanged.as_str().to_string(),
                            describe_nested_type_change(old_out, new_out).unwrap_or_else(|| {
                                format!(
                                    "changed from `{}` to `{}`",
                                    crate::mapper::type_to_string(old_out),
                                    crate::mapper::type_to_string(new_out)
                                )
                            }),
                        )
                    };
                report.findings.push(Finding {
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category,
                    message: format!("Function '{}': return type {} {}.", name, i, detail),
                    type_name: None,
                    target: Some(name.to_string()),
                    root_target: None,
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
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category: if is_evt {
                        FindingCategory::EventDefinitionRemoved.as_str().to_string()
                    } else {
                        FindingCategory::StructRemoved.as_str().to_string()
                    },
                    message: format!(
                        "{} '{}' was removed. Storage or systems relying on this type will break.",
                        if is_evt { "Event struct" } else { "Struct" },
                        name
                    ),
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                    root_target: None,
                });
            }
            Some(new_struct) => {
                check_struct_fields(name, old_struct, new_struct, report);
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
                        axes: Vec::new(),
                        severity: Severity::Info,
                        category: FindingCategory::StructDocumentationChanged
                            .as_str()
                            .to_string(),
                        message,
                        type_name: Some(name.clone()),
                        target: Some(name.clone()),
                        root_target: None,
                    });
                }
            }
        }
    }

    // Check for newly added structs (informational)
    for name in new.structs.keys() {
        if !old.structs.contains_key(name) {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Info,
                category: FindingCategory::StructAdded.as_str().to_string(),
                message: format!("New struct '{}' added.", name),
                type_name: Some(name.clone()),
                target: Some(name.clone()),
                root_target: None,
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
    let msg_prefix = if is_evt { "Event schema" } else { "Struct" };

    // Check for removed fields
    for old_field in old_fields {
        let old_name = old_field.name.to_string();
        let still_exists = new_fields.iter().any(|f| f.name.to_string() == old_name);
        if !still_exists {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Critical,
                category: if is_evt {
                    FindingCategory::EventSchemaRemoved.as_str().to_string()
                } else {
                    FindingCategory::StructFieldRemoved.as_str().to_string()
                },
                message: format!(
                    "{} '{}': field '{}' was removed. Backwards compatibility is broken.",
                    msg_prefix, name, old_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                root_target: None,
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
                axes: Vec::new(),
                severity: Severity::Critical,
                category: if is_evt {
                    FindingCategory::EventSchemaReordered.as_str().to_string()
                } else {
                    FindingCategory::StructFieldReordered.as_str().to_string()
                },
                message: format!(
                    "{} '{}': field at position {} changed from '{}' to '{}'. \
                     Positional serialization breaks layout compatibility.",
                    msg_prefix, name, i, old_name, new_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                root_target: None,
            });
        }

        // Field type changed
        if !types_equal(&old_field.type_, &new_field.type_) {
            let (category, detail) = if let Some(bytesn_msg) =
                describe_bytesn_size_change(&old_field.type_, &new_field.type_)
            {
                (
                    FindingCategory::BytesNSizeChanged.as_str().to_string(),
                    bytesn_msg,
                )
            } else {
                (
                    if is_evt {
                        FindingCategory::EventSchemaTypeChanged.as_str().to_string()
                    } else {
                        FindingCategory::StructFieldTypeChanged.as_str().to_string()
                    },
                    describe_nested_type_change(&old_field.type_, &new_field.type_).unwrap_or_else(
                        || {
                            format!(
                                "type changed from `{}` to `{}`",
                                crate::mapper::type_to_string(&old_field.type_),
                                crate::mapper::type_to_string(&new_field.type_)
                            )
                        },
                    ),
                )
            };
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Critical,
                category,
                message: format!(
                    "{} '{}': field '{}' (position {}) {}.",
                    msg_prefix, name, old_name, i, detail
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                root_target: None,
            });
        }
    }

    // Check for new fields appended at the end
    if new_fields.len() > old_fields.len() {
        for new_field in &new_fields[old_fields.len()..] {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Warning,
                category: FindingCategory::StructFieldAdded.as_str().to_string(),
                message: format!(
                    "Struct '{}': new field '{}' appended. \
                     Existing storage entries won't have this field — ensure migration handles defaults.",
                    name,
                    new_field.name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, new_field.name)),
                root_target: None,
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
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category: if is_evt {
                        FindingCategory::EventEnumRemoved.as_str().to_string()
                    } else {
                        FindingCategory::EnumRemoved.as_str().to_string()
                    },
                    message: format!(
                        "{} '{}' was removed. Data using this type will be invalid.",
                        if is_evt { "Event enum" } else { "Enum" },
                        name
                    ),
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                    root_target: None,
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
                        axes: Vec::new(),
                        severity: Severity::Info,
                        category: FindingCategory::EnumDocumentationChanged
                            .as_str()
                            .to_string(),
                        message,
                        type_name: Some(name.clone()),
                        target: Some(name.clone()),
                        root_target: None,
                    });
                }
            }
        }
    }

    // Check for newly added enums
    for name in new.enums.keys() {
        if !old.enums.contains_key(name) {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Info,
                category: FindingCategory::EnumAdded.as_str().to_string(),
                message: format!("New enum '{}' added.", name),
                type_name: Some(name.clone()),
                target: Some(name.clone()),
                root_target: None,
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
    let msg_prefix = if is_evt { "Event enum" } else { "Enum" };
    let old_cases: &[ScSpecUdtEnumCaseV0] = old_enum.cases.as_ref();
    let new_cases: &[ScSpecUdtEnumCaseV0] = new_enum.cases.as_ref();

    for old_case in old_cases {
        let old_name = old_case.name.to_string();

        match new_cases.iter().find(|c| c.name.to_string() == old_name) {
            None => {
                // The case was removed entirely
                report.findings.push(Finding {
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category: if is_evt {
                        FindingCategory::EventEnumCaseRemoved.as_str().to_string()
                    } else {
                        FindingCategory::EnumCaseRemoved.as_str().to_string()
                    },
                    message: format!(
                        "{} '{}': case '{}' (value: {}) was removed. \
                         On-chain data or events relying on this value will be invalid.",
                        msg_prefix, name, old_name, old_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                    root_target: None,
                });
            }
            Some(new_case) => {
                // The case exists, but did its integer value change?
                if old_case.value != new_case.value {
                    report.findings.push(Finding {
                        axes: Vec::new(),
                        severity: Severity::Critical,
                        category: if is_evt {
                            FindingCategory::EventEnumCaseValueChanged
                                .as_str()
                                .to_string()
                        } else {
                            FindingCategory::EnumCaseValueChanged.as_str().to_string()
                        },
                        message: format!(
                            "{} '{}': case '{}' value changed from {} to {}. \
                             This breaks data serialization.",
                            msg_prefix, name, old_name, old_case.value, new_case.value
                        ),
                        type_name: Some(name.to_string()),
                        target: Some(format!("{}.{}", name, old_name)),
                        root_target: None,
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
                    axes: Vec::new(),
                    severity: Severity::Info,
                    category: if is_evt {
                        FindingCategory::EventEnumCaseAdded.as_str().to_string()
                    } else {
                        FindingCategory::EnumCaseAdded.as_str().to_string()
                    },
                    message: format!(
                        "{} '{}': new case '{}' (value {}) added.",
                        msg_prefix, name, new_name, new_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, new_name)),
                    root_target: None,
                });
            }
        }
    }
}

/// Compare union definitions between old and new contract specs.
fn compare_unions(old: &ContractSpec, new: &ContractSpec, report: &mut DiffReport) {
    for (name, old_union) in &old.unions {
        match new.unions.get(name) {
            None => {
                report.findings.push(Finding {
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category: FindingCategory::UnionRemoved.as_str().to_string(),
                    message: format!(
                        "Union '{}' was removed. Data using this type will be invalid.",
                        name
                    ),
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                    root_target: None,
                });
            }
            Some(new_union) => {
                check_union_cases(name, old_union, new_union, report);
            }
        }
    }

    for name in new.unions.keys() {
        if !old.unions.contains_key(name) {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Info,
                category: FindingCategory::UnionAdded.as_str().to_string(),
                message: format!("New union '{}' added.", name),
                type_name: Some(name.clone()),
                target: Some(name.clone()),
                root_target: None,
            });
        }
    }
}

/// Compare cases of two unions with the same name.
///
/// Soroban unions serialize cases by positional discriminant, so case reordering,
/// removal, or payload type changes all break layout compatibility.
fn check_union_cases(
    name: &str,
    old_union: &ScSpecUdtUnionV0,
    new_union: &ScSpecUdtUnionV0,
    report: &mut DiffReport,
) {
    let old_cases: &[ScSpecUdtUnionCaseV0] = old_union.cases.as_ref();
    let new_cases: &[ScSpecUdtUnionCaseV0] = new_union.cases.as_ref();

    for old_case in old_cases {
        let old_name = union_case_name(old_case);
        let still_exists = new_cases.iter().any(|c| union_case_name(c) == old_name);
        if !still_exists {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Critical,
                category: FindingCategory::UnionCaseRemoved.as_str().to_string(),
                message: format!(
                    "Union '{}': case '{}' was removed. Backwards compatibility is broken.",
                    name, old_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                root_target: None,
            });
        }
    }

    for (i, (old_case, new_case)) in old_cases.iter().zip(new_cases.iter()).enumerate() {
        let old_name = union_case_name(old_case);
        let new_name = union_case_name(new_case);

        if old_name != new_name {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Critical,
                category: FindingCategory::UnionCaseReordered.as_str().to_string(),
                message: format!(
                    "Union '{}': case at position {} changed from '{}' to '{}'. \
                     Positional discriminant breaks layout compatibility.",
                    name, i, old_name, new_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                root_target: None,
            });
        }

        if !union_cases_equal(old_case, new_case) {
            let (category, detail) =
                if let Some(bytesn_msg) = union_case_bytesn_size_change(old_case, new_case) {
                    (
                        FindingCategory::BytesNSizeChanged.as_str().to_string(),
                        bytesn_msg,
                    )
                } else {
                    (
                        FindingCategory::UnionCaseTypeChanged.as_str().to_string(),
                        describe_union_case_type_change(old_case, new_case).unwrap_or_else(|| {
                            format!(
                                "type changed from `{}` to `{}`",
                                union_case_type_signature(old_case),
                                union_case_type_signature(new_case)
                            )
                        }),
                    )
                };
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Critical,
                category,
                message: format!(
                    "Union '{}': case '{}' (position {}) {}.",
                    name, old_name, i, detail
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                root_target: None,
            });
        }
    }

    if new_cases.len() > old_cases.len() {
        for new_case in &new_cases[old_cases.len()..] {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Info,
                category: FindingCategory::UnionCaseAdded.as_str().to_string(),
                message: format!(
                    "Union '{}': new case '{}' ({}) added.",
                    name,
                    union_case_name(new_case),
                    union_case_type_signature(new_case)
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, union_case_name(new_case))),
                root_target: None,
            });
        }
    }
}

fn union_case_name(case: &ScSpecUdtUnionCaseV0) -> String {
    match case {
        ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string(),
        ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string(),
    }
}

fn union_case_type_signature(case: &ScSpecUdtUnionCaseV0) -> String {
    match case {
        ScSpecUdtUnionCaseV0::VoidV0(_) => "void".to_string(),
        ScSpecUdtUnionCaseV0::TupleV0(t) => {
            let types: Vec<String> = t.type_.iter().map(crate::mapper::type_to_string).collect();
            format!("({})", types.join(", "))
        }
    }
}

fn union_cases_equal(a: &ScSpecUdtUnionCaseV0, b: &ScSpecUdtUnionCaseV0) -> bool {
    match (a, b) {
        (ScSpecUdtUnionCaseV0::VoidV0(_), ScSpecUdtUnionCaseV0::VoidV0(_)) => true,
        (ScSpecUdtUnionCaseV0::TupleV0(a_tuple), ScSpecUdtUnionCaseV0::TupleV0(b_tuple)) => {
            let a_types: &[ScSpecTypeDef] = a_tuple.type_.as_ref();
            let b_types: &[ScSpecTypeDef] = b_tuple.type_.as_ref();
            a_types.len() == b_types.len()
                && a_types
                    .iter()
                    .zip(b_types.iter())
                    .all(|(left, right)| types_equal(left, right))
        }
        _ => false,
    }
}

/// Compare contract error enum definitions between old and new specs.
fn compare_error_enums(old: &ContractSpec, new: &ContractSpec, report: &mut DiffReport) {
    for (name, old_error_enum) in &old.error_enums {
        match new.error_enums.get(name) {
            None => {
                report.findings.push(Finding {
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category: FindingCategory::ErrorEnumRemoved.as_str().to_string(),
                    message: format!(
                        "Error enum '{}' was removed. Clients matching on these errors will break.",
                        name
                    ),
                    type_name: Some(name.clone()),
                    target: Some(name.clone()),
                    root_target: None,
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
                axes: Vec::new(),
                severity: Severity::Info,
                category: FindingCategory::ErrorEnumAdded.as_str().to_string(),
                message: format!("New error enum '{}' added.", name),
                type_name: Some(name.clone()),
                target: Some(name.clone()),
                root_target: None,
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
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category: FindingCategory::ErrorEnumCaseRemoved.as_str().to_string(),
                    message: format!(
                        "Error enum '{}': case '{}' (value: {}) was removed. \
                         Clients matching on this error code will break.",
                        name, old_name, old_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                    root_target: None,
                });
            }
            Some(new_case) if old_case.value != new_case.value => {
                report.findings.push(Finding {
                    axes: Vec::new(),
                    severity: Severity::Critical,
                    category: FindingCategory::ErrorEnumCaseValueChanged
                        .as_str()
                        .to_string(),
                    message: format!(
                        "Error enum '{}': case '{}' value changed from {} to {}. \
                         This breaks error-code compatibility.",
                        name, old_name, old_case.value, new_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                    root_target: None,
                });
            }
            _ => {}
        }
    }

    for new_case in new_cases {
        let new_name = new_case.name.to_string();
        if !old_cases.iter().any(|c| c.name.to_string() == new_name) {
            report.findings.push(Finding {
                axes: Vec::new(),
                severity: Severity::Info,
                category: FindingCategory::ErrorEnumCaseAdded.as_str().to_string(),
                message: format!(
                    "Error enum '{}': new case '{}' (value {}) added.",
                    name, new_name, new_case.value
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, new_name)),
                root_target: None,
            });
        }
    }
}

/// Uses dependency graphing to figure out if storage layout changes cascade to other types.
///
/// The category string for a type-kind change.  Kept as a convenience alias for
/// external users; the single source of truth is `FindingCategory::TypeKindChanged`.
pub const TYPE_KIND_CHANGED_CATEGORY: &str = "Type Kind Changed";

/// Which of the five spec maps a user-defined type lives in.
///
/// The per-kind comparison passes each look at a single map, so they cannot see
/// that a name moved between maps. This enum is what lets
/// [`detect_type_kind_changes`] reason across them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UdtKind {
    Struct,
    Enum,
    Union,
    ErrorEnum,
}

impl UdtKind {
    /// Human-readable label used in finding messages.
    pub fn label(self) -> &'static str {
        match self {
            UdtKind::Struct => "struct",
            UdtKind::Enum => "enum",
            UdtKind::Union => "union",
            UdtKind::ErrorEnum => "error enum",
        }
    }

    /// The categories a per-kind pass emits when a type of this kind vanishes
    /// from the new spec.
    ///
    /// Two are possible for structs and enums because the event-naming
    /// convention picks a different label for the same underlying removal.
    fn removal_categories(self) -> &'static [&'static str] {
        match self {
            UdtKind::Struct => &["Struct Removed", "Event Definition Removed"],
            UdtKind::Enum => &["Enum Removed", "Event Enum Removed"],
            UdtKind::Union => &["Union Removed"],
            UdtKind::ErrorEnum => &["Error Enum Removed"],
        }
    }

    /// The category a per-kind pass emits when a type of this kind appears in
    /// the new spec.
    fn addition_category(self) -> &'static str {
        match self {
            UdtKind::Struct => "Struct Added",
            UdtKind::Enum => "Enum Added",
            UdtKind::Union => "Union Added",
            UdtKind::ErrorEnum => "Error Enum Added",
        }
    }
}

/// The kind a name is defined as in `spec`, if it is defined at all.
///
/// A name resolves to at most one kind: Rust type names are unique within a
/// contract, so the maps cannot both claim it.
fn udt_kind_of(spec: &ContractSpec, name: &str) -> Option<UdtKind> {
    if spec.structs.contains_key(name) {
        Some(UdtKind::Struct)
    } else if spec.enums.contains_key(name) {
        Some(UdtKind::Enum)
    } else if spec.unions.contains_key(name) {
        Some(UdtKind::Union)
    } else if spec.error_enums.contains_key(name) {
        Some(UdtKind::ErrorEnum)
    } else {
        None
    }
}

/// Report a user-defined type whose name persists but whose kind changed.
///
/// `compare_structs`, `compare_enums`, `compare_unions`, and
/// `compare_error_enums` each consult only their own map. When `Status` is a
/// struct in the old build and an enum in the new one, `compare_structs` sees a
/// struct that disappeared and reports a critical `Struct Removed`, while
/// `compare_enums` sees a brand-new enum and reports an informational
/// `Enum Added`. Nothing connects the two, and the informational half badly
/// understates the change: the type did not appear from nowhere, it replaced a
/// struct of the same name, which invalidates any stored data of that type.
///
/// This pass replaces that pair with a single critical finding. It runs after
/// the per-kind passes so it can retract their output, matching on `target`
/// (which is the bare type name for whole-type findings) rather than on message
/// text. Member-level findings such as `Status.field` are never retracted,
/// because their target carries a `Type.member` suffix.
///
/// There is currently no type-level rename detection in this module; if one is
/// added it must skip names handled here, so that a single change is not
/// reported as both a rename and a kind change.
pub fn detect_type_kind_changes(old: &ContractSpec, new: &ContractSpec, report: &mut DiffReport) {
    let mut changed: Vec<(String, UdtKind, UdtKind)> = old
        .structs
        .keys()
        .chain(old.enums.keys())
        .chain(old.unions.keys())
        .chain(old.error_enums.keys())
        .filter_map(|name| {
            let old_kind = udt_kind_of(old, name)?;
            let new_kind = udt_kind_of(new, name)?;
            (old_kind != new_kind).then(|| (name.clone(), old_kind, new_kind))
        })
        .collect();

    // The spec maps have no inherent order, so sort for a deterministic report.
    changed.sort();

    for (name, old_kind, new_kind) in changed {
        // Drop the spurious removal/addition pair the per-kind passes produced
        // for this name. Anything else about the type is left alone.
        report.findings.retain(|finding| {
            if finding.target.as_deref() != Some(name.as_str()) {
                return true;
            }
            let is_stale_removal = old_kind
                .removal_categories()
                .contains(&finding.category.as_str());
            let is_stale_addition = finding.category == new_kind.addition_category();
            !(is_stale_removal || is_stale_addition)
        });

        report.findings.push(Finding {
            axes: Vec::new(),
            severity: Severity::Critical,
            category: FindingCategory::TypeKindChanged.as_str().to_string(),
            message: format!(
                "Type '{}' changed from {} to {}. Stored data and client \
                 decoders written against the {} layout cannot read the {} \
                 that replaced it.",
                name,
                old_kind.label(),
                new_kind.label(),
                old_kind.label(),
                new_kind.label(),
            ),
            type_name: Some(name.clone()),
            target: Some(name),
            root_target: None,
        });
    }
}

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

    // A queue for transitive breaks: (type_name, root_target)
    let mut queue: Vec<(String, String)> =
        broken_types.into_iter().map(|t| (t.clone(), t)).collect();
    let mut i = 0;
    let mut cascaded: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();

    while i < queue.len() {
        let (current_broken_type, root) = queue[i].clone();
        i += 1;

        if let Some(dependents) = reverse_deps.get(&current_broken_type) {
            for dep in dependents {
                let key = (dep.clone(), root.clone());
                if !cascaded.contains(&key) {
                    cascaded.insert(key);
                    queue.push((dep.clone(), root.clone()));

                    report.findings.push(Finding {
                        axes: Vec::new(),
                        severity: Severity::Critical,
                        category: FindingCategory::CascadingLayoutBreak.as_str().to_string(),
                        message: format!(
                            "Type '{}' layout is broken because it embeds modified type '{}'. \
                             Stored data for '{}' is no longer compatible.",
                            dep, current_broken_type, dep
                        ),
                        type_name: Some(dep.clone()),
                        target: Some(dep.clone()),
                        root_target: Some(root.clone()),
                    });
                }
            }
        }
    }
}

/// When two `ScSpecUdtUnionCaseV0` values are both tuples with the same length
/// and differ only in one inner type, produce a concise description of the
/// innermost difference.  Returns `None` when the outer structures differ,
/// signalling the caller to fall back to the full-signature form.
fn describe_union_case_type_change(
    old: &ScSpecUdtUnionCaseV0,
    new: &ScSpecUdtUnionCaseV0,
) -> Option<String> {
    match (old, new) {
        (ScSpecUdtUnionCaseV0::TupleV0(a), ScSpecUdtUnionCaseV0::TupleV0(b)) => {
            let a_types: &[ScSpecTypeDef] = a.type_.as_ref();
            let b_types: &[ScSpecTypeDef] = b.type_.as_ref();
            if a_types.len() != b_types.len() {
                return None;
            }
            for (i, (at, bt)) in a_types.iter().zip(b_types.iter()).enumerate() {
                if at != bt {
                    return describe_nested_type_change(at, bt).or_else(|| {
                        Some(format!(
                            "payload type at index {} changed from `{}` to `{}`",
                            i,
                            crate::mapper::type_to_string(at),
                            crate::mapper::type_to_string(bt),
                        ))
                    });
                }
            }
            None
        }
        _ => None,
    }
}

/// When two `ScSpecTypeDef` values share the same container shape (e.g. both are
/// `Vec`) and differ only in a type argument, produce a concise description of
/// the innermost difference.  Returns `None` when the outer constructors
/// themselves differ, signalling the caller to fall back to the full-signature
/// form (e.g.  `"type changed from \`Map<Address, u32>\` to \`Map<Address, u64>\`"`).
fn describe_nested_type_change(old: &ScSpecTypeDef, new: &ScSpecTypeDef) -> Option<String> {
    if old == new {
        return None;
    }
    match (old, new) {
        (ScSpecTypeDef::Option(a), ScSpecTypeDef::Option(b)) => {
            describe_nested_type_change(&a.value_type, &b.value_type).or_else(|| {
                Some(format!(
                    "the inner type of Option changed from `{}` to `{}`",
                    crate::mapper::type_to_string(&a.value_type),
                    crate::mapper::type_to_string(&b.value_type),
                ))
            })
        }
        (ScSpecTypeDef::Vec(a), ScSpecTypeDef::Vec(b)) => {
            describe_nested_type_change(&a.element_type, &b.element_type).or_else(|| {
                Some(format!(
                    "the element type of Vec changed from `{}` to `{}`",
                    crate::mapper::type_to_string(&a.element_type),
                    crate::mapper::type_to_string(&b.element_type),
                ))
            })
        }
        (ScSpecTypeDef::Map(a), ScSpecTypeDef::Map(b)) => {
            if a.key_type != b.key_type {
                return describe_nested_type_change(&a.key_type, &b.key_type).or_else(|| {
                    Some(format!(
                        "the key type of Map changed from `{}` to `{}`",
                        crate::mapper::type_to_string(&a.key_type),
                        crate::mapper::type_to_string(&b.key_type),
                    ))
                });
            }
            describe_nested_type_change(&a.value_type, &b.value_type).or_else(|| {
                Some(format!(
                    "the value type of Map changed from `{}` to `{}`",
                    crate::mapper::type_to_string(&a.value_type),
                    crate::mapper::type_to_string(&b.value_type),
                ))
            })
        }
        (ScSpecTypeDef::Result(a), ScSpecTypeDef::Result(b)) => {
            if a.ok_type != b.ok_type {
                return describe_nested_type_change(&a.ok_type, &b.ok_type).or_else(|| {
                    Some(format!(
                        "the ok type of Result changed from `{}` to `{}`",
                        crate::mapper::type_to_string(&a.ok_type),
                        crate::mapper::type_to_string(&b.ok_type),
                    ))
                });
            }
            describe_nested_type_change(&a.error_type, &b.error_type).or_else(|| {
                Some(format!(
                    "the error type of Result changed from `{}` to `{}`",
                    crate::mapper::type_to_string(&a.error_type),
                    crate::mapper::type_to_string(&b.error_type),
                ))
            })
        }
        (ScSpecTypeDef::Tuple(a), ScSpecTypeDef::Tuple(b)) => {
            let a_types: &[ScSpecTypeDef] = a.value_types.as_ref();
            let b_types: &[ScSpecTypeDef] = b.value_types.as_ref();
            if a_types.len() != b_types.len() {
                return None;
            }
            for (i, (at, bt)) in a_types.iter().zip(b_types.iter()).enumerate() {
                if at != bt {
                    return describe_nested_type_change(at, bt).or_else(|| {
                        Some(format!(
                            "type at index {} of tuple changed from `{}` to `{}`",
                            i,
                            crate::mapper::type_to_string(at),
                            crate::mapper::type_to_string(bt),
                        ))
                    });
                }
            }
            None
        }
        _ => None,
    }
}

fn describe_bytesn_size_change(old: &ScSpecTypeDef, new: &ScSpecTypeDef) -> Option<String> {
    match (old, new) {
        (ScSpecTypeDef::BytesN(a), ScSpecTypeDef::BytesN(b)) if a.n != b.n => {
            Some(format!("size of BytesN changed from {} to {}", a.n, b.n))
        }
        _ => None,
    }
}

fn union_case_bytesn_size_change(
    old: &ScSpecUdtUnionCaseV0,
    new: &ScSpecUdtUnionCaseV0,
) -> Option<String> {
    match (old, new) {
        (ScSpecUdtUnionCaseV0::TupleV0(a), ScSpecUdtUnionCaseV0::TupleV0(b)) => {
            let a_types: &[ScSpecTypeDef] = a.type_.as_ref();
            let b_types: &[ScSpecTypeDef] = b.type_.as_ref();
            if a_types.len() != b_types.len() {
                return None;
            }
            for (i, (at, bt)) in a_types.iter().zip(b_types.iter()).enumerate() {
                if let Some(msg) = describe_bytesn_size_change(at, bt) {
                    return Some(format!("{} in payload type at index {}", msg, i));
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{ScEnvMetaEntry, ScSpecTypeUdt, StringM, VecM};
    use wasmparser::ValType;

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
            axes: Vec::new(),
            severity: Severity::Critical,
            category: "TOTALLY CUSTOM CATEGORY".to_string(),
            message: "This message has no quotes and mentions no type prefix whatsoever."
                .to_string(),
            type_name: Some("Child".to_string()),
            target: Some("Child".to_string()),
            root_target: None,
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
            axes: Vec::new(),
            severity: Severity::Critical,
            category: FindingCategory::FunctionRemoved.as_str().to_string(),
            message: "Function 'do_stuff' was removed.".to_string(),
            type_name: None,
            target: Some("do_stuff".to_string()),
            root_target: None,
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
        let safety = crate::report::SafetyReport::new_with_specs(&report, &old, &new);
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
        assert_eq!(finding.category, FindingCategory::Environment.as_str());
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
        assert_eq!(finding.category, FindingCategory::Environment.as_str());
    }

    #[test]
    fn env_metadata_findings_do_not_affect_is_safe() {
        let old = env_meta(21, 0);
        let new = env_meta(22, 0);
        let mut report = DiffReport::default();
        compare_env_metadata(Some(&old), Some(&new), &mut report);

        let empty_spec = ContractSpec::default();
        let safety = crate::report::SafetyReport::new_with_specs(&report, &empty_spec, &empty_spec);
        assert!(safety.is_safe);
        assert_eq!(safety.critical_count, 0);
    }

    /// Helper: a host import with no resolvable signature.
    fn imported(module: &str, name: &str) -> ImportedFunction {
        ImportedFunction {
            module: module.to_string(),
            name: name.to_string(),
            signature: None,
        }
    }

    /// Helper: a host import with a resolved (possibly empty) signature.
    fn imported_with_signature(
        module: &str,
        name: &str,
        params: Vec<ValType>,
        results: Vec<ValType>,
    ) -> ImportedFunction {
        ImportedFunction {
            module: module.to_string(),
            name: name.to_string(),
            signature: Some(crate::parser::ImportSignature { params, results }),
        }
    }

    #[test]
    fn unrecognized_import_added_is_reported_as_unknown() {
        let old: Vec<ImportedFunction> = vec![];
        let new = vec![imported("z", "not_a_real_import")];
        let mut report = DiffReport::default();
        compare_host_imports(&old, &new, None, None, &mut report);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(
            finding.category,
            FindingCategory::UnknownHostImport.as_str()
        );
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.target.as_deref(), Some("z::not_a_real_import"));
    }

    #[test]
    fn unrecognized_import_removed_is_reported_as_unknown() {
        let old = vec![imported("z", "not_a_real_import")];
        let new: Vec<ImportedFunction> = vec![];
        let mut report = DiffReport::default();
        compare_host_imports(&old, &new, None, None, &mut report);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].category,
            FindingCategory::UnknownHostImport.as_str()
        );
        assert!(report.findings[0].message.contains("removed"));
    }

    #[test]
    fn recognized_import_added_reports_capability_metadata() {
        let old: Vec<ImportedFunction> = vec![];
        // "l"/"_" is `put_contract_data`, available since the Soroban
        // baseline protocol (20).
        let new = vec![imported("l", "_")];
        let mut report = DiffReport::default();
        compare_host_imports(&old, &new, None, None, &mut report);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == FindingCategory::HostImportAdded.as_str())
            .expect("expected a host-import-added finding");
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.target.as_deref(), Some("ledger.put_contract_data"));
    }

    #[test]
    fn recognized_import_removed_is_info() {
        let old = vec![imported("l", "_")];
        let new: Vec<ImportedFunction> = vec![];
        let mut report = DiffReport::default();
        compare_host_imports(&old, &new, None, None, &mut report);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == FindingCategory::HostImportRemoved.as_str())
            .expect("expected a host-import-removed finding");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.target.as_deref(), Some("ledger.put_contract_data"));
    }

    #[test]
    fn no_findings_when_imports_are_unchanged() {
        let imports = vec![imported("l", "_"), imported("z", "custom")];
        let mut report = DiffReport::default();
        compare_host_imports(&imports, &imports, None, None, &mut report);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn signature_change_on_recognized_import_is_critical() {
        let old = vec![imported_with_signature(
            "l",
            "_",
            vec![ValType::I64],
            vec![ValType::I64],
        )];
        let new = vec![imported_with_signature(
            "l",
            "_",
            vec![ValType::I64, ValType::I64],
            vec![ValType::I64],
        )];
        let mut report = DiffReport::default();
        compare_host_imports(&old, &new, None, None, &mut report);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == FindingCategory::HostImportSignatureChanged.as_str())
            .expect("expected a signature-changed finding");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.target.as_deref(), Some("ledger.put_contract_data"));
    }

    #[test]
    fn signature_change_on_unknown_import_is_warning() {
        let old = vec![imported_with_signature(
            "z",
            "custom",
            vec![ValType::I64],
            vec![],
        )];
        let new = vec![imported_with_signature(
            "z",
            "custom",
            vec![ValType::I32],
            vec![],
        )];
        let mut report = DiffReport::default();
        compare_host_imports(&old, &new, None, None, &mut report);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == FindingCategory::HostImportSignatureChanged.as_str())
            .expect("expected a signature-changed finding");
        assert_eq!(finding.severity, Severity::Warning);
    }

    #[test]
    fn signature_change_is_never_guessed_when_either_side_is_unresolved() {
        let old = vec![imported("l", "_")];
        let new = vec![imported_with_signature(
            "l",
            "_",
            vec![ValType::I64],
            vec![ValType::I64],
        )];
        let mut report = DiffReport::default();
        compare_host_imports(&old, &new, None, None, &mut report);

        assert!(
            report
                .findings
                .iter()
                .all(|f| f.category != FindingCategory::HostImportSignatureChanged.as_str()),
            "an unresolved signature on either side must not produce a signature-changed finding"
        );
    }

    #[test]
    fn protocol_requirement_raised_across_a_protocol_boundary() {
        // "l"/"_" (put_contract_data) is available since protocol 20.
        let old = vec![imported("l", "_")];
        // "c"/"3" (verify_sig_ecdsa_secp256r1) requires protocol 21+.
        let new = vec![imported("l", "_"), imported("c", "3")];
        let mut report = DiffReport::default();
        compare_host_imports(&old, &new, None, None, &mut report);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == FindingCategory::ProtocolRequirementRaised.as_str())
            .expect("expected a protocol-requirement-raised finding");
        assert_eq!(finding.severity, Severity::Warning);
        assert!(finding.message.contains("21"));
        assert!(finding.message.contains("20"));
    }

    #[test]
    fn protocol_requirement_unchanged_produces_no_raised_finding() {
        let imports = vec![imported("l", "_"), imported("c", "3")];
        let mut report = DiffReport::default();
        compare_host_imports(&imports, &imports, None, None, &mut report);

        assert!(report
            .findings
            .iter()
            .all(|f| f.category != FindingCategory::ProtocolRequirementRaised.as_str()));
    }

    #[test]
    fn environment_mismatch_flagged_when_declared_protocol_is_too_low() {
        // The build declares protocol 20 but imports a protocol-21 capability.
        let new = vec![imported("c", "3")];
        let new_env = env_meta(20, 0);
        let mut report = DiffReport::default();
        compare_host_imports(&[], &new, None, Some(&new_env), &mut report);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == FindingCategory::ProtocolEnvironmentMismatch.as_str())
            .expect("expected a protocol-environment-mismatch finding");
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.message.contains("new"));
    }

    #[test]
    fn environment_mismatch_not_flagged_when_declared_protocol_is_sufficient() {
        let new = vec![imported("c", "3")];
        let new_env = env_meta(21, 0);
        let mut report = DiffReport::default();
        compare_host_imports(&[], &new, None, Some(&new_env), &mut report);

        assert!(report
            .findings
            .iter()
            .all(|f| f.category != FindingCategory::ProtocolEnvironmentMismatch.as_str()));
    }

    #[test]
    fn minimum_required_protocol_ignores_unrecognized_imports() {
        let imports = vec![imported("z", "custom")];
        assert_eq!(minimum_required_protocol(&imports), None);
    }

    #[test]
    fn minimum_required_protocol_is_the_highest_recognized_capability() {
        let imports = vec![imported("l", "_"), imported("c", "3"), imported("z", "x")];
        assert_eq!(minimum_required_protocol(&imports), Some(21));
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

    // --- Type kind changes (#250) -------------------------------------------

    fn insert_struct(spec: &mut ContractSpec, name: &str) {
        spec.structs.insert(
            name.to_string(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: name.try_into().unwrap(),
                fields: VecM::default(),
            },
        );
    }

    fn insert_enum(spec: &mut ContractSpec, name: &str) {
        spec.enums.insert(
            name.to_string(),
            ScSpecUdtEnumV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: name.try_into().unwrap(),
                cases: VecM::default(),
            },
        );
    }

    fn insert_union(spec: &mut ContractSpec, name: &str) {
        spec.unions.insert(
            name.to_string(),
            ScSpecUdtUnionV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: name.try_into().unwrap(),
                cases: VecM::default(),
            },
        );
    }

    fn insert_error_enum(spec: &mut ContractSpec, name: &str) {
        spec.error_enums.insert(
            name.to_string(),
            ScSpecUdtErrorEnumV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: name.try_into().unwrap(),
                cases: VecM::default(),
            },
        );
    }

    fn kind_change_findings<'a>(report: &'a DiffReport, name: &str) -> Vec<&'a Finding> {
        report
            .findings
            .iter()
            .filter(|f| {
                f.category == FindingCategory::TypeKindChanged.as_str()
                    && f.target.as_deref() == Some(name)
            })
            .collect()
    }

    #[test]
    fn struct_to_enum_is_a_single_breaking_kind_change() {
        let mut old = ContractSpec::default();
        insert_struct(&mut old, "Status");
        let mut new = ContractSpec::default();
        insert_enum(&mut new, "Status");

        let report = compare(&old, &new);

        let findings = kind_change_findings(&report, "Status");
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one kind-change finding"
        );

        let finding = findings[0];
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.type_name.as_deref(), Some("Status"));
        assert!(
            finding.message.contains("from struct to enum"),
            "message should name both kinds, got: {}",
            finding.message
        );
    }

    // ---------------------------------------------------------------
    // describe_nested_type_change unit tests
    // ---------------------------------------------------------------
    #[test]
    fn nested_type_change_option() {
        let old = ScSpecTypeDef::Option(Box::new(stellar_xdr::curr::ScSpecTypeOption {
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        let new = ScSpecTypeDef::Option(Box::new(stellar_xdr::curr::ScSpecTypeOption {
            value_type: Box::new(ScSpecTypeDef::U64),
        }));
        let desc = describe_nested_type_change(&old, &new);
        assert_eq!(
            desc,
            Some("the inner type of Option changed from `u32` to `u64`".to_string())
        );
    }

    #[test]
    fn nested_type_change_vec() {
        let old = ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::U32),
        }));
        let new = ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::U64),
        }));
        let desc = describe_nested_type_change(&old, &new);
        assert_eq!(
            desc,
            Some("the element type of Vec changed from `u32` to `u64`".to_string())
        );
    }

    #[test]
    fn nested_type_change_map_value() {
        let old = ScSpecTypeDef::Map(Box::new(stellar_xdr::curr::ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::Address),
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        let new = ScSpecTypeDef::Map(Box::new(stellar_xdr::curr::ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::Address),
            value_type: Box::new(ScSpecTypeDef::U64),
        }));
        let desc = describe_nested_type_change(&old, &new);
        assert_eq!(
            desc,
            Some("the value type of Map changed from `u32` to `u64`".to_string())
        );
    }

    #[test]
    fn nested_type_change_map_key() {
        let old = ScSpecTypeDef::Map(Box::new(stellar_xdr::curr::ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::Symbol),
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        let new = ScSpecTypeDef::Map(Box::new(stellar_xdr::curr::ScSpecTypeMap {
            key_type: Box::new(ScSpecTypeDef::String),
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        let desc = describe_nested_type_change(&old, &new);
        assert_eq!(
            desc,
            Some("the key type of Map changed from `Symbol` to `String`".to_string())
        );
    }

    #[test]
    fn nested_type_change_tuple() {
        let make_tuple = |types: Vec<ScSpecTypeDef>| {
            ScSpecTypeDef::Tuple(Box::new(stellar_xdr::curr::ScSpecTypeTuple {
                value_types: stellar_xdr::curr::VecM::try_from(types).unwrap(),
            }))
        };
        let old = make_tuple(vec![ScSpecTypeDef::U32, ScSpecTypeDef::U64]);
        let new = make_tuple(vec![ScSpecTypeDef::U32, ScSpecTypeDef::I128]);
        let desc = describe_nested_type_change(&old, &new);
        assert_eq!(
            desc,
            Some("type at index 1 of tuple changed from `u64` to `i128`".to_string())
        );
    }

    #[test]
    fn enum_to_union_is_a_single_breaking_kind_change() {
        let mut old = ContractSpec::default();
        insert_enum(&mut old, "Payload");
        let mut new = ContractSpec::default();
        insert_union(&mut new, "Payload");

        let report = compare(&old, &new);

        let findings = kind_change_findings(&report, "Payload");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(
            findings[0].message.contains("from enum to union"),
            "message should name both kinds, got: {}",
            findings[0].message
        );
    }

    #[test]
    fn nested_type_change_deeply_nested() {
        // Vec<Option<Map<Address, u32>>> -> Vec<Option<Map<Address, u64>>>
        let inner_map = |value: ScSpecTypeDef| {
            ScSpecTypeDef::Map(Box::new(stellar_xdr::curr::ScSpecTypeMap {
                key_type: Box::new(ScSpecTypeDef::Address),
                value_type: Box::new(value),
            }))
        };
        let old = ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::Option(Box::new(
                stellar_xdr::curr::ScSpecTypeOption {
                    value_type: Box::new(inner_map(ScSpecTypeDef::U32)),
                },
            ))),
        }));
        let new = ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::Option(Box::new(
                stellar_xdr::curr::ScSpecTypeOption {
                    value_type: Box::new(inner_map(ScSpecTypeDef::U64)),
                },
            ))),
        }));
        let desc = describe_nested_type_change(&old, &new);
        assert_eq!(
            desc,
            Some("the value type of Map changed from `u32` to `u64`".to_string())
        );
    }

    #[test]
    fn kind_change_replaces_the_spurious_removal_and_addition() {
        let mut old = ContractSpec::default();
        insert_struct(&mut old, "Status");
        let mut new = ContractSpec::default();
        insert_enum(&mut new, "Status");

        let report = compare(&old, &new);

        // The removal `compare_structs` produced and the addition
        // `compare_enums` produced must both be gone.
        for category in ["Struct Removed", "Enum Added"] {
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|f| f.category == category && f.target.as_deref() == Some("Status")),
                "'{category}' should have been replaced by the kind change"
            );
        }

        // And nothing else should be reported about `Status`.
        let about_status: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.target.as_deref() == Some("Status"))
            .map(|f| f.category.as_str())
            .collect();
        assert_eq!(
            about_status,
            vec![FindingCategory::TypeKindChanged.as_str()]
        );
    }

    #[test]
    fn kind_change_to_error_enum_is_detected() {
        let mut old = ContractSpec::default();
        insert_union(&mut old, "Outcome");
        let mut new = ContractSpec::default();
        insert_error_enum(&mut new, "Outcome");

        let report = compare(&old, &new);

        assert_eq!(kind_change_findings(&report, "Outcome").len(), 1);
        assert!(!report
            .findings
            .iter()
            .any(|f| f.category == "Union Removed" || f.category == "Error Enum Added"));
    }

    #[test]
    fn event_named_struct_to_enum_retracts_the_event_removal_variant() {
        // `is_event` gives a struct named "...Event" a different removal
        // category, which the retraction must also cover.
        let mut old = ContractSpec::default();
        insert_struct(&mut old, "TransferEvent");
        let mut new = ContractSpec::default();
        insert_enum(&mut new, "TransferEvent");

        let report = compare(&old, &new);

        assert_eq!(kind_change_findings(&report, "TransferEvent").len(), 1);
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.category == "Event Definition Removed"),
            "the event-flavored removal must be retracted too"
        );
    }

    #[test]
    fn nested_type_change_outer_constructor_differs() {
        // Vec<u32> -> Option<u32> — different outer constructors
        let old = ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::U32),
        }));
        let new = ScSpecTypeDef::Option(Box::new(stellar_xdr::curr::ScSpecTypeOption {
            value_type: Box::new(ScSpecTypeDef::U32),
        }));
        let desc = describe_nested_type_change(&old, &new);
        assert_eq!(desc, None);
    }

    // ---------------------------------------------------------------
    // Integration tests: type-change messages use concise format
    // ---------------------------------------------------------------
    #[test]
    fn field_type_change_vec_shows_concise_message() {
        let old = spec_with_structs(vec![(
            "Data",
            vec![(
                "values",
                ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
                    element_type: Box::new(ScSpecTypeDef::U32),
                })),
            )],
        )]);
        let new = spec_with_structs(vec![(
            "Data",
            vec![(
                "values",
                ScSpecTypeDef::Vec(Box::new(stellar_xdr::curr::ScSpecTypeVec {
                    element_type: Box::new(ScSpecTypeDef::U64),
                })),
            )],
        )]);

        let report = compare(&old, &new);
        let fc = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Changed")
            .expect("Expected field type change");
        assert!(
            fc.message
                .contains("the element type of Vec changed from `u32` to `u64`"),
            "Message was: {}",
            fc.message
        );
    }

    #[test]
    fn a_genuine_removal_is_still_reported() {
        // A type that really did disappear, with no replacement of another
        // kind, must keep its plain removal finding.
        let mut old = ContractSpec::default();
        insert_struct(&mut old, "Gone");
        let new = ContractSpec::default();

        let report = compare(&old, &new);

        assert!(kind_change_findings(&report, "Gone").is_empty());
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Struct Removed" && f.target.as_deref() == Some("Gone")));
    }

    #[test]
    fn a_genuine_addition_is_still_reported() {
        let old = ContractSpec::default();
        let mut new = ContractSpec::default();
        insert_enum(&mut new, "Fresh");

        let report = compare(&old, &new);

        assert!(kind_change_findings(&report, "Fresh").is_empty());
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Enum Added" && f.target.as_deref() == Some("Fresh")));
    }

    #[test]
    fn an_unchanged_kind_produces_no_kind_change() {
        let mut old = ContractSpec::default();
        insert_struct(&mut old, "Same");
        let mut new = ContractSpec::default();
        insert_struct(&mut new, "Same");

        let report = compare(&old, &new);
        assert!(kind_change_findings(&report, "Same").is_empty());
    }

    #[test]
    fn kind_change_does_not_retract_member_level_findings() {
        // A struct `Data` loses a field *and* another type changes kind. The
        // field finding targets `Data.amount`, so it must survive.
        let mut old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::I128)])]);
        insert_struct(&mut old, "Status");

        let mut new = spec_with_structs(vec![("Data", vec![])]);
        insert_enum(&mut new, "Status");

        let report = compare(&old, &new);

        assert_eq!(kind_change_findings(&report, "Status").len(), 1);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.target.as_deref() == Some("Data.amount")),
            "member-level findings must not be retracted"
        );
    }

    #[test]
    fn kind_change_cascades_to_embedding_types() {
        // `Wrapper` embeds `Status`. When `Status` changes kind, `Wrapper`'s
        // stored layout breaks too, so cascade detection must still fire.
        let mut old = spec_with_structs(vec![("Wrapper", vec![("status", udt("Status"))])]);
        insert_struct(&mut old, "Status");

        let mut new = spec_with_structs(vec![("Wrapper", vec![("status", udt("Status"))])]);
        insert_enum(&mut new, "Status");

        let report = compare(&old, &new);

        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == "Cascading Layout Break"
                    && f.target.as_deref() == Some("Wrapper")),
            "a kind change must cascade to types embedding it"
        );
    }

    #[test]
    fn field_type_change_map_shows_concise_message() {
        let make_map = |value: ScSpecTypeDef| {
            ScSpecTypeDef::Map(Box::new(stellar_xdr::curr::ScSpecTypeMap {
                key_type: Box::new(ScSpecTypeDef::Address),
                value_type: Box::new(value),
            }))
        };
        let old = spec_with_structs(vec![(
            "Data",
            vec![("balances", make_map(ScSpecTypeDef::U32))],
        )]);
        let new = spec_with_structs(vec![(
            "Data",
            vec![("balances", make_map(ScSpecTypeDef::U64))],
        )]);

        let report = compare(&old, &new);
        let fc = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Changed")
            .expect("Expected field type change");
        assert!(
            fc.message
                .contains("the value type of Map changed from `u32` to `u64`"),
            "Message was: {}",
            fc.message
        );
    }

    #[test]
    fn field_type_change_primitive_shows_full_message() {
        // u32 -> i128 — primitive change, should use full fallback format
        let old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::I128)])]);

        let report = compare(&old, &new);
        let fc = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Changed")
            .expect("Expected field type change");
        assert!(
            fc.message.contains("type changed from `u32` to `i128`"),
            "Message was: {}",
            fc.message
        );
    }

    // ---------------------------------------------------------------
    // BytesN size change unit tests
    // ---------------------------------------------------------------
    fn bytesn(n: u32) -> ScSpecTypeDef {
        ScSpecTypeDef::BytesN(stellar_xdr::curr::ScSpecTypeBytesN { n })
    }

    #[test]
    fn bytesn_size_change_detected() {
        let desc = describe_bytesn_size_change(&bytesn(32), &bytesn(64));
        assert_eq!(
            desc,
            Some("size of BytesN changed from 32 to 64".to_string())
        );
    }

    #[test]
    fn bytesn_same_size_no_change() {
        let desc = describe_bytesn_size_change(&bytesn(32), &bytesn(32));
        assert_eq!(desc, None);
    }

    #[test]
    fn bytesn_to_unrelated_no_change() {
        let desc = describe_bytesn_size_change(&bytesn(32), &ScSpecTypeDef::U64);
        assert_eq!(desc, None);
    }

    #[test]
    fn bytesn_struct_field_gets_specific_category() {
        let old = spec_with_structs(vec![("Data", vec![("key", bytesn(32))])]);
        let new = spec_with_structs(vec![("Data", vec![("key", bytesn(64))])]);

        let report = compare(&old, &new);
        let fc = report
            .findings
            .iter()
            .find(|f| f.category == "BytesN Size Changed")
            .expect("Expected a BytesN Size Changed finding");
        assert!(
            fc.message.contains("size of BytesN changed from 32 to 64"),
            "Message was: {}",
            fc.message
        );
        assert_eq!(fc.severity, Severity::Critical);
        assert_eq!(fc.target.as_deref(), Some("Data.key"));
    }

    #[test]
    fn bytesn_field_change_to_unrelated_uses_generic_category() {
        let old = spec_with_structs(vec![("Data", vec![("key", bytesn(32))])]);
        let new = spec_with_structs(vec![("Data", vec![("key", ScSpecTypeDef::String)])]);

        let report = compare(&old, &new);
        let fc = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Changed")
            .expect("Expected generic Struct Field Type Changed");
        assert!(
            fc.message
                .contains("type changed from `BytesN<32>` to `String`"),
            "Message was: {}",
            fc.message
        );
    }

    #[test]
    fn multiple_kind_changes_are_reported_deterministically() {
        let mut old = ContractSpec::default();
        insert_struct(&mut old, "Beta");
        insert_struct(&mut old, "Alpha");
        insert_union(&mut old, "Gamma");

        let mut new = ContractSpec::default();
        insert_enum(&mut new, "Beta");
        insert_enum(&mut new, "Alpha");
        insert_enum(&mut new, "Gamma");

        // The spec maps have no inherent order; the emitted order must not
        // depend on it, so repeated runs have to agree.
        let names_in_order = |report: &DiffReport| -> Vec<String> {
            report
                .findings
                .iter()
                .filter(|f| f.category == FindingCategory::TypeKindChanged.as_str())
                .map(|f| f.target.clone().unwrap())
                .collect()
        };

        let first = names_in_order(&compare(&old, &new));
        assert_eq!(first, vec!["Alpha", "Beta", "Gamma"]);

        for _ in 0..5 {
            assert_eq!(names_in_order(&compare(&old, &new)), first);
        }
    }

    #[test]
    fn bytesn_parameter_change_gets_specific_category() {
        let old = spec_with_functions(vec![("test", vec![("x", bytesn(32))])]);
        let new = spec_with_functions(vec![("test", vec![("x", bytesn(64))])]);

        let report = compare(&old, &new);
        let fc = report
            .findings
            .iter()
            .find(|f| f.category == "BytesN Size Changed")
            .expect("Expected a BytesN Size Changed finding");
        assert!(
            fc.message.contains("size of BytesN changed from 32 to 64"),
            "Message was: {}",
            fc.message
        );
    }
}

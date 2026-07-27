use crate::classification::{ClassificationConfig, TypeClass};
use crate::mapper::LayoutMapper;
use crate::parser::{ContractEnvMeta, ContractMeta, RUST_VERSION_KEY, SDK_VERSION_KEY};
use crate::rename::{match_renames, Rename};
use crate::spec::ContractSpec;
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use stellar_xdr::curr::{
    ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeDef, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0,
    ScSpecUdtErrorEnumCaseV0, ScSpecUdtErrorEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    ScSpecUdtUnionCaseV0, ScSpecUdtUnionV0,
};

/// Severity of a detected issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

/// A single finding from the comparison analysis.
#[derive(Debug, Clone, Serialize, JsonSchema)]
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
    /// How the affected user-defined type was classified (event vs. ordinary
    /// storage/interface type), when this finding is about a UDT.
    ///
    /// This is *display metadata only*. It never appears in [`Self::category`]
    /// and is never part of the suppression key, so a suppression rule keeps
    /// matching even if the classification later changes. `None` for findings
    /// not tied to a UDT (functions, parameters, environment metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<TypeClass>,
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
/// Uses the default classification config, which treats every type as ordinary
/// storage (no event claims). Use [`compare_with_classification`] to supply an
/// explicit [`ClassificationConfig`].
pub fn compare(old: &ContractSpec, new: &ContractSpec) -> DiffReport {
    compare_with_classification(old, new, &ClassificationConfig::none())
}

/// Compare two contract specs, resolving event/storage classification via
/// `classification`.
///
/// Classification affects only the human-facing message, remediation, and the
/// per-finding `classification` metadata — never the structural `category` used
/// for suppression matching.
pub fn compare_with_classification(
    old: &ContractSpec,
    new: &ContractSpec,
    classification: &ClassificationConfig,
) -> DiffReport {
    let mut report = DiffReport::default();

    compare_functions(old, new, &mut report);
    compare_structs(old, new, classification, &mut report);
    compare_enums(old, new, classification, &mut report);
    compare_unions(old, new, classification, &mut report);
    compare_error_enums(old, new, classification, &mut report);

    detect_cascading_layout_breaks(old, &mut report);

    report
}

/// Run the full structural diff bounded by `policy`.
///
/// This is the function the canonical pipeline ([`crate::lib`]) calls. It
/// runs the same stages as [`compare_with_classification`] but also enforces
/// the recursive type-walk depth limit from `policy`, returning a typed
/// [`crate::limits::LimitError`] when a type graph exceeds the configured
/// bound rather than overflowing the stack.
pub fn compare_with_policy(
    old: &ContractSpec,
    new: &ContractSpec,
    policy: &crate::limits::ResourcePolicy,
) -> Result<DiffReport, crate::limits::LimitError> {
    let mut report = DiffReport::default();

    compare_functions(old, new, &mut report);
    compare_structs(old, new, &ClassificationConfig::none(), &mut report);
    compare_enums(old, new, &ClassificationConfig::none(), &mut report);
    compare_unions(old, new, &ClassificationConfig::none(), &mut report);
    compare_error_enums(old, new, &ClassificationConfig::none(), &mut report);

    // Cascade detection uses the LayoutMapper which enforces the walk-depth
    // limit. If the graph exceeds it we surface a LimitError rather than
    // overflowing the stack.
    detect_cascading_layout_breaks_with_policy(old, &mut report, policy)?;

    Ok(report)
}

/// Category label for duplicate spec entries that are byte-identical across sections.
pub const SPEC_DUPLICATE_CATEGORY: &str = "Spec Entry Duplicate";
/// Category label for duplicate spec entries that conflict (different definitions).
pub const SPEC_CONFLICT_CATEGORY: &str = "Spec Entry Conflict";

/// Inject findings for duplicate spec entries detected during `ContractSpec::from_entries_checked`.
///
/// Identical duplicates (same definition in multiple sections) become `Info`
/// findings unless `compat_duplicates` is `true`, in which case they are
/// silently dropped. Conflicting duplicates (different definitions) always
/// become `Critical` findings.
pub fn report_duplicate_spec_entries(
    side: &str,
    duplicates: &[crate::spec::DuplicateEntry],
    section_count: usize,
    report: &mut DiffReport,
    compat_duplicates: bool,
) {
    for dup in duplicates {
        if dup.is_identical {
            let severity = if compat_duplicates {
                Severity::Info
            } else {
                Severity::Warning
            };
            report.findings.push(Finding {
                severity,
                category: SPEC_DUPLICATE_CATEGORY.to_string(),
                message: format!(
                    "{} WASM: {} '{}' appears in {} of {} contractspecv0 section(s) with an \
                     identical definition. The WASM is non-canonical but safe to use.",
                    side,
                    dup.kind.label(),
                    dup.name,
                    dup.sections.len(),
                    section_count,
                ),
                type_name: Some(dup.name.clone()),
                target: Some(dup.name.clone()),
                classification: None,
            });
        } else {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: SPEC_CONFLICT_CATEGORY.to_string(),
                message: format!(
                    "{} WASM: {} '{}' has conflicting definitions across contractspecv0 \
                     sections {:?}. The spec is ambiguous and the build cannot be trusted.",
                    side,
                    dup.kind.label(),
                    dup.name,
                    dup.sections,
                ),
                type_name: Some(dup.name.clone()),
                target: Some(dup.name.clone()),
                classification: None,
            });
        }
    }
}

/// Prefix applied to every finding that came from a declared storage schema.
///
/// Storage findings deliberately reuse the exported-interface categories, since
/// they are the same structural breaks; the prefix keeps the two scopes visibly
/// distinct in the report and in `findings_by_category` without duplicating the
/// comparison logic.
pub const STORAGE_CATEGORY_PREFIX: &str = "Storage ";

/// Category for a storage-schema reference whose target layout is unknown.
pub const STORAGE_UNRESOLVED_CATEGORY: &str = "Storage Reference Unresolved";

/// Compare two resolved storage schemas through the same diff engine used for
/// the exported interface, returning a `DiffReport` with the storage findings.
pub fn compare_storage_schemas(
    old: &crate::storage_schema::ResolvedStorageSchema,
    new: &crate::storage_schema::ResolvedStorageSchema,
) -> DiffReport {
    let mut report = compare_with_classification(&old.spec, &new.spec, &ClassificationConfig::none());

    for finding in &mut report.findings {
        // Prefer the old build's declaration: it describes the layout that
        // existing on-chain data was actually written with.
        let meta = finding
            .type_name
            .as_deref()
            .and_then(|name| old.meta.get(name).or_else(|| new.meta.get(name)));

        if let Some(meta) = meta {
            finding.severity = storage_severity(meta.role, &finding.category, &finding.severity);
            finding.message = format!(
                "[declared {} ({})] {}",
                meta.role.label(),
                meta.durability.label(),
                finding.message
            );
        } else {
            finding.message = format!("[declared storage type] {}", finding.message);
        }

        finding.category = format!("{}{}", STORAGE_CATEGORY_PREFIX, finding.category);
    }

    report
}

/// Re-evaluate a finding's severity in light of the role the type plays.
///
/// A storage key's serialized bytes *are* the address of every entry written
/// under it. Appending a field to a value type is a migration concern, because
/// existing bytes still decode for the fields that were already there. Appending
/// a field to a *key* changes the address itself, so every existing entry
/// becomes unreachable: the same edit, a categorically worse outcome.
fn storage_severity(
    role: crate::storage_schema::DeclarationRole,
    category: &str,
    current: &Severity,
) -> Severity {
    if role == crate::storage_schema::DeclarationRole::StorageKey && category == "Struct Field Added" {
        return Severity::Critical;
    }
    current.clone()
}

/// Inject `Info` findings for schema references the resolver could not match
/// against the exported spec. These are not errors — they just cap the coverage
/// claim so the report cannot overstate what was verified.
pub fn report_unresolved_storage_references(
    unresolved: &[String],
    report: &mut DiffReport,
) {
    for name in unresolved {
        report.findings.push(Finding {
            severity: Severity::Info,
            category: STORAGE_UNRESOLVED_CATEGORY.to_string(),
            message: format!(
                "Storage schema references type '{}', which is neither declared in the \
                 schema nor exported by the contract. Its layout could not be analyzed.",
                name
            ),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: None,
        });
    }
}

/// Category label for contract environment metadata findings.
pub const ENVIRONMENT_CATEGORY: &str = "Environment";

/// Every category string this crate can emit.
///
/// Categories are **purely structural**: they describe what changed in the
/// shape of the contract, never how a type was classified. There is no
/// `"Event …"` category — event-ness is reported separately in
/// [`Finding::classification`] and affects only wording and remediation. That
/// keeps a suppression key (`category` + `target`) stable across changes to the
/// classification config, so reclassifying a type can never silently suppress
/// or un-suppress a real breaking change.
///
/// Pre-1.0 event-flavored names are still accepted in suppression configs and
/// mapped onto these by [`crate::suppression::stable_category`].
///
/// This list is the single inventory the tests check against: every entry must
/// have remediation guidance, and every category literal emitted by this module
/// must appear here.
pub const ALL_CATEGORIES: &[&str] = &[
    ENVIRONMENT_CATEGORY,
    // Functions and their signatures.
    "Function Removed",
    "Function Added",
    "Function Documentation Changed",
    "Function Signature Changed",
    "Parameter Renamed",
    "Parameter Reordered",
    "Parameter Type Changed",
    "Parameter Type Widened",
    "Parameter Type Narrowed",
    "Parameter Type Signedness Changed",
    "Parameter Documentation Changed",
    "Return Type Changed",
    "Return Type Widened",
    "Return Type Narrowed",
    "Return Type Signedness Changed",
    // Type identity.
    "Type Renamed",
    "Type Renamed With Changes",
    // Structs.
    "Struct Removed",
    "Struct Added",
    "Struct Documentation Changed",
    "Struct Field Removed",
    "Struct Field Added",
    "Struct Field Reordered",
    "Struct Field Type Changed",
    "Struct Field Type Widened",
    "Struct Field Type Narrowed",
    "Struct Field Type Signedness Changed",
    "Struct Field Documentation Changed",
    // Enums.
    "Enum Removed",
    "Enum Added",
    "Enum Documentation Changed",
    "Enum Case Removed",
    "Enum Case Added",
    "Enum Case Value Changed",
    "Enum Case Documentation Changed",
    // Unions.
    "Union Removed",
    "Union Added",
    "Union Documentation Changed",
    "Union Case Removed",
    "Union Case Added",
    "Union Case Reordered",
    "Union Case Type Changed",
    "Union Case Type Widened",
    "Union Case Type Narrowed",
    "Union Case Type Signedness Changed",
    // Error enums.
    "Error Enum Removed",
    "Error Enum Added",
    "Error Enum Documentation Changed",
    "Error Enum Case Removed",
    "Error Enum Case Added",
    "Error Enum Case Value Changed",
    // Cascades.
    "Cascading Layout Break",
    // WASM host function imports.
    "Host Import Added",
    "Host Import Removed",
    // Contract metadata (`contractmetav0`) provenance and author keys.
    "Metadata SDK Version Changed",
    "Metadata Compiler Version Changed",
    "Metadata Key Added",
    "Metadata Key Removed",
    "Metadata Key Changed",
    // Spec-section integrity and storage-schema coverage.
    "Unresolved Storage Reference",
    // Binary export section vs. declared spec.
    "Export Removed",
    "Export Added",
    "Export Spec Mismatch",
    // Duplicate / conflicting spec entries.
    "Spec Entry Duplicate",
    "Spec Entry Conflict",
];

/// Compare the binary export sections of two WASM builds.
///
/// A function present in the old binary's export section but absent from the new
/// one is a breaking change — callers that invoke by name will get a missing
/// export at runtime. A function present in the new binary but absent from the
/// old one is informational (new export available).
///
/// Additionally, any name that appears in the `contractspecv0` spec but NOT in
/// the binary's export section (or vice versa) indicates a spec/binary mismatch
/// that should be visible.
///
/// `old_exports` and `new_exports` are the `exported_function_names` sets from
/// [`crate::parser::SorobanMetadata`]. `old_spec_fns` and `new_spec_fns` are
/// the function name sets from the respective [`crate::spec::ContractSpec`].
pub fn compare_exports(
    old_exports: &std::collections::BTreeSet<String>,
    new_exports: &std::collections::BTreeSet<String>,
    old_spec_fns: &std::collections::HashSet<String>,
    new_spec_fns: &std::collections::HashSet<String>,
    report: &mut DiffReport,
) {
    // 1. Exports present in the old binary but removed in the new binary.
    for name in old_exports {
        if name.starts_with('_') {
            continue;
        }
        if !new_exports.contains(name) {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Export Removed".to_string(),
                message: format!(
                    "Exported function '{}' is present in the old binary but absent from \
                     the new binary. On-chain callers will get a missing-export error at runtime.",
                    name
                ),
                type_name: None,
                target: Some(name.clone()),
                classification: None,
            });
        }
    }

    // 2. Exports present in the new binary but absent from the old binary.
    for name in new_exports {
        if name.starts_with('_') {
            continue;
        }
        if !old_exports.contains(name) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Export Added".to_string(),
                message: format!(
                    "Function '{}' is exported by the new binary but was absent from \
                     the old binary. New entry-point available to callers.",
                    name
                ),
                type_name: None,
                target: Some(name.clone()),
                classification: None,
            });
        }
    }

    // 3. Each build's declared spec must agree with the functions the binary
    // actually exports. Check both sides: an inconsistent baseline is useful
    // diagnostic information too, and an inconsistent candidate is unsafe.
    for (side, exports, spec_fns) in [
        ("old", old_exports, old_spec_fns),
        ("new", new_exports, new_spec_fns),
    ] {
        for name in spec_fns {
            if !exports.contains(name) {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Export Spec Mismatch".to_string(),
                    message: format!(
                        "Function '{}' is declared in the {} contract spec but is NOT present in \
                         that binary's export section. Callers following the spec will fail at runtime.",
                        name, side
                    ),
                    type_name: None,
                    target: Some(name.clone()),
                    classification: None,
                });
            }
        }
        for name in exports {
            if name.starts_with('_') {
                continue;
            }
            if !spec_fns.contains(name) {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Export Spec Mismatch".to_string(),
                    message: format!(
                        "Function '{}' is exported by the {} binary but is NOT declared in \
                         that contract spec. The spec does not reflect all callable entry-points.",
                        name, side
                    ),
                    type_name: None,
                    target: Some(name.clone()),
                    classification: None,
                });
            }
        }
    }
}

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
                classification: None,
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

/// Compare decoded contract metadata (`contractmetav0`) between two builds.
///
/// The Soroban SDK records build provenance here — its own version
/// ([`SDK_VERSION_KEY`]) and the Rust compiler version ([`RUST_VERSION_KEY`]) —
/// and authors may add their own keys via `contractmeta!`. Provenance changes
/// are reported as distinct, higher-signal findings (`Warning`) than arbitrary
/// author-key changes (`Info`). Neither is a storage/interface layout break, so
/// nothing here is `Critical`: that severity stays reserved for breaks that
/// actually orphan data or callers.
pub fn compare_contract_metadata(
    old: Option<&ContractMeta>,
    new: Option<&ContractMeta>,
    report: &mut DiffReport,
) {
    let old_pairs = old.map(ContractMeta::pairs).unwrap_or_default();
    let new_pairs = new.map(ContractMeta::pairs).unwrap_or_default();

    // Reserved provenance keys, reported as dedicated version findings.
    compare_meta_version(
        "Metadata SDK Version Changed",
        "Soroban SDK version",
        old_pairs.get(SDK_VERSION_KEY),
        new_pairs.get(SDK_VERSION_KEY),
        report,
    );
    compare_meta_version(
        "Metadata Compiler Version Changed",
        "Rust compiler version",
        old_pairs.get(RUST_VERSION_KEY),
        new_pairs.get(RUST_VERSION_KEY),
        report,
    );

    // Generic author-supplied keys: everything that is not a reserved key. The
    // union is sorted (BTreeSet) so findings are emitted in a stable order.
    let keys: BTreeSet<&str> = old_pairs
        .keys()
        .chain(new_pairs.keys())
        .map(String::as_str)
        .filter(|k| *k != SDK_VERSION_KEY && *k != RUST_VERSION_KEY)
        .collect();

    for key in keys {
        match (old_pairs.get(key), new_pairs.get(key)) {
            (Some(old_val), Some(new_val)) if old_val != new_val => push_meta_key_finding(
                report,
                "Metadata Key Changed",
                format!("Metadata key '{key}' changed from '{old_val}' to '{new_val}'."),
                key,
            ),
            (Some(_), Some(_)) => {}
            (None, Some(new_val)) => push_meta_key_finding(
                report,
                "Metadata Key Added",
                format!("Metadata key '{key}' was added with value '{new_val}'."),
                key,
            ),
            (Some(old_val), None) => push_meta_key_finding(
                report,
                "Metadata Key Removed",
                format!("Metadata key '{key}' was removed (was '{old_val}')."),
                key,
            ),
            (None, None) => {}
        }
    }
}

/// Emit a provenance-version finding (`Warning`) when a reserved metadata key's
/// value changed, appeared, or disappeared. `label` is the human noun (e.g.
/// "Soroban SDK version").
fn compare_meta_version(
    category: &str,
    label: &str,
    old: Option<&String>,
    new: Option<&String>,
    report: &mut DiffReport,
) {
    let message = match (old, new) {
        (Some(o), Some(n)) if o == n => return,
        (Some(o), Some(n)) => format!("{label} changed from '{o}' to '{n}'."),
        (None, Some(n)) => format!("{label} is now recorded as '{n}' (previously absent)."),
        (Some(o), None) => format!("{label} is no longer recorded (was '{o}')."),
        (None, None) => return,
    };
    report.findings.push(Finding {
        severity: Severity::Warning,
        category: category.to_string(),
        message,
        type_name: None,
        target: None,
        classification: None,
    });
}

/// Push a generic author-supplied metadata-key finding (`Info`), keyed on the
/// metadata key so a suppression rule can target it precisely.
fn push_meta_key_finding(report: &mut DiffReport, category: &str, message: String, key: &str) {
    report.findings.push(Finding {
        severity: Severity::Info,
        category: category.to_string(),
        message,
        type_name: None,
        target: Some(key.to_string()),
        classification: None,
    });
}

/// The human-facing noun used in a message for a type of the given class.
///
/// Only the *wording* varies with classification; the structural `category`
/// (e.g. `"Struct Field Removed"`) never does, so suppression keys stay stable
/// even if a type's classification later changes. See [`crate::classification`].
fn type_noun<'a>(class: TypeClass, storage: &'a str, event: &'a str) -> &'a str {
    match class {
        TypeClass::Event { .. } => event,
        TypeClass::Storage => storage,
    }
}

/// Append a heuristic-classification disclaimer to `message` when the class was
/// guessed from the type name rather than declared. Satisfies "the report labels
/// any heuristic classification as such."
fn with_heuristic_note(mut message: String, class: TypeClass) -> String {
    if class.is_heuristic() {
        message.push_str(
            " (classified as an event by the name heuristic; \
             declare it under [classification] to make this explicit)",
        );
    }
    message
}

/// The two sets of names consumed by detected renames: old names that should no
/// longer be reported as removed, and new names that should no longer be
/// reported as added.
fn rename_name_sets(renames: &[Rename]) -> (BTreeSet<&str>, BTreeSet<&str>) {
    let old_names = renames.iter().map(|r| r.old_name.as_str()).collect();
    let new_names = renames.iter().map(|r| r.new_name.as_str()).collect();
    (old_names, new_names)
}

/// Emit the finding for a detected rename. An identical layout is informational
/// (`Type Renamed`); a rename that also changes fields is a warning
/// (`Type Renamed With Changes`) and is followed by the field-level diff so the
/// actual break is not buried. `kind` is the lowercase type kind (e.g. `struct`).
fn emit_rename_finding(rename: &Rename, kind: &str, class: TypeClass, report: &mut DiffReport) {
    let (severity, category, detail) = if rename.identical {
        (
            Severity::Info,
            "Type Renamed",
            "the layout is identical, so stored data stays compatible",
        )
    } else {
        (
            Severity::Warning,
            "Type Renamed With Changes",
            "the layout also changed; see the field-level findings below",
        )
    };
    report.findings.push(Finding {
        severity,
        category: category.to_string(),
        message: with_heuristic_note(
            format!(
                "{} '{}' appears to have been renamed to '{}' — {}.",
                capitalize(kind),
                rename.old_name,
                rename.new_name,
                detail
            ),
            class,
        ),
        // Anchor to the NEW name so cascade/field targets line up with the
        // surviving type.
        type_name: Some(rename.new_name.clone()),
        target: Some(rename.new_name.clone()),
        classification: Some(class),
    });
}

/// Uppercase the first ASCII character of a short, known-lowercase kind label.
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
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
                    target: Some(name.clone()),
                    classification: None,
                });
            }
            Some(new_fn) => {
                check_function_signature(name, old_fn, new_fn, report);
                // Compare function doc-strings and emit informational findings
                push_doc_finding(
                    report,
                    "Function Documentation Changed",
                    &format!("Function '{}'", name),
                    &old_fn.doc.to_string(),
                    &new_fn.doc.to_string(),
                    None,
                    Some(name.clone()),
                    None,
                );
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
                classification: None,
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
            target: Some(name.to_string()),
            classification: None,
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
            severity: Severity::Critical,
            category: "Parameter Reordered".to_string(),
            message: format!(
                "Function '{}': parameters reordered. The set of parameter names is unchanged but their order differs.",
                name
            ),
            type_name: None,
            target: Some(name.to_string()),
            classification: None,
        });

        // Check for genuine type changes by matching parameter name.
        let new_by_name: std::collections::HashMap<String, &ScSpecFunctionInputV0> = new_inputs
            .iter()
            .map(|input| (input.name.to_string(), input))
            .collect();

        for (i, old_input) in old_inputs.iter().enumerate() {
            let p_name = old_input.name.to_string();
            if let Some(new_input) = new_by_name.get(&p_name) {
                if !types_equal(&old_input.type_, &new_input.type_) {
                    push_type_change_finding(
                        report,
                        &old_input.type_,
                        &new_input.type_,
                        "Parameter Type",
                        format!(
                            "Function '{}': parameter {} ('{}') type changed from `{}` to `{}`.",
                            name,
                            i,
                            p_name,
                            crate::mapper::type_to_string(&old_input.type_),
                            crate::mapper::type_to_string(&new_input.type_)
                        ),
                        None,
                        Some(format!("{}.{}", name, p_name)),
                        None,
                    );
                }
                push_doc_finding(
                    report,
                    "Parameter Documentation Changed",
                    &format!("Function '{}': parameter '{}'", name, p_name),
                    &old_input.doc.to_string(),
                    &new_input.doc.to_string(),
                    None,
                    Some(format!("{}.{}", name, p_name)),
                    None,
                );
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
                    classification: None,
                });
            }

            if !types_equal(&old_input.type_, &new_input.type_) {
                push_type_change_finding(
                    report,
                    &old_input.type_,
                    &new_input.type_,
                    "Parameter Type",
                    format!(
                        "Function '{}': parameter {} ('{}') type changed from `{}` to `{}`.",
                        name,
                        i,
                        old_name,
                        crate::mapper::type_to_string(&old_input.type_),
                        crate::mapper::type_to_string(&new_input.type_)
                    ),
                    None,
                    Some(format!("{}.{}", name, old_name)),
                    None,
                );
            }

            push_doc_finding(
                report,
                "Parameter Documentation Changed",
                &format!("Function '{}': parameter '{}'", name, old_name),
                &old_input.doc.to_string(),
                &new_input.doc.to_string(),
                None,
                Some(format!("{}.{}", name, old_name)),
                None,
            );
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
            classification: None,
        });
    } else {
        for (i, (old_out, new_out)) in old_outputs.iter().zip(new_outputs.iter()).enumerate() {
            if !types_equal(old_out, new_out) {
                push_type_change_finding(
                    report,
                    old_out,
                    new_out,
                    "Return Type",
                    format!(
                        "Function '{}': return type {} changed from `{}` to `{}`.",
                        name,
                        i,
                        crate::mapper::type_to_string(old_out),
                        crate::mapper::type_to_string(new_out)
                    ),
                    None,
                    Some(name.to_string()),
                    None,
                );
            }
        }
    }
}

/// Compare two ScSpecTypeDef values for equality.
/// We use the PartialEq derive on the XDR types.
fn types_equal(a: &ScSpecTypeDef, b: &ScSpecTypeDef) -> bool {
    a == b
}

/// How a numeric type change relates the old and new representations.
enum NumericChangeKind {
    /// Every value representable in the old type fits in the new type
    /// without loss (e.g. `u32` -> `u64`, or `u64` -> `i128`).
    Widened,
    /// The new type cannot represent every value the old type could
    /// (e.g. `u64` -> `u32`): values that don't fit are truncated.
    Narrowed,
    /// Old and new disagree on sign in a way that isn't a safe widening
    /// (e.g. `u32` -> `i32`, or `i64` -> `u32`): the stored bit pattern is
    /// reinterpreted, which can turn a valid value into a nonsensical one.
    SignednessChanged,
}

/// Bit width and signedness of a plain integer `ScSpecTypeDef`, or `None` for
/// any other type (including `Timepoint`/`Duration`, which are u64-shaped but
/// semantically distinct rather than plain numeric storage).
fn numeric_kind(t: &ScSpecTypeDef) -> Option<(u32, bool)> {
    Some(match t {
        ScSpecTypeDef::U32 => (32, false),
        ScSpecTypeDef::I32 => (32, true),
        ScSpecTypeDef::U64 => (64, false),
        ScSpecTypeDef::I64 => (64, true),
        ScSpecTypeDef::U128 => (128, false),
        ScSpecTypeDef::I128 => (128, true),
        ScSpecTypeDef::U256 => (256, false),
        ScSpecTypeDef::I256 => (256, true),
        _ => return None,
    })
}

/// Classify a numeric type change by ordering the two integer types on bit
/// width and signedness. Returns `None` when either side isn't a plain integer
/// type (the caller then falls back to the unclassified "Changed" wording).
fn classify_numeric_type_change(
    old: &ScSpecTypeDef,
    new: &ScSpecTypeDef,
) -> Option<NumericChangeKind> {
    let (old_bits, old_signed) = numeric_kind(old)?;
    let (new_bits, new_signed) = numeric_kind(new)?;
    if old_bits == new_bits && old_signed == new_signed {
        return None;
    }
    Some(match (old_signed, new_signed) {
        (false, false) | (true, true) => {
            if new_bits > old_bits {
                NumericChangeKind::Widened
            } else {
                NumericChangeKind::Narrowed
            }
        }
        // unsigned -> signed is a safe widening only if the signed type has
        // strictly more bits, since it then needs one of those extra bits
        // just to hold the sign and still covers the old unsigned range.
        (false, true) if new_bits > old_bits => NumericChangeKind::Widened,
        // Any other signedness flip (signed -> unsigned, or same/fewer bits)
        // can reinterpret the old bit pattern rather than merely truncate it.
        _ => NumericChangeKind::SignednessChanged,
    })
}

/// The category suffix, severity, and detail sentence for a type change,
/// derived from [`classify_numeric_type_change`].
struct TypeChangeClass {
    suffix: &'static str,
    severity: Severity,
    detail: Option<&'static str>,
}

fn classify_type_change(old: &ScSpecTypeDef, new: &ScSpecTypeDef) -> TypeChangeClass {
    match classify_numeric_type_change(old, new) {
        Some(NumericChangeKind::Widened) => TypeChangeClass {
            suffix: "Widened",
            severity: Severity::Warning,
            detail: Some(
                "This is a widening numeric conversion: every value representable in the old \
                 type fits in the new type without loss, but the on-chain layout still changes, \
                 so existing stored values must still be migrated to the new encoding.",
            ),
        },
        Some(NumericChangeKind::Narrowed) => TypeChangeClass {
            suffix: "Narrowed",
            severity: Severity::Critical,
            detail: Some(
                "This is a narrowing numeric conversion: values that don't fit in the new type \
                 will be truncated, corrupting stored data.",
            ),
        },
        Some(NumericChangeKind::SignednessChanged) => TypeChangeClass {
            suffix: "Signedness Changed",
            severity: Severity::Critical,
            detail: Some(
                "This changes signedness: existing stored bit patterns will be reinterpreted \
                 with a different sign, corrupting stored values.",
            ),
        },
        None => TypeChangeClass {
            suffix: "Changed",
            severity: Severity::Critical,
            detail: None,
        },
    }
}

/// Push a type-change finding whose category and severity reflect whether the
/// change is a plain (non-numeric) type change, or a numeric widening,
/// narrowing, or signedness change.
///
/// `base_category` is the category prefix (e.g. `"Parameter Type"`, which
/// becomes `"Parameter Type Widened"`/`"...Narrowed"`/`"...Signedness
/// Changed"`/`"...Changed"`). `base_message` is the full sentence describing
/// the change, ending in a period; the numeric detail sentence (if any) is
/// appended after it, so a non-numeric change renders exactly as it did
/// before this classification existed.
#[allow(clippy::too_many_arguments)]
fn push_type_change_finding(
    report: &mut DiffReport,
    old_ty: &ScSpecTypeDef,
    new_ty: &ScSpecTypeDef,
    base_category: &str,
    base_message: String,
    type_name: Option<String>,
    target: Option<String>,
    classification: Option<TypeClass>,
) {
    let class = classify_type_change(old_ty, new_ty);
    let message = match class.detail {
        Some(detail) => format!("{} {}", base_message, detail),
        None => base_message,
    };
    report.findings.push(Finding {
        severity: class.severity,
        category: format!("{} {}", base_category, class.suffix),
        message,
        type_name,
        target,
        classification,
    });
}

/// Build the Added/Removed/Changed documentation-change message fragment for
/// `subject` (e.g. `"Function 'transfer'"` or `"Struct 'Data': field
/// 'amount'"`), or `None` if the docs are identical. Shared by every entity
/// kind (functions, structs, enums, unions, error enums, and their members)
/// so the wording stays consistent everywhere a doc comparison is made.
fn doc_change_message(subject: &str, old_doc: &str, new_doc: &str) -> Option<String> {
    if old_doc == new_doc {
        return None;
    }
    let old_empty = old_doc.is_empty();
    let new_empty = new_doc.is_empty();
    Some(if old_empty && !new_empty {
        format!("{} documentation was added.", subject)
    } else if !old_empty && new_empty {
        format!("{} documentation was removed.", subject)
    } else {
        format!("{} documentation changed.", subject)
    })
}

/// Push an `Info` documentation-change finding via [`doc_change_message`], if
/// `old_doc` and `new_doc` differ.
#[allow(clippy::too_many_arguments)]
fn push_doc_finding(
    report: &mut DiffReport,
    category: &str,
    subject: &str,
    old_doc: &str,
    new_doc: &str,
    type_name: Option<String>,
    target: Option<String>,
    classification: Option<TypeClass>,
) {
    if let Some(message) = doc_change_message(subject, old_doc, new_doc) {
        report.findings.push(Finding {
            severity: Severity::Info,
            category: category.to_string(),
            message,
            type_name,
            target,
            classification,
        });
    }
}

/// Compare struct definitions between old and new contract specs.
///
/// Types present under the same name in both specs are compared field-by-field.
/// Names that appear only on one side are run through structural rename
/// detection ([`match_renames`]) *before* being reported as removed/added, so a
/// renamed-but-compatible type is reported as a rename rather than a delete plus
/// an add.
fn compare_structs(
    old: &ContractSpec,
    new: &ContractSpec,
    classification: &ClassificationConfig,
    report: &mut DiffReport,
) {
    // 1. Types present in both specs (same name): compare in place.
    for (name, old_struct) in &old.structs {
        if let Some(new_struct) = new.structs.get(name) {
            let class = classification.classify(name);
            check_struct_fields(name, old_struct, new_struct, class, report);
            // Compare struct doc-strings (informational only)
            push_doc_finding(
                report,
                "Struct Documentation Changed",
                &format!("Struct '{}'", name),
                &old_struct.doc.to_string(),
                &new_struct.doc.to_string(),
                Some(name.clone()),
                Some(name.clone()),
                Some(class),
            );
        }
    }

    // 2. Names on only one side: try to pair them up as renames first.
    let removed: BTreeMap<String, &ScSpecUdtStructV0> = old
        .structs
        .iter()
        .filter(|(n, _)| !new.structs.contains_key(*n))
        .map(|(n, s)| (n.clone(), s))
        .collect();
    let added: BTreeMap<String, &ScSpecUdtStructV0> = new
        .structs
        .iter()
        .filter(|(n, _)| !old.structs.contains_key(*n))
        .map(|(n, s)| (n.clone(), s))
        .collect();

    let renames = match_renames(&removed, &added);
    let (renamed_old, renamed_new) = rename_name_sets(&renames);

    for rename in &renames {
        let old_struct = removed[&rename.old_name];
        let new_struct = added[&rename.new_name];
        let class = classification.classify(&rename.new_name);
        emit_rename_finding(rename, "struct", class, report);
        if !rename.identical {
            // Diff the renamed type under its NEW name so field targets are stable.
            check_struct_fields(&rename.new_name, old_struct, new_struct, class, report);
        }
    }

    // 3. Genuinely removed structs (not part of a rename).
    for name in removed.keys() {
        if renamed_old.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        let noun = type_noun(class, "Struct", "Event struct");
        let message = with_heuristic_note(
            format!(
                "{} '{}' was removed. Storage or systems relying on this type will break.",
                noun, name
            ),
            class,
        );
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Struct Removed".to_string(),
            message,
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }

    // 4. Genuinely added structs (not part of a rename).
    for name in added.keys() {
        if renamed_new.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        report.findings.push(Finding {
            severity: Severity::Info,
            category: "Struct Added".to_string(),
            message: format!("New struct '{}' added.", name),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }
}

/// Compare fields of two structs with the same name.
///
/// Soroban serializes struct fields by position order, so field reordering,
/// removal, or type changes all break storage layout compatibility.
///
/// `class` only affects the human-facing wording and per-finding metadata; the
/// structural `category` is identical for storage and event types so that a
/// suppression keyed on it keeps matching even if the classification flips.
fn check_struct_fields(
    name: &str,
    old_struct: &ScSpecUdtStructV0,
    new_struct: &ScSpecUdtStructV0,
    class: TypeClass,
    report: &mut DiffReport,
) {
    let old_fields: &[ScSpecUdtStructFieldV0] = old_struct.fields.as_ref();
    let new_fields: &[ScSpecUdtStructFieldV0] = new_struct.fields.as_ref();
    let msg_prefix = type_noun(class, "Struct", "Event schema");

    // Check for removed fields
    for old_field in old_fields {
        let old_name = old_field.name.to_string();
        let still_exists = new_fields.iter().any(|f| f.name.to_string() == old_name);
        if !still_exists {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Struct Field Removed".to_string(),
                message: with_heuristic_note(
                    format!(
                        "{} '{}': field '{}' was removed. Backwards compatibility is broken.",
                        msg_prefix, name, old_name
                    ),
                    class,
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: Some(class),
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
                category: "Struct Field Reordered".to_string(),
                message: with_heuristic_note(
                    format!(
                        "{} '{}': field at position {} changed from '{}' to '{}'. \
                         Positional serialization breaks layout compatibility.",
                        msg_prefix, name, i, old_name, new_name
                    ),
                    class,
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: Some(class),
            });
        }

        // Field type changed
        if !types_equal(&old_field.type_, &new_field.type_) {
            let base_message = with_heuristic_note(
                format!(
                    "{} '{}': field '{}' (position {}) type changed from `{}` to `{}`.",
                    msg_prefix,
                    name,
                    old_name,
                    i,
                    crate::mapper::type_to_string(&old_field.type_),
                    crate::mapper::type_to_string(&new_field.type_)
                ),
                class,
            );
            push_type_change_finding(
                report,
                &old_field.type_,
                &new_field.type_,
                "Struct Field Type",
                base_message,
                Some(name.to_string()),
                Some(format!("{}.{}", name, old_name)),
                Some(class),
            );
        }

        // Field documentation changed
        push_doc_finding(
            report,
            "Struct Field Documentation Changed",
            &format!("Struct '{}': field '{}'", name, old_name),
            &old_field.doc.to_string(),
            &new_field.doc.to_string(),
            Some(name.to_string()),
            Some(format!("{}.{}", name, old_name)),
            Some(class),
        );
    }

    // Check for new fields appended at the end
    if new_fields.len() > old_fields.len() {
        for new_field in &new_fields[old_fields.len()..] {
            report.findings.push(Finding {
                severity: Severity::Warning,
                category: "Struct Field Added".to_string(),
                message: format!(
                    "{} '{}': new field '{}' appended. \
                     Existing storage entries won't have this field — ensure migration handles defaults.",
                    msg_prefix,
                    name,
                    new_field.name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, new_field.name)),
                classification: Some(class),
            });
        }
    }
}

/// Compare enum definitions between old and new contract specs.
fn compare_enums(
    old: &ContractSpec,
    new: &ContractSpec,
    classification: &ClassificationConfig,
    report: &mut DiffReport,
) {
    // 1. Enums present in both specs (same name): compare in place.
    for (name, old_enum) in &old.enums {
        if let Some(new_enum) = new.enums.get(name) {
            let class = classification.classify(name);
            check_enum_cases(name, old_enum, new_enum, class, report);
            // Compare enum doc-strings (informational only)
            push_doc_finding(
                report,
                "Enum Documentation Changed",
                &format!("Enum '{}'", name),
                &old_enum.doc.to_string(),
                &new_enum.doc.to_string(),
                Some(name.clone()),
                Some(name.clone()),
                Some(class),
            );
        }
    }

    // 2. Names on only one side: try to pair them up as renames first.
    let removed: BTreeMap<String, &ScSpecUdtEnumV0> = old
        .enums
        .iter()
        .filter(|(n, _)| !new.enums.contains_key(*n))
        .map(|(n, e)| (n.clone(), e))
        .collect();
    let added: BTreeMap<String, &ScSpecUdtEnumV0> = new
        .enums
        .iter()
        .filter(|(n, _)| !old.enums.contains_key(*n))
        .map(|(n, e)| (n.clone(), e))
        .collect();

    let renames = match_renames(&removed, &added);
    let (renamed_old, renamed_new) = rename_name_sets(&renames);

    for rename in &renames {
        let old_enum = removed[&rename.old_name];
        let new_enum = added[&rename.new_name];
        let class = classification.classify(&rename.new_name);
        emit_rename_finding(rename, "enum", class, report);
        if !rename.identical {
            check_enum_cases(&rename.new_name, old_enum, new_enum, class, report);
        }
    }

    // 3. Genuinely removed enums.
    for name in removed.keys() {
        if renamed_old.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        let noun = type_noun(class, "Enum", "Event enum");
        let message = with_heuristic_note(
            format!(
                "{} '{}' was removed. Data using this type will be invalid.",
                noun, name
            ),
            class,
        );
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Enum Removed".to_string(),
            message,
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }

    // 4. Genuinely added enums.
    for name in added.keys() {
        if renamed_new.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        report.findings.push(Finding {
            severity: Severity::Info,
            category: "Enum Added".to_string(),
            message: format!("New enum '{}' added.", name),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }
}

/// Compare cases of two enums with the same name.
///
/// `class` affects only the message wording and per-finding metadata; the
/// structural `category` never varies with classification.
fn check_enum_cases(
    name: &str,
    old_enum: &ScSpecUdtEnumV0,
    new_enum: &ScSpecUdtEnumV0,
    class: TypeClass,
    report: &mut DiffReport,
) {
    let msg_prefix = type_noun(class, "Enum", "Event enum");
    let old_cases: &[ScSpecUdtEnumCaseV0] = old_enum.cases.as_ref();
    let new_cases: &[ScSpecUdtEnumCaseV0] = new_enum.cases.as_ref();

    for old_case in old_cases {
        let old_name = old_case.name.to_string();

        match new_cases.iter().find(|c| c.name.to_string() == old_name) {
            None => {
                // The case was removed entirely
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Enum Case Removed".to_string(),
                    message: with_heuristic_note(
                        format!(
                            "{} '{}': case '{}' (value: {}) was removed. \
                             On-chain data or events relying on this value will be invalid.",
                            msg_prefix, name, old_name, old_case.value
                        ),
                        class,
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                    classification: Some(class),
                });
            }
            Some(new_case) => {
                // The case exists, but did its integer value change?
                if old_case.value != new_case.value {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        category: "Enum Case Value Changed".to_string(),
                        message: with_heuristic_note(
                            format!(
                                "{} '{}': case '{}' value changed from {} to {}. \
                                 This breaks data serialization.",
                                msg_prefix, name, old_name, old_case.value, new_case.value
                            ),
                            class,
                        ),
                        type_name: Some(name.to_string()),
                        target: Some(format!("{}.{}", name, old_name)),
                        classification: Some(class),
                    });
                }

                push_doc_finding(
                    report,
                    "Enum Case Documentation Changed",
                    &format!("Enum '{}': case '{}'", name, old_name),
                    &old_case.doc.to_string(),
                    &new_case.doc.to_string(),
                    Some(name.to_string()),
                    Some(format!("{}.{}", name, old_name)),
                    Some(class),
                );
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
                    category: "Enum Case Added".to_string(),
                    message: format!(
                        "{} '{}': new case '{}' (value {}) added.",
                        msg_prefix, name, new_name, new_case.value
                    ),
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, new_name)),
                    classification: Some(class),
                });
            }
        }
    }
}

/// Compare union definitions between old and new contract specs.
fn compare_unions(
    old: &ContractSpec,
    new: &ContractSpec,
    classification: &ClassificationConfig,
    report: &mut DiffReport,
) {
    // 1. Same-name unions: compare in place.
    for (name, old_union) in &old.unions {
        if let Some(new_union) = new.unions.get(name) {
            check_union_cases(name, old_union, new_union, report);
            let class = classification.classify(name);
            push_doc_finding(
                report,
                "Union Documentation Changed",
                &format!("Union '{}'", name),
                &old_union.doc.to_string(),
                &new_union.doc.to_string(),
                Some(name.clone()),
                Some(name.clone()),
                Some(class),
            );
        }
    }

    // 2. One-sided names: pair renames before reporting delete/add.
    let removed: BTreeMap<String, &ScSpecUdtUnionV0> = old
        .unions
        .iter()
        .filter(|(n, _)| !new.unions.contains_key(*n))
        .map(|(n, u)| (n.clone(), u))
        .collect();
    let added: BTreeMap<String, &ScSpecUdtUnionV0> = new
        .unions
        .iter()
        .filter(|(n, _)| !old.unions.contains_key(*n))
        .map(|(n, u)| (n.clone(), u))
        .collect();

    let renames = match_renames(&removed, &added);
    let (renamed_old, renamed_new) = rename_name_sets(&renames);

    for rename in &renames {
        let class = classification.classify(&rename.new_name);
        emit_rename_finding(rename, "union", class, report);
        if !rename.identical {
            check_union_cases(
                &rename.new_name,
                removed[&rename.old_name],
                added[&rename.new_name],
                report,
            );
        }
    }

    // 3. Genuinely removed unions.
    for name in removed.keys() {
        if renamed_old.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Union Removed".to_string(),
            message: format!(
                "Union '{}' was removed. Data using this type will be invalid.",
                name
            ),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
    }

    // 4. Genuinely added unions.
    for name in added.keys() {
        if renamed_new.contains(name.as_str()) {
            continue;
        }
        let class = classification.classify(name);
        report.findings.push(Finding {
            severity: Severity::Info,
            category: "Union Added".to_string(),
            message: format!("New union '{}' added.", name),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: Some(class),
        });
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
                severity: Severity::Critical,
                category: "Union Case Removed".to_string(),
                message: format!(
                    "Union '{}': case '{}' was removed. Backwards compatibility is broken.",
                    name, old_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: None,
            });
        }
    }

    for (i, (old_case, new_case)) in old_cases.iter().zip(new_cases.iter()).enumerate() {
        let old_name = union_case_name(old_case);
        let new_name = union_case_name(new_case);

        if old_name != new_name {
            report.findings.push(Finding {
                severity: Severity::Critical,
                category: "Union Case Reordered".to_string(),
                message: format!(
                    "Union '{}': case at position {} changed from '{}' to '{}'. \
                     Positional discriminant breaks layout compatibility.",
                    name, i, old_name, new_name
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, old_name)),
                classification: None,
            });
        }

        if !union_cases_equal(old_case, new_case) {
            let base_message = format!(
                "Union '{}': case '{}' (position {}) type changed from `{}` to `{}`.",
                name,
                old_name,
                i,
                union_case_type_signature(old_case),
                union_case_type_signature(new_case)
            );
            // Numeric classification only applies when both sides are a
            // single-value payload — a multi-value tuple change doesn't map
            // onto a single old-type/new-type pair.
            match (
                union_case_single_type(old_case),
                union_case_single_type(new_case),
            ) {
                (Some(old_ty), Some(new_ty)) => push_type_change_finding(
                    report,
                    old_ty,
                    new_ty,
                    "Union Case Type",
                    base_message,
                    Some(name.to_string()),
                    Some(format!("{}.{}", name, old_name)),
                    None,
                ),
                _ => report.findings.push(Finding {
                    severity: Severity::Critical,
                    category: "Union Case Type Changed".to_string(),
                    message: base_message,
                    type_name: Some(name.to_string()),
                    target: Some(format!("{}.{}", name, old_name)),
                    classification: None,
                }),
            }
        }
    }

    if new_cases.len() > old_cases.len() {
        for new_case in &new_cases[old_cases.len()..] {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Union Case Added".to_string(),
                message: format!(
                    "Union '{}': new case '{}' ({}) added.",
                    name,
                    union_case_name(new_case),
                    union_case_type_signature(new_case)
                ),
                type_name: Some(name.to_string()),
                target: Some(format!("{}.{}", name, union_case_name(new_case))),
                classification: None,
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

/// The single payload type of a union case, when it carries exactly one
/// value (e.g. `Deposit(u64)`). `None` for a void case or a multi-value tuple
/// case, where a type change can't be expressed as a single old/new pair.
fn union_case_single_type(case: &ScSpecUdtUnionCaseV0) -> Option<&ScSpecTypeDef> {
    match case {
        ScSpecUdtUnionCaseV0::VoidV0(_) => None,
        ScSpecUdtUnionCaseV0::TupleV0(t) => {
            let types: &[ScSpecTypeDef] = t.type_.as_ref();
            match types {
                [only] => Some(only),
                _ => None,
            }
        }
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
///
/// Error enums are never classified as events, so their findings carry
/// `classification: None`. Rename detection still applies: an error enum
/// renamed with an identical set of `name=value` cases is reported as a rename.
fn compare_error_enums(
    old: &ContractSpec,
    new: &ContractSpec,
    _classification: &ClassificationConfig,
    report: &mut DiffReport,
) {
    // 1. Same name on both sides: compare cases.
    for (name, old_error_enum) in &old.error_enums {
        if let Some(new_error_enum) = new.error_enums.get(name) {
            check_error_enum_cases(name, old_error_enum, new_error_enum, report);
            // Error enums are never classified as events (see module docs above).
            push_doc_finding(
                report,
                "Error Enum Documentation Changed",
                &format!("Error enum '{}'", name),
                &old_error_enum.doc.to_string(),
                &new_error_enum.doc.to_string(),
                Some(name.clone()),
                Some(name.clone()),
                None,
            );
        }
    }

    // 2. One-sided names: detect renames before reporting removed/added.
    let removed: BTreeMap<String, &ScSpecUdtErrorEnumV0> = old
        .error_enums
        .iter()
        .filter(|(n, _)| !new.error_enums.contains_key(*n))
        .map(|(n, e)| (n.clone(), e))
        .collect();
    let added: BTreeMap<String, &ScSpecUdtErrorEnumV0> = new
        .error_enums
        .iter()
        .filter(|(n, _)| !old.error_enums.contains_key(*n))
        .map(|(n, e)| (n.clone(), e))
        .collect();

    let renames = match_renames(&removed, &added);
    let (renamed_old, renamed_new) = rename_name_sets(&renames);

    for rename in &renames {
        emit_rename_finding(rename, "error enum", TypeClass::Storage, report);
        if !rename.identical {
            check_error_enum_cases(
                &rename.new_name,
                removed[&rename.old_name],
                added[&rename.new_name],
                report,
            );
        }
    }

    // 3. Genuinely removed error enums.
    for name in removed.keys() {
        if renamed_old.contains(name.as_str()) {
            continue;
        }
        report.findings.push(Finding {
            severity: Severity::Critical,
            category: "Error Enum Removed".to_string(),
            message: format!(
                "Error enum '{}' was removed. Clients matching on these errors will break.",
                name
            ),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: None,
        });
    }

    // 4. Genuinely added error enums.
    for name in added.keys() {
        if renamed_new.contains(name.as_str()) {
            continue;
        }
        report.findings.push(Finding {
            severity: Severity::Info,
            category: "Error Enum Added".to_string(),
            message: format!("New error enum '{}' added.", name),
            type_name: Some(name.clone()),
            target: Some(name.clone()),
            classification: None,
        });
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
                    classification: None,
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
                    classification: None,
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
                classification: None,
            });
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
                            "Type '{}' layout is broken because it embeds modified type '{}'. \
                             Stored data for '{}' is no longer compatible.",
                            dep, current_broken_type, dep
                        ),
                        type_name: Some(dep.clone()),
                        target: Some(dep.clone()),
                        classification: None,
                    });
                }
            }
        }
    }
}

/// Policy-aware variant of [`detect_cascading_layout_breaks`].
///
/// Uses [`crate::mapper::LayoutMapper::new_with_policy`] so the walk is bounded
/// by `policy.max_walk_depth`. Returns a [`crate::limits::LimitError`] if the
/// type graph is deeper than the configured limit.
fn detect_cascading_layout_breaks_with_policy(
    old: &ContractSpec,
    report: &mut DiffReport,
    policy: &crate::limits::ResourcePolicy,
) -> Result<(), crate::limits::LimitError> {
    let old_mapper = LayoutMapper::new_with_policy(old, policy);
    let reverse_deps = old_mapper.try_build_reverse_dependencies()?;

    let mut broken_types = std::collections::HashSet::new();
    for finding in &report.findings {
        if finding.severity == Severity::Critical {
            if let Some(ref name) = finding.type_name {
                broken_types.insert(name.clone());
            }
        }
    }

    let mut queue: Vec<String> = broken_types.into_iter().collect();
    let mut i = 0;
    let mut cascaded = std::collections::HashSet::new();

    while i < queue.len() {
        let current_broken_type = queue[i].clone();
        i += 1;

        if let Some(dependents) = reverse_deps.get(&current_broken_type) {
            for dep in dependents {
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
                        classification: None,
                    });
                }
            }
        }
    }
    Ok(())
}

pub fn compare_wasm_imports(
    old_imports: &[(String, String)],
    new_imports: &[(String, String)],
    report: &mut DiffReport,
) {
    use std::collections::BTreeSet;

    let old_set: BTreeSet<(&str, &str)> = old_imports.iter().map(|(m, n)| (m.as_str(), n.as_str())).collect();
    let new_set: BTreeSet<(&str, &str)> = new_imports.iter().map(|(m, n)| (m.as_str(), n.as_str())).collect();

    // Newly required host functions (in new, not in old)
    for (module, name) in &new_set {
        if !old_set.contains(&(module, name)) {
            report.findings.push(Finding {
                severity: Severity::Warning,
                category: "Host Import Added".to_string(),
                message: format!(
                    "New host function import '{}.{}' required by the new build. \
                     The network must provide this function; deploying to an older protocol \
                     that does not support it will cause a runtime trap.",
                    module, name
                ),
                type_name: None,
                target: Some(format!("{}.{}", module, name)),
                classification: None,
            });
        }
    }

    // Removed host functions (in old, not in new)
    for (module, name) in &old_set {
        if !new_set.contains(&(module, name)) {
            report.findings.push(Finding {
                severity: Severity::Info,
                category: "Host Import Removed".to_string(),
                message: format!(
                    "Host function import '{}.{}' is no longer required by the new build. \
                     This relaxes the environment requirement.",
                    module, name
                ),
                type_name: None,
                target: Some(format!("{}.{}", module, name)),
                classification: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashSet};
    use stellar_xdr::curr::{ScEnvMetaEntry, ScMetaEntry, ScMetaV0, ScSpecTypeUdt, StringM, VecM};

    #[test]
    fn exported_functions_detect_removals_additions_and_spec_mismatches() {
        let old_exports = BTreeSet::from(["legacy".to_string(), "old_only".to_string()]);
        let new_exports = BTreeSet::from(["legacy".to_string(), "new_only".to_string()]);
        let old_spec = HashSet::from(["legacy".to_string(), "declared_only_old".to_string()]);
        let new_spec = HashSet::from(["legacy".to_string(), "declared_only_new".to_string()]);
        let mut report = DiffReport::default();

        compare_exports(
            &old_exports,
            &new_exports,
            &old_spec,
            &new_spec,
            &mut report,
        );

        assert!(report.findings.iter().any(|finding| {
            finding.category == "Export Removed"
                && finding.target.as_deref() == Some("old_only")
                && finding.severity == Severity::Critical
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.category == "Export Added"
                && finding.target.as_deref() == Some("new_only")
                && finding.severity == Severity::Info
        }));
        for target in [
            "declared_only_old",
            "old_only",
            "declared_only_new",
            "new_only",
        ] {
            assert!(report.findings.iter().any(|finding| {
                finding.category == "Export Spec Mismatch"
                    && finding.target.as_deref() == Some(target)
            }));
        }
    }

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
            ("Inner", vec![("value", ScSpecTypeDef::Bool)]),
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
            classification: None,
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
            classification: None,
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
            ("Leaf", vec![("x", ScSpecTypeDef::Bool)]), // break
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
        let new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::Bool)])]);

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

    fn contract_meta(pairs: &[(&str, &str)]) -> ContractMeta {
        ContractMeta {
            entries: pairs
                .iter()
                .map(|&(k, v)| {
                    ScMetaEntry::ScMetaV0(ScMetaV0 {
                        key: k.try_into().unwrap(),
                        val: v.try_into().unwrap(),
                    })
                })
                .collect(),
        }
    }

    #[test]
    fn meta_sdk_version_change_is_warning() {
        let old = contract_meta(&[("rssdkver", "21.6.0"), ("rsver", "1.79.0")]);
        let new = contract_meta(&[("rssdkver", "22.0.0"), ("rsver", "1.79.0")]);
        let mut report = DiffReport::default();
        compare_contract_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.category, "Metadata SDK Version Changed");
        assert!(f.message.contains("Soroban SDK version"));
    }

    #[test]
    fn meta_compiler_version_change_is_warning() {
        let old = contract_meta(&[("rsver", "1.79.0")]);
        let new = contract_meta(&[("rsver", "1.80.0")]);
        let mut report = DiffReport::default();
        compare_contract_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.category, "Metadata Compiler Version Changed");
        assert!(f.message.contains("Rust compiler version"));
    }

    #[test]
    fn meta_generic_key_added_is_info() {
        let old = contract_meta(&[]);
        let new = contract_meta(&[("author", "acme")]);
        let mut report = DiffReport::default();
        compare_contract_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.category, "Metadata Key Added");
        assert_eq!(f.target.as_deref(), Some("author"));
    }

    #[test]
    fn meta_generic_key_removed_is_info() {
        let old = contract_meta(&[("author", "acme")]);
        let new = contract_meta(&[]);
        let mut report = DiffReport::default();
        compare_contract_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.category, "Metadata Key Removed");
        assert_eq!(f.target.as_deref(), Some("author"));
    }

    #[test]
    fn meta_generic_key_changed_is_info() {
        let old = contract_meta(&[("author", "acme")]);
        let new = contract_meta(&[("author", "globex")]);
        let mut report = DiffReport::default();
        compare_contract_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.category, "Metadata Key Changed");
        assert!(f.message.contains("globex"));
    }

    #[test]
    fn meta_version_and_generic_are_distinct_findings() {
        // Version bumps and author-key changes are graded differently and must
        // not collapse into one finding.
        let old = contract_meta(&[("rssdkver", "21.6.0"), ("author", "acme")]);
        let new = contract_meta(&[("rssdkver", "22.0.0"), ("author", "globex")]);
        let mut report = DiffReport::default();
        compare_contract_metadata(Some(&old), Some(&new), &mut report);

        assert_eq!(report.findings.len(), 2);
        assert!(report.findings.iter().any(
            |f| f.category == "Metadata SDK Version Changed" && f.severity == Severity::Warning
        ));
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Metadata Key Changed" && f.severity == Severity::Info));
    }

    #[test]
    fn meta_absent_in_both_produces_no_finding() {
        let mut report = DiffReport::default();
        compare_contract_metadata(None, None, &mut report);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn meta_identical_produces_no_finding() {
        let meta = contract_meta(&[("rssdkver", "21.6.0"), ("author", "acme")]);
        let mut report = DiffReport::default();
        compare_contract_metadata(Some(&meta), Some(&meta), &mut report);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn meta_findings_do_not_affect_is_safe() {
        let old = contract_meta(&[("rssdkver", "21.6.0")]);
        let new = contract_meta(&[("rssdkver", "22.0.0")]);
        let mut report = DiffReport::default();
        compare_contract_metadata(Some(&old), Some(&new), &mut report);

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
    // Numeric widening / narrowing / signedness classification
    // ---------------------------------------------------------------

    #[test]
    fn numeric_classification_widening_same_signedness() {
        assert!(matches!(
            classify_numeric_type_change(&ScSpecTypeDef::U32, &ScSpecTypeDef::U64),
            Some(NumericChangeKind::Widened)
        ));
        assert!(matches!(
            classify_numeric_type_change(&ScSpecTypeDef::I32, &ScSpecTypeDef::I128),
            Some(NumericChangeKind::Widened)
        ));
    }

    #[test]
    fn numeric_classification_widening_across_signedness() {
        // u64 -> i128: every u64 value fits in i128, so this is a safe widening
        // even though signedness differs.
        assert!(matches!(
            classify_numeric_type_change(&ScSpecTypeDef::U64, &ScSpecTypeDef::I128),
            Some(NumericChangeKind::Widened)
        ));
    }

    #[test]
    fn numeric_classification_narrowing_same_signedness() {
        assert!(matches!(
            classify_numeric_type_change(&ScSpecTypeDef::U64, &ScSpecTypeDef::U32),
            Some(NumericChangeKind::Narrowed)
        ));
    }

    #[test]
    fn numeric_classification_signedness_changed() {
        // Same width, sign flip: reinterprets the bit pattern.
        assert!(matches!(
            classify_numeric_type_change(&ScSpecTypeDef::U32, &ScSpecTypeDef::I32),
            Some(NumericChangeKind::SignednessChanged)
        ));
        // signed -> unsigned can never safely widen: negative values have no
        // unsigned representation.
        assert!(matches!(
            classify_numeric_type_change(&ScSpecTypeDef::I64, &ScSpecTypeDef::U64),
            Some(NumericChangeKind::SignednessChanged)
        ));
        assert!(matches!(
            classify_numeric_type_change(&ScSpecTypeDef::I64, &ScSpecTypeDef::U32),
            Some(NumericChangeKind::SignednessChanged)
        ));
    }

    #[test]
    fn numeric_classification_none_for_non_numeric_types() {
        assert!(classify_numeric_type_change(&ScSpecTypeDef::U32, &ScSpecTypeDef::Bool).is_none());
        assert!(classify_numeric_type_change(&ScSpecTypeDef::Bool, &ScSpecTypeDef::Void).is_none());
    }

    #[test]
    fn struct_field_widening_is_warning_not_critical() {
        let old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U64)])]);
        let report = compare(&old, &new);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Widened")
            .expect("expected a Struct Field Type Widened finding");
        assert_eq!(finding.severity, Severity::Warning);
        assert!(finding.message.contains("widening"));

        assert!(!report
            .findings
            .iter()
            .any(|f| f.category == "Struct Field Type Changed"));
    }

    #[test]
    fn struct_field_narrowing_is_critical() {
        let old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U64)])]);
        let new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let report = compare(&old, &new);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Narrowed")
            .expect("expected a Struct Field Type Narrowed finding");
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.message.contains("truncat"));
    }

    #[test]
    fn struct_field_signedness_change_is_critical() {
        let old = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::U32)])]);
        let new = spec_with_structs(vec![("Data", vec![("amount", ScSpecTypeDef::I32)])]);
        let report = compare(&old, &new);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Signedness Changed")
            .expect("expected a Struct Field Type Signedness Changed finding");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn struct_field_non_numeric_type_change_is_unaffected() {
        let old = spec_with_structs(vec![("Data", vec![("flag", ScSpecTypeDef::U32)])]);
        let new = spec_with_structs(vec![("Data", vec![("flag", ScSpecTypeDef::Bool)])]);
        let report = compare(&old, &new);

        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Type Changed")
            .expect("non-numeric changes must keep the original category");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn parameter_widening_and_return_type_narrowing_are_classified() {
        let old = spec_with_functions(vec![("transfer", vec![("amount", ScSpecTypeDef::U32)])]);
        let new = spec_with_functions(vec![("transfer", vec![("amount", ScSpecTypeDef::U64)])]);
        let report = compare(&old, &new);
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "Parameter Type Widened" && f.severity == Severity::Warning));

        let mut old_fn = spec_with_functions(vec![("get_balance", vec![])]);
        let mut new_fn = spec_with_functions(vec![("get_balance", vec![])]);
        old_fn.functions.get_mut("get_balance").unwrap().outputs =
            VecM::try_from(vec![ScSpecTypeDef::U64]).unwrap();
        new_fn.functions.get_mut("get_balance").unwrap().outputs =
            VecM::try_from(vec![ScSpecTypeDef::U32]).unwrap();
        let report2 = compare(&old_fn, &new_fn);
        assert!(report2
            .findings
            .iter()
            .any(|f| f.category == "Return Type Narrowed" && f.severity == Severity::Critical));
    }

    // ---------------------------------------------------------------
    // Documentation changes on unions, error enums, and members
    // ---------------------------------------------------------------

    fn union_with_case(
        union_name: &str,
        case_name: &str,
        doc: &str,
        types: Vec<ScSpecTypeDef>,
    ) -> ScSpecUdtUnionV0 {
        ScSpecUdtUnionV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: union_name.try_into().unwrap(),
            cases: VecM::try_from(vec![ScSpecUdtUnionCaseV0::TupleV0(
                stellar_xdr::curr::ScSpecUdtUnionCaseTupleV0 {
                    doc: StringM::default(),
                    name: case_name.try_into().unwrap(),
                    type_: VecM::try_from(types).unwrap(),
                },
            )])
            .unwrap(),
        }
    }

    #[test]
    fn union_documentation_change_produces_info_finding() {
        let mut old = ContractSpec::default();
        old.unions.insert(
            "Event".to_string(),
            union_with_case("Event", "Deposit", "", vec![ScSpecTypeDef::U64]),
        );
        let mut new = ContractSpec::default();
        new.unions.insert(
            "Event".to_string(),
            union_with_case("Event", "Deposit", "records a deposit", vec![ScSpecTypeDef::U64]),
        );

        let report = compare(&old, &new);
        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Union Documentation Changed")
            .expect("expected a Union Documentation Changed finding");
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.message.contains("was added"));
    }

    #[test]
    fn union_case_widening_is_classified() {
        let mut old = ContractSpec::default();
        old.unions.insert(
            "Event".to_string(),
            union_with_case("Event", "Deposit", "", vec![ScSpecTypeDef::U32]),
        );
        let mut new = ContractSpec::default();
        new.unions.insert(
            "Event".to_string(),
            union_with_case("Event", "Deposit", "", vec![ScSpecTypeDef::U64]),
        );

        let report = compare(&old, &new);
        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Union Case Type Widened")
            .expect("expected a Union Case Type Widened finding");
        assert_eq!(finding.severity, Severity::Warning);
    }

    fn error_enum_with_case(name: &str, case_name: &str, doc: &str) -> ScSpecUdtErrorEnumV0 {
        ScSpecUdtErrorEnumV0 {
            doc: doc.try_into().unwrap(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            cases: VecM::try_from(vec![ScSpecUdtErrorEnumCaseV0 {
                doc: StringM::default(),
                name: case_name.try_into().unwrap(),
                value: 1,
            }])
            .unwrap(),
        }
    }

    #[test]
    fn error_enum_documentation_change_produces_info_finding() {
        let mut old = ContractSpec::default();
        old.error_enums
            .insert("Error".to_string(), error_enum_with_case("Error", "NotFound", "old doc"));
        let mut new = ContractSpec::default();
        new.error_enums
            .insert("Error".to_string(), error_enum_with_case("Error", "NotFound", "new doc"));

        let report = compare(&old, &new);
        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Error Enum Documentation Changed")
            .expect("expected an Error Enum Documentation Changed finding");
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.message.contains("changed"));
        assert!(finding.classification.is_none());
    }

    #[test]
    fn struct_field_documentation_change_produces_targeted_info_finding() {
        let mut old = ContractSpec::default();
        old.structs.insert(
            "Data".to_string(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Data".try_into().unwrap(),
                fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
                    doc: "old doc".try_into().unwrap(),
                    name: "amount".try_into().unwrap(),
                    type_: ScSpecTypeDef::U64,
                }])
                .unwrap(),
            },
        );
        let mut new = ContractSpec::default();
        new.structs.insert(
            "Data".to_string(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Data".try_into().unwrap(),
                fields: VecM::try_from(vec![ScSpecUdtStructFieldV0 {
                    doc: "amount in stroops".try_into().unwrap(),
                    name: "amount".try_into().unwrap(),
                    type_: ScSpecTypeDef::U64,
                }])
                .unwrap(),
            },
        );

        let report = compare(&old, &new);
        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Struct Field Documentation Changed")
            .expect("expected a Struct Field Documentation Changed finding");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.target.as_deref(), Some("Data.amount"));
    }

    /// Helper: build a single-function ContractSpec with an explicit doc on
    /// its one parameter.
    fn spec_with_function_param_doc(fn_name: &str, param_name: &str, doc: &str) -> ContractSpec {
        let mut spec = ContractSpec::default();
        spec.functions.insert(
            fn_name.to_string(),
            stellar_xdr::curr::ScSpecFunctionV0 {
                doc: StringM::default(),
                name: fn_name.try_into().unwrap(),
                inputs: VecM::try_from(vec![stellar_xdr::curr::ScSpecFunctionInputV0 {
                    doc: doc.try_into().unwrap(),
                    name: param_name.try_into().unwrap(),
                    type_: ScSpecTypeDef::Address,
                }])
                .unwrap(),
                outputs: VecM::default(),
            },
        );
        spec
    }

    #[test]
    fn parameter_documentation_change_produces_targeted_info_finding() {
        let old = spec_with_function_param_doc("transfer", "to", "old");
        let new = spec_with_function_param_doc("transfer", "to", "recipient address");

        let report = compare(&old, &new);
        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Parameter Documentation Changed")
            .expect("expected a Parameter Documentation Changed finding");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.target.as_deref(), Some("transfer.to"));
    }

    #[test]
    fn enum_case_documentation_change_produces_targeted_info_finding() {
        let mut old = ContractSpec::default();
        old.enums.insert(
            "Status".to_string(),
            ScSpecUdtEnumV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Status".try_into().unwrap(),
                cases: VecM::try_from(vec![ScSpecUdtEnumCaseV0 {
                    doc: StringM::default(),
                    name: "Active".try_into().unwrap(),
                    value: 0,
                }])
                .unwrap(),
            },
        );
        let mut new = ContractSpec::default();
        new.enums.insert(
            "Status".to_string(),
            ScSpecUdtEnumV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Status".try_into().unwrap(),
                cases: VecM::try_from(vec![ScSpecUdtEnumCaseV0 {
                    doc: "entity is active".try_into().unwrap(),
                    name: "Active".try_into().unwrap(),
                    value: 0,
                }])
                .unwrap(),
            },
        );

        let report = compare(&old, &new);
        let finding = report
            .findings
            .iter()
            .find(|f| f.category == "Enum Case Documentation Changed")
            .expect("expected an Enum Case Documentation Changed finding");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.target.as_deref(), Some("Status.Active"));
    }

    #[test]
    fn doc_findings_never_affect_is_safe() {
        let old = spec_with_function_param_doc("transfer", "to", "old");
        let new = spec_with_function_param_doc("transfer", "to", "new");

        let report = compare(&old, &new);
        let safety = crate::report::SafetyReport::new(&report);
        assert!(safety.is_safe);
        assert_eq!(safety.critical_count, 0);
    }
}

//! Single-artifact contract spec lint: graph and schema integrity checks.
//!
//! [`crate::diff`] validates that two builds are *compatible with each
//! other*. This module validates that **one** decoded [`ContractSpec`] (and,
//! optionally, its declared storage schema) is internally well-formed and
//! safely analyzable in isolation, before it is ever used as an upgrade
//! baseline.
//!
//! Lint findings intentionally use a separate rule-ID namespace and severity
//! scale from [`crate::diff::Finding`]/[`crate::category::FindingCategory`]:
//! they describe the validity of one artifact, not a change between two
//! artifacts, and are never mixed into a [`crate::diff::DiffReport`].
//!
//! Where possible this module *reuses* existing single-artifact analysis
//! rather than re-implementing it:
//! - Duplicate-name detection reuses [`ContractSpec::duplicate_declarations`]
//!   (the same first-wins semantics as [`ContractSpec::from_entries`]).
//! - Type-reference-graph traversal reuses [`crate::mapper::LayoutMapper`].
//! - Resource bounds reuse [`crate::limits::ResourcePolicy`].
//! - Storage schema structural validation reuses
//!   [`crate::storage_schema::StorageSchema::validate`], and evidence-based
//!   reconciliation reuses [`crate::storage_schema::StorageSchema::reconcile`].

use std::collections::{BTreeSet, HashSet};

use serde::Serialize;
use stellar_xdr::curr::{ScSpecEntry, ScSpecTypeDef, ScSpecUdtUnionCaseV0};

use crate::limits::ResourcePolicy;
use crate::mapper::LayoutMapper;
use crate::spec::ContractSpec;
use crate::storage_inference::StorageInference;
use crate::storage_schema::{SchemaMismatch, StorageSchema};

// ── Rule identity ────────────────────────────────────────────────────────────

/// Stable identifier for a lint rule.
///
/// [`LintRuleId::as_str`] is the value that appears in structured output and
/// documentation; it is a committed, stable string and must never change for
/// an existing variant once released (add a new variant instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LintRuleId {
    /// Same name declared more than once for the same entry kind.
    DuplicateDeclaration,
    /// Same name declared for more than one entry kind (e.g. both a struct
    /// and an enum named `Token`).
    CrossKindNameCollision,
    /// Two cases of the same enum/union/error-enum share a name.
    DuplicateCaseName,
    /// Two cases of the same enum/error-enum share a discriminant value.
    ConflictingDiscriminant,
    /// A field, case, or signature references a UDT name that is not
    /// declared anywhere in the spec.
    DanglingTypeReference,
    /// A struct/enum/union is declared but never reachable from any exported
    /// function's inputs/outputs.
    UnreachableDeclaration,
    /// A type nests containers deeper than the configured walk-depth limit,
    /// so it cannot be safely analyzed (equality, rendering, diffing).
    UnanalyzableRecursiveShape,
    /// The same name is declared with different `lib` origin metadata across
    /// kinds, so its true source library is ambiguous.
    InconsistentOrigin,
    /// The optional storage schema file itself is structurally invalid.
    StorageSchemaInvalid,
    /// The declared storage schema disagrees with inferred storage evidence.
    StorageSchemaMismatch,
}

impl LintRuleId {
    /// The stable rule ID string used in output and documentation.
    pub fn as_str(self) -> &'static str {
        match self {
            LintRuleId::DuplicateDeclaration => "duplicate-declaration",
            LintRuleId::CrossKindNameCollision => "cross-kind-name-collision",
            LintRuleId::DuplicateCaseName => "duplicate-case-name",
            LintRuleId::ConflictingDiscriminant => "conflicting-discriminant",
            LintRuleId::DanglingTypeReference => "dangling-type-reference",
            LintRuleId::UnreachableDeclaration => "unreachable-declaration",
            LintRuleId::UnanalyzableRecursiveShape => "unanalyzable-recursive-shape",
            LintRuleId::InconsistentOrigin => "inconsistent-origin",
            LintRuleId::StorageSchemaInvalid => "storage-schema-invalid",
            LintRuleId::StorageSchemaMismatch => "storage-schema-mismatch",
        }
    }

    /// The severity a finding for this rule has when nothing overrides it.
    ///
    /// `Error` rules mean the artifact is structurally broken (ambiguous
    /// wire identity, missing type, invalid config). `Warning` rules mean
    /// the artifact is valid but risky or only partially analyzable.
    /// `Info` rules are maintainability observations that never fail a lint
    /// run on their own.
    pub fn default_severity(self) -> LintSeverity {
        match self {
            LintRuleId::DuplicateDeclaration
            | LintRuleId::CrossKindNameCollision
            | LintRuleId::ConflictingDiscriminant
            | LintRuleId::DanglingTypeReference
            | LintRuleId::StorageSchemaInvalid => LintSeverity::Error,
            LintRuleId::DuplicateCaseName
            | LintRuleId::UnanalyzableRecursiveShape
            | LintRuleId::StorageSchemaMismatch => LintSeverity::Warning,
            LintRuleId::UnreachableDeclaration | LintRuleId::InconsistentOrigin => {
                LintSeverity::Info
            }
        }
    }

    /// Short, generic remediation guidance for this rule.
    pub fn remediation(self) -> &'static str {
        match self {
            LintRuleId::DuplicateDeclaration => {
                "Rename or remove one of the conflicting declarations. \
                 Only the first occurrence is kept; the rest are silently dropped."
            }
            LintRuleId::CrossKindNameCollision => {
                "Rename one of the declarations so the same identifier is not \
                 reused across a struct, enum, union, or error enum."
            }
            LintRuleId::DuplicateCaseName => {
                "Rename the duplicate case so every case in this type has a unique name."
            }
            LintRuleId::ConflictingDiscriminant => {
                "Assign each case a unique discriminant value; the decoded \
                 value determines wire identity and ambiguous values make \
                 decoding non-deterministic."
            }
            LintRuleId::DanglingTypeReference => {
                "Define the missing type, or remove the field/parameter/case \
                 that references it."
            }
            LintRuleId::UnreachableDeclaration => {
                "Reference this type from an exported function's inputs or \
                 outputs, or remove it if it is genuinely unused."
            }
            LintRuleId::UnanalyzableRecursiveShape => {
                "Reduce the container nesting depth of this type, or raise \
                 --max-walk-depth if the shape is intentional."
            }
            LintRuleId::InconsistentOrigin => {
                "Confirm which library actually owns this type name and align \
                 the `lib` metadata on both declarations."
            }
            LintRuleId::StorageSchemaInvalid => {
                "Fix the storage schema file; see the finding message for the specific field."
            }
            LintRuleId::StorageSchemaMismatch => {
                "Reconcile the declared storage schema with what the contract \
                 actually reads and writes, or update the schema file."
            }
        }
    }
}

/// Severity of a lint finding, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LintSeverity {
    Info,
    Warning,
    Error,
}

impl LintSeverity {
    pub fn label(self) -> &'static str {
        match self {
            LintSeverity::Info => "INFO",
            LintSeverity::Warning => "WARN",
            LintSeverity::Error => "ERROR",
        }
    }
}

/// The structured location a lint finding points at.
#[derive(Debug, Clone, Serialize)]
pub struct LintTarget {
    /// "function", "struct", "enum", "union", "error_enum", or "storage_schema".
    pub kind: &'static str,
    /// Name of the declaring item (function or type name).
    pub name: String,
    /// Field or case name within the item, when the finding is that specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
}

impl LintTarget {
    fn new(kind: &'static str, name: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
            member: None,
        }
    }

    fn with_member(kind: &'static str, name: impl Into<String>, member: impl Into<String>) -> Self {
        Self {
            kind,
            name: name.into(),
            member: Some(member.into()),
        }
    }
}

impl std::fmt::Display for LintTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.member {
            Some(member) => write!(f, "{} {}::{}", self.kind, self.name, member),
            None => write!(f, "{} {}", self.kind, self.name),
        }
    }
}

/// A single lint finding.
#[derive(Debug, Clone, Serialize)]
pub struct LintFinding {
    pub rule_id: &'static str,
    pub severity: LintSeverity,
    pub target: LintTarget,
    pub message: String,
    pub remediation: &'static str,
}

impl LintFinding {
    fn new(rule: LintRuleId, target: LintTarget, message: impl Into<String>) -> Self {
        Self {
            rule_id: rule.as_str(),
            severity: rule.default_severity(),
            target,
            message: message.into(),
            remediation: rule.remediation(),
        }
    }
}

/// The full set of findings from a lint run, plus summary counts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LintReport {
    pub findings: Vec<LintFinding>,
}

impl LintReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == LintSeverity::Error)
    }

    pub fn has_warnings(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == LintSeverity::Warning)
    }

    /// (errors, warnings, infos)
    pub fn counts(&self) -> (usize, usize, usize) {
        let errors = self
            .findings
            .iter()
            .filter(|f| f.severity == LintSeverity::Error)
            .count();
        let warnings = self
            .findings
            .iter()
            .filter(|f| f.severity == LintSeverity::Warning)
            .count();
        let infos = self
            .findings
            .iter()
            .filter(|f| f.severity == LintSeverity::Info)
            .count();
        (errors, warnings, infos)
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        let (errors, warnings, infos) = self.counts();
        serde_json::json!({
            "clean": self.is_clean(),
            "summary": {
                "errors": errors,
                "warnings": warnings,
                "infos": infos,
            },
            "findings": self.findings,
        })
    }

    pub fn render_text(&self, explain: bool) -> String {
        if self.is_clean() {
            return "[PASS] No lint findings.\n".to_string();
        }
        let mut out = String::new();
        for finding in &self.findings {
            out.push_str(&format!(
                "[{}] {} ({}): {}\n",
                finding.severity.label(),
                finding.target,
                finding.rule_id,
                finding.message
            ));
            if explain {
                out.push_str(&format!("    -> {}\n", finding.remediation));
            }
        }
        let (errors, warnings, infos) = self.counts();
        out.push_str(&format!(
            "\n{errors} error(s), {warnings} warning(s), {infos} info finding(s)\n"
        ));
        out
    }

    pub fn render_markdown(&self, explain: bool) -> String {
        if self.is_clean() {
            return "**No lint findings.**\n".to_string();
        }
        let mut out = String::from("| Severity | Rule | Target | Message |\n|---|---|---|---|\n");
        for finding in &self.findings {
            out.push_str(&format!(
                "| {} | `{}` | `{}` | {} |\n",
                finding.severity.label(),
                finding.rule_id,
                finding.target,
                finding.message.replace('|', "\\|")
            ));
        }
        if explain {
            out.push_str("\n### Remediation\n\n");
            for finding in &self.findings {
                out.push_str(&format!(
                    "- `{}` ({}): {}\n",
                    finding.rule_id, finding.target, finding.remediation
                ));
            }
        }
        let (errors, warnings, infos) = self.counts();
        out.push_str(&format!(
            "\n_{errors} error(s), {warnings} warning(s), {infos} info finding(s)_\n"
        ));
        out
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Inputs to a lint run beyond the decoded spec entries themselves.
#[derive(Debug, Clone, Copy, Default)]
pub struct LintOptions<'a> {
    /// An optional declared storage schema to validate/reconcile.
    pub schema: Option<&'a StorageSchema>,
    /// Optional storage evidence inferred from the WASM body, used to
    /// reconcile against `schema` when both are present.
    pub inferred_storage: Option<&'a StorageInference>,
    /// Resource bounds reused from [`crate::limits`] for the recursive-shape check.
    pub policy: ResourcePolicy,
}

/// Lint one decoded contract spec (and its optional storage schema) in isolation.
pub fn lint(entries: &[ScSpecEntry], options: &LintOptions<'_>) -> LintReport {
    let spec = ContractSpec::from_entries(entries);
    let mut findings = Vec::new();

    lint_duplicate_declarations(entries, &mut findings);
    lint_cross_kind_and_origin(&spec, &mut findings);
    lint_case_integrity(&spec, &mut findings);

    let referenced = lint_reference_graph(&spec, &mut findings);
    lint_unreachable(&spec, &referenced, &mut findings);

    lint_recursive_shapes(&spec, options.policy.max_walk_depth, &mut findings);

    lint_storage_schema(options.schema, options.inferred_storage, &mut findings);

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(b.rule_id))
            .then_with(|| a.target.name.cmp(&b.target.name))
    });

    LintReport { findings }
}

// ── Duplicate declarations (reuses ContractSpec::duplicate_declarations) ────

fn lint_duplicate_declarations(entries: &[ScSpecEntry], findings: &mut Vec<LintFinding>) {
    for dup in ContractSpec::duplicate_declarations(entries) {
        let kind_static: &'static str = match dup.kind.as_str() {
            "function" => "function",
            "struct" => "struct",
            "enum" => "enum",
            "union" => "union",
            "error_enum" => "error_enum",
            _ => "unknown",
        };
        findings.push(LintFinding::new(
            LintRuleId::DuplicateDeclaration,
            LintTarget::new(kind_static, dup.name.clone()),
            format!(
                "'{}' is declared {} times as a {}; only the first is kept.",
                dup.name, dup.occurrences, dup.kind
            ),
        ));
    }
}

// ── Cross-kind collisions and inconsistent origin metadata ─────────────────

#[allow(clippy::type_complexity)]
fn lint_cross_kind_and_origin(spec: &ContractSpec, findings: &mut Vec<LintFinding>) {
    // (kind label, name -> lib) pairs for every UDT kind that carries `lib` metadata.
    let kinds: [(&'static str, Box<dyn Fn(&str) -> Option<String>>); 3] = [
        (
            "struct",
            Box::new(|n: &str| spec.structs.get(n).map(|s| s.lib.to_string())),
        ),
        (
            "enum",
            Box::new(|n: &str| spec.enums.get(n).map(|e| e.lib.to_string())),
        ),
        (
            "union",
            Box::new(|n: &str| spec.unions.get(n).map(|u| u.lib.to_string())),
        ),
    ];

    let mut all_names: BTreeSet<&str> = BTreeSet::new();
    all_names.extend(spec.structs.keys().map(String::as_str));
    all_names.extend(spec.enums.keys().map(String::as_str));
    all_names.extend(spec.unions.keys().map(String::as_str));
    all_names.extend(spec.error_enums.keys().map(String::as_str));

    for name in all_names {
        let mut present_in: Vec<&'static str> = Vec::new();
        if spec.structs.contains_key(name) {
            present_in.push("struct");
        }
        if spec.enums.contains_key(name) {
            present_in.push("enum");
        }
        if spec.unions.contains_key(name) {
            present_in.push("union");
        }
        if spec.error_enums.contains_key(name) {
            present_in.push("error_enum");
        }

        if present_in.len() > 1 {
            findings.push(LintFinding::new(
                LintRuleId::CrossKindNameCollision,
                LintTarget::new(present_in[0], name.to_string()),
                format!(
                    "'{}' is declared as more than one kind: {}.",
                    name,
                    present_in.join(", ")
                ),
            ));

            // Inconsistent origin: among the kinds that carry `lib` metadata,
            // do the declarations disagree about which library owns `name`?
            let libs: Vec<(&'static str, String)> = kinds
                .iter()
                .filter_map(|(kind, get_lib)| get_lib(name).map(|lib| (*kind, lib)))
                .filter(|(_, lib)| !lib.is_empty())
                .collect();
            let distinct: BTreeSet<&str> = libs.iter().map(|(_, lib)| lib.as_str()).collect();
            if distinct.len() > 1 {
                let detail = libs
                    .iter()
                    .map(|(kind, lib)| format!("{kind}=\"{lib}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                findings.push(LintFinding::new(
                    LintRuleId::InconsistentOrigin,
                    LintTarget::new(present_in[0], name.to_string()),
                    format!("'{name}' has conflicting library origins: {detail}."),
                ));
            }
        }
    }
}

// ── Case integrity: duplicate case names, conflicting discriminants ────────

fn lint_case_integrity(spec: &ContractSpec, findings: &mut Vec<LintFinding>) {
    for (name, e) in &spec.enums {
        check_case_names(
            "enum",
            name,
            e.cases.iter().map(|c| c.name.to_string()),
            findings,
        );
        check_discriminants(
            "enum",
            name,
            e.cases.iter().map(|c| (c.name.to_string(), c.value)),
            findings,
        );
    }

    for (name, e) in &spec.error_enums {
        check_case_names(
            "error_enum",
            name,
            e.cases.iter().map(|c| c.name.to_string()),
            findings,
        );
        check_discriminants(
            "error_enum",
            name,
            e.cases.iter().map(|c| (c.name.to_string(), c.value)),
            findings,
        );
    }

    for (name, u) in &spec.unions {
        let case_names = u.cases.iter().map(|c| match c {
            ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string(),
            ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string(),
        });
        check_case_names("union", name, case_names, findings);
    }
}

fn check_case_names(
    kind: &'static str,
    type_name: &str,
    names: impl Iterator<Item = String>,
    findings: &mut Vec<LintFinding>,
) {
    let mut seen: HashSet<String> = HashSet::new();
    let mut reported: HashSet<String> = HashSet::new();
    for name in names {
        if !seen.insert(name.clone()) && reported.insert(name.clone()) {
            findings.push(LintFinding::new(
                LintRuleId::DuplicateCaseName,
                LintTarget::with_member(kind, type_name, name.clone()),
                format!("Case '{name}' appears more than once in {kind} '{type_name}'."),
            ));
        }
    }
}

fn check_discriminants(
    kind: &'static str,
    type_name: &str,
    cases: impl Iterator<Item = (String, u32)>,
    findings: &mut Vec<LintFinding>,
) {
    let mut by_value: std::collections::BTreeMap<u32, Vec<String>> =
        std::collections::BTreeMap::new();
    for (name, value) in cases {
        by_value.entry(value).or_default().push(name);
    }
    for (value, names) in by_value {
        if names.len() > 1 {
            findings.push(LintFinding::new(
                LintRuleId::ConflictingDiscriminant,
                LintTarget::new(kind, type_name.to_string()),
                format!(
                    "Cases {:?} in {kind} '{type_name}' all use discriminant value {value}.",
                    names
                ),
            ));
        }
    }
}

// ── Reference graph: dangling references and reachability ──────────────────

/// Walks every function input/output and every UDT field/case, using
/// [`LayoutMapper`] to resolve UDT references, and returns the set of UDT
/// names reachable from the exported function surface. Along the way, any
/// referenced UDT name that resolves to nothing in the spec is reported as
/// [`LintRuleId::DanglingTypeReference`].
fn lint_reference_graph(spec: &ContractSpec, findings: &mut Vec<LintFinding>) -> HashSet<String> {
    let mapper = LayoutMapper::new(spec);
    let known: HashSet<&str> = spec
        .structs
        .keys()
        .map(String::as_str)
        .chain(spec.unions.keys().map(String::as_str))
        .chain(spec.enums.keys().map(String::as_str))
        .chain(spec.error_enums.keys().map(String::as_str))
        .collect();

    let mut reported_dangling: HashSet<String> = HashSet::new();
    let mut report_dangling = |target: LintTarget,
                               deps: &HashSet<String>,
                               findings: &mut Vec<LintFinding>| {
        for dep in deps {
            if !known.contains(dep.as_str()) && reported_dangling.insert(format!("{target}::{dep}"))
            {
                findings.push(LintFinding::new(
                    LintRuleId::DanglingTypeReference,
                    target.clone(),
                    format!("References undefined type '{dep}'."),
                ));
            }
        }
    };

    let mut reachable: HashSet<String> = HashSet::new();

    // Struct fields.
    for (name, s) in &spec.structs {
        for field in s.fields.iter() {
            let mut deps = mapper.get_udt_dependencies(&field.type_);
            if let ScSpecTypeDef::Udt(udt) = &field.type_ {
                deps.insert(udt.name.to_string());
            }
            report_dangling(
                LintTarget::with_member("struct", name.as_str(), field.name.to_string()),
                &deps,
                findings,
            );
            reachable.extend(deps);
        }
    }

    // Union tuple-case member types.
    for (name, u) in &spec.unions {
        for case in u.cases.iter() {
            if let ScSpecUdtUnionCaseV0::TupleV0(t) = case {
                for ty in t.type_.iter() {
                    let mut deps = mapper.get_udt_dependencies(ty);
                    if let ScSpecTypeDef::Udt(udt) = ty {
                        deps.insert(udt.name.to_string());
                    }
                    report_dangling(
                        LintTarget::with_member("union", name.as_str(), t.name.to_string()),
                        &deps,
                        findings,
                    );
                    reachable.extend(deps);
                }
            }
        }
    }

    // Function inputs/outputs -- these are also the roots of reachability.
    for (name, f) in &spec.functions {
        for input in f.inputs.iter() {
            let mut deps = mapper.get_udt_dependencies(&input.type_);
            if let ScSpecTypeDef::Udt(udt) = &input.type_ {
                deps.insert(udt.name.to_string());
            }
            report_dangling(
                LintTarget::with_member("function", name.as_str(), input.name.to_string()),
                &deps,
                findings,
            );
            reachable.extend(deps);
        }
        for output in f.outputs.iter() {
            let mut deps = mapper.get_udt_dependencies(output);
            if let ScSpecTypeDef::Udt(udt) = output {
                deps.insert(udt.name.to_string());
            }
            report_dangling(LintTarget::new("function", name.as_str()), &deps, findings);
            reachable.extend(deps);
        }
    }

    reachable
}

/// Structs, enums, and unions that are never reachable from an exported
/// function are flagged as [`LintRuleId::UnreachableDeclaration`].
///
/// Error enums are exempted: `contractspecv0` records the *shape* of an
/// error type via the generic `ScSpecTypeDef::Error` marker on a function's
/// `Result<_, Error>` output, not a named `Udt` reference to a specific
/// error-enum declaration, so error enums are never structurally
/// "reachable" in this graph even when they are genuinely used.
fn lint_unreachable(
    spec: &ContractSpec,
    reachable: &HashSet<String>,
    findings: &mut Vec<LintFinding>,
) {
    for (name, _) in spec.structs.iter().filter(|(n, _)| !reachable.contains(*n)) {
        findings.push(unreachable_finding("struct", name));
    }
    for (name, _) in spec.enums.iter().filter(|(n, _)| !reachable.contains(*n)) {
        findings.push(unreachable_finding("enum", name));
    }
    for (name, _) in spec.unions.iter().filter(|(n, _)| !reachable.contains(*n)) {
        findings.push(unreachable_finding("union", name));
    }
}

fn unreachable_finding(kind: &'static str, name: &str) -> LintFinding {
    LintFinding::new(
        LintRuleId::UnreachableDeclaration,
        LintTarget::new(kind, name.to_string()),
        format!("{kind} '{name}' is declared but not reachable from any exported function."),
    )
}

// ── Recursive / container shape depth ───────────────────────────────────────

/// Depth-bounded container walk, independent of [`LayoutMapper`]'s
/// UDT-name cycle guard: it also catches shapes with no named-UDT cycle at
/// all (e.g. deeply nested `Vec<Vec<Vec<...>>>`), which a name-based guard
/// cannot detect since there is no repeated name to break on.
fn lint_recursive_shapes(spec: &ContractSpec, max_depth: usize, findings: &mut Vec<LintFinding>) {
    for (name, s) in &spec.structs {
        for field in s.fields.iter() {
            let mut seen = HashSet::new();
            if depth_exceeds(&field.type_, spec, &mut seen, 0, max_depth) {
                findings.push(recursive_finding(
                    "struct",
                    name,
                    Some(field.name.to_string()),
                    max_depth,
                ));
            }
        }
    }
    for (name, u) in &spec.unions {
        for case in u.cases.iter() {
            if let ScSpecUdtUnionCaseV0::TupleV0(t) = case {
                for ty in t.type_.iter() {
                    let mut seen = HashSet::new();
                    if depth_exceeds(ty, spec, &mut seen, 0, max_depth) {
                        findings.push(recursive_finding(
                            "union",
                            name,
                            Some(t.name.to_string()),
                            max_depth,
                        ));
                    }
                }
            }
        }
    }
    for (name, f) in &spec.functions {
        for input in f.inputs.iter() {
            let mut seen = HashSet::new();
            if depth_exceeds(&input.type_, spec, &mut seen, 0, max_depth) {
                findings.push(recursive_finding(
                    "function",
                    name,
                    Some(input.name.to_string()),
                    max_depth,
                ));
            }
        }
        for output in f.outputs.iter() {
            let mut seen = HashSet::new();
            if depth_exceeds(output, spec, &mut seen, 0, max_depth) {
                findings.push(recursive_finding("function", name, None, max_depth));
            }
        }
    }
}

fn recursive_finding(
    kind: &'static str,
    name: &str,
    member: Option<String>,
    max_depth: usize,
) -> LintFinding {
    let target = match member {
        Some(m) => LintTarget::with_member(kind, name, m),
        None => LintTarget::new(kind, name.to_string()),
    };
    LintFinding::new(
        LintRuleId::UnanalyzableRecursiveShape,
        target,
        format!("Nesting depth exceeds the configured limit of {max_depth}."),
    )
}

/// Returns `true` once the walk would exceed `max_depth`. `seen` guards
/// against true UDT-name cycles (e.g. `struct A { next: Option<A> }`), which
/// are not themselves a depth violation as long as they terminate via
/// `Option`/`Vec`/etc. at runtime; only container nesting depth counts here.
fn depth_exceeds(
    type_def: &ScSpecTypeDef,
    spec: &ContractSpec,
    seen: &mut HashSet<String>,
    depth: usize,
    max_depth: usize,
) -> bool {
    if depth > max_depth {
        return true;
    }
    match type_def {
        ScSpecTypeDef::Option(opt) => {
            depth_exceeds(&opt.value_type, spec, seen, depth + 1, max_depth)
        }
        ScSpecTypeDef::Result(res) => {
            depth_exceeds(&res.ok_type, spec, seen, depth + 1, max_depth)
                || depth_exceeds(&res.error_type, spec, seen, depth + 1, max_depth)
        }
        ScSpecTypeDef::Vec(v) => depth_exceeds(&v.element_type, spec, seen, depth + 1, max_depth),
        ScSpecTypeDef::Map(m) => {
            depth_exceeds(&m.key_type, spec, seen, depth + 1, max_depth)
                || depth_exceeds(&m.value_type, spec, seen, depth + 1, max_depth)
        }
        ScSpecTypeDef::Tuple(t) => t
            .value_types
            .iter()
            .any(|ty| depth_exceeds(ty, spec, seen, depth + 1, max_depth)),
        ScSpecTypeDef::Udt(udt) => {
            let name = udt.name.to_string();
            if !seen.insert(name.clone()) {
                // Already on this path: a true cycle, not a depth violation.
                return false;
            }
            let exceeded = if let Some(s) = spec.structs.get(&name) {
                s.fields
                    .iter()
                    .any(|field| depth_exceeds(&field.type_, spec, seen, depth + 1, max_depth))
            } else if let Some(u) = spec.unions.get(&name) {
                u.cases.iter().any(|case| match case {
                    ScSpecUdtUnionCaseV0::TupleV0(t) => t
                        .type_
                        .iter()
                        .any(|ty| depth_exceeds(ty, spec, seen, depth + 1, max_depth)),
                    ScSpecUdtUnionCaseV0::VoidV0(_) => false,
                })
            } else {
                false
            };
            seen.remove(&name);
            exceeded
        }
        _ => false,
    }
}

// ── Storage schema ───────────────────────────────────────────────────────────

fn lint_storage_schema(
    schema: Option<&StorageSchema>,
    inferred: Option<&StorageInference>,
    findings: &mut Vec<LintFinding>,
) {
    let Some(schema) = schema else {
        return;
    };

    if let Err(err) = schema.validate() {
        findings.push(LintFinding::new(
            LintRuleId::StorageSchemaInvalid,
            LintTarget::new("storage_schema", "storage_schema"),
            err,
        ));
        return;
    }

    let Some(inferred) = inferred else {
        return;
    };

    let reconciliation = schema.reconcile(inferred);
    for mismatch in &reconciliation.findings {
        findings.push(LintFinding::new(
            LintRuleId::StorageSchemaMismatch,
            LintTarget::new("storage_schema", mismatch_key(mismatch)),
            mismatch.to_string(),
        ));
    }
}

fn mismatch_key(mismatch: &SchemaMismatch) -> String {
    // `SchemaMismatch` variants carry their own identifying fields; render
    // via Display and take the leading token as a stable-ish target name so
    // findings remain traceable without depending on internal field names.
    mismatch
        .to_string()
        .split(':')
        .next()
        .unwrap_or("declaration")
        .to_string()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ScSpecFunctionV0, ScSpecTypeDef, ScSpecTypeOption, ScSpecTypeVec, ScSpecUdtEnumCaseV0,
        ScSpecUdtEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0, ScSpecUdtUnionCaseTupleV0,
        ScSpecUdtUnionV0, StringM, VecM,
    };

    fn udt(name: &str) -> ScSpecTypeDef {
        ScSpecTypeDef::Udt(stellar_xdr::curr::ScSpecTypeUdt {
            name: name.try_into().unwrap(),
        })
    }

    fn default_options() -> LintOptions<'static> {
        LintOptions {
            schema: None,
            inferred_storage: None,
            policy: ResourcePolicy::default(),
        }
    }

    #[test]
    fn detects_dangling_type_reference() {
        let s = ScSpecUdtStructV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "Wrapper".try_into().unwrap(),
            fields: vec![ScSpecUdtStructFieldV0 {
                doc: "".try_into().unwrap(),
                name: "inner".try_into().unwrap(),
                type_: udt("Missing"),
            }]
            .try_into()
            .unwrap(),
        };
        let entries = vec![ScSpecEntry::UdtStructV0(s)];

        let report = lint(&entries, &default_options());
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == LintRuleId::DanglingTypeReference.as_str()));
    }

    #[test]
    fn detects_unreachable_declaration_but_not_error_enums() {
        let s = ScSpecUdtStructV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "Orphan".try_into().unwrap(),
            fields: VecM::default(),
        };
        let e = stellar_xdr::curr::ScSpecUdtErrorEnumV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "MyError".try_into().unwrap(),
            cases: vec![stellar_xdr::curr::ScSpecUdtErrorEnumCaseV0 {
                doc: "".try_into().unwrap(),
                name: "Bad".try_into().unwrap(),
                value: 1,
            }]
            .try_into()
            .unwrap(),
        };
        let entries = vec![ScSpecEntry::UdtStructV0(s), ScSpecEntry::UdtErrorEnumV0(e)];

        let report = lint(&entries, &default_options());
        let unreachable: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == LintRuleId::UnreachableDeclaration.as_str())
            .collect();
        assert_eq!(unreachable.len(), 1);
        assert_eq!(unreachable[0].target.name, "Orphan");
    }

    #[test]
    fn reachable_struct_is_not_flagged_unreachable() {
        let s = ScSpecUdtStructV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "Used".try_into().unwrap(),
            fields: VecM::default(),
        };
        let f = ScSpecFunctionV0 {
            doc: "".try_into().unwrap(),
            name: "get_used".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: vec![udt("Used")].try_into().unwrap(),
        };
        let entries = vec![ScSpecEntry::UdtStructV0(s), ScSpecEntry::FunctionV0(f)];

        let report = lint(&entries, &default_options());
        assert!(!report
            .findings
            .iter()
            .any(|f| f.rule_id == LintRuleId::UnreachableDeclaration.as_str()));
    }

    #[test]
    fn detects_duplicate_case_name() {
        let e = ScSpecUdtEnumV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "Status".try_into().unwrap(),
            cases: vec![
                ScSpecUdtEnumCaseV0 {
                    doc: "".try_into().unwrap(),
                    name: "Active".try_into().unwrap(),
                    value: 0,
                },
                ScSpecUdtEnumCaseV0 {
                    doc: "".try_into().unwrap(),
                    name: "Active".try_into().unwrap(),
                    value: 1,
                },
            ]
            .try_into()
            .unwrap(),
        };
        let entries = vec![ScSpecEntry::UdtEnumV0(e)];

        let report = lint(&entries, &default_options());
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == LintRuleId::DuplicateCaseName.as_str()));
    }

    #[test]
    fn detects_conflicting_discriminant() {
        let e = ScSpecUdtEnumV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "Status".try_into().unwrap(),
            cases: vec![
                ScSpecUdtEnumCaseV0 {
                    doc: "".try_into().unwrap(),
                    name: "Active".try_into().unwrap(),
                    value: 0,
                },
                ScSpecUdtEnumCaseV0 {
                    doc: "".try_into().unwrap(),
                    name: "Inactive".try_into().unwrap(),
                    value: 0,
                },
            ]
            .try_into()
            .unwrap(),
        };
        let entries = vec![ScSpecEntry::UdtEnumV0(e)];

        let report = lint(&entries, &default_options());
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == LintRuleId::ConflictingDiscriminant.as_str()));
    }

    #[test]
    fn detects_cross_kind_name_collision() {
        let s = ScSpecUdtStructV0 {
            doc: "".try_into().unwrap(),
            lib: "crate_a".try_into().unwrap(),
            name: "Token".try_into().unwrap(),
            fields: VecM::default(),
        };
        let e = ScSpecUdtEnumV0 {
            doc: "".try_into().unwrap(),
            lib: "crate_b".try_into().unwrap(),
            name: "Token".try_into().unwrap(),
            cases: VecM::default(),
        };
        let entries = vec![ScSpecEntry::UdtStructV0(s), ScSpecEntry::UdtEnumV0(e)];

        let report = lint(&entries, &default_options());
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == LintRuleId::CrossKindNameCollision.as_str()));
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == LintRuleId::InconsistentOrigin.as_str()));
    }

    #[test]
    fn detects_unanalyzable_recursive_container_depth() {
        // Vec<Vec<Vec<Vec<u32>>>> nested 4 deep, with a max_walk_depth of 2.
        let deeply_nested = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                element_type: Box::new(ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                    element_type: Box::new(ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                        element_type: Box::new(ScSpecTypeDef::U32),
                    }))),
                }))),
            }))),
        }));
        let s = ScSpecUdtStructV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "Deep".try_into().unwrap(),
            fields: vec![ScSpecUdtStructFieldV0 {
                doc: "".try_into().unwrap(),
                name: "nested".try_into().unwrap(),
                type_: deeply_nested,
            }]
            .try_into()
            .unwrap(),
        };
        let entries = vec![ScSpecEntry::UdtStructV0(s)];

        let mut options = default_options();
        options.policy.max_walk_depth = 2;

        let report = lint(&entries, &options);
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == LintRuleId::UnanalyzableRecursiveShape.as_str()));
    }

    #[test]
    fn true_udt_cycle_is_not_flagged_as_recursive_shape() {
        // struct A { next: Option<A> } -- a genuine cycle, but not a depth
        // violation: it terminates via Option at runtime.
        let s = ScSpecUdtStructV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "Node".try_into().unwrap(),
            fields: vec![ScSpecUdtStructFieldV0 {
                doc: "".try_into().unwrap(),
                name: "next".try_into().unwrap(),
                type_: ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
                    value_type: Box::new(udt("Node")),
                })),
            }]
            .try_into()
            .unwrap(),
        };
        let entries = vec![ScSpecEntry::UdtStructV0(s)];

        let report = lint(&entries, &default_options());
        assert!(!report
            .findings
            .iter()
            .any(|f| f.rule_id == LintRuleId::UnanalyzableRecursiveShape.as_str()));
    }

    #[test]
    fn clean_spec_produces_no_findings() {
        let f = ScSpecFunctionV0 {
            doc: "".try_into().unwrap(),
            name: "ping".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let entries = vec![ScSpecEntry::FunctionV0(f)];

        let report = lint(&entries, &default_options());
        assert!(report.is_clean());
        assert!(!report.has_errors());
    }

    #[test]
    fn duplicate_union_case_name_is_detected() {
        let u = ScSpecUdtUnionV0 {
            doc: "".try_into().unwrap(),
            lib: StringM::default(),
            name: "Msg".try_into().unwrap(),
            cases: vec![
                ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                    doc: "".try_into().unwrap(),
                    name: "Ping".try_into().unwrap(),
                    type_: vec![ScSpecTypeDef::U32].try_into().unwrap(),
                }),
                ScSpecUdtUnionCaseV0::TupleV0(ScSpecUdtUnionCaseTupleV0 {
                    doc: "".try_into().unwrap(),
                    name: "Ping".try_into().unwrap(),
                    type_: vec![ScSpecTypeDef::U64].try_into().unwrap(),
                }),
            ]
            .try_into()
            .unwrap(),
        };
        let entries = vec![ScSpecEntry::UdtUnionV0(u)];

        let report = lint(&entries, &default_options());
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == LintRuleId::DuplicateCaseName.as_str()));
    }
}

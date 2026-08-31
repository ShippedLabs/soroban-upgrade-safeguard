//! Declared storage schemas and evidence-based reconciliation.

use serde::{Deserialize, Serialize};

use crate::storage_inference::{
    CoverageGap, Durability, StorageInference, StorageObservation, StorageOperation,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageDeclaration {
    pub name: String,
    #[serde(default)]
    pub function: Option<String>,
    pub operation: StorageOperation,
    #[serde(default)]
    pub durability: Option<Durability>,
    #[serde(default)]
    pub key_type: Option<String>,
    #[serde(default)]
    pub value_type: Option<String>,
    /// Optional logical namespace for this storage key.  Two declarations with
    /// different namespaces that share the same name represent distinct ledger
    /// entries — changing the namespace causes reads and writes to target a
    /// different entry and effectively orphans any data stored under the old one.
    #[serde(default)]
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSchema {
    #[serde(default)]
    pub declarations: Vec<StorageDeclaration>,
}

impl StorageSchema {
    pub fn from_json(input: &str) -> Result<Self, String> {
        serde_json::from_str(input).map_err(|e| format!("invalid storage schema JSON: {e}"))
    }

    pub fn from_toml(input: &str) -> Result<Self, String> {
        toml::from_str(input).map_err(|e| format!("invalid storage schema TOML: {e}"))
    }

    pub fn from_str(input: &str, format: SchemaFormat) -> Result<Self, String> {
        let schema = match format {
            SchemaFormat::Json => Self::from_json(input)?,
            SchemaFormat::Toml => Self::from_toml(input)?,
        };
        schema.validate()?;
        Ok(schema)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.declarations.iter().any(|d| d.name.trim().is_empty()) {
            return Err("storage schema declaration names must not be empty".into());
        }
        for (index, declaration) in self.declarations.iter().enumerate() {
            if declaration.operation == StorageOperation::Unknown {
                return Err(format!(
                    "declaration {index} uses unknown storage operation"
                ));
            }
        }
        Ok(())
    }

    pub fn reconcile(&self, inferred: &StorageInference) -> StorageReconciliation {
        let mut findings = Vec::new();
        let mut used = vec![false; self.declarations.len()];

        for observation in &inferred.observations {
            let candidate = self
                .declarations
                .iter()
                .enumerate()
                .find(|(_, declaration)| declaration_matches(declaration, observation));
            let Some((index, declaration)) = candidate else {
                findings.push(SchemaMismatch::MissingDeclaration {
                    function: observation.function.clone(),
                    operation: observation.operation,
                    durability: observation.durability,
                    evidence: observation.evidence.clone(),
                    dependency_path: vec![
                        observation.function.clone(),
                        format!("{:?}", observation.operation),
                    ],
                    remediation: "declare this storage operation or remove the unreachable access"
                        .into(),
                });
                continue;
            };
            used[index] = true;
            if let (Some(inferred), Some(declared)) = (
                observation.key_type.as_deref(),
                declaration.key_type.as_deref(),
            ) {
                if inferred != declared {
                    findings.push(SchemaMismatch::TypeContradiction {
                        declaration: declaration.name.clone(),
                        role: "key".into(),
                        declared: declared.into(),
                        inferred: inferred.into(),
                        dependency_path: observation.evidence.clone(),
                        remediation: "update the declaration to the compiled type or rebuild the contract with the intended type".into(),
                    });
                }
            }
            if let (Some(inferred), Some(declared)) = (
                observation.value_type.as_deref(),
                declaration.value_type.as_deref(),
            ) {
                if inferred != declared {
                    findings.push(SchemaMismatch::TypeContradiction {
                        declaration: declaration.name.clone(),
                        role: "value".into(),
                        declared: declared.into(),
                        inferred: inferred.into(),
                        dependency_path: observation.evidence.clone(),
                        remediation: "update the declaration to the compiled type or rebuild the contract with the intended type".into(),
                    });
                }
            }
            if declaration.durability.is_some()
                && observation.durability.is_some()
                && declaration.durability != observation.durability
            {
                findings.push(SchemaMismatch::DurabilityContradiction {
                    declaration: declaration.name.clone(),
                    declared: declaration.durability,
                    inferred: observation.durability,
                    dependency_path: observation.evidence.clone(),
                    remediation: "make the declaration and compiled storage durability agree"
                        .into(),
                });
            }
        }

        for (index, declaration) in self.declarations.iter().enumerate() {
            if !used[index] {
                findings.push(SchemaMismatch::UnobservedDeclaration {
                    declaration: declaration.name.clone(),
                    remediation:
                        "remove the stale declaration or ensure the storage path remains reachable"
                            .into(),
                });
            }
        }

        StorageReconciliation {
            observations: inferred.observations.clone(),
            findings,
            coverage_gaps: inferred.gaps.clone(),
            complete: inferred.gaps.is_empty(),
        }
    }
}

pub fn compare_storage_schemas(
    old_schema: &StorageSchema,
    old_inference: &StorageInference,
    new_schema: &StorageSchema,
    new_inference: &StorageInference,
) -> StorageSchemaComparison {
    let cross_findings =
        cross_compare_declarations(&old_schema.declarations, &new_schema.declarations);
    StorageSchemaComparison {
        old: old_schema.reconcile(old_inference),
        new: new_schema.reconcile(new_inference),
        cross_findings,
    }
}

/// Compare old and new schema declarations by name to detect durability and
/// namespace changes that would orphan data or alter retention behaviour.
fn cross_compare_declarations(
    old_decls: &[StorageDeclaration],
    new_decls: &[StorageDeclaration],
) -> Vec<SchemaMismatch> {
    let mut findings = Vec::new();

    for old in old_decls {
        let Some(new) = new_decls.iter().find(|d| d.name == old.name) else {
            continue; // removed declarations are handled by the individual reconciliations
        };

        // Detect durability changes
        if let (Some(old_dur), Some(new_dur)) = (old.durability, new.durability) {
            if old_dur != new_dur {
                let consequence = durability_change_consequence(old_dur, new_dur);
                findings.push(SchemaMismatch::DurabilityChanged {
                    declaration: old.name.clone(),
                    old_durability: old_dur,
                    new_durability: new_dur,
                    consequence: consequence.into(),
                    remediation: durability_change_remediation(old_dur, new_dur).into(),
                });
            }
        }

        // Detect namespace changes
        match (&old.namespace, &new.namespace) {
            (Some(old_ns), Some(new_ns)) if old_ns != new_ns => {
                findings.push(SchemaMismatch::NamespaceChanged {
                    declaration: old.name.clone(),
                    old_namespace: old_ns.clone(),
                    new_namespace: new_ns.clone(),
                    remediation: "Changing the namespace redirects reads and writes to a \
                        different ledger entry, orphaning any data stored under the old key. \
                        Restore the original namespace or perform a data migration."
                        .into(),
                });
            }
            (Some(old_ns), None) => {
                findings.push(SchemaMismatch::NamespaceChanged {
                    declaration: old.name.clone(),
                    old_namespace: old_ns.clone(),
                    new_namespace: String::new(),
                    remediation: "The namespace was removed. This changes the effective ledger \
                        key and orphans data stored under the old namespaced key. \
                        Restore the namespace or migrate the existing data."
                        .into(),
                });
            }
            (None, Some(new_ns)) => {
                findings.push(SchemaMismatch::NamespaceChanged {
                    declaration: old.name.clone(),
                    old_namespace: String::new(),
                    new_namespace: new_ns.clone(),
                    remediation: "A namespace was added to this declaration. This changes the \
                        effective ledger key and orphans data stored under the un-namespaced key. \
                        Restore the missing namespace or migrate the existing data."
                        .into(),
                });
            }
            _ => {}
        }
    }

    findings
}

/// Describe the operational consequence of a durability change.
fn durability_change_consequence(old: Durability, new: Durability) -> &'static str {
    match (old, new) {
        (Durability::Persistent, Durability::Temporary) => {
            "Data that was retained indefinitely will now expire; existing entries become \
             unreachable once their TTL elapses."
        }
        (Durability::Persistent, Durability::Instance) => {
            "Data is now tied to the contract instance lifetime instead of being retained \
             independently; the old persistent entry is no longer read."
        }
        (Durability::Temporary, Durability::Persistent) => {
            "Data that previously expired will now be retained indefinitely; the upgrade \
             creates a new persistent entry separate from any expired temporary entry."
        }
        (Durability::Temporary, Durability::Instance) => {
            "Temporary storage (expiring) is replaced by instance storage; the old \
             temporary entry is no longer read."
        }
        (Durability::Instance, Durability::Persistent) => {
            "Instance-scoped storage is replaced by persistent storage; the old instance \
             entry is no longer read, and a new persistent entry is written."
        }
        (Durability::Instance, Durability::Temporary) => {
            "Instance-scoped storage is replaced by temporary storage, which will expire; \
             the old instance entry is no longer read."
        }
        _ => "Durability changed; existing entries may become unreachable.",
    }
}

/// Produce a remediation hint for a durability change.
fn durability_change_remediation(old: Durability, new: Durability) -> &'static str {
    match (old, new) {
        (Durability::Persistent, _) => {
            "Existing persistent entries will not be read under the new durability tier. \
             Restore the original durability or migrate any on-chain data before deploying."
        }
        (_, Durability::Temporary) => {
            "Temporary entries expire and cannot replace durable on-chain state without \
             data loss. Restore the original durability or plan an explicit migration."
        }
        _ => {
            "Restore the original durability or perform a data migration so existing \
             on-chain entries remain accessible."
        }
    }
}

fn declaration_matches(
    declaration: &StorageDeclaration,
    observation: &crate::storage_inference::StorageObservation,
) -> bool {
    declaration.operation == observation.operation
        && declaration
            .function
            .as_deref()
            .map(|name| name == observation.function)
            .unwrap_or(true)
        && declaration
            .durability
            .map(|durability| Some(durability) == observation.durability)
            .unwrap_or(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaFormat {
    Json,
    Toml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SchemaMismatch {
    MissingDeclaration {
        function: String,
        operation: StorageOperation,
        durability: Option<Durability>,
        evidence: Vec<String>,
        dependency_path: Vec<String>,
        remediation: String,
    },
    TypeContradiction {
        declaration: String,
        role: String,
        declared: String,
        inferred: String,
        dependency_path: Vec<String>,
        remediation: String,
    },
    DurabilityContradiction {
        declaration: String,
        declared: Option<Durability>,
        inferred: Option<Durability>,
        dependency_path: Vec<String>,
        remediation: String,
    },
    UnobservedDeclaration {
        declaration: String,
        remediation: String,
    },
    /// The durability tier for a named declaration changed between the old and
    /// new schema versions.  This causes reads and writes to target a different
    /// ledger bucket, effectively orphaning any data stored under the old tier.
    DurabilityChanged {
        declaration: String,
        old_durability: Durability,
        new_durability: Durability,
        /// Human-readable description of the operational consequence.
        consequence: String,
        remediation: String,
    },
    /// The logical namespace (key-domain prefix) for a named declaration changed
    /// between the old and new schema versions.  This causes reads and writes to
    /// target a different ledger entry key even when the value type is unchanged.
    NamespaceChanged {
        declaration: String,
        old_namespace: String,
        new_namespace: String,
        remediation: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageReconciliation {
    pub observations: Vec<StorageObservation>,
    pub findings: Vec<SchemaMismatch>,
    pub coverage_gaps: Vec<CoverageGap>,
    pub complete: bool,
}

impl StorageReconciliation {
    pub fn is_compatible(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "compatible": self.is_compatible(),
            "complete": self.complete,
            "finding_count": self.findings.len(),
            "coverage_gap_count": self.coverage_gaps.len(),
            "observations": &self.observations,
            "findings": &self.findings,
            "coverage_gaps": &self.coverage_gaps,
        })
    }

    pub fn render_text(&self) -> String {
        let mut out = format!(
            "Storage schema: {}\nCoverage: {} ({} gap{})\n",
            if self.is_compatible() {
                "compatible"
            } else {
                "mismatch"
            },
            if self.complete {
                "complete"
            } else {
                "incomplete"
            },
            self.coverage_gaps.len(),
            if self.coverage_gaps.len() == 1 {
                ""
            } else {
                "s"
            },
        );
        for observation in &self.observations {
            out.push_str(&format!(
                "- inferred {:?} in {}: key={}, value={}, durability={}, confidence={}\n",
                observation.operation,
                observation.function,
                observation.key_type.as_deref().unwrap_or("unknown"),
                observation.value_type.as_deref().unwrap_or("unknown"),
                observation
                    .durability
                    .map(|d| d.label())
                    .unwrap_or("unknown"),
                observation.confidence,
            ));
        }
        for finding in &self.findings {
            out.push_str(&format!("- {}\n", finding));
        }
        for gap in &self.coverage_gaps {
            out.push_str(&format!("- coverage gap: {}\n", gap.reason));
        }
        out
    }

    pub fn render_markdown(&self) -> String {
        let mut out = format!(
            "## Inferred Storage Schema\n\n- **Compatibility**: {}\n- **Coverage**: {}\n\n",
            if self.is_compatible() {
                "compatible"
            } else {
                "mismatch"
            },
            if self.complete {
                "complete"
            } else {
                "incomplete"
            },
        );
        for observation in &self.observations {
            out.push_str(&format!(
                "- **Inferred {:?}** in `{}`: key `{}`, value `{}`, durability `{}`, confidence `{}`\n",
                observation.operation,
                observation.function,
                observation.key_type.as_deref().unwrap_or("unknown"),
                observation.value_type.as_deref().unwrap_or("unknown"),
                observation.durability.map(|d| d.label()).unwrap_or("unknown"),
                observation.confidence,
            ));
        }
        if self.findings.is_empty() && self.coverage_gaps.is_empty() {
            out.push_str("No storage schema mismatches detected.\n");
        } else {
            for finding in &self.findings {
                out.push_str(&format!("- {}\n", finding));
            }
            for gap in &self.coverage_gaps {
                out.push_str(&format!("- **Coverage gap**: {}\n", gap.reason));
            }
        }
        out
    }
}

impl std::fmt::Display for SchemaMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDeclaration {
                function,
                operation,
                durability,
                ..
            } => write!(
                f,
                "missing declaration for {operation:?} in {function} ({})",
                durability
                    .map(|d| d.label())
                    .unwrap_or("unknown durability")
            ),
            Self::TypeContradiction {
                declaration,
                role,
                declared,
                inferred,
                ..
            } => write!(
                f,
                "{declaration} {role} type declares {declared}, inferred {inferred}"
            ),
            Self::DurabilityContradiction {
                declaration,
                declared,
                inferred,
                ..
            } => write!(
                f,
                "{declaration} durability declares {declared:?}, inferred {inferred:?}"
            ),
            Self::UnobservedDeclaration { declaration, .. } => {
                write!(f, "declaration {declaration} was not observed")
            }
            Self::DurabilityChanged {
                declaration,
                old_durability,
                new_durability,
                ..
            } => write!(
                f,
                "{declaration} durability changed from {} to {}",
                old_durability.label(),
                new_durability.label()
            ),
            Self::NamespaceChanged {
                declaration,
                old_namespace,
                new_namespace,
                ..
            } => {
                if old_namespace.is_empty() {
                    write!(f, "{declaration} namespace added: '{new_namespace}'")
                } else if new_namespace.is_empty() {
                    write!(f, "{declaration} namespace removed (was '{old_namespace}')")
                } else {
                    write!(
                        f,
                        "{declaration} namespace changed from '{old_namespace}' to '{new_namespace}'"
                    )
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSchemaComparison {
    pub old: StorageReconciliation,
    pub new: StorageReconciliation,
    /// Findings produced by comparing old declarations directly against new
    /// declarations — durability changes, namespace changes, etc.  These are
    /// cross-version concerns that are invisible to the per-side reconciliations.
    #[serde(default)]
    pub cross_findings: Vec<SchemaMismatch>,
}

impl StorageSchemaComparison {
    pub fn is_compatible(&self) -> bool {
        self.old.is_compatible() && self.new.is_compatible() && self.cross_findings.is_empty()
    }
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "compatible": self.is_compatible(),
            "old": self.old.to_json_value(),
            "new": self.new.to_json_value(),
            "cross_findings": &self.cross_findings,
        })
    }
    pub fn render_text(&self) -> String {
        let mut out = format!(
            "old:\n{}new:\n{}",
            self.old.render_text(),
            self.new.render_text()
        );
        if !self.cross_findings.is_empty() {
            out.push_str("cross-schema findings:\n");
            for finding in &self.cross_findings {
                out.push_str(&format!("- {finding}\n"));
            }
        }
        out
    }
    pub fn render_markdown(&self) -> String {
        let mut out = format!(
            "# Storage Schema Comparison\n\n### Old\n\n{}\n### New\n\n{}",
            self.old.render_markdown(),
            self.new.render_markdown()
        );
        if !self.cross_findings.is_empty() {
            out.push_str("\n### Cross-Schema Findings\n\n");
            for finding in &self.cross_findings {
                out.push_str(&format!("- {finding}\n"));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_inference::{StorageObservation, StorageOperation};

    #[test]
    fn reports_missing_declaration_and_preserves_gap() {
        let inferred = StorageInference {
            observations: vec![StorageObservation {
                function: "save".into(),
                operation: StorageOperation::Set,
                durability: Some(Durability::Persistent),
                key_type: None,
                value_type: None,
                confidence: "host_call_only".into(),
                evidence: vec!["call env::storage_set".into()],
            }],
            gaps: vec![CoverageGap {
                function: Some("save".into()),
                reason: "indirect call".into(),
                evidence: vec![],
            }],
            ..Default::default()
        };
        let result = StorageSchema::default().reconcile(&inferred);
        assert!(!result.is_compatible());
        assert_eq!(result.coverage_gaps.len(), 1);
        assert!(matches!(
            result.findings[0],
            SchemaMismatch::MissingDeclaration { .. }
        ));
    }

    #[test]
    fn rejects_unknown_operations() {
        let schema = StorageSchema {
            declarations: vec![StorageDeclaration {
                name: "x".into(),
                function: None,
                operation: StorageOperation::Unknown,
                durability: None,
                key_type: None,
                value_type: None,
                namespace: None,
            }],
        };
        assert!(schema.validate().is_err());
    }

    #[test]
    fn renders_json_text_and_markdown_with_coverage() {
        let result = StorageSchema::default().reconcile(&StorageInference {
            gaps: vec![CoverageGap {
                function: None,
                reason: "indirect call".into(),
                evidence: vec![],
            }],
            ..Default::default()
        });
        assert_eq!(result.to_json_value()["complete"], false);
        assert!(result.render_text().contains("Coverage: incomplete"));
        assert!(result.render_markdown().contains("Coverage gap"));
    }

    fn make_decl(
        name: &str,
        durability: Option<Durability>,
        namespace: Option<&str>,
    ) -> StorageDeclaration {
        StorageDeclaration {
            name: name.into(),
            function: None,
            operation: StorageOperation::Set,
            durability,
            key_type: None,
            value_type: None,
            namespace: namespace.map(Into::into),
        }
    }

    #[test]
    fn detects_durability_change_persistent_to_temporary() {
        let old = StorageSchema {
            declarations: vec![make_decl("counter", Some(Durability::Persistent), None)],
        };
        let new = StorageSchema {
            declarations: vec![make_decl("counter", Some(Durability::Temporary), None)],
        };
        let comparison = compare_storage_schemas(
            &old,
            &StorageInference::default(),
            &new,
            &StorageInference::default(),
        );
        assert_eq!(comparison.cross_findings.len(), 1);
        assert!(matches!(
            &comparison.cross_findings[0],
            SchemaMismatch::DurabilityChanged {
                declaration,
                old_durability: Durability::Persistent,
                new_durability: Durability::Temporary,
                ..
            } if declaration == "counter"
        ));
        assert!(!comparison.is_compatible());
        let text = comparison.render_text();
        assert!(text.contains("cross-schema findings"));
        assert!(text.contains("persistent"));
        assert!(text.contains("temporary"));
        let json = comparison.to_json_value();
        assert_eq!(json["cross_findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn detects_namespace_change() {
        let old = StorageSchema {
            declarations: vec![make_decl(
                "balance",
                Some(Durability::Persistent),
                Some("v1"),
            )],
        };
        let new = StorageSchema {
            declarations: vec![make_decl(
                "balance",
                Some(Durability::Persistent),
                Some("v2"),
            )],
        };
        let comparison = compare_storage_schemas(
            &old,
            &StorageInference::default(),
            &new,
            &StorageInference::default(),
        );
        assert_eq!(comparison.cross_findings.len(), 1);
        assert!(matches!(
            &comparison.cross_findings[0],
            SchemaMismatch::NamespaceChanged {
                declaration,
                old_namespace,
                new_namespace,
                ..
            } if declaration == "balance" && old_namespace == "v1" && new_namespace == "v2"
        ));
        assert!(!comparison.is_compatible());
        let text = comparison.render_text();
        assert!(text.contains("v1"));
        assert!(text.contains("v2"));
    }

    #[test]
    fn detects_namespace_added() {
        let old = StorageSchema {
            declarations: vec![make_decl("config", Some(Durability::Instance), None)],
        };
        let new = StorageSchema {
            declarations: vec![make_decl("config", Some(Durability::Instance), Some("ns"))],
        };
        let comparison = compare_storage_schemas(
            &old,
            &StorageInference::default(),
            &new,
            &StorageInference::default(),
        );
        assert_eq!(comparison.cross_findings.len(), 1);
        assert!(matches!(
            &comparison.cross_findings[0],
            SchemaMismatch::NamespaceChanged {
                declaration,
                old_namespace,
                new_namespace,
                ..
            } if declaration == "config" && old_namespace.is_empty() && new_namespace == "ns"
        ));
    }

    #[test]
    fn detects_namespace_removed() {
        let old = StorageSchema {
            declarations: vec![make_decl("config", Some(Durability::Instance), Some("ns"))],
        };
        let new = StorageSchema {
            declarations: vec![make_decl("config", Some(Durability::Instance), None)],
        };
        let comparison = compare_storage_schemas(
            &old,
            &StorageInference::default(),
            &new,
            &StorageInference::default(),
        );
        assert_eq!(comparison.cross_findings.len(), 1);
        assert!(matches!(
            &comparison.cross_findings[0],
            SchemaMismatch::NamespaceChanged {
                declaration,
                old_namespace,
                new_namespace,
                ..
            } if declaration == "config" && old_namespace == "ns" && new_namespace.is_empty()
        ));
    }

    #[test]
    fn no_cross_findings_when_schemas_unchanged() {
        let schema = StorageSchema {
            declarations: vec![make_decl(
                "counter",
                Some(Durability::Persistent),
                Some("myns"),
            )],
        };
        let comparison = compare_storage_schemas(
            &schema,
            &StorageInference::default(),
            &schema,
            &StorageInference::default(),
        );
        assert!(comparison.cross_findings.is_empty());
    }

    #[test]
    fn schema_with_namespace_field_roundtrips_json() {
        let json = r#"{"declarations":[{"name":"bal","operation":"set","durability":"persistent","namespace":"v1"}]}"#;
        let schema = StorageSchema::from_json(json).expect("parses");
        assert_eq!(schema.declarations[0].namespace.as_deref(), Some("v1"));
        let roundtripped = serde_json::to_string(&schema).unwrap();
        assert!(roundtripped.contains("\"namespace\":\"v1\""));
    }

    #[test]
    fn schema_without_namespace_field_roundtrips_json() {
        let json = r#"{"declarations":[{"name":"bal","operation":"set"}]}"#;
        let schema = StorageSchema::from_json(json).expect("parses");
        assert_eq!(schema.declarations[0].namespace, None);
    }

    #[test]
    fn render_markdown_includes_cross_findings_section() {
        let old = StorageSchema {
            declarations: vec![make_decl("k", Some(Durability::Persistent), None)],
        };
        let new = StorageSchema {
            declarations: vec![make_decl("k", Some(Durability::Temporary), None)],
        };
        let comparison = compare_storage_schemas(
            &old,
            &StorageInference::default(),
            &new,
            &StorageInference::default(),
        );
        let md = comparison.render_markdown();
        assert!(md.contains("Cross-Schema Findings"));
        assert!(md.contains("persistent"));
        assert!(md.contains("temporary"));
    }

    #[test]
    fn durability_change_consequence_covers_all_transitions() {
        use Durability::{Instance, Persistent, Temporary};
        for &(old, new) in &[
            (Persistent, Temporary),
            (Persistent, Instance),
            (Temporary, Persistent),
            (Temporary, Instance),
            (Instance, Persistent),
            (Instance, Temporary),
        ] {
            let msg = durability_change_consequence(old, new);
            assert!(
                !msg.is_empty(),
                "consequence string must be non-empty for {old:?} → {new:?}"
            );
        }
    }

    #[test]
    fn both_durability_and_namespace_changes_reported() {
        let old = StorageSchema {
            declarations: vec![make_decl("entry", Some(Durability::Persistent), Some("a"))],
        };
        let new = StorageSchema {
            declarations: vec![make_decl("entry", Some(Durability::Temporary), Some("b"))],
        };
        let comparison = compare_storage_schemas(
            &old,
            &StorageInference::default(),
            &new,
            &StorageInference::default(),
        );
        // Both a DurabilityChanged and a NamespaceChanged should be reported.
        assert_eq!(comparison.cross_findings.len(), 2);
        let has_durability = comparison
            .cross_findings
            .iter()
            .any(|f| matches!(f, SchemaMismatch::DurabilityChanged { .. }));
        let has_namespace = comparison
            .cross_findings
            .iter()
            .any(|f| matches!(f, SchemaMismatch::NamespaceChanged { .. }));
        assert!(has_durability, "expected DurabilityChanged finding");
        assert!(has_namespace, "expected NamespaceChanged finding");
    }
}

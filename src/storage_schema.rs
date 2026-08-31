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
    StorageSchemaComparison {
        old: old_schema.reconcile(old_inference),
        new: new_schema.reconcile(new_inference),
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSchemaComparison {
    pub old: StorageReconciliation,
    pub new: StorageReconciliation,
}

impl StorageSchemaComparison {
    pub fn is_compatible(&self) -> bool {
        self.old.is_compatible() && self.new.is_compatible()
    }
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({ "compatible": self.is_compatible(), "old": self.old.to_json_value(), "new": self.new.to_json_value() })
    }
    pub fn render_text(&self) -> String {
        format!(
            "old:\n{}new:\n{}",
            self.old.render_text(),
            self.new.render_text()
        )
    }
    pub fn render_markdown(&self) -> String {
        format!(
            "# Storage Schema Comparison\n\n### Old\n\n{}\n### New\n\n{}",
            self.old.render_markdown(),
            self.new.render_markdown()
        )
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
}

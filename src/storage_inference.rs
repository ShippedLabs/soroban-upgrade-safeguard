//! Conservative static analysis of Soroban SDK storage host calls.
//!
//! The WASM ABI represents storage keys and values as generic `Val`s.  A
//! reliable type can therefore only be reported when data-flow evidence ties a
//! call operand to a known source.  This module deliberately records an
//! explicit coverage gap for every recognized call whose operands cannot be
//! proven, rather than guessing from nearby instructions.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use wasmparser::{Operator, Parser, Payload};

const DEFAULT_MAX_WASM_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_INSTRUCTIONS: usize = 2_000_000;
const DEFAULT_MAX_CALLS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    Instance,
    Persistent,
    Temporary,
}

impl Durability {
    pub fn label(self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::Persistent => "persistent",
            Self::Temporary => "temporary",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageOperation {
    Get,
    Set,
    Remove,
    Has,
    ExtendTtl,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageObservation {
    pub function: String,
    pub operation: StorageOperation,
    pub durability: Option<Durability>,
    pub key_type: Option<String>,
    pub value_type: Option<String>,
    pub confidence: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageGap {
    pub function: Option<String>,
    pub reason: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageInference {
    pub observations: Vec<StorageObservation>,
    pub gaps: Vec<CoverageGap>,
    pub instruction_count: usize,
    pub call_count: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct InferenceLimits {
    pub max_wasm_bytes: usize,
    pub max_instructions: usize,
    pub max_calls: usize,
}

impl Default for InferenceLimits {
    fn default() -> Self {
        Self {
            max_wasm_bytes: DEFAULT_MAX_WASM_BYTES,
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            max_calls: DEFAULT_MAX_CALLS,
        }
    }
}

/// Analyze a WASM module using the default safety limits.
pub fn infer_storage(bytes: &[u8]) -> Result<StorageInference, String> {
    infer_storage_with_limits(bytes, InferenceLimits::default())
}

/// Analyze imports and code calls. Unknown or indirect data-flow is a gap.
pub fn infer_storage_with_limits(
    bytes: &[u8],
    limits: InferenceLimits,
) -> Result<StorageInference, String> {
    if bytes.len() > limits.max_wasm_bytes {
        return Err(format!(
            "WASM exceeds storage analysis limit of {} bytes",
            limits.max_wasm_bytes
        ));
    }

    let mut result = StorageInference::default();
    let mut imports = BTreeMap::<u32, (String, StorageOperation, Option<Durability>)>::new();
    let mut function_names = BTreeSet::<u32>::new();
    let mut imported_functions = 0u32;
    let mut current_function = None::<String>;

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| format!("storage analysis parse error: {e}"))?;
        match payload {
            Payload::ImportSection(section) => {
                for import in section {
                    let import = import.map_err(|e| format!("storage import parse error: {e}"))?;
                    if let wasmparser::TypeRef::Func(_) = import.ty {
                        let name = format!("{}::{}", import.module, import.name);
                        if let Some((operation, durability)) = classify_host_call(&name) {
                            imports.insert(imported_functions, (name, operation, durability));
                        }
                        imported_functions += 1;
                    }
                }
            }
            Payload::ExportSection(section) => {
                for export in section {
                    let export = export.map_err(|e| format!("storage export parse error: {e}"))?;
                    if let wasmparser::ExternalKind::Func = export.kind {
                        function_names.insert(export.index);
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let function = current_function
                    .clone()
                    .unwrap_or_else(|| format!("function_{}", result.instruction_count));
                let mut reader = body.get_operators_reader().map_err(|e| e.to_string())?;
                while !reader.eof() {
                    if result.instruction_count >= limits.max_instructions {
                        result.truncated = true;
                        result.gaps.push(CoverageGap {
                            function: Some(function.clone()),
                            reason: "instruction limit reached".into(),
                            evidence: vec![],
                        });
                        return Ok(result);
                    }
                    let op = reader.read().map_err(|e| e.to_string())?;
                    result.instruction_count += 1;
                    if let Operator::Call { function_index } = op {
                        result.call_count += 1;
                        if result.call_count > limits.max_calls {
                            result.truncated = true;
                            result.gaps.push(CoverageGap {
                                function: Some(function.clone()),
                                reason: "call limit reached".into(),
                                evidence: vec![],
                            });
                            return Ok(result);
                        }
                        if let Some((name, operation, durability)) = imports.get(&function_index) {
                            result.observations.push(StorageObservation {
                                function: function.clone(),
                                operation: *operation,
                                durability: *durability,
                                key_type: None,
                                value_type: None,
                                confidence: "host_call_only".into(),
                                evidence: vec![format!("call {name}")],
                            });
                            result.gaps.push(CoverageGap {
                                function: Some(function.clone()),
                                reason: "storage key/value data flow is not provable from generic Val operands".into(),
                                evidence: vec![format!("call {name}")],
                            });
                        }
                    } else if matches!(op, Operator::CallIndirect { .. }) {
                        result.gaps.push(CoverageGap {
                            function: Some(function.clone()),
                            reason: "indirect call prevents reliable storage reachability analysis"
                                .into(),
                            evidence: vec!["call_indirect".into()],
                        });
                    }
                }
                current_function = Some(format!("function_{}", result.instruction_count));
            }
            _ => {}
        }
    }
    if !function_names.is_empty() && result.observations.is_empty() && !imports.is_empty() {
        result.gaps.push(CoverageGap {
            function: None,
            reason: "recognized storage imports were not reachable from parsed function bodies"
                .into(),
            evidence: vec![],
        });
    }
    Ok(result)
}

fn classify_host_call(name: &str) -> Option<(StorageOperation, Option<Durability>)> {
    let lower = name.to_ascii_lowercase();
    if !lower.contains("storage") && !lower.contains("contract_data") {
        return None;
    }
    let durability = if lower.contains("instance") {
        Some(Durability::Instance)
    } else if lower.contains("temporary") || lower.contains("temp") {
        Some(Durability::Temporary)
    } else if lower.contains("persistent") {
        Some(Durability::Persistent)
    } else {
        None
    };
    let operation = if lower.contains("extend_ttl") || lower.contains("extendttl") {
        StorageOperation::ExtendTtl
    } else if lower.contains("remove") || lower.contains("del") {
        StorageOperation::Remove
    } else if lower.contains("set") || lower.contains("put") {
        StorageOperation::Set
    } else if lower.contains("has") || lower.contains("contains") {
        StorageOperation::Has
    } else if lower.contains("get") || lower.contains("read") {
        StorageOperation::Get
    } else {
        StorageOperation::Unknown
    };
    Some((operation, durability))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_modules_before_parsing() {
        let error = infer_storage_with_limits(
            &[0; 8],
            InferenceLimits {
                max_wasm_bytes: 4,
                ..Default::default()
            },
        )
        .expect_err("limit must be enforced");
        assert!(error.contains("limit"));
    }

    #[test]
    fn host_name_classifier_is_conservative() {
        assert_eq!(
            classify_host_call("env::storage_set_instance"),
            Some((StorageOperation::Set, Some(Durability::Instance)))
        );
        assert_eq!(classify_host_call("env::random"), None);
    }

    #[test]
    fn classifies_all_supported_durabilities() {
        assert_eq!(
            classify_host_call("env::storage_get_persistent"),
            Some((StorageOperation::Get, Some(Durability::Persistent)))
        );
        assert_eq!(
            classify_host_call("env::storage_remove_temporary"),
            Some((StorageOperation::Remove, Some(Durability::Temporary)))
        );
        assert_eq!(Durability::Instance.label(), "instance");
    }
}

// SPDX-License-Identifier: MIT

//! Stable, deterministic, no-network entry points for native-language
//! bindings (`bindings/python` via PyO3, `bindings/node` via napi-rs).
//!
//! The crate root's own public functions (`compare_wasm_bytes`,
//! `compare_wasm_files_with_options`, ...) return `anyhow::Result`, which
//! is the right shape for a CLI but loses structure at a language
//! boundary: `anyhow::anyhow!("{}", e)` (used in a few of their internal
//! call sites) formats an error into a message and discards the original
//! typed [`crate::error::Error`], so a binding built on top of them would
//! have nothing left to convert but a string. Everything in this module
//! instead returns `Result<_, crate::error::Error>`, so each binding can
//! map every failure to its own typed exception/error object field by
//! field, never by parsing prose.
//!
//! Scope is intentionally narrower than [`crate::CompareOptions`]: no RPC
//! inputs (bindings are no-network and deterministic by construction) and
//! no lineage store (a local but broader surface left for a later pass).
//! [`CompareRequest`] takes every input as an owned, plain value — no
//! lifetimes, no borrowed config structs, no file paths implied — so a
//! binding can build one entirely from caller-supplied bytes/strings.
//!
//! [`compare_bytes`] and [`compare_files`] return a [`crate::report::SafetyReport`].
//! Converting it onward into a native Python/JS value is each binding's
//! job (see `bindings/python/src/lib.rs` and `bindings/node/src/lib.rs`):
//! both walk the report's serde data model directly into native
//! dict/object values (via `pythonize` and napi-rs's JSON support,
//! respectively) rather than serializing to a JSON *string* and handing
//! the host language a blob to re-parse.

use std::path::Path;

use crate::error::Error;
use crate::report::SafetyReport;
use crate::spec::ContractSpec;
use crate::storage_schema::{compare_storage_schemas, SchemaFormat, StorageSchema};
use crate::suppression::SuppressionConfig;
use crate::{diff, loader, parser};

/// A storage schema input, as raw source text plus its format. Bindings
/// hand over whatever the caller gave them (a file's content, or a string
/// built in-language) rather than a path, so supplying one implies no
/// filesystem access on the Rust side.
#[derive(Debug, Clone)]
pub struct SchemaSource {
    pub source: String,
    pub format: SchemaFormat,
}

/// Request model for a single comparison.
///
/// Every field has a meaningful default (`CompareRequest::default()` is a
/// bare structural comparison, no policy applied), so bindings can expose
/// it as an options object where every key is optional.
#[derive(Debug, Default, Clone)]
pub struct CompareRequest {
    /// Explain mode: include human-readable remediation guidance in each
    /// finding.
    pub explain: bool,
    /// Strict mode: findings that are merely suppressed (acknowledged but
    /// not migrated) still gate `is_safe`.
    pub strict: bool,
    /// The contract's name, used to scope migrations declared with
    /// `contracts = [..]` in a suppression config shared across several
    /// contracts. `None` matches only migrations with no `contracts` key.
    pub contract: Option<String>,
    /// Suppression config, as the raw text of a `.safeguard.toml`-shaped
    /// document. `None` applies no suppressions.
    pub suppressions_toml: Option<String>,
    /// Storage schema for the old build. Must be supplied together with
    /// `new_storage_schema` or not at all.
    pub old_storage_schema: Option<SchemaSource>,
    /// Storage schema for the new build. Must be supplied together with
    /// `old_storage_schema` or not at all.
    pub new_storage_schema: Option<SchemaSource>,
}

impl CompareRequest {
    fn resolve_suppressions(&self) -> Result<SuppressionConfig, Error> {
        match &self.suppressions_toml {
            Some(toml_text) => SuppressionConfig::from_toml_str(toml_text),
            None => Ok(SuppressionConfig::default()),
        }
    }

    fn resolve_storage_schemas(&self) -> Result<Option<(StorageSchema, StorageSchema)>, Error> {
        match (&self.old_storage_schema, &self.new_storage_schema) {
            (None, None) => Ok(None),
            (Some(old), Some(new)) => {
                let old_schema =
                    StorageSchema::from_str(&old.source, old.format).map_err(|details| {
                        Error::InvalidInput {
                            details: format!("Invalid old storage schema: {details}"),
                        }
                    })?;
                let new_schema =
                    StorageSchema::from_str(&new.source, new.format).map_err(|details| {
                        Error::InvalidInput {
                            details: format!("Invalid new storage schema: {details}"),
                        }
                    })?;
                Ok(Some((old_schema, new_schema)))
            }
            _ => Err(Error::InvalidInput {
                details:
                    "old_storage_schema and new_storage_schema must be supplied together, or not at all"
                        .to_string(),
            }),
        }
    }
}

/// Compare two Soroban contract builds given as raw WASM bytes.
///
/// Deterministic and network-free: every input is either bytes already in
/// memory or a plain string the caller supplied, and nothing here performs
/// I/O beyond what the caller already did to obtain `old_wasm`/`new_wasm`.
pub fn compare_bytes(
    old_wasm: &[u8],
    new_wasm: &[u8],
    request: &CompareRequest,
) -> Result<SafetyReport, Error> {
    let suppressions = request.resolve_suppressions()?;
    let storage_schemas = request.resolve_storage_schemas()?;

    let old_meta = parser::extract_metadata(old_wasm)?;
    let new_meta = parser::extract_metadata(new_wasm)?;

    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);

    let mut diff_report = diff::compare(&old_spec, &new_spec);
    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );
    diff::compare_host_imports(
        &old_meta.host_imports,
        &new_meta.host_imports,
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );
    diff::compare_runtime_surfaces(
        &old_meta.runtime_surface,
        &new_meta.runtime_surface,
        &mut diff_report,
    );

    let mut safety_report = SafetyReport::with_suppressions_with_specs(
        &diff_report,
        &suppressions,
        request.explain,
        request.strict,
        &old_spec,
        &new_spec,
        request.contract.as_deref(),
    );
    safety_report.scope.exported_interface = true;
    safety_report.scope.env_metadata = old_meta.env_meta.is_some() || new_meta.env_meta.is_some();
    safety_report.old_spec_summary = Some(old_spec.summary());
    safety_report.new_spec_summary = Some(new_spec.summary());

    if let Some((old_schema, new_schema)) = storage_schemas {
        let storage_comparison = compare_storage_schemas(
            &old_schema,
            &old_meta.storage,
            &new_schema,
            &new_meta.storage,
        );
        safety_report.apply_storage_schema_comparison(
            &storage_comparison,
            &suppressions,
            request.explain,
            request.strict,
        );
    }

    Ok(safety_report)
}

/// Compare two Soroban contract builds read from WASM files on disk.
///
/// The only I/O this function performs is reading exactly these two paths;
/// it does not consult the network, a cache directory, or any other
/// ambient state.
pub fn compare_files(
    old_path: &Path,
    new_path: &Path,
    request: &CompareRequest,
) -> Result<SafetyReport, Error> {
    let old = loader::load_wasm(old_path)?;
    let new = loader::load_wasm(new_path)?;
    compare_bytes(&old.bytes, &new.bytes, request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("wasm")
            .join(name);
        std::fs::read(path).expect("fixture WASM should exist")
    }

    #[test]
    fn compare_bytes_matches_the_crate_root_convenience_function() {
        let old = fixture("v1.wasm");
        let new = fixture("v2.wasm");

        let via_binding_api = compare_bytes(&old, &new, &CompareRequest::default())
            .expect("binding_api::compare_bytes should succeed");
        // `binding_api::compare_bytes` mirrors `compare_wasm_bytes_with_options`
        // (env metadata, host imports, and runtime surface are all compared),
        // not the narrower `compare_wasm_bytes`, so this is the apples-to-apples
        // baseline for a request carrying no extra policy.
        let via_root_api = crate::compare_wasm_bytes_with_options(
            &old,
            &new,
            &crate::CompareOptions::default(),
        )
        .expect("crate::compare_wasm_bytes_with_options should succeed");

        assert_eq!(via_binding_api.is_safe, via_root_api.is_safe);
        assert_eq!(
            via_binding_api.critical_count,
            via_root_api.critical_count
        );
        assert_eq!(
            serde_json::to_value(via_binding_api.to_json()).unwrap(),
            serde_json::to_value(via_root_api.to_json()).unwrap()
        );
    }

    #[test]
    fn invalid_storage_schema_is_a_typed_error_not_a_panic() {
        let old = fixture("v1.wasm");
        let new = fixture("v2.wasm");

        let request = CompareRequest {
            old_storage_schema: Some(SchemaSource {
                source: "not valid toml {{{".to_string(),
                format: SchemaFormat::Toml,
            }),
            new_storage_schema: Some(SchemaSource {
                source: "".to_string(),
                format: SchemaFormat::Toml,
            }),
            ..Default::default()
        };

        let err = compare_bytes(&old, &new, &request).expect_err("invalid schema must error");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidInput);
    }

    #[test]
    fn mismatched_schema_pair_is_rejected() {
        let old = fixture("v1.wasm");
        let new = fixture("v2.wasm");

        let request = CompareRequest {
            old_storage_schema: Some(SchemaSource {
                source: "".to_string(),
                format: SchemaFormat::Toml,
            }),
            new_storage_schema: None,
            ..Default::default()
        };

        let err = compare_bytes(&old, &new, &request).expect_err("one-sided schema must error");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidInput);
    }
}

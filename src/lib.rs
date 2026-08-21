#[cfg(feature = "unstable")]
pub mod attestation;
#[cfg(not(feature = "unstable"))]
mod attestation;

#[cfg(feature = "unstable")]
pub mod call_abi;
#[cfg(not(feature = "unstable"))]
mod call_abi;

#[cfg(feature = "unstable")]
pub mod category;
#[cfg(not(feature = "unstable"))]
mod category;

#[cfg(feature = "unstable")]
pub mod color;
#[cfg(not(feature = "unstable"))]
mod color;

#[cfg(feature = "unstable")]
pub mod config;
#[cfg(not(feature = "unstable"))]
mod config;

#[cfg(feature = "unstable")]
pub mod dependency;
#[cfg(not(feature = "unstable"))]
mod dependency;

#[cfg(feature = "unstable")]
pub mod diff;
#[cfg(not(feature = "unstable"))]
mod diff;

#[cfg(feature = "unstable")]
pub mod empirical;
#[cfg(not(feature = "unstable"))]
mod empirical;

#[cfg(feature = "unstable")]
pub mod error;
#[cfg(not(feature = "unstable"))]
mod error;

#[cfg(feature = "unstable")]
pub mod interface_hash;
#[cfg(not(feature = "unstable"))]
mod interface_hash;

#[cfg(feature = "unstable")]
pub mod loader;
#[cfg(not(feature = "unstable"))]
mod loader;

#[cfg(feature = "unstable")]
pub mod limits;
#[cfg(not(feature = "unstable"))]
mod limits;

#[cfg(feature = "unstable")]
pub mod mapper;
#[cfg(not(feature = "unstable"))]
mod mapper;

#[cfg(feature = "unstable")]
pub mod parser;
#[cfg(not(feature = "unstable"))]
mod parser;

#[cfg(feature = "unstable")]
pub mod render;
#[cfg(not(feature = "unstable"))]
mod render;

#[cfg(feature = "unstable")]
pub mod report;
#[cfg(not(feature = "unstable"))]
mod report;

#[cfg(feature = "unstable")]
pub mod rpc;
#[cfg(not(feature = "unstable"))]
mod rpc;

#[cfg(feature = "unstable")]
pub mod rpc_retry;
#[cfg(not(feature = "unstable"))]
mod rpc_retry;

#[cfg(feature = "unstable")]
pub mod spec;
#[cfg(not(feature = "unstable"))]
mod spec;

#[cfg(feature = "unstable")]
pub mod spec_json;
#[cfg(not(feature = "unstable"))]
mod spec_json;

#[cfg(feature = "unstable")]
pub mod storage_inference;
#[cfg(not(feature = "unstable"))]
mod storage_inference;

#[cfg(feature = "unstable")]
pub mod storage_schema;
#[cfg(not(feature = "unstable"))]
mod storage_schema;

#[cfg(feature = "unstable")]
pub mod suppression;
#[cfg(not(feature = "unstable"))]
mod suppression;

// Stable public API exports at the root
pub use crate::attestation::{
    sign_statement, verify_artifacts, verify_signatures, ArtifactDigest, AttestationSigner,
    DsseEnvelope, Ed25519Signer, InTotoStatementV1, SafeguardPredicateV1, SignatureVerification,
    VerificationFailure, VerificationFailureKind, VerificationPolicy,
};
pub use crate::call_abi::{
    CallAbiBreak, CallAbiCompatibility, CallDirection, DirectionalCallVerdict,
};
pub use crate::diff::{Finding, Severity};
pub use crate::report::{ReportedFinding, SafetyReport};
pub use crate::storage_schema::{StorageReconciliation, StorageSchema, StorageSchemaComparison};

use std::path::Path;

use anyhow::{Context, Result};

use crate::spec::ContractSpec;
use crate::suppression::SuppressionConfig;

/// Infer and reconcile storage use for a single compiled contract.
pub fn analyze_wasm_storage_schema(
    wasm: &[u8],
    schema: &StorageSchema,
) -> Result<StorageReconciliation> {
    let metadata =
        parser::extract_metadata(wasm).context("Failed to analyze storage use in WASM")?;
    Ok(schema.reconcile(&metadata.storage))
}

/// Infer and reconcile storage use for both sides of an upgrade.
pub fn compare_wasm_storage_schemas(
    old_wasm: &[u8],
    old_schema: &StorageSchema,
    new_wasm: &[u8],
    new_schema: &StorageSchema,
) -> Result<StorageSchemaComparison> {
    let old = parser::extract_metadata(old_wasm)
        .context("Failed to analyze storage use in the old WASM")?;
    let new = parser::extract_metadata(new_wasm)
        .context("Failed to analyze storage use in the new WASM")?;
    Ok(storage_schema::compare_storage_schemas(
        old_schema,
        &old.storage,
        new_schema,
        &new.storage,
    ))
}

/// Compare two Soroban contract builds supplied as raw WASM byte slices.
pub fn compare_wasm_bytes(old_wasm: &[u8], new_wasm: &[u8]) -> Result<SafetyReport> {
    let old_meta = parser::extract_metadata(old_wasm)
        .context("Failed to extract metadata from the old WASM")?;
    let new_meta = parser::extract_metadata(new_wasm)
        .context("Failed to extract metadata from the new WASM")?;

    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);

    let diff_report = diff::compare(&old_spec, &new_spec);
    Ok(
        SafetyReport::new_with_specs(&diff_report, &old_spec, &new_spec)
            .with_interface_hashes(old_spec.interface_hash(), new_spec.interface_hash()),
    )
}

/// Compare two Soroban contract builds read from WASM files on disk.
pub fn compare_wasm_files(old_path: &Path, new_path: &Path) -> Result<SafetyReport> {
    let old = loader::load_wasm(old_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    let new = loader::load_wasm(new_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    compare_wasm_bytes(&old.bytes, &new.bytes)
}

/// Options for the analysis pipeline.
#[derive(Default)]
pub struct CompareOptions<'a> {
    pub suppressions: Option<&'a SuppressionConfig>,
    pub explain: bool,
    pub strict: bool,
}

/// Compare two Soroban contract builds supplied as raw WASM byte slices with options.
pub fn compare_wasm_bytes_with_options(
    old_wasm: &[u8],
    new_wasm: &[u8],
    options: &CompareOptions<'_>,
) -> Result<SafetyReport> {
    let empty_suppressions = SuppressionConfig::default();
    let suppressions = options.suppressions.unwrap_or(&empty_suppressions);

    let old_meta = parser::extract_metadata(old_wasm)
        .context("Failed to extract metadata from the old WASM")?;
    let new_meta = parser::extract_metadata(new_wasm)
        .context("Failed to extract metadata from the new WASM")?;

    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);

    let mut diff_report = diff::compare(&old_spec, &new_spec);

    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );

    let mut safety_report = SafetyReport::with_suppressions_with_specs(
        &diff_report,
        suppressions,
        options.explain,
        options.strict,
        &old_spec,
        &new_spec,
    );
    safety_report.old_spec_summary = Some(old_spec.summary());
    safety_report.new_spec_summary = Some(new_spec.summary());

    Ok(safety_report)
}

/// Compare two Soroban contract builds read from WASM files on disk with options.
pub fn compare_wasm_files_with_options(
    old_path: &Path,
    new_path: &Path,
    options: &CompareOptions<'_>,
) -> Result<SafetyReport> {
    let old = loader::load_wasm(old_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    let new = loader::load_wasm(new_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    compare_wasm_bytes_with_options(&old.bytes, &new.bytes, options)
}

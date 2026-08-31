//! # Soroban Upgrade Safeguard
//!
//! Library for analyzing and validating Soroban smart-contract upgrades on the
//! Stellar network. It detects breaking changes in storage layout, function
//! signatures, and event schemas before an upgrade is deployed.
//!
//! A breaking change has two independent axes in the output: whether a human
//! *acknowledged* it ([`suppression`]) and whether a migration *handles* it
//! ([`contract_migration`]). They are reported separately and never collapse
//! into one another.

#[cfg(feature = "unstable")]
pub mod attestation;
#[cfg(not(feature = "unstable"))]
mod attestation;

#[cfg(feature = "unstable")]
pub mod budget;
#[cfg(not(feature = "unstable"))]
mod budget;
pub mod bundle;
#[cfg(not(feature = "unstable"))]
mod bundle;

#[cfg(feature = "unstable")]
pub mod call_abi;
#[cfg(not(feature = "unstable"))]
mod call_abi;

#[cfg(feature = "unstable")]
pub mod capability;
#[cfg(not(feature = "unstable"))]
mod capability;

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

pub mod interface_hash;

#[cfg(feature = "unstable")]
pub mod jsonl;
#[cfg(not(feature = "unstable"))]
mod jsonl;

#[cfg(feature = "unstable")]
pub mod loader;
#[cfg(not(feature = "unstable"))]
mod loader;

#[cfg(feature = "unstable")]
pub mod limits;
#[cfg(not(feature = "unstable"))]
mod limits;

#[cfg(feature = "unstable")]
#[cfg(feature = "unstable")]
pub mod lint;
#[cfg(not(feature = "unstable"))]
mod lint;

#[cfg(feature = "unstable")]
pub mod manifest;
#[cfg(not(feature = "unstable"))]
mod manifest;

#[cfg(feature = "unstable")]
pub mod mapper;
#[cfg(not(feature = "unstable"))]
mod mapper;

#[cfg(feature = "unstable")]
pub mod contract_migration;
#[cfg(not(feature = "unstable"))]
mod contract_migration;

#[cfg(feature = "unstable")]
pub mod migration;
#[cfg(not(feature = "unstable"))]
mod migration;

#[cfg(feature = "unstable")]
pub mod oci;
#[cfg(not(feature = "unstable"))]
mod oci;

#[cfg(feature = "unstable")]
pub mod parser;
#[cfg(not(feature = "unstable"))]
mod parser;

#[cfg(feature = "unstable")]
pub mod preflight;
#[cfg(not(feature = "unstable"))]
mod preflight;

#[cfg(feature = "unstable")]
pub mod profile;
#[cfg(not(feature = "unstable"))]
mod profile;

#[cfg(feature = "unstable")]
pub mod redact;
#[cfg(not(feature = "unstable"))]
mod redact;

#[cfg(feature = "unstable")]
pub mod remote;
#[cfg(not(feature = "unstable"))]
mod remote;

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
pub mod rpc_bundle;
#[cfg(not(feature = "unstable"))]
mod rpc_bundle;

#[cfg(feature = "unstable")]
pub mod rpc_record;
#[cfg(not(feature = "unstable"))]
mod rpc_record;

#[cfg(feature = "unstable")]
pub mod runtime_surface;
#[cfg(not(feature = "unstable"))]
mod runtime_surface;

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

#[cfg(feature = "unstable")]
pub mod lineage;
#[cfg(not(feature = "unstable"))]
pub mod lineage;

#[cfg(feature = "unstable")]
pub mod watch_status;
#[cfg(not(feature = "unstable"))]
mod watch_status;

#[cfg(feature = "unstable")]
pub mod wasm_complexity;
#[cfg(not(feature = "unstable"))]
mod wasm_complexity;

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
pub use crate::lineage::{
    validate_candidate_against_lineage, HistoricalFinding, LineageRecord, LineageStore,
    LineageValidationReport, LiveStatus, LiveVersionPolicy,
};
pub use crate::oci::{
    OciArtifact, OciArtifactKind, OciFetchConfig, OciReference, OciSelector,
    MEDIA_TYPE_EXTRACTED_SPEC, MEDIA_TYPE_WASM,
};
pub use crate::remote::{
    default_cache_dir, fetch_verified, CacheStatus, FetchedArtifact, RemoteFetchConfig, RemoteRef,
};
pub use crate::report::{ReportedFinding, SafetyReport};
pub use crate::runtime_surface::{
    DataSegmentSummary, ElementSegmentSummary, GlobalDeclaration, MemoryDeclaration,
    RuntimeSurface, TableDeclaration,
};
pub use crate::spec_json::{InterfaceLockfile, INTERFACE_LOCKFILE_SCHEMA_VERSION};
pub use crate::storage_schema::{
    SchemaFormat, StorageReconciliation, StorageSchema, StorageSchemaComparison,
};

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

    let mut diff_report = diff::compare(&old_spec, &new_spec);
    diff::compare_runtime_surfaces(
        &old_meta.runtime_surface,
        &new_meta.runtime_surface,
        &mut diff_report,
    );

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
    pub storage_schemas: Option<(&'a StorageSchema, &'a StorageSchema)>,
    pub lineage_store: Option<&'a lineage::LineageStore>,
    /// The contract's name, used to scope migrations declared with
    /// `contracts = [..]` in a `.safeguard.toml` shared across several
    /// contracts. `None` matches only migrations with no `contracts` key.
    pub contract: Option<&'a str>,
    /// Complexity budgets for the WASM code section. When non-empty the
    /// profiler is invoked and exceeded entries gate `is_safe`.
    pub complexity_budget: Option<&'a crate::wasm_complexity::ComplexityBudgetConfig>,
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
        suppressions,
        options.explain,
        options.strict,
        &old_spec,
        &new_spec,
        options.contract,
    );
    safety_report.scope.exported_interface = true;
    safety_report.scope.env_metadata = old_meta.env_meta.is_some() || new_meta.env_meta.is_some();
    safety_report.old_spec_summary = Some(old_spec.summary());
    safety_report.new_spec_summary = Some(new_spec.summary());

    if let Some((old_schema, new_schema)) = options.storage_schemas {
        let storage_comparison = storage_schema::compare_storage_schemas(
            old_schema,
            &old_meta.storage,
            new_schema,
            &new_meta.storage,
        );
        safety_report.apply_storage_schema_comparison(
            &storage_comparison,
            suppressions,
            options.explain,
            options.strict,
        );
    }

    if let Some(store) = options.lineage_store {
        let lineage_report = lineage::validate_candidate_against_lineage(
            new_wasm,
            &new_spec,
            store,
            suppressions,
            options.strict,
        )?;
        safety_report.apply_lineage_report(
            &lineage_report,
            suppressions,
            options.explain,
            options.strict,
        );
    }

    // Run the WASM complexity profiler when a budget is configured, or
    // unconditionally when an empty budget is passed (so the profile still
    // appears in the report for informational purposes).
    if let Some(budget) = options.complexity_budget {
        safety_report.apply_complexity(old_wasm, new_wasm, budget);
    }

    Ok(safety_report)
}

/// Compare a Soroban contract build against a serialized interface lockfile.
///
/// Lockfile comparisons intentionally cover only the exported interface. A
/// lockfile contains no WASM metadata for host imports, runtime surface, or
/// environment metadata, so those axes are not inferred from the snapshot.
pub fn compare_wasm_against_interface_lockfile(
    lockfile_json: &str,
    new_wasm: &[u8],
    options: &CompareOptions<'_>,
) -> Result<SafetyReport> {
    let lockfile = InterfaceLockfile::from_json_str(lockfile_json)
        .map_err(|error| anyhow::anyhow!("Invalid interface lockfile: {error}"))?;
    let old_spec = lockfile
        .to_contract_spec()
        .map_err(|error| anyhow::anyhow!("Invalid interface lockfile: {error}"))?;
    let new_meta = parser::extract_metadata(new_wasm)
        .context("Failed to extract metadata from the candidate WASM")?;
    let new_spec = ContractSpec::from_entries(&new_meta.spec);
    let diff_report = diff::compare(&old_spec, &new_spec);
    let empty_suppressions = SuppressionConfig::default();
    let suppressions = options.suppressions.unwrap_or(&empty_suppressions);
    let mut report = SafetyReport::with_suppressions_with_specs(
        &diff_report,
        suppressions,
        options.explain,
        options.strict,
        &old_spec,
        &new_spec,
        options.contract,
    )
    .with_interface_hashes(old_spec.interface_hash(), new_spec.interface_hash());
    report.scope.exported_interface = true;
    report.old_spec_summary = Some(old_spec.summary());
    report.new_spec_summary = Some(new_spec.summary());
    Ok(report)
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

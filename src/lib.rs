//! # Soroban Upgrade Safeguard
//!
//! Library for analyzing and validating Soroban smart-contract upgrades on the
//! Stellar network. It detects breaking changes in storage layout, function
//! signatures, and event schemas before an upgrade is deployed.
//!
//! The crate is split into focused modules that form an analysis pipeline:
//!
//! - [`loader`] reads and validates raw WASM binaries from disk.
//! - [`parser`] extracts the Soroban `contractspecv0` custom section and decodes
//!   its XDR entries.
//! - [`spec`] organizes the decoded entries into a [`spec::ContractSpec`].
//! - [`mapper`] builds type-dependency graphs used for cascade detection.
//! - [`diff`] compares two specs and produces a list of findings.
//! - [`report`] aggregates findings into a [`report::SafetyReport`].
//!
//! Most callers only need the two top-level helpers, [`compare_wasm_files`] and
//! [`compare_wasm_bytes`], which run the whole pipeline and return a structured
//! [`report::SafetyReport`]. The individual modules are public so that more
//! specialized tools (CI bots, dashboards, custom checks) can reuse any single
//! stage without shelling out to the CLI binary.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//!
//! let report = soroban_upgrade_safeguard::compare_wasm_files(
//!     Path::new("./wasm/v1.wasm"),
//!     Path::new("./wasm/v2.wasm"),
//! )?;
//!
//! if !report.is_safe {
//!     eprintln!("Upgrade is unsafe: {} critical issue(s)", report.critical_count);
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod color;
pub mod diff;
pub mod limits;
pub mod loader;
pub mod mapper;
pub mod parser;
pub mod report;
pub mod spec;
pub mod suppression;
pub mod view;

use std::path::Path;

use anyhow::{Context, Result};

use crate::report::SafetyReport;
use crate::spec::ContractSpec;

pub use crate::limits::{LimitError, ResourcePolicy};

/// Compare two Soroban contract builds supplied as raw WASM byte slices.
///
/// This runs the full analysis pipeline — metadata extraction, spec building,
/// structural diffing, and cascade detection — and returns an aggregated
/// [`SafetyReport`]. Use this overload when the WASM is already in memory (for
/// example fetched over the network); use [`compare_wasm_files`] to read the
/// builds from disk.
///
/// `old_wasm` is the currently deployed (on-chain) contract and `new_wasm` is
/// the candidate upgrade.
///
/// # Errors
///
/// Returns an error if either input is not a parseable WASM module or if the
/// embedded `contractspecv0` section cannot be decoded.
pub fn compare_wasm_bytes(old_wasm: &[u8], new_wasm: &[u8]) -> Result<SafetyReport> {
    compare_wasm_bytes_with_policy(old_wasm, new_wasm, &ResourcePolicy::default())
}

/// Like [`compare_wasm_bytes`], but bounds decoding and every recursive type walk
/// by an explicit [`ResourcePolicy`].
///
/// Untrusted WASM (a file, or bytes fetched over RPC) can declare oversized XDR
/// lengths or arbitrarily nested types. Threading `policy` through metadata
/// extraction and the diff makes those inputs fail with a controlled
/// [`LimitError`] instead of exhausting memory or overflowing the stack.
///
/// # Errors
///
/// Returns a [`LimitError`] (recoverable via [`anyhow::Error::downcast_ref`]) when
/// the input exceeds a configured limit, or an ordinary error if either input is
/// not a parseable WASM module or its `contractspecv0` section cannot be decoded.
pub fn compare_wasm_bytes_with_policy(
    old_wasm: &[u8],
    new_wasm: &[u8],
    policy: &ResourcePolicy,
) -> Result<SafetyReport> {
    let old_meta = parser::extract_metadata_with_policy(old_wasm, policy)
        .context("Failed to extract metadata from the old WASM")?;
    let new_meta = parser::extract_metadata_with_policy(new_wasm, policy)
        .context("Failed to extract metadata from the new WASM")?;

    let old_spec = ContractSpec::from_entries(&old_meta.spec);
    let new_spec = ContractSpec::from_entries(&new_meta.spec);

    let diff_report = diff::compare_with_policy(&old_spec, &new_spec, policy)?;
    Ok(SafetyReport::new(&diff_report))
}

/// Compare two Soroban contract builds read from WASM files on disk.
///
/// The files are validated as WASM binaries (via [`loader::load_wasm`]) before
/// being analyzed. This is the path used by the CLI binary and is the most
/// convenient entry point for callers that have the builds on disk.
///
/// `old_path` points at the currently deployed (on-chain) contract and
/// `new_path` at the candidate upgrade.
///
/// # Errors
///
/// Returns an error if either file is missing, is not a valid WASM binary, or
/// if its embedded contract spec cannot be decoded.
pub fn compare_wasm_files(old_path: &Path, new_path: &Path) -> Result<SafetyReport> {
    compare_wasm_files_with_policy(old_path, new_path, &ResourcePolicy::default())
}

/// Like [`compare_wasm_files`], but bounds decoding and every recursive type walk
/// by an explicit [`ResourcePolicy`]. See [`compare_wasm_bytes_with_policy`].
pub fn compare_wasm_files_with_policy(
    old_path: &Path,
    new_path: &Path,
    policy: &ResourcePolicy,
) -> Result<SafetyReport> {
    let old = loader::load_wasm(old_path)?;
    let new = loader::load_wasm(new_path)?;
    compare_wasm_bytes_with_policy(&old.bytes, &new.bytes, policy)
}

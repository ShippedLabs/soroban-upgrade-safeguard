// SPDX-License-Identifier: MIT

//! Node.js bindings for the `soroban-upgrade-safeguard` comparison
//! engine, built on [napi-rs](https://napi.rs).
//!
//! Comparison functions return a *tagged result object*
//! (`{ ok, report, error }`) rather than throwing: napi-rs can throw a JS
//! `Error`, but only with a plain message string, which would force a
//! caller wanting structured failure information (`kind`, `details`) back
//! into parsing prose — exactly the "lossy string parsing" this binding
//! is meant to avoid. The JS-side wrapper in `index.js` turns this into
//! the usual try/catch ergonomics by throwing `SafeguardError` (a real
//! class with `.kind`/`.details` properties) when `ok` is `false`, so
//! most callers never see the tagged object directly.
//!
//! The report itself is returned as a native JS value built directly from
//! the Rust report's `serde` data model (`napi`'s `serde-json` feature),
//! never as a JSON string the caller has to `JSON.parse()`.
//!
//! This module is intentionally thin: all comparison logic lives in
//! `soroban_upgrade_safeguard::binding_api`, which this crate wraps
//! without reimplementing or duplicating it.

#[macro_use]
extern crate napi_derive;

use napi::bindgen_prelude::Buffer;
use napi::Result as NapiResult;

use soroban_upgrade_safeguard::binding_api::{self, CompareRequest, SchemaSource};
use soroban_upgrade_safeguard::error::Error as SafeguardCoreError;
use soroban_upgrade_safeguard::storage_schema::SchemaFormat;

/// Options accepted by `compareBytes`/`compareFiles`. Every field is
/// optional; omitting all of them runs a bare structural comparison with
/// no suppression policy applied.
#[napi(object)]
#[derive(Default)]
pub struct CompareJsOptions {
    pub explain: Option<bool>,
    pub strict: Option<bool>,
    pub contract: Option<String>,
    pub suppressions_toml: Option<String>,
    pub old_storage_schema: Option<String>,
    pub old_storage_schema_format: Option<String>,
    pub new_storage_schema: Option<String>,
    pub new_storage_schema_format: Option<String>,
}

/// Structured failure payload. `kind` is the stable string form of
/// `soroban_upgrade_safeguard::error::ErrorKind` (e.g. `"WasmValidation"`,
/// `"InvalidInput"`) — match on it, not on `details`, which is free text
/// for humans and may change wording between releases.
#[napi(object)]
pub struct SafeguardErrorPayload {
    pub kind: String,
    pub details: String,
}

/// Tagged result: exactly one of `report`/`error` is present, selected by
/// `ok`. See the module docs for why this shape exists instead of a
/// thrown exception.
#[napi(object)]
pub struct CompareOutcome {
    pub ok: bool,
    pub report: Option<serde_json::Value>,
    pub error: Option<SafeguardErrorPayload>,
}

fn ok_outcome(report: serde_json::Value) -> CompareOutcome {
    CompareOutcome {
        ok: true,
        report: Some(report),
        error: None,
    }
}

fn err_outcome(err: SafeguardCoreError) -> CompareOutcome {
    CompareOutcome {
        ok: false,
        report: None,
        error: Some(SafeguardErrorPayload {
            kind: format!("{:?}", err.kind()),
            details: err.to_string(),
        }),
    }
}

fn parse_schema_format(value: &str) -> Result<SchemaFormat, SafeguardCoreError> {
    match value.to_ascii_lowercase().as_str() {
        "toml" => Ok(SchemaFormat::Toml),
        "json" => Ok(SchemaFormat::Json),
        other => Err(SafeguardCoreError::invalid_input(format!(
            "Unknown storage schema format '{other}'; expected 'toml' or 'json'"
        ))),
    }
}

fn build_request(options: Option<CompareJsOptions>) -> Result<CompareRequest, SafeguardCoreError> {
    let options = options.unwrap_or_default();

    let schema_pair = match (options.old_storage_schema, options.new_storage_schema) {
        (Some(old_src), Some(new_src)) => {
            let old_fmt = parse_schema_format(
                options.old_storage_schema_format.as_deref().unwrap_or("toml"),
            )?;
            let new_fmt = parse_schema_format(
                options.new_storage_schema_format.as_deref().unwrap_or("toml"),
            )?;
            (
                Some(SchemaSource {
                    source: old_src,
                    format: old_fmt,
                }),
                Some(SchemaSource {
                    source: new_src,
                    format: new_fmt,
                }),
            )
        }
        (None, None) => (None, None),
        _ => {
            return Err(SafeguardCoreError::invalid_input(
                "old_storage_schema and new_storage_schema must be supplied together, or not at all",
            ))
        }
    };

    Ok(CompareRequest {
        explain: options.explain.unwrap_or(false),
        strict: options.strict.unwrap_or(false),
        contract: options.contract,
        suppressions_toml: options.suppressions_toml,
        old_storage_schema: schema_pair.0,
        new_storage_schema: schema_pair.1,
    })
}

fn report_to_json(
    report: &soroban_upgrade_safeguard::SafetyReport,
) -> Result<serde_json::Value, SafeguardCoreError> {
    serde_json::to_value(report.to_json())
        .map_err(|e| SafeguardCoreError::integrity(format!("Failed to convert report to JSON: {e}")))
}

/// Compare two Soroban contract builds given as raw WASM bytes.
#[napi]
pub fn compare_bytes(
    old_wasm: Buffer,
    new_wasm: Buffer,
    options: Option<CompareJsOptions>,
) -> NapiResult<CompareOutcome> {
    let outcome = match build_request(options) {
        Ok(request) => match binding_api::compare_bytes(&old_wasm, &new_wasm, &request) {
            Ok(report) => match report_to_json(&report) {
                Ok(json) => ok_outcome(json),
                Err(e) => err_outcome(e),
            },
            Err(e) => err_outcome(e),
        },
        Err(e) => err_outcome(e),
    };
    Ok(outcome)
}

/// Compare two Soroban contract builds read from WASM files on disk.
///
/// The only I/O this performs is reading exactly `old_path`/`new_path`; it
/// never consults the network or a cache directory.
#[napi]
pub fn compare_files(
    old_path: String,
    new_path: String,
    options: Option<CompareJsOptions>,
) -> NapiResult<CompareOutcome> {
    let outcome = match build_request(options) {
        Ok(request) => {
            match binding_api::compare_files(
                std::path::Path::new(&old_path),
                std::path::Path::new(&new_path),
                &request,
            ) {
                Ok(report) => match report_to_json(&report) {
                    Ok(json) => ok_outcome(json),
                    Err(e) => err_outcome(e),
                },
                Err(e) => err_outcome(e),
            }
        }
        Err(e) => err_outcome(e),
    };
    Ok(outcome)
}

/// The version of `soroban-upgrade-safeguard` (the Rust engine) that this
/// addon was built against. See `docs/bindings.md` for the
/// version-compatibility policy between this number and the npm
/// package's own version.
#[napi]
pub fn engine_version() -> String {
    soroban_upgrade_safeguard::ENGINE_VERSION.to_string()
}

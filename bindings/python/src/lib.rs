// SPDX-License-Identifier: MIT

//! Python bindings for the `soroban-upgrade-safeguard` comparison engine,
//! built on PyO3.
//!
//! Every comparison function returns a plain Python `dict`/`list` object
//! graph built directly from the Rust report's `serde` data model via
//! [`pythonize`] — never a JSON *string* the caller has to `json.loads()`
//! itself — and every failure raises [`SafeguardError`], a typed exception
//! carrying `.kind` (a stable string matching
//! `soroban_upgrade_safeguard::error::ErrorKind`) and `.details`, rather
//! than only a formatted message string.
//!
//! This module is intentionally thin: all comparison logic lives in
//! `soroban_upgrade_safeguard::binding_api`, which this crate wraps
//! without reimplementing or duplicating it.

use pyo3::exceptions::PyException;
use pyo3::prelude::*;

use soroban_upgrade_safeguard::binding_api::{self, CompareRequest, SchemaSource};
use soroban_upgrade_safeguard::error::Error as SafeguardCoreError;
use soroban_upgrade_safeguard::storage_schema::SchemaFormat;

/// Typed exception raised for every failure from this module.
///
/// `kind` is the stable string form of
/// `soroban_upgrade_safeguard::error::ErrorKind` (e.g. `"WasmValidation"`,
/// `"InvalidInput"`) — match on it instead of parsing `.details` or
/// `str(exc)`, since `details` is free-text intended for humans and may
/// change wording between releases.
#[pyclass(extends = PyException)]
struct SafeguardError {
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    details: String,
}

#[pymethods]
impl SafeguardError {
    #[new]
    fn new(kind: String, details: String) -> Self {
        SafeguardError { kind, details }
    }

    fn __str__(&self) -> String {
        format!("{}: {}", self.kind, self.details)
    }
}

fn error_to_pyerr(err: SafeguardCoreError) -> PyErr {
    let kind = format!("{:?}", err.kind());
    let details = err.to_string();
    PyErr::new::<SafeguardError, _>((kind, details))
}

fn parse_schema_format(value: &str) -> PyResult<SchemaFormat> {
    match value.to_ascii_lowercase().as_str() {
        "toml" => Ok(SchemaFormat::Toml),
        "json" => Ok(SchemaFormat::Json),
        other => Err(error_to_pyerr(SafeguardCoreError::invalid_input(format!(
            "Unknown storage schema format '{other}'; expected 'toml' or 'json'"
        )))),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_request(
    explain: bool,
    strict: bool,
    contract: Option<String>,
    suppressions_toml: Option<String>,
    old_storage_schema: Option<String>,
    old_storage_schema_format: Option<String>,
    new_storage_schema: Option<String>,
    new_storage_schema_format: Option<String>,
) -> PyResult<CompareRequest> {
    let schema_pair = match (old_storage_schema, new_storage_schema) {
        (Some(old_src), Some(new_src)) => {
            let old_fmt = parse_schema_format(
                old_storage_schema_format.as_deref().unwrap_or("toml"),
            )?;
            let new_fmt = parse_schema_format(
                new_storage_schema_format.as_deref().unwrap_or("toml"),
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
            return Err(error_to_pyerr(SafeguardCoreError::invalid_input(
                "old_storage_schema and new_storage_schema must be supplied together, or not at all",
            )))
        }
    };

    Ok(CompareRequest {
        explain,
        strict,
        contract,
        suppressions_toml,
        old_storage_schema: schema_pair.0,
        new_storage_schema: schema_pair.1,
    })
}

fn report_to_py(py: Python<'_>, report: &soroban_upgrade_safeguard::SafetyReport) -> PyResult<PyObject> {
    let renderable = report.to_json();
    pythonize::pythonize(py, &renderable)
        .map(|bound| bound.unbind())
        .map_err(|e| {
            error_to_pyerr(SafeguardCoreError::integrity(format!(
                "Failed to convert report to a Python object: {e}"
            )))
        })
}

/// Compare two Soroban contract builds given as raw WASM bytes.
///
/// Returns a plain `dict` matching the CLI's `--format json` report shape
/// (see `soroban_upgrade_safeguard::render::RenderableReport`). Raises
/// `SafeguardError` on any failure.
#[pyfunction]
#[pyo3(signature = (
    old_wasm,
    new_wasm,
    *,
    explain = false,
    strict = false,
    contract = None,
    suppressions_toml = None,
    old_storage_schema = None,
    old_storage_schema_format = None,
    new_storage_schema = None,
    new_storage_schema_format = None,
))]
#[allow(clippy::too_many_arguments)]
fn compare_bytes(
    py: Python<'_>,
    old_wasm: &[u8],
    new_wasm: &[u8],
    explain: bool,
    strict: bool,
    contract: Option<String>,
    suppressions_toml: Option<String>,
    old_storage_schema: Option<String>,
    old_storage_schema_format: Option<String>,
    new_storage_schema: Option<String>,
    new_storage_schema_format: Option<String>,
) -> PyResult<PyObject> {
    let request = build_request(
        explain,
        strict,
        contract,
        suppressions_toml,
        old_storage_schema,
        old_storage_schema_format,
        new_storage_schema,
        new_storage_schema_format,
    )?;
    let report = binding_api::compare_bytes(old_wasm, new_wasm, &request).map_err(error_to_pyerr)?;
    report_to_py(py, &report)
}

/// Compare two Soroban contract builds read from WASM files on disk.
///
/// The only I/O this performs is reading exactly `old_path`/`new_path`; it
/// never consults the network or a cache directory.
#[pyfunction]
#[pyo3(signature = (
    old_path,
    new_path,
    *,
    explain = false,
    strict = false,
    contract = None,
    suppressions_toml = None,
    old_storage_schema = None,
    old_storage_schema_format = None,
    new_storage_schema = None,
    new_storage_schema_format = None,
))]
#[allow(clippy::too_many_arguments)]
fn compare_files(
    py: Python<'_>,
    old_path: std::path::PathBuf,
    new_path: std::path::PathBuf,
    explain: bool,
    strict: bool,
    contract: Option<String>,
    suppressions_toml: Option<String>,
    old_storage_schema: Option<String>,
    old_storage_schema_format: Option<String>,
    new_storage_schema: Option<String>,
    new_storage_schema_format: Option<String>,
) -> PyResult<PyObject> {
    let request = build_request(
        explain,
        strict,
        contract,
        suppressions_toml,
        old_storage_schema,
        old_storage_schema_format,
        new_storage_schema,
        new_storage_schema_format,
    )?;
    let report =
        binding_api::compare_files(&old_path, &new_path, &request).map_err(error_to_pyerr)?;
    report_to_py(py, &report)
}

/// The version of `soroban-upgrade-safeguard` (the Rust engine) that this
/// extension was built against. See `docs/bindings.md` for the
/// version-compatibility policy between this number and the Python
/// package's own version.
#[pyfunction]
fn engine_version() -> &'static str {
    soroban_upgrade_safeguard::ENGINE_VERSION
}

#[pymodule]
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SafeguardError", py.get_type::<SafeguardError>())?;
    m.add_function(wrap_pyfunction!(compare_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(compare_files, m)?)?;
    m.add_function(wrap_pyfunction!(engine_version, m)?)?;
    Ok(())
}

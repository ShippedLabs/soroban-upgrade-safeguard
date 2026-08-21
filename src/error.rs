use std::fmt;
use std::path::PathBuf;

/// Stable identifier for each error variant, suitable for programmatic matching.
///
/// Unlike the full [`Error`] enum, `ErrorKind` carries no data, so it is
/// `PartialEq` and can be compared directly in tests and match arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    FileAccess,
    WasmValidation,
    SectionExtraction,
    XdrDecoding,
    RpcTransport,
    RpcProtocol,
    UnsupportedContract,
    SuppressionConfig,
    BatchBoundary,
    Integrity,
    InvalidInput,
    LimitExceeded,
    RpcAuthConfig,
    InvalidHeaderName,
    RemoteFetch,
}

/// The canonical error type for the soroban-upgrade-safeguard library.
///
/// Every fallible path in the public API returns `Result<T, Error>`, ensuring
/// that callers can distinguish failure modes programmatically without parsing
/// formatted strings.
///
/// # Variants
///
/// | Variant | When it occurs |
/// |---|---|
/// | [`FileAccess`](Error::FileAccess) | A file could not be read or does not exist |
/// | [`WasmValidation`](Error::WasmValidation) | The bytes are not a valid WASM binary |
/// | [`SectionExtraction`](Error::SectionExtraction) | A custom WASM section could not be decoded |
/// | [`XdrDecoding`](Error::XdrDecoding) | Stellar XDR deserialization failed |
/// | [`RpcTransport`](Error::RpcTransport) | The HTTP request to the Soroban RPC failed |
/// | [`RpcProtocol`](Error::RpcProtocol) | The RPC returned a JSON-RPC error object |
/// | [`UnsupportedContract`](Error::UnsupportedContract) | The contract is a built-in (e.g. Stellar Asset) with no bytecode |
/// | [`SuppressionConfig`](Error::SuppressionConfig) | The suppression config could not be loaded or parsed |
/// | [`BatchBoundary`](Error::BatchBoundary) | An error crossing the batch loop boundary |
/// | [`Integrity`](Error::Integrity) | An integrity check (hash comparison, magic bytes) failed |
/// | [`InvalidInput`](Error::InvalidInput) | An argument or input value is semantically invalid |
/// | [`LimitExceeded`](Error::LimitExceeded) | A resource limit (XDR depth, entry count, WASM size) was exceeded |
/// | [`RemoteFetch`](Error::RemoteFetch) | Downloading a `https://` input artifact failed (transport, size, redirect, or transport-policy violation) |
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    FileAccess {
        path: PathBuf,
        details: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    WasmValidation {
        path: Option<PathBuf>,
        details: String,
        byte_offset: Option<u64>,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    SectionExtraction {
        section_name: String,
        section_index: usize,
        byte_offset: u64,
        details: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    XdrDecoding {
        entry_index: Option<usize>,
        byte_offset: Option<u64>,
        details: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    RpcTransport {
        rpc_url: String,
        details: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    RpcProtocol {
        rpc_url: String,
        code: i64,
        message: String,
    },
    UnsupportedContract {
        contract_id: String,
        kind: String,
    },
    SuppressionConfig {
        path: Option<PathBuf>,
        details: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    BatchBoundary {
        details: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    Integrity {
        details: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    InvalidInput {
        details: String,
    },
    LimitExceeded {
        details: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    RpcAuthConfig {
        details: String,
    },
    InvalidHeaderName {
        name: String,
    },
    RemoteFetch {
        url: String,
        details: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
}

impl Error {
    /// Return a stable [`ErrorKind`] identifier for this error.
    ///
    /// Unlike matching on the enum variant directly, `kind()` is guaranteed to
    /// remain stable across `#[non_exhaustive]` additions.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::FileAccess { .. } => ErrorKind::FileAccess,
            Error::WasmValidation { .. } => ErrorKind::WasmValidation,
            Error::SectionExtraction { .. } => ErrorKind::SectionExtraction,
            Error::XdrDecoding { .. } => ErrorKind::XdrDecoding,
            Error::RpcTransport { .. } => ErrorKind::RpcTransport,
            Error::RpcProtocol { .. } => ErrorKind::RpcProtocol,
            Error::UnsupportedContract { .. } => ErrorKind::UnsupportedContract,
            Error::SuppressionConfig { .. } => ErrorKind::SuppressionConfig,
            Error::BatchBoundary { .. } => ErrorKind::BatchBoundary,
            Error::Integrity { .. } => ErrorKind::Integrity,
            Error::InvalidInput { .. } => ErrorKind::InvalidInput,
            Error::LimitExceeded { .. } => ErrorKind::LimitExceeded,
            Error::RpcAuthConfig { .. } => ErrorKind::RpcAuthConfig,
            Error::InvalidHeaderName { .. } => ErrorKind::InvalidHeaderName,
            Error::RemoteFetch { .. } => ErrorKind::RemoteFetch,
        }
    }

    /// Returns `true` if the error is likely transient and the operation may
    /// succeed if retried.
    ///
    /// Currently returns `true` for [`RpcTransport`](Error::RpcTransport) and
    /// [`RemoteFetch`](Error::RemoteFetch) errors (network hiccups) and `false`
    /// for all other variants.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::RpcTransport { .. } | Error::RemoteFetch { .. })
    }

    /// Returns `true` if the error is a transient infrastructure issue
    /// (network, server load, etc.) rather than a logical error in the input.
    pub fn is_transient(&self) -> bool {
        self.is_retryable()
    }

    /// If this error is related to a specific contract ID, return it.
    pub fn contract_id(&self) -> Option<&str> {
        match self {
            Error::UnsupportedContract { contract_id, .. } => Some(contract_id),
            _ => None,
        }
    }

    /// If this error is related to a specific file path, return it.
    pub fn file_path(&self) -> Option<&std::path::Path> {
        match self {
            Error::FileAccess { path, .. } => Some(path),
            Error::WasmValidation {
                path: Some(path), ..
            } => Some(path),
            Error::SuppressionConfig {
                path: Some(path), ..
            } => Some(path),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::FileAccess { path, details, .. } => {
                write!(f, "File access error for '{}': {}", path.display(), details)
            }
            Error::WasmValidation {
                path,
                details,
                byte_offset,
                ..
            } => {
                if let Some(offset) = byte_offset {
                    write!(
                        f,
                        "WASM validation error at byte offset {offset}: {details}"
                    )
                } else {
                    write!(f, "WASM validation error: {details}")
                }?;
                if let Some(path) = path {
                    write!(f, " (path: {})", path.display())?;
                }
                Ok(())
            }
            Error::SectionExtraction {
                section_name,
                section_index,
                byte_offset,
                ..
            } => {
                write!(
                    f,
                    "Failed to decode {section_name} section {section_index} at byte offset {byte_offset}"
                )
            }
            Error::XdrDecoding {
                entry_index,
                byte_offset,
                details,
                ..
            } => {
                write!(f, "{details}")?;
                if let Some(idx) = entry_index {
                    write!(f, " at entry index {idx}")?;
                }
                if let Some(offset) = byte_offset {
                    write!(f, " (byte offset {offset})")?;
                }
                Ok(())
            }
            Error::RpcTransport {
                rpc_url, details, ..
            } => {
                write!(f, "RPC transport error for '{rpc_url}': {details}")
            }
            Error::RpcProtocol {
                rpc_url,
                code,
                message,
            } => {
                write!(f, "RPC error (code {code}) from '{rpc_url}': {message}")
            }
            Error::UnsupportedContract { contract_id, kind } => {
                write!(f, "Contract '{contract_id}' is a built-in {kind} contract and does not have WASM bytecode")
            }
            Error::SuppressionConfig { path, details, .. } => {
                if let Some(path) = path {
                    write!(
                        f,
                        "Suppression config error for '{}': {details}",
                        path.display()
                    )
                } else {
                    write!(f, "Suppression config error: {details}")
                }
            }
            Error::BatchBoundary { details, .. } => {
                write!(f, "Batch processing error: {details}")
            }
            Error::Integrity { details, .. } => {
                write!(f, "Integrity check failed: {details}")
            }
            Error::InvalidInput { details } => {
                write!(f, "Invalid input: {details}")
            }
            Error::LimitExceeded { details, .. } => {
                write!(f, "Resource limit exceeded: {details}")
            }
            Error::RpcAuthConfig { details } => {
                write!(f, "RPC authentication configuration error: {details}")
            }
            Error::InvalidHeaderName { name } => write!(f, "Invalid RPC header name '{name}'"),
            Error::RemoteFetch { url, details, .. } => {
                write!(f, "Failed to fetch remote input '{url}': {details}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::FileAccess { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
            Error::WasmValidation { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
            Error::SectionExtraction { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
            Error::XdrDecoding { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
            Error::RpcTransport { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
            Error::RpcProtocol { .. } => None,
            Error::UnsupportedContract { .. } => None,
            Error::SuppressionConfig { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
            Error::BatchBoundary { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
            Error::Integrity { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
            Error::InvalidInput { .. } => None,
            Error::LimitExceeded { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
            Error::RpcAuthConfig { .. } | Error::InvalidHeaderName { .. } => None,
            Error::RemoteFetch { source, .. } => source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
        }
    }
}

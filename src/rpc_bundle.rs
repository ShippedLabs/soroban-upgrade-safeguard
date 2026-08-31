//! Versioned, deterministic RPC record/replay bundle format.
//!
//! A [`ReplayBundle`] is a self-contained, inspectable artifact that captures
//! the exact sequence of JSON-RPC interactions needed to reproduce a contract
//! fetch offline. Every embedded payload is hashed so tampering is detectable.
//!
//! # Security model
//!
//! Bundles are designed so secrets never appear in the artifact:
//!
//! - Authorization header **values** are stripped before recording.
//! - URL query strings and `user:pass@` components are redacted.
//! - Only header **names** (not values) are recorded as evidence of which
//!   headers were sent.
//!
//! # Format stability
//!
//! The [`BUNDLE_VERSION`] constant is bumped whenever the schema changes in a
//! backwards-incompatible way. The replay engine rejects bundles with an
//! unknown version rather than silently misinterpreting them.

use serde::{Deserialize, Serialize};

use crate::loader::sha256_hex;
use crate::rpc::redact_url;

/// Current bundle format version. Increment on breaking schema changes.
pub const BUNDLE_VERSION: u32 = 1;

/// A single captured JSON-RPC request/response pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleEntry {
    /// Sequence index (0-based) within the original interaction. Used to
    /// detect reordering during replay.
    pub sequence: usize,
    /// The JSON-RPC method name (e.g. `"getLedgerEntries"`).
    pub method: String,
    /// Sanitized request parameters — authorization data and sensitive URL
    /// fragments are stripped before this field is written.
    pub params: serde_json::Value,
    /// The full JSON-RPC response body received from the provider.
    pub response: serde_json::Value,
    /// SHA-256 (hex) of the canonical JSON serialization of `response`.
    /// Allows the replay engine to detect bundle tampering without network.
    pub response_hash: String,
}

impl BundleEntry {
    /// Construct a new entry, computing `response_hash` automatically.
    pub fn new(
        sequence: usize,
        method: impl Into<String>,
        params: serde_json::Value,
        response: serde_json::Value,
    ) -> Self {
        let response_hash = hash_json(&response);
        Self {
            sequence,
            method: method.into(),
            params,
            response,
            response_hash,
        }
    }

    /// Verify the stored `response_hash` matches the current `response`.
    ///
    /// Returns `Err` with a descriptive message if the hash is wrong.
    pub fn verify_hash(&self) -> Result<(), String> {
        let expected = hash_json(&self.response);
        if expected != self.response_hash {
            return Err(format!(
                "Bundle entry {} (method '{}') has been tampered with: \
                 stored hash {} does not match computed hash {}",
                self.sequence, self.method, self.response_hash, expected
            ));
        }
        Ok(())
    }
}

/// A verified binary artifact (e.g. WASM bytecode) embedded in a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleArtifact {
    /// Human-readable label (e.g. `"contract_wasm"`).
    pub label: String,
    /// Raw bytes, Base64-encoded for JSON portability.
    pub bytes_b64: String,
    /// SHA-256 (hex) of the raw bytes. Verified on load.
    pub sha256: String,
}

impl BundleArtifact {
    /// Encode `bytes` and compute its SHA-256.
    pub fn new(label: impl Into<String>, bytes: &[u8]) -> Self {
        use base64::Engine as _;
        Self {
            label: label.into(),
            bytes_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
            sha256: sha256_hex(bytes),
        }
    }

    /// Decode the Base64 bytes and verify the SHA-256.
    ///
    /// Returns the raw bytes or a descriptive error.
    pub fn decode_verified(&self) -> Result<Vec<u8>, String> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.bytes_b64)
            .map_err(|e| format!("Artifact '{}' Base64 decode failed: {}", self.label, e))?;
        let actual = sha256_hex(&bytes);
        if actual != self.sha256 {
            return Err(format!(
                "Artifact '{}' integrity check failed: stored hash {} \
                 does not match computed hash {}",
                self.label, self.sha256, actual
            ));
        }
        Ok(bytes)
    }
}

/// Top-level bundle wrapping all captured interactions for one contract fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBundle {
    /// Format version. Must equal [`BUNDLE_VERSION`] for the replay engine to
    /// accept the bundle.
    pub version: u32,
    /// Sanitized (redacted) RPC endpoint URL — query strings and credentials
    /// are stripped so the bundle can be shared without leaking secrets.
    pub sanitized_url: String,
    /// Contract ID that was fetched.
    pub contract_id: String,
    /// Header **names** that were present on requests (values are stripped).
    pub header_names: Vec<String>,
    /// Ordered sequence of request/response pairs.
    pub entries: Vec<BundleEntry>,
    /// Binary artifacts (e.g. verified WASM) embedded for offline replay.
    pub artifacts: Vec<BundleArtifact>,
}

impl ReplayBundle {
    /// Construct an empty bundle for `contract_id` fetched from `url`.
    ///
    /// `header_names` should list the names (not values) of any authentication
    /// or custom headers that were included in requests.
    pub fn new(url: &str, contract_id: impl Into<String>, header_names: Vec<String>) -> Self {
        Self {
            version: BUNDLE_VERSION,
            sanitized_url: redact_url(url),
            contract_id: contract_id.into(),
            header_names,
            entries: Vec::new(),
            artifacts: Vec::new(),
        }
    }

    /// Append an RPC interaction to the bundle, assigning the next sequence
    /// number automatically.
    pub fn push_entry(
        &mut self,
        method: impl Into<String>,
        params: serde_json::Value,
        response: serde_json::Value,
    ) {
        let sequence = self.entries.len();
        self.entries
            .push(BundleEntry::new(sequence, method, params, response));
    }

    /// Embed a binary artifact (e.g. WASM bytes).
    pub fn push_artifact(&mut self, label: impl Into<String>, bytes: &[u8]) {
        self.artifacts.push(BundleArtifact::new(label, bytes));
    }

    /// Serialize the bundle to a pretty-printed JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a bundle from a JSON string, then validate its integrity.
    ///
    /// Returns `Err` if the version is unsupported, any entry hash is wrong,
    /// or any artifact hash is wrong.
    pub fn from_json(json: &str) -> Result<Self, ReplayBundleError> {
        let bundle: Self = serde_json::from_str(json).map_err(ReplayBundleError::Deserialize)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Validate version, entry ordering, and all hashes without performing any
    /// network requests.
    pub fn validate(&self) -> Result<(), ReplayBundleError> {
        if self.version != BUNDLE_VERSION {
            return Err(ReplayBundleError::UnsupportedVersion {
                found: self.version,
                expected: BUNDLE_VERSION,
            });
        }

        for (i, entry) in self.entries.iter().enumerate() {
            // Detect reordering
            if entry.sequence != i {
                return Err(ReplayBundleError::EntryOutOfOrder {
                    index: i,
                    stored_sequence: entry.sequence,
                });
            }
            // Detect tampering
            entry
                .verify_hash()
                .map_err(ReplayBundleError::TamperedEntry)?;
        }

        for artifact in &self.artifacts {
            artifact
                .decode_verified()
                .map_err(ReplayBundleError::TamperedArtifact)?;
        }

        Ok(())
    }

    /// Return the artifact with the given label, or `None`.
    pub fn artifact(&self, label: &str) -> Option<&BundleArtifact> {
        self.artifacts.iter().find(|a| a.label == label)
    }
}

/// Errors that can occur when loading or validating a [`ReplayBundle`].
#[derive(Debug)]
pub enum ReplayBundleError {
    /// The JSON could not be deserialized.
    Deserialize(serde_json::Error),
    /// The bundle's `version` field is not recognized by this release.
    UnsupportedVersion { found: u32, expected: u32 },
    /// An entry's `sequence` field does not match its position in the array.
    EntryOutOfOrder {
        index: usize,
        stored_sequence: usize,
    },
    /// An entry's `response_hash` does not match the entry's `response`.
    TamperedEntry(String),
    /// An artifact's `sha256` does not match the decoded bytes.
    TamperedArtifact(String),
    /// The replay engine ran out of entries before the caller finished.
    ExhaustedEntries { method: String },
    /// The next entry's method does not match what the caller requested.
    MethodMismatch { expected: String, got: String },
    /// The bundle contained more entries than the replay consumed.
    UnconsumedEntries { count: usize },
}

impl std::fmt::Display for ReplayBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deserialize(e) => write!(f, "Bundle deserialization failed: {}", e),
            Self::UnsupportedVersion { found, expected } => write!(
                f,
                "Bundle version {} is not supported (expected {})",
                found, expected
            ),
            Self::EntryOutOfOrder {
                index,
                stored_sequence,
            } => write!(
                f,
                "Entry at index {} has sequence {} (out of order)",
                index, stored_sequence
            ),
            Self::TamperedEntry(msg) => write!(f, "Tampered entry: {}", msg),
            Self::TamperedArtifact(msg) => write!(f, "Tampered artifact: {}", msg),
            Self::ExhaustedEntries { method } => write!(
                f,
                "Replay bundle exhausted — no entry available for method '{}'",
                method
            ),
            Self::MethodMismatch { expected, got } => write!(
                f,
                "Replay method mismatch: expected '{}', got '{}'",
                expected, got
            ),
            Self::UnconsumedEntries { count } => write!(
                f,
                "Replay finished with {} unconsumed bundle entries",
                count
            ),
        }
    }
}

impl std::error::Error for ReplayBundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Deserialize(e) => Some(e),
            _ => None,
        }
    }
}

/// Compute the SHA-256 of the canonical (compact) JSON serialization of `v`.
pub(crate) fn hash_json(v: &serde_json::Value) -> String {
    sha256_hex(v.to_string().as_bytes())
}

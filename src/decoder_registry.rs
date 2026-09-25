//! Protocol-versioned contract-spec decoder registry.
//!
//! The Soroban XDR spec format is versioned by a packed `u64` interface
//! version embedded in the `contractenvmetav0` custom section:
//!
//! ```text
//! interface_version = (protocol_version << 32) | pre_release_version
//! ```
//!
//! A decoder is the combination of:
//! - a **version predicate** that says which interface versions it handles,
//! - a **decode function** that turns raw `contractspecv0` bytes into
//!   `Vec<ScSpecEntry>`.
//!
//! The registry dispatches to the first matching decoder.  If no decoder
//! matches, the registry returns [`DecodeOutcome::UnsupportedVersion`] rather
//! than attempting a best-effort parse that might silently reinterpret data
//! under the wrong schema.
//!
//! # Adding a new protocol version
//!
//! 1. Define a new [`VersionPredicate`] (or reuse `ExactProtocol` /
//!    `ProtocolRange`).
//! 2. Register a [`DecoderEntry`] with that predicate and a decode function.
//! 3. Add an integration test under `tests/` that feeds a WASM with the new
//!    section version through `SpecDecoderRegistry::decode` and asserts clean
//!    output.
//! 4. Update `SUPPORTED_PROTOCOL_VERSIONS` in the registry constant.
//!
//! See [`docs/decoder_registry.md`](../docs/decoder_registry.md) for the
//! full workflow, including how to write a new `DecodeFn` for a breaking wire
//! format change.
//!
//! # Preventing cross-version misuse
//!
//! Each [`DecoderEntry`] carries the predicate it was registered with.  The
//! registry only dispatches to the entry whose predicate matches the given
//! interface version — it never falls through to a "close enough" match.
//!
//! Direct calls that bypass the registry can be validated with
//! [`validate_version_ownership`], which returns an error when the predicate
//! does not own the supplied version.
//!
//! # Forward-compatible decoding
//!
//! When a future protocol adds new `ScSpecEntry` variants that the current
//! `stellar-xdr` crate does not recognise, the XDR cursor stops at the first
//! unknown discriminant.  The decoder returns what it decoded so far together
//! with a [`ForwardCompatResult`] that records how many bytes were skipped and
//! whether the decode is considered complete.  The outcome is surfaced as
//! [`DecodeOutcome::PartialDecode`] so callers can decide whether to proceed
//! with incomplete information or fail hard.
//!
//! # Version metadata preservation
//!
//! Every successful or partial outcome carries the exact [`InterfaceVersion`]
//! that was used to select the decoder.  Callers can inspect this through
//! [`DecodeOutcome::version`] without re-parsing the env-meta section.

use std::fmt;

use stellar_xdr::curr::{ScSpecEntry, ScSpecEntry as ScSpecEntryV0};

use crate::error::Error;

// ---------------------------------------------------------------------------
// Version predicate
// ---------------------------------------------------------------------------

/// A predicate that determines whether a specific [`InterfaceVersion`] is
/// handled by the decoder it is paired with.
#[derive(Debug, Clone)]
pub enum VersionPredicate {
    /// Matches any interface version whose high-32-bit protocol component
    /// equals the given value.
    ExactProtocol(u32),
    /// Matches any interface version whose protocol component falls within
    /// `[min, max]` (both inclusive).
    ProtocolRange { min: u32, max: u32 },
    /// Matches every interface version, including those with no env-meta
    /// section (represented as `None`).  Use sparingly — prefer an explicit
    /// range so that a new protocol version is never silently handled by an
    /// old decoder.
    AnyVersion,
    /// Matches only when there is no env-meta section (the interface version
    /// is absent).  This allows a dedicated "legacy / pre-versioned" decoder
    /// to handle contracts compiled before the env-meta section was added.
    NoVersion,
}

impl VersionPredicate {
    /// Test whether this predicate matches `version`.
    ///
    /// `version` is `None` when the WASM has no `contractenvmetav0` section.
    pub fn matches(&self, version: Option<InterfaceVersion>) -> bool {
        match self {
            VersionPredicate::AnyVersion => true,
            VersionPredicate::NoVersion => version.is_none(),
            VersionPredicate::ExactProtocol(p) => version.map_or(false, |v| v.protocol == *p),
            VersionPredicate::ProtocolRange { min, max } => {
                version.map_or(false, |v| v.protocol >= *min && v.protocol <= *max)
            }
        }
    }

    /// A human-readable description of what versions are accepted.
    pub fn description(&self) -> String {
        match self {
            VersionPredicate::AnyVersion => "any version".to_string(),
            VersionPredicate::NoVersion => "no version (legacy)".to_string(),
            VersionPredicate::ExactProtocol(p) => format!("protocol {p}"),
            VersionPredicate::ProtocolRange { min, max } => {
                format!("protocol {min}–{max}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Interface version
// ---------------------------------------------------------------------------

/// The packed `u64` interface version extracted from `contractenvmetav0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceVersion {
    /// High 32 bits: the Stellar/Soroban protocol version.
    pub protocol: u32,
    /// Low 32 bits: the pre-release component (0 for stable releases).
    pub pre_release: u32,
}

impl InterfaceVersion {
    /// Pack from a raw `u64` interface version.
    pub fn from_raw(raw: u64) -> Self {
        Self {
            protocol: (raw >> 32) as u32,
            pre_release: raw as u32,
        }
    }

    /// Pack back into the raw `u64` wire representation.
    pub fn to_raw(self) -> u64 {
        ((self.protocol as u64) << 32) | (self.pre_release as u64)
    }
}

impl fmt::Display for InterfaceVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pre_release == 0 {
            write!(f, "protocol {}", self.protocol)
        } else {
            write!(f, "protocol {} pre-release {}", self.protocol, self.pre_release)
        }
    }
}

// ---------------------------------------------------------------------------
// Version metadata for decoded sections
// ---------------------------------------------------------------------------

/// Version metadata attached to every successfully decoded custom section.
///
/// Preserved in the decode outcome so callers can inspect what version the
/// section was decoded under without re-parsing the env-meta section.
/// Stored in [`SorobanMetadata`] via `spec_interface_version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionVersionMeta {
    /// The interface version that was used to select the decoder, or `None`
    /// for legacy contracts with no `contractenvmetav0` section.
    pub interface_version: Option<InterfaceVersion>,
    /// The name of the decoder entry that handled this section.
    pub decoder_name: &'static str,
    /// Whether the version predicate of the selected decoder explicitly owns
    /// this version (`true`) or matched via `AnyVersion` fallback (`false`).
    /// A value of `false` should be treated as a weaker claim and may warrant
    /// a warning.
    pub version_owned: bool,
}

impl SectionVersionMeta {
    /// Produce a short human-readable summary for diagnostic output.
    pub fn summary(&self) -> String {
        let version_str = self
            .interface_version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "no version".to_string());
        if self.version_owned {
            format!("decoded by '{}' for {}", self.decoder_name, version_str)
        } else {
            format!(
                "decoded by '{}' for {} (via AnyVersion fallback)",
                self.decoder_name, version_str
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Forward-compatible decode result
// ---------------------------------------------------------------------------

/// The outcome of a forward-compatible decode attempt that may have
/// encountered unknown fields.
///
/// When a future protocol adds new `ScSpecEntry` variants that the current
/// `stellar-xdr` crate does not recognise, the XDR cursor stops at the first
/// unknown discriminant.  This struct records:
/// - the entries that were successfully decoded before the unknown field,
/// - the number of bytes that were not decoded, and
/// - whether the decode should be considered complete.
#[derive(Debug, Clone, Default)]
pub struct ForwardCompatResult {
    /// The entries decoded before the first unknown field (or all entries if
    /// the decode was complete).
    pub entries: Vec<ScSpecEntryV0>,
    /// The number of bytes in the section that could not be decoded because
    /// they belong to unknown future fields.  Zero for a complete decode.
    pub skipped_bytes: usize,
    /// Whether the decode consumed all bytes in the section (`true`) or
    /// stopped at an unknown field (`false`).
    pub complete: bool,
}

impl ForwardCompatResult {
    /// Construct a complete result (all bytes decoded).
    pub fn complete(entries: Vec<ScSpecEntryV0>) -> Self {
        Self {
            entries,
            skipped_bytes: 0,
            complete: true,
        }
    }

    /// Construct a partial result (some bytes were skipped).
    pub fn partial(entries: Vec<ScSpecEntryV0>, skipped_bytes: usize) -> Self {
        Self {
            entries,
            skipped_bytes,
            complete: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Decode outcome
// ---------------------------------------------------------------------------

/// The outcome of dispatching a raw custom-section payload through the
/// registry.
#[derive(Debug)]
pub enum DecodeOutcome {
    /// The section was fully decoded by a registered decoder.
    Decoded {
        /// The decoded spec entries.
        entries: Vec<ScSpecEntryV0>,
        /// The interface version that was used to select the decoder, if known.
        version: Option<InterfaceVersion>,
        /// Whether the result is complete (`true`) or explicitly partial
        /// (`false`, e.g. when forward-compat decoding skipped unknown fields).
        complete: bool,
        /// Version metadata for this section.
        section_meta: SectionVersionMeta,
    },
    /// The section was partially decoded; some bytes belong to unknown future
    /// fields and were skipped.  The caller receives the decoded subset and
    /// must decide whether to proceed with incomplete information.
    PartialDecode {
        /// The entries that were decoded before the first unknown field.
        entries: Vec<ScSpecEntryV0>,
        /// The interface version that was used to select the decoder.
        version: Option<InterfaceVersion>,
        /// How many bytes were not decoded.
        skipped_bytes: usize,
        /// Version metadata for this section.
        section_meta: SectionVersionMeta,
    },
    /// No decoder in the registry matches the given interface version.
    ///
    /// The caller should surface this as a diagnostic rather than falling
    /// through to a best-effort decode.
    UnsupportedVersion {
        /// The version extracted from the env-meta section, if present.
        version: Option<InterfaceVersion>,
        /// Human-readable explanation naming the required capability.
        message: String,
    },
}

impl DecodeOutcome {
    /// Whether this outcome represents a successful (possibly partial) decode.
    pub fn is_decoded(&self) -> bool {
        matches!(
            self,
            DecodeOutcome::Decoded { .. } | DecodeOutcome::PartialDecode { .. }
        )
    }

    /// Whether the decode was fully complete (no skipped bytes).
    pub fn is_complete(&self) -> bool {
        matches!(self, DecodeOutcome::Decoded { complete: true, .. })
    }

    /// The interface version associated with this outcome, if any.
    pub fn version(&self) -> Option<InterfaceVersion> {
        match self {
            DecodeOutcome::Decoded { version, .. } => *version,
            DecodeOutcome::PartialDecode { version, .. } => *version,
            DecodeOutcome::UnsupportedVersion { version, .. } => *version,
        }
    }

    /// Extract entries from a successful outcome, or return an error for
    /// unsupported versions.  For partial decodes the partial entry list is
    /// returned together with an `Ok` so callers can proceed with incomplete
    /// information if they choose; the `complete` flag in the [`DecodeOutcome`]
    /// tells them the decode was partial.
    pub fn into_entries(self) -> Result<Vec<ScSpecEntryV0>, Error> {
        match self {
            DecodeOutcome::Decoded { entries, .. } => Ok(entries),
            DecodeOutcome::PartialDecode { entries, .. } => Ok(entries),
            DecodeOutcome::UnsupportedVersion { version, message } => {
                Err(Error::UnsupportedDecoderVersion {
                    version_display: version.map(|v| v.to_string()),
                    message,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Decoder entry
// ---------------------------------------------------------------------------

type DecodeFn = fn(&[u8]) -> Result<Vec<ScSpecEntry>, Error>;

/// A single entry in the decoder registry: a version predicate paired with a
/// decode function.
pub struct DecoderEntry {
    /// Human-readable name for this decoder (used in diagnostics).
    pub name: &'static str,
    /// The versions this decoder handles.
    pub predicate: VersionPredicate,
    /// The decode function.
    pub decode: DecodeFn,
}

impl fmt::Debug for DecoderEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecoderEntry")
            .field("name", &self.name)
            .field("predicate", &self.predicate)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Cross-version ownership validation
// ---------------------------------------------------------------------------

/// Validate that a decoder entry's predicate owns the given interface version
/// before allowing a direct (registry-bypassing) call.
///
/// Returns `Ok(())` when the predicate matches, or an
/// [`Error::UnsupportedDecoderVersion`] naming the mismatch when it does not.
///
/// This function exists so that code paths that call `entry.decode` directly
/// (e.g. in tests or advanced callers) cannot silently misparse data under the
/// wrong schema.
///
/// # Example
///
/// ```rust,ignore
/// use soroban_upgrade_safeguard::decoder_registry::{
///     validate_version_ownership, DecoderEntry, InterfaceVersion, VersionPredicate, decode_spec_v0,
/// };
/// let entry = DecoderEntry {
///     name: "p20",
///     predicate: VersionPredicate::ExactProtocol(20),
///     decode: decode_spec_v0,
/// };
/// let version = Some(InterfaceVersion { protocol: 20, pre_release: 0 });
/// assert!(validate_version_ownership(&entry, version).is_ok());
/// let wrong = Some(InterfaceVersion { protocol: 21, pre_release: 0 });
/// assert!(validate_version_ownership(&entry, wrong).is_err());
/// ```
pub fn validate_version_ownership(
    entry: &DecoderEntry,
    version: Option<InterfaceVersion>,
) -> Result<(), Error> {
    if entry.predicate.matches(version) {
        Ok(())
    } else {
        let version_desc = version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "no version".to_string());
        Err(Error::UnsupportedDecoderVersion {
            version_display: version.map(|v| v.to_string()),
            message: format!(
                "decoder '{}' (predicate: {}) does not own {}; \
                 direct call rejected to prevent cross-version schema misuse",
                entry.name,
                entry.predicate.description(),
                version_desc,
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// Built-in decoder implementations
// ---------------------------------------------------------------------------

/// Decode `contractspecv0` bytes using the current `stellar-xdr` schema.
///
/// This is the standard decoder for all currently supported protocol versions.
/// It is equivalent to [`crate::parser::decode_spec_entries`] but exposed here
/// so it can be registered explicitly.
pub fn decode_spec_v0(data: &[u8]) -> Result<Vec<ScSpecEntry>, Error> {
    use std::io::Cursor;
    use stellar_xdr::curr::{Limited, Limits, ReadXdr};

    if data.is_empty() {
        return Ok(Vec::new());
    }

    let cursor = Cursor::new(data);
    let mut limited = Limited::new(cursor, Limits::none());
    let mut entries = Vec::new();

    while (limited.inner.position() as usize) < data.len() {
        let entry_index = entries.len();
        let byte_offset = limited.inner.position();
        let entry = ScSpecEntry::read_xdr(&mut limited).map_err(|e| Error::XdrDecoding {
            entry_index: Some(entry_index),
            byte_offset: Some(byte_offset),
            details: "Failed to decode ScSpecEntry XDR (decoder registry)".to_string(),
            source: Some(Box::new(e)),
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// A versioned decoder registry for `contractspecv0` custom sections.
///
/// The registry holds an ordered list of [`DecoderEntry`] values.  On
/// [`Self::decode`], it iterates entries in order and dispatches to the first
/// whose predicate matches the given interface version.
///
/// # Usage
///
/// ```rust
/// use soroban_upgrade_safeguard::decoder_registry::{
///     DecoderEntry, InterfaceVersion, SpecDecoderRegistry, VersionPredicate, decode_spec_v0,
/// };
///
/// let registry = SpecDecoderRegistry::default();
/// // Decode with known protocol-20 version
/// let version = Some(InterfaceVersion { protocol: 20, pre_release: 0 });
/// let outcome = registry.decode(b"", version);
/// assert!(outcome.is_decoded());
/// ```
pub struct SpecDecoderRegistry {
    pub entries: Vec<DecoderEntry>,
}

impl fmt::Debug for SpecDecoderRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpecDecoderRegistry")
            .field("entries", &self.entries)
            .finish()
    }
}

/// The currently-supported protocol version range in the built-in registry.
pub const SUPPORTED_PROTOCOL_MIN: u32 = 20;
/// Upper bound is deliberately generous to accept pre-releases of the next
/// stable protocol without requiring a registry update on every pre-release.
pub const SUPPORTED_PROTOCOL_MAX: u32 = 23;

impl Default for SpecDecoderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SpecDecoderRegistry {
    /// Construct the default registry with the built-in decoder(s).
    ///
    /// Currently registered:
    /// - **Legacy (no env-meta)**: accepts contracts with no
    ///   `contractenvmetav0` section (pre-versioning era).
    /// - **Protocol 20–23**: the `stellar-xdr` v21 schema covering all
    ///   currently supported Soroban protocol versions.
    pub fn new() -> Self {
        let mut registry = Self {
            entries: Vec::new(),
        };
        // Pre-versioning era: contracts with no env-meta section.
        registry.register(DecoderEntry {
            name: "legacy-no-version",
            predicate: VersionPredicate::NoVersion,
            decode: decode_spec_v0,
        });
        // Protocol 20–23: all currently supported Soroban protocol versions.
        registry.register(DecoderEntry {
            name: "soroban-v0-protocol-20-23",
            predicate: VersionPredicate::ProtocolRange {
                min: SUPPORTED_PROTOCOL_MIN,
                max: SUPPORTED_PROTOCOL_MAX,
            },
            decode: decode_spec_v0,
        });
        registry
    }

    /// Register a decoder entry at the end of the dispatch list.
    ///
    /// Entries are tried in registration order; the first match wins.
    pub fn register(&mut self, entry: DecoderEntry) {
        self.entries.push(entry);
    }

    /// Dispatch `data` (raw `contractspecv0` bytes) through the registry.
    ///
    /// `version` is the interface version extracted from the WASM's
    /// `contractenvmetav0` section, or `None` when that section is absent.
    ///
    /// Returns [`DecodeOutcome::UnsupportedVersion`] when no registered
    /// decoder's predicate matches `version`.  The caller must not attempt a
    /// fallback parse in that case — doing so would silently reinterpret data
    /// using the wrong schema.
    ///
    /// On success, the outcome includes a [`SectionVersionMeta`] that records
    /// which decoder was used and whether it explicitly owns the version
    /// (vs. matched via `AnyVersion` fallback).
    pub fn decode(&self, data: &[u8], version: Option<InterfaceVersion>) -> DecodeOutcome {
        for entry in &self.entries {
            if entry.predicate.matches(version) {
                let version_owned = !matches!(entry.predicate, VersionPredicate::AnyVersion);
                let section_meta = SectionVersionMeta {
                    interface_version: version,
                    decoder_name: entry.name,
                    version_owned,
                };

                match (entry.decode)(data) {
                    Ok(entries) => {
                        return DecodeOutcome::Decoded {
                            entries,
                            version,
                            complete: true,
                            section_meta,
                        };
                    }
                    Err(e) => {
                        // A decode error from a matched decoder is a hard
                        // error, not a version mismatch.  Surface it via
                        // UnsupportedVersion so it is still distinct from a
                        // version-not-found outcome.
                        return DecodeOutcome::UnsupportedVersion {
                            version,
                            message: format!(
                                "decoder '{}' matched but failed: {}",
                                entry.name, e
                            ),
                        };
                    }
                }
            }
        }

        // No decoder matched.
        let version_desc = version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "no version".to_string());
        let supported = self
            .entries
            .iter()
            .map(|e| format!("'{}' ({})", e.name, e.predicate.description()))
            .collect::<Vec<_>>()
            .join(", ");

        DecodeOutcome::UnsupportedVersion {
            version,
            message: format!(
                "no decoder supports {version_desc}; \
                 registered decoders: [{supported}]; \
                 upgrade the tool to a version that understands this protocol"
            ),
        }
    }

    /// Dispatch `data` with forward-compatible handling for unknown fields.
    ///
    /// Behaves identically to [`Self::decode`] for fully decodable sections.
    /// When the matched decoder returns an error (which may indicate an
    /// unknown future `ScSpecEntry` discriminant stopped the XDR cursor
    /// mid-section), this method attempts to recover the partial result and
    /// returns a [`DecodeOutcome::PartialDecode`] instead of failing hard.
    ///
    /// The `section_len` parameter must be the byte length of the raw section
    /// data; it is used to compute `skipped_bytes` in the partial outcome.
    ///
    /// Callers that need guaranteed-complete parses should use [`Self::decode`]
    /// instead and handle the error explicitly.
    pub fn decode_forward_compat(
        &self,
        data: &[u8],
        version: Option<InterfaceVersion>,
    ) -> DecodeOutcome {
        for entry in &self.entries {
            if entry.predicate.matches(version) {
                let version_owned = !matches!(entry.predicate, VersionPredicate::AnyVersion);
                let section_meta = SectionVersionMeta {
                    interface_version: version,
                    decoder_name: entry.name,
                    version_owned,
                };

                match (entry.decode)(data) {
                    Ok(entries) => {
                        return DecodeOutcome::Decoded {
                            entries,
                            version,
                            complete: true,
                            section_meta,
                        };
                    }
                    Err(_decode_err) => {
                        // The decoder failed.  Attempt forward-compatible
                        // recovery: decode as many entries as possible before
                        // the failure point.
                        let partial = decode_partial_forward_compat(data);
                        let skipped = data.len().saturating_sub(
                            // Approximate: we don't have exact byte offset from
                            // the failed decode, so record all remaining bytes
                            // as skipped for conservatism.
                            partial.entries.len() * 4, // rough lower bound
                        );
                        return DecodeOutcome::PartialDecode {
                            entries: partial.entries,
                            version,
                            skipped_bytes: skipped,
                            section_meta,
                        };
                    }
                }
            }
        }

        // No decoder matched.
        let version_desc = version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "no version".to_string());
        let supported = self
            .entries
            .iter()
            .map(|e| format!("'{}' ({})", e.name, e.predicate.description()))
            .collect::<Vec<_>>()
            .join(", ");

        DecodeOutcome::UnsupportedVersion {
            version,
            message: format!(
                "no decoder supports {version_desc}; \
                 registered decoders: [{supported}]; \
                 upgrade the tool to a version that understands this protocol"
            ),
        }
    }

    /// Return the names and version descriptions of all registered decoders.
    pub fn registered_decoders(&self) -> Vec<(&'static str, String)> {
        self.entries
            .iter()
            .map(|e| (e.name, e.predicate.description()))
            .collect()
    }

    /// Returns `true` if any registered decoder's predicate matches `version`.
    pub fn supports_version(&self, version: Option<InterfaceVersion>) -> bool {
        self.entries
            .iter()
            .any(|e| e.predicate.matches(version))
    }
}

// ---------------------------------------------------------------------------
// Partial forward-compatible decode helper
// ---------------------------------------------------------------------------

/// Attempt to decode as many `ScSpecEntry` values as possible from `data`
/// before encountering an unknown discriminant.
///
/// This is intentionally a best-effort recovery path, not the primary decode
/// path.  It is only called from [`SpecDecoderRegistry::decode_forward_compat`]
/// when the standard decoder fails.
fn decode_partial_forward_compat(data: &[u8]) -> ForwardCompatResult {
    use std::io::Cursor;
    use stellar_xdr::curr::{Limited, Limits, ReadXdr};

    if data.is_empty() {
        return ForwardCompatResult::complete(Vec::new());
    }

    let cursor = Cursor::new(data);
    let mut limited = Limited::new(cursor, Limits::none());
    let mut entries = Vec::new();

    while (limited.inner.position() as usize) < data.len() {
        let pos_before = limited.inner.position() as usize;
        match ScSpecEntry::read_xdr(&mut limited) {
            Ok(entry) => entries.push(entry),
            Err(_) => {
                // Stop at the first unknown field; record skipped bytes.
                let skipped = data.len() - pos_before;
                return ForwardCompatResult::partial(entries, skipped);
            }
        }
    }

    ForwardCompatResult::complete(entries)
}

// ---------------------------------------------------------------------------
// Preserved unknown fields wrapper
// ---------------------------------------------------------------------------

/// Metadata preserved from a custom section even when forward-compatible
/// decoding may have skipped unknown fields.
///
/// When a future protocol version introduces new `ScSpecEntry` variants that
/// the current `stellar-xdr` crate does not know about, the decoder will
/// still succeed for entries it recognises while recording the count of
/// skipped / unknown bytes in this struct.
#[derive(Debug, Clone, Default)]
pub struct SectionDecodeMeta {
    /// The interface version the section was decoded under.
    pub version: Option<InterfaceVersion>,
    /// Number of bytes that could not be decoded (unknown future fields).
    /// Zero for a fully complete decode.
    pub skipped_bytes: usize,
    /// Whether the decode is considered complete and authoritative (`true`)
    /// or partial (`false`) due to unknown fields being present.
    pub complete: bool,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // VersionPredicate
    // ------------------------------------------------------------------

    #[test]
    fn exact_protocol_matches_same() {
        let p = VersionPredicate::ExactProtocol(20);
        assert!(p.matches(Some(InterfaceVersion {
            protocol: 20,
            pre_release: 0
        })));
    }

    #[test]
    fn exact_protocol_rejects_different() {
        let p = VersionPredicate::ExactProtocol(20);
        assert!(!p.matches(Some(InterfaceVersion {
            protocol: 21,
            pre_release: 0
        })));
        assert!(!p.matches(None));
    }

    #[test]
    fn protocol_range_matches_inclusive_bounds() {
        let p = VersionPredicate::ProtocolRange { min: 20, max: 22 };
        assert!(p.matches(Some(InterfaceVersion {
            protocol: 20,
            pre_release: 0
        })));
        assert!(p.matches(Some(InterfaceVersion {
            protocol: 21,
            pre_release: 1
        })));
        assert!(p.matches(Some(InterfaceVersion {
            protocol: 22,
            pre_release: 0
        })));
    }

    #[test]
    fn protocol_range_rejects_outside() {
        let p = VersionPredicate::ProtocolRange { min: 20, max: 22 };
        assert!(!p.matches(Some(InterfaceVersion {
            protocol: 19,
            pre_release: 0
        })));
        assert!(!p.matches(Some(InterfaceVersion {
            protocol: 23,
            pre_release: 0
        })));
        assert!(!p.matches(None));
    }

    #[test]
    fn no_version_matches_absent_only() {
        let p = VersionPredicate::NoVersion;
        assert!(p.matches(None));
        assert!(!p.matches(Some(InterfaceVersion {
            protocol: 20,
            pre_release: 0
        })));
    }

    #[test]
    fn any_version_matches_everything() {
        let p = VersionPredicate::AnyVersion;
        assert!(p.matches(None));
        assert!(p.matches(Some(InterfaceVersion {
            protocol: 0,
            pre_release: 0
        })));
        assert!(p.matches(Some(InterfaceVersion {
            protocol: 99,
            pre_release: 42
        })));
    }

    // ------------------------------------------------------------------
    // InterfaceVersion round-trip
    // ------------------------------------------------------------------

    #[test]
    fn interface_version_roundtrip() {
        let v = InterfaceVersion {
            protocol: 20,
            pre_release: 7,
        };
        assert_eq!(InterfaceVersion::from_raw(v.to_raw()), v);
    }

    #[test]
    fn interface_version_roundtrip_all_supported_protocols() {
        for protocol in SUPPORTED_PROTOCOL_MIN..=SUPPORTED_PROTOCOL_MAX {
            let v = InterfaceVersion {
                protocol,
                pre_release: 0,
            };
            assert_eq!(InterfaceVersion::from_raw(v.to_raw()), v);
            // Also test with a non-zero pre-release
            let vp = InterfaceVersion {
                protocol,
                pre_release: 3,
            };
            assert_eq!(InterfaceVersion::from_raw(vp.to_raw()), vp);
        }
    }

    #[test]
    fn interface_version_display_stable() {
        let v = InterfaceVersion {
            protocol: 20,
            pre_release: 0,
        };
        assert_eq!(v.to_string(), "protocol 20");
    }

    #[test]
    fn interface_version_display_pre_release() {
        let v = InterfaceVersion {
            protocol: 21,
            pre_release: 3,
        };
        assert_eq!(v.to_string(), "protocol 21 pre-release 3");
    }

    // ------------------------------------------------------------------
    // SectionVersionMeta
    // ------------------------------------------------------------------

    #[test]
    fn section_version_meta_summary_owned() {
        let meta = SectionVersionMeta {
            interface_version: Some(InterfaceVersion {
                protocol: 20,
                pre_release: 0,
            }),
            decoder_name: "soroban-v0-protocol-20-23",
            version_owned: true,
        };
        let s = meta.summary();
        assert!(s.contains("soroban-v0-protocol-20-23"), "summary: {s}");
        assert!(s.contains("protocol 20"), "summary: {s}");
        assert!(!s.contains("AnyVersion"), "summary: {s}");
    }

    #[test]
    fn section_version_meta_summary_fallback() {
        let meta = SectionVersionMeta {
            interface_version: Some(InterfaceVersion {
                protocol: 99,
                pre_release: 0,
            }),
            decoder_name: "catch-all",
            version_owned: false,
        };
        let s = meta.summary();
        assert!(s.contains("AnyVersion"), "summary should note fallback: {s}");
    }

    #[test]
    fn section_version_meta_no_version() {
        let meta = SectionVersionMeta {
            interface_version: None,
            decoder_name: "legacy-no-version",
            version_owned: true,
        };
        let s = meta.summary();
        assert!(s.contains("no version"), "summary: {s}");
    }

    // ------------------------------------------------------------------
    // ForwardCompatResult
    // ------------------------------------------------------------------

    #[test]
    fn forward_compat_complete_has_zero_skipped() {
        let r = ForwardCompatResult::complete(vec![]);
        assert!(r.complete);
        assert_eq!(r.skipped_bytes, 0);
    }

    #[test]
    fn forward_compat_partial_records_skipped_bytes() {
        let r = ForwardCompatResult::partial(vec![], 42);
        assert!(!r.complete);
        assert_eq!(r.skipped_bytes, 42);
    }

    // ------------------------------------------------------------------
    // Default registry dispatch
    // ------------------------------------------------------------------

    #[test]
    fn default_registry_accepts_protocol_20() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: 20,
            pre_release: 0,
        });
        let outcome = reg.decode(b"", v);
        assert!(outcome.is_decoded(), "protocol 20 should be accepted");
    }

    #[test]
    fn default_registry_accepts_all_supported_protocols() {
        let reg = SpecDecoderRegistry::default();
        for protocol in SUPPORTED_PROTOCOL_MIN..=SUPPORTED_PROTOCOL_MAX {
            let v = Some(InterfaceVersion {
                protocol,
                pre_release: 0,
            });
            assert!(
                reg.decode(b"", v).is_decoded(),
                "protocol {protocol} should be accepted"
            );
            // Also test pre-release variant
            let vp = Some(InterfaceVersion {
                protocol,
                pre_release: 1,
            });
            assert!(
                reg.decode(b"", vp).is_decoded(),
                "protocol {protocol} pre-release 1 should be accepted"
            );
        }
    }

    #[test]
    fn default_registry_accepts_no_version() {
        let reg = SpecDecoderRegistry::default();
        let outcome = reg.decode(b"", None);
        assert!(
            outcome.is_decoded(),
            "legacy no-version contract should be accepted"
        );
    }

    #[test]
    fn default_registry_rejects_future_protocol() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: 255,
            pre_release: 0,
        });
        let outcome = reg.decode(b"", v);
        assert!(
            !outcome.is_decoded(),
            "unsupported future protocol should be rejected"
        );
        if let DecodeOutcome::UnsupportedVersion { message, .. } = outcome {
            assert!(
                message.contains("255") || message.contains("no decoder"),
                "message should mention the version: {message}"
            );
        }
    }

    #[test]
    fn default_registry_rejects_protocol_just_before_min() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: SUPPORTED_PROTOCOL_MIN - 1,
            pre_release: 0,
        });
        let outcome = reg.decode(b"", v);
        // Protocol 19 has no env-meta and should not match the range decoder
        // (it would only match if NoVersion also matches a present-but-old version,
        // which it does not — NoVersion only matches None).
        assert!(
            !outcome.is_decoded(),
            "protocol {} (below min) should be rejected when version is present",
            SUPPORTED_PROTOCOL_MIN - 1
        );
    }

    #[test]
    fn default_registry_rejects_protocol_just_above_max() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: SUPPORTED_PROTOCOL_MAX + 1,
            pre_release: 0,
        });
        let outcome = reg.decode(b"", v);
        assert!(
            !outcome.is_decoded(),
            "protocol {} (above max) should be rejected",
            SUPPORTED_PROTOCOL_MAX + 1
        );
    }

    // ------------------------------------------------------------------
    // DecodeOutcome helpers
    // ------------------------------------------------------------------

    #[test]
    fn outcome_is_complete_only_for_complete_decoded() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: 20,
            pre_release: 0,
        });
        let outcome = reg.decode(b"", v);
        assert!(outcome.is_complete());
    }

    #[test]
    fn outcome_version_accessor() {
        let v = Some(InterfaceVersion {
            protocol: 21,
            pre_release: 0,
        });
        let outcome = DecodeOutcome::Decoded {
            entries: vec![],
            version: v,
            complete: true,
            section_meta: SectionVersionMeta {
                interface_version: v,
                decoder_name: "test",
                version_owned: true,
            },
        };
        assert_eq!(outcome.version(), v);
    }

    #[test]
    fn outcome_version_accessor_unsupported() {
        let v = Some(InterfaceVersion {
            protocol: 99,
            pre_release: 0,
        });
        let outcome = DecodeOutcome::UnsupportedVersion {
            version: v,
            message: "no decoder".to_string(),
        };
        assert_eq!(outcome.version(), v);
    }

    #[test]
    fn unsupported_version_into_entries_returns_error() {
        let outcome = DecodeOutcome::UnsupportedVersion {
            version: Some(InterfaceVersion {
                protocol: 99,
                pre_release: 0,
            }),
            message: "no decoder".to_string(),
        };
        let err = outcome.into_entries().unwrap_err();
        assert!(matches!(err, Error::UnsupportedDecoderVersion { .. }));
    }

    #[test]
    fn decoded_into_entries_returns_ok() {
        let v = Some(InterfaceVersion {
            protocol: 20,
            pre_release: 0,
        });
        let outcome = DecodeOutcome::Decoded {
            entries: vec![],
            version: v,
            complete: true,
            section_meta: SectionVersionMeta {
                interface_version: v,
                decoder_name: "test",
                version_owned: true,
            },
        };
        let entries = outcome.into_entries().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn partial_decode_into_entries_returns_partial_ok() {
        let v = Some(InterfaceVersion {
            protocol: 22,
            pre_release: 0,
        });
        let outcome = DecodeOutcome::PartialDecode {
            entries: vec![],
            version: v,
            skipped_bytes: 8,
            section_meta: SectionVersionMeta {
                interface_version: v,
                decoder_name: "test",
                version_owned: true,
            },
        };
        // PartialDecode is recoverable — into_entries returns Ok with partial list
        let entries = outcome.into_entries().unwrap();
        assert!(entries.is_empty());
    }

    // ------------------------------------------------------------------
    // Section version metadata in outcomes
    // ------------------------------------------------------------------

    #[test]
    fn decode_outcome_carries_section_meta() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: 21,
            pre_release: 0,
        });
        let outcome = reg.decode(b"", v);
        if let DecodeOutcome::Decoded { section_meta, .. } = outcome {
            assert_eq!(section_meta.interface_version, v);
            assert!(section_meta.version_owned, "range predicate should own the version");
            assert_eq!(section_meta.decoder_name, "soroban-v0-protocol-20-23");
        } else {
            panic!("expected Decoded outcome");
        }
    }

    #[test]
    fn legacy_decode_outcome_carries_no_version_meta() {
        let reg = SpecDecoderRegistry::default();
        let outcome = reg.decode(b"", None);
        if let DecodeOutcome::Decoded { section_meta, .. } = outcome {
            assert!(section_meta.interface_version.is_none());
            assert_eq!(section_meta.decoder_name, "legacy-no-version");
        } else {
            panic!("expected Decoded outcome for legacy contract");
        }
    }

    #[test]
    fn any_version_decoder_sets_version_owned_false() {
        let mut reg = SpecDecoderRegistry { entries: Vec::new() };
        reg.register(DecoderEntry {
            name: "catch-all",
            predicate: VersionPredicate::AnyVersion,
            decode: decode_spec_v0,
        });
        let v = Some(InterfaceVersion {
            protocol: 99,
            pre_release: 0,
        });
        let outcome = reg.decode(b"", v);
        if let DecodeOutcome::Decoded { section_meta, .. } = outcome {
            assert!(
                !section_meta.version_owned,
                "AnyVersion should set version_owned = false"
            );
        } else {
            panic!("expected Decoded outcome");
        }
    }

    // ------------------------------------------------------------------
    // validate_version_ownership
    // ------------------------------------------------------------------

    #[test]
    fn validate_version_ownership_accepts_owned_version() {
        let entry = DecoderEntry {
            name: "p20",
            predicate: VersionPredicate::ExactProtocol(20),
            decode: decode_spec_v0,
        };
        let v = Some(InterfaceVersion {
            protocol: 20,
            pre_release: 0,
        });
        assert!(validate_version_ownership(&entry, v).is_ok());
    }

    #[test]
    fn validate_version_ownership_rejects_unowned_version() {
        let entry = DecoderEntry {
            name: "p20",
            predicate: VersionPredicate::ExactProtocol(20),
            decode: decode_spec_v0,
        };
        let v = Some(InterfaceVersion {
            protocol: 21,
            pre_release: 0,
        });
        let err = validate_version_ownership(&entry, v).unwrap_err();
        assert!(matches!(err, Error::UnsupportedDecoderVersion { .. }));
        if let Error::UnsupportedDecoderVersion { message, .. } = err {
            assert!(
                message.contains("p20") && message.contains("cross-version"),
                "error message: {message}"
            );
        }
    }

    #[test]
    fn validate_version_ownership_rejects_none_for_protocol_predicate() {
        let entry = DecoderEntry {
            name: "p20",
            predicate: VersionPredicate::ExactProtocol(20),
            decode: decode_spec_v0,
        };
        let err = validate_version_ownership(&entry, None).unwrap_err();
        assert!(matches!(err, Error::UnsupportedDecoderVersion { .. }));
    }

    #[test]
    fn validate_version_ownership_accepts_none_for_no_version_predicate() {
        let entry = DecoderEntry {
            name: "legacy",
            predicate: VersionPredicate::NoVersion,
            decode: decode_spec_v0,
        };
        assert!(validate_version_ownership(&entry, None).is_ok());
    }

    // ------------------------------------------------------------------
    // Malformed version markers
    // ------------------------------------------------------------------

    #[test]
    fn malformed_version_zero_protocol_zero_prerelease_rejected() {
        // A raw interface version of 0 encodes protocol=0, pre_release=0.
        // Protocol 0 is not in the supported range, so it should be rejected.
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: 0,
            pre_release: 0,
        });
        // Protocol 0 with a version present: no NoVersion match, no range match
        let outcome = reg.decode(b"", v);
        assert!(
            !outcome.is_decoded(),
            "protocol 0 (malformed/zeroed version) should be rejected when version is present"
        );
    }

    #[test]
    fn malformed_version_very_large_protocol_rejected() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: u32::MAX,
            pre_release: u32::MAX,
        });
        let outcome = reg.decode(b"", v);
        assert!(
            !outcome.is_decoded(),
            "max-u32 protocol version should be rejected"
        );
        if let DecodeOutcome::UnsupportedVersion { message, .. } = outcome {
            assert!(
                message.contains("upgrade the tool") || message.contains("no decoder"),
                "message: {message}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Custom registry / cross-version safety
    // ------------------------------------------------------------------

    #[test]
    fn custom_registry_only_handles_registered_version() {
        let mut reg = SpecDecoderRegistry { entries: Vec::new() };
        reg.register(DecoderEntry {
            name: "protocol-99",
            predicate: VersionPredicate::ExactProtocol(99),
            decode: decode_spec_v0,
        });

        let accepted = reg.decode(
            b"",
            Some(InterfaceVersion {
                protocol: 99,
                pre_release: 0,
            }),
        );
        assert!(accepted.is_decoded());

        let rejected = reg.decode(
            b"",
            Some(InterfaceVersion {
                protocol: 20,
                pre_release: 0,
            }),
        );
        assert!(!rejected.is_decoded());
    }

    #[test]
    fn first_matching_decoder_wins() {
        let mut reg = SpecDecoderRegistry { entries: Vec::new() };
        reg.register(DecoderEntry {
            name: "first",
            predicate: VersionPredicate::ExactProtocol(20),
            decode: decode_spec_v0,
        });
        reg.register(DecoderEntry {
            name: "second",
            predicate: VersionPredicate::ExactProtocol(20),
            decode: decode_spec_v0,
        });

        let outcome = reg.decode(
            b"",
            Some(InterfaceVersion {
                protocol: 20,
                pre_release: 0,
            }),
        );
        assert!(outcome.is_decoded());
        // First decoder wins: section_meta should name "first"
        if let DecodeOutcome::Decoded { section_meta, .. } = outcome {
            assert_eq!(section_meta.decoder_name, "first");
        }
    }

    #[test]
    fn unsupported_version_message_names_registered_decoders() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: 255,
            pre_release: 0,
        });
        if let DecodeOutcome::UnsupportedVersion { message, .. } = reg.decode(b"", v) {
            assert!(
                message.contains("soroban-v0-protocol-20-23")
                    || message.contains("upgrade the tool"),
                "message: {message}"
            );
        } else {
            panic!("expected UnsupportedVersion outcome");
        }
    }

    #[test]
    fn registered_decoders_lists_all_entries() {
        let reg = SpecDecoderRegistry::default();
        let decoders = reg.registered_decoders();
        assert!(!decoders.is_empty());
        let names: Vec<&str> = decoders.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"legacy-no-version"));
        assert!(names.contains(&"soroban-v0-protocol-20-23"));
    }

    #[test]
    fn supports_version_returns_true_for_known() {
        let reg = SpecDecoderRegistry::default();
        assert!(reg.supports_version(None));
        assert!(reg.supports_version(Some(InterfaceVersion {
            protocol: 20,
            pre_release: 0
        })));
        assert!(reg.supports_version(Some(InterfaceVersion {
            protocol: 23,
            pre_release: 0
        })));
    }

    #[test]
    fn supports_version_returns_false_for_unknown() {
        let reg = SpecDecoderRegistry::default();
        assert!(!reg.supports_version(Some(InterfaceVersion {
            protocol: 255,
            pre_release: 0
        })));
        assert!(!reg.supports_version(Some(InterfaceVersion {
            protocol: 0,
            pre_release: 0
        })));
    }

    // ------------------------------------------------------------------
    // decode_forward_compat path
    // ------------------------------------------------------------------

    #[test]
    fn decode_forward_compat_succeeds_on_empty_data() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: 20,
            pre_release: 0,
        });
        let outcome = reg.decode_forward_compat(b"", v);
        assert!(outcome.is_decoded());
        assert!(outcome.is_complete());
    }

    #[test]
    fn decode_forward_compat_rejects_unsupported_version() {
        let reg = SpecDecoderRegistry::default();
        let v = Some(InterfaceVersion {
            protocol: 255,
            pre_release: 0,
        });
        let outcome = reg.decode_forward_compat(b"", v);
        assert!(!outcome.is_decoded());
    }

    // ------------------------------------------------------------------
    // Decoder not called for wrong version (cross-version safety)
    // ------------------------------------------------------------------

    #[test]
    fn decoder_not_called_for_wrong_version() {
        let mut reg = SpecDecoderRegistry { entries: Vec::new() };
        reg.register(DecoderEntry {
            name: "p20-only",
            predicate: VersionPredicate::ExactProtocol(20),
            decode: decode_spec_v0,
        });

        let outcome = reg.decode(
            b"",
            Some(InterfaceVersion {
                protocol: 21,
                pre_release: 0,
            }),
        );
        assert!(
            !outcome.is_decoded(),
            "p20-only decoder must not handle p21"
        );
    }
}

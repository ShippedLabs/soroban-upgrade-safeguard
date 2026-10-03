// SPDX-License-Identifier: MIT

//! Signed, centrally governed policy bundles.
//!
//! Named local policy profiles (`src/profile.rs`) are useful within one
//! repository. An organization running this tool across many repositories
//! may instead want one centrally governed compatibility policy, resource
//! limits, and rule documentation, distributed and verified the same way
//! everywhere. A [`PolicyBundle`] is that: a small, versioned, *signed*
//! document a run can opt into with `--policy-bundle`.
//!
//! # Trust model
//!
//! A bundle is wrapped in the same DSSE envelope shape `src/attestation.rs`
//! uses for signed reports (`payloadType`/`payload`/`signatures`), and its
//! payload type (`POLICY_BUNDLE_PAYLOAD_TYPE`) is deliberately different
//! from the report attestation's (`application/vnd.in-toto+json`) so the
//! two can never be confused for one another. Signature verification
//! reuses `attestation.rs`'s actual cryptographic primitives —
//! [`crate::attestation::dsse_pae`] (the DSSE pre-authentication encoding)
//! and [`crate::attestation::canonical_json_bytes`] (the same
//! canonicalization reports are signed over) — rather than a second,
//! independent implementation. It does **not** reuse
//! [`crate::attestation::verify_signatures`] or
//! [`crate::attestation::DsseEnvelope::statement`] directly: both are
//! hardcoded to decode `InTotoStatementV1`, the report-attestation
//! statement shape, so reusing them would mean teaching attestation
//! verification about an unrelated payload type. [`verify_bundle_envelope`]
//! is the bundle-shaped sibling, built from the same primitives.
//!
//! Verification ([`verify_bundle_envelope`]) rejects a bundle *before*
//! returning one the caller can apply, for every one of: malformed
//! envelope/payload, wrong payload type, non-canonical payload, an
//! unsupported schema version, no signatures, a signature from an
//! untrusted identity, a signature that doesn't verify, and an expired
//! bundle (`expires_at` in the past). There is no partial-trust path: any
//! one of these fails the whole bundle.
//!
//! # What a bundle can never contain
//!
//! [`PolicyBundle`] has no field for suppression rules, migrations, or
//! credentials, and (`#[serde(deny_unknown_fields)]`) rejects a payload
//! that tries to smuggle one in under any name — a malformed-payload
//! verification failure, not a silently-ignored extra field. A bundle can
//! supply *governance* (gating policy, resource limits, rule
//! documentation, capability data); it can never supply a specific
//! acknowledged break, which stays a local, human decision.
//!
//! # Precedence: a bundle can only tighten, never loosen
//!
//! [`apply_bundle_policy`] merges a verified bundle's gating policy into
//! the local [`crate::suppression::SuppressionConfig`] with an OR-union:
//! an axis or rule the bundle wants reviewed is added to what the local
//! config already requires, and nothing the local config already enforces
//! can be turned off by a bundle. [`merge_limits`] does the resource-limit
//! analog with a minimum: the *more restrictive* of the local and bundle
//! value wins for each cap. Both directions of this matter equally: a
//! compromised or misconfigured bundle source can make a run stricter
//! than the operator intended, never more permissive than the local repo
//! or CLI flags already made it.
//!
//! # Scope of this pass
//!
//! - **Capability overrides** ([`CapabilityOverrideEntry`]) round-trip
//!   through the format and are exposed via [`PolicyBundle::capability_overrides`],
//!   but are not yet consulted by [`crate::capability::lookup`] — wiring
//!   bundle-supplied capability data into live host-import classification
//!   is a follow-up.
//! - **Limits** ([`merge_limits`]) are merged as a pure, tested function,
//!   but the main comparison pipeline does not yet thread *any*
//!   `.safeguard.toml` `[limits]` table into live WASM parsing either
//!   (`ResourcePolicy::default()` is used unconditionally outside `lint`) —
//!   this is a pre-existing gap, not one this feature introduces, and
//!   fixing it is out of scope here.
//! - **Batch mode** does not support `--policy-bundle` yet; it is rejected
//!   with a clear error rather than silently ignored (see `src/main.rs`).

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ring::signature;
use serde::{Deserialize, Serialize};

use crate::attestation::{
    canonical_json_bytes, dsse_pae, AttestationError, AttestationSigner, DsseEnvelope,
    DsseSignature,
};
use crate::diff::Severity;
use crate::error::Error;
use crate::limits::LimitsConfig;
use crate::suppression::{PolicyConfig, RequireReasonPolicy, SuppressionConfig};

/// Current version of the policy-bundle format.
pub const POLICY_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// The DSSE `payloadType` a policy bundle's envelope must declare.
/// Deliberately distinct from `crate::attestation::DSSE_PAYLOAD_TYPE`, so a
/// report attestation and a policy bundle can never be confused for each
/// other even though both are DSSE envelopes.
pub const POLICY_BUNDLE_PAYLOAD_TYPE: &str =
    "application/vnd.soroban-upgrade-safeguard.policy-bundle+json";

/// Documentation for one compatibility rule/category, supplied by the
/// bundle's governing organization. Never a suppression — it describes
/// the rule itself, not an acknowledged instance of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleMetadataEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_severity: Option<Severity>,
}

/// An organization-supplied addition to the host-import capability
/// registry (`crate::capability`) — e.g. for a custom or forked Soroban
/// host environment with host imports not in the upstream registry.
/// See the module docs for why this isn't wired into live classification
/// yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityOverrideEntry {
    pub module: String,
    pub name: String,
    pub function: String,
    pub capability_id: String,
    pub group: String,
    pub min_protocol: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<String>,
}

/// A versioned, signed policy bundle. See the module docs for the trust
/// model and precedence rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub version: u32,
    /// A stable identifier for this bundle (e.g. `"org-baseline-2026"`),
    /// surfaced in provenance so a run can be traced back to which
    /// governance document it used.
    pub bundle_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    /// Unix timestamp after which this bundle must be rejected. `None`
    /// means the bundle never expires on its own (still subject to key
    /// rotation/revocation via the trusted-key set a run is given).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub require_reason: RequireReasonPolicy,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rule_metadata: BTreeMap<String, RuleMetadataEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_overrides: Vec<CapabilityOverrideEntry>,
}

impl PolicyBundle {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        canonical_json_bytes(self)
    }

    pub fn capability_overrides(&self) -> &[CapabilityOverrideEntry] {
        &self.capability_overrides
    }
}

/// Why a bundle, or one of its signatures, failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BundleFailureKind {
    InvalidEnvelope,
    UnsupportedPayloadType,
    NonCanonicalPayload,
    UnsupportedVersion,
    NoSignatures,
    UntrustedSigner,
    InvalidSignature,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BundleFailure {
    pub kind: BundleFailureKind,
    pub message: String,
}

/// What a run recorded about a policy bundle it tried to apply — present
/// in the report regardless of outcome, so "a bundle was used and
/// verified" is never indistinguishable from "no bundle was used at all".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleProvenance {
    /// Where the bundle came from: a redacted URL, or a local file path.
    pub source: String,
    /// `sha256:<hex>` of the raw envelope bytes, exactly as fetched/read —
    /// an immutable fingerprint of what was actually used, independent of
    /// whether verification succeeded.
    pub digest: String,
    pub signer_identities: Vec<String>,
    pub bundle_id: String,
    pub bundle_version: u32,
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<BundleFailure>,
}

/// Verify a policy bundle's DSSE envelope: payload type, canonical
/// encoding, schema version, expiry, and at least one signature from
/// `trusted_keys` (raw 32-byte Ed25519 public keys keyed by identity).
///
/// `source` is a label for provenance only (e.g. a redacted URL or local
/// path) — it plays no part in verification itself. `now_unix_secs` is
/// the caller's "current time" for the expiry check, taken as a
/// parameter (rather than read internally) so tests can exercise expiry
/// deterministically.
///
/// Returns the parsed bundle and its provenance only when verification
/// fully succeeds; any failure is returned as an [`Error::Integrity`]
/// whose message lists every reason, so a caller can reject the bundle
/// outright rather than deciding which failures are "safe enough" to
/// proceed past.
pub fn verify_bundle_envelope(
    envelope_bytes: &[u8],
    trusted_keys: &BTreeMap<String, Vec<u8>>,
    now_unix_secs: u64,
    source: &str,
) -> Result<(PolicyBundle, BundleProvenance), Error> {
    let digest = format!("sha256:{}", crate::bundle::sha256_hex(envelope_bytes));

    let envelope: DsseEnvelope =
        serde_json::from_slice(envelope_bytes).map_err(|e| Error::Integrity {
            details: format!("Policy bundle envelope is not valid JSON: {e}"),
            source: Some(Box::new(e)),
        })?;

    let mut failures = Vec::new();

    if envelope.payload_type != POLICY_BUNDLE_PAYLOAD_TYPE {
        failures.push(BundleFailure {
            kind: BundleFailureKind::UnsupportedPayloadType,
            message: format!(
                "expected payloadType '{POLICY_BUNDLE_PAYLOAD_TYPE}', got '{}'",
                envelope.payload_type
            ),
        });
    }

    let payload = BASE64.decode(&envelope.payload).map_err(|e| Error::Integrity {
        details: format!("Policy bundle payload is not valid base64: {e}"),
        source: None,
    })?;

    let bundle: PolicyBundle =
        serde_json::from_slice(&payload).map_err(|e| Error::Integrity {
            details: format!("Policy bundle payload does not match the expected schema: {e}"),
            source: Some(Box::new(e)),
        })?;

    if bundle.canonical_bytes().ok().as_deref() != Some(payload.as_slice()) {
        failures.push(BundleFailure {
            kind: BundleFailureKind::NonCanonicalPayload,
            message: "bundle payload is not in canonical JSON form".to_string(),
        });
    }

    if bundle.version != POLICY_BUNDLE_SCHEMA_VERSION {
        failures.push(BundleFailure {
            kind: BundleFailureKind::UnsupportedVersion,
            message: format!(
                "bundle declares version {} but this build supports version {POLICY_BUNDLE_SCHEMA_VERSION}",
                bundle.version
            ),
        });
    }

    if let Some(expires_at) = bundle.expires_at {
        if now_unix_secs >= expires_at {
            failures.push(BundleFailure {
                kind: BundleFailureKind::Expired,
                message: format!("bundle expired at Unix timestamp {expires_at}"),
            });
        }
    }

    if envelope.signatures.is_empty() {
        failures.push(BundleFailure {
            kind: BundleFailureKind::NoSignatures,
            message: "envelope contains no signatures".to_string(),
        });
    }

    let pae = dsse_pae(&envelope.payload_type, &payload);
    let mut signer_identities = Vec::new();
    let mut any_verified = false;
    for sig in &envelope.signatures {
        let Some(public_key) = trusted_keys.get(&sig.keyid) else {
            failures.push(BundleFailure {
                kind: BundleFailureKind::UntrustedSigner,
                message: format!(
                    "signature identity '{}' is not in the trusted key set",
                    sig.keyid
                ),
            });
            continue;
        };
        let sig_bytes = match BASE64.decode(&sig.sig) {
            Ok(bytes) => bytes,
            Err(_) => {
                failures.push(BundleFailure {
                    kind: BundleFailureKind::InvalidSignature,
                    message: format!("signature '{}' is not valid base64", sig.keyid),
                });
                continue;
            }
        };
        if signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&pae, &sig_bytes)
            .is_ok()
        {
            signer_identities.push(sig.keyid.clone());
            any_verified = true;
        } else {
            failures.push(BundleFailure {
                kind: BundleFailureKind::InvalidSignature,
                message: format!(
                    "signature '{}' does not verify against its trusted key",
                    sig.keyid
                ),
            });
        }
    }

    let verified = any_verified && failures.is_empty();

    let provenance = BundleProvenance {
        source: source.to_string(),
        digest,
        signer_identities,
        bundle_id: bundle.bundle_id.clone(),
        bundle_version: bundle.version,
        verified,
        failures: failures.clone(),
    };

    if !verified {
        return Err(Error::Integrity {
            details: format!(
                "Policy bundle '{source}' failed verification: {}",
                failures
                    .iter()
                    .map(|f| f.message.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            source: None,
        });
    }

    Ok((bundle, provenance))
}

/// Sign `bundle`, producing the DSSE envelope a run would load with
/// `--policy-bundle`. Reuses [`crate::attestation::AttestationSigner`]
/// directly — the same signing trait and `Ed25519Signer` implementation
/// reports are signed with — so operators who already manage attestation
/// keys can sign policy bundles with the same key material and tooling.
pub fn sign_bundle(
    bundle: &PolicyBundle,
    signer: &dyn AttestationSigner,
) -> Result<DsseEnvelope, AttestationError> {
    let payload = bundle.canonical_bytes()?;
    let pae = dsse_pae(POLICY_BUNDLE_PAYLOAD_TYPE, &payload);
    let sig_bytes = signer.sign(&pae)?;
    Ok(DsseEnvelope {
        payload_type: POLICY_BUNDLE_PAYLOAD_TYPE.to_string(),
        payload: BASE64.encode(&payload),
        signatures: vec![DsseSignature {
            keyid: signer.key_id().to_string(),
            sig: BASE64.encode(&sig_bytes),
        }],
    })
}

/// Merge a verified bundle's gating policy into `suppressions`, in place.
/// See the module docs for why this is an OR-union rather than a
/// replacement: the bundle can only add gates/review requirements the
/// local config didn't already have, never remove one.
pub fn apply_bundle_policy(suppressions: &mut SuppressionConfig, bundle: &PolicyBundle) {
    suppressions.policy.gate_storage_layout |= bundle.policy.gate_storage_layout;
    suppressions.policy.gate_call_abi |= bundle.policy.gate_call_abi;
    suppressions.policy.gate_event_indexer |= bundle.policy.gate_event_indexer;
    suppressions.policy.gate_source_level |= bundle.policy.gate_source_level;
    suppressions.policy.gate_runtime_surface |= bundle.policy.gate_runtime_surface;

    for id in &bundle.require_reason.rule_ids {
        if !suppressions.require_reason.rule_ids.contains(id) {
            suppressions.require_reason.rule_ids.push(id.clone());
        }
    }
    for axis in &bundle.require_reason.axes {
        if !suppressions.require_reason.axes.contains(axis) {
            suppressions.require_reason.axes.push(*axis);
        }
    }
}

/// Merge a verified bundle's resource limits with `local`, keeping
/// whichever value is more restrictive (smaller) for each cap — the
/// resource-limit analog of [`apply_bundle_policy`]'s OR-union. See the
/// module docs for why this isn't yet wired into live WASM parsing.
pub fn merge_limits(local: &LimitsConfig, bundle: &LimitsConfig) -> LimitsConfig {
    fn tighter_u32(a: Option<u32>, b: Option<u32>) -> Option<u32> {
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (Some(x), None) | (None, Some(x)) => Some(x),
            (None, None) => None,
        }
    }
    fn tighter_usize(a: Option<usize>, b: Option<usize>) -> Option<usize> {
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (Some(x), None) | (None, Some(x)) => Some(x),
            (None, None) => None,
        }
    }
    LimitsConfig {
        max_xdr_depth: tighter_u32(local.max_xdr_depth, bundle.max_xdr_depth),
        max_xdr_len: tighter_usize(local.max_xdr_len, bundle.max_xdr_len),
        max_entries: tighter_usize(local.max_entries, bundle.max_entries),
        max_walk_depth: tighter_usize(local.max_walk_depth, bundle.max_walk_depth),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Ed25519Signer;
    use crate::diff::CompatibilityAxis;

    /// A fixed (not randomly generated) Ed25519 PKCS#8 v1 private key
    /// (`PrivateKeyInfo`, no embedded public key — the form
    /// `Ed25519KeyPair::from_pkcs8_maybe_unchecked` accepts), so signing
    /// vector tests are fully deterministic across runs. Generated once
    /// with `openssl genpkey -algorithm ed25519` and converted to DER
    /// with `openssl pkey -outform DER`, then frozen here as a byte
    /// literal — not a real, trusted key.
    const TEST_PKCS8: [u8; 48] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20, 0x83, 0xe6, 0x15, 0x76, 0xfd, 0x09, 0xae, 0x04, 0xea, 0xf3, 0x6d, 0xdb, 0x9a, 0x2b,
        0xee, 0x62, 0x5d, 0x55, 0xe8, 0xc0, 0x9e, 0xc6, 0xa1, 0x81, 0x72, 0x5d, 0x5f, 0xc5, 0xc9,
        0x64, 0xfa, 0xcf,
    ];

    fn test_signer() -> Ed25519Signer {
        Ed25519Signer::from_pkcs8("test-key", &TEST_PKCS8).expect("valid test PKCS#8 key")
    }

    fn sample_bundle() -> PolicyBundle {
        PolicyBundle {
            version: POLICY_BUNDLE_SCHEMA_VERSION,
            bundle_id: "org-baseline-2026".to_string(),
            issued_at: Some("2026-01-01T00:00:00Z".to_string()),
            expires_at: Some(4_000_000_000), // far future
            policy: PolicyConfig {
                gate_storage_layout: true,
                gate_call_abi: true,
                gate_event_indexer: true,
                gate_source_level: false,
                gate_runtime_surface: true,
            },
            require_reason: RequireReasonPolicy {
                rule_ids: vec!["struct_field_removed".to_string()],
                axes: vec![],
            },
            limits: LimitsConfig {
                max_xdr_depth: Some(16),
                max_xdr_len: None,
                max_entries: None,
                max_walk_depth: None,
            },
            rule_metadata: BTreeMap::new(),
            capability_overrides: Vec::new(),
        }
    }

    fn trust_store_for(signer: &Ed25519Signer) -> BTreeMap<String, Vec<u8>> {
        let mut trusted = BTreeMap::new();
        trusted.insert(signer.key_id().to_string(), signer.public_key());
        trusted
    }

    #[test]
    fn signing_is_deterministic() {
        // Ed25519 signatures are deterministic for a given key+message (no
        // randomized nonce, unlike e.g. ECDSA), so signing the same bundle
        // twice with the same fixed test key must produce byte-identical
        // envelopes -- this is the "deterministic signing vector" the
        // ticket asks for.
        let bundle = sample_bundle();
        let signer = test_signer();
        let envelope_a = sign_bundle(&bundle, &signer).unwrap();
        let envelope_b = sign_bundle(&bundle, &signer).unwrap();
        assert_eq!(envelope_a, envelope_b);
    }

    #[test]
    fn a_correctly_signed_bundle_verifies() {
        let bundle = sample_bundle();
        let signer = test_signer();
        let envelope = sign_bundle(&bundle, &signer).unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let trusted = trust_store_for(&signer);

        let (verified_bundle, provenance) =
            verify_bundle_envelope(&bytes, &trusted, 0, "test").expect("should verify");
        assert_eq!(verified_bundle, bundle);
        assert!(provenance.verified);
        assert_eq!(provenance.signer_identities, vec!["test-key".to_string()]);
        assert!(provenance.failures.is_empty());
        assert!(provenance.digest.starts_with("sha256:"));
    }

    #[test]
    fn a_tampered_payload_is_rejected() {
        let bundle = sample_bundle();
        let signer = test_signer();
        let envelope = sign_bundle(&bundle, &signer).unwrap();
        let mut tampered = envelope.clone();
        // Flip the policy by re-encoding a different bundle under the same
        // signature -- the signature was computed over the *original*
        // payload bytes, so this must fail even though the new payload is
        // itself well-formed JSON.
        let mut other = bundle.clone();
        other.policy.gate_storage_layout = false;
        tampered.payload = BASE64.encode(other.canonical_bytes().unwrap());

        let bytes = serde_json::to_vec(&tampered).unwrap();
        let trusted = trust_store_for(&signer);
        let err = verify_bundle_envelope(&bytes, &trusted, 0, "test")
            .expect_err("tampered payload must fail verification");
        assert!(format!("{err}").contains("does not verify"));
    }

    #[test]
    fn an_untrusted_signer_is_rejected() {
        let bundle = sample_bundle();
        let signer = test_signer();
        let envelope = sign_bundle(&bundle, &signer).unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();

        let empty_trust_store = BTreeMap::new();
        let err = verify_bundle_envelope(&bytes, &empty_trust_store, 0, "test")
            .expect_err("untrusted signer must be rejected");
        assert!(format!("{err}").contains("not in the trusted key set"));
    }

    #[test]
    fn an_expired_bundle_is_rejected() {
        let mut bundle = sample_bundle();
        bundle.expires_at = Some(1_000);
        let signer = test_signer();
        let envelope = sign_bundle(&bundle, &signer).unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let trusted = trust_store_for(&signer);

        // "now" (2_000) is after the bundle's expiry (1_000).
        let err = verify_bundle_envelope(&bytes, &trusted, 2_000, "test")
            .expect_err("expired bundle must be rejected");
        assert!(format!("{err}").contains("expired"));
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let mut bundle = sample_bundle();
        bundle.version = POLICY_BUNDLE_SCHEMA_VERSION + 1;
        let signer = test_signer();
        let envelope = sign_bundle(&bundle, &signer).unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let trusted = trust_store_for(&signer);

        let err = verify_bundle_envelope(&bytes, &trusted, 0, "test")
            .expect_err("unsupported version must be rejected");
        assert!(format!("{err}").contains("version"));
    }

    #[test]
    fn wrong_payload_type_is_rejected() {
        let bundle = sample_bundle();
        let signer = test_signer();
        let mut envelope = sign_bundle(&bundle, &signer).unwrap();
        envelope.payload_type = "application/vnd.in-toto+json".to_string();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let trusted = trust_store_for(&signer);

        let err = verify_bundle_envelope(&bytes, &trusted, 0, "test")
            .expect_err("wrong payload type must be rejected");
        assert!(format!("{err}").contains("payloadType"));
    }

    #[test]
    fn a_bundle_with_no_signatures_is_rejected() {
        let bundle = sample_bundle();
        let envelope = DsseEnvelope {
            payload_type: POLICY_BUNDLE_PAYLOAD_TYPE.to_string(),
            payload: BASE64.encode(bundle.canonical_bytes().unwrap()),
            signatures: vec![],
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let trusted: BTreeMap<String, Vec<u8>> = BTreeMap::new();

        let err = verify_bundle_envelope(&bytes, &trusted, 0, "test")
            .expect_err("a bundle with no signatures must be rejected");
        assert!(format!("{err}").contains("no signatures"));
    }

    #[test]
    fn a_payload_claiming_suppression_rules_is_rejected_as_malformed() {
        // Structural guarantee: there is no way to express a suppression
        // *inside* a bundle at all. An attempt to smuggle one in under the
        // field name real suppression configs use is just an unknown
        // field, rejected by `deny_unknown_fields` before anything about
        // signatures is even considered.
        let mut value = serde_json::to_value(sample_bundle()).unwrap();
        value["suppress"] = serde_json::json!([{
            "category": "Struct Field Removed",
            "target": "Anything",
        }]);
        let err = serde_json::from_value::<PolicyBundle>(value)
            .expect_err("a bundle payload with a 'suppress' field must not deserialize");
        assert!(format!("{err}").contains("suppress") || format!("{err}").contains("unknown field"));
    }

    #[test]
    fn apply_bundle_policy_only_adds_gates_never_removes_them() {
        let mut suppressions = SuppressionConfig::default();
        // Local config has explicitly turned event-indexer gating off (the
        // default -- but pretend it was a deliberate choice) and has no
        // require_reason entries.
        suppressions.policy.gate_event_indexer = false;
        suppressions.policy.gate_source_level = false;

        let bundle = sample_bundle(); // gate_event_indexer: true, gate_source_level: false
        apply_bundle_policy(&mut suppressions, &bundle);

        assert!(
            suppressions.policy.gate_event_indexer,
            "bundle requested gate_event_indexer; OR-union must turn it on"
        );
        assert!(
            !suppressions.policy.gate_source_level,
            "neither local nor bundle requested gate_source_level; must stay off"
        );
        assert!(suppressions
            .require_reason
            .rule_ids
            .contains(&"struct_field_removed".to_string()));
    }

    #[test]
    fn apply_bundle_policy_cannot_turn_off_a_locally_enabled_gate() {
        let mut suppressions = SuppressionConfig::default();
        suppressions.policy.gate_source_level = true; // local explicitly wants this gated

        let mut bundle = sample_bundle();
        bundle.policy.gate_source_level = false; // bundle doesn't ask for it

        apply_bundle_policy(&mut suppressions, &bundle);

        assert!(
            suppressions.policy.gate_source_level,
            "a bundle must never be able to turn off a gate local config enabled"
        );
    }

    #[test]
    fn apply_bundle_policy_merges_require_reason_without_duplicating() {
        let mut suppressions = SuppressionConfig::default();
        suppressions.require_reason.rule_ids = vec!["struct_field_removed".to_string()];
        suppressions.require_reason.axes = vec![CompatibilityAxis::CallAbi];

        let mut bundle = sample_bundle();
        bundle.require_reason.rule_ids = vec!["struct_field_removed".to_string(), "function_removed".to_string()];
        bundle.require_reason.axes = vec![CompatibilityAxis::StorageLayout];

        apply_bundle_policy(&mut suppressions, &bundle);

        assert_eq!(
            suppressions.require_reason.rule_ids,
            vec!["struct_field_removed".to_string(), "function_removed".to_string()]
        );
        assert_eq!(
            suppressions.require_reason.axes,
            vec![CompatibilityAxis::CallAbi, CompatibilityAxis::StorageLayout]
        );
    }

    #[test]
    fn merge_limits_keeps_the_more_restrictive_value() {
        let local = LimitsConfig {
            max_xdr_depth: Some(64),
            max_xdr_len: None,
            max_entries: Some(1000),
            max_walk_depth: None,
        };
        let bundle = LimitsConfig {
            max_xdr_depth: Some(32), // tighter than local
            max_xdr_len: Some(4096), // local has none, so this applies
            max_entries: Some(5000), // looser than local -- local must win
            max_walk_depth: None,
        };

        let merged = merge_limits(&local, &bundle);
        assert_eq!(merged.max_xdr_depth, Some(32), "bundle's tighter depth cap must win");
        assert_eq!(merged.max_xdr_len, Some(4096), "bundle may set a cap local left unset");
        assert_eq!(merged.max_entries, Some(1000), "local's tighter cap must win over a looser bundle value");
        assert_eq!(merged.max_walk_depth, None);
    }
}

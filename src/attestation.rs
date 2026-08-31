//! Deterministic in-toto statements and DSSE signing primitives.
//!
//! Signing is performed over the DSSE pre-authentication encoding (PAE) of a
//! canonical JSON in-toto statement. Rendered reports are never signed.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str =
    "https://github.com/ShippedLabs/soroban-upgrade-safeguard/attestation/v1";
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDigest {
    pub sha256: String,
}

impl ArtifactDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        self == &Self::from_bytes(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InTotoSubject {
    pub name: String,
    pub digest: ArtifactDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedArtifact {
    pub name: String,
    pub digest: ArtifactDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedTool {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedVerdict {
    pub is_safe: bool,
    pub recommended_bump: String,
    pub old_client_to_new_contract: bool,
    pub new_client_to_old_contract: bool,
}

/// Version 1 safeguard analysis predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafeguardPredicateV1 {
    pub version: u32,
    pub tool: AttestedTool,
    pub inputs: Vec<AttestedArtifact>,
    pub extracted_specs: Vec<AttestedArtifact>,
    pub storage_schemas: Vec<AttestedArtifact>,
    pub resolved_policy: Value,
    pub report: AttestedArtifact,
    pub verdict: AttestedVerdict,
}

impl SafeguardPredicateV1 {
    pub fn new(
        inputs: Vec<AttestedArtifact>,
        extracted_specs: Vec<AttestedArtifact>,
        storage_schemas: Vec<AttestedArtifact>,
        resolved_policy: Value,
        report: AttestedArtifact,
        verdict: AttestedVerdict,
    ) -> Self {
        Self {
            version: 1,
            tool: AttestedTool {
                name: "soroban-upgrade-safeguard".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            inputs,
            extracted_specs,
            storage_schemas,
            resolved_policy,
            report,
            verdict,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InTotoStatementV1 {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<InTotoSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: SafeguardPredicateV1,
}

impl InTotoStatementV1 {
    pub fn new(mut subject: Vec<InTotoSubject>, predicate: SafeguardPredicateV1) -> Self {
        subject.sort_by(|a, b| a.name.cmp(&b.name));
        Self {
            statement_type: STATEMENT_TYPE.to_string(),
            subject,
            predicate_type: PREDICATE_TYPE.to_string(),
            predicate,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        canonical_json_bytes(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    pub fn statement(&self) -> Result<InTotoStatementV1, AttestationError> {
        if self.payload_type != DSSE_PAYLOAD_TYPE {
            return Err(AttestationError::InvalidPayloadType(
                self.payload_type.clone(),
            ));
        }
        let bytes = BASE64
            .decode(&self.payload)
            .map_err(|_| AttestationError::InvalidBase64("payload"))?;
        let statement: InTotoStatementV1 =
            serde_json::from_slice(&bytes).map_err(AttestationError::InvalidStatement)?;
        if statement.canonical_bytes()? != bytes {
            return Err(AttestationError::NonCanonicalPayload);
        }
        statement.validate()?;
        Ok(statement)
    }
}

impl InTotoStatementV1 {
    fn validate(&self) -> Result<(), AttestationError> {
        if self.statement_type != STATEMENT_TYPE {
            return Err(AttestationError::InvalidStatementShape(format!(
                "unsupported in-toto statement type '{}'",
                self.statement_type
            )));
        }
        if self.predicate_type != PREDICATE_TYPE {
            return Err(AttestationError::InvalidStatementShape(format!(
                "unsupported safeguard predicate type '{}'",
                self.predicate_type
            )));
        }
        if self.predicate.version != 1 {
            return Err(AttestationError::InvalidStatementShape(format!(
                "unsupported safeguard predicate version {}",
                self.predicate.version
            )));
        }
        Ok(())
    }
}

/// Pluggable signing interface. Implementations receive only DSSE PAE bytes;
/// private key material never enters the statement or envelope.
pub trait AttestationSigner {
    fn key_id(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AttestationError>;
}

pub struct Ed25519Signer {
    key_id: String,
    key_pair: signature::Ed25519KeyPair,
}

impl Ed25519Signer {
    /// Load an Ed25519 key from unencrypted PKCS#8 v1 or v2 bytes. Diagnostics
    /// never include the supplied bytes.
    pub fn from_pkcs8(
        key_id: impl Into<String>,
        private_key: &[u8],
    ) -> Result<Self, AttestationError> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(private_key)
            .map_err(|_| AttestationError::InvalidPrivateKey)?;
        Ok(Self {
            key_id: key_id.into(),
            key_pair,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key_pair.public_key().as_ref().to_vec()
    }
}

impl AttestationSigner for Ed25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AttestationError> {
        Ok(self.key_pair.sign(message).as_ref().to_vec())
    }
}

pub fn sign_statement(
    statement: &InTotoStatementV1,
    signer: &dyn AttestationSigner,
) -> Result<DsseEnvelope, AttestationError> {
    let payload = statement.canonical_bytes()?;
    let pae = dsse_pae(DSSE_PAYLOAD_TYPE, &payload);
    let signature = signer.sign(&pae)?;
    Ok(DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_string(),
        payload: BASE64.encode(payload),
        signatures: vec![DsseSignature {
            keyid: signer.key_id().to_string(),
            sig: BASE64.encode(signature),
        }],
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailureKind {
    MissingArtifact,
    ArtifactDigestMismatch,
    UntrustedSigner,
    InvalidSignature,
    NonCanonicalPayload,
    ExpiredPolicy,
    InvalidStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationFailure {
    pub kind: VerificationFailureKind,
    pub subject: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerification {
    pub verified: bool,
    pub signer_identities: Vec<String>,
    pub failures: Vec<VerificationFailure>,
}

#[derive(Debug, Clone, Default)]
pub struct VerificationPolicy {
    /// Unix timestamp after which this verification policy is invalid.
    pub expires_at: Option<u64>,
}

pub fn verify_artifacts(
    statement: &InTotoStatementV1,
    artifacts: &BTreeMap<String, Vec<u8>>,
    policy: &VerificationPolicy,
) -> Vec<VerificationFailure> {
    let mut failures = Vec::new();
    if let Some(expires_at) = policy.expires_at {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now >= expires_at {
            failures.push(VerificationFailure {
                kind: VerificationFailureKind::ExpiredPolicy,
                subject: None,
                message: format!("verification policy expired at Unix timestamp {expires_at}"),
            });
        }
    }

    let referenced = statement
        .predicate
        .inputs
        .iter()
        .chain(statement.predicate.extracted_specs.iter())
        .chain(statement.predicate.storage_schemas.iter())
        .chain(std::iter::once(&statement.predicate.report));
    for artifact in referenced {
        match artifacts.get(&artifact.name) {
            None => failures.push(VerificationFailure {
                kind: VerificationFailureKind::MissingArtifact,
                subject: Some(artifact.name.clone()),
                message: "referenced artifact was not supplied for verification".to_string(),
            }),
            Some(bytes) if !artifact.digest.matches(bytes) => failures.push(VerificationFailure {
                kind: VerificationFailureKind::ArtifactDigestMismatch,
                subject: Some(artifact.name.clone()),
                message: "supplied artifact does not match the attested SHA-256 digest".to_string(),
            }),
            Some(_) => {}
        }
    }
    failures
}

/// Verify at least one signature against the supplied offline trust store.
/// Trust-store values are raw 32-byte Ed25519 public keys keyed by identity.
pub fn verify_signatures(
    envelope: &DsseEnvelope,
    trusted_keys: &BTreeMap<String, Vec<u8>>,
) -> SignatureVerification {
    let payload = match BASE64.decode(&envelope.payload) {
        Ok(payload) => payload,
        Err(_) => {
            return verification_failure(
                VerificationFailureKind::InvalidStatement,
                None,
                "DSSE payload is not valid base64",
            )
        }
    };
    let statement: InTotoStatementV1 = match serde_json::from_slice(&payload) {
        Ok(statement) => statement,
        Err(_) => {
            return verification_failure(
                VerificationFailureKind::InvalidStatement,
                None,
                "DSSE payload is not a safeguard in-toto statement",
            )
        }
    };
    if statement.canonical_bytes().ok().as_deref() != Some(payload.as_slice()) {
        return verification_failure(
            VerificationFailureKind::NonCanonicalPayload,
            None,
            "DSSE payload is not in canonical JSON form",
        );
    }
    if let Err(error) = statement.validate() {
        return verification_failure(
            VerificationFailureKind::InvalidStatement,
            None,
            &error.to_string(),
        );
    }
    if envelope.signatures.is_empty() {
        return verification_failure(
            VerificationFailureKind::InvalidSignature,
            None,
            "DSSE envelope contains no signatures",
        );
    }

    let pae = dsse_pae(&envelope.payload_type, &payload);
    let mut identities = Vec::new();
    let mut failures = Vec::new();
    for signature in &envelope.signatures {
        let Some(public_key) = trusted_keys.get(&signature.keyid) else {
            failures.push(VerificationFailure {
                kind: VerificationFailureKind::UntrustedSigner,
                subject: Some(signature.keyid.clone()),
                message: "signature identity is not in the trusted key set".to_string(),
            });
            continue;
        };
        let signature_bytes = match BASE64.decode(&signature.sig) {
            Ok(value) => value,
            Err(_) => {
                failures.push(VerificationFailure {
                    kind: VerificationFailureKind::InvalidSignature,
                    subject: Some(signature.keyid.clone()),
                    message: "signature is not valid base64".to_string(),
                });
                continue;
            }
        };
        if signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&pae, &signature_bytes)
            .is_ok()
        {
            identities.push(signature.keyid.clone());
        } else {
            failures.push(VerificationFailure {
                kind: VerificationFailureKind::InvalidSignature,
                subject: Some(signature.keyid.clone()),
                message: "signature does not verify for the trusted public key".to_string(),
            });
        }
    }
    identities.sort();
    identities.dedup();
    SignatureVerification {
        verified: !identities.is_empty(),
        signer_identities: identities,
        failures,
    }
}

pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut result = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    result.extend_from_slice(payload);
    result
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, AttestationError> {
    let value = serde_json::to_value(value).map_err(AttestationError::Serialize)?;
    let mut output = String::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output.into_bytes())
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<(), AttestationError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => {
            if value.as_i64().is_none() && value.as_u64().is_none() {
                return Err(AttestationError::UnsupportedJsonNumber);
            }
            output.push_str(&value.to_string());
        }
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).map_err(AttestationError::Serialize)?)
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).map_err(AttestationError::Serialize)?);
                output.push(':');
                write_canonical_json(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn verification_failure(
    kind: VerificationFailureKind,
    subject: Option<String>,
    message: &str,
) -> SignatureVerification {
    SignatureVerification {
        verified: false,
        signer_identities: Vec::new(),
        failures: vec![VerificationFailure {
            kind,
            subject,
            message: message.to_string(),
        }],
    }
}

#[derive(Debug)]
pub enum AttestationError {
    Serialize(serde_json::Error),
    InvalidStatement(serde_json::Error),
    InvalidStatementShape(String),
    InvalidPayloadType(String),
    InvalidBase64(&'static str),
    NonCanonicalPayload,
    UnsupportedJsonNumber,
    InvalidPrivateKey,
    Signing(String),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(error) => write!(f, "failed to serialize attestation: {error}"),
            Self::InvalidStatement(error) => write!(f, "invalid in-toto statement: {error}"),
            Self::InvalidStatementShape(message) => {
                write!(f, "invalid in-toto statement: {message}")
            }
            Self::InvalidPayloadType(value) => write!(f, "unsupported DSSE payload type: {value}"),
            Self::InvalidBase64(field) => write!(f, "DSSE {field} is not valid base64"),
            Self::NonCanonicalPayload => write!(f, "DSSE payload is not canonical JSON"),
            Self::UnsupportedJsonNumber => write!(
                f,
                "canonical statements do not permit floating-point numbers"
            ),
            Self::InvalidPrivateKey => write!(f, "invalid unencrypted Ed25519 PKCS#8 private key"),
            Self::Signing(message) => write!(f, "attestation signing failed: {message}"),
        }
    }
}

impl std::error::Error for AttestationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use std::collections::BTreeMap;

    fn statement() -> InTotoStatementV1 {
        let predicate = SafeguardPredicateV1::new(
            vec![AttestedArtifact {
                name: "old.wasm".into(),
                digest: ArtifactDigest::from_bytes(b"old"),
            }],
            vec![],
            vec![],
            serde_json::json!({"strict": true, "gated_axes": ["call_abi"]}),
            AttestedArtifact {
                name: "report.json".into(),
                digest: ArtifactDigest::from_bytes(b"report"),
            },
            AttestedVerdict {
                is_safe: true,
                recommended_bump: "patch".into(),
                old_client_to_new_contract: true,
                new_client_to_old_contract: true,
            },
        );
        InTotoStatementV1::new(
            vec![InTotoSubject {
                name: "old.wasm".into(),
                digest: ArtifactDigest::from_bytes(b"old"),
            }],
            predicate,
        )
    }

    #[test]
    fn canonical_statement_and_dsse_vector_are_deterministic() {
        let statement = statement();
        let first = statement.canonical_bytes().unwrap();
        let second = statement.canonical_bytes().unwrap();
        assert_eq!(first, second);
        assert_eq!(
            dsse_pae("text/plain", b"hello"),
            b"DSSEv1 10 text/plain 5 hello"
        );
        assert_eq!(hex::encode(Sha256::digest(&first)).len(), 64);
    }

    #[test]
    fn ed25519_signatures_verify_offline_and_report_identity() {
        let key = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519Signer::from_pkcs8("build-key", key.as_ref()).unwrap();
        let envelope = sign_statement(&statement(), &signer).unwrap();
        let mut trusted = BTreeMap::new();
        trusted.insert("build-key".into(), signer.public_key());
        let result = verify_signatures(&envelope, &trusted);
        assert!(result.verified);
        assert_eq!(result.signer_identities, vec!["build-key"]);
    }

    #[test]
    fn tampering_and_trust_failures_are_distinct() {
        let key = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519Signer::from_pkcs8("trusted", key.as_ref()).unwrap();
        let mut envelope = sign_statement(&statement(), &signer).unwrap();
        envelope.payload.push('A');
        let mut trusted = BTreeMap::new();
        trusted.insert("trusted".into(), signer.public_key());
        assert_eq!(
            verify_signatures(&envelope, &trusted).failures[0].kind,
            VerificationFailureKind::InvalidStatement
        );

        let envelope = sign_statement(&statement(), &signer).unwrap();
        let result = verify_signatures(&envelope, &BTreeMap::new());
        assert_eq!(
            result.failures[0].kind,
            VerificationFailureKind::UntrustedSigner
        );

        let mut envelope = sign_statement(&statement(), &signer).unwrap();
        envelope.signatures.clear();
        assert_eq!(
            verify_signatures(&envelope, &trusted).failures[0].kind,
            VerificationFailureKind::InvalidSignature
        );
    }

    #[test]
    fn unsupported_predicate_versions_are_rejected() {
        let mut statement = statement();
        statement.predicate.version = 2;
        let key = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519Signer::from_pkcs8("trusted", key.as_ref()).unwrap();
        let envelope = sign_statement(&statement, &signer).unwrap();
        let mut trusted = BTreeMap::new();
        trusted.insert("trusted".into(), signer.public_key());
        assert_eq!(
            verify_signatures(&envelope, &trusted).failures[0].kind,
            VerificationFailureKind::InvalidStatement
        );
    }

    #[test]
    fn artifact_failures_cover_missing_mismatch_and_expiry() {
        let mut artifacts = BTreeMap::new();
        artifacts.insert("old.wasm".into(), b"wrong".to_vec());
        let failures = verify_artifacts(
            &statement(),
            &artifacts,
            &VerificationPolicy {
                expires_at: Some(0),
            },
        );
        assert!(failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::ArtifactDigestMismatch));
        assert!(failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::MissingArtifact));
        assert!(failures
            .iter()
            .any(|f| f.kind == VerificationFailureKind::ExpiredPolicy));
    }
}

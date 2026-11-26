// SPDX-License-Identifier: MIT

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_FILENAME: &str = "manifest.json";
pub const BUILD_MANIFEST_FILENAME: &str = "build-manifest.toml";

pub const MAX_MEMBERS: usize = 1024;
pub const MAX_MEMBER_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemberInfo {
    pub sha256: String,
    pub size: u64,
    pub media_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub generator: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provenance: BTreeMap<String, String>,
    pub members: BTreeMap<String, MemberInfo>,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleInspection {
    pub schema_version: u32,
    pub created_at: Option<String>,
    pub generator: String,
    pub provenance: BTreeMap<String, String>,
    pub member_count: usize,
    pub total_bytes: u64,
    pub members: BTreeMap<String, MemberInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    pub no_timestamp: bool,
    pub generator: Option<String>,
    pub provenance: BTreeMap<String, String>,
}

fn default_generator() -> String {
    format!("soroban-upgrade-safeguard/{}", env!("CARGO_PKG_VERSION"))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn sha256_file(path: &Path) -> Result<(String, u64)> {
    use std::io::Read;
    let mut file = fs::File::open(path)
        .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = file.read(&mut buf).context("Failed to read file bytes")?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| anyhow!("Member byte count overflow"))?;
        if total > MAX_MEMBER_BYTES as u64 {
            bail!(
                "Member exceeds max size of {} bytes: {}",
                MAX_MEMBER_BYTES,
                path.display()
            );
        }
        h.update(&buf[..n]);
    }
    Ok((hex::encode(h.finalize()), total))
}

fn validate_member_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("Member name must not be empty");
    }
    if name == MANIFEST_FILENAME {
        bail!("Member name '{}' is reserved", MANIFEST_FILENAME);
    }
    for c in name.chars() {
        if c.is_control() || c == '\0' {
            bail!("Member name contains control character");
        }
    }
    let p = Path::new(name);
    for comp in p.components() {
        match comp {
            Component::Normal(_) => {}
            Component::Prefix(_)
            | Component::RootDir
            | Component::ParentDir
            | Component::CurDir => {
                bail!("Member path must be relative and contain no '..' or '.'");
            }
        }
    }
    if name.starts_with('/') || name.starts_with('\\') {
        bail!("Member path must not be absolute");
    }
    if name.contains("..") {
        bail!("Member path must not contain '..'");
    }
    Ok(())
}

fn canonical_member_path(root: &Path, member: &str) -> Result<PathBuf> {
    validate_member_name(member)?;
    let joined = root.join(member);
    let canon = fs::canonicalize(&joined).unwrap_or_else(|_| joined.clone());
    let canon_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    if !canon.starts_with(&canon_root) {
        bail!("Member path escapes bundle root: {}", member);
    }
    Ok(joined)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String> {
    let buf = serde_json::to_vec_pretty(value).context("Failed to serialize JSON")?;
    let val: serde_json::Value =
        serde_json::from_slice(&buf).context("Failed to round-trip JSON for canonical order")?;
    serde_json::to_string(&val).context("Failed to produce canonical JSON")
}

pub fn create_bundle(
    bundle_dir: &Path,
    members: &BTreeMap<String, (&Path, String)>,
    opts: &CreateOptions,
) -> Result<PathBuf> {
    if members.len() > MAX_MEMBERS {
        bail!(
            "Too many bundle members: {} (max {})",
            members.len(),
            MAX_MEMBERS
        );
    }

    fs::create_dir_all(bundle_dir)
        .with_context(|| format!("Failed to create bundle dir: {}", bundle_dir.display()))?;

    let mut seen = BTreeSet::new();
    let mut infos: BTreeMap<String, MemberInfo> = BTreeMap::new();
    let mut total_bytes: u64 = 0;

    for (name, (src_path, media_type)) in members {
        validate_member_name(name)?;
        if !seen.insert(name.clone()) {
            bail!("Duplicate member name: {}", name);
        }

        let meta = fs::metadata(src_path)
            .with_context(|| format!("Missing member source: {}", src_path.display()))?;
        if !meta.is_file() {
            bail!(
                "Member source is not a regular file: {}",
                src_path.display()
            );
        }
        let size = meta.len();
        if size > MAX_MEMBER_BYTES as u64 {
            bail!(
                "Member '{}' exceeds max size of {} bytes",
                name,
                MAX_MEMBER_BYTES
            );
        }
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or_else(|| anyhow!("Total member bytes overflow"))?;
        if total_bytes > MAX_TOTAL_BYTES {
            bail!("Bundle total exceeds max size of {} bytes", MAX_TOTAL_BYTES);
        }

        let (sha, actual_size) = sha256_file(src_path)?;

        let dest = canonical_member_path(bundle_dir, name)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create parent dir for member '{}'", name))?;
        }
        fs::copy(src_path, &dest).with_context(|| {
            format!(
                "Failed to copy '{}' into bundle as '{}'",
                src_path.display(),
                name
            )
        })?;

        infos.insert(
            name.clone(),
            MemberInfo {
                sha256: sha,
                size: actual_size,
                media_type: media_type.clone(),
            },
        );
    }

    let generator = opts.generator.clone().unwrap_or_else(default_generator);

    let created_at = if opts.no_timestamp {
        None
    } else {
        Some(chrono_like_now_iso())
    };

    let provenance = opts.provenance.clone();

    let mut manifest_placeholder = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        created_at: created_at.clone(),
        generator: generator.clone(),
        provenance: provenance.clone(),
        members: infos.clone(),
        manifest_sha256: String::new(),
    };

    let partial = {
        let mut tmp = manifest_placeholder.clone();
        tmp.manifest_sha256 = String::new();
        canonical_json(&tmp)?
    };
    let manifest_hash = sha256_hex(partial.as_bytes());
    manifest_placeholder.manifest_sha256 = manifest_hash;

    let final_json = canonical_json(&manifest_placeholder)?;
    let manifest_path = bundle_dir.join(MANIFEST_FILENAME);
    let mut f = fs::File::create(&manifest_path)
        .with_context(|| format!("Failed to write manifest: {}", manifest_path.display()))?;
    f.write_all(final_json.as_bytes())
        .context("Failed to write manifest bytes")?;
    f.flush().ok();

    Ok(manifest_path)
}

fn chrono_like_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d,
        Err(_) => return "unknown".to_string(),
    };
    let secs = dur.as_secs();
    let (y, mo, d, h, mi, s) = secs_to_ymdhms(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

fn secs_to_ymdhms(mut secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let s = (secs % 60) as u32;
    secs /= 60;
    let mi = (secs % 60) as u32;
    secs /= 60;
    let h = (secs % 24) as u32;
    secs /= 24;
    let mut days = secs;
    let mut y: u32 = 1970;
    loop {
        let leap = (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
        let ydays = if leap { 366 } else { 365 };
        if days < ydays as u64 {
            break;
        }
        days -= ydays as u64;
        y += 1;
    }
    let leap = (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let mdays = [
        31u32,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mo: u32 = 0;
    for (i, &md) in mdays.iter().enumerate() {
        if days < md as u64 {
            mo = (i + 1) as u32;
            break;
        }
        days -= md as u64;
    }
    let d = (days + 1) as u32;
    (y, mo, d, h, mi, s)
}

fn load_manifest(bundle_dir: &Path) -> Result<BundleManifest> {
    let manifest_path = bundle_dir.join(MANIFEST_FILENAME);
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("Failed to read manifest: {}", manifest_path.display()))?;
    let manifest: BundleManifest =
        serde_json::from_str(&raw).context("Failed to parse bundle manifest JSON")?;
    if manifest.schema_version != BUNDLE_SCHEMA_VERSION {
        bail!(
            "Unsupported bundle schema version: {} (expected {})",
            manifest.schema_version,
            BUNDLE_SCHEMA_VERSION
        );
    }
    Ok(manifest)
}

pub fn verify_bundle(bundle_dir: &Path) -> Result<BundleManifest> {
    let manifest = load_manifest(bundle_dir)?;

    if manifest.members.len() > MAX_MEMBERS {
        bail!(
            "Manifest declares too many members: {} (max {})",
            manifest.members.len(),
            MAX_MEMBERS
        );
    }

    let mut total: u64 = 0;
    for (name, info) in &manifest.members {
        validate_member_name(name)
            .with_context(|| format!("Manifest contains invalid member name: {}", name))?;
        let path = canonical_member_path(bundle_dir, name)?;
        let (sha, size) =
            sha256_file(&path).with_context(|| format!("Failed to rehash member '{}'", name))?;
        if sha != info.sha256 {
            bail!(
                "Hash mismatch for member '{}': expected {} got {}",
                name,
                info.sha256,
                sha
            );
        }
        if size != info.size {
            bail!(
                "Size mismatch for member '{}': expected {} got {}",
                name,
                info.size,
                size
            );
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| anyhow!("Total member bytes overflow during verify"))?;
        if total > MAX_TOTAL_BYTES {
            bail!(
                "Bundle total exceeds max size of {} bytes during verify",
                MAX_TOTAL_BYTES
            );
        }
    }

    let mut tmp = manifest.clone();
    let expected_manifest_sha = tmp.manifest_sha256.clone();
    tmp.manifest_sha256 = String::new();
    let partial = canonical_json(&tmp)?;
    let recomputed = sha256_hex(partial.as_bytes());
    if recomputed != expected_manifest_sha {
        bail!(
            "Manifest self-hash mismatch: expected {} recomputed {}",
            expected_manifest_sha,
            recomputed
        );
    }

    Ok(manifest)
}

pub fn inspect_bundle(bundle_dir: &Path) -> Result<BundleInspection> {
    let manifest = load_manifest(bundle_dir)?;
    let mut total: u64 = 0;
    for info in manifest.members.values() {
        total = total.saturating_add(info.size);
    }
    Ok(BundleInspection {
        schema_version: manifest.schema_version,
        created_at: manifest.created_at,
        generator: manifest.generator,
        provenance: manifest.provenance,
        member_count: manifest.members.len(),
        total_bytes: total,
        members: manifest.members,
    })
}

pub fn read_member(bundle_dir: &Path, name: &str) -> Result<Vec<u8>> {
    validate_member_name(name)?;
    let _ = &load_manifest(bundle_dir)?;
    let path = canonical_member_path(bundle_dir, name)?;
    let meta = fs::metadata(&path).with_context(|| format!("Missing bundle member: {}", name))?;
    if meta.len() > MAX_MEMBER_BYTES as u64 {
        bail!(
            "Member '{}' exceeds max size of {} bytes when reading",
            name,
            MAX_MEMBER_BYTES
        );
    }
    fs::read(&path).with_context(|| format!("Failed to read member '{}'", name))
}

// ----------------------------------------------------------------------------
// Reproducible build manifest support
// ---------------------------------------------------------------------------

/// Maximum size of a build manifest file we are willing to parse.
pub const MAX_BUILD_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Schema version for the reproducible build manifest format.
pub const BUILD_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// A single expected artifact entry in a build manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildArtifact {
    /// Logical artifact name (e.g. `contract.wasm`).
    pub name: String,
    /// Expected lowercase hex SHA-256 digest of the artifact bytes.
    pub sha256: String,
    /// Optional expected size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Reproducible build manifest describing the expected provenance of a build.
///
/// This is intentionally independent from interface compatibility gating: it
/// records what the release pipeline *claims* produced the artifact so that the
/// tool can compare it against embedded metadata and actual bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    pub schema_version: u32,
    /// Source revision (e.g. git commit SHA) the artifact was built from.
    pub source_revision: String,
    /// Rust toolchain version (e.g. `1.79.0`).
    pub rust_version: String,
    /// Soroban SDK version (e.g. `21.0.0`).
    pub sdk_version: String,
    /// Compilation target triple (e.g. `wasm32-unknown-unknown`).
    pub target: String,
    /// Build profile (e.g. `release`).
    pub profile: String,
    /// Enabled cargo feature flags.
    #[serde(default)]
    pub features: Vec<String>,
    /// Expected artifact digests.
    #[serde(default)]
    pub artifacts: Vec<BuildArtifact>,
    /// Optional free-form provenance notes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provenance: BTreeMap<String, String>,
}

/// The result of comparing a build manifest against observed data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceFinding {
    /// Field name that was compared (e.g. `source_revision`).
    pub field: String,
    /// Expected value from the manifest.
    pub expected: String,
    /// Observed value from embedded metadata or artifact bytes.
    pub observed: String,
    /// Whether the values matched.
    pub matched: bool,
    /// Human-readable explanation.
    pub message: String,
}

/// A metadata field that was verified against the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedField {
    pub field: String,
    pub value: String,
}

/// A metadata field that could not be verified (missing on either side).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnverifiedField {
    pub field: String,
    pub reason: String,
}

/// Full provenance report produced by comparing a manifest with observed data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceReport {
    pub manifest_present: bool,
    pub manifest_schema_version: Option<u32>,
    pub findings: Vec<ProvenanceFinding>,
    pub verified: Vec<VerifiedField>,
    pub unverified: Vec<UnverifiedField>,
    /// True when every compared field matched and no mismatches were found.
    pub all_matched: bool,
}

impl ProvenanceReport {
    fn empty() -> Self {
        ProvenanceReport {
            manifest_present: false,
            manifest_schema_version: None,
            findings: Vec::new(),
            verified: Vec::new(),
            unverified: Vec::new(),
            all_matched: true,
        }
    }

    /// Returns true if any finding represents a mismatch.
    pub fn has_mismatch(&self) -> bool {
        self.findings.iter().any(|f| !f.matched)
    }
}

/// Observed metadata extracted from a contract artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservedMetadata {
    pub source_revision: Option<String>,
    pub rust_version: Option<String>,
    pub sdk_version: Option<String>,
    pub target: Option<String>,
    pub profile: Option<String>,
    pub features: Option<Vec<String>>,
}

fn validate_hex_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64 {
        bail!(
            "Field '{}' must be a 64-character hex SHA-256 digest, got {} chars",
            field,
            value.len()
        );
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("Field '{}' must contain only hex characters", field);
    }
    if value.chars().any(|c| c.is_ascii_uppercase()) {
        bail!("Field '{}' must be lowercase hex", field);
    }
    Ok(())
}

fn validate_non_empty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("Field '{}' must not be empty", field);
    }
    if value.chars().any(|c| c.is_control()) {
        bail!("Field '{}' must not contain control characters", field);
    }
    Ok(())
}

impl BuildManifest {
    /// Strictly validate the manifest, rejecting unknown or malformed values.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != BUILD_MANIFEST_SCHEMA_VERSION {
            bail!(
                "Unsupported build manifest schema version: {} (expected {})",
                self.schema_version,
                BUILD_MANIFEST_SCHEMA_VERSION
            );
        }
        validate_non_empty(&self.source_revision, "source_revision")?;
        validate_non_empty(&self.rust_version, "rust_version")?;
        validate_non_empty(&self.sdk_version, "sdk_version")?;
        validate_non_empty(&self.target, "target")?;
        validate_non_empty(&self.profile, "profile")?;

        let mut seen_features = BTreeSet::new();
        for feature in &self.features {
            validate_non_empty(feature, "features")?;
            if !seen_features.insert(feature.clone()) {
                bail!("Duplicate feature in build manifest: {}", feature);
            }
        }

        let mut seen_artifacts = BTreeSet::new();
        for artifact in &self.artifacts {
            validate_non_empty(&artifact.name, "artifacts.name")?;
            validate_hex_sha256(&artifact.sha256, "artifacts.sha256")?;
            if !seen_artifacts.insert(artifact.name.clone()) {
                bail!(
                    "Duplicate artifact name in build manifest: {}",
                    artifact.name
                );
            }
        }

        Ok(())
    }

    /// Parse a build manifest from TOML text.
    pub fn from_toml(text: &str) -> Result<Self> {
        let manifest: BuildManifest =
            toml::from_str(text).context("Failed to parse build manifest TOML")?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Parse a build manifest from JSON text.
    pub fn from_json(text: &str) -> Result<Self> {
        let manifest: BuildManifest =
            serde_json::from_str(text).context("Failed to parse build manifest JSON")?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Parse a build manifest, auto-detecting TOML or JSON by content.
    pub fn parse_auto(text: &str) -> Result<Self> {
        let trimmed = text.trim_start();
        if trimmed.starts_with('{') {
            Self::from_json(text)
        } else {
            Self::from_toml(text)
        }
    }

    /// Load a build manifest from a file, auto-detecting the format.
    pub fn load(path: &Path) -> Result<Self> {
        let meta = fs::metadata(path)
            .with_context(|| format!("Failed to stat build manifest: {}", path.display()))?;
        if meta.len() > MAX_BUILD_MANIFEST_BYTES {
            bail!(
                "Build manifest exceeds max size of {} bytes: {}",
                MAX_BUILD_MANIFEST_BYTES,
                path.display()
            );
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read build manifest: {}", path.display()))?;
        Self::parse_auto(&raw)
            .with_context(|| format!("Invalid build manifest: {}", path.display()))
    }

    /// Serialize the manifest to canonical TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("Failed to serialize build manifest TOML")
    }

    /// Serialize the manifest to canonical JSON.
    pub fn to_json(&self) -> Result<String> {
        canonical_json(self)
    }

    /// Compare this manifest against observed metadata and artifact digests.
    ///
    /// `artifact_digests` maps artifact names to their actual lowercase hex
    /// SHA-256 digests. Missing artifacts are reported as unverified.
    pub fn compare(
        &self,
        observed: &ObservedMetadata,
        artifact_digests: &BTreeMap<String, String>,
    ) -> ProvenanceReport {
        let mut report = ProvenanceReport {
            manifest_present: true,
            manifest_schema_version: Some(self.schema_version),
            findings: Vec::new(),
            verified: Vec::new(),
            unverified: Vec::new(),
            all_matched: true,
        };

        compare_field(
            &mut report,
            "source_revision",
            &self.source_revision,
            observed.source_revision.as_deref(),
        );
        compare_field(
            &mut report,
            "rust_version",
            &self.rust_version,
            observed.rust_version.as_deref(),
        );
        compare_field(
            &mut report,
            "sdk_version",
            &self.sdk_version,
            observed.sdk_version.as_deref(),
        );
        compare_field(
            &mut report,
            "target",
            &self.target,
            observed.target.as_deref(),
        );
        compare_field(
            &mut report,
            "profile",
            &self.profile,
            observed.profile.as_deref(),
        );

        // Features are compared as a set.
        match &observed.features {
            Some(observed_features) => {
                let mut expected: Vec<String> = self.features.clone();
                let mut actual: Vec<String> = observed_features.clone();
                expected.sort();
                actual.sort();
                let expected_str = expected.join(",");
                let actual_str = actual.join(",");
                let matched = expected == actual;
                report.findings.push(ProvenanceFinding {
                    field: "features".to_string(),
                    expected: expected_str.clone(),
                    observed: actual_str.clone(),
                    matched,
                    message: if matched {
                        "Feature flags match build manifest".to_string()
                    } else {
                        format!(
                            "Feature flags mismatch: manifest [{}] vs metadata [{}]",
                            expected_str, actual_str
                        )
                    },
                });
                if matched {
                    report.verified.push(VerifiedField {
                        field: "features".to_string(),
                        value: actual_str,
                    });
                } else {
                    report.all_matched = false;
                }
            }
            None => {
                report.unverified.push(UnverifiedField {
                    field: "features".to_string(),
                    reason: "Embedded metadata does not declare feature flags".to_string(),
                });
            }
        }

        // Artifact digests.
        for artifact in &self.artifacts {
            match artifact_digests.get(&artifact.name) {
                Some(actual) => {
                    let matched = actual.eq_ignore_ascii_case(&artifact.sha256);
                    report.findings.push(ProvenanceFinding {
                        field: format!("artifact:{}", artifact.name),
                        expected: artifact.sha256.clone(),
                        observed: actual.clone(),
                        matched,
                        message: if matched {
                            format!("Artifact '{}' digest matches manifest", artifact.name)
                        } else {
                            format!(
                                "Artifact '{}' digest mismatch: manifest {} vs actual {}",
                                artifact.name, artifact.sha256, actual
                            )
                        },
                    });
                    if matched {
                        report.verified.push(VerifiedField {
                            field: format!("artifact:{}", artifact.name),
                            value: actual.clone(),
                        });
                    } else {
                        report.all_matched = false;
                    }
                }
                None => {
                    report.unverified.push(UnverifiedField {
                        field: format!("artifact:{}", artifact.name),
                        reason: "Artifact bytes were not available for hashing".to_string(),
                    });
                }
            }
        }

        report
    }
}

fn compare_field(
    report: &mut ProvenanceReport,
    field: &str,
    expected: &str,
    observed: Option<&str>,
) {
    match observed {
        Some(actual) => {
            let matched = expected == actual;
            report.findings.push(ProvenanceFinding {
                field: field.to_string(),
                expected: expected.to_string(),
                observed: actual.to_string(),
                matched,
                message: if matched {
                    format!("{} matches build manifest", field)
                } else {
                    format!(
                        "{} mismatch: manifest '{}' vs metadata '{}'",
                        field, expected, actual
                    )
                },
            });
            if matched {
                report.verified.push(VerifiedField {
                    field: field.to_string(),
                    value: actual.to_string(),
                });
            } else {
                report.all_matched = false;
            }
        }
        None => {
            report.unverified.push(UnverifiedField {
                field: field.to_string(),
                reason: format!("Embedded metadata does not declare {}", field),
            });
        }
    }
}

/// Load a build manifest from a bundle directory if present.
pub fn load_bundle_build_manifest(bundle_dir: &Path) -> Result<Option<BuildManifest>> {
    let path = bundle_dir.join(BUILD_MANIFEST_FILENAME);
    if !path.exists() {
        return Ok(None);
    }
    BuildManifest::load(&path).map(Some)
}

/// Verify a bundle's build manifest against its members.
//.
/// This is independent from interface compatibility gating: it only reports
/// provenance findings. Callers decide whether mismatches should block.
pub fn verify_bundle_provenance(
    bundle_dir: &Path,
    observed: &ObservedMetadata,
) -> Result<ProvenanceReport> {
    let manifest = match load_bundle_build_manifest(bundle_dir)? {
        Some(m) => m,
        None => return Ok(ProvenanceReport::empty()),
    };

    let mut digests: BTreeMap<String, String> = BTreeMap::new();
    for artifact in &manifest.artifacts {
        let candidate = bundle_dir.join(&artifact.name);
        if candidate.is_file() {
            let (sha, _size) = sha256_file(&candidate)
                .with_context(|| format!("Failed to hash artifact '{}'", artifact.name))?;
            digests.insert(artifact.name.clone(), sha);
        }
    }

    Ok(manifest.compare(observed, &digests))
}

/// Compare a build manifest against observed metadata and explicit artifact
/// digests, without requiring a bundle directory.
pub fn verify_manifest_provenance(
    manifest: &BuildManifest,
    observed: &ObservedMetadata,
    artifact_digests: &BTreeMap<String, String>,
) -> ProvenanceReport {
    manifest.compare(observed, artifact_digests)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> BuildManifest {
        BuildManifest {
            schema_version: BUILD_MANIFEST_SCHEMA_VERSION,
            source_revision: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
            rust_version: "1.79.0".to_string(),
            sdk_version: "21.0.0".to_string(),
            target: "wasm32-unknown-unknown".to_string(),
            profile: "release".to_string(),
            features: vec!["opt".to_string(), "wasm".to_string()],
            artifacts: vec![BuildArtifact {
                name: "contract.wasm".to_string(),
                sha256: "a".repeat(64),
                size: Some(1024),
            }],
            provenance: BTreeMap::new(),
        }
    }

    fn sample_observed() -> ObservedMetadata {
        ObservedMetadata {
            source_revision: Some("abcdef1234567890abcdef1234567890abcdef12".to_string()),
            rust_version: Some("1.79.0".to_string()),
            sdk_version: Some("21.0.0".to_string()),
            target: Some("wasm32-unknown-unknown".to_string()),
            profile: Some("release".to_string()),
            features: Some(vec!["wasm".to_string(), "opt".to_string()]),
        }
    }

    #[test]
    fn valid_manifest_roundtrips_toml_and_json() {
        let manifest = sample_manifest();
        manifest.validate().unwrap();

        let toml_text = manifest.to_toml().unwrap();
        let from_toml = BuildManifest::from_toml(&toml_text).unwrap();
        assert_eq!(from_toml, manifest);

        let json_text = manifest.to_json().unwrap();
        let from_json = BuildManifest::from_json(&json_text).unwrap();
        assert_eq!(from_json, manifest);
    }

    #[test]
    fn valid_manifest_all_fields_match() {
        let manifest = sample_manifest();
        let observed = sample_observed();
        let mut digests = BTreeMap::new();
        digests.insert("contract.wasm".to_string(), "a".repeat(64));

        let report = manifest.compare(&observed, &digests);
        assert!(report.manifest_present);
        assert!(report.all_matched);
        assert!(!report.has_mismatch());
        assert!(report.unverified.is_empty());
        assert_eq!(report.verified.len(), 7); // 5 fields + features + artifact
    }

    #[test]
    fn mismatch_detected_for_source_revision() {
        let manifest = sample_manifest();
        let mut observed = sample_observed();
        observed.source_revision = Some("deadbeef".to_string());
        let mut digests = BTreeMap::new();
        digests.insert("contract.wasm".to_string(), "a".repeat(64));

        let report = manifest.compare(&observed, &digests);
        assert!(!report.all_matched);
        assert!(report.has_mismatch());
        let finding = report
            .findings
            .iter()
            .find(|f| f.field == "source_revision")
            .unwrap();
        assert!(!finding.matched);
    }

    #[test]
    fn mismatch_detected_for_compiler_sdk_target_profile_and_features() {
        let manifest = sample_manifest();
        let mut observed = sample_observed();
        observed.rust_version = Some("1.80.0".to_string());
        observed.sdk_version = Some("20.0.0".to_string());
        observed.target = Some("wasm32-wasi".to_string());
        observed.profile = Some("debug".to_string());
        observed.features = Some(vec!["opt".to_string()]);
        let mut digests = BTreeMap::new();
        digests.insert("contract.wasm".to_string(), "a".repeat(64));

        let report = manifest.compare(&observed, &digests);
        assert!(!report.all_matched);
        for field in [
            "rust_version",
            "sdk_version",
            "target",
            "profile",
            "features",
        ] {
            let finding = report.findings.iter().find(|f| f.field == field).unwrap();
            assert!(!finding.matched, "expected mismatch for {}", field);
        }
    }

    #[test]
    fn mismatch_detected_for_artifact_digest() {
        let manifest = sample_manifest();
        let observed = sample_observed();
        let mut digests = BTreeMap::new();
        digests.insert("contract.wasm".to_string(), "b".repeat(64));

        let report = manifest.compare(&observed, &digests);
        assert!(!report.all_matched);
        let finding = report
            .findings
            .iter()
            .find(|f| f.field == "artifact:contract.wasm")
            .unwrap();
        assert!(!finding.matched);
    }

    #[test]
    fn missing_metadata_fields_are_unverified() {
        let manifest = sample_manifest();
        let observed = ObservedMetadata::default();
        let digests = BTreeMap::new();

        let report = manifest.compare(&observed, &digests);
        assert!(report.findings.is_empty());
        assert!(report.all_matched);
        // 5 scalar fields + features + artifact
        assert_eq!(report.unverified.len(), 7);
        assert!(report.verified.is_empty());
    }

    #[test]
    fn missing_artifact_digest_is_unverified() {
        let manifest = sample_manifest();
        let observed = sample_observed();
        let digests = BTreeMap::new();

        let report = manifest.compare(&observed, &digests);
        assert!(report.all_matched);
        let unverified = report
            .unverified
            .iter()
            .find(|u| u.field == "artifact:contract.wasm")
            .unwrap();
        assert!(unverified.reason.contains("not available"));
    }

    #[test]
    fn stale_manifest_schema_version_rejected() {
        let mut manifest = sample_manifest();
        manifest.schema_version = 999;
        let err = manifest.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("Unsupported build manifest schema"));
    }

    #[test]
    fn invalid_artifact_digest_rejected() {
        let mut manifest = sample_manifest();
        manifest.artifacts[0].sha256 = "not-a-digest".to_string();
        assert!(manifest.validate().is_err());

        let mut manifest = sample_manifest();
        manifest.artifacts[0].sha256 = "A".repeat(64);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn duplicate_features_rejected() {
        let mut manifest = sample_manifest();
        manifest.features = vec!["opt".to_string(), "opt".to_string()];
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn duplicate_artifacts_rejected() {
        let mut manifest = sample_manifest();
        let dup = manifest.artifacts[0].clone();
        manifest.artifacts.push(dup);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn empty_required_field_rejected() {
        let mut manifest = sample_manifest();
        manifest.source_revision = "   ".to_string();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn unknown_fields_rejected_in_json() {
        let json = r#"{
            "schema_version": 1,
            "source_revision": "abc",
            "rust_version": "1.79.0",
            "sdk_version": "21.0.0",
            "target": "wasm32-unknown-unknown",
            "profile": "release",
            "unexpected": true
        }"#;
        assert!(BuildManifest::from_json(json).is_err());
    }

    #[test]
    fn parse_auto_detects_json_and_toml() {
        let manifest = sample_manifest();
        let json_text = manifest.to_json().unwrap();
        let toml_text = manifest.to_toml().unwrap();
        assert_eq!(BuildManifest::parse_auto(&json_text).unwrap(), manifest);
        assert_eq!(BuildManifest::parse_auto(&toml_text).unwrap(), manifest);
    }

    #[test]
    fn empty_report_when_no_manifest() {
        let report = ProvenanceReport::empty();
        assert!(!report.manifest_present);
        assert!(report.all_matched);
        assert!(!report.has_mismatch());
    }
}

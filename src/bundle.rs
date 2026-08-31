use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_FILENAME: &str = "manifest.json";

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

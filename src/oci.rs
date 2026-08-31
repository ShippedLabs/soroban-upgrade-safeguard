//! OCI registry input resolver for WASM binaries and extracted-spec artifacts.
//!
//! Teams that publish contract artifacts to OCI-compatible registries
//! alongside container images and supply-chain metadata can point any input
//! *position* that already accepts a local path at an `oci://` reference
//! instead, without hand-rolling registry authentication, manifest
//! selection, layer extraction, and digest verification in a wrapper script.
//!
//! # Reference syntax
//!
//! An OCI reference is `oci://<registry>[:<port>]/<repository>` followed by
//! either an immutable digest or a mutable tag:
//!
//! ```text
//! oci://ghcr.io/example/contracts@sha256:3b1a2c9e4d5f6071829384756617283940516273849506172839405162738495   (pinned, default)
//! oci://ghcr.io/example/contracts:v1.2.3                                                                    (tag, requires --allow-oci-tags)
//! ```
//!
//! A digest reference is preferred and requires no opt-in: [`OciReference`]
//! resolves it directly, and the manifest bytes are themselves verified
//! against that digest before anything downstream is trusted (this is what
//! "immutable" means for an OCI reference — the digest *is* the content
//! hash). A tag reference names something that can be repointed at any time,
//! so [`OciReference::parse`] refuses it unless
//! [`OciFetchConfig::allow_tags`] is explicitly set; when it is, the
//! resolved manifest digest is still computed and returned on
//! [`OciArtifact`] so the caller can print it and pin the reference for next
//! time.
//!
//! # Manifest and layer selection
//!
//! [`resolve_oci_artifact`] requests an OCI (or Docker v2) image manifest,
//! then selects the single layer whose `mediaType` matches the artifact kind
//! being requested — [`MEDIA_TYPE_WASM`] (or the generic `application/wasm`)
//! for a WASM comparison input, [`MEDIA_TYPE_EXTRACTED_SPEC`] for a
//! storage-schema/extracted-spec input. A multi-manifest image index is
//! rejected with a clear error rather than guessing a platform, since a
//! Soroban contract artifact is not a multi-platform image.
//!
//! # Authentication
//!
//! Every request is first attempted anonymously. A `401` response carrying a
//! `WWW-Authenticate: Bearer realm=...,service=...,scope=...` challenge is
//! handled automatically: the challenge is exchanged for a token,
//! optionally using credentials resolved from the standard Docker credential
//! store (`~/.docker/config.json` — a plaintext `auths` entry, or a
//! `credHelpers`/`credsStore` credential helper binary invoked exactly as
//! `docker login`/`docker pull` would). A `Basic` challenge falls back to the
//! same resolved credentials directly. No bespoke credential flags exist —
//! logging in with `docker login <registry>` before running the tool is
//! sufficient.
//!
//! # Caching
//!
//! Every fetch is keyed by the resolved *layer* digest, so a verified blob is
//! cached content-addressed under [`OciFetchConfig::cache_dir`] (default:
//! [`default_cache_dir`]) with no risk of staleness. The cache sidecar
//! records the registry, repository, manifest digest, and layer digest that
//! produced the entry.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::loader::sha256_hex;
pub use crate::remote::CacheStatus;

/// Default cap on a single manifest or layer download, in bytes (64 MiB).
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Default per-request timeout.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Environment variable that overrides the default OCI artifact cache
/// directory when [`OciFetchConfig::cache_dir`] is not set explicitly.
pub const CACHE_DIR_ENV_VAR: &str = "SOROBAN_SAFEGUARD_OCI_CACHE";

/// Documented media type for a Soroban contract WASM layer.
pub const MEDIA_TYPE_WASM: &str = "application/vnd.soroban.contract.wasm.v1";
/// Generic WASM media type accepted alongside [`MEDIA_TYPE_WASM`] for
/// interoperability with pipelines that don't tag artifacts with a
/// Soroban-specific type.
pub const MEDIA_TYPE_WASM_GENERIC: &str = "application/wasm";
/// Documented media type for an extracted contract-spec JSON layer, used for
/// `--old-storage-schema` / `--new-storage-schema` inputs.
pub const MEDIA_TYPE_EXTRACTED_SPEC: &str = "application/vnd.soroban.extracted-spec.v1+json";

const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_MANIFEST_LIST_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";

/// Which documented artifact kind a caller is resolving from a manifest's
/// layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciArtifactKind {
    Wasm,
    ExtractedSpec,
}

impl OciArtifactKind {
    fn accepted_media_types(self) -> &'static [&'static str] {
        match self {
            OciArtifactKind::Wasm => &[MEDIA_TYPE_WASM, MEDIA_TYPE_WASM_GENERIC],
            OciArtifactKind::ExtractedSpec => &[MEDIA_TYPE_EXTRACTED_SPEC],
        }
    }
}

impl fmt::Display for OciArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OciArtifactKind::Wasm => "wasm",
            OciArtifactKind::ExtractedSpec => "extracted-spec",
        })
    }
}

/// How an [`OciReference`] pins the content it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciSelector {
    /// A `sha256:<hex>` digest — immutable by construction.
    Digest(String),
    /// A mutable tag. Only honored when [`OciFetchConfig::allow_tags`] is
    /// set; the tag is resolved to a digest before anything is trusted.
    Tag(String),
}

/// A parsed `oci://<registry>/<repository>(@sha256:<hex>|:<tag>)` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciReference {
    pub registry: String,
    pub repository: String,
    pub selector: OciSelector,
}

impl OciReference {
    /// Parse `input` as an OCI reference if it looks like an `oci://` URI.
    ///
    /// Returns `Ok(None)` when `input` does not start with `oci://`, so
    /// callers can fall through to other input kinds unchanged. Returns
    /// `Err` when it is an `oci://` reference but is malformed, or names a
    /// digest algorithm other than sha256.
    pub fn parse(input: &str) -> Result<Option<Self>, Error> {
        let Some(rest) = input.strip_prefix("oci://") else {
            return Ok(None);
        };

        let slash = rest.find('/').ok_or_else(|| Error::InvalidInput {
            details: format!(
                "OCI reference '{input}' is missing a repository path (expected 'oci://<registry>/<repository>@sha256:<hex>')"
            ),
        })?;
        let registry = &rest[..slash];
        let remainder = &rest[slash + 1..];
        if registry.is_empty() {
            return Err(Error::InvalidInput {
                details: format!("OCI reference '{input}' has an empty registry host"),
            });
        }

        let (repository, selector) = if let Some(at) = remainder.rfind('@') {
            let repository = &remainder[..at];
            let digest_part = &remainder[at + 1..];
            let hex_digest = digest_part.strip_prefix("sha256:").ok_or_else(|| {
                Error::InvalidInput {
                    details: format!(
                        "OCI reference '{input}' uses an unsupported digest algorithm in '@{digest_part}'; only 'sha256:<hex>' is supported"
                    ),
                }
            })?;
            if hex_digest.len() != 64 || !hex_digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::InvalidInput {
                    details: format!(
                        "OCI reference '{input}' has an invalid sha256 digest (expected 64 hex characters, got '{hex_digest}')"
                    ),
                });
            }
            (
                repository,
                OciSelector::Digest(format!("sha256:{}", hex_digest.to_ascii_lowercase())),
            )
        } else if let Some(colon) = remainder.rfind(':') {
            let repository = &remainder[..colon];
            let tag = &remainder[colon + 1..];
            if tag.is_empty() {
                return Err(Error::InvalidInput {
                    details: format!("OCI reference '{input}' has an empty tag"),
                });
            }
            (repository, OciSelector::Tag(tag.to_string()))
        } else {
            return Err(Error::InvalidInput {
                details: format!(
                    "OCI reference '{input}' must pin a digest ('@sha256:<hex>') or, if explicitly allowed, a tag (':<tag>')"
                ),
            });
        };

        if repository.is_empty() {
            return Err(Error::InvalidInput {
                details: format!("OCI reference '{input}' has an empty repository path"),
            });
        }

        Ok(Some(OciReference {
            registry: registry.to_string(),
            repository: repository.to_string(),
            selector,
        }))
    }

    /// The `algorithm:hex` digest this reference pins, when it is a digest
    /// reference. `None` for a tag reference (the digest is not known until
    /// the manifest is fetched).
    pub fn pinned_digest(&self) -> Option<&str> {
        match &self.selector {
            OciSelector::Digest(d) => Some(d),
            OciSelector::Tag(_) => None,
        }
    }
}

/// Policy controlling how [`resolve_oci_artifact`] authenticates, downloads,
/// and caches an OCI artifact.
#[derive(Debug, Clone)]
pub struct OciFetchConfig {
    /// Hard cap on any single manifest or blob download, in bytes.
    pub max_bytes: usize,
    /// Overall per-request timeout.
    pub timeout: Duration,
    /// Content-addressed cache directory. `None` resolves lazily to
    /// [`default_cache_dir`] at fetch time.
    pub cache_dir: Option<PathBuf>,
    /// When `true`, neither read from nor write to the cache for this fetch.
    pub no_cache: bool,
    /// Reject a non-`https` registry endpoint. Defaults to `true`; the CLI
    /// never overrides it. The only reason to set this to `false` is
    /// pointing at a plaintext local mock registry in a test harness.
    pub https_only: bool,
    /// Explicit opt-in required to resolve a mutable tag reference rather
    /// than a pinned digest. Defaults to `false`.
    pub allow_tags: bool,
}

impl Default for OciFetchConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            cache_dir: None,
            no_cache: false,
            https_only: true,
            allow_tags: false,
        }
    }
}

impl OciFetchConfig {
    /// The cache directory this config resolves to: [`Self::cache_dir`] if
    /// set, otherwise [`default_cache_dir`].
    #[must_use]
    pub fn resolved_cache_dir(&self) -> PathBuf {
        self.cache_dir.clone().unwrap_or_else(default_cache_dir)
    }

    fn scheme(&self) -> &'static str {
        if self.https_only {
            "https"
        } else {
            "http"
        }
    }
}

/// The default OCI artifact cache directory: [`CACHE_DIR_ENV_VAR`] if set,
/// otherwise a `soroban-upgrade-safeguard/oci-cache` directory under the OS
/// temporary directory.
#[must_use]
pub fn default_cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(CACHE_DIR_ENV_VAR) {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    std::env::temp_dir()
        .join("soroban-upgrade-safeguard")
        .join("oci-cache")
}

/// Delete every cached OCI artifact under `dir`. A no-op if `dir` does not
/// exist. Wired to the CLI's `--clear-oci-cache` flag.
pub fn clear_cache(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

/// A verified OCI artifact with enough provenance to identify exactly what
/// registry, repository, manifest, and layer it came from.
#[derive(Debug, Clone)]
pub struct OciArtifact {
    pub registry: String,
    pub repository: String,
    /// The tag that was resolved, if the reference was a tag rather than a
    /// pinned digest.
    pub resolved_tag: Option<String>,
    /// The manifest's own content digest (`sha256:<hex>`), computed locally
    /// rather than trusted from a response header.
    pub manifest_digest: String,
    /// The selected layer's digest (`sha256:<hex>`), verified against the
    /// downloaded bytes.
    pub layer_digest: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
    pub cache_status: CacheStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMeta {
    registry: String,
    repository: String,
    manifest_digest: String,
    layer_digest: String,
    media_type: String,
}

#[derive(Debug, Deserialize)]
struct ManifestLayer {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
struct RawManifest {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    layers: Option<Vec<ManifestLayer>>,
    manifests: Option<Vec<serde_json::Value>>,
}

/// Resolve, verify, and (unless disabled) cache the artifact referenced by
/// `reference`, selecting the layer matching `kind`.
///
/// Fails before returning any bytes to the caller if: the reference is a tag
/// and `config.allow_tags` is `false`; the manifest cannot be fetched or
/// parsed; no layer matches an accepted media type for `kind`; the manifest
/// or the selected layer's downloaded bytes do not match their digest; or
/// the response exceeds `config.max_bytes`.
pub fn resolve_oci_artifact(
    reference: &OciReference,
    kind: OciArtifactKind,
    config: &OciFetchConfig,
) -> Result<OciArtifact, Error> {
    let tag = match &reference.selector {
        OciSelector::Tag(tag) if !config.allow_tags => {
            return Err(Error::InvalidInput {
                details: format!(
                    "OCI reference '{}/{}:{}' names a mutable tag; pin it with '@sha256:<hex>' \
                     or pass --allow-oci-tags to explicitly opt in (the resolved digest will be \
                     printed so you can pin it afterward)",
                    reference.registry, reference.repository, tag
                ),
            });
        }
        OciSelector::Tag(tag) => Some(tag.clone()),
        OciSelector::Digest(_) => None,
    };

    let manifest_ref = match &reference.selector {
        OciSelector::Digest(d) => d.clone(),
        OciSelector::Tag(t) => t.clone(),
    };

    let (manifest_bytes, manifest_digest) =
        fetch_manifest(reference, &manifest_ref, config).map_err(|e| annotate(reference, e))?;

    if let Some(expected) = reference.pinned_digest() {
        verify_digest(&manifest_bytes, expected, "manifest")?;
    }

    let manifest: RawManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| Error::OciFetch {
            reference: reference_label(reference),
            details: format!("manifest is not valid JSON: {e}"),
            source: Some(Box::new(e)),
        })?;

    if manifest.manifests.is_some()
        || matches!(
            manifest.media_type.as_deref(),
            Some(OCI_INDEX_MEDIA_TYPE) | Some(DOCKER_MANIFEST_LIST_MEDIA_TYPE)
        )
    {
        return Err(Error::OciFetch {
            reference: reference_label(reference),
            details: "manifest is a multi-manifest image index; reference a single WASM/spec \
                       manifest digest directly, not an index"
                .to_string(),
            source: None,
        });
    }

    let layers = manifest.layers.unwrap_or_default();
    let accepted = kind.accepted_media_types();
    let layer = layers
        .iter()
        .find(|l| accepted.contains(&l.media_type.as_str()))
        .ok_or_else(|| {
            let found: Vec<&str> = layers.iter().map(|l| l.media_type.as_str()).collect();
            Error::OciFetch {
                reference: reference_label(reference),
                details: format!(
                    "manifest has no layer with an accepted media type for '{kind}' (accepted: {}; found: {})",
                    accepted.join(", "),
                    if found.is_empty() { "none".to_string() } else { found.join(", ") }
                ),
                source: None,
            }
        })?;

    let cache_dir = config.resolved_cache_dir();
    if !config.no_cache {
        if let Some(cached) = read_cache(&cache_dir, &layer.digest) {
            return Ok(OciArtifact {
                registry: reference.registry.clone(),
                repository: reference.repository.clone(),
                resolved_tag: tag,
                manifest_digest,
                layer_digest: layer.digest.clone(),
                media_type: cached.media_type,
                bytes: cached.bytes,
                cache_status: CacheStatus::Hit,
            });
        }
    }

    let blob_bytes =
        fetch_blob(reference, &layer.digest, config).map_err(|e| annotate(reference, e))?;
    verify_digest(&blob_bytes, &layer.digest, "layer")?;

    let cache_status = if config.no_cache {
        CacheStatus::Bypassed
    } else {
        write_cache(
            &cache_dir,
            &layer.digest,
            &blob_bytes,
            &CacheMeta {
                registry: reference.registry.clone(),
                repository: reference.repository.clone(),
                manifest_digest: manifest_digest.clone(),
                layer_digest: layer.digest.clone(),
                media_type: layer.media_type.clone(),
            },
        );
        CacheStatus::Miss
    };

    Ok(OciArtifact {
        registry: reference.registry.clone(),
        repository: reference.repository.clone(),
        resolved_tag: tag,
        manifest_digest,
        layer_digest: layer.digest.clone(),
        media_type: layer.media_type.clone(),
        bytes: blob_bytes,
        cache_status,
    })
}

fn reference_label(reference: &OciReference) -> String {
    format!("{}/{}", reference.registry, reference.repository)
}

fn annotate(reference: &OciReference, err: Error) -> Error {
    match err {
        Error::OciFetch {
            reference: r,
            details,
            source,
        } if r.is_empty() => Error::OciFetch {
            reference: reference_label(reference),
            details,
            source,
        },
        other => other,
    }
}

/// Compares `bytes`'s own sha256 against `expected` (`sha256:<hex>`),
/// returning the computed `sha256:<hex>` digest on success.
fn verify_digest(bytes: &[u8], expected: &str, what: &str) -> Result<String, Error> {
    let expected_hex = expected.strip_prefix("sha256:").ok_or_else(|| Error::Integrity {
        details: format!("{what} digest '{expected}' uses an unsupported algorithm; only sha256 is supported"),
        source: None,
    })?;
    let actual_hex = sha256_hex(bytes);
    if !actual_hex.eq_ignore_ascii_case(expected_hex) {
        return Err(Error::Integrity {
            details: format!(
                "{what} digest mismatch: expected sha256:{expected_hex} but downloaded content hashed to sha256:{actual_hex}"
            ),
            source: None,
        });
    }
    Ok(format!("sha256:{actual_hex}"))
}

fn build_agent(config: &OciFetchConfig) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(config.timeout)
        .redirects(3)
        .redirect_auth_headers(ureq::RedirectAuthHeaders::Never)
        .build()
}

fn fetch_manifest(
    reference: &OciReference,
    manifest_ref: &str,
    config: &OciFetchConfig,
) -> Result<(Vec<u8>, String), Error> {
    let url = format!(
        "{}://{}/v2/{}/manifests/{}",
        config.scheme(),
        reference.registry,
        reference.repository,
        manifest_ref
    );
    let accept = [
        OCI_MANIFEST_MEDIA_TYPE,
        DOCKER_MANIFEST_MEDIA_TYPE,
        OCI_INDEX_MEDIA_TYPE,
        DOCKER_MANIFEST_LIST_MEDIA_TYPE,
    ];
    let bytes = get_with_auth(&url, &accept, &reference.registry, config)?;
    let digest = format!("sha256:{}", sha256_hex(&bytes));
    Ok((bytes, digest))
}

fn fetch_blob(
    reference: &OciReference,
    digest: &str,
    config: &OciFetchConfig,
) -> Result<Vec<u8>, Error> {
    let url = format!(
        "{}://{}/v2/{}/blobs/{}",
        config.scheme(),
        reference.registry,
        reference.repository,
        digest
    );
    get_with_auth(
        &url,
        &["application/octet-stream", "*/*"],
        &reference.registry,
        config,
    )
}

/// GET `url`, transparently handling a `401` `WWW-Authenticate` challenge
/// (Bearer token exchange or Basic auth) with credentials resolved from the
/// standard Docker credential store, then returns the verified-size response
/// body.
fn get_with_auth(
    url: &str,
    accept: &[&str],
    registry_host: &str,
    config: &OciFetchConfig,
) -> Result<Vec<u8>, Error> {
    let agent = build_agent(config);
    let accept_header = accept.join(", ");

    let first = agent.get(url).set("Accept", &accept_header).call();

    let response = match first {
        Ok(resp) => resp,
        Err(ureq::Error::Status(401, resp)) => {
            let challenge = resp
                .header("WWW-Authenticate")
                .and_then(parse_www_authenticate)
                .ok_or_else(|| Error::OciFetch {
                    reference: String::new(),
                    details: format!(
                        "registry '{registry_host}' returned 401 with no usable WWW-Authenticate challenge"
                    ),
                    source: None,
                })?;
            let creds = credentials_for_host(registry_host);
            let authorization = match &challenge {
                AuthChallenge::Bearer { .. } => {
                    format!(
                        "Bearer {}",
                        fetch_bearer_token(&agent, &challenge, creds.as_ref(), config)?
                    )
                }
                AuthChallenge::Basic => {
                    let creds = creds.ok_or_else(|| Error::OciFetch {
                        reference: String::new(),
                        details: format!(
                            "registry '{registry_host}' requires Basic authentication but no \
                             Docker credentials were found for it (run 'docker login {registry_host}')"
                        ),
                        source: None,
                    })?;
                    format!(
                        "Basic {}",
                        BASE64.encode(format!("{}:{}", creds.username, creds.secret))
                    )
                }
            };
            agent
                .get(url)
                .set("Accept", &accept_header)
                .set("Authorization", &authorization)
                .call()
                .map_err(|e| Error::OciFetch {
                    reference: String::new(),
                    details: format!(
                        "authenticated request to '{url}' failed: {}",
                        describe_transport_error(&e)
                    ),
                    source: None,
                })?
        }
        Err(e) => {
            return Err(Error::OciFetch {
                reference: String::new(),
                details: format!(
                    "request to '{url}' failed: {}",
                    describe_transport_error(&e)
                ),
                source: None,
            })
        }
    };

    read_body_capped(response, config.max_bytes, url)
}

fn read_body_capped(
    response: ureq::Response,
    max_bytes: usize,
    url: &str,
) -> Result<Vec<u8>, Error> {
    let mut limited = response.into_reader().take(max_bytes as u64 + 1);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|e| Error::OciFetch {
            reference: String::new(),
            details: format!("failed reading response body from '{url}': {e}"),
            source: Some(Box::new(e)),
        })?;
    if bytes.len() as u64 > max_bytes as u64 {
        return Err(Error::OciFetch {
            reference: String::new(),
            details: format!(
                "response from '{url}' exceeded the maximum download size of {max_bytes} bytes"
            ),
            source: None,
        });
    }
    Ok(bytes)
}

fn describe_transport_error(err: &ureq::Error) -> String {
    match err {
        ureq::Error::Status(code, _) => format!("unexpected HTTP status {code}"),
        ureq::Error::Transport(t) => format!("transport error: {t}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthChallenge {
    Bearer {
        realm: String,
        service: Option<String>,
        scope: Option<String>,
    },
    Basic,
}

/// Parse a `WWW-Authenticate` header value into a [`AuthChallenge`].
///
/// Supports the standard `Bearer realm="...",service="...",scope="..."` and
/// `Basic realm="..."` forms used by the Docker/OCI distribution token auth
/// spec.
fn parse_www_authenticate(header: &str) -> Option<AuthChallenge> {
    let header = header.trim();
    if let Some(rest) = header.strip_prefix("Bearer ") {
        let params = parse_auth_params(rest);
        let realm = params.get("realm")?.clone();
        Some(AuthChallenge::Bearer {
            realm,
            service: params.get("service").cloned(),
            scope: params.get("scope").cloned(),
        })
    } else if header.starts_with("Basic") {
        Some(AuthChallenge::Basic)
    } else {
        None
    }
}

fn parse_auth_params(rest: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for part in split_auth_params(rest) {
        if let Some((key, value)) = part.split_once('=') {
            let value = value.trim().trim_matches('"');
            out.insert(key.trim().to_string(), value.to_string());
        }
    }
    out
}

/// Splits `realm="a,b",scope="c"` on top-level commas without breaking up
/// commas that appear inside a quoted value.
fn split_auth_params(rest: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in rest.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ',' if !in_quotes => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Exchange a Bearer challenge for a token, using `creds` (if any) as Basic
/// auth on the token request. Accepts either the `token` or `access_token`
/// response field, matching both the current and legacy distribution token
/// spec responses.
fn fetch_bearer_token(
    agent: &ureq::Agent,
    challenge: &AuthChallenge,
    creds: Option<&DockerCredentials>,
    config: &OciFetchConfig,
) -> Result<String, Error> {
    let AuthChallenge::Bearer {
        realm,
        service,
        scope,
    } = challenge
    else {
        return Err(Error::OciFetch {
            reference: String::new(),
            details: "expected a Bearer challenge".to_string(),
            source: None,
        });
    };

    let mut request = agent.get(realm);
    if let Some(service) = service {
        request = request.query("service", service);
    }
    if let Some(scope) = scope {
        request = request.query("scope", scope);
    }
    if let Some(creds) = creds {
        request = request.set(
            "Authorization",
            &format!(
                "Basic {}",
                BASE64.encode(format!("{}:{}", creds.username, creds.secret))
            ),
        );
    }

    let response = request.call().map_err(|e| Error::OciFetch {
        reference: String::new(),
        details: format!(
            "token exchange with '{realm}' failed: {}",
            describe_transport_error(&e)
        ),
        source: None,
    })?;
    let bytes = read_body_capped(response, config.max_bytes, realm)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| Error::OciFetch {
        reference: String::new(),
        details: format!("token response from '{realm}' is not valid JSON: {e}"),
        source: Some(Box::new(e)),
    })?;
    value
        .get("token")
        .or_else(|| value.get("access_token"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| Error::OciFetch {
            reference: String::new(),
            details: format!(
                "token response from '{realm}' had no 'token' or 'access_token' field"
            ),
            source: None,
        })
}

/// Resolved username/secret pair, from either a plaintext `auths` entry or a
/// credential helper's output.
#[derive(Clone)]
struct DockerCredentials {
    username: String,
    secret: String,
}

impl fmt::Debug for DockerCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DockerCredentials")
            .field("username", &self.username)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// The Docker CLI config file path: `$DOCKER_CONFIG/config.json` if set,
/// otherwise `~/.docker/config.json`.
fn docker_config_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("DOCKER_CONFIG") {
        if !dir.trim().is_empty() {
            return Some(PathBuf::from(dir).join("config.json"));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(PathBuf::from(home).join(".docker").join("config.json"))
}

fn load_docker_config() -> Option<serde_json::Value> {
    let path = docker_config_path()?;
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Resolve credentials for `host` from the standard Docker credential store:
/// a plaintext `auths[host].auth` entry first, then a per-registry
/// `credHelpers[host]` helper, then the global `credsStore` helper.
fn credentials_for_host(host: &str) -> Option<DockerCredentials> {
    credentials_for_host_from(&load_docker_config()?, host)
}

fn credentials_for_host_from(config: &serde_json::Value, host: &str) -> Option<DockerCredentials> {
    if let Some(auth_b64) = config
        .get("auths")
        .and_then(|a| a.get(host))
        .and_then(|e| e.get("auth"))
        .and_then(|v| v.as_str())
    {
        if let Some(creds) = decode_basic_auth(auth_b64) {
            return Some(creds);
        }
    }

    if let Some(helper) = config
        .get("credHelpers")
        .and_then(|h| h.get(host))
        .and_then(|v| v.as_str())
    {
        if let Some(creds) = run_credential_helper(helper, host) {
            return Some(creds);
        }
    }

    if let Some(helper) = config.get("credsStore").and_then(|v| v.as_str()) {
        if let Some(creds) = run_credential_helper(helper, host) {
            return Some(creds);
        }
    }

    None
}

fn decode_basic_auth(auth_b64: &str) -> Option<DockerCredentials> {
    let decoded = BASE64.decode(auth_b64.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (username, secret) = text.split_once(':')?;
    Some(DockerCredentials {
        username: username.to_string(),
        secret: secret.to_string(),
    })
}

/// Invoke `docker-credential-<helper> get`, writing `host` to stdin per the
/// documented Docker credential helper protocol, and parse its
/// `{"ServerURL":...,"Username":...,"Secret":...}` stdout response.
fn run_credential_helper(helper: &str, host: &str) -> Option<DockerCredentials> {
    let mut child = Command::new(format!("docker-credential-{helper}"))
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut()?;
        stdin.write_all(host.as_bytes()).ok()?;
    }

    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let username = value.get("Username")?.as_str()?.to_string();
    let secret = value.get("Secret")?.as_str()?.to_string();
    Some(DockerCredentials { username, secret })
}

struct CachedEntry {
    bytes: Vec<u8>,
    media_type: String,
}

fn entry_dir(cache_dir: &Path, digest: &str) -> PathBuf {
    // `sha256:<hex>` -> a filesystem-safe directory name.
    cache_dir.join(digest.replace(':', "_"))
}

/// Read a cache entry for `digest`, if present and internally consistent.
///
/// Defensively re-hashes the cached bytes against the digest (the key)
/// rather than trusting a possibly corrupted or tampered-with file.
fn read_cache(cache_dir: &Path, digest: &str) -> Option<CachedEntry> {
    let dir = entry_dir(cache_dir, digest);
    let bytes = std::fs::read(dir.join("artifact.bin")).ok()?;
    let expected_hex = digest.strip_prefix("sha256:")?;
    if !sha256_hex(&bytes).eq_ignore_ascii_case(expected_hex) {
        return None;
    }
    let meta: CacheMeta = std::fs::read_to_string(dir.join("meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())?;
    Some(CachedEntry {
        bytes,
        media_type: meta.media_type,
    })
}

/// Best-effort cache write. A failure to cache (read-only filesystem, full
/// disk) does not fail the fetch itself — the caller already has verified
/// bytes in hand.
fn write_cache(cache_dir: &Path, digest: &str, bytes: &[u8], meta: &CacheMeta) {
    let dir = entry_dir(cache_dir, digest);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let tmp_path = dir.join("artifact.bin.tmp");
    if std::fs::write(&tmp_path, bytes).is_err() {
        return;
    }
    if std::fs::rename(&tmp_path, dir.join("artifact.bin")).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        return;
    }
    if let Ok(json) = serde_json::to_string(meta) {
        let _ = std::fs::write(dir.join("meta.json"), json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_returns_none_for_non_oci() {
        assert_eq!(OciReference::parse("./local/file.wasm").unwrap(), None);
        assert_eq!(
            OciReference::parse("https://example.com/x.wasm#sha256=abc").unwrap(),
            None
        );
        assert_eq!(OciReference::parse("-").unwrap(), None);
    }

    #[test]
    fn parse_accepts_a_digest_reference() {
        let digest = "a".repeat(64);
        let input = format!("oci://ghcr.io/example/contracts@sha256:{digest}");
        let parsed = OciReference::parse(&input).unwrap().unwrap();
        assert_eq!(parsed.registry, "ghcr.io");
        assert_eq!(parsed.repository, "example/contracts");
        assert_eq!(
            parsed.selector,
            OciSelector::Digest(format!("sha256:{digest}"))
        );
        assert_eq!(
            parsed.pinned_digest(),
            Some(format!("sha256:{digest}").as_str())
        );
    }

    #[test]
    fn parse_lowercases_the_digest() {
        let input = format!("oci://ghcr.io/example/contracts@sha256:{}", "A".repeat(64));
        let parsed = OciReference::parse(&input).unwrap().unwrap();
        assert_eq!(
            parsed.selector,
            OciSelector::Digest(format!("sha256:{}", "a".repeat(64)))
        );
    }

    #[test]
    fn parse_accepts_a_tag_reference_but_marks_it_unpinned() {
        let input = "oci://ghcr.io/example/contracts:v1.2.3";
        let parsed = OciReference::parse(input).unwrap().unwrap();
        assert_eq!(parsed.selector, OciSelector::Tag("v1.2.3".to_string()));
        assert_eq!(parsed.pinned_digest(), None);
    }

    #[test]
    fn parse_supports_a_registry_with_a_port() {
        let digest = "b".repeat(64);
        let input = format!("oci://localhost:5000/mycontract@sha256:{digest}");
        let parsed = OciReference::parse(&input).unwrap().unwrap();
        assert_eq!(parsed.registry, "localhost:5000");
        assert_eq!(parsed.repository, "mycontract");
    }

    #[test]
    fn parse_rejects_missing_repository() {
        let err = OciReference::parse("oci://ghcr.io").unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
    }

    #[test]
    fn parse_rejects_a_reference_with_no_digest_or_tag() {
        let err = OciReference::parse("oci://ghcr.io/example/contracts").unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
    }

    #[test]
    fn parse_rejects_a_non_sha256_digest_algorithm() {
        let err = OciReference::parse("oci://ghcr.io/example/contracts@sha512:abc").unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn parse_rejects_a_malformed_digest_length() {
        let err = OciReference::parse("oci://ghcr.io/example/contracts@sha256:abcd").unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
    }

    #[test]
    fn resolve_rejects_a_tag_reference_by_default() {
        let reference = OciReference {
            registry: "ghcr.io".to_string(),
            repository: "example/contracts".to_string(),
            selector: OciSelector::Tag("latest".to_string()),
        };
        let config = OciFetchConfig::default();
        assert!(!config.allow_tags);
        let err = resolve_oci_artifact(&reference, OciArtifactKind::Wasm, &config).unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
        assert!(err.to_string().contains("allow-oci-tags"));
    }

    #[test]
    fn verify_digest_accepts_a_matching_digest() {
        let bytes = b"hello world";
        let digest = format!("sha256:{}", sha256_hex(bytes));
        let resolved = verify_digest(bytes, &digest, "layer").unwrap();
        assert_eq!(resolved, digest);
    }

    #[test]
    fn verify_digest_rejects_a_mismatch() {
        let err = verify_digest(b"hello", "sha256:deadbeef", "layer").unwrap_err();
        assert!(matches!(err, Error::Integrity { .. }));
        assert!(err.to_string().contains("digest mismatch"));
    }

    #[test]
    fn parse_www_authenticate_extracts_bearer_challenge_fields() {
        let header = r#"Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:example/contracts:pull""#;
        let challenge = parse_www_authenticate(header).unwrap();
        assert_eq!(
            challenge,
            AuthChallenge::Bearer {
                realm: "https://auth.example.com/token".to_string(),
                service: Some("registry.example.com".to_string()),
                scope: Some("repository:example/contracts:pull".to_string()),
            }
        );
    }

    #[test]
    fn parse_www_authenticate_extracts_basic_challenge() {
        let challenge = parse_www_authenticate(r#"Basic realm="registry""#).unwrap();
        assert_eq!(challenge, AuthChallenge::Basic);
    }

    #[test]
    fn parse_www_authenticate_returns_none_for_unrecognized_scheme() {
        assert!(parse_www_authenticate("Digest realm=\"x\"").is_none());
    }

    #[test]
    fn credentials_for_host_decodes_a_plaintext_auth_entry() {
        let user_pass = BASE64.encode("alice:hunter2");
        let config = serde_json::json!({
            "auths": {
                "ghcr.io": { "auth": user_pass }
            }
        });
        let creds = credentials_for_host_from(&config, "ghcr.io").unwrap();
        assert_eq!(creds.username, "alice");
        assert_eq!(creds.secret, "hunter2");
    }

    #[test]
    fn credentials_for_host_returns_none_when_host_is_absent() {
        let config = serde_json::json!({ "auths": {} });
        assert!(credentials_for_host_from(&config, "ghcr.io").is_none());
    }

    #[test]
    fn credentials_for_host_falls_back_to_a_credential_helper() {
        let dir = std::env::temp_dir().join(format!(
            "safeguard-oci-credhelper-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let helper_path = dir.join("docker-credential-test");
        std::fs::write(
            &helper_path,
            "#!/bin/sh\nread host\necho '{\"ServerURL\":\"'\"$host\"'\",\"Username\":\"bob\",\"Secret\":\"s3cr3t\"}'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&helper_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&helper_path, perms).unwrap();
        }

        let original_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", dir.display(), original_path);
        std::env::set_var("PATH", &new_path);

        #[cfg(unix)]
        {
            let creds = run_credential_helper("test", "ghcr.io");
            let creds = creds.expect("credential helper should resolve credentials");
            assert_eq!(creds.username, "bob");
            assert_eq!(creds.secret, "s3cr3t");
        }

        std::env::set_var("PATH", original_path);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_round_trips_through_disk() {
        let dir =
            std::env::temp_dir().join(format!("safeguard-oci-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let bytes = b"pretend wasm layer bytes".to_vec();
        let digest = format!("sha256:{}", sha256_hex(&bytes));
        assert!(read_cache(&dir, &digest).is_none());

        write_cache(
            &dir,
            &digest,
            &bytes,
            &CacheMeta {
                registry: "ghcr.io".to_string(),
                repository: "example/contracts".to_string(),
                manifest_digest: "sha256:manifest".to_string(),
                layer_digest: digest.clone(),
                media_type: MEDIA_TYPE_WASM.to_string(),
            },
        );

        let cached = read_cache(&dir, &digest).expect("cache hit after write");
        assert_eq!(cached.bytes, bytes);
        assert_eq!(cached.media_type, MEDIA_TYPE_WASM);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_rejects_a_corrupted_entry() {
        let dir = std::env::temp_dir().join(format!(
            "safeguard-oci-cache-corrupt-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let digest = format!("sha256:{}", "c".repeat(64));
        let entry = entry_dir(&dir, &digest);
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("artifact.bin"), b"not the right bytes").unwrap();

        assert!(read_cache(&dir, &digest).is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clear_cache_removes_directory() {
        let dir = std::env::temp_dir().join(format!(
            "safeguard-oci-cache-clear-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(dir.join("abc")).unwrap();
        std::fs::write(dir.join("abc").join("artifact.bin"), b"x").unwrap();

        clear_cache(&dir).unwrap();
        assert!(!dir.exists());
        clear_cache(&dir).unwrap();
    }

    #[test]
    fn default_cache_dir_honors_env_var() {
        std::env::set_var(CACHE_DIR_ENV_VAR, "/tmp/custom-safeguard-oci-cache");
        assert_eq!(
            default_cache_dir(),
            PathBuf::from("/tmp/custom-safeguard-oci-cache")
        );
        std::env::remove_var(CACHE_DIR_ENV_VAR);
    }
}

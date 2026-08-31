//! HTTPS input resolver for WASM binaries and JSON/TOML spec artifacts.
//!
//! Release pipelines frequently publish immutable build artifacts (a compiled
//! WASM, a storage-schema manifest) to HTTPS object storage rather than a
//! local checkout. This module lets any input *position* that already accepts
//! a local path also accept a `https://` URL, without weakening the
//! provenance guarantees a local file gets for free (a fixed byte sequence
//! the caller can point at again).
//!
//! # Reference syntax
//!
//! A remote reference is an `https://` URL followed by a `#sha256=<hex>`
//! fragment carrying the expected digest of the downloaded bytes:
//!
//! ```text
//! https://cdn.example.com/releases/v2/contract.wasm#sha256=3b1a2c...            (64 hex chars)
//! ```
//!
//! The fragment is never sent over the wire (fragments are a client-side-only
//! part of a URL), so it is a natural place to pin an expected digest onto a
//! bare URL string without inventing a second CLI flag per input position.
//! The digest is **mandatory** — [`RemoteRef::parse`] refuses a bare
//! `https://` URL with no `#sha256=` fragment before any network access
//! happens, since an unpinned remote fetch has no integrity guarantee at all.
//!
//! # Transport policy
//!
//! [`fetch_verified`] enforces, via [`ureq`]'s battle-tested redirect
//! machinery rather than a hand-rolled loop:
//!
//! - **HTTPS-only, on every hop.** [`ureq::AgentBuilder::https_only`] rejects
//!   both a non-HTTPS starting URL and any redirect that would downgrade to
//!   plain HTTP.
//! - **A bounded redirect chain** ([`RemoteFetchConfig::max_redirects`]);
//!   exceeding it is a hard error rather than an infinite/very long chain.
//! - **No credential leakage across redirects.** The agent is built with
//!   [`ureq::RedirectAuthHeaders::Never`], so an `Authorization` (or
//!   `Cookie`) header set on the initial request is dropped before any
//!   redirected request is sent — including a same-origin one.
//! - **A hard cap on response size**, enforced by capping the number of bytes
//!   read from the body stream rather than trusting a `Content-Length`
//!   header (which the server may omit, lie about, or which does not exist
//!   at all under chunked transfer encoding).
//! - **A request timeout** ([`RemoteFetchConfig::timeout`]).
//!
//! # Caching
//!
//! Because every fetch is keyed by an expected digest, verified content can
//! be cached content-addressed under [`RemoteFetchConfig::cache_dir`]
//! (default: [`default_cache_dir`]) with no risk of serving stale content for
//! a given reference — the reference itself changes if the artifact does.
//! [`RemoteFetchConfig::no_cache`] bypasses both the read and the write for a
//! single run without deleting anything already cached; [`clear_cache`]
//! deletes the whole cache directory outright (wired to the CLI's
//! `--clear-remote-cache` flag).

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::loader::sha256_hex;
use crate::rpc::redact_url;

/// Default cap on a single remote artifact download, in bytes (64 MiB).
///
/// Generous headroom over any real Soroban contract WASM (kilobytes to a few
/// megabytes) while still bounding memory use against a misbehaving or
/// malicious endpoint.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Default per-request timeout.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default maximum number of redirect hops followed before giving up.
pub const DEFAULT_MAX_REDIRECTS: u32 = 5;

/// Environment variable that overrides the default remote-artifact cache
/// directory when [`RemoteFetchConfig::cache_dir`] is not set explicitly.
pub const CACHE_DIR_ENV_VAR: &str = "SOROBAN_SAFEGUARD_REMOTE_CACHE";

/// A parsed `https://…#sha256=<hex>` reference: a remote artifact together
/// with the digest it must match after download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRef {
    /// The URL with the `#sha256=…` fragment stripped off.
    pub url: String,
    /// Lowercase hex SHA-256 the downloaded bytes must match.
    pub expected_sha256: String,
}

impl RemoteRef {
    /// Parse `input` as a remote reference if it looks like an `https://` URL.
    ///
    /// Returns `Ok(None)` when `input` does not start with `https://`, so
    /// callers can fall through to local-path handling unchanged. Returns
    /// `Err` when it is an `https://` URL but is missing, or has a malformed,
    /// `#sha256=<hex>` digest fragment.
    pub fn parse(input: &str) -> Result<Option<Self>, Error> {
        if !input.starts_with("https://") {
            return Ok(None);
        }
        let (url, fragment) = input.split_once('#').ok_or_else(|| Error::InvalidInput {
            details: format!(
                "remote input '{}' is missing the required '#sha256=<hex>' digest fragment; \
                 every remote artifact must pin an expected digest",
                redact_url(input)
            ),
        })?;
        let hex_digest = fragment.strip_prefix("sha256=").ok_or_else(|| Error::InvalidInput {
            details: format!(
                "remote input '{}' has an unsupported digest fragment '#{}'; expected '#sha256=<hex>'",
                redact_url(url),
                fragment
            ),
        })?;
        if hex_digest.len() != 64 || !hex_digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidInput {
                details: format!(
                    "remote input '{}' has an invalid sha256 digest (expected 64 hex characters, got '{}')",
                    redact_url(url),
                    hex_digest
                ),
            });
        }
        if url.is_empty() {
            return Err(Error::InvalidInput {
                details: "remote input has an empty URL before the '#sha256=' fragment".into(),
            });
        }
        Ok(Some(RemoteRef {
            url: url.to_string(),
            expected_sha256: hex_digest.to_ascii_lowercase(),
        }))
    }
}

/// Policy controlling how [`fetch_verified`] downloads and caches a remote
/// artifact. Every field is independently overridable from the compiled-in
/// default so a CI pipeline can tighten or loosen the policy explicitly.
#[derive(Debug, Clone)]
pub struct RemoteFetchConfig {
    /// Hard cap on the downloaded response body, in bytes.
    pub max_bytes: usize,
    /// Overall per-request timeout.
    pub timeout: Duration,
    /// Maximum number of redirect hops followed before failing.
    pub max_redirects: u32,
    /// Content-addressed cache directory. `None` resolves lazily to
    /// [`default_cache_dir`] at fetch time.
    pub cache_dir: Option<PathBuf>,
    /// When `true`, neither read from nor write to the cache for this fetch.
    pub no_cache: bool,
    /// Reject a non-`https` starting URL or redirect target. Defaults to
    /// `true` and the CLI never changes it — the only reason to set this to
    /// `false` is pointing [`fetch_verified`] at a plaintext local mock
    /// server in a test harness. **Never disable this for a real fetch**:
    /// [`RemoteRef::parse`] already refuses to build a reference from
    /// anything but an `https://` URL, so setting this to `false` only
    /// matters if a caller constructs [`RemoteRef`] directly.
    pub https_only: bool,
}

impl Default for RemoteFetchConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_redirects: DEFAULT_MAX_REDIRECTS,
            cache_dir: None,
            no_cache: false,
            https_only: true,
        }
    }
}

impl RemoteFetchConfig {
    /// The cache directory this config resolves to: [`Self::cache_dir`] if
    /// set, otherwise [`default_cache_dir`].
    #[must_use]
    pub fn resolved_cache_dir(&self) -> PathBuf {
        self.cache_dir.clone().unwrap_or_else(default_cache_dir)
    }
}

/// The default remote-artifact cache directory: [`CACHE_DIR_ENV_VAR`] if set,
/// otherwise a `soroban-upgrade-safeguard/remote-cache` directory under the
/// OS temporary directory.
#[must_use]
pub fn default_cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(CACHE_DIR_ENV_VAR) {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    std::env::temp_dir()
        .join("soroban-upgrade-safeguard")
        .join("remote-cache")
}

/// Delete every cached remote artifact under `dir`. A no-op if `dir` does not
/// exist. Wired to the CLI's `--clear-remote-cache` flag; nothing else
/// evicts cache entries automatically since they are content-addressed and
/// therefore never go stale for a given reference.
pub fn clear_cache(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

/// Whether a fetch was served from the local cache, went to the network, or
/// deliberately bypassed the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStatus {
    /// Served from a previously verified, content-addressed cache entry.
    Hit,
    /// Downloaded from the network and (if caching is enabled) newly cached.
    Miss,
    /// Downloaded from the network with caching disabled for this fetch.
    Bypassed,
}

impl fmt::Display for CacheStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CacheStatus::Hit => "hit",
            CacheStatus::Miss => "miss",
            CacheStatus::Bypassed => "bypassed",
        })
    }
}

/// A verified remote artifact, with enough provenance to identify exactly
/// what was analyzed and where it came from.
#[derive(Debug, Clone)]
pub struct FetchedArtifact {
    /// The URL as given, with any userinfo/query/fragment redacted.
    pub original_url: String,
    /// The URL the bytes were actually served from, after redirects, with
    /// the same redaction applied.
    pub final_url: String,
    /// The verified response body.
    pub bytes: Vec<u8>,
    /// Lowercase hex SHA-256 of `bytes` (equal to the reference's
    /// `expected_sha256` by construction, since a mismatch is an error).
    pub sha256: String,
    pub cache_status: CacheStatus,
    /// The `Content-Type` response header, if the origin sent one.
    pub media_type: Option<String>,
}

/// On-disk sidecar for a cached artifact, holding the provenance fields that
/// aren't recoverable from the bytes alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMeta {
    final_url: String,
    media_type: Option<String>,
}

/// Download, verify, and (unless disabled) cache the artifact referenced by
/// `remote`.
///
/// Fails before returning any bytes to the caller if: the URL is not
/// `https://` (on the initial request or any redirect hop), the redirect
/// count exceeds `config.max_redirects`, the response exceeds
/// `config.max_bytes`, the request exceeds `config.timeout`, or the
/// downloaded content's SHA-256 does not match `remote.expected_sha256`.
pub fn fetch_verified(
    remote: &RemoteRef,
    config: &RemoteFetchConfig,
) -> Result<FetchedArtifact, Error> {
    let cache_dir = config.resolved_cache_dir();

    if !config.no_cache {
        if let Some(cached) = read_cache(&cache_dir, &remote.expected_sha256) {
            return Ok(FetchedArtifact {
                original_url: redact_url(&remote.url),
                final_url: cached.meta.final_url,
                bytes: cached.bytes,
                sha256: remote.expected_sha256.clone(),
                cache_status: CacheStatus::Hit,
                media_type: cached.meta.media_type,
            });
        }
    }

    let agent = ureq::AgentBuilder::new()
        .https_only(config.https_only)
        .redirects(config.max_redirects)
        .redirect_auth_headers(ureq::RedirectAuthHeaders::Never)
        .timeout(config.timeout)
        .build();

    let response = agent
        .get(&remote.url)
        .call()
        .map_err(|e| Error::RemoteFetch {
            url: redact_url(&remote.url),
            details: describe_transport_error(&e),
            source: None,
        })?;

    let media_type = response.header("Content-Type").map(|s| s.to_string());
    let final_url = redact_url(response.get_url());

    let mut limited = response.into_reader().take(config.max_bytes as u64 + 1);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|e| Error::RemoteFetch {
            url: final_url.clone(),
            details: format!("failed reading response body: {e}"),
            source: Some(Box::new(e)),
        })?;
    if bytes.len() as u64 > config.max_bytes as u64 {
        return Err(Error::RemoteFetch {
            url: final_url,
            details: format!(
                "response body exceeded the maximum download size of {} bytes (raise the remote size limit if this artifact is legitimately larger)",
                config.max_bytes
            ),
            source: None,
        });
    }

    let actual_sha256 = sha256_hex(&bytes);
    if !actual_sha256.eq_ignore_ascii_case(&remote.expected_sha256) {
        return Err(Error::Integrity {
            details: format!(
                "digest mismatch for '{}': expected sha256:{} but downloaded content hashed to sha256:{}",
                final_url, remote.expected_sha256, actual_sha256
            ),
            source: None,
        });
    }

    let cache_status = if config.no_cache {
        CacheStatus::Bypassed
    } else {
        write_cache(
            &cache_dir,
            &actual_sha256,
            &bytes,
            &final_url,
            media_type.as_deref(),
        );
        CacheStatus::Miss
    };

    Ok(FetchedArtifact {
        original_url: redact_url(&remote.url),
        final_url,
        bytes,
        sha256: actual_sha256,
        cache_status,
        media_type,
    })
}

fn describe_transport_error(err: &ureq::Error) -> String {
    match err {
        ureq::Error::Status(code, _) => format!("unexpected HTTP status {code}"),
        ureq::Error::Transport(t) => format!("transport error: {t}"),
    }
}

struct CachedEntry {
    bytes: Vec<u8>,
    meta: CacheMeta,
}

fn entry_dir(cache_dir: &Path, sha256: &str) -> PathBuf {
    cache_dir.join(sha256)
}

/// Read a cache entry for `sha256`, if present and internally consistent.
///
/// Defensively re-hashes the cached bytes against the directory name (the
/// key) and silently treats a mismatch as a cache miss rather than trusting
/// a possibly corrupted or tampered-with file.
fn read_cache(cache_dir: &Path, sha256: &str) -> Option<CachedEntry> {
    let dir = entry_dir(cache_dir, sha256);
    let bytes = std::fs::read(dir.join("artifact.bin")).ok()?;
    if !sha256_hex(&bytes).eq_ignore_ascii_case(sha256) {
        return None;
    }
    let meta = std::fs::read_to_string(dir.join("meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<CacheMeta>(&s).ok())
        .unwrap_or(CacheMeta {
            final_url: String::new(),
            media_type: None,
        });
    Some(CachedEntry { bytes, meta })
}

/// Best-effort cache write. A failure to cache (read-only filesystem, full
/// disk) does not fail the fetch itself — the caller already has verified
/// bytes in hand.
fn write_cache(
    cache_dir: &Path,
    sha256: &str,
    bytes: &[u8],
    final_url: &str,
    media_type: Option<&str>,
) {
    let dir = entry_dir(cache_dir, sha256);
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
    let meta = CacheMeta {
        final_url: final_url.to_string(),
        media_type: media_type.map(str::to_string),
    };
    if let Ok(json) = serde_json::to_string(&meta) {
        let _ = std::fs::write(dir.join("meta.json"), json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "3b1a2c9e4d5f6071829384756617283940516273849506172839405162738495";

    fn short_digest() -> String {
        "a".repeat(64)
    }

    #[test]
    fn parse_returns_none_for_non_https() {
        assert_eq!(RemoteRef::parse("./local/file.wasm").unwrap(), None);
        assert_eq!(RemoteRef::parse("http://example.com/x.wasm").unwrap(), None);
        assert_eq!(RemoteRef::parse("-").unwrap(), None);
    }

    #[test]
    fn parse_requires_digest_fragment() {
        let err = RemoteRef::parse("https://example.com/x.wasm").unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn parse_rejects_malformed_digest() {
        let err = RemoteRef::parse("https://example.com/x.wasm#sha256=zz").unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));

        let err = RemoteRef::parse("https://example.com/x.wasm#md5=abc").unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
    }

    #[test]
    fn parse_accepts_valid_reference() {
        let short = short_digest();
        let input = format!("https://example.com/x.wasm#sha256={short}");
        let parsed = RemoteRef::parse(&input).unwrap().unwrap();
        assert_eq!(parsed.url, "https://example.com/x.wasm");
        assert_eq!(parsed.expected_sha256, short);
    }

    #[test]
    fn parse_lowercases_digest() {
        let input = "https://example.com/x.wasm#sha256=".to_string() + &"A".repeat(64);
        let parsed = RemoteRef::parse(&input).unwrap().unwrap();
        assert_eq!(parsed.expected_sha256, "a".repeat(64));
    }

    #[test]
    fn cache_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!(
            "safeguard-remote-cache-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let bytes = b"hello wasm bytes".to_vec();
        let sha = sha256_hex(&bytes);
        assert!(read_cache(&dir, &sha).is_none());

        write_cache(
            &dir,
            &sha,
            &bytes,
            "https://example.com/final.wasm",
            Some("application/wasm"),
        );

        let cached = read_cache(&dir, &sha).expect("cache hit after write");
        assert_eq!(cached.bytes, bytes);
        assert_eq!(cached.meta.final_url, "https://example.com/final.wasm");
        assert_eq!(cached.meta.media_type.as_deref(), Some("application/wasm"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_rejects_corrupted_entry() {
        let dir = std::env::temp_dir().join(format!(
            "safeguard-remote-cache-corrupt-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let sha = DIGEST;
        let entry = entry_dir(&dir, sha);
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("artifact.bin"), b"not the right bytes").unwrap();

        assert!(read_cache(&dir, sha).is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clear_cache_removes_directory() {
        let dir = std::env::temp_dir().join(format!(
            "safeguard-remote-cache-clear-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(dir.join("abc")).unwrap();
        std::fs::write(dir.join("abc").join("artifact.bin"), b"x").unwrap();

        clear_cache(&dir).unwrap();
        assert!(!dir.exists());

        // Idempotent when already absent.
        clear_cache(&dir).unwrap();
    }

    #[test]
    fn default_cache_dir_honors_env_var() {
        std::env::set_var(CACHE_DIR_ENV_VAR, "/tmp/custom-safeguard-cache");
        assert_eq!(
            default_cache_dir(),
            PathBuf::from("/tmp/custom-safeguard-cache")
        );
        std::env::remove_var(CACHE_DIR_ENV_VAR);
    }
}

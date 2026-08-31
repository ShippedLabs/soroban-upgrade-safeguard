//! Authenticated RPC client configuration.
//!
//! Header values are intentionally represented by environment-variable names
//! until a request is about to be made. Resolved values are never serialized
//! or included in `Debug` output.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use crate::error::Error;
use ureq::{Agent, AgentBuilder};

/// Upper bound on how long a single RPC request may take before it is
/// aborted. Without this, a stalled or non-responding RPC endpoint would
/// block the tool (and any caller, including CI) indefinitely.
const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The single shared `ureq::Agent` builder for all RPC requests, authenticated
/// or not. Centralized so timeout/redirect hardening can't silently regress
/// on one call path while being applied to another.
pub(crate) fn default_agent() -> Agent {
    agent_with_timeout(RPC_REQUEST_TIMEOUT)
}

/// Build an RPC agent with an explicit request timeout, sharing the same
/// redirect hardening as [`default_agent`]. Used by callers (like the
/// preflight check) that need a shorter timeout than the production default.
pub(crate) fn agent_with_timeout(timeout: Duration) -> Agent {
    AgentBuilder::new()
        // Reject redirects entirely. `ureq` only strips the standard
        // Authorization header; provider-specific API-key headers would
        // otherwise be forwarded to the redirected origin.
        .redirects(0)
        .redirect_auth_headers(ureq::RedirectAuthHeaders::Never)
        .timeout(timeout)
        .build()
}

#[derive(Clone, PartialEq, Eq)]
pub struct RpcHeader {
    pub name: String,
    pub env_var: String,
}

impl fmt::Debug for RpcHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcHeader")
            .field("name", &self.name)
            .field("env_var", &self.env_var)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

pub const DEFAULT_MAX_SNAPSHOT_RETRIES: u32 = 3;

/// Provenance metadata captured from an RPC snapshot read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RpcProvenance {
    /// Ledger sequence at which the snapshot was captured.
    pub ledger_sequence: u64,
    /// Stellar network passphrase or identifier (e.g. `"Public Global Stellar Network ; September 2015"`).
    pub network: String,
    /// Redacted RPC endpoint URL.
    pub rpc_endpoint: String,
    /// Lowercase hex SHA-256 hash of the contract's WASM code.
    pub code_hash: String,
    /// Ledger sequence until which the sampled ledger entry is live
    /// (`liveUntilLedgerSeq`), if the RPC reported one. `None` means either
    /// the entry has no TTL or the endpoint did not report it; it is not an
    /// error condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_until_ledger_seq: Option<u64>,
}

#[derive(Clone)]
pub struct RpcClientConfig {
    pub url: String,
    pub headers: Vec<RpcHeader>,
    pub max_snapshot_retries: u32,
    /// When `true`, a JSON-RPC response whose `id` is missing or does not
    /// match the request's `id` is accepted instead of rejected. Off by
    /// default; only turn this on for a provider that is known not to echo
    /// request IDs correctly, since it weakens protection against a proxy
    /// or misconfigured endpoint returning a response for the wrong request.
    pub allow_id_mismatch: bool,
}

impl Default for RpcClientConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            headers: Vec::new(),
            max_snapshot_retries: DEFAULT_MAX_SNAPSHOT_RETRIES,
            allow_id_mismatch: false,
        }
    }
}

impl fmt::Debug for RpcClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcClientConfig")
            .field("url", &redact_url(&self.url))
            .field("headers", &self.headers)
            .field("max_snapshot_retries", &self.max_snapshot_retries)
            .field("allow_id_mismatch", &self.allow_id_mismatch)
            .finish()
    }
}

impl RpcClientConfig {
    pub fn new(url: impl Into<String>) -> Result<Self, Error> {
        let url = normalize_url(&url.into())?;
        Ok(Self {
            url,
            headers: Vec::new(),
            max_snapshot_retries: DEFAULT_MAX_SNAPSHOT_RETRIES,
            allow_id_mismatch: false,
        })
    }

    /// Configure maximum retries for snapshot consistency failures.
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_snapshot_retries = retries;
        self
    }

    /// Accept a JSON-RPC response whose `id` is missing or does not match
    /// the request's `id`, for providers known not to echo it correctly.
    /// Off by default; see [`RpcClientConfig::allow_id_mismatch`].
    pub fn with_id_mismatch_allowed(mut self, allow: bool) -> Self {
        self.allow_id_mismatch = allow;
        self
    }

    /// Add a header whose value is read from `env_var` at resolution time.
    pub fn with_env_header(
        mut self,
        name: impl Into<String>,
        env_var: impl Into<String>,
    ) -> Result<Self, Error> {
        let name = name.into();
        let env_var = env_var.into();
        validate_header_name(&name)?;
        if env_var.trim().is_empty() {
            return Err(Error::RpcAuthConfig {
                details: "secret environment variable name cannot be empty".into(),
            });
        }
        if self
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(&name))
        {
            return Err(Error::RpcAuthConfig {
                details: format!("duplicate RPC header '{}'", name),
            });
        }
        self.headers.push(RpcHeader { name, env_var });
        Ok(self)
    }

    pub fn resolve_headers(&self) -> Result<ResolvedRpcHeaders, Error> {
        let mut values = HashMap::new();
        for header in &self.headers {
            let value = std::env::var(&header.env_var).map_err(|_| Error::RpcAuthConfig {
                details: format!(
                    "required RPC secret environment variable '{}' is not set",
                    header.env_var
                ),
            })?;
            if value.is_empty() {
                return Err(Error::RpcAuthConfig {
                    details: format!(
                        "required RPC secret environment variable '{}' is empty",
                        header.env_var
                    ),
                });
            }
            values.insert(header.name.clone(), value);
        }
        Ok(ResolvedRpcHeaders { values })
    }

    pub fn redacted_url(&self) -> String {
        redact_url(&self.url)
    }

    pub(crate) fn request_parts(&self) -> Result<(Agent, ResolvedRpcHeaders), Error> {
        let headers = self.resolve_headers()?;
        Ok((default_agent(), headers))
    }
}

pub struct ResolvedRpcHeaders {
    pub(crate) values: HashMap<String, String>,
}

impl ResolvedRpcHeaders {
    pub(crate) fn empty() -> Self {
        Self {
            values: HashMap::new(),
        }
    }
}

impl fmt::Debug for ResolvedRpcHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.values.keys().map(|key| (key, "[REDACTED]")))
            .finish()
    }
}

pub fn validate_header_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b':') {
        return Err(Error::InvalidHeaderName {
            name: name.to_string(),
        });
    }
    Ok(())
}

/// Normalize safe, semantics-preserving variations of an RPC URL: a default
/// port for the scheme (`:443` on `https://`, `:80` on `http://`) and an
/// empty or root-only path both collapse to the same canonical form, so that
/// equivalent URLs produce identical provenance and replay-bundle identity.
/// Lowercases the scheme and host (both are case-insensitive per RFC 3986);
/// everything else — path segments beyond the root, query, fragment,
/// userinfo — is passed through unchanged since altering it could change
/// what the server actually receives.
///
/// Returns a descriptive [`Error::RpcAuthConfig`] that always names the
/// original, user-facing value when the URL cannot be parsed or normalized.
pub fn normalize_url(url: &str) -> Result<String, Error> {
    let malformed = |details: String| Error::RpcAuthConfig {
        details: format!("RPC URL '{url}' {details}"),
    };

    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| malformed("is missing a scheme (expected http:// or https://)".into()))?;
    let scheme_lower = scheme.to_ascii_lowercase();
    if scheme_lower != "http" && scheme_lower != "https" {
        return Err(malformed("must use http:// or https://".into()));
    }

    let (authority_and_path, query_and_fragment) = match rest.find(['?', '#']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    let (authority, path) = match authority_and_path.find('/') {
        Some(idx) => (&authority_and_path[..idx], &authority_and_path[idx..]),
        None => (authority_and_path, ""),
    };
    if authority.is_empty() {
        return Err(malformed("is missing a host".into()));
    }

    let (userinfo, host_port) = match authority.rfind('@') {
        Some(idx) => (&authority[..=idx], &authority[idx + 1..]),
        None => ("", authority),
    };
    if host_port.is_empty() {
        return Err(malformed("is missing a host".into()));
    }

    let (host, port) = split_host_port(host_port, url)?;
    if host.is_empty() {
        return Err(malformed("is missing a host".into()));
    }

    let default_port = if scheme_lower == "https" { "443" } else { "80" };
    let host_lower = host.to_ascii_lowercase();
    let normalized_authority = match port {
        Some(p) if p == default_port => host_lower,
        Some(p) => format!("{host_lower}:{p}"),
        None => host_lower,
    };

    // An empty path and a bare "/" both mean "the root", per RFC 3986 §6.2.3.
    let normalized_path = if path.is_empty() || path == "/" {
        ""
    } else {
        path
    };

    Ok(format!(
        "{scheme_lower}://{userinfo}{normalized_authority}{normalized_path}{query_and_fragment}"
    ))
}

/// Split a `host:port` or bracketed `[ipv6]:port` authority component into
/// its host and optional port, validating that any port is numeric.
fn split_host_port<'a>(
    host_port: &'a str,
    original_url: &str,
) -> Result<(&'a str, Option<&'a str>), Error> {
    let malformed = |details: String| Error::RpcAuthConfig {
        details: format!("RPC URL '{original_url}' {details}"),
    };

    if let Some(rest) = host_port.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| malformed("has an unterminated IPv6 host literal".into()))?;
        let host = &host_port[..=end + 1];
        let after = &rest[end + 1..];
        return match after.strip_prefix(':') {
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                Ok((host, Some(p)))
            }
            Some("") => Err(malformed("has an empty port".into())),
            Some(_) => Err(malformed("has a non-numeric port".into())),
            None => Ok((host, None)),
        };
    }

    match host_port.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
            Ok((h, Some(p)))
        }
        Some((_, "")) => Err(malformed("has an empty port".into())),
        Some(("", _)) => Err(malformed("is missing a host".into())),
        Some(_) => Err(malformed("has a non-numeric port".into())),
        None => Ok((host_port, None)),
    }
}

pub fn redact_url(url: &str) -> String {
    let without_query = url.split(['?', '#']).next().unwrap_or(url);
    if let Some(scheme_end) = without_query.find("://") {
        let prefix_end = scheme_end + 3;
        if let Some(at) = without_query[prefix_end..].find('@') {
            return format!(
                "{}[REDACTED]{}",
                &without_query[..prefix_end],
                &without_query[prefix_end + at + 1..]
            );
        }
    }
    without_query.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_header_names() {
        assert!(validate_header_name("Authorization").is_ok());
        assert!(validate_header_name("Bad Header").is_err());
        assert!(validate_header_name("Bad:Header").is_err());
    }

    #[test]
    fn redacts_sensitive_url_parts() {
        assert_eq!(
            redact_url("https://user:pass@example.test/rpc?key=secret"),
            "https://[REDACTED]example.test/rpc"
        );
    }

    #[test]
    fn normalize_https_collapses_default_port_and_root_path() {
        assert_eq!(
            normalize_url("https://example.test:443/").unwrap(),
            "https://example.test"
        );
        assert_eq!(
            normalize_url("https://example.test").unwrap(),
            "https://example.test"
        );
    }

    #[test]
    fn normalize_local_http_collapses_default_port_and_empty_path() {
        assert_eq!(
            normalize_url("http://127.0.0.1:80").unwrap(),
            "http://127.0.0.1"
        );
        assert_eq!(
            normalize_url("http://127.0.0.1/").unwrap(),
            "http://127.0.0.1"
        );
    }

    #[test]
    fn normalize_preserves_non_default_ports() {
        assert_eq!(
            normalize_url("https://example.test:8443/rpc").unwrap(),
            "https://example.test:8443/rpc"
        );
        assert_eq!(
            normalize_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn normalize_preserves_non_root_paths_exactly() {
        // Only the empty/root path is collapsed; a deeper path is left
        // untouched, including its trailing slash, since stripping it could
        // change what the server receives.
        assert_eq!(
            normalize_url("https://example.test/rpc/").unwrap(),
            "https://example.test/rpc/"
        );
        assert_eq!(
            normalize_url("https://example.test/rpc").unwrap(),
            "https://example.test/rpc"
        );
    }

    #[test]
    fn normalize_lowercases_scheme_and_host_only() {
        assert_eq!(
            normalize_url("HTTPS://Example.TEST:443/RPC?Key=Value").unwrap(),
            "https://example.test/RPC?Key=Value"
        );
    }

    #[test]
    fn normalize_preserves_userinfo_query_and_fragment() {
        assert_eq!(
            normalize_url("https://user:pass@example.test:443/?token=secret#frag").unwrap(),
            "https://user:pass@example.test?token=secret#frag"
        );
    }

    #[test]
    fn normalize_handles_bracketed_ipv6_hosts() {
        assert_eq!(
            normalize_url("http://[::1]:80/rpc").unwrap(),
            "http://[::1]/rpc"
        );
        assert_eq!(
            normalize_url("http://[::1]:8080").unwrap(),
            "http://[::1]:8080"
        );
    }

    #[test]
    fn normalize_is_idempotent() {
        let once = normalize_url("HTTPS://Example.test:443/rpc/").unwrap();
        let twice = normalize_url(&once).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn normalize_rejects_malformed_urls() {
        let cases = [
            "example.test/rpc",             // no scheme
            "ftp://example.test",           // unsupported scheme
            "https://",                     // no host
            "https:///rpc",                 // no host, path only
            "https://example.test:abc/rpc", // non-numeric port
            "https://:8080/rpc",            // empty host with port
            "http://[::1/rpc",              // unterminated IPv6 literal
        ];
        for case in cases {
            let err = normalize_url(case)
                .expect_err(&format!("expected '{case}' to be rejected as malformed"));
            assert_eq!(err.kind(), crate::error::ErrorKind::RpcAuthConfig);
            assert!(
                err.to_string().contains(case),
                "error for '{case}' should include the original value, got: {err}"
            );
        }
    }
}

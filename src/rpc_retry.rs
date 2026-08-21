//! Bounded RPC retry policy and ordered endpoint failover.
//!
//! # Overview
//!
//! [`RpcResiliencePolicy`] controls how many times a failing RPC call is
//! retried and when the engine moves to the next endpoint in an ordered list.
//! It classifies every failure so that only transient infrastructure problems
//! (network timeouts, rate limits, 5xx responses) are retried; deterministic
//! errors (integrity failures, invalid identifiers, malformed responses) fail
//! immediately without consuming retries.
//!
//! # Retry classification
//!
//! | Error kind | Behaviour |
//! |---|---|
//! | [`RpcTransport`](crate::error::ErrorKind::RpcTransport) | Retryable: network / timeout |
//! | [`RpcProtocol`] with code 429 | Retryable: rate limited |
//! | [`RpcProtocol`] with code 503 | Retryable: provider unavailable |
//! | [`RpcProtocol`] with any other code | **Non-retryable**: deterministic error |
//! | [`Integrity`](crate::error::ErrorKind::Integrity) | **Non-retryable**: hash mismatch |
//! | [`InvalidInput`](crate::error::ErrorKind::InvalidInput) | **Non-retryable**: bad argument |
//! | Everything else | **Non-retryable** |
//!
//! # Injectable timing
//!
//! The [`Sleeper`] trait abstracts `std::thread::sleep` so tests can drive the
//! policy at full speed without real delays.
//!
//! # Example
//!
//! ```rust
//! use soroban_upgrade_safeguard::rpc_retry::{RpcResiliencePolicy, EndpointList};
//!
//! let policy = RpcResiliencePolicy::default();
//! let endpoints = EndpointList::new(vec![
//!     "https://soroban-testnet.stellar.org".into(),
//!     "https://backup.example.com/rpc".into(),
//! ]);
//! ```

use std::time::Duration;

use crate::error::{Error, ErrorKind};

// ── Failure classification ────────────────────────────────────────────────────

/// Whether a failure should be retried or aborted immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// The failure is transient — retry on the same or next endpoint.
    Retry,
    /// The failure is deterministic — abort immediately, no retry.
    Abort,
}

/// Classify an [`Error`] to decide whether a retry is appropriate.
///
/// Only transport failures and a small set of explicitly retryable protocol
/// codes (429 rate-limit, 503 unavailable) are retried. Everything else
/// (integrity failures, invalid inputs, malformed responses, auth errors) is
/// aborted immediately.
pub fn classify(error: &Error) -> RetryDecision {
    match error {
        Error::RpcTransport { .. } => RetryDecision::Retry,
        Error::RpcProtocol { code, .. } => match code {
            429 | 503 => RetryDecision::Retry,
            _ => RetryDecision::Abort,
        },
        // These are all deterministic — retrying will not help.
        Error::Integrity { .. }
        | Error::InvalidInput { .. }
        | Error::UnsupportedContract { .. }
        | Error::XdrDecoding { .. }
        | Error::WasmValidation { .. }
        | Error::RpcAuthConfig { .. }
        | Error::InvalidHeaderName { .. }
        | Error::LimitExceeded { .. }
        | Error::FileAccess { .. }
        | Error::SectionExtraction { .. }
        | Error::SuppressionConfig { .. }
        | Error::BatchBoundary { .. } => RetryDecision::Abort,
        // Unknown variants (non_exhaustive) are conservatively aborted.
        _ => RetryDecision::Abort,
    }
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

/// A sanitized record of one failed attempt, safe to include in provenance.
///
/// The URL is redacted (no credentials) and the error message is a plain
/// string — no secrets, no stack traces.
#[derive(Debug, Clone)]
pub struct AttemptRecord {
    /// Sanitized (redacted) endpoint URL.
    pub endpoint: String,
    /// Attempt number within the overall retry sequence (1-based).
    pub attempt: usize,
    /// Human-readable summary of why this attempt failed.
    pub reason: String,
    /// Whether this failure was classified as retryable.
    pub retryable: bool,
}

/// Accumulated diagnostics from all failed attempts before a success or final
/// failure. Included in the final error when all retries are exhausted.
#[derive(Debug, Clone, Default)]
pub struct RetryDiagnostics {
    pub attempts: Vec<AttemptRecord>,
}

impl RetryDiagnostics {
    /// Record one failed attempt.
    pub fn record(&mut self, endpoint: &str, attempt: usize, error: &Error, retryable: bool) {
        self.attempts.push(AttemptRecord {
            endpoint: crate::rpc::redact_url(endpoint),
            attempt,
            reason: error.to_string(),
            retryable,
        });
    }

    /// Return `true` if any attempt was recorded.
    pub fn is_empty(&self) -> bool {
        self.attempts.is_empty()
    }

    /// A one-line summary of all failed attempts, suitable for an error message.
    pub fn summary(&self) -> String {
        if self.attempts.is_empty() {
            return String::new();
        }
        let lines: Vec<String> = self
            .attempts
            .iter()
            .map(|a| format!("attempt {} on {}: {}", a.attempt, a.endpoint, a.reason))
            .collect();
        lines.join("; ")
    }
}

// ── Resilience policy ─────────────────────────────────────────────────────────

/// Configuration for the retry and failover engine.
///
/// All durations are in milliseconds. Timing is injectable via [`Sleeper`] so
/// tests can run at full speed without real delays.
#[derive(Debug, Clone)]
pub struct RpcResiliencePolicy {
    /// Maximum total number of attempts across all endpoints (including the
    /// first try). Must be at least 1.
    pub max_attempts: usize,
    /// Base delay before the first retry, in milliseconds.
    pub base_delay_ms: u64,
    /// Maximum delay between retries (caps exponential backoff), in milliseconds.
    pub max_delay_ms: u64,
    /// When `true`, add uniform random jitter of up to `base_delay_ms` to each
    /// backoff interval. Disabled by default for deterministic test output.
    pub jitter: bool,
}

impl Default for RpcResiliencePolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 200,
            max_delay_ms: 5_000,
            jitter: false,
        }
    }
}

impl RpcResiliencePolicy {
    /// Compute the backoff delay (in milliseconds) before attempt `n` (1-based).
    ///
    /// Uses truncated exponential backoff: `base * 2^(n-1)` capped at
    /// `max_delay_ms`. Attempt 1 never backs off (returns 0).
    pub fn delay_ms(&self, attempt: usize) -> u64 {
        if attempt <= 1 {
            return 0;
        }
        let exp = (attempt as u32).saturating_sub(1);
        let raw = self.base_delay_ms.saturating_mul(1u64.saturating_shl(exp));
        raw.min(self.max_delay_ms)
    }
}

// ── Ordered endpoint list ─────────────────────────────────────────────────────

/// An ordered list of RPC endpoints tried left-to-right on retryable failures.
///
/// If the list contains only one URL (the common case), behaviour is identical
/// to the existing single-endpoint path.
#[derive(Debug, Clone)]
pub struct EndpointList {
    urls: Vec<String>,
}

impl EndpointList {
    /// Construct from a non-empty list of URLs.
    ///
    /// # Panics
    ///
    /// Panics if `urls` is empty. Use [`EndpointList::single`] for the
    /// common single-URL case.
    pub fn new(urls: Vec<String>) -> Self {
        assert!(!urls.is_empty(), "EndpointList must contain at least one URL");
        Self { urls }
    }

    /// Convenience constructor for the single-URL case.
    pub fn single(url: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
        }
    }

    /// Return the URL at `index`, wrapping around if the index exceeds the list
    /// length (round-robin within the endpoint list).
    pub fn url_for_attempt(&self, attempt: usize) -> &str {
        let idx = (attempt.saturating_sub(1)) % self.urls.len();
        &self.urls[idx]
    }

    /// The number of configured endpoints.
    pub fn len(&self) -> usize {
        self.urls.len()
    }

    /// Whether the list contains exactly one endpoint.
    pub fn is_single(&self) -> bool {
        self.urls.len() == 1
    }
}

// ── Injectable sleep abstraction ──────────────────────────────────────────────

/// Abstracts `std::thread::sleep` so tests can replace it with a no-op.
pub trait Sleeper: Send + Sync {
    fn sleep(&self, duration: Duration);
}

/// Production sleeper backed by `std::thread::sleep`.
pub struct RealSleeper;

impl Sleeper for RealSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// No-op sleeper for tests — returns immediately regardless of duration.
pub struct NoopSleeper;

impl Sleeper for NoopSleeper {
    fn sleep(&self, _duration: Duration) {}
}

// ── Retry engine ──────────────────────────────────────────────────────────────

/// Execute `op` with bounded retries and endpoint failover according to
/// `policy`.
///
/// `op` receives the URL to use for this attempt. On a retryable failure the
/// engine sleeps for the computed backoff, increments the attempt counter, and
/// picks the next endpoint from `endpoints`. On a non-retryable failure it
/// returns immediately.
///
/// When all attempts are exhausted the last error is returned, augmented with
/// a `RetryDiagnostics` summary via [`Error::RpcTransport`].
///
/// # Type parameters
///
/// `F` is a `FnMut(&str) -> Result<T, Error>` — the per-attempt operation.
pub fn with_retry<T, F>(
    policy: &RpcResiliencePolicy,
    endpoints: &EndpointList,
    sleeper: &dyn Sleeper,
    mut op: F,
) -> Result<T, Error>
where
    F: FnMut(&str) -> Result<T, Error>,
{
    let mut diagnostics = RetryDiagnostics::default();

    for attempt in 1..=policy.max_attempts {
        let url = endpoints.url_for_attempt(attempt);

        match op(url) {
            Ok(value) => return Ok(value),
            Err(err) => {
                let decision = classify(&err);
                let retryable = decision == RetryDecision::Retry;
                diagnostics.record(url, attempt, &err, retryable);

                if !retryable || attempt == policy.max_attempts {
                    // Non-retryable or exhausted: return wrapped error.
                    if diagnostics.attempts.len() > 1 {
                        // Wrap in a transport error that carries the full history.
                        let summary = diagnostics.summary();
                        return Err(Error::RpcTransport {
                            rpc_url: crate::rpc::redact_url(url),
                            details: format!(
                                "All {} attempt(s) failed. {}",
                                policy.max_attempts, summary
                            ),
                            source: None,
                        });
                    }
                    return Err(err);
                }

                // Retryable and attempts remain: sleep then continue.
                let delay = policy.delay_ms(attempt + 1);
                if delay > 0 {
                    sleeper.sleep(Duration::from_millis(delay));
                }
            }
        }
    }

    // Unreachable: the loop always returns inside.
    unreachable!("retry loop exited without returning")
}

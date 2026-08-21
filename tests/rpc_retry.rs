//! Tests for the bounded RPC retry policy and endpoint failover engine.
//!
//! All tests are deterministic and require no network access. The
//! [`NoopSleeper`] is used throughout so backoff delays are skipped.

use soroban_upgrade_safeguard::error::Error;
use soroban_upgrade_safeguard::rpc_retry::{
    classify, EndpointList, NoopSleeper, RetryDecision, RpcResiliencePolicy, with_retry,
};

// ── Classification tests ──────────────────────────────────────────────────────

#[test]
fn transport_error_is_retryable() {
    let err = Error::RpcTransport {
        rpc_url: "https://example.com".into(),
        details: "connection reset".into(),
        source: None,
    };
    assert_eq!(classify(&err), RetryDecision::Retry);
}

#[test]
fn rate_limit_429_is_retryable() {
    let err = Error::RpcProtocol {
        rpc_url: "https://example.com".into(),
        code: 429,
        message: "Too Many Requests".into(),
    };
    assert_eq!(classify(&err), RetryDecision::Retry);
}

#[test]
fn service_unavailable_503_is_retryable() {
    let err = Error::RpcProtocol {
        rpc_url: "https://example.com".into(),
        code: 503,
        message: "Service Unavailable".into(),
    };
    assert_eq!(classify(&err), RetryDecision::Retry);
}

#[test]
fn other_protocol_error_is_not_retryable() {
    let err = Error::RpcProtocol {
        rpc_url: "https://example.com".into(),
        code: 400,
        message: "Bad Request".into(),
    };
    assert_eq!(classify(&err), RetryDecision::Abort);
}

#[test]
fn integrity_error_is_not_retryable() {
    let err = Error::Integrity {
        details: "hash mismatch".into(),
        source: None,
    };
    assert_eq!(classify(&err), RetryDecision::Abort);
}

#[test]
fn invalid_input_is_not_retryable() {
    let err = Error::InvalidInput {
        details: "bad contract ID".into(),
    };
    assert_eq!(classify(&err), RetryDecision::Abort);
}

#[test]
fn xdr_decoding_is_not_retryable() {
    let err = Error::XdrDecoding {
        entry_index: None,
        byte_offset: None,
        details: "unexpected EOF".into(),
        source: None,
    };
    assert_eq!(classify(&err), RetryDecision::Abort);
}

// ── Backoff computation ───────────────────────────────────────────────────────

#[test]
fn first_attempt_has_no_delay() {
    let policy = RpcResiliencePolicy {
        base_delay_ms: 200,
        max_delay_ms: 5_000,
        ..Default::default()
    };
    assert_eq!(policy.delay_ms(1), 0);
}

#[test]
fn backoff_doubles_each_attempt() {
    let policy = RpcResiliencePolicy {
        base_delay_ms: 100,
        max_delay_ms: 10_000,
        ..Default::default()
    };
    assert_eq!(policy.delay_ms(2), 100);
    assert_eq!(policy.delay_ms(3), 200);
    assert_eq!(policy.delay_ms(4), 400);
}

#[test]
fn backoff_is_capped_at_max_delay() {
    let policy = RpcResiliencePolicy {
        base_delay_ms: 1_000,
        max_delay_ms: 2_000,
        ..Default::default()
    };
    // 1000 * 2^3 = 8000, capped at 2000
    assert_eq!(policy.delay_ms(4), 2_000);
    assert_eq!(policy.delay_ms(10), 2_000);
}

// ── EndpointList ──────────────────────────────────────────────────────────────

#[test]
fn single_endpoint_always_returns_same_url() {
    let list = EndpointList::single("https://primary.example.com");
    assert_eq!(list.url_for_attempt(1), "https://primary.example.com");
    assert_eq!(list.url_for_attempt(2), "https://primary.example.com");
    assert_eq!(list.url_for_attempt(3), "https://primary.example.com");
}

#[test]
fn multiple_endpoints_round_robin() {
    let list = EndpointList::new(vec![
        "https://primary.example.com".into(),
        "https://backup.example.com".into(),
    ]);
    assert_eq!(list.url_for_attempt(1), "https://primary.example.com");
    assert_eq!(list.url_for_attempt(2), "https://backup.example.com");
    // Wraps around
    assert_eq!(list.url_for_attempt(3), "https://primary.example.com");
}

#[test]
fn endpoint_list_len_is_correct() {
    let list = EndpointList::new(vec!["a".into(), "b".into(), "c".into()]);
    assert_eq!(list.len(), 3);
    assert!(!list.is_single());

    let single = EndpointList::single("a");
    assert_eq!(single.len(), 1);
    assert!(single.is_single());
}

// ── with_retry engine ─────────────────────────────────────────────────────────

#[test]
fn succeeds_on_first_attempt() {
    let policy = RpcResiliencePolicy {
        max_attempts: 3,
        ..Default::default()
    };
    let endpoints = EndpointList::single("https://primary.example.com");
    let mut call_count = 0usize;

    let result = with_retry(&policy, &endpoints, &NoopSleeper, |_url| {
        call_count += 1;
        Ok::<_, Error>(42u32)
    });

    assert_eq!(result.unwrap(), 42);
    assert_eq!(call_count, 1);
}

#[test]
fn retries_transport_failures_and_succeeds_on_third_attempt() {
    let policy = RpcResiliencePolicy {
        max_attempts: 3,
        base_delay_ms: 0,
        ..Default::default()
    };
    let endpoints = EndpointList::single("https://primary.example.com");
    let mut call_count = 0usize;

    let result = with_retry(&policy, &endpoints, &NoopSleeper, |_url| {
        call_count += 1;
        if call_count < 3 {
            Err(Error::RpcTransport {
                rpc_url: "https://primary.example.com".into(),
                details: "timeout".into(),
                source: None,
            })
        } else {
            Ok(99u32)
        }
    });

    assert_eq!(result.unwrap(), 99);
    assert_eq!(call_count, 3);
}

#[test]
fn exhausted_retries_returns_error_with_diagnostics() {
    let policy = RpcResiliencePolicy {
        max_attempts: 3,
        base_delay_ms: 0,
        ..Default::default()
    };
    let endpoints = EndpointList::single("https://primary.example.com");
    let mut call_count = 0usize;

    let result = with_retry(&policy, &endpoints, &NoopSleeper, |_url| {
        call_count += 1;
        Err::<u32, _>(Error::RpcTransport {
            rpc_url: "https://primary.example.com".into(),
            details: "connection refused".into(),
            source: None,
        })
    });

    assert!(result.is_err());
    assert_eq!(call_count, 3, "should have made exactly max_attempts calls");
    // The wrapped error should mention all attempts
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("3 attempt"),
        "error should mention attempt count: {msg}"
    );
}

#[test]
fn non_retryable_error_aborts_immediately() {
    let policy = RpcResiliencePolicy {
        max_attempts: 5,
        base_delay_ms: 0,
        ..Default::default()
    };
    let endpoints = EndpointList::single("https://primary.example.com");
    let mut call_count = 0usize;

    let result = with_retry(&policy, &endpoints, &NoopSleeper, |_url| {
        call_count += 1;
        Err::<u32, _>(Error::Integrity {
            details: "hash mismatch".into(),
            source: None,
        })
    });

    assert!(result.is_err());
    assert_eq!(call_count, 1, "integrity errors must not be retried");
}

#[test]
fn failover_uses_next_endpoint_on_retry() {
    let policy = RpcResiliencePolicy {
        max_attempts: 3,
        base_delay_ms: 0,
        ..Default::default()
    };
    let endpoints = EndpointList::new(vec![
        "https://primary.example.com".into(),
        "https://backup.example.com".into(),
    ]);
    let mut seen_urls: Vec<String> = Vec::new();

    let result = with_retry(&policy, &endpoints, &NoopSleeper, |url| {
        seen_urls.push(url.to_string());
        if url.contains("primary") {
            Err(Error::RpcTransport {
                rpc_url: url.to_string(),
                details: "timeout".into(),
                source: None,
            })
        } else {
            Ok(1u32)
        }
    });

    assert!(result.is_ok(), "backup endpoint should succeed");
    assert!(
        seen_urls.iter().any(|u| u.contains("backup")),
        "backup endpoint must be tried: {:?}",
        seen_urls
    );
}

#[test]
fn rate_limit_is_retried_on_next_endpoint() {
    let policy = RpcResiliencePolicy {
        max_attempts: 2,
        base_delay_ms: 0,
        ..Default::default()
    };
    let endpoints = EndpointList::new(vec![
        "https://primary.example.com".into(),
        "https://backup.example.com".into(),
    ]);
    let mut call_count = 0usize;

    let result = with_retry(&policy, &endpoints, &NoopSleeper, |url| {
        call_count += 1;
        if call_count == 1 {
            Err(Error::RpcProtocol {
                rpc_url: url.to_string(),
                code: 429,
                message: "Too Many Requests".into(),
            })
        } else {
            Ok("ok".to_string())
        }
    });

    assert_eq!(result.unwrap(), "ok");
    assert_eq!(call_count, 2);
}

// ── Configuration tests ───────────────────────────────────────────────────────

#[test]
fn default_policy_has_sensible_values() {
    let policy = RpcResiliencePolicy::default();
    assert!(policy.max_attempts >= 2, "default must allow at least one retry");
    assert!(policy.base_delay_ms > 0, "base delay must be positive");
    assert!(
        policy.max_delay_ms >= policy.base_delay_ms,
        "max delay must not be less than base delay"
    );
}

#[test]
fn single_attempt_policy_never_retries() {
    let policy = RpcResiliencePolicy {
        max_attempts: 1,
        base_delay_ms: 0,
        ..Default::default()
    };
    let endpoints = EndpointList::single("https://primary.example.com");
    let mut call_count = 0usize;

    let _ = with_retry(&policy, &endpoints, &NoopSleeper, |_url| {
        call_count += 1;
        Err::<u32, _>(Error::RpcTransport {
            rpc_url: "https://primary.example.com".into(),
            details: "timeout".into(),
            source: None,
        })
    });

    assert_eq!(call_count, 1, "max_attempts=1 must not retry");
}

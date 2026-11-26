// SPDX-License-Identifier: MIT

//! Integration tests for the metrics module.
//!
//! These tests exercise the public API of `soroban_upgrade_safeguard::metrics`
//! as a user of the library would, verifying the OpenMetrics output format,
//! label cardinality bounds, and data-sanitization guarantees.

use soroban_upgrade_safeguard::metrics::{
    write_metrics_file, AxisLabel, CacheResultLabel, Counter, DurationMetric, Gauge,
    MetricsRegistry, ModeLabel, OutcomeLabel, RpcResultLabel, SeverityLabel, VerdictLabel,
};
use std::time::Duration;

// ── Basic primitive types ────────────────────────────────────────────────────

#[test]
fn counter_starts_at_zero_and_increments() {
    let c = Counter::new();
    assert_eq!(c.get(), 0);
    c.increment();
    assert_eq!(c.get(), 1);
    c.add(9);
    assert_eq!(c.get(), 10);
}

#[test]
fn gauge_stores_last_set_value() {
    let g = Gauge::new();
    assert_eq!(g.get(), 0);
    g.set(100);
    assert_eq!(g.get(), 100);
    g.set(0);
    assert_eq!(g.get(), 0);
}

#[test]
fn duration_metric_sums_correctly() {
    let d = DurationMetric::new();
    d.record(Duration::from_millis(250));
    d.record(Duration::from_millis(750));
    assert_eq!(d.count(), 2);
    // 250 + 750 = 1000ms = 1.0s
    assert!(
        (d.total_seconds() - 1.0).abs() < 1e-6,
        "expected 1.0s, got {}",
        d.total_seconds()
    );
}

// ── MetricsRegistry ──────────────────────────────────────────────────────────

#[test]
fn registry_new_returns_arc() {
    let reg = MetricsRegistry::new();
    // Should be usable as Arc<MetricsRegistry>
    let clone = reg.clone();
    clone.pairs_total.increment();
    assert_eq!(reg.pairs_total.get(), 1);
}

#[test]
fn record_verdict_safe_increments_success_not_error() {
    let reg = MetricsRegistry::default();
    reg.record_verdict(VerdictLabel::Safe);
    assert_eq!(reg.pairs_total.get(), 1);
    assert_eq!(reg.pairs_success.get(), 1);
    assert_eq!(reg.pairs_error.get(), 0);
}

#[test]
fn record_verdict_unsafe_increments_success_not_error() {
    let reg = MetricsRegistry::default();
    reg.record_verdict(VerdictLabel::Unsafe);
    assert_eq!(reg.pairs_total.get(), 1);
    assert_eq!(reg.pairs_success.get(), 1);
    assert_eq!(reg.pairs_error.get(), 0);
}

#[test]
fn record_verdict_error_increments_error_not_success() {
    let reg = MetricsRegistry::default();
    reg.record_verdict(VerdictLabel::Error);
    assert_eq!(reg.pairs_total.get(), 1);
    assert_eq!(reg.pairs_success.get(), 0);
    assert_eq!(reg.pairs_error.get(), 1);
}

#[test]
fn record_finding_increments_correct_cell() {
    let reg = MetricsRegistry::default();
    reg.record_finding(
        SeverityLabel::Critical,
        AxisLabel::StorageLayout,
        OutcomeLabel::Active,
    );
    reg.record_finding(
        SeverityLabel::Warning,
        AxisLabel::CallAbi,
        OutcomeLabel::Suppressed,
    );

    assert_eq!(
        reg.findings.get(
            SeverityLabel::Critical,
            AxisLabel::StorageLayout,
            OutcomeLabel::Active
        ),
        1
    );
    assert_eq!(
        reg.findings.get(
            SeverityLabel::Warning,
            AxisLabel::CallAbi,
            OutcomeLabel::Suppressed
        ),
        1
    );
    // Other cells must remain zero
    assert_eq!(
        reg.findings.get(
            SeverityLabel::Info,
            AxisLabel::EventIndexer,
            OutcomeLabel::Migrated
        ),
        0
    );
}

#[test]
fn set_mode_records_correctly() {
    let reg = MetricsRegistry::default();
    reg.set_mode(ModeLabel::Batch);
    let guard = reg.mode.lock().unwrap();
    assert_eq!(*guard, Some(ModeLabel::Batch));
}

#[test]
fn rpc_result_all_variants() {
    let reg = MetricsRegistry::default();
    reg.record_rpc_result(RpcResultLabel::Success);
    reg.record_rpc_result(RpcResultLabel::TransportError);
    reg.record_rpc_result(RpcResultLabel::ProtocolError);
    reg.record_rpc_result(RpcResultLabel::Timeout);
    reg.record_rpc_result(RpcResultLabel::HashMismatch);

    assert_eq!(reg.rpc_attempts_success.get(), 1);
    assert_eq!(reg.rpc_attempts_transport_error.get(), 1);
    assert_eq!(reg.rpc_attempts_protocol_error.get(), 1);
    assert_eq!(reg.rpc_attempts_timeout.get(), 1);
    assert_eq!(reg.rpc_attempts_hash_mismatch.get(), 1);
}

#[test]
fn cache_result_all_variants() {
    let reg = MetricsRegistry::default();
    reg.record_cache_result(CacheResultLabel::Hit);
    reg.record_cache_result(CacheResultLabel::Miss);
    reg.record_cache_result(CacheResultLabel::Invalidated);

    assert_eq!(reg.cache_hits.get(), 1);
    assert_eq!(reg.cache_misses.get(), 1);
    assert_eq!(reg.cache_invalidations.get(), 1);
}

// ── OpenMetrics output format ────────────────────────────────────────────────

#[test]
fn openmetrics_output_ends_with_eof_marker() {
    let reg = MetricsRegistry::default();
    let text = reg.to_openmetrics_text();
    assert!(
        text.ends_with("# EOF\n"),
        "output must end with '# EOF\\n', got: {text:?}"
    );
}

#[test]
fn openmetrics_output_contains_required_metrics() {
    let reg = MetricsRegistry::default();
    let text = reg.to_openmetrics_text();

    for expected in &[
        "soroban_safeguard_pairs_total",
        "soroban_safeguard_pairs_success_total",
        "soroban_safeguard_pairs_error_total",
        "soroban_safeguard_cache_lookups_total",
        "soroban_safeguard_rpc_attempts_total",
    ] {
        assert!(
            text.contains(expected),
            "missing metric {expected:?} in output"
        );
    }
}

#[test]
fn openmetrics_output_is_deterministic() {
    let reg = MetricsRegistry::default();
    reg.pairs_total.increment();
    reg.record_finding(
        SeverityLabel::Critical,
        AxisLabel::StorageLayout,
        OutcomeLabel::Active,
    );
    reg.set_mode(ModeLabel::Single);
    reg.wasm_bytes_old.set(100);
    reg.wasm_bytes_new.set(200);

    let a = reg.to_openmetrics_text();
    let b = reg.to_openmetrics_text();
    assert_eq!(a, b, "output must be identical across multiple calls");
}

#[test]
fn finding_cardinality_is_exactly_45() {
    let reg = MetricsRegistry::default();
    for severity in &[
        SeverityLabel::Critical,
        SeverityLabel::Warning,
        SeverityLabel::Info,
    ] {
        for axis in &[
            AxisLabel::StorageLayout,
            AxisLabel::CallAbi,
            AxisLabel::EventIndexer,
            AxisLabel::SourceLevel,
            AxisLabel::RuntimeSurface,
        ] {
            for outcome in &[
                OutcomeLabel::Active,
                OutcomeLabel::Suppressed,
                OutcomeLabel::Migrated,
            ] {
                reg.findings.record(*severity, *axis, *outcome);
            }
        }
    }

    let text = reg.to_openmetrics_text();
    let unique: std::collections::HashSet<&str> = text
        .lines()
        .filter(|l| l.starts_with("soroban_safeguard_findings_total{"))
        .collect();
    assert_eq!(
        unique.len(),
        45,
        "expected 45 finding time series, got {}",
        unique.len()
    );
}

// ── Data-sanitization guarantee ──────────────────────────────────────────────

#[test]
fn no_user_supplied_strings_appear_in_output() {
    let reg = MetricsRegistry::default();
    reg.set_mode(ModeLabel::Single);
    reg.record_finding(
        SeverityLabel::Critical,
        AxisLabel::StorageLayout,
        OutcomeLabel::Active,
    );

    let text = reg.to_openmetrics_text();

    // User-supplied strings that must never appear as label values
    let forbidden = [
        "CABCD1234...",
        "https://soroban-testnet.stellar.org",
        "/home/user/contracts/token.wasm",
        "Struct Field Removed",
        "ConfigData.threshold",
        "my-secret-token",
    ];
    for s in &forbidden {
        assert!(
            !text.contains(s),
            "user data leaked into metrics output: {s:?}"
        );
    }
}

// ── File I/O ─────────────────────────────────────────────────────────────────

#[test]
fn write_metrics_file_produces_valid_openmetrics() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "soroban_metrics_integration_test_{}.txt",
        std::process::id()
    ));

    let reg = MetricsRegistry::default();
    reg.pairs_total.increment();
    reg.pairs_success.increment();
    reg.record_finding(
        SeverityLabel::Warning,
        AxisLabel::CallAbi,
        OutcomeLabel::Active,
    );

    write_metrics_file(&reg, &path).expect("write_metrics_file should succeed");

    let content = std::fs::read_to_string(&path).expect("file should be readable after write");
    assert!(
        content.contains("soroban_safeguard_pairs_total"),
        "output should contain pair counter"
    );
    assert!(content.ends_with("# EOF\n"), "output should end with # EOF");

    // Clean up
    std::fs::remove_file(&path).ok();
}

#[test]
fn write_metrics_file_to_nonexistent_parent_fails_gracefully() {
    let path = std::path::Path::new("/nonexistent_dir_xyz/metrics.txt");
    let reg = MetricsRegistry::default();
    let result = write_metrics_file(&reg, path);
    assert!(
        result.is_err(),
        "writing to a nonexistent parent directory should fail"
    );
}

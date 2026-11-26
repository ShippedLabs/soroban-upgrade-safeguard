// SPDX-License-Identifier: MIT

//! # Analysis Metrics
//!
//! Provides Prometheus/OpenMetrics-compatible metric collection and export for
//! the analysis pipeline. Metrics are emitted separately from reports and never
//! include contract IDs, RPC URLs, file paths, or finding messages as label
//! values to prevent sensitive data leakage.
//!
//! ## Stability
//!
//! Metric names, units, label names, and label value cardinality are part of
//! the documented compatibility policy. Once stabilised, a metric name or its
//! labels will not change in a backwards-incompatible way without a major
//! version bump. The `# HELP` and `# TYPE` lines follow the OpenMetrics
//! text format (Content-Type: `application/openmetrics-text; version=1.0.0`).
//!
//! ## Label cardinality
//!
//! Every label is drawn from a **closed enumeration** defined in this module;
//! no user-supplied string (contract name, RPC URL, file path, finding message,
//! or target) ever appears as a label value. The complete set of distinct time
//! series this module can produce is bounded and documented in
//! `docs/metrics.md`.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Controlled severity label values (closed enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeverityLabel {
    Critical,
    Warning,
    Info,
}

impl SeverityLabel {
    fn as_str(self) -> &'static str {
        match self {
            SeverityLabel::Critical => "critical",
            SeverityLabel::Warning => "warning",
            SeverityLabel::Info => "info",
        }
    }
}

/// Controlled compatibility-axis label values (closed enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AxisLabel {
    StorageLayout,
    CallAbi,
    EventIndexer,
    SourceLevel,
    RuntimeSurface,
}

impl AxisLabel {
    fn as_str(self) -> &'static str {
        match self {
            AxisLabel::StorageLayout => "storage_layout",
            AxisLabel::CallAbi => "call_abi",
            AxisLabel::EventIndexer => "event_indexer",
            AxisLabel::SourceLevel => "source_level",
            AxisLabel::RuntimeSurface => "runtime_surface",
        }
    }
}

/// Controlled finding-outcome label values (closed enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeLabel {
    /// Finding was not suppressed.
    Active,
    /// Finding was suppressed by a suppression config.
    Suppressed,
    /// Finding is covered by a verified migration.
    Migrated,
}

impl OutcomeLabel {
    fn as_str(self) -> &'static str {
        match self {
            OutcomeLabel::Active => "active",
            OutcomeLabel::Suppressed => "suppressed",
            OutcomeLabel::Migrated => "migrated",
        }
    }
}

/// Controlled input-source label values (closed enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputSourceLabel {
    /// Local file on disk.
    LocalFile,
    /// Fetched via HTTPS with digest verification.
    RemoteHttps,
    /// Fetched from an OCI registry.
    Oci,
    /// Fetched over Stellar RPC.
    Rpc,
    /// Read from stdin.
    Stdin,
}

/// Controlled cache-result label values (closed enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheResultLabel {
    Hit,
    Miss,
    Invalidated,
}

impl CacheResultLabel {
    fn as_str(self) -> &'static str {
        match self {
            CacheResultLabel::Hit => "hit",
            CacheResultLabel::Miss => "miss",
            CacheResultLabel::Invalidated => "invalidated",
        }
    }
}

/// Controlled pipeline-stage label values for duration metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageLabel {
    Loading,
    Parsing,
    Diffing,
    Rendering,
    Rpc,
}

impl StageLabel {
    fn as_str(self) -> &'static str {
        match self {
            StageLabel::Loading => "loading",
            StageLabel::Parsing => "parsing",
            StageLabel::Diffing => "diffing",
            StageLabel::Rendering => "rendering",
            StageLabel::Rpc => "rpc",
        }
    }
}

/// Controlled RPC-attempt-result label values (closed enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcResultLabel {
    Success,
    TransportError,
    ProtocolError,
    Timeout,
    HashMismatch,
}

impl RpcResultLabel {
    fn as_str(self) -> &'static str {
        match self {
            RpcResultLabel::Success => "success",
            RpcResultLabel::TransportError => "transport_error",
            RpcResultLabel::ProtocolError => "protocol_error",
            RpcResultLabel::Timeout => "timeout",
            RpcResultLabel::HashMismatch => "hash_mismatch",
        }
    }
}

/// Controlled analysis-mode label values (closed enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeLabel {
    Single,
    Batch,
    Watch,
    Directory,
    Stream,
}

impl ModeLabel {
    fn as_str(self) -> &'static str {
        match self {
            ModeLabel::Single => "single",
            ModeLabel::Batch => "batch",
            ModeLabel::Watch => "watch",
            ModeLabel::Directory => "directory",
            ModeLabel::Stream => "stream",
        }
    }
}

/// Controlled verdict label values (closed enumeration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerdictLabel {
    Safe,
    Unsafe,
    Error,
}

/// A simple counter backed by an atomic u64.
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A simple gauge backed by an atomic u64.
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, v: u64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A duration accumulator (sum of nanoseconds + count).
#[derive(Debug, Default)]
pub struct DurationMetric {
    total_ns: AtomicU64,
    count: AtomicU64,
}

impl DurationMetric {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, d: Duration) {
        self.total_ns
            .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_seconds(&self) -> f64 {
        self.total_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// A RAII guard that records a duration when dropped.
pub struct StageTimer<'a> {
    start: Instant,
    metric: &'a DurationMetric,
}

impl<'a> StageTimer<'a> {
    pub fn start(metric: &'a DurationMetric) -> Self {
        Self {
            start: Instant::now(),
            metric,
        }
    }
}

impl Drop for StageTimer<'_> {
    fn drop(&mut self) {
        self.metric.record(self.start.elapsed());
    }
}

/// Per-severity, per-axis, per-outcome finding counter matrix.
/// All dimensions are closed enumerations, so cardinality is bounded.
#[derive(Debug, Default)]
pub struct FindingCounters {
    // [severity][axis][outcome]
    counts: [[[AtomicU64; 3]; 5]; 3],
}

// Severity index: Critical=0, Warning=1, Info=2
fn severity_idx(s: SeverityLabel) -> usize {
    match s {
        SeverityLabel::Critical => 0,
        SeverityLabel::Warning => 1,
        SeverityLabel::Info => 2,
    }
}

// Axis index: StorageLayout=0, CallAbi=1, EventIndexer=2, SourceLevel=3, RuntimeSurface=4
fn axis_idx(a: AxisLabel) -> usize {
    match a {
        AxisLabel::StorageLayout => 0,
        AxisLabel::CallAbi => 1,
        AxisLabel::EventIndexer => 2,
        AxisLabel::SourceLevel => 3,
        AxisLabel::RuntimeSurface => 4,
    }
}

// Outcome index: Active=0, Suppressed=1, Migrated=2
fn outcome_idx(o: OutcomeLabel) -> usize {
    match o {
        OutcomeLabel::Active => 0,
        OutcomeLabel::Suppressed => 1,
        OutcomeLabel::Migrated => 2,
    }
}

impl FindingCounters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one finding with severity + axis + outcome labels.
    pub fn record(&self, severity: SeverityLabel, axis: AxisLabel, outcome: OutcomeLabel) {
        let s = severity_idx(severity);
        let a = axis_idx(axis);
        let o = outcome_idx(outcome);
        self.counts[s][a][o].fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self, severity: SeverityLabel, axis: AxisLabel, outcome: OutcomeLabel) -> u64 {
        let s = severity_idx(severity);
        let a = axis_idx(axis);
        let o = outcome_idx(outcome);
        self.counts[s][a][o].load(Ordering::Relaxed)
    }
}

/// The central metrics registry for one tool invocation.
#[derive(Debug)]
pub struct MetricsRegistry {
    // ---- Analysis runs ----
    /// Total number of analysis pairs attempted (counter).
    pub pairs_total: Counter,
    /// Pairs that completed without error (counter).
    pub pairs_success: Counter,
    /// Pairs that failed with an error (counter).
    pub pairs_error: Counter,

    // ---- Finding counts ----
    /// Per-severity/axis/outcome finding counts.
    pub findings: FindingCounters,

    // ---- Pipeline stage durations ----
    pub duration_loading_seconds: DurationMetric,
    pub duration_parsing_seconds: DurationMetric,
    pub duration_diffing_seconds: DurationMetric,
    pub duration_rendering_seconds: DurationMetric,
    pub duration_rpc_seconds: DurationMetric,
    /// Total wall-clock duration of the entire run.
    pub duration_total_seconds: DurationMetric,

    // ---- Cache ----
    /// Metadata cache hits.
    pub cache_hits: Counter,
    /// Metadata cache misses.
    pub cache_misses: Counter,
    /// Metadata cache invalidations.
    pub cache_invalidations: Counter,

    // ---- RPC ----
    /// RPC attempt results by outcome.
    pub rpc_attempts_success: Counter,
    pub rpc_attempts_transport_error: Counter,
    pub rpc_attempts_protocol_error: Counter,
    pub rpc_attempts_timeout: Counter,
    pub rpc_attempts_hash_mismatch: Counter,

    // ---- Batch / watch ----
    /// Number of watch-mode re-analysis cycles triggered.
    pub watch_cycles_total: Counter,
    /// Number of times a resource-limit was hit (WASM size, complexity budget, etc.).
    pub resource_limit_hits: Counter,

    // ---- Gauges ----
    /// WASM size in bytes (old build).
    pub wasm_bytes_old: Gauge,
    /// WASM size in bytes (new build).
    pub wasm_bytes_new: Gauge,

    // ---- Mode ----
    /// Analysis mode for this run.
    pub mode: std::sync::Mutex<Option<ModeLabel>>,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self {
            pairs_total: Counter::new(),
            pairs_success: Counter::new(),
            pairs_error: Counter::new(),
            findings: FindingCounters::new(),
            duration_loading_seconds: DurationMetric::new(),
            duration_parsing_seconds: DurationMetric::new(),
            duration_diffing_seconds: DurationMetric::new(),
            duration_rendering_seconds: DurationMetric::new(),
            duration_rpc_seconds: DurationMetric::new(),
            duration_total_seconds: DurationMetric::new(),
            cache_hits: Counter::new(),
            cache_misses: Counter::new(),
            cache_invalidations: Counter::new(),
            rpc_attempts_success: Counter::new(),
            rpc_attempts_transport_error: Counter::new(),
            rpc_attempts_protocol_error: Counter::new(),
            rpc_attempts_timeout: Counter::new(),
            rpc_attempts_hash_mismatch: Counter::new(),
            watch_cycles_total: Counter::new(),
            resource_limit_hits: Counter::new(),
            wasm_bytes_old: Gauge::new(),
            wasm_bytes_new: Gauge::new(),
            mode: std::sync::Mutex::new(None),
        }
    }
}

impl MetricsRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record a verdict for one analysis pair.
    pub fn record_verdict(&self, verdict: VerdictLabel) {
        self.pairs_total.increment();
        match verdict {
            VerdictLabel::Safe | VerdictLabel::Unsafe => self.pairs_success.increment(),
            VerdictLabel::Error => self.pairs_error.increment(),
        }
    }

    /// Record a single finding with its labels.
    pub fn record_finding(&self, severity: SeverityLabel, axis: AxisLabel, outcome: OutcomeLabel) {
        self.findings.record(severity, axis, outcome);
    }

    /// Record an RPC attempt result.
    pub fn record_rpc_result(&self, result: RpcResultLabel) {
        match result {
            RpcResultLabel::Success => self.rpc_attempts_success.increment(),
            RpcResultLabel::TransportError => self.rpc_attempts_transport_error.increment(),
            RpcResultLabel::ProtocolError => self.rpc_attempts_protocol_error.increment(),
            RpcResultLabel::Timeout => self.rpc_attempts_timeout.increment(),
            RpcResultLabel::HashMismatch => self.rpc_attempts_hash_mismatch.increment(),
        }
    }

    /// Set the analysis mode for this run.
    pub fn set_mode(&self, mode: ModeLabel) {
        if let Ok(mut guard) = self.mode.lock() {
            *guard = Some(mode);
        }
    }

    /// Record a cache lookup result.
    pub fn record_cache_result(&self, result: CacheResultLabel) {
        match result {
            CacheResultLabel::Hit => self.cache_hits.increment(),
            CacheResultLabel::Miss => self.cache_misses.increment(),
            CacheResultLabel::Invalidated => self.cache_invalidations.increment(),
        }
    }

    /// Serialize to OpenMetrics text format.
    pub fn to_openmetrics_text(&self) -> String {
        let mut out = String::with_capacity(4096);
        self.write_openmetrics(&mut out);
        out
    }

    fn write_openmetrics(&self, out: &mut String) {
        use std::fmt::Write;

        // --- pairs ---
        writeln!(
            out,
            "# HELP soroban_safeguard_pairs Total number of contract-pair analysis attempts in this run."
        )
        .unwrap();
        writeln!(out, "# TYPE soroban_safeguard_pairs counter").unwrap();
        writeln!(
            out,
            "soroban_safeguard_pairs_total {}",
            self.pairs_total.get()
        )
        .unwrap();

        writeln!(
            out,
            "# HELP soroban_safeguard_pairs_success Contract-pair analyses that completed without an error."
        )
        .unwrap();
        writeln!(out, "# TYPE soroban_safeguard_pairs_success counter").unwrap();
        writeln!(
            out,
            "soroban_safeguard_pairs_success_total {}",
            self.pairs_success.get()
        )
        .unwrap();

        writeln!(
            out,
            "# HELP soroban_safeguard_pairs_error Contract-pair analyses that failed with an internal error."
        )
        .unwrap();
        writeln!(out, "# TYPE soroban_safeguard_pairs_error counter").unwrap();
        writeln!(
            out,
            "soroban_safeguard_pairs_error_total {}",
            self.pairs_error.get()
        )
        .unwrap();

        // --- findings ---
        writeln!(
            out,
            "# HELP soroban_safeguard_findings Finding counts by severity, axis, and outcome. Labels are drawn from closed enumerations; no user data appears as a label value."
        )
        .unwrap();
        writeln!(out, "# TYPE soroban_safeguard_findings counter").unwrap();
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
                    let v = self.findings.get(*severity, *axis, *outcome);
                    if v > 0 {
                        writeln!(
                            out,
                            "soroban_safeguard_findings_total{{severity=\"{}\",axis=\"{}\",outcome=\"{}\"}} {}",
                            severity.as_str(),
                            axis.as_str(),
                            outcome.as_str(),
                            v
                        )
                        .unwrap();
                    }
                }
            }
        }

        // --- durations ---
        for (stage, metric) in &[
            (StageLabel::Loading, &self.duration_loading_seconds),
            (StageLabel::Parsing, &self.duration_parsing_seconds),
            (StageLabel::Diffing, &self.duration_diffing_seconds),
            (StageLabel::Rendering, &self.duration_rendering_seconds),
            (StageLabel::Rpc, &self.duration_rpc_seconds),
        ] {
            if metric.count() > 0 {
                writeln!(
                    out,
                    "# HELP soroban_safeguard_stage_duration_seconds Cumulative time spent in each pipeline stage."
                )
                .unwrap();
                writeln!(
                    out,
                    "# TYPE soroban_safeguard_stage_duration_seconds counter"
                )
                .unwrap();
                writeln!(
                    out,
                    "soroban_safeguard_stage_duration_seconds_total{{stage=\"{}\"}} {:.9}",
                    stage.as_str(),
                    metric.total_seconds()
                )
                .unwrap();
            }
        }
        if self.duration_total_seconds.count() > 0 {
            writeln!(
                out,
                "# HELP soroban_safeguard_run_duration_seconds Total wall-clock time of the analysis run."
            )
            .unwrap();
            writeln!(out, "# TYPE soroban_safeguard_run_duration_seconds counter").unwrap();
            writeln!(
                out,
                "soroban_safeguard_run_duration_seconds_total {:.9}",
                self.duration_total_seconds.total_seconds()
            )
            .unwrap();
        }

        // --- cache ---
        writeln!(
            out,
            "# HELP soroban_safeguard_cache_lookups Metadata-cache lookups by result."
        )
        .unwrap();
        writeln!(out, "# TYPE soroban_safeguard_cache_lookups counter").unwrap();
        for (result, count) in &[
            (CacheResultLabel::Hit, self.cache_hits.get()),
            (CacheResultLabel::Miss, self.cache_misses.get()),
            (
                CacheResultLabel::Invalidated,
                self.cache_invalidations.get(),
            ),
        ] {
            writeln!(
                out,
                "soroban_safeguard_cache_lookups_total{{result=\"{}\"}} {}",
                result.as_str(),
                count
            )
            .unwrap();
        }

        // --- RPC ---
        writeln!(
            out,
            "# HELP soroban_safeguard_rpc_attempts RPC baseline-fetch attempts by result."
        )
        .unwrap();
        writeln!(out, "# TYPE soroban_safeguard_rpc_attempts counter").unwrap();
        for (result, count) in &[
            (RpcResultLabel::Success, self.rpc_attempts_success.get()),
            (
                RpcResultLabel::TransportError,
                self.rpc_attempts_transport_error.get(),
            ),
            (
                RpcResultLabel::ProtocolError,
                self.rpc_attempts_protocol_error.get(),
            ),
            (RpcResultLabel::Timeout, self.rpc_attempts_timeout.get()),
            (
                RpcResultLabel::HashMismatch,
                self.rpc_attempts_hash_mismatch.get(),
            ),
        ] {
            writeln!(
                out,
                "soroban_safeguard_rpc_attempts_total{{result=\"{}\"}} {}",
                result.as_str(),
                count
            )
            .unwrap();
        }

        // --- batch / watch ---
        if self.watch_cycles_total.get() > 0 {
            writeln!(
                out,
                "# HELP soroban_safeguard_watch_cycles Number of watch-mode re-analysis cycles triggered by filesystem events."
            )
            .unwrap();
            writeln!(out, "# TYPE soroban_safeguard_watch_cycles counter").unwrap();
            writeln!(
                out,
                "soroban_safeguard_watch_cycles_total {}",
                self.watch_cycles_total.get()
            )
            .unwrap();
        }
        if self.resource_limit_hits.get() > 0 {
            writeln!(
                out,
                "# HELP soroban_safeguard_resource_limit_hits Number of times a configured resource limit (WASM size, complexity budget) was exceeded."
            )
            .unwrap();
            writeln!(out, "# TYPE soroban_safeguard_resource_limit_hits counter").unwrap();
            writeln!(
                out,
                "soroban_safeguard_resource_limit_hits_total {}",
                self.resource_limit_hits.get()
            )
            .unwrap();
        }

        // --- gauges ---
        if self.wasm_bytes_old.get() > 0 || self.wasm_bytes_new.get() > 0 {
            writeln!(
                out,
                "# HELP soroban_safeguard_wasm_bytes WASM input size in bytes."
            )
            .unwrap();
            writeln!(out, "# TYPE soroban_safeguard_wasm_bytes gauge").unwrap();
            writeln!(
                out,
                "soroban_safeguard_wasm_bytes{{build=\"old\"}} {}",
                self.wasm_bytes_old.get()
            )
            .unwrap();
            writeln!(
                out,
                "soroban_safeguard_wasm_bytes{{build=\"new\"}} {}",
                self.wasm_bytes_new.get()
            )
            .unwrap();
        }

        // --- mode ---
        if let Ok(guard) = self.mode.lock() {
            if let Some(mode) = *guard {
                writeln!(
                    out,
                    "# HELP soroban_safeguard_mode Analysis mode for this invocation (gauge, exactly one label value is 1)."
                )
                .unwrap();
                writeln!(out, "# TYPE soroban_safeguard_mode gauge").unwrap();
                for m in &[
                    ModeLabel::Single,
                    ModeLabel::Batch,
                    ModeLabel::Watch,
                    ModeLabel::Directory,
                    ModeLabel::Stream,
                ] {
                    writeln!(
                        out,
                        "soroban_safeguard_mode{{mode=\"{}\"}} {}",
                        m.as_str(),
                        if *m == mode { 1 } else { 0 }
                    )
                    .unwrap();
                }
            }
        }

        // OpenMetrics EOF marker
        writeln!(out, "# EOF").unwrap();
    }
}

impl fmt::Display for MetricsRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_openmetrics_text())
    }
}

/// Write the metrics text to a file at `path`.
///
/// Writes to a temporary file in the same directory first, then atomically
/// renames to the final path, so an interrupted write never leaves a partial
/// file.
pub fn write_metrics_file(
    registry: &MetricsRegistry,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let tmp_path = dir.join(format!(
        ".metrics_tmp_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    ));
    let text = registry.to_openmetrics_text();
    {
        let mut f = std::fs::File::create(&tmp_path)
            .map_err(|e| anyhow::anyhow!("Failed to create metrics temp file: {e}"))?;
        f.write_all(text.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to write metrics: {e}"))?;
    }
    std::fs::rename(&tmp_path, path)
        .map_err(|e| anyhow::anyhow!("Failed to rename metrics file: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Snapshot test: the OpenMetrics output must be deterministic for the
    /// same sequence of recorded events.
    #[test]
    fn snapshot_empty_registry() {
        let reg = MetricsRegistry::default();
        let text = reg.to_openmetrics_text();
        // Must contain the mandatory # EOF marker
        assert!(text.ends_with("# EOF\n"), "missing # EOF: {text:?}");
        // Must not be empty
        assert!(!text.is_empty());
    }

    #[test]
    fn snapshot_deterministic() {
        let reg = MetricsRegistry::default();
        reg.pairs_total.increment();
        reg.pairs_success.increment();
        reg.findings.record(
            SeverityLabel::Critical,
            AxisLabel::StorageLayout,
            OutcomeLabel::Active,
        );
        reg.duration_loading_seconds
            .record(Duration::from_millis(42));
        reg.cache_hits.increment();
        reg.rpc_attempts_success.increment();
        reg.set_mode(ModeLabel::Single);
        reg.wasm_bytes_old.set(1234);
        reg.wasm_bytes_new.set(5678);

        let a = reg.to_openmetrics_text();
        let b = reg.to_openmetrics_text();
        assert_eq!(a, b, "output must be deterministic");
    }

    /// Cardinality test: the finding counter matrix has at most
    /// severity (3) * axis (5) * outcome (3) = 45 time series.
    #[test]
    fn cardinality_bounded() {
        let reg = MetricsRegistry::default();
        let mut unique_lines = std::collections::HashSet::new();
        // Record one of every combination
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
        for line in text.lines() {
            if line.starts_with("soroban_safeguard_findings_total{") {
                unique_lines.insert(line.to_string());
            }
        }
        // Exactly 3 * 5 * 3 = 45 time series
        assert_eq!(
            unique_lines.len(),
            45,
            "expected 45 finding time series, got {}",
            unique_lines.len()
        );
    }

    /// Sanitization test: no user data (URLs, IDs, paths, messages) appears
    /// in label positions.
    #[test]
    fn no_user_data_in_labels() {
        let reg = MetricsRegistry::default();
        reg.set_mode(ModeLabel::Single);
        reg.findings.record(
            SeverityLabel::Critical,
            AxisLabel::StorageLayout,
            OutcomeLabel::Active,
        );
        let text = reg.to_openmetrics_text();
        // These strings must never appear in the output
        let forbidden = [
            "CABCD1234",
            "https://soroban-testnet.stellar.org",
            "/home/user/contract.wasm",
            "Struct Field Removed",
        ];
        for s in &forbidden {
            assert!(
                !text.contains(s),
                "user data leaked into metrics: {s:?} found in output"
            );
        }
    }

    #[test]
    fn counter_increments() {
        let c = Counter::new();
        assert_eq!(c.get(), 0);
        c.increment();
        c.increment();
        assert_eq!(c.get(), 2);
        c.add(10);
        assert_eq!(c.get(), 12);
    }

    #[test]
    fn gauge_set_get() {
        let g = Gauge::new();
        g.set(42);
        assert_eq!(g.get(), 42);
    }

    #[test]
    fn duration_metric_accumulates() {
        let d = DurationMetric::new();
        d.record(Duration::from_millis(100));
        d.record(Duration::from_millis(200));
        assert_eq!(d.count(), 2);
        let total = d.total_seconds();
        assert!((total - 0.3).abs() < 1e-6, "expected ~0.3s, got {total}");
    }

    #[test]
    fn write_metrics_file_creates_valid_output() {
        use std::fs;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("test_metrics_{}.txt", std::process::id()));
        let reg = MetricsRegistry::default();
        reg.pairs_total.increment();
        write_metrics_file(&reg, &path).expect("write should succeed");
        let content = fs::read_to_string(&path).expect("file should be readable");
        assert!(content.contains("soroban_safeguard_pairs_total"));
        assert!(content.ends_with("# EOF\n"));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn record_verdict_increments_pairs() {
        let reg = MetricsRegistry::default();
        reg.record_verdict(VerdictLabel::Safe);
        assert_eq!(reg.pairs_total.get(), 1);
        assert_eq!(reg.pairs_success.get(), 1);
        assert_eq!(reg.pairs_error.get(), 0);

        reg.record_verdict(VerdictLabel::Error);
        assert_eq!(reg.pairs_total.get(), 2);
        assert_eq!(reg.pairs_success.get(), 1);
        assert_eq!(reg.pairs_error.get(), 1);
    }

    #[test]
    fn rpc_result_counters() {
        let reg = MetricsRegistry::default();
        reg.record_rpc_result(RpcResultLabel::Success);
        reg.record_rpc_result(RpcResultLabel::Timeout);
        reg.record_rpc_result(RpcResultLabel::HashMismatch);
        assert_eq!(reg.rpc_attempts_success.get(), 1);
        assert_eq!(reg.rpc_attempts_timeout.get(), 1);
        assert_eq!(reg.rpc_attempts_hash_mismatch.get(), 1);
        assert_eq!(reg.rpc_attempts_transport_error.get(), 0);
        assert_eq!(reg.rpc_attempts_protocol_error.get(), 0);
    }

    #[test]
    fn cache_result_counters() {
        let reg = MetricsRegistry::default();
        reg.record_cache_result(CacheResultLabel::Hit);
        reg.record_cache_result(CacheResultLabel::Hit);
        reg.record_cache_result(CacheResultLabel::Miss);
        assert_eq!(reg.cache_hits.get(), 2);
        assert_eq!(reg.cache_misses.get(), 1);
        assert_eq!(reg.cache_invalidations.get(), 0);
    }
}

//! JSON Lines (JSONL) streaming batch protocol.
//!
//! Reads one versioned JSON job per line from standard input and writes one
//! versioned JSON result per line to standard output. Each job carries a
//! caller-provided identifier, structured input descriptors, and optional
//! analysis overrides.
//!
//! # Job Schema (`schema_version: 1`)
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "id": "job-42",
//!   "old": { "local": "/path/to/old.wasm" },
//!   "new": { "local": "/path/to/new.wasm" },
//!   "overrides": { "strict": true }
//! }
//! ```
//!
//! # Result Schema (`schema_version: 1`)
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "id": "job-42",
//!   "status": "success",
//!   "report": { ... },
//!   "elapsed_ms": 123
//! }
//! ```
//!
//! # Input Descriptors
//!
//! Every `old` / `new` field is an **input descriptor** — a single-key object
//! choosing exactly one source:
//!
//! | Key        | Example                                          |
//! |------------|--------------------------------------------------|
//! | `local`    | `{ "local": "/path/to/file.wasm" }`              |
//! | `rpc`      | `{ "rpc": { "url": "...", "contract_id": "C…" } }`|
//! | `hash`     | `{ "hash": { "path": "...", "sha256": "hex…" } }`|
//! | `extracted`| `{ "extracted": "/path/to/spec.json" }`          |
//! | `remote`   | `{ "remote": "https://…#sha256=hex" }`            |

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::loader;
use crate::remote::RemoteFetchConfig;
use crate::rpc::RpcClientConfig;
use crate::suppression::SuppressionConfig;

/// Protocol schema version. Bump when the wire format changes in a
/// backwards-incompatible way.
pub const SCHEMA_VERSION: u32 = 1;

// ── Job schema ───────────────────────────────────────────────────────────────

/// A single streaming job read from one line of stdin.
#[derive(Debug, Deserialize, Serialize)]
pub struct StreamingJob {
    /// Schema version; currently always `1`.
    pub schema_version: u32,
    /// Caller-provided unique identifier for this job.
    pub id: String,
    /// Input descriptor for the old (pre-upgrade) WASM.
    pub old: InputDescriptor,
    /// Input descriptor for the new (post-upgrade) WASM.
    pub new: InputDescriptor,
    /// Optional analysis overrides.
    #[serde(default)]
    pub overrides: JobOverrides,
}

/// Allowed analysis overrides for a single job.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct JobOverrides {
    /// Treat warnings as errors (mirrors `--strict`).
    #[serde(default)]
    pub strict: bool,
    /// Print remediation guidance (mirrors `--explain`).
    #[serde(default)]
    pub explain: bool,
    /// Use ASCII markers instead of emoji.
    #[serde(default)]
    pub ascii: bool,
    /// Run empirical storage validation.
    #[serde(default)]
    pub empirical: bool,
    /// Path to a suppression config to use for this job.
    #[serde(default)]
    pub suppression_config: Option<String>,
}

// ── Input descriptors ────────────────────────────────────────────────────────

/// A single-key object describing where to load a WASM from.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputDescriptor {
    /// Read a local file path.
    Local(String),
    /// Fetch from Stellar RPC.
    Rpc(RpcInput),
    /// Verify a file against an expected SHA-256 hash.
    Hash(HashInput),
    /// Load an extracted-spec JSON file (old side only in diff mode).
    Extracted(String),
    /// Fetch from an `https://` URL with a pinned digest.
    Remote(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcInput {
    /// Stellar RPC endpoint URL.
    pub url: String,
    /// Contract identifier on-chain (e.g. `C...`).
    pub contract_id: String,
    /// Optional extra headers as `NAME=VALUE` pairs.
    #[serde(default)]
    pub headers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HashInput {
    /// File path to read.
    pub path: String,
    /// Expected lowercase hex SHA-256 digest.
    pub sha256: String,
}

// ── Result schema ────────────────────────────────────────────────────────────

/// Status of a processed streaming job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// The job was processed and a report was produced.
    Success,
    /// Input loading or WASM parsing failed; the error is described in
    /// `error`.
    Failure,
    /// The job identifier was a duplicate and was skipped.
    Duplicate,
    /// The job line was malformed JSON or violated the schema.
    Malformed,
}

/// A result record written to stdout, exactly one per accepted `id`.
#[derive(Debug, Serialize)]
pub struct StreamingResult {
    /// Schema version, always [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Echoed from the corresponding [`StreamingJob::id`].
    pub id: String,
    /// Processing outcome.
    pub status: JobStatus,
    /// The rendered safety report (present on `success`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<serde_json::Value>,
    /// Human-readable error string (present on `failure`, `duplicate`,
    /// or `malformed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Wall-clock processing time in milliseconds.
    pub elapsed_ms: u64,
}

// ── Streaming runner ─────────────────────────────────────────────────────────

/// Ordering policy for output results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputOrder {
    /// Emit results as soon as each job completes (completion order).
    #[default]
    CompletionOrder,
    /// Buffer results and emit them in the same order the jobs appeared on
    /// stdin (input order).
    InputOrder,
}

/// Configuration for the streaming runner.
#[derive(Debug)]
pub struct StreamConfig {
    /// Maximum number of concurrent worker threads.
    pub concurrency: usize,
    /// Whether to preserve input order in the output.
    pub output_order: OutputOrder,
    /// Apply strict mode globally (jobs may override).
    pub strict: bool,
    /// Global suppressions to apply unless a job provides its own config.
    pub suppressions: SuppressionConfig,
    /// Do not load .safeguard.toml automatically.
    pub no_config: bool,
    /// Timeout for remote/OCI downloads per job.
    pub remote_max_bytes: usize,
    pub remote_timeout_secs: u64,
    pub remote_max_redirects: u32,
    pub oci_max_bytes: usize,
    pub oci_timeout_secs: u64,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            concurrency: 4,
            output_order: OutputOrder::default(),
            strict: false,
            suppressions: SuppressionConfig::default(),
            no_config: false,
            remote_max_bytes: crate::remote::DEFAULT_MAX_BYTES,
            remote_timeout_secs: crate::remote::DEFAULT_TIMEOUT_SECS,
            remote_max_redirects: crate::remote::DEFAULT_MAX_REDIRECTS,
            oci_max_bytes: crate::oci::DEFAULT_MAX_BYTES,
            oci_timeout_secs: crate::oci::DEFAULT_TIMEOUT_SECS,
        }
    }
}

/// Run the streaming JSONL protocol.
///
/// Reads jobs from `reader` (typically stdin), processes them with bounded
/// concurrency, and writes results to `writer` (typically stdout). All
/// diagnostic messages are written to `stderr`.
pub fn run_streaming<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    config: &StreamConfig,
) -> Result<()> {
    let buf_reader = BufReader::new(reader);
    let (job_tx, job_rx) = mpsc::channel::<StreamJobMessage>();
    let (result_tx, result_rx) = mpsc::channel::<IndexedResult>();
    let num_workers = config.concurrency.max(1);

    // Share the job receiver across workers via Arc<Mutex<…>> so that each
    // worker can compete to receive the next job.
    let shared_rx = Arc::new(Mutex::new(job_rx));

    // Spawn worker threads.
    let mut worker_handles = Vec::with_capacity(num_workers);
    for worker_id in 0..num_workers {
        let rx = Arc::clone(&shared_rx);
        let tx = result_tx.clone();
        let suppressions = config.suppressions.clone();
        let no_config = config.no_config;
        let strict = config.strict;
        let remote_max_bytes = config.remote_max_bytes;
        let remote_timeout_secs = config.remote_timeout_secs;
        let remote_max_redirects = config.remote_max_redirects;
        let oci_max_bytes = config.oci_max_bytes;
        let oci_timeout_secs = config.oci_timeout_secs;
        let handle = std::thread::spawn(move || {
            loop {
                // Lock the shared receiver, take a message, then drop the
                // lock so other workers can receive concurrently.
                let msg = {
                    let guard = rx.lock().expect("job receiver lock poisoned");
                    guard.recv()
                };
                match msg {
                    Ok(msg) => {
                        if msg.is_cancel() {
                            break;
                        }
                        let result = process_job(
                            &msg.job,
                            msg.slot_index,
                            strict,
                            &suppressions,
                            no_config,
                            remote_max_bytes,
                            remote_timeout_secs,
                            remote_max_redirects,
                            oci_max_bytes,
                            oci_timeout_secs,
                        );
                        let _ = tx.send(result);
                    }
                    Err(_) => break, // channel closed
                }
            }
            drop(tx);
            eprintln!("[stream] worker {worker_id} exiting");
        });
        worker_handles.push(handle);
    }
    // Drop our copy so workers can detect when all senders are gone.
    drop(result_tx);
    // Drop the Arc so the Mutex is released when all workers are done.
    drop(shared_rx);

    // Writer thread: collects results and writes to stdout in the correct
    // order.  Runs in the main thread when input-order is not requested so
    // that stdout writes stay synchronous with the caller's expectations.
    let output_order = config.output_order;

    // Read and dispatch jobs.
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut pending_order: Vec<Option<StreamingResult>> = Vec::new();
    let mut jobs_sent = 0u64;
    let mut line_no: u64 = 0;

    for line_result in buf_reader.lines() {
        line_no += 1;
        let line =
            line_result.with_context(|| format!("I/O error reading line {line_no} from stdin"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // ── Parse the line ─────────────────────────────────────────────
        let job: StreamingJob = match serde_json::from_str(trimmed) {
            Ok(j) => j,
            Err(e) => {
                // Emit a malformed-line result immediately with a synthetic id.
                let synthetic_id = format!("__line_{line_no}");
                let result = StreamingResult {
                    schema_version: SCHEMA_VERSION,
                    id: synthetic_id,
                    status: JobStatus::Malformed,
                    report: None,
                    error: Some(format!("Line {line_no}: invalid JSON — {e}")),
                    elapsed_ms: 0,
                };
                if output_order == OutputOrder::InputOrder {
                    pending_order.push(Some(result));
                } else {
                    write_result(&mut writer, &result)?;
                }
                continue;
            }
        };

        // ── Validate schema version ────────────────────────────────────
        if job.schema_version != SCHEMA_VERSION {
            let result = StreamingResult {
                schema_version: SCHEMA_VERSION,
                id: job.id.clone(),
                status: JobStatus::Malformed,
                report: None,
                error: Some(format!(
                    "Unsupported schema_version {} (expected {SCHEMA_VERSION})",
                    job.schema_version
                )),
                elapsed_ms: 0,
            };
            if output_order == OutputOrder::InputOrder {
                pending_order.push(Some(result));
            } else {
                write_result(&mut writer, &result)?;
            }
            continue;
        }

        // ── Duplicate-id check ─────────────────────────────────────────
        if !seen_ids.insert(job.id.clone()) {
            let result = StreamingResult {
                schema_version: SCHEMA_VERSION,
                id: job.id.clone(),
                status: JobStatus::Duplicate,
                report: None,
                error: Some(format!("Duplicate job id '{}'", job.id)),
                elapsed_ms: 0,
            };
            if output_order == OutputOrder::InputOrder {
                pending_order.push(Some(result));
            } else {
                write_result(&mut writer, &result)?;
            }
            continue;
        }

        // ── Enqueue for a worker ───────────────────────────────────────
        if output_order == OutputOrder::InputOrder {
            pending_order.push(None); // placeholder
            let slot_index = pending_order.len() - 1;
            let job_msg = StreamJobMessage {
                job,
                slot_index: Some(slot_index),
            };
            jobs_sent += 1;
            if job_tx.send(job_msg).is_err() {
                break; // all workers exited unexpectedly
            }
        } else {
            let job_msg = StreamJobMessage {
                job,
                slot_index: None,
            };
            jobs_sent += 1;
            if job_tx.send(job_msg).is_err() {
                break;
            }
        }
    }

    // Signal workers to shut down and wait for them.
    for _ in 0..num_workers {
        let _ = job_tx.send(StreamJobMessage::cancel());
    }
    drop(job_tx);

    // ── Collect results and write ────────────────────────────────────────
    if output_order == OutputOrder::InputOrder {
        // Drain the result channel and slot results into the ordered vec.
        let mut received = 0u64;
        while let Ok(result) = result_rx.recv() {
            if let Some(slot) = result.slot_index {
                if slot < pending_order.len() {
                    pending_order[slot] = Some(result.into_inner());
                }
            } else {
                // shouldn't happen in input-order mode, but be safe
                pending_order.push(Some(result.into_inner()));
            }
            received += 1;
            if received >= jobs_sent {
                break;
            }
        }
        // Write everything in order.
        for slot in pending_order.iter_mut() {
            if let Some(result) = slot.take() {
                write_result(&mut writer, &result)?;
            }
        }
    } else {
        // Drain remaining results (workers may still be finishing).
        for result in result_rx {
            write_result(&mut writer, &result.into_inner())?;
        }
    }

    // Wait for all workers to join.
    for handle in worker_handles {
        let _ = handle.join();
    }

    Ok(())
}

// ── Internal types ───────────────────────────────────────────────────────────

/// Message sent to a worker thread.
struct StreamJobMessage {
    job: StreamingJob,
    /// When `Some`, the result must be placed at this index in the ordered
    /// output buffer.
    slot_index: Option<usize>,
}

impl StreamJobMessage {
    /// Create a cancellation sentinel (an empty job with a synthetic id).
    fn cancel() -> Self {
        Self {
            job: StreamingJob {
                schema_version: SCHEMA_VERSION,
                id: String::new(),
                old: InputDescriptor::Local(String::new()),
                new: InputDescriptor::Local(String::new()),
                overrides: JobOverrides::default(),
            },
            slot_index: None,
        }
    }

    fn is_cancel(&self) -> bool {
        self.job.id.is_empty() && self.slot_index.is_none()
    }
}

/// Envelope that carries both the result and its position index.
struct IndexedResult {
    result: StreamingResult,
    slot_index: Option<usize>,
}

impl IndexedResult {
    fn into_inner(self) -> StreamingResult {
        self.result
    }
}

impl std::ops::Deref for IndexedResult {
    type Target = StreamingResult;
    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

// ── Job processing ───────────────────────────────────────────────────────────

/// Process a single job on a worker thread.
#[allow(clippy::too_many_arguments)]
fn process_job(
    job: &StreamingJob,
    slot_index: Option<usize>,
    global_strict: bool,
    global_suppressions: &SuppressionConfig,
    global_no_config: bool,
    remote_max_bytes: usize,
    remote_timeout_secs: u64,
    remote_max_redirects: u32,
    oci_max_bytes: usize,
    oci_timeout_secs: u64,
) -> IndexedResult {
    let start = Instant::now();

    // Merge suppressions: use job-level config if provided, otherwise
    // the global suppressions.
    let suppressions = if let Some(ref config_path) = job.overrides.suppression_config {
        match SuppressionConfig::load_from_path(std::path::Path::new(config_path)) {
            Ok(s) => s,
            Err(e) => {
                return IndexedResult {
                    result: StreamingResult {
                        schema_version: SCHEMA_VERSION,
                        id: job.id.clone(),
                        status: JobStatus::Failure,
                        report: None,
                        error: Some(format!("Failed to load suppression config: {e}")),
                        elapsed_ms: start.elapsed().as_millis() as u64,
                    },
                    slot_index,
                };
            }
        }
    } else if global_no_config {
        SuppressionConfig::default()
    } else {
        global_suppressions.clone()
    };

    let strict = job.overrides.strict || global_strict;

    // Build remote/OCI configs.
    let remote_config = RemoteFetchConfig {
        max_bytes: remote_max_bytes,
        timeout: Duration::from_secs(remote_timeout_secs),
        max_redirects: remote_max_redirects,
        cache_dir: None,
        no_cache: false,
        https_only: true,
    };
    let oci_config = crate::oci::OciFetchConfig {
        max_bytes: oci_max_bytes,
        timeout: Duration::from_secs(oci_timeout_secs),
        cache_dir: None,
        no_cache: false,
        https_only: true,
        allow_tags: false,
    };

    // Resolve inputs.
    let progress = |line: String| {
        eprintln!("[stream] {}", line);
    };

    let old_module = match resolve_input(&job.old, &remote_config, &oci_config, &progress) {
        Ok(m) => m,
        Err(e) => {
            return IndexedResult {
                result: StreamingResult {
                    schema_version: SCHEMA_VERSION,
                    id: job.id.clone(),
                    status: JobStatus::Failure,
                    report: None,
                    error: Some(format!("Failed to load old input: {e}")),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                },
                slot_index,
            };
        }
    };

    let new_module = match resolve_input(&job.new, &remote_config, &oci_config, &progress) {
        Ok(m) => m,
        Err(e) => {
            return IndexedResult {
                result: StreamingResult {
                    schema_version: SCHEMA_VERSION,
                    id: job.id.clone(),
                    status: JobStatus::Failure,
                    report: None,
                    error: Some(format!("Failed to load new input: {e}")),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                },
                slot_index,
            };
        }
    };

    // Run comparison.
    match crate::compare_wasm_bytes_with_options(
        &old_module.bytes,
        &new_module.bytes,
        &crate::CompareOptions {
            suppressions: Some(&suppressions),
            explain: job.overrides.explain,
            strict,
            storage_schemas: None,
            lineage_store: None,
            contract: None,
            complexity_budget: None,
        },
    ) {
        Ok(report) => {
            let report_json = report.to_json();
            IndexedResult {
                result: StreamingResult {
                    schema_version: SCHEMA_VERSION,
                    id: job.id.clone(),
                    status: JobStatus::Success,
                    report: Some(serde_json::to_value(&report_json).unwrap_or_default()),
                    error: None,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                },
                slot_index,
            }
        }
        Err(e) => IndexedResult {
            result: StreamingResult {
                schema_version: SCHEMA_VERSION,
                id: job.id.clone(),
                status: JobStatus::Failure,
                report: None,
                error: Some(format!("Analysis failed: {e}")),
                elapsed_ms: start.elapsed().as_millis() as u64,
            },
            slot_index,
        },
    }
}

/// Resolve an [`InputDescriptor`] into a [`loader::WasmModule`].
fn resolve_input(
    descriptor: &InputDescriptor,
    remote_config: &RemoteFetchConfig,
    _oci_config: &crate::oci::OciFetchConfig,
    progress: &dyn Fn(String),
) -> Result<loader::WasmModule> {
    match descriptor {
        InputDescriptor::Local(path) => {
            let p = std::path::Path::new(path);
            loader::load_wasm(p).map_err(|e| anyhow::anyhow!("{e}"))
        }
        InputDescriptor::Rpc(rpc) => {
            let mut config =
                RpcClientConfig::new(rpc.url.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
            for header in &rpc.headers {
                let (name, env_var) = header.split_once('=').ok_or_else(|| {
                    anyhow::anyhow!("Invalid rpc header '{header}'; expected NAME=ENV_VAR")
                })?;
                config = config
                    .with_env_header(name.to_string(), env_var.to_string())
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            loader::fetch_wasm_from_rpc_with_config(&rpc.contract_id, &config)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        InputDescriptor::Hash(h) => {
            let p = std::path::Path::new(&h.path);
            let module = loader::load_wasm(p).map_err(|e| anyhow::anyhow!("{e}"))?;
            let expected = h.sha256.to_lowercase();
            if module.sha256 != expected {
                anyhow::bail!(
                    "SHA-256 mismatch for '{}': expected {}, got {}",
                    h.path,
                    expected,
                    module.sha256
                );
            }
            Ok(module)
        }
        InputDescriptor::Extracted(path) => {
            // Treat extracted-spec paths as local file loads — the caller is
            // providing an already-extracted spec rather than a WASM binary.
            // For the streaming protocol we accept it as a WASM path for
            // compatibility; the actual spec extraction happens downstream.
            let p = std::path::Path::new(path);
            loader::load_wasm(p).map_err(|e| anyhow::anyhow!("{e}"))
        }
        InputDescriptor::Remote(url) => {
            let remote_ref = crate::remote::RemoteRef::parse(url)
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .ok_or_else(|| anyhow::anyhow!("'{}' is not a valid remote reference", url))?;
            let (module, artifact) = loader::load_wasm_from_url(&remote_ref, remote_config)?;
            progress(format!(
                "🌐 Remote: {} (sha256:{})",
                artifact.final_url, artifact.sha256
            ));
            Ok(module)
        }
    }
}

// ── Output helpers ───────────────────────────────────────────────────────────

/// Write a single result as one JSON line to the writer.
fn write_result(writer: &mut impl Write, result: &StreamingResult) -> Result<()> {
    let mut line = serde_json::to_string(result).context("Failed to serialize streaming result")?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .context("Failed to write streaming result")?;
    writer.flush().context("Failed to flush streaming output")?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_job_json() {
        let job = StreamingJob {
            schema_version: 1,
            id: "test-1".into(),
            old: InputDescriptor::Local("/tmp/old.wasm".into()),
            new: InputDescriptor::Local("/tmp/new.wasm".into()),
            overrides: JobOverrides::default(),
        };
        let json = serde_json::to_string(&job).unwrap();
        let back: StreamingJob = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "test-1");
        assert_eq!(back.schema_version, 1);
    }

    #[test]
    fn round_trip_result_json() {
        let result = StreamingResult {
            schema_version: 1,
            id: "test-1".into(),
            status: JobStatus::Success,
            report: Some(serde_json::json!({"is_safe": true})),
            error: None,
            elapsed_ms: 42,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "test-1");
        assert_eq!(parsed["status"], "success");
        assert_eq!(parsed["elapsed_ms"], 42);
        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn result_omits_none_fields() {
        let result = StreamingResult {
            schema_version: 1,
            id: "x".into(),
            status: JobStatus::Failure,
            report: None,
            error: Some("bad".into()),
            elapsed_ms: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("report"));
        assert!(json.contains("error"));
    }

    #[test]
    fn input_descriptor_deserialize() {
        let json = r#"{"local": "/tmp/a.wasm"}"#;
        let desc: InputDescriptor = serde_json::from_str(json).unwrap();
        match desc {
            InputDescriptor::Local(p) => assert_eq!(p, "/tmp/a.wasm"),
            _ => panic!("expected Local variant"),
        }
    }

    #[test]
    fn input_descriptor_rpc() {
        let json = r#"{"rpc": {"url": "https://rpc.example.com", "contract_id": "CABC..."}}"#;
        let desc: InputDescriptor = serde_json::from_str(json).unwrap();
        match desc {
            InputDescriptor::Rpc(rpc) => {
                assert_eq!(rpc.url, "https://rpc.example.com");
                assert_eq!(rpc.contract_id, "CABC...");
            }
            _ => panic!("expected Rpc variant"),
        }
    }

    #[test]
    fn input_descriptor_hash() {
        let json = r#"{"hash": {"path": "/tmp/b.wasm", "sha256": "abcdef1234"}}"#;
        let desc: InputDescriptor = serde_json::from_str(json).unwrap();
        match desc {
            InputDescriptor::Hash(h) => {
                assert_eq!(h.path, "/tmp/b.wasm");
                assert_eq!(h.sha256, "abcdef1234");
            }
            _ => panic!("expected Hash variant"),
        }
    }

    #[test]
    fn input_descriptor_remote() {
        let json = r#"{"remote": "https://example.com/module.wasm#sha256=deadbeef"}"#;
        let desc: InputDescriptor = serde_json::from_str(json).unwrap();
        match desc {
            InputDescriptor::Remote(url) => {
                assert!(url.contains("sha256=deadbeef"));
            }
            _ => panic!("expected Remote variant"),
        }
    }

    #[test]
    fn job_overrides_defaults() {
        let json = r#"{"schema_version":1,"id":"a","old":{"local":"x"},"new":{"local":"y"}}"#;
        let job: StreamingJob = serde_json::from_str(json).unwrap();
        assert!(!job.overrides.strict);
        assert!(!job.overrides.explain);
        assert!(!job.overrides.ascii);
        assert!(!job.overrides.empirical);
        assert!(job.overrides.suppression_config.is_none());
    }

    #[test]
    fn malformed_json_yields_malformed_result() {
        let mut input = b"not json\n".as_slice();
        let mut output = Vec::new();

        let config = StreamConfig::default();
        run_streaming(&mut input, &mut output, &config).unwrap();

        let out_str = String::from_utf8(output).unwrap();
        let result: serde_json::Value = serde_json::from_str(out_str.trim()).unwrap();
        assert_eq!(result["status"], "malformed");
        assert_eq!(result["schema_version"], SCHEMA_VERSION);
    }

    #[test]
    fn empty_input_produces_no_output() {
        let input = b"\n\n\n";
        let mut output = Vec::new();
        let config = StreamConfig::default();
        run_streaming(input.as_slice(), &mut output, &config).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn duplicate_id_detected() {
        let job = StreamingJob {
            schema_version: 1,
            id: "dup".into(),
            old: InputDescriptor::Local("x".into()),
            new: InputDescriptor::Local("y".into()),
            overrides: JobOverrides::default(),
        };
        let line = serde_json::to_string(&job).unwrap();
        let input = format!("{line}\n{line}\n");
        let mut output = Vec::new();

        let config = StreamConfig::default();
        run_streaming(input.as_bytes(), &mut output, &config).unwrap();

        let out_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = out_str.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        // In completion order the duplicate is detected and emitted inline
        // during line reading, before the worker finishes the first job.
        let mut has_failure = false;
        let mut has_duplicate = false;
        for l in &lines {
            let val: serde_json::Value = serde_json::from_str(l).unwrap();
            match val["status"].as_str() {
                Some("failure") => has_failure = true,
                Some("duplicate") => has_duplicate = true,
                other => panic!("unexpected status: {other:?}"),
            }
        }
        assert!(
            has_failure,
            "expected a failure result for the non-existent file"
        );
        assert!(
            has_duplicate,
            "expected a duplicate result for the repeated id"
        );
    }

    #[test]
    fn schema_version_mismatch_detected() {
        let json = r#"{"schema_version":99,"id":"bad","old":{"local":"x"},"new":{"local":"y"}}"#;
        let mut output = Vec::new();
        let config = StreamConfig::default();
        run_streaming(json.as_bytes(), &mut output, &config).unwrap();

        let out_str = String::from_utf8(output).unwrap();
        let result: serde_json::Value = serde_json::from_str(out_str.trim()).unwrap();
        assert_eq!(result["status"], "malformed");
        assert!(result["error"]
            .as_str()
            .unwrap()
            .contains("Unsupported schema_version"));
    }
}

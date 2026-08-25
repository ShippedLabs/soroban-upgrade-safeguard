use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::Colorize;
use rayon::prelude::*;
use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use soroban_upgrade_safeguard::{
    color::should_disable_color,
    dependency::{
        cycle_findings, missing_contract_findings, ContractDependency, CrossContractFinding,
        DependencyGraph,
    },
    limits::{find_limit_error, LimitsConfig, ResourcePolicy},
    loader, report,
    report::{validate_categories, CategoryFilter},
    storage_schema::StorageSchema,
    suppression::{SuppressionConfig, DEFAULT_CONFIG_FILE},
    CompareOptions,
};

/// Output format for the safety report.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum OutputFormat {
    /// Colored, human-readable report (default).
    #[default]
    Text,
    /// A single machine-readable JSON document for CI and dashboards.
    Json,
    /// Markdown document suitable for PR descriptions and comments.
    Markdown,
    /// GitHub Actions workflow commands so findings appear as annotations in
    /// the run summary and pull-request checks.
    GithubActions,
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = None,
    // Four usage modes:
    //   1. Local:      soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]
    //   2. RPC:        soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]
    //   3. Manifest:   soroban-upgrade-safeguard --manifest <MANIFEST_PATH> [OPTIONS]
    //   4. Dir Scan:   soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR> [OPTIONS]
    override_usage = "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --manifest <MANIFEST_PATH> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR> [OPTIONS]"
)]
struct Args {
    /// WASM paths: <OLD_WASM> <NEW_WASM> in local mode, or just <NEW_WASM> in RPC mode
    #[arg(value_name = "WASM", num_args = 0..=2)]
    wasm_paths: Vec<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Stellar/Soroban Contract ID to fetch from on-chain (e.g. C...)
    #[arg(long, value_name = "CONTRACT_ID", requires = "rpc_url")]
    contract_id: Option<String>,

    /// Stellar RPC URL (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, value_name = "RPC_URL", requires = "contract_id")]
    rpc_url: Option<String>,

    /// Path to a suppression config acknowledging known, intentional breaking
    /// changes. When omitted, `.safeguard.toml` in the current directory is
    /// used if present; otherwise no suppressions are applied.
    #[arg(long, value_name = "CONFIG")]
    config: Option<PathBuf>,

    /// Print a concise remediation explanation for each finding.
    #[arg(long)]
    explain: bool,

    /// Exit with a non-zero code if any Warnings or Critical findings are found
    #[arg(long)]
    strict: bool,

    /// Do not color output
    #[arg(long)]
    no_color: bool,

    /// Allow HTTP connections for RPC when the host is localhost/127.0.0.1.
    /// Without this flag only HTTPS URLs are accepted.
    #[arg(long)]
    allow_http_local: bool,

    /// Expected SHA-256 hash (hex) of the on-chain WASM baseline.
    /// When provided the tool verifies the hash of the fetched bytecode
    /// matches this value and fails immediately on mismatch.
    #[arg(long, value_name = "HEX_HASH")]
    expected_wasm_hash: Option<String>,

    /// Path to a manifest file (TOML or JSON) containing contract pairs to compare
    #[arg(long, value_name = "MANIFEST_PATH")]
    manifest: Option<PathBuf>,

    /// Directory containing the old versions of the contracts for directory comparison
    #[arg(long, value_name = "OLD_DIR", requires = "new_dir")]
    old_dir: Option<PathBuf>,

    /// Directory containing the new versions of the contracts for directory comparison
    #[arg(long, value_name = "NEW_DIR", requires = "old_dir")]
    new_dir: Option<PathBuf>,

    /// Only include findings from these categories. Repeatable.
    #[arg(long, value_name = "CATEGORY", num_args = 0..)]
    include_category: Vec<String>,

    /// Exclude findings from these categories. Repeatable.
    #[arg(long, value_name = "CATEGORY", num_args = 0..)]
    exclude_category: Vec<String>,
    /// Storage-schema manifest describing the OLD build's storage layout.
    ///
    /// Declares the storage-key types and internal value types that govern
    /// on-chain compatibility but need not appear in the exported spec. Must be
    /// given together with --new-storage-schema: detecting a layout change
    /// requires both snapshots.
    #[arg(long, value_name = "PATH", requires = "new_storage_schema")]
    old_storage_schema: Option<PathBuf>,

    /// Storage-schema manifest describing the NEW build's storage layout.
    #[arg(long, value_name = "PATH", requires = "old_storage_schema")]
    new_storage_schema: Option<PathBuf>,

    /// Maximum XDR decode depth per entry. Overrides `[limits]` in the config
    /// file and the built-in default. Guards against stack-overflow inputs.
    #[arg(long, value_name = "N")]
    max_xdr_depth: Option<u32>,

    /// Maximum bytes decoded per WASM custom section. Overrides `[limits]` and
    /// the default. Guards against oversized-length allocation inputs.
    #[arg(long, value_name = "BYTES")]
    max_xdr_len: Option<usize>,

    /// Maximum decoded spec entries, summed across all sections. Overrides
    /// `[limits]` and the default.
    #[arg(long, value_name = "N")]
    max_entries: Option<usize>,

    /// Maximum recursive type-walk depth (equality, rendering, cascade
    /// detection). Overrides `[limits]` and the default.
    #[arg(long, value_name = "N")]
    max_walk_depth: Option<usize>,

    /// Treat identical duplicate spec entries (same name, byte-identical
    /// definition) as informational rather than warnings.
    ///
    /// This is a compatibility mode for toolchains that legitimately emit
    /// split contractspecv0 sections with identical entries (e.g., some
    /// SDK versions). Conflicting duplicates (different definitions) are
    /// always Critical regardless of this flag.
    #[arg(long)]
    compat_duplicates: bool,

    /// Write the report to this file instead of stdout.
    ///
    /// The file is created (or overwritten) only after the report has been
    /// successfully rendered, so a failed comparison never leaves a
    /// partial file behind. Progress output continues to go to its normal
    /// destination regardless of this flag.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

/// Resolve the effective [`ResourcePolicy`]: built-in defaults, overlaid by the
/// `[limits]` table in the config file, overlaid by any `--max-*` CLI flags
/// (flags win). `config_path` is the same file the suppression config is read
/// from, if any.
fn resolve_policy(args: &Args, config_path: Option<&Path>) -> Result<ResourcePolicy> {
    let mut policy = ResourcePolicy::default();

    if let Some(path) = config_path {
        if let Some(file_limits) = LimitsConfig::load_optional(path)? {
            policy = file_limits.apply_to(policy);
        }
    }

    // CLI flags take precedence over the file and defaults.
    if let Some(v) = args.max_xdr_depth {
        policy.max_xdr_depth = v;
    }
    if let Some(v) = args.max_xdr_len {
        policy.max_xdr_len = v;
    }
    if let Some(v) = args.max_entries {
        policy.max_entries = v;
    }
    if let Some(v) = args.max_walk_depth {
        policy.max_walk_depth = v;
    }

    Ok(policy)
}

/// Exit codes:
/// - `0`: safe (no breaking changes, or all suppressed).
/// - `1`: breaking changes detected, or a generic/IO/parse error.
/// - `2`: a resource-limit violation on untrusted input (distinct so CI can tell
///   "input was rejected as adversarial" apart from "the upgrade is unsafe").
fn main() {
    match run() {
        Ok(()) => {}
        Err(err) => {
            if let Some(limit_err) = find_limit_error(&err) {
                eprintln!("⛔ Resource limit exceeded: {limit_err}");
                eprintln!(
                    "   The input was rejected as potentially adversarial before it could \
                     exhaust memory or the stack."
                );
                eprintln!(
                    "   Raise the relevant limit via the [limits] table in .safeguard.toml or a \
                     --max-* flag (see README)."
                );
                std::process::exit(2);
            }
            // Preserve anyhow's full error-chain formatting for everything else.
            eprintln!("Error: {err:?}");
            std::process::exit(1);
        }
    }
}
/// Write `content` to a file if `output_path` is `Some`, otherwise print it
/// to stdout. Writing to a file is atomic: the full string is rendered before
/// any file is opened, so a failed comparison never leaves a partial file.
///
/// When a file path is used, a progress message is emitted via `progress` so
/// the user can see where the report landed.
fn emit_report_output(
    content: &str,
    output_path: Option<&std::path::Path>,
    progress: &impl Fn(String),
) -> Result<()> {
    if let Some(path) = output_path {
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write report to '{}'", path.display()))?;
        progress(format!("✅ Report written to: {}", path.display()));
    } else {
        println!("{}", content);
    }
    Ok(())
}

fn run() -> Result<()> {
    let args = Args::parse();

    if should_disable_color(
        args.no_color,
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    ) {
        colored::control::set_override(false);
    }

    // Validate category filter arguments before doing any real work.
    let all_categories: Vec<String> = args
        .include_category
        .iter()
        .chain(args.exclude_category.iter())
        .cloned()
        .collect();
    if !all_categories.is_empty() {
        if let Err(unknown) = validate_categories(&all_categories) {
            anyhow::bail!(
                "Unknown category name(s): {}. Valid categories are: {}",
                unknown.join(", "),
                report::KNOWN_CATEGORIES.join(", ")
            );
        }
    }
    let category_filter = CategoryFilter {
        include: if args.include_category.is_empty() {
            None
        } else {
            Some(args.include_category.iter().cloned().collect())
        },
        exclude: args.exclude_category.iter().cloned().collect(),
    };

    // 1. Identify which mode we are running:
    //    - Batch Manifest Mode
    //    - Batch Directory Mode
    //    - Single Contract Pair Mode
    let is_batch = args.manifest.is_some() || (args.old_dir.is_some() && args.new_dir.is_some());

    if args.manifest.is_some() && (args.old_dir.is_some() || args.new_dir.is_some()) {
        anyhow::bail!("Cannot specify both --manifest and --old-dir/--new-dir at the same time");
    }

    if is_batch && !args.wasm_paths.is_empty() {
        anyhow::bail!("Cannot specify positional WASM paths when using batch mode (--manifest or --old-dir/--new-dir)");
    }

    // A storage schema describes one specific contract's layout, so a single
    // pair of manifests cannot be applied across a batch of different
    // contracts. Refusing is better than silently analyzing the wrong layout.
    if is_batch && args.old_storage_schema.is_some() {
        anyhow::bail!(
            "--old-storage-schema/--new-storage-schema describe a single contract's storage \
             layout and cannot be used with batch mode. Run the pair on its own to analyze \
             storage layout."
        );
    }

    // Both manifests are loaded and validated up front so a malformed schema
    // fails before any comparison work is reported.
    let storage_schemas = match (&args.old_storage_schema, &args.new_storage_schema) {
        (Some(old), Some(new)) => Some((
            StorageSchema::load_from_path(old)?,
            StorageSchema::load_from_path(new)?,
        )),
        _ => None,
    };

    // In JSON or Markdown mode, decorative progress goes to stderr so stdout
    // stays a single, pristine document. An explicit output file also keeps
    // stdout empty in text mode: the report is in that file and all progress
    // belongs on stderr rather than alongside it.
    let clean_stdout = args.output.is_some()
        || args.format == OutputFormat::Json
        || args.format == OutputFormat::Markdown;
    let progress = |line: String| {
        if clean_stdout {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    // Load suppression config: an explicit --config must exist; otherwise fall
    // back to `.safeguard.toml` in the working directory if it happens to be
    // present. With neither, an empty config preserves today's behavior.
    //
    // SECURITY WARNING: Storing a suppression configuration file (`.safeguard.toml`)
    // in the current working directory is a security risk if the directory is writable
    // by untrusted actors (e.g. pull request contributors in CI environments). A contributor
    // could place/edit this file to neutralize Critical breaking change warnings.
    // Ensure changes to `.safeguard.toml` are strictly reviewed, or use the explicit
    // `--config` flag pointing to a trusted/read-only location in production pipelines.
    let suppressions = match &args.config {
        Some(path) => SuppressionConfig::load_from_path(path)?,
        None => {
            SuppressionConfig::load_optional(Path::new(DEFAULT_CONFIG_FILE))?.unwrap_or_default()
        }
    };

    // The resource-limit policy is read from the same file as the suppression
    // config (an explicit --config, else `.safeguard.toml` if present), then any
    // --max-* flags applied on top.
    let config_path: Option<PathBuf> = match &args.config {
        Some(path) => Some(path.clone()),
        None => {
            let default = Path::new(DEFAULT_CONFIG_FILE);
            default.exists().then(|| default.to_path_buf())
        }
    };
    let policy = resolve_policy(&args, config_path.as_deref())?;

    if is_batch {
        let (pairs, dep_declarations) = if let Some(manifest_path) = &args.manifest {
            parse_manifest(manifest_path)?
        } else {
            // Directory scan mode has no dependency declaration mechanism.
            let pairs = scan_directories(
                args.old_dir.as_ref().unwrap(),
                args.new_dir.as_ref().unwrap(),
            )?;
            (pairs, vec![])
        };

        progress("🔍 Soroban Upgrade Safeguard (Batch Mode)".to_string());
        progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());
        progress(format!("Loaded {} pair(s) for comparison.\n", pairs.len()));

        // Resolve a stable, unique display name for every pair *before* any
        // analysis runs. Two rules:
        //
        //  1. An explicit `name` that is duplicated across manifest entries is
        //     an error — the user wrote it deliberately, so a silent rename
        //     would be more confusing than failing early.
        //  2. A derived name (taken from the new WASM basename) that collides
        //     is disambiguated by appending " (2)", " (3)", … so both pairs
        //     appear in the output rather than one silently overwriting the
        //     other.
        let pair_names: Vec<String> = resolve_pair_names(&pairs)?;

        let mut results = std::collections::BTreeMap::new();
        let mut failed: std::collections::BTreeMap<String, PairFailure> =
            std::collections::BTreeMap::new();
        let mut overall_safe = true;
        let mut any_limit_violation = false;

        // Compare all pairs concurrently. Rayon bounds parallelism to the
        // available CPU count by default (override via RAYON_NUM_THREADS).
        //
        // Each pair's progress lines are captured into its own buffer rather
        // than written straight to stdout/stderr — concurrent writers would
        // interleave unrelated pairs' output. Buffers are flushed after the
        // parallel phase completes, one pair at a time, in original
        // manifest/scan order (not completion order): this keeps the printed
        // transcript exactly as readable as the old sequential version and
        // reproducible run-to-run regardless of which pair actually finished
        // first. The final report results are collected into a `BTreeMap`
        // keyed by contract name either way, so JSON/Markdown/text rendering
        // was already independent of completion order before this change.
        //
        // A panic partway through one pair's comparison is caught and
        // recorded as that pair's failure instead of unwinding across the
        // thread boundary and taking down every other in-flight pair with it.
        let pair_outcomes: Vec<(String, Vec<String>, Result<report::SafetyReport>)> = pairs
            .par_iter()
            .enumerate()
            .map(|(i, pair)| {
                let contract_name = pair_names[i].clone();
                let lines = std::cell::RefCell::new(Vec::new());
                let capture = |line: String| lines.borrow_mut().push(line);

                capture(format!(
                    "📦 [{}/{}] Comparing contract pair: {}",
                    i + 1,
                    pairs.len(),
                    contract_name.bold()
                ));

                // Per-pair policy: a pair that trips a resource limit, errors,
                // or panics fails only that pair — it must not abort the whole
                // batch, so its result is recorded and every other pair still
                // runs to completion.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || -> Result<report::SafetyReport> {
                        let old_wasm = loader::load_wasm(&pair.old)?;
                        let new_wasm = loader::load_wasm(&pair.new)?;
                        compare_contracts(
                            &ContractComparison {
                                old_bytes: &old_wasm.bytes,
                                old_path: &old_wasm.path,
                                new_bytes: &new_wasm.bytes,
                                new_path: &new_wasm.path,
                                suppressions: &suppressions,
                                policy: &policy,
                                // Storage schemas are contract-specific and
                                // rejected in batch mode, so no pair carries one.
                                storage_schemas: None,
                            },
                            &args,
                            &capture,
                        )
                    },
                ))
                .unwrap_or_else(|panic_payload| {
                    let message = panic_payload
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "panicked with a non-string payload".to_string());
                    Err(anyhow::anyhow!("Comparison panicked: {message}"))
                });

                (contract_name, lines.into_inner(), outcome)
            })
            .collect();

        for (contract_name, lines, outcome) in pair_outcomes {
            for line in lines {
                progress(line);
            }

            match outcome {
                Ok(mut report) => {
                    if !all_categories.is_empty() {
                        report.apply_category_filter(&category_filter);
                    }
                    if !report.is_safe {
                        overall_safe = false;
                    }
                    results.insert(contract_name, report);
                }
                Err(err) => {
                    overall_safe = false;
                    let limit = find_limit_error(&err);
                    let is_limit = limit.is_some();
                    if is_limit {
                        any_limit_violation = true;
                    }
                    let message = match limit {
                        Some(limit_err) => limit_err.to_string(),
                        None => format!("{err:#}"),
                    };
                    progress(format!(
                        "  {} {}",
                        if is_limit {
                            "⛔ Resource limit exceeded:".red().bold()
                        } else {
                            "⚠️  Failed:".red().bold()
                        },
                        message
                    ));
                    failed.insert(contract_name, PairFailure { message, is_limit });
                }
            }

            progress("\n----------------------------------------\n".to_string());
        }

        // ── Cross-contract dependency propagation ──────────────────────────
        // After all individual pairs have been analyzed, build the dependency
        // graph and propagate caller-visible breaking changes from callees to
        // every contract that depends on them.
        let dep_graph = DependencyGraph::from_declarations(&dep_declarations);

        // Detect and report cycles.
        let cycles = dep_graph.detect_cycles();
        let cycle_findings_list = cycle_findings(&cycles);
        if !cycle_findings_list.is_empty() {
            progress(format!(
                "\n⚠️  {} cyclic dependency/ies detected in the declared graph.",
                cycles.len()
            ));
            for f in &cycle_findings_list {
                progress(format!("   {}", f.message));
            }
            if args.strict {
                overall_safe = false;
            }
        }

        // Detect dependencies on contracts absent from this batch.
        let known_contracts: std::collections::HashSet<String> =
            results.keys().cloned().collect();
        let missing = dep_graph.missing_contracts(&known_contracts);
        let missing_findings_list = missing_contract_findings(&missing);
        if !missing_findings_list.is_empty() {
            progress(format!(
                "\n⚠️  {} dependency contract(s) not present in this batch:",
                missing.len()
            ));
            for name in &missing {
                progress(format!("   - {}", name));
            }
            overall_safe = false;
        }

        // Collect per-contract raw findings for propagation.
        let mut per_contract_findings: std::collections::HashMap<
            String,
            Vec<soroban_upgrade_safeguard::diff::Finding>,
        > = std::collections::HashMap::new();
        for (name, report) in &results {
            let all: Vec<_> = report
                .findings_by_category
                .values()
                .flat_map(|v| v.iter().map(|rf| rf.finding.clone()))
                .collect();
            per_contract_findings.insert(name.clone(), all);
        }

        let cross_findings: Vec<CrossContractFinding> =
            dep_graph.propagate(&per_contract_findings);

        // Cross-contract criticals always fail; warnings only fail under --strict.
        let cross_critical_count = cross_findings
            .iter()
            .filter(|f| {
                f.finding.severity == soroban_upgrade_safeguard::diff::Severity::Critical
            })
            .count();
        let cross_warning_count = cross_findings
            .iter()
            .filter(|f| {
                f.finding.severity == soroban_upgrade_safeguard::diff::Severity::Warning
            })
            .count();
        if cross_critical_count > 0 {
            overall_safe = false;
        }
        if args.strict && cross_warning_count > 0 {
            overall_safe = false;
        }

        if !cross_findings.is_empty() {
            progress(format!(
                "\n🔗 {} cross-contract finding(s) propagated from dependency analysis.",
                cross_findings.len()
            ));
        }

        match args.format {
            OutputFormat::Json => {
                let mut results_json = serde_json::Map::new();
                for (name, report) in &results {
                    results_json.insert(name.clone(), serde_json::to_value(report.to_json())?);
                }

                let mut failed_json = serde_json::Map::new();
                for (name, failure) in &failed {
                    failed_json.insert(
                        name.clone(),
                        serde_json::json!({
                            "error": failure.message,
                            "limit_violation": failure.is_limit,
                        }),
                    );
                }

                // Cross-contract findings grouped by affected contract.
                let mut cross_by_contract: serde_json::Map<String, serde_json::Value> =
                    serde_json::Map::new();
                for cf in &cross_findings {
                    cross_by_contract
                        .entry(cf.affected_contract.clone())
                        .or_insert_with(|| serde_json::json!([]))
                        .as_array_mut()
                        .unwrap()
                        .push(serde_json::to_value(cf)?);
                }

                let infra_findings: Vec<serde_json::Value> = cycle_findings_list
                    .iter()
                    .chain(missing_findings_list.iter())
                    .map(|f| serde_json::to_value(f))
                    .collect::<Result<_, _>>()?;

                // Overall recommended bump: the most severe bump across all
                // pairs in the batch, since batch mode compares a whole set
                // of contracts that ship together.
                let bump_rank = |bump: &str| match bump {
                    "major" => 2,
                    "minor" => 1,
                    _ => 0,
                };
                let overall_bump = results
                    .values()
                    .map(|report| report.recommended_bump())
                    .max_by_key(|bump| bump_rank(bump))
                    .unwrap_or("patch");

                let batch_json = serde_json::json!({
                    "is_safe": overall_safe,
                    "strict": args.strict,
                    "total_pairs": results.len() + failed.len(),
                    "limit_violation": any_limit_violation,
                    "recommended_bump": overall_bump,
                    "results": results_json,
                    "failed": failed_json,
                    "cross_contract_findings": cross_by_contract,
                    "dependency_findings": infra_findings,
                });

                let rendered = serde_json::to_string_pretty(&batch_json)?;
                emit_report_output(&rendered, args.output.as_deref(), &progress)?;
            }
            OutputFormat::Markdown => {
                let mut markdown = String::new();
                markdown.push_str("# Soroban Upgrade Safety Report (Batch Mode)\n\n");

                let status = if overall_safe {
                    "✅ PASSED (All contracts safe)"
                } else {
                    "❌ FAILED (Some contracts have breaking changes)"
                };
                markdown.push_str(&format!("## Status: {}\n\n", status));
                markdown.push_str("### Summary\n\n");
                markdown
                    .push_str("| Contract | Status | Critical | Warning | Info | Suppressed |\n");
                markdown.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

                for (name, report) in &results {
                    let status_str = if report.is_safe {
                        "✅ PASSED"
                    } else {
                        "❌ FAILED"
                    };
                    markdown.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} |\n",
                        name,
                        status_str,
                        report.critical_count,
                        report.warning_count,
                        report.info_count,
                        report.suppressed_count
                    ));
                }

                for (name, failure) in &failed {
                    let status_str = if failure.is_limit {
                        "⛔ ERROR (limit)"
                    } else {
                        "⛔ ERROR"
                    };
                    markdown.push_str(&format!("| {} | {} | — | — | — | — |\n", name, status_str));
                }

                markdown.push_str("\n---\n\n");

                if !failed.is_empty() {
                    markdown.push_str("### Errored Pairs\n\n");
                    for (name, failure) in &failed {
                        markdown.push_str(&format!("- **{}**: {}\n", name, failure.message));
                    }
                    markdown.push_str("\n---\n\n");
                }

                for (name, report) in &results {
                    markdown.push_str(&format!("## Details: {}\n\n", name));
                    let report_md = report.generate_summary_markdown();
                    let stripped_md = report_md.replace("# Soroban Upgrade Safety Report\n\n", "");
                    markdown.push_str(&stripped_md);
                    markdown.push_str("\n---\n\n");
                }

                if !cross_findings.is_empty() {
                    markdown.push_str("## Cross-Contract Dependency Findings\n\n");
                    markdown.push_str("| Affected Contract | Changed Contract | Depth | Severity | Category | Target |\n");
                    markdown.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
                    for cf in &cross_findings {
                        let sev = match cf.finding.severity {
                            soroban_upgrade_safeguard::diff::Severity::Critical => "🔴 Critical",
                            soroban_upgrade_safeguard::diff::Severity::Warning => "🟡 Warning",
                            soroban_upgrade_safeguard::diff::Severity::Info => "🔵 Info",
                        };
                        markdown.push_str(&format!(
                            "| {} | {} | {} | {} | {} | {} |\n",
                            cf.affected_contract,
                            cf.changed_contract,
                            cf.propagation_depth,
                            sev,
                            cf.finding.category,
                            cf.finding.target.as_deref().unwrap_or("-")
                        ));
                    }
                    markdown.push_str("\n---\n\n");
                }

                if !cycle_findings_list.is_empty() || !missing_findings_list.is_empty() {
                    markdown.push_str("## Dependency Graph Findings\n\n");
                    for f in cycle_findings_list
                        .iter()
                        .chain(missing_findings_list.iter())
                    {
                        let emoji = match f.severity {
                            soroban_upgrade_safeguard::diff::Severity::Warning => "🟡",
                            _ => "🔵",
                        };
                        markdown.push_str(&format!("- {} {}\n", emoji, f.message));
                    }
                    markdown.push_str("\n---\n\n");
                }

                println!("{}", markdown);
            }
            OutputFormat::Text => {
                println!("========================================");
                println!("    SOROBAN BATCH SAFETY REPORT");
                println!("========================================");

                let status = if overall_safe {
                    "✅ PASSED (All contracts safe)".green().bold()
                } else {
                    "❌ FAILED (Some contracts have breaking changes)"
                        .red()
                        .bold()
                };
                println!("Overall Status: {}\n", status);

                println!("Summary of Contracts:");
                for (name, report) in &results {
                    let status_str = if report.is_safe {
                        "✅ PASSED".green()
                    } else {
                        "❌ FAILED".red().bold()
                    };
                    println!(
                        "  - {}: {} ({} critical, {} warnings, {} info, {} suppressed)",
                        name.bold(),
                        status_str,
                        report.critical_count,
                        report.warning_count,
                        report.info_count,
                        report.suppressed_count
                    );
                }
                for (name, failure) in &failed {
                    let status_str = if failure.is_limit {
                        "⛔ ERROR (resource limit)".red().bold()
                    } else {
                        "⛔ ERROR".red().bold()
                    };
                    println!("  - {}: {} — {}", name.bold(), status_str, failure.message);
                }

                if !cross_findings.is_empty() {
                    println!("\n🔗 Cross-Contract Dependency Findings:");
                    let mut by_affected: std::collections::BTreeMap<
                        &str,
                        Vec<&CrossContractFinding>,
                    > = std::collections::BTreeMap::new();
                    for cf in &cross_findings {
                        by_affected
                            .entry(cf.affected_contract.as_str())
                            .or_default()
                            .push(cf);
                    }
                    for (affected, cfs) in &by_affected {
                        println!(
                            "  Contract '{}' is affected by changes in:",
                            affected.bold()
                        );
                        for cf in cfs {
                            let sev_icon = match cf.finding.severity {
                                soroban_upgrade_safeguard::diff::Severity::Critical => "🔴",
                                soroban_upgrade_safeguard::diff::Severity::Warning => "🟡",
                                soroban_upgrade_safeguard::diff::Severity::Info => "🔵",
                            };
                            let depth_label = if cf.propagation_depth == 1 {
                                "direct".to_string()
                            } else {
                                format!("transitive depth {}", cf.propagation_depth)
                            };
                            println!(
                                "    {} [{}] '{}' → {} ({})",
                                sev_icon,
                                cf.finding.category,
                                cf.finding.target.as_deref().unwrap_or(""),
                                cf.changed_contract.bold(),
                                depth_label
                            );
                        }
                    }
                }

                if !cycle_findings_list.is_empty() {
                    println!("\n⚠️  Cyclic Dependencies:");
                    for f in &cycle_findings_list {
                        println!("  🟡 {}", f.message);
                    }
                }

                if !missing_findings_list.is_empty() {
                    println!("\n⚠️  Missing Dependency Contracts:");
                    for f in &missing_findings_list {
                        println!("  🟡 {}", f.message);
                    }
                }

                println!("\n========================================\n");

                for (name, report) in &results {
                    println!("=== Contract: {} ===", name.bold().magenta());
                    println!("{}", report.generate_summary_text(args.explain));
                    println!("========================================\n");
                }
            }
            OutputFormat::GithubActions => {
                // Each contract pair is wrapped in a log group so the run
                // summary stays readable when many pairs are compared.
                for (name, report) in &results {
                    print!(
                        "{}",
                        report.generate_summary_github_actions(Some(name.as_str()))
                    );
                }
                // Errored pairs get a plain error annotation.
                for (name, failure) in &failed {
                    println!(
                        "::error::Contract '{}' could not be analyzed: {}",
                        name, failure.message
                    );
                }
            }
        } // end match args.format

        // Exit precedence: resource-limit violation (2) > breaking changes (1) > safe (0).
        if any_limit_violation {
            std::process::exit(2);
        }
        if !overall_safe {
            std::process::exit(1);
        }

        let total_suppressed_criticals: usize =
            results.values().map(|r| r.suppressed_critical_count).sum();
        if total_suppressed_criticals > 0 {
            eprintln!(
                "{}",
                format!(
                    "⚠️  SECURITY NOTICE: The gate passed because {} Critical breaking changes were suppressed. Ensure these suppressions are fully reviewed and authorized.",
                    total_suppressed_criticals
                )
                .red()
                .bold()
            );
        }

        return Ok(());
    }

    // Resolve the two usage modes for single pair:
    //   - 2 positional args => local-vs-local comparison
    //   - 1 positional arg  + --contract-id/--rpc-url => RPC-vs-local comparison
    let (old_source, new_wasm_path) = match (args.wasm_paths.len(), &args.contract_id) {
        (2, None) => (None, &args.wasm_paths[1]), // local mode
        (1, Some(_)) => (args.contract_id.as_deref(), &args.wasm_paths[0]), // RPC mode
        (2, Some(_)) => {
            anyhow::bail!(
                "When using --contract-id, provide only the NEW_WASM path as a positional argument"
            );
        }
        (1, None) => {
            anyhow::bail!(
                "Missing OLD_WASM path. Provide two WASM files, or use --contract-id and --rpc-url \
                 to fetch the old contract from chain.\n\n\
                 Usage: soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>\n       \
                 soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>\n\n\
                 Or use batch mode:\n       \
                 soroban-upgrade-safeguard --manifest <MANIFEST_PATH>\n       \
                 soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR>"
            );
        }
        _ => {
            anyhow::bail!(
                "Expected 1 or 2 WASM path arguments.\n\n\
                 Usage: soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>\n       \
                 soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>\n\n\
                 Or use batch mode:\n       \
                 soroban-upgrade-safeguard --manifest <MANIFEST_PATH>\n       \
                 soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR>"
            );
        }
    };

    progress("🔍 Soroban Upgrade Safeguard".to_string());
    progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());

    progress(format!(
        "\n{}",
        "📦 Loading and Parsing contracts...".cyan().bold()
    ));

    // Old WASM — from file or from RPC. RPC-fetched bytes are subject to the
    // same resource policy as file input.
    let old = if let Some(contract_id) = old_source {
        let rpc_url = args.rpc_url.as_ref().unwrap();
        let module = loader::fetch_wasm_from_rpc_with_policy(contract_id, rpc_url, &policy)?;

        // If the caller pinned an expected hash, verify it now against the hash
        // that was verified on-chain during the RPC fetch.
        if let Some(expected_hex) = &args.expected_wasm_hash {
            let expected_bytes = hex::decode(expected_hex)
                .context("--expected-wasm-hash must be a valid hex string")?;
            let actual = module
                .verified_hash
                .as_ref()
                .map(|h| h.as_slice())
                .unwrap_or(&[]);
            if actual != expected_bytes.as_slice() {
                anyhow::bail!(
                    "Hash mismatch: expected on-chain WASM hash {}, but fetched hash was {}",
                    expected_hex,
                    module
                        .verified_hash
                        .map(hex::encode)
                        .unwrap_or_else(|| "<none>".to_string()),
                );
            }
        }

        module
    } else {
        loader::load_wasm(&args.wasm_paths[0])?
    };

    // New WASM
    let new = loader::load_wasm(new_wasm_path)?;

    if !suppressions.rules.is_empty() {
        progress(format!(
            "\n🔕 {} suppression rule(s) loaded",
            suppressions.rules.len()
        ));
    }

    // Generate Safety Report using the factored helper
    let baseline_source: Option<&str> = if old_source.is_some() {
        Some("RPC")
    } else {
        Some("Local File")
    };
    let verified_hash_hex = old.verified_hash.as_ref().map(hex::encode);
    let mut safety_report = compare_contracts(
        &ContractComparison {
            old_bytes: &old.bytes,
            old_path: &old.path,
            new_bytes: &new.bytes,
            new_path: &new.path,
            suppressions: &suppressions,
            policy: &policy,
            storage_schemas: storage_schemas
                .as_ref()
                .map(|(old_schema, new_schema)| (old_schema, new_schema)),
        },
        &args,
        &progress,
    )?;
    safety_report.baseline_source = baseline_source.map(|s| s.to_string());
    safety_report.verified_code_hash = verified_hash_hex;

    if !all_categories.is_empty() {
        safety_report.apply_category_filter(&category_filter);
    }

    // Render the report to a string first so --output can write it atomically.
    let rendered = match args.format {
        OutputFormat::Json => serde_json::to_string_pretty(&safety_report.to_json())?,
        OutputFormat::Markdown => safety_report.generate_summary_markdown(),
        OutputFormat::Text => safety_report.generate_summary_text(args.explain),
        OutputFormat::GithubActions => safety_report.generate_summary_github_actions(None),
    };

    // Write the report — either to a file (--output) or to stdout.
    if let Some(ref output_path) = args.output {
        std::fs::write(output_path, &rendered).with_context(|| {
            format!("Failed to write report to '{}'", output_path.display())
        })?;
        progress(format!(
            "✅ Report written to: {}",
            output_path.display()
        ));
    } else {
        println!("{}", rendered);
    }

    // Warn about suppression rules that never matched any finding.
    // Goes to stderr so it does not pollute the report on stdout.
    for rule in &safety_report.unmatched_suppressions {
        let target_part = rule
            .target
            .as_deref()
            .map(|t| format!(", target='{}'", t))
            .unwrap_or_default();
        eprintln!(
            "⚠️  Suppression rule never matched any finding: category='{}'{} — possible typo or stale rule.",
            rule.rule_id, target_part
        );
    }

    if !safety_report.is_safe {
        std::process::exit(1);
    } else if safety_report.suppressed_critical_count > 0 {
        eprintln!(
            "{}",
            format!(
                "⚠️  SECURITY NOTICE: The gate passed because {} Critical breaking changes were suppressed. Ensure these suppressions are fully reviewed and authorized.",
                safety_report.suppressed_critical_count
            )
            .red()
            .bold()
        );
    }

    Ok(())
}

#[derive(serde::Deserialize, Clone, Debug)]
struct ContractPair {
    old: PathBuf,
    new: PathBuf,
    name: Option<String>,
}

/// A batch pair that could not be compared. Recorded so one bad pair fails only
/// itself; `is_limit` distinguishes an adversarial-input rejection (exit 2) from
/// an ordinary failure such as a missing or malformed file.
struct PairFailure {
    message: String,
    is_limit: bool,
}

#[derive(serde::Deserialize, Clone, Debug)]
struct Manifest {
    pairs: Vec<ContractPair>,
    #[serde(default)]
    dependencies: Vec<ContractDependency>,
}

struct ContractComparison<'a> {
    old_bytes: &'a [u8],
    old_path: &'a str,
    new_bytes: &'a [u8],
    new_path: &'a str,
    suppressions: &'a SuppressionConfig,
    policy: &'a ResourcePolicy,
    /// The declared storage layouts of the old and new builds, when supplied.
    /// Both sides are required: a layout change is only visible as a diff.
    storage_schemas: Option<(&'a StorageSchema, &'a StorageSchema)>,
}

/// Helper function to run comparison for a single pair.
///
/// Delegates to the canonical library pipeline ([`soroban_upgrade_safeguard::compare_wasm_bytes_with_options`])
/// so both the CLI and library callers always run exactly the same stages.
fn compare_contracts(
    comparison: &ContractComparison<'_>,
    args: &Args,
    progress: &impl Fn(String),
) -> Result<report::SafetyReport> {
    let ContractComparison {
        old_bytes,
        old_path,
        new_bytes,
        new_path,
        suppressions,
        policy,
        storage_schemas,
    } = comparison;

    // Show per-file progress lines before running the pipeline.
    // spec summaries are recovered from the returned report.
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ Old:".green().bold(),
        old_path,
        old_bytes.len()
    ));
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ New:".green().bold(),
        new_path,
        new_bytes.len()
    ));

    progress(format!(
        "\n{}",
        "🔬 Analyzing structural compatibility...".cyan().bold()
    ));

    if storage_schemas.is_some() {
        progress(format!(
            "\n{}",
            "🗄️  Analyzing declared storage layout...".cyan().bold()
        ));
    }

    // Delegate to the single canonical pipeline. Storage-schema analysis,
    // reconciliation against the exported spec, and the resulting scope are all
    // handled inside it, so the CLI and every library caller run the same
    // stages. Reconciliation failure (a manifest that contradicts its build)
    // surfaces here as an error and stops the run.
    let safety_report = soroban_upgrade_safeguard::compare_wasm_bytes_with_options(
        old_bytes,
        new_bytes,
        &CompareOptions {
            policy: Some(policy),
            suppressions: Some(suppressions),
            explain: args.explain,
            strict: args.strict,
            compat_duplicates: args.compat_duplicates,
            storage_schemas: *storage_schemas,
        },
    )?;

    // Print spec summaries now that we have them from the report.
    if let Some(ref summary) = safety_report.old_spec_summary {
        progress(format!("     └─ {}", summary.dimmed()));
    }
    if let Some(ref summary) = safety_report.new_spec_summary {
        progress(format!("     └─ {}", summary.dimmed()));
    }

    if safety_report.scope.storage_analyzed() {
        progress(format!(
            "     └─ {}",
            safety_report.scope.storage_status_line().dimmed()
        ));
    }

    Ok(safety_report)
}

/// Assign a stable, unique display name to every pair in the batch.
///
/// Two rules govern the assignment:
///
/// - **Explicit duplicates are an error.** When two manifest entries carry the
///   same explicit `name`, the user wrote that name deliberately. Silently
///   renaming one would hide the mistake; failing early with a clear message is
///   safer.
///
/// - **Derived duplicates are disambiguated.** When two pairs share the same
///   basename (common with directory scans across sub-directories), the second
///   occurrence is renamed `name (2)`, the third `name (3)`, and so on. Both
///   pairs appear in the output instead of the second silently overwriting the
///   first.
fn resolve_pair_names(pairs: &[ContractPair]) -> Result<Vec<String>> {
    use std::collections::HashMap;

    // Validate explicit names first — duplicates are always an error.
    let mut explicit_seen: HashMap<&str, usize> = HashMap::new();
    for (i, pair) in pairs.iter().enumerate() {
        if let Some(ref name) = pair.name {
            if let Some(first) = explicit_seen.insert(name.as_str(), i) {
                anyhow::bail!(
                    "Manifest has two entries with the same explicit name {:?} \
                     (positions {} and {}). Each entry must have a distinct name.",
                    name,
                    first + 1,
                    i + 1,
                );
            }
        }
    }

    // Build unique names. For derived names, track how many times each
    // candidate has been seen and append a counter on collision.
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut names: Vec<String> = Vec::with_capacity(pairs.len());

    for (i, pair) in pairs.iter().enumerate() {
        let candidate = pair.name.clone().unwrap_or_else(|| {
            pair.new
                .file_stem()
                .and_then(|s| s.to_str())
                .map(String::from)
                .unwrap_or_else(|| format!("pair_{}", i + 1))
        });

        let count = counts.entry(candidate.clone()).or_insert(0);
        *count += 1;
        let unique_name = if *count == 1 {
            candidate
        } else {
            format!("{} ({})", candidate, count)
        };
        names.push(unique_name);
    }

    Ok(names)
}

fn parse_manifest(path: &Path) -> Result<(Vec<ContractPair>, Vec<ContractDependency>)> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read manifest file: {}", path.display()))?;

    // Capture both errors before deciding which to surface.
    let toml_err = match toml::from_str::<Manifest>(&content) {
        Ok(manifest) => return Ok((manifest.pairs, manifest.dependencies)),
        Err(e) => e,
    };
    let json_err = match serde_json::from_str::<Manifest>(&content) {
        Ok(manifest) => return Ok((manifest.pairs, manifest.dependencies)),
        Err(e) => e,
    };

    // Use the file extension to pick the most relevant error; fall back to
    // showing both when the extension is absent or unrecognised.
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase);

    match ext.as_deref() {
        Some("toml") => Err(toml_err)
            .with_context(|| format!("Failed to parse TOML manifest '{}'", path.display())),
        Some("json") => Err(json_err)
            .with_context(|| format!("Failed to parse JSON manifest '{}'", path.display())),
        _ => Err(anyhow::anyhow!(
            "Failed to parse manifest '{}' as either TOML or JSON.\n\
             TOML error: {}\n\
             JSON error: {}",
            path.display(),
            toml_err,
            json_err,
        )),
    }
}

/// Collect all `.wasm` files under `root`, returning their relative paths
/// (relative to `root`). Protects against symlink loops via a visited-path set
/// and enforces a maximum recursion depth of 32.
fn collect_wasm_files(root: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut files: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut stack: Vec<(PathBuf, usize)> = Vec::new();
    stack.push((root.to_path_buf(), 0));

    while let Some((dir, depth)) = stack.pop() {
        if depth > 32 {
            eprintln!(
                "⚠️  Warning: Exceeded maximum recursion depth at '{}', skipping",
                dir.display()
            );
            continue;
        }

        // Resolve symlinks before tracking visited paths
        let canonical = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        if !visited.insert(canonical) {
            continue;
        }

        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                eprintln!(
                    "⚠️  Warning: Cannot read directory '{}': {}",
                    dir.display(),
                    e
                );
                continue;
            }
        };

        for entry in read_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "⚠️  Warning: Error reading entry in '{}': {}",
                        dir.display(),
                        e
                    );
                    continue;
                }
            };

            let path = entry.path();

            if path.is_dir() {
                stack.push((path, depth + 1));
            } else if path.is_file()
                && path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("wasm"))
                    .unwrap_or(false)
            {
                let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                files.push((relative, path));
            }
        }
    }

    // Sort by relative path for deterministic ordering
    files.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(files)
}

fn scan_directories(old_dir: &Path, new_dir: &Path) -> Result<Vec<ContractPair>> {
    if !old_dir.is_dir() {
        anyhow::bail!("Old directory '{}' is not a directory", old_dir.display());
    }
    if !new_dir.is_dir() {
        anyhow::bail!("New directory '{}' is not a directory", new_dir.display());
    }

    let old_files = collect_wasm_files(old_dir)?;
    let new_files_map: std::collections::HashMap<PathBuf, PathBuf> =
        collect_wasm_files(new_dir)?.into_iter().collect();

    let mut pairs = Vec::new();

    for (rel_path, old_abs_path) in &old_files {
        if let Some(new_abs_path) = new_files_map.get(rel_path) {
            let name = rel_path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(String::from);
            pairs.push(ContractPair {
                old: old_abs_path.clone(),
                new: new_abs_path.clone(),
                name,
            });
        } else {
            eprintln!(
                "⚠️  Warning: Match not found for '{}' in new directory '{}'",
                rel_path.display(),
                new_dir.display()
            );
        }
    }

    // Warn about files in new_dir that have no counterpart in old_dir
    for (rel_path, _) in &collect_wasm_files(new_dir)? {
        if !old_files.iter().any(|(r, _)| r == rel_path) {
            eprintln!(
                "⚠️  Warning: No old counterpart found for '{}' in old directory '{}'",
                rel_path.display(),
                old_dir.display()
            );
        }
    }

    if pairs.is_empty() {
        anyhow::bail!(
            "No matching .wasm contract pairs found between '{}' and '{}'",
            old_dir.display(),
            new_dir.display()
        );
    }

    Ok(pairs)
}

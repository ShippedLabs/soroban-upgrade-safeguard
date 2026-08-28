use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use colored::Colorize;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::time::Duration;

use soroban_upgrade_safeguard::{
    attestation::{
        canonical_json_bytes, sign_statement, verify_artifacts, verify_signatures, ArtifactDigest,
        AttestedArtifact, AttestedVerdict, DsseEnvelope, Ed25519Signer, InTotoStatementV1,
        InTotoSubject, SafeguardPredicateV1, VerificationFailure, VerificationFailureKind,
        VerificationPolicy,
    },
    color::{should_disable_color, ColorMode},
    diff,
    limits::ResourcePolicy,
    lint, loader, manifest, migration,
    oci::{self, OciArtifactKind, OciFetchConfig, OciReference},
    parser, preflight,
    remote::{self, RemoteFetchConfig, RemoteRef},
    render::{self, RenderableReport},
    report,
    rpc::RpcClientConfig,
    spec,
    spec_json::{ExtractedSpec, InterfaceLockfile},
    storage_inference,
    storage_schema::{SchemaFormat, StorageSchema},
    suppression::{SuppressionConfig, DEFAULT_CONFIG_FILE},
};

/// Environment variable providing a fallback suppression config path when
/// `--config` is not passed on the command line. See `--config`'s own help
/// text. CI systems can set this once instead of repeating `--config` on
/// every invocation; an explicit `--config` flag always takes precedence.
const CONFIG_PATH_ENV_VAR: &str = "SOROBAN_SAFEGUARD_CONFIG";

/// Where a resolved suppression config path came from, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigSource {
    /// Explicit `--config <PATH>`.
    Cli,
    /// The `SOROBAN_SAFEGUARD_CONFIG` environment variable.
    Env,
    /// Auto-discovered `.safeguard.toml` in the current directory.
    AutoDiscovered,
    /// Found in an ancestor directory via `--search-parent-config`.
    AncestorSearch,
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSource::Cli => write!(f, "--config"),
            ConfigSource::Env => write!(f, "{CONFIG_PATH_ENV_VAR} env var"),
            ConfigSource::AutoDiscovered => write!(f, "auto-discovered {DEFAULT_CONFIG_FILE}"),
            ConfigSource::AncestorSearch => write!(f, "--search-parent-config"),
        }
    }
}

/// Whether `dir` is the workspace boundary ancestor search must not go past:
/// a directory containing a `.git` entry. Checked with a plain path join
/// rather than `.is_dir()`/`.is_file()` specifically, since a git worktree
/// or submodule uses a `.git` *file* (a pointer to the real git dir)
/// where a normal checkout uses a directory — either one marks the same
/// boundary. Inclusive: this directory is itself still searched before the
/// walk stops.
fn is_workspace_boundary(dir: &Path) -> bool {
    dir.join(".git").exists()
}

/// Search `start`'s ancestors — not `start` itself, which the plain
/// auto-discovered-default tier already covers — for `.safeguard.toml`,
/// stopping at the workspace boundary ([`is_workspace_boundary`]) or the
/// filesystem root, whichever comes first. Returns every candidate found,
/// nearest to `start` first; purely lexical (`Path::parent`), so it cannot
/// loop even if a symlink appears in the chain.
fn find_ancestor_configs(start: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut dir = start.to_path_buf();
    loop {
        if dir != start {
            let candidate = dir.join(DEFAULT_CONFIG_FILE);
            if candidate.exists() {
                found.push(candidate);
            }
        }
        if is_workspace_boundary(&dir) {
            break;
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }
    found
}

/// Resolve the `--search-parent-config` tier: `enabled` gates it entirely
/// (the search never runs otherwise), and it is only ever consulted by
/// [`load_suppressions`] after `--config`, the env var, and the current
/// directory have all come up empty.
///
/// More than one candidate along the ancestor chain is rejected outright —
/// silently picking the nearest would make the effective config depend on
/// exactly which subdirectory the tool happened to be run from, which is the
/// ambiguity this option exists to resolve, not reproduce one level up.
fn resolve_ancestor_config(enabled: bool) -> Result<Option<PathBuf>> {
    if !enabled {
        return Ok(None);
    }
    let cwd = std::env::current_dir().context("Failed to read the current directory")?;
    match find_ancestor_configs(&cwd).as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(only.clone())),
        multiple => {
            let list = multiple
                .iter()
                .map(|p| {
                    format!(
                        "  - {}",
                        loader::normalize_path_display(&p.display().to_string())
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!(
                "Ambiguous --search-parent-config: found {} candidate suppression configs \
                 between '{}' and the workspace boundary:\n{list}\n\
                 Pass --config explicitly to choose one.",
                multiple.len(),
                loader::normalize_path_display(&cwd.display().to_string())
            );
        }
    }
}

/// Resolve and load the suppression config: `--config` wins, then the
/// `SOROBAN_SAFEGUARD_CONFIG` environment variable, then the auto-discovered
/// `.safeguard.toml` in the current directory, then (with
/// `search_parent_config`) an ancestor directory, else no suppressions are
/// applied. `no_config` bypasses all of it.
///
/// An explicit `--config`, env-var, or ancestor-search path that is missing
/// or malformed is an error; the current-directory default is silently
/// skipped when absent (existing behavior, unchanged).
fn load_suppressions(
    no_config: bool,
    cli_config: Option<&Path>,
    search_parent_config: bool,
) -> Result<(SuppressionConfig, Option<(PathBuf, ConfigSource)>)> {
    if no_config {
        return Ok((SuppressionConfig::default(), None));
    }
    if let Some(path) = cli_config {
        let config = SuppressionConfig::load_from_path(path)?;
        return Ok((config, Some((path.to_path_buf(), ConfigSource::Cli))));
    }
    if let Some(env_path) = std::env::var_os(CONFIG_PATH_ENV_VAR) {
        let path = PathBuf::from(env_path);
        let config = SuppressionConfig::load_from_path(&path)?;
        return Ok((config, Some((path, ConfigSource::Env))));
    }
    if let Some(config) = SuppressionConfig::load_optional(Path::new(DEFAULT_CONFIG_FILE))? {
        return Ok((
            config,
            Some((
                PathBuf::from(DEFAULT_CONFIG_FILE),
                ConfigSource::AutoDiscovered,
            )),
        ));
    }
    if let Some(path) = resolve_ancestor_config(search_parent_config)? {
        let config = SuppressionConfig::load_from_path(&path)?;
        return Ok((config, Some((path, ConfigSource::AncestorSearch))));
    }
    Ok((SuppressionConfig::default(), None))
}

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
    /// GitHub Actions workflow annotations.
    GithubActions,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Markdown => write!(f, "markdown"),
            OutputFormat::GithubActions => write!(f, "github-actions"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "github-actions" | "gha" => Ok(OutputFormat::GithubActions),
            _ => Err(format!(
                "Unknown format '{s}'. Supported: text, json, markdown, github-actions"
            )),
        }
    }
}

impl OutputFormat {
    fn file_extension(&self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::Markdown => "md",
            OutputFormat::Text => "txt",
            OutputFormat::GithubActions => "txt",
        }
    }
}

/// A single output specification: a format and an optional file path.
/// When `path` is `None`, output goes to stdout.
#[derive(Clone, Debug)]
struct OutputSpec {
    format: OutputFormat,
    path: Option<PathBuf>,
    inherit_format: bool,
}

impl std::str::FromStr for OutputSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if is_windows_absolute_path(s) {
            return Ok(OutputSpec {
                format: OutputFormat::Text,
                path: Some(PathBuf::from(s)),
                inherit_format: true,
            });
        }
        if let Some((fmt, path)) = s.split_once(':') {
            let format: OutputFormat = fmt
                .parse()
                .map_err(|_| format!("Invalid format '{fmt}'. Supported: text, json, markdown"))?;
            Ok(OutputSpec {
                format,
                path: Some(PathBuf::from(path)),
                inherit_format: false,
            })
        } else if let Ok(format) = s.parse() {
            Ok(OutputSpec {
                format,
                path: None,
                inherit_format: false,
            })
        } else if looks_like_output_path(s) {
            Ok(OutputSpec {
                format: OutputFormat::Text,
                path: Some(PathBuf::from(s)),
                inherit_format: true,
            })
        } else {
            Err(format!(
                "Invalid format '{s}'. Use a known format, FORMAT:PATH, or a file path"
            ))
        }
    }
}

fn is_windows_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn looks_like_output_path(value: &str) -> bool {
    value.contains(['/', '\\']) || Path::new(value).extension().is_some()
}

/// Output format for a re-rendered report. JSON is excluded: re-rendering a
/// stored JSON document as JSON would be a no-op copy.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum RenderFormat {
    /// Colored, human-readable report (default).
    #[default]
    Text,
    /// Markdown document suitable for PR descriptions and comments.
    Markdown,
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = None,
    override_usage = "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --manifest <MANIFEST_PATH> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR> [OPTIONS]\n       \
                      soroban-upgrade-safeguard extract <WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard lockfile <WASM> --output <PATH> [OPTIONS]\n       \
                      soroban-upgrade-safeguard render <REPORT_JSON> [OPTIONS]\n       \
                      soroban-upgrade-safeguard init [OPTIONS]\n       \
                      soroban-upgrade-safeguard stream [OPTIONS]\n       \
                      soroban-upgrade-safeguard preflight --rpc-url <URL> [OPTIONS]",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
)]
struct Args {
    /// Subcommand, when not running a comparison
    #[command(subcommand)]
    command: Option<Command>,

    /// WASM paths: <OLD_WASM> <NEW_WASM> in local mode, or just <NEW_WASM> in RPC mode.
    /// Use - to read one WASM from stdin.
    #[arg(value_name = "WASM", num_args = 0..=2)]
    wasm_paths: Vec<PathBuf>,

    /// Output format for stdout. Omit or use --output for file output.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// Output specification(s) in FORMAT:PATH format (e.g. json:report.json),
    /// or a bare path whose format comes from --format. Can be repeated.
    #[arg(long, value_name = "FORMAT:PATH|PATH", num_args = 1)]
    output: Vec<OutputSpec>,

    /// Stellar/Soroban Contract ID to fetch from on-chain (e.g. C...)
    #[arg(long, value_name = "CONTRACT_ID", requires = "rpc_url")]
    contract_id: Option<String>,

    /// Stellar RPC URL (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, value_name = "RPC_URL", requires = "contract_id")]
    rpc_url: Option<String>,

    /// RPC headers as NAME=ENV_VAR. The secret is read only from the environment.
    #[arg(long = "rpc-header", value_name = "NAME=ENV_VAR")]
    rpc_headers: Vec<String>,

    /// Accept a JSON-RPC response whose `id` is missing or does not match
    /// the request's `id`. Off by default; only use this for a provider
    /// known not to echo request IDs correctly.
    #[arg(long)]
    rpc_allow_id_mismatch: bool,

    /// Path to a suppression config acknowledging known, intentional breaking
    /// changes. When omitted, falls back to the SOROBAN_SAFEGUARD_CONFIG
    /// environment variable, then to `.safeguard.toml` in the current
    /// directory if present, then (with --search-parent-config) an ancestor
    /// directory; otherwise no suppressions are applied.
    #[arg(long, value_name = "CONFIG")]
    config: Option<PathBuf>,

    /// Do not load any suppression config, including SOROBAN_SAFEGUARD_CONFIG,
    /// the default .safeguard.toml, and --search-parent-config.
    #[arg(long, conflicts_with = "config")]
    no_config: bool,

    /// When no config resolved from --config, SOROBAN_SAFEGUARD_CONFIG, or
    /// the current directory, search ancestor directories for a
    /// .safeguard.toml, stopping at the workspace boundary (a directory
    /// containing .git) or the filesystem root. Off by default: without
    /// this flag, only the current directory is checked. More than one
    /// candidate along the way is a hard error — pass --config to
    /// disambiguate rather than have the tool guess.
    #[arg(long, conflicts_with = "no_config")]
    search_parent_config: bool,

    /// Validate a suppression config without analyzing WASM inputs.
    #[arg(long, value_name = "CONFIG")]
    validate_config: Option<PathBuf>,

    /// Print a concise remediation explanation for each finding.
    #[arg(long)]
    explain: bool,

    /// Exit with a non-zero code if any Warnings or Critical findings are found
    #[arg(long)]
    strict: bool,

    /// Do not color output
    #[arg(long)]
    no_color: bool,

    /// Use ASCII-only markers instead of emoji ([CRITICAL], [WARN], [INFO],
    /// [PASS], [FAIL], [SUPPRESSED]) for terminals and log viewers that cannot
    /// render emoji. Applies to text and Markdown output, single and batch.
    #[arg(long)]
    ascii: bool,

    /// Fully plain output for log processors: implies --no-color and --ascii,
    /// and also strips the remaining decorative Unicode (guidance arrows,
    /// box-drawing separators) that --ascii alone leaves in place. Applies to
    /// text and Markdown output, single and batch. Report content (severity,
    /// targets, scope, remediation) is unchanged.
    #[arg(long)]
    plain: bool,

    /// Word-wrap finding messages in text output to this many columns,
    /// overriding detection entirely. When omitted, width is detected only
    /// when stdout is a terminal: the COLUMNS environment variable if set
    /// and valid, else 80. Piped/redirected output is left unwrapped unless
    /// this flag is given. Never affects JSON or Markdown output, which have
    /// no line-width concept.
    #[arg(long, value_name = "COLUMNS")]
    width: Option<usize>,

    /// Suppress decorative and progress output; the report and exit code are unchanged.
    #[arg(long)]
    quiet: bool,

    /// Control when ANSI color is used. --no-color overrides this option.
    #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,

    /// Allow HTTP connections for RPC when the host is localhost/127.0.0.1.
    /// Without this flag only HTTPS URLs are accepted.
    #[arg(long)]
    allow_http_local: bool,

    /// Reject a local WASM input path that is a symlink (or resolves through
    /// one) instead of following it. Off by default: a symlinked input is
    /// followed and the resolved target recorded in the report's provenance.
    /// For pipelines where an input must be a direct file.
    #[arg(long)]
    no_symlinks: bool,

    /// Expected SHA-256 hash (hex) of the on-chain WASM baseline.
    #[arg(long, value_name = "HEX_HASH")]
    expected_wasm_hash: Option<String>,

    /// Compare the candidate WASM against a committed interface lockfile.
    #[arg(long, value_name = "LOCKFILE")]
    interface_lockfile: Option<PathBuf>,

    /// Path to a manifest file (TOML or JSON) containing contract pairs to compare
    #[arg(long, value_name = "MANIFEST_PATH")]
    manifest: Option<PathBuf>,

    /// Resolve --manifest (including its `include` chain) and print how every
    /// setting was decided, then exit without comparing anything.
    #[arg(long, requires = "manifest")]
    explain_manifest: bool,

    /// Maximum number of pairs a composed manifest may contain. Rejected as a
    /// configuration error before any WASM is loaded. Not settable from
    /// within the manifest itself, so a runaway or malformed manifest cannot
    /// raise its own ceiling.
    #[arg(long, value_name = "N", default_value_t = manifest::DEFAULT_MAX_PAIRS)]
    max_pairs: usize,

    /// Directory containing the old versions of the contracts for directory comparison
    #[arg(long, value_name = "OLD_DIR", requires = "new_dir")]
    old_dir: Option<PathBuf>,

    /// Directory containing the new versions of the contracts for directory comparison
    #[arg(long, value_name = "NEW_DIR", requires = "old_dir")]
    new_dir: Option<PathBuf>,

    /// Directory to write one report file per contract into, using the selected format
    #[arg(
        long = "per-contract-output-dir",
        alias = "report-dir",
        alias = "output-dir",
        alias = "per-contract-report-dir",
        alias = "per-contract-reports-dir",
        alias = "batch-output-dir",
        value_name = "DIR"
    )]
    per_contract_output_dir: Option<PathBuf>,

    /// Template for per-contract report filenames (e.g. "{name}_report.{ext}")
    /// Documented placeholders:
    ///   {name}  - Contract name
    ///   {id}    - Pair identity
    ///   {ext}   - Output extension for the format (e.g. "json", "md", "txt")
    #[arg(
        long = "per-contract-output-name-template",
        alias = "report-name-template",
        alias = "filename-template",
        value_name = "TEMPLATE",
        default_value = "{name}.{ext}"
    )]
    per_contract_output_name_template: String,

    /// Watch mode: re-run comparison when input files change
    #[arg(long)]
    watch: bool,

    /// Debounce window, in milliseconds, for coalescing rapid filesystem
    /// events in --watch mode before re-running the comparison. Bounds:
    /// WATCH_DEBOUNCE_MIN_MS..=WATCH_DEBOUNCE_MAX_MS.
    #[arg(
        long,
        value_name = "MILLISECONDS",
        default_value_t = DEFAULT_WATCH_DEBOUNCE_MS,
        value_parser = parse_watch_debounce_ms,
    )]
    watch_debounce_ms: u64,

    /// Path to a JSON status file that --watch mode updates atomically after
    /// every cycle transition (start, completion, error, shutdown). Contains
    /// only structured operational state (timestamps, cycle count, verdict),
    /// never findings, so external build systems or service managers can
    /// poll it cheaply to check liveness.
    #[arg(long, value_name = "PATH", requires = "watch")]
    watch_status_file: Option<PathBuf>,

    /// Suppress timestamps in report output for deterministic/snapshot testing
    #[arg(long)]
    no_timestamp: bool,

    /// Sample storage entries and perform empirical validation.
    #[arg(long)]
    empirical: bool,

    /// Path to a JSON file containing captured ledger/storage entries for offline validation.
    #[arg(long, value_name = "EMPIRICAL_FILE")]
    empirical_file: Option<PathBuf>,

    /// Maximum bytes accepted for any `https://` input download.
    #[arg(long, value_name = "BYTES", default_value_t = remote::DEFAULT_MAX_BYTES)]
    remote_max_bytes: usize,

    /// Timeout, in seconds, for any single `https://` input request.
    #[arg(long, value_name = "SECONDS", default_value_t = remote::DEFAULT_TIMEOUT_SECS)]
    remote_timeout_secs: u64,

    /// Maximum redirect hops followed when fetching an `https://` input.
    #[arg(long, value_name = "COUNT", default_value_t = remote::DEFAULT_MAX_REDIRECTS)]
    remote_max_redirects: u32,

    /// Directory used to cache verified `https://` input downloads by digest.
    /// Defaults to a directory under the OS temp dir; see
    /// `SOROBAN_SAFEGUARD_REMOTE_CACHE`.
    #[arg(long, value_name = "DIR")]
    remote_cache_dir: Option<PathBuf>,

    /// Do not read from or write to the remote-artifact cache for this run.
    #[arg(long)]
    no_remote_cache: bool,

    /// Delete every cached `https://` input artifact and exit.
    #[arg(long)]
    clear_remote_cache: bool,

    /// Maximum bytes accepted for any `oci://` manifest or layer download.
    #[arg(long, value_name = "BYTES", default_value_t = oci::DEFAULT_MAX_BYTES)]
    oci_max_bytes: usize,

    /// Timeout, in seconds, for any single `oci://` registry request.
    #[arg(long, value_name = "SECONDS", default_value_t = oci::DEFAULT_TIMEOUT_SECS)]
    oci_timeout_secs: u64,

    /// Directory used to cache verified `oci://` input layers by digest.
    /// Defaults to a directory under the OS temp dir; see
    /// `SOROBAN_SAFEGUARD_OCI_CACHE`.
    #[arg(long, value_name = "DIR")]
    oci_cache_dir: Option<PathBuf>,

    /// Do not read from or write to the OCI-artifact cache for this run.
    #[arg(long)]
    no_oci_cache: bool,

    /// Delete every cached `oci://` input artifact and exit.
    #[arg(long)]
    clear_oci_cache: bool,

    /// Allow an `oci://` input to reference a mutable tag instead of a
    /// pinned `@sha256:<hex>` digest. The resolved digest is printed so the
    /// reference can be pinned afterward. Off by default.
    #[arg(long)]
    allow_oci_tags: bool,

    /// Path to a persistent lineage store (JSON/TOML) tracking historical versions.
    #[arg(long, value_name = "PATH")]
    lineage_store: Option<PathBuf>,

    /// Record candidate build as a new version in the lineage store with this tag.
    #[arg(long, value_name = "VERSION_ID")]
    record_version: Option<String>,

    /// Mark an existing historical version as retired in the lineage store.
    #[arg(long, value_name = "VERSION_ID")]
    retire_version: Option<String>,

    /// Maximum live historical versions to validate candidate against.
    #[arg(long, value_name = "N")]
    max_live_versions: Option<usize>,
}

/// Build the remote-fetch policy for `https://` inputs from the top-level CLI flags.
fn remote_fetch_config(args: &Args) -> RemoteFetchConfig {
    RemoteFetchConfig {
        max_bytes: args.remote_max_bytes,
        timeout: Duration::from_secs(args.remote_timeout_secs),
        max_redirects: args.remote_max_redirects,
        cache_dir: args.remote_cache_dir.clone(),
        no_cache: args.no_remote_cache,
        https_only: true,
    }
}

/// Build the OCI-fetch policy for `oci://` inputs from the top-level CLI flags.
fn oci_fetch_config(args: &Args) -> OciFetchConfig {
    OciFetchConfig {
        max_bytes: args.oci_max_bytes,
        timeout: Duration::from_secs(args.oci_timeout_secs),
        cache_dir: args.oci_cache_dir.clone(),
        no_cache: args.no_oci_cache,
        https_only: true,
        allow_tags: args.allow_oci_tags,
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Dump a single contract's decoded spec as JSON
    Extract(ExtractArgs),
    /// Generate or update a committed interface lockfile from one WASM build
    Lockfile(LockfileArgs),
    /// Re-render a previously saved JSON report in another format
    Render(RenderArgs),
    /// Migrate a saved JSON report to the latest schema version
    UpgradeReport(UpgradeReportArgs),
    /// Generate a suppression config from current findings
    Init(InitArgs),
    /// Create a signed DSSE in-toto attestation for a saved analysis report
    Attest(AttestArgs),
    /// Verify a safeguard DSSE attestation and all referenced artifacts offline
    VerifyAttestation(VerifyAttestationArgs),
    /// Streaming JSON Lines batch mode: one job per line on stdin, one result per line on stdout
    Stream(StreamArgs),
    /// Validate one contract spec (and optional storage schema) in isolation
    Lint(LintArgs),
    /// Validate RPC connectivity and JSON-RPC protocol shape without fetching contract code
    Preflight(PreflightArgs),
}

/// `lint`: validate a single decoded contract spec (and optional storage
/// schema) for graph and schema integrity, independent of any comparison.
///
/// Exit codes are distinct from the comparison command's:
/// - `0`: clean, or only warning/info findings without `--strict`.
/// - `2`: at least one error-severity finding (the artifact is structurally invalid).
/// - `3`: only warning/info findings, but `--strict` was passed.
#[derive(ClapArgs, Debug)]
struct LintArgs {
    /// WASM file to decode. Omit when using --contract-id/--rpc-url.
    #[arg(value_name = "WASM")]
    wasm: Option<PathBuf>,

    /// Stellar/Soroban Contract ID to fetch from on-chain (e.g. C...)
    #[arg(long, value_name = "CONTRACT_ID", requires = "rpc_url")]
    contract_id: Option<String>,

    /// Stellar RPC URL (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, value_name = "RPC_URL", requires = "contract_id")]
    rpc_url: Option<String>,

    #[arg(long = "rpc-header", value_name = "NAME=ENV_VAR")]
    rpc_headers: Vec<String>,

    /// Optional declared storage schema (JSON or TOML, inferred from extension).
    #[arg(long, value_name = "SCHEMA")]
    storage_schema: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = LintOutputFormat::Text)]
    format: LintOutputFormat,

    /// Include remediation guidance for each finding.
    #[arg(long)]
    explain: bool,

    /// Exit non-zero even when only warning/info findings are present.
    #[arg(long)]
    strict: bool,

    /// Maximum recursive type-walk depth. Overrides the built-in default.
    #[arg(long, value_name = "N")]
    max_walk_depth: Option<usize>,

    #[arg(long)]
    no_color: bool,
}

/// Output format for the `lint` subcommand.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
enum LintOutputFormat {
    #[default]
    Text,
    Json,
    Markdown,
}

#[derive(ClapArgs, Debug)]
struct AttestArgs {
    #[arg(value_name = "REPORT_JSON")]
    report: PathBuf,
    #[arg(long, value_name = "WASM")]
    old_wasm: PathBuf,
    #[arg(long, value_name = "WASM")]
    new_wasm: PathBuf,
    #[arg(long, value_name = "PKCS8_KEY")]
    private_key: PathBuf,
    #[arg(long, value_name = "IDENTITY")]
    key_id: String,
    #[arg(long, value_name = "DSSE_JSON")]
    output: PathBuf,
    /// JSON file containing the fully resolved policy/configuration.
    #[arg(long, value_name = "POLICY_JSON")]
    policy: Option<PathBuf>,
    #[arg(long, value_name = "SCHEMA", requires = "new_storage_schema")]
    old_storage_schema: Option<PathBuf>,
    #[arg(long, value_name = "SCHEMA", requires = "old_storage_schema")]
    new_storage_schema: Option<PathBuf>,
}

#[derive(ClapArgs, Debug)]
struct VerifyAttestationArgs {
    #[arg(value_name = "DSSE_JSON")]
    attestation: PathBuf,
    #[arg(long, value_name = "REPORT_JSON")]
    report: Option<PathBuf>,
    #[arg(long, value_name = "WASM")]
    old_wasm: Option<PathBuf>,
    #[arg(long, value_name = "WASM")]
    new_wasm: Option<PathBuf>,
    /// Trusted Ed25519 key in ID=PATH form. PATH contains a raw 32-byte public key.
    #[arg(long = "trusted-key", value_name = "ID=PATH", required = true)]
    trusted_keys: Vec<String>,
    #[arg(long, value_name = "SCHEMA")]
    old_storage_schema: Option<PathBuf>,
    #[arg(long, value_name = "SCHEMA")]
    new_storage_schema: Option<PathBuf>,
    /// Unix timestamp after which the verification policy is expired.
    #[arg(long, value_name = "UNIX_SECONDS")]
    policy_expires_at: Option<u64>,
}

/// `stream`: JSON Lines streaming batch mode.
#[derive(ClapArgs, Debug)]
struct StreamArgs {
    /// Maximum number of concurrent worker threads.
    #[arg(long, default_value_t = 4)]
    concurrency: usize,
    /// Preserve input order in output (slower; buffers results).
    #[arg(long)]
    input_order: bool,
    /// Treat warnings as errors globally (jobs may override).
    #[arg(long)]
    strict: bool,
    /// Do not load a suppression config automatically, including
    /// SOROBAN_SAFEGUARD_CONFIG, the default .safeguard.toml, and
    /// --search-parent-config.
    #[arg(long)]
    no_config: bool,
    /// Path to a suppression config. Falls back to SOROBAN_SAFEGUARD_CONFIG,
    /// then to `.safeguard.toml` in the current directory if present, then
    /// (with --search-parent-config) an ancestor directory.
    #[arg(long, value_name = "CONFIG")]
    config: Option<PathBuf>,
    /// Search ancestor directories for `.safeguard.toml` when nothing more
    /// specific resolved one. See the top-level flag of the same name.
    #[arg(long, conflicts_with = "no_config")]
    search_parent_config: bool,
}

/// `extract`: decode one build and emit its interface.
#[derive(ClapArgs, Debug)]
struct ExtractArgs {
    /// WASM file to decode. Omit when using --contract-id/--rpc-url.
    #[arg(value_name = "WASM")]
    wasm: Option<PathBuf>,

    /// Stellar/Soroban Contract ID to fetch from on-chain (e.g. C...)
    #[arg(long, value_name = "CONTRACT_ID", requires = "rpc_url")]
    contract_id: Option<String>,

    /// Stellar RPC URL (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, value_name = "RPC_URL", requires = "contract_id")]
    rpc_url: Option<String>,

    #[arg(long = "rpc-header", value_name = "NAME=ENV_VAR")]
    rpc_headers: Vec<String>,

    /// Print only the interface hash, with no other output.
    #[arg(long)]
    hash_only: bool,
}

/// `lockfile`: write a committed snapshot of one contract's exported interface.
#[derive(ClapArgs, Debug)]
struct LockfileArgs {
    /// WASM file whose exported interface should be recorded.
    #[arg(value_name = "WASM")]
    wasm: PathBuf,

    /// Destination path for the interface lockfile.
    #[arg(long, value_name = "PATH", required = true)]
    output: PathBuf,

    /// Allow replacing an existing lockfile.
    #[arg(long)]
    force: bool,
}

/// `render`: turn a stored JSON report back into a human format.
#[derive(ClapArgs, Debug)]
struct RenderArgs {
    /// Path to a JSON report previously written with --format json, or `-` to
    /// read it from stdin.
    #[arg(value_name = "REPORT_JSON")]
    report: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t = RenderFormat::Text)]
    format: RenderFormat,

    /// Print the remediation guidance stored in the report, if it has any.
    #[arg(long)]
    explain: bool,

    /// Do not color output
    #[arg(long)]
    no_color: bool,

    /// Fully plain output for log processors: implies --no-color and strips
    /// Unicode markers and decorative separators. Report content is unchanged.
    #[arg(long)]
    plain: bool,

    /// Word-wrap finding messages in text output to this many columns,
    /// overriding detection entirely. When omitted, width is detected only
    /// when stdout is a terminal: the COLUMNS environment variable if set
    /// and valid, else 80. Piped/redirected output is left unwrapped unless
    /// this flag is given. Has no effect on --format markdown.
    #[arg(long, value_name = "COLUMNS")]
    width: Option<usize>,
}

/// `upgrade-report`: migrate a saved JSON report to the latest schema version.
#[derive(ClapArgs, Debug)]
struct UpgradeReportArgs {
    /// Path to a JSON report, or `-` to read it from stdin.
    #[arg(value_name = "REPORT_JSON")]
    report: PathBuf,

    /// Destination path for the upgraded report. Defaults to stdout.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

/// `init`: generate a suppression config from current findings.
#[derive(ClapArgs, Debug)]
struct InitArgs {
    /// Overwrite existing .safeguard.toml if it exists
    #[arg(long)]
    force: bool,

    /// Path to the old WASM file (or contract ID with --rpc-url)
    #[arg(value_name = "OLD")]
    old: Option<PathBuf>,

    /// Path to the new WASM file
    #[arg(value_name = "NEW")]
    new: Option<PathBuf>,

    /// Stellar/Soroban Contract ID to fetch from on-chain (e.g. C...)
    #[arg(long, value_name = "CONTRACT_ID", requires = "rpc_url")]
    contract_id: Option<String>,

    /// Stellar RPC URL (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, value_name = "RPC_URL", requires = "contract_id")]
    rpc_url: Option<String>,

    #[arg(long = "rpc-header", value_name = "NAME=ENV_VAR")]
    rpc_headers: Vec<String>,
}

/// `preflight`: validate RPC connectivity and protocol shape only.
#[derive(ClapArgs, Debug)]
struct PreflightArgs {
    /// Stellar RPC URL (e.g. https://soroban-testnet.stellar.org)
    #[arg(long, value_name = "RPC_URL", required = true)]
    rpc_url: String,

    /// RPC headers as NAME=ENV_VAR. The secret is read only from the environment.
    #[arg(long = "rpc-header", value_name = "NAME=ENV_VAR")]
    rpc_headers: Vec<String>,

    /// Timeout, in seconds, for the preflight request.
    #[arg(long, value_name = "SECONDS", default_value_t = preflight::DEFAULT_PREFLIGHT_TIMEOUT.as_secs())]
    timeout_secs: u64,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Do not color output
    #[arg(long)]
    no_color: bool,
}

fn rpc_config(url: &str, headers: &[String]) -> Result<RpcClientConfig> {
    let mut config = RpcClientConfig::new(url.to_string()).map_err(|e| anyhow::anyhow!(e))?;
    for spec in headers {
        let (name, env_var) = spec.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("Invalid --rpc-header '{}'; expected NAME=ENV_VAR", spec)
        })?;
        config = config
            .with_env_header(name.to_string(), env_var.to_string())
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    Ok(config)
}

/// Decode one build and emit its interface as JSON, or just its hash.
fn run_extract(args: &ExtractArgs) -> Result<()> {
    let build = match (&args.wasm, &args.contract_id) {
        (Some(path), None) => load_wasm_input(
            path,
            &RemoteFetchConfig::default(),
            &OciFetchConfig::default(),
            false,
            &|line| {
                eprintln!("{line}");
            },
        )?,
        (None, Some(contract_id)) => {
            let rpc_url = args
                .rpc_url
                .as_ref()
                .expect("clap requires --rpc-url alongside --contract-id");
            loader::fetch_wasm_from_rpc_with_config(
                contract_id,
                &rpc_config(rpc_url, &args.rpc_headers)?,
            )?
        }
        (Some(_), Some(_)) => anyhow::bail!(
            "Provide either a WASM path or --contract-id, not both.\n\n\
             Usage: soroban-upgrade-safeguard extract <WASM>\n       \
             soroban-upgrade-safeguard extract --contract-id <ID> --rpc-url <URL>"
        ),
        (None, None) => anyhow::bail!(
            "Missing WASM path.\n\n\
             Usage: soroban-upgrade-safeguard extract <WASM>\n       \
             soroban-upgrade-safeguard extract --contract-id <ID> --rpc-url <URL>"
        ),
    };

    let metadata = parser::extract_metadata(&build.bytes)?;
    let contract_spec = spec::ContractSpec::from_entries(&metadata.spec);

    if args.hash_only {
        println!("{}", contract_spec.interface_hash());
        return Ok(());
    }

    let extracted = ExtractedSpec::new(&build.path, &metadata, &contract_spec);
    println!("{}", serde_json::to_string_pretty(&extracted)?);
    Ok(())
}

/// Validate RPC connectivity and JSON-RPC protocol shape without fetching
/// any contract code. See [`preflight::run_preflight_with_timeout`] for the
/// exact checks performed.
fn run_preflight(args: &PreflightArgs) -> Result<()> {
    if should_disable_color(
        args.no_color,
        ColorMode::Auto,
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    ) {
        colored::control::set_override(false);
    }

    let config = rpc_config(&args.rpc_url, &args.rpc_headers)?;
    let report =
        preflight::run_preflight_with_timeout(&config, Duration::from_secs(args.timeout_secs));

    if args.format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Preflight check: {}", report.rpc_endpoint);
        println!();

        let transport_detail = if report.transport.success {
            Some(format!(
                "HTTP {}",
                report.transport.status_code.unwrap_or_default()
            ))
        } else {
            report.transport.error.clone()
        };
        print_preflight_line("Transport", report.transport.success, transport_detail);

        let protocol_detail = if report.protocol.success {
            Some(format!(
                "jsonrpc {}, id matches",
                report.protocol.jsonrpc_version.as_deref().unwrap_or("?")
            ))
        } else {
            report.protocol.error.clone()
        };
        print_preflight_line("Protocol", report.protocol.success, protocol_detail);

        let capability_detail = if report.capability.success {
            Some(match report.capability.latest_ledger {
                Some(seq) => format!(
                    "{} succeeded (latestLedger {seq})",
                    report.capability.method
                ),
                None => format!("{} succeeded", report.capability.method),
            })
        } else {
            report.capability.error.clone()
        };
        print_preflight_line("Capability", report.capability.success, capability_detail);

        println!();
        println!(
            "Overall: {}",
            if report.all_passed() {
                "PASS".green().bold()
            } else {
                "FAIL".red().bold()
            }
        );
        println!();
        println!(
            "Note: a passing preflight check confirms endpoint connectivity only. \
             It does not verify that any specific contract or network is compatible."
        );
    }

    std::io::stdout().flush().ok();
    if !report.all_passed() {
        std::process::exit(1);
    }
    Ok(())
}

fn print_preflight_line(label: &str, success: bool, detail: Option<String>) {
    let status = if success {
        "PASS".green()
    } else {
        "FAIL".red()
    };
    match detail {
        Some(detail) => println!("{label:<12}{status}  {detail}"),
        None => println!("{label:<12}{status}"),
    }
}

/// Extract one build and write its exported interface as a lockfile.
fn run_lockfile(args: &LockfileArgs) -> Result<()> {
    if args.output.exists() && !args.force {
        anyhow::bail!(
            "{} already exists. Use --force to update it.",
            args.output.display()
        );
    }

    let build = loader::load_wasm(&args.wasm)
        .map_err(|error| anyhow::anyhow!("Failed to load '{}': {error}", args.wasm.display()))?;
    let metadata = parser::extract_metadata(&build.bytes)
        .context("Failed to extract metadata from the lockfile source WASM")?;
    let contract_spec = spec::ContractSpec::from_entries(&metadata.spec);
    let extracted = ExtractedSpec::new(&build.path, &metadata, &contract_spec);
    let lockfile = InterfaceLockfile::from_extracted(&extracted);
    let mut contents = serde_json::to_vec_pretty(&lockfile)?;
    contents.push(b'\n');

    if let Some(parent) = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create lockfile directory '{}'.",
                parent.display()
            )
        })?;
    }
    write_atomically(&args.output, &contents)
        .with_context(|| format!("Failed to write lockfile '{}'.", args.output.display()))?;
    println!(
        "{} {} ({})",
        if args.force { "Updated" } else { "Generated" },
        args.output.display(),
        contract_spec.interface_hash()
    );
    Ok(())
}

/// Reads bytes for an artifact reference that may be a local path, an
/// `https://…#sha256=<hex>` remote reference, or an
/// `oci://registry/repository@sha256:<hex>` reference (used for
/// storage-schema references in `attest`/`verify-attestation`).
fn read_artifact_bytes(path: &Path) -> Result<Vec<u8>> {
    if let Some(remote) =
        RemoteRef::parse(&path.to_string_lossy()).map_err(|e| anyhow::anyhow!(e))?
    {
        let artifact = remote::fetch_verified(&remote, &RemoteFetchConfig::default())?;
        eprintln!(
            "🌐 Remote input: {} (sha256:{}, cache {}{})",
            artifact.final_url,
            artifact.sha256,
            artifact.cache_status,
            artifact
                .media_type
                .as_deref()
                .map(|m| format!(", {m}"))
                .unwrap_or_default()
        );
        Ok(artifact.bytes)
    } else if let Some(reference) =
        OciReference::parse(&path.to_string_lossy()).map_err(|e| anyhow::anyhow!(e))?
    {
        let artifact = oci::resolve_oci_artifact(
            &reference,
            OciArtifactKind::ExtractedSpec,
            &OciFetchConfig::default(),
        )?;
        print_oci_provenance(&artifact);
        Ok(artifact.bytes)
    } else {
        std::fs::read(path)
            .with_context(|| format!("Failed to read artifact '{}'.", path.display()))
    }
}

/// Prints a provenance line for a resolved OCI artifact naming exactly which
/// registry, repository, manifest, and layer were analyzed.
fn print_oci_provenance(artifact: &oci::OciArtifact) {
    eprintln!(
        "📦 OCI input: {}/{}@{} (manifest {}{}, cache {}, {})",
        artifact.registry,
        artifact.repository,
        artifact.layer_digest,
        artifact.manifest_digest,
        artifact
            .resolved_tag
            .as_deref()
            .map(|t| format!(", resolved from tag '{t}'"))
            .unwrap_or_default(),
        artifact.cache_status,
        artifact.media_type
    );
}

/// Exit code when the lint run found at least one error-severity finding.
const LINT_EXIT_ERROR: i32 = 2;
/// Exit code when only warning/info findings were found but `--strict` was passed.
const LINT_EXIT_STRICT_WARNINGS: i32 = 3;

/// Validate one decoded contract spec (and optional storage schema) in isolation.
fn run_lint(args: &LintArgs) -> Result<()> {
    if args.no_color || std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }

    let build = match (&args.wasm, &args.contract_id) {
        (Some(path), None) => loader::load_wasm(path)?,
        (None, Some(contract_id)) => {
            let rpc_url = args
                .rpc_url
                .as_ref()
                .expect("clap requires --rpc-url alongside --contract-id");
            loader::fetch_wasm_from_rpc_with_config(
                contract_id,
                &rpc_config(rpc_url, &args.rpc_headers)?,
            )?
        }
        (Some(_), Some(_)) => anyhow::bail!(
            "Provide either a WASM path or --contract-id, not both.\n\n\
             Usage: soroban-upgrade-safeguard lint <WASM>\n       \
             soroban-upgrade-safeguard lint --contract-id <ID> --rpc-url <URL>"
        ),
        (None, None) => anyhow::bail!(
            "Missing WASM path.\n\n\
             Usage: soroban-upgrade-safeguard lint <WASM>\n       \
             soroban-upgrade-safeguard lint --contract-id <ID> --rpc-url <URL>"
        ),
    };

    let metadata = parser::extract_metadata(&build.bytes)?;

    let schema = match &args.storage_schema {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read storage schema '{}'", path.display()))?;
            let format = match path.extension().and_then(|e| e.to_str()) {
                Some("toml") => SchemaFormat::Toml,
                _ => SchemaFormat::Json,
            };
            // Parse without eagerly validating here: an invalid schema should
            // surface as a lint finding, not a hard CLI error.
            let parsed = match format {
                SchemaFormat::Json => StorageSchema::from_json(&content),
                SchemaFormat::Toml => StorageSchema::from_toml(&content),
            };
            match parsed {
                Ok(schema) => Some(schema),
                Err(err) => {
                    anyhow::bail!("Failed to parse storage schema '{}': {err}", path.display())
                }
            }
        }
        None => None,
    };

    let inferred = if schema.is_some() {
        Some(storage_inference::infer_storage(&build.bytes).map_err(|e| anyhow::anyhow!(e))?)
    } else {
        None
    };

    let mut policy = ResourcePolicy::default();
    if let Some(v) = args.max_walk_depth {
        policy.max_walk_depth = v;
    }

    let options = lint::LintOptions {
        schema: schema.as_ref(),
        inferred_storage: inferred.as_ref(),
        policy,
    };

    let report = lint::lint(&metadata.spec, &options);

    match args.format {
        LintOutputFormat::Text => print!("{}", report.render_text(args.explain)),
        LintOutputFormat::Markdown => print!("{}", report.render_markdown(args.explain)),
        LintOutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report.to_json_value())?)
        }
    }

    if report.has_errors() {
        std::process::exit(LINT_EXIT_ERROR);
    }
    if args.strict && report.has_warnings() {
        std::process::exit(LINT_EXIT_STRICT_WARNINGS);
    }

    Ok(())
}

fn file_artifact(path: &Path) -> Result<AttestedArtifact> {
    let bytes = read_artifact_bytes(path)?;
    Ok(AttestedArtifact {
        name: path.to_string_lossy().to_string(),
        digest: ArtifactDigest::from_bytes(&bytes),
    })
}

fn extracted_spec_bytes(path: &Path) -> Result<Vec<u8>> {
    let build = loader::load_wasm(path)?;
    let metadata = parser::extract_metadata(&build.bytes)?;
    let contract_spec = spec::ContractSpec::from_entries(&metadata.spec);
    let extracted = ExtractedSpec::new(&build.path, &metadata, &contract_spec);
    canonical_json_bytes(&extracted).map_err(|e| anyhow::anyhow!(e))
}

fn extracted_spec_artifact(path: &Path) -> Result<AttestedArtifact> {
    let bytes = extracted_spec_bytes(path)?;
    Ok(AttestedArtifact {
        name: format!("{}.spec.json", path.display()),
        digest: ArtifactDigest::from_bytes(&bytes),
    })
}

fn run_attest(args: &AttestArgs) -> Result<()> {
    let report_bytes = std::fs::read(&args.report)
        .with_context(|| format!("Failed to read report '{}'.", args.report.display()))?;
    let old_bytes = std::fs::read(&args.old_wasm)?;
    let new_bytes = std::fs::read(&args.new_wasm)?;
    let report: RenderableReport = RenderableReport::from_json_str(
        std::str::from_utf8(&report_bytes).context("Report is not UTF-8")?,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let old_spec = extracted_spec_artifact(&args.old_wasm)?;
    let new_spec = extracted_spec_artifact(&args.new_wasm)?;
    let mut storage_schemas = Vec::new();
    for path in [&args.old_storage_schema, &args.new_storage_schema]
        .into_iter()
        .flatten()
    {
        storage_schemas.push(file_artifact(path)?);
    }
    let resolved_policy = if let Some(path) = &args.policy {
        let bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read policy '{}'.", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("Policy '{}' is not valid JSON.", path.display()))?
    } else {
        serde_json::json!({
            "strict": report.strict,
            "gated_axes": report.gated_axes,
            "axis_verdicts": report.axis_verdicts,
            "report_schema_version": report.report_schema_version,
        })
    };
    let predicate = SafeguardPredicateV1::new(
        vec![
            AttestedArtifact {
                name: args.old_wasm.to_string_lossy().to_string(),
                digest: ArtifactDigest::from_bytes(&old_bytes),
            },
            AttestedArtifact {
                name: args.new_wasm.to_string_lossy().to_string(),
                digest: ArtifactDigest::from_bytes(&new_bytes),
            },
        ],
        vec![old_spec, new_spec],
        storage_schemas,
        resolved_policy,
        AttestedArtifact {
            name: args.report.to_string_lossy().to_string(),
            digest: ArtifactDigest::from_bytes(&report_bytes),
        },
        AttestedVerdict {
            is_safe: report.is_safe,
            recommended_bump: report.recommended_bump.clone(),
            old_client_to_new_contract: report.call_abi.old_client_to_new_contract.compatible,
            new_client_to_old_contract: report.call_abi.new_client_to_old_contract.compatible,
        },
    );
    let statement = InTotoStatementV1::new(
        vec![
            InTotoSubject {
                name: args.old_wasm.to_string_lossy().to_string(),
                digest: ArtifactDigest::from_bytes(&old_bytes),
            },
            InTotoSubject {
                name: args.new_wasm.to_string_lossy().to_string(),
                digest: ArtifactDigest::from_bytes(&new_bytes),
            },
        ],
        predicate,
    );
    let key = std::fs::read(&args.private_key).with_context(|| {
        format!(
            "Failed to read private key '{}'.",
            args.private_key.display()
        )
    })?;
    let signer = Ed25519Signer::from_pkcs8(&args.key_id, &key).map_err(|e| anyhow::anyhow!(e))?;
    let envelope = sign_statement(&statement, &signer).map_err(|e| anyhow::anyhow!(e))?;
    write_atomically(&args.output, &serde_json::to_vec_pretty(&envelope)?)?;
    Ok(())
}

fn run_verify_attestation(args: &VerifyAttestationArgs) -> Result<()> {
    let envelope: DsseEnvelope = serde_json::from_slice(&std::fs::read(&args.attestation)?)?;
    let statement = match envelope.statement() {
        Ok(statement) => statement,
        Err(error) => {
            let result = serde_json::json!({
                "verified": false,
                "signer_identities": [],
                "failures": [VerificationFailure {
                    kind: VerificationFailureKind::InvalidStatement,
                    subject: None,
                    message: error.to_string(),
                }],
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
            std::io::stdout().flush().ok();
            std::process::exit(1);
        }
    };
    let mut trusted = std::collections::BTreeMap::new();
    for item in &args.trusted_keys {
        let (id, path) = item
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--trusted-key must use ID=PATH"))?;
        trusted.insert(
            id.to_string(),
            std::fs::read(path).with_context(|| format!("Failed to read trusted key '{id}'."))?,
        );
    }
    let signatures = verify_signatures(&envelope, &trusted);
    let mut artifacts = std::collections::BTreeMap::new();
    if let Some(path) = &args.report {
        artifacts.insert(
            statement.predicate.report.name.clone(),
            std::fs::read(path)?,
        );
    }
    for (path, artifact) in [&args.old_wasm, &args.new_wasm]
        .into_iter()
        .zip(&statement.predicate.inputs)
    {
        if let Some(path) = path {
            artifacts.insert(artifact.name.clone(), std::fs::read(path)?);
        }
    }
    for (path, artifact) in [&args.old_wasm, &args.new_wasm]
        .into_iter()
        .zip(&statement.predicate.extracted_specs)
    {
        if let Some(path) = path {
            artifacts.insert(artifact.name.clone(), extracted_spec_bytes(path)?);
        }
    }
    for (path, artifact) in [&args.old_storage_schema, &args.new_storage_schema]
        .into_iter()
        .zip(&statement.predicate.storage_schemas)
    {
        if let Some(path) = path {
            artifacts.insert(artifact.name.clone(), read_artifact_bytes(path)?);
        }
    }
    let mut failures = signatures.failures;
    failures.extend(verify_artifacts(
        &statement,
        &artifacts,
        &VerificationPolicy {
            expires_at: args.policy_expires_at,
        },
    ));
    let result = serde_json::json!({
        "verified": signatures.verified && failures.is_empty(),
        "signer_identities": signatures.signer_identities,
        "failures": failures,
    });
    println!("{}", serde_json::to_string_pretty(&result)?);
    if result["verified"] != true {
        std::io::stdout().flush().ok();
        std::process::exit(1);
    }
    Ok(())
}

/// Run the streaming JSONL batch protocol.
///
/// Reads versioned JSON jobs from stdin, processes them concurrently,
/// and writes versioned JSON results to stdout. All diagnostics go to stderr.
fn run_stream(args: &StreamArgs) -> Result<()> {
    use soroban_upgrade_safeguard::jsonl::{self, OutputOrder, StreamConfig};

    let (suppressions, config_source) = load_suppressions(
        args.no_config,
        args.config.as_deref(),
        args.search_parent_config,
    )?;
    if let Some((path, source)) = &config_source {
        eprintln!("Suppression config: {} (source: {source})", path.display());
    }

    let output_order = if args.input_order {
        OutputOrder::InputOrder
    } else {
        OutputOrder::CompletionOrder
    };

    let config = StreamConfig {
        concurrency: args.concurrency.max(1),
        output_order,
        strict: args.strict,
        suppressions,
        no_config: args.no_config,
        ..StreamConfig::default()
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    jsonl::run_streaming(stdin.lock(), stdout.lock(), &config)
}

/// Re-render a stored JSON report as text or Markdown.
fn run_render(args: &RenderArgs) -> Result<()> {
    let raw = if args.report == Path::new("-") {
        std::io::read_to_string(std::io::stdin()).context("Failed to read report from stdin")?
    } else {
        std::fs::read_to_string(&args.report)
            .with_context(|| format!("Failed to read report file: {}", args.report.display()))?
    };

    if should_disable_color(
        args.no_color || args.plain,
        ColorMode::Auto,
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    ) {
        colored::control::set_override(false);
    }

    let report = RenderableReport::from_json_str(&raw).with_context(|| {
        format!(
            "Failed to read the saved report at '{}'",
            args.report.display()
        )
    })?;

    match args.format {
        RenderFormat::Text => {
            let width = resolve_text_width(args.width, std::io::stdout().is_terminal());
            let text = report.to_text_with_width(args.explain, width);
            println!(
                "{}",
                if args.plain {
                    report::plainify(&text)
                } else {
                    text
                }
            );
        }
        RenderFormat::Markdown => {
            let markdown = report.to_markdown();
            println!(
                "{}",
                if args.plain {
                    report::plainify(&markdown)
                } else {
                    markdown
                }
            );
        }
    }

    if !report.is_safe {
        std::process::exit(1);
    }

    Ok(())
}

/// Migrate a saved JSON report to [`crate::render::REPORT_SCHEMA_VERSION`] and
/// write it back out as canonical JSON.
///
/// Deterministic and idempotent (see [`crate::migration::upgrade_to_latest`]):
/// a document already at the latest version is re-emitted unchanged, steps
/// and all, so running this in a pipeline on every stored report is safe
/// regardless of which reports actually need upgrading.
fn run_upgrade_report(args: &UpgradeReportArgs) -> Result<()> {
    let raw = if args.report == Path::new("-") {
        std::io::read_to_string(std::io::stdin()).context("Failed to read report from stdin")?
    } else {
        std::fs::read_to_string(&args.report)
            .with_context(|| format!("Failed to read report file: {}", args.report.display()))?
    };

    let (report, record) = migration::upgrade_to_latest(&raw).with_context(|| {
        format!(
            "Failed to upgrade the saved report at '{}'",
            args.report.display()
        )
    })?;

    let json = serde_json::to_string_pretty(&report)?;

    match &args.output {
        Some(path) => {
            write_atomically(path, json.as_bytes()).with_context(|| {
                format!("Failed to write upgraded report to '{}'", path.display())
            })?;
        }
        None => println!("{json}"),
    }

    if record.steps.is_empty() {
        eprintln!(
            "Already at schema version {}; nothing to migrate.",
            record.migrated_to
        );
    } else {
        eprintln!(
            "Migrated from schema version {} to {} ({} step{}).",
            record.original_schema_version,
            record.migrated_to,
            record.steps.len(),
            if record.steps.len() == 1 { "" } else { "s" }
        );
    }

    Ok(())
}

/// Generate a suppression config from current findings.
fn run_init(args: &InitArgs) -> Result<()> {
    use std::fs;
    use std::io::Write;

    let config_path = Path::new(DEFAULT_CONFIG_FILE);

    // Check if config already exists
    if config_path.exists() && !args.force {
        anyhow::bail!(
            "{} already exists. Use --force to overwrite.",
            config_path.display()
        );
    }

    // Determine old and new sources
    let (old_source, new_source) = match (&args.old, &args.new, &args.contract_id) {
        (Some(old), Some(new), None) => (Ok(loader::load_wasm(old)?), Ok(loader::load_wasm(new)?)),
        (None, Some(new), Some(contract_id)) => {
            let rpc_url = args
                .rpc_url
                .as_ref()
                .expect("clap requires --rpc-url alongside --contract-id");
            (
                loader::fetch_wasm_from_rpc_with_config(
                    contract_id,
                    &rpc_config(rpc_url, &args.rpc_headers)?,
                ),
                loader::load_wasm(new),
            )
        }
        (Some(_), Some(_), Some(_)) => anyhow::bail!(
            "Provide either WASM paths or --contract-id, not both.\n\n\
             Usage: soroban-upgrade-safeguard init <OLD_WASM> <NEW_WASM>\n       \
             soroban-upgrade-safeguard init --contract-id <ID> --rpc-url <URL> <NEW_WASM>"
        ),
        _ => anyhow::bail!(
            "Missing WASM paths.\n\n\
             Usage: soroban-upgrade-safeguard init <OLD_WASM> <NEW_WASM>\n       \
             soroban-upgrade-safeguard init --contract-id <ID> --rpc-url <URL> <NEW_WASM>"
        ),
    };

    let old = old_source?;
    let new = new_source?;

    // Extract metadata and compare
    let old_meta = parser::extract_metadata(&old.bytes)?;
    let old_spec = spec::ContractSpec::from_entries(&old_meta.spec);

    let new_meta = parser::extract_metadata(&new.bytes)?;
    let new_spec = spec::ContractSpec::from_entries(&new_meta.spec);

    // Generate diff
    let mut diff_report = diff::compare(&old_spec, &new_spec);
    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );
    diff::compare_host_imports(
        &old_meta.host_imports,
        &new_meta.host_imports,
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );
    diff::compare_runtime_surfaces(
        &old_meta.runtime_surface,
        &new_meta.runtime_surface,
        &mut diff_report,
    );

    // Collect unsuppressed findings (with empty suppression config)
    let empty_suppressions = SuppressionConfig::default();
    let safety_report = report::SafetyReport::with_suppressions_with_specs(
        &diff_report,
        &empty_suppressions,
        false,
        false,
        &old_spec,
        &new_spec,
    );

    // Extract findings from the report
    let mut findings: Vec<(String, String)> = Vec::new();

    // Extract from findings_by_category
    for (category, reported_findings) in safety_report.findings_by_category.iter() {
        for finding in reported_findings {
            // Skip suppressed findings (none will be suppressed with empty config)
            if !finding.suppressed {
                let target = finding
                    .finding
                    .target
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                findings.push((category.clone(), target));
            }
        }
    }

    // Generate config content
    let mut content = String::new();
    content.push_str("# Auto-generated suppression config\n");
    content.push_str("# This file was generated by `soroban-upgrade-safeguard init`.\n");
    content.push_str("# Each suppression entry requires a reason to be filled in.\n");
    content.push_str("# Remove the '#' to uncomment and activate each suppression.\n\n");

    if findings.is_empty() {
        content.push_str("# No findings found. Your contracts are compatible!\n");
        content.push_str("# No suppression entries needed.\n");
    } else {
        content.push_str("# Suppressions are commented out by default. Edit this file and\n");
        content.push_str("# remove the '#' before each [[suppress]] block you want to apply.\n\n");

        for (category, target) in &findings {
            content.push_str(&format!(
                "# [[suppress]]\n\
                 # category = \"{}\"\n\
                 # target = \"{}\"\n\
                 # reason = \"TODO: Add justification for suppressing this rule.\"\n\n",
                category, target
            ));
        }
    }

    // Write the file
    let mut file = fs::File::create(config_path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;

    println!("✅ Generated {}", config_path.display());
    println!("📝 Found {} finding(s) requiring attention", findings.len());
    if findings.is_empty() {
        println!("🎉 No compatibility issues detected. No suppressions needed.");
    } else {
        println!(
            "📝 Please edit {} and add a valid reason for each suppression entry you want to apply.",
            config_path.display()
        );
        println!("   Remove the '#' before each [[suppress]] block to activate it.");
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.clear_remote_cache {
        let dir = args
            .remote_cache_dir
            .clone()
            .unwrap_or_else(remote::default_cache_dir);
        remote::clear_cache(&dir)
            .with_context(|| format!("Failed to clear remote cache at '{}'", dir.display()))?;
        if !args.quiet {
            println!("Cleared remote artifact cache at '{}'", dir.display());
        }
        return Ok(());
    }

    if args.clear_oci_cache {
        let dir = args
            .oci_cache_dir
            .clone()
            .unwrap_or_else(oci::default_cache_dir);
        oci::clear_cache(&dir)
            .with_context(|| format!("Failed to clear OCI cache at '{}'", dir.display()))?;
        if !args.quiet {
            println!("Cleared OCI artifact cache at '{}'", dir.display());
        }
        return Ok(());
    }

    match &args.command {
        Some(Command::Extract(extract_args)) => return run_extract(extract_args),
        Some(Command::Lockfile(lockfile_args)) => return run_lockfile(lockfile_args),
        Some(Command::Render(render_args)) => return run_render(render_args),
        Some(Command::UpgradeReport(upgrade_args)) => return run_upgrade_report(upgrade_args),
        Some(Command::Init(init_args)) => return run_init(init_args),
        Some(Command::Attest(attest_args)) => return run_attest(attest_args),
        Some(Command::VerifyAttestation(verify_args)) => {
            return run_verify_attestation(verify_args)
        }
        Some(Command::Stream(stream_args)) => return run_stream(stream_args),
        Some(Command::Lint(lint_args)) => return run_lint(lint_args),
        Some(Command::Preflight(preflight_args)) => return run_preflight(preflight_args),
        None => {}
    }

    if should_disable_color(
        args.no_color || args.plain,
        args.color,
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    ) {
        colored::control::set_override(false);
    } else if args.color == ColorMode::Always {
        colored::control::set_override(true);
    }

    // Config-validation mode: check a suppression config on its own and exit,
    // before any WASM inputs are required.
    if let Some(path) = &args.validate_config {
        return validate_suppression_config(path);
    }

    let is_batch = args.manifest.is_some() || (args.old_dir.is_some() && args.new_dir.is_some());

    if args.manifest.is_some() && (args.old_dir.is_some() || args.new_dir.is_some()) {
        anyhow::bail!("Cannot specify both --manifest and --old-dir/--new-dir at the same time");
    }

    if is_batch && !args.wasm_paths.is_empty() {
        anyhow::bail!("Cannot specify positional WASM paths when using batch mode (--manifest or --old-dir/--new-dir)");
    }

    if args.interface_lockfile.is_some() && is_batch {
        anyhow::bail!("Cannot use --interface-lockfile with batch mode");
    }
    if args.interface_lockfile.is_some() && args.contract_id.is_some() {
        anyhow::bail!("Cannot use --interface-lockfile with --contract-id; the lockfile supplies the baseline");
    }
    if args.interface_lockfile.is_some() && (args.empirical || args.empirical_file.is_some()) {
        anyhow::bail!("Cannot use empirical validation with --interface-lockfile");
    }

    // Manifest-resolution mode: show how the composition resolved and exit,
    // before any WASM is required. Makes a manifest reviewable on its own.
    if args.explain_manifest {
        let manifest_path = args
            .manifest
            .as_ref()
            .expect("--explain-manifest requires --manifest (enforced by clap)");
        let resolved = manifest::resolve(manifest_path, &cli_settings(&args)?)?;
        print!("{}", resolved.explain_text());
        return Ok(());
    }

    // Determine stdout format: use --format if given, or "text" as default
    // (only used when no --output flags target stdout).
    let stdout_format = args.format.unwrap_or(OutputFormat::Text);

    // Build the list of outputs:
    // - If --format is given and no --output targets stdout, add stdout output for --format.
    // - If no --output at all, fallback to --format (or Text) to stdout.
    let outputs: Vec<OutputSpec> = if !args.output.is_empty() {
        // User specified explicit outputs; --format still controls stdout if not
        // already covered by an --output spec.
        let has_stdout = args.output.iter().any(|o| o.path.is_none());
        let has_inherited_file = args.output.iter().any(|o| o.inherit_format);
        let mut outputs = args.output.clone();
        for output in &mut outputs {
            if output.inherit_format {
                output.format = stdout_format;
            }
        }
        if args.format.is_some() && !has_stdout && !has_inherited_file {
            // Add --format (or text) as stdout output
            outputs.push(OutputSpec {
                format: stdout_format,
                path: None,
                inherit_format: false,
            });
        }
        outputs
    } else {
        vec![OutputSpec {
            format: stdout_format,
            path: None,
            inherit_format: false,
        }]
    };

    let has_non_stdout = outputs.iter().any(|o| o.path.is_some());
    // Decorative progress goes to stderr when stdout is clean (JSON/Markdown to file
    // or when stdout format would produce a clean document), or when any file output
    // is requested alongside stdout in a clean format.
    let stdout_is_clean = outputs.iter().any(|o| {
        o.path.is_none()
            && matches!(
                o.format,
                OutputFormat::Json | OutputFormat::Markdown | OutputFormat::GithubActions
            )
    });
    let clean_stdout = stdout_is_clean || has_non_stdout;
    let progress = |line: String| {
        if args.quiet {
            return;
        }
        if clean_stdout {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    let (suppressions, config_source) = load_suppressions(
        args.no_config,
        args.config.as_deref(),
        args.search_parent_config,
    )?;
    if let Some((path, source)) = &config_source {
        progress(format!(
            "Suppression config: {} (source: {source})",
            path.display()
        ));
    }

    if is_batch {
        // Batch mode resolves its suppression config per pair; the eager load
        // above still runs so an unreadable --config fails before any analysis.
        return run_batch(&args, &outputs, &progress);
    }

    run_single(&args, &outputs, &suppressions, &progress)
}

fn run_batch(args: &Args, outputs: &[OutputSpec], progress: &dyn Fn(String)) -> Result<()> {
    let cli = cli_settings(args)?;

    // Manifest mode resolves includes, defaults and per-pair overrides up front —
    // including duplicate-identity detection, so a collision fails before any
    // pair runs rather than mid-loop with earlier reports already on disk.
    let (resolved_manifest, pairs, mut gaps, new_only) = if let Some(manifest_path) = &args.manifest
    {
        let resolved = manifest::resolve(manifest_path, &cli)?;
        let pairs: Vec<BatchPair> = resolved
            .pairs
            .iter()
            .cloned()
            .map(BatchPair::from)
            .collect();
        // A manifest names both sides of every pair explicitly, so there is no
        // directory to sweep and no such thing as an unmatched artifact.
        (Some(resolved), pairs, Vec::new(), Vec::new())
    } else {
        let settings = manifest::cli_only_settings(&cli);
        let (pairs, gaps, new_only) = scan_directories(
            args.old_dir.as_ref().unwrap(),
            args.new_dir.as_ref().unwrap(),
            &settings,
        )?;
        (None, pairs, gaps, new_only)
    };

    if args.per_contract_output_dir.is_some() {
        validate_template(&args.per_contract_output_name_template)?;

        let format = args.format.unwrap_or(OutputFormat::Text);
        let ext = match format {
            OutputFormat::Json => "json",
            OutputFormat::Markdown => "md",
            OutputFormat::Text => "txt",
            OutputFormat::GithubActions => "txt",
        };

        let mut seen = std::collections::HashMap::new();
        for pair in &pairs {
            let filename = evaluate_template(
                &args.per_contract_output_name_template,
                &pair.name,
                &pair.id,
                ext,
            )?;
            if let Some(other) = seen.insert(filename.clone(), format!("pair '{}'", pair.name)) {
                anyhow::bail!(
                    "Output filename collision: both pair '{}' and {} resolve to the same filename '{}'",
                    pair.name, other, filename
                );
            }
        }
        for gap in &gaps {
            let filename = evaluate_template(
                &args.per_contract_output_name_template,
                &gap.name,
                &gap.name,
                ext,
            )?;
            if let Some(other) = seen.insert(filename.clone(), format!("gap '{}'", gap.name)) {
                anyhow::bail!(
                    "Output filename collision: both gap '{}' and {} resolve to the same filename '{}'",
                    gap.name, other, filename
                );
            }
        }
    }
    let remote_config = remote_fetch_config(args);
    let oci_config = oci_fetch_config(args);
    let width = resolve_text_width(args.width, std::io::stdout().is_terminal());

    // Suppression configs are shared across pairs far more often than not.
    let mut config_cache: std::collections::HashMap<PathBuf, SuppressionConfig> =
        std::collections::HashMap::new();

    progress("🔍 Soroban Upgrade Safeguard (Batch Mode)".to_string());
    progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());
    progress(format!(
        "Loaded {} pair(s) for comparison. {} old-only contract(s) will be flagged.\n",
        pairs.len(),
        gaps.len()
    ));

    // New-only artifacts are reported here and nowhere else. They are not
    // comparison pairs: they never enter `results`, never claim a slot in the
    // `[n/total]` counter, and never move the verdict — there is no old build to
    // judge them against. This goes to stderr rather than through `progress`
    // because it is a diagnostic, not narration, and `--quiet` exists to silence
    // the latter; a likely naming mistake should still reach a quiet CI log.
    if !new_only.is_empty() {
        eprintln!(
            "Warning: {} .wasm file(s) in the new directory have no counterpart in \
             the old directory and were not compared:",
            new_only.len()
        );
        for contract in &new_only {
            eprintln!("  - {} ({})", contract.name, contract.new_path.display());
        }
        eprintln!(
            "  A new contract is expected here; a renamed one is not. If any of these \
             is a rename, the old-side file must share its name for the upgrade to be \
             checked."
        );
    }

    let mut results = Vec::new();
    let mut overall_safe = true;
    let mut seen_names = std::collections::BTreeSet::new();
    let gap_count = gaps.len();
    let total = pairs.len() + gap_count;

    // Process each gap (old contract missing from new directory) as a Critical failure
    for gap in gaps.drain(..) {
        if !seen_names.insert(gap.name.clone()) {
            anyhow::bail!(
                "Duplicate contract name '{}' found in batch input; names must be unique",
                gap.name
            );
        }
        progress(format!(
            "📦 [{}/{}] Gap: '{}' exists in old directory but NOT in new directory",
            results.len() + 1,
            total,
            gap.name.bold().red()
        ));

        let gap_report = report::SafetyReport {
            call_abi: soroban_upgrade_safeguard::CallAbiCompatibility::default(),
            critical_count: 1,
            warning_count: 0,
            info_count: 0,
            suppressed_count: 0,
            suppressed_critical_count: 0,
            suppressed_warning_count: 0,
            suppressed_info_count: 0,
            total_findings: 1,
            is_safe: false,
            strict: args.strict,
            critical_root_count: 1,
            cascade_critical_count: 0,
            rpc_provenance: None,
            old_symlink: None,
            new_symlink: None,
            old_interface_hash: None,
            new_interface_hash: None,
            no_timestamp: args.no_timestamp,
            old_spec_summary: None,
            new_spec_summary: Some("(contract missing from new deployment)".to_string()),
            scope: report::AnalysisScope::default(),
            metrics: None,
            axis_verdicts: {
                let mut verdicts = std::collections::HashMap::new();
                verdicts.insert(diff::CompatibilityAxis::CallAbi, report::AxisStatus::Failed);
                verdicts.insert(
                    diff::CompatibilityAxis::StorageLayout,
                    report::AxisStatus::Passed,
                );
                verdicts.insert(
                    diff::CompatibilityAxis::EventIndexer,
                    report::AxisStatus::Passed,
                );
                verdicts.insert(
                    diff::CompatibilityAxis::SourceLevel,
                    report::AxisStatus::Passed,
                );
                verdicts.insert(
                    diff::CompatibilityAxis::RuntimeSurface,
                    report::AxisStatus::Passed,
                );
                verdicts
            },
            gated_axes: {
                let mut gated = std::collections::HashSet::new();
                gated.insert(diff::CompatibilityAxis::CallAbi);
                gated.insert(diff::CompatibilityAxis::StorageLayout);
                gated.insert(diff::CompatibilityAxis::RuntimeSurface);
                gated
            },
            findings_by_category: {
                let mut map = std::collections::HashMap::new();
                map.insert(
                    "contract-missing-from-new".to_string(),
                    vec![report::ReportedFinding {
                        rule_id: "contract_missing_from_new".to_string(),
                        finding: diff::Finding {
                            severity: diff::Severity::Critical,
                            axes: vec![diff::CompatibilityAxis::CallAbi],
                            category: "contract-missing-from-new".to_string(),
                            message: format!(
                                "'{}' exists in the old directory but was not found in the new directory. \
                                 This contract would be removed from the deployment, breaking all clients \
                                 that depend on it.",
                                gap.name
                            ),
                            type_name: None,
                            target: Some(gap.name.clone()),
                            root_target: None,
                        },
                        axes: vec![diff::CompatibilityAxis::CallAbi],
                        suppressed: false,
                        suppression_reason: None,
                        remediation: Some(format!(
                            "Ensure the .wasm for '{}' is present in the new directory, or add it to \
                             the --suppressions file if removal is intentional.",
                            gap.name
                        )),
                    }],
                );
                map
            },
            empirical: false,
            empirical_findings: Vec::new(),
            budget_violations: Vec::new(),
            settings: report::ReportSettings::default(),
        };

        let file_outputs: Vec<OutputSpec> = outputs
            .iter()
            .filter(|output| output.path.is_some())
            .cloned()
            .collect();
        render_to_outputs(
            &gap_report,
            &file_outputs,
            args.explain,
            args.ascii,
            args.plain,
            width,
            Some(&gap.name),
            progress,
        )?;

        if let Some(output_dir) = args.per_contract_output_dir.as_deref() {
            let content = render_single(
                &gap_report,
                args.format.unwrap_or(OutputFormat::Text),
                args.explain,
                args.ascii,
                args.plain,
                width,
            )?;
            write_report_file(
                output_dir,
                &gap.name,
                &gap.name,
                &args.per_contract_output_name_template,
                args.format.unwrap_or(OutputFormat::Text),
                &content,
            )?;
        }

        results.push(BatchResult::Error {
            id: gap.name.clone(),
            name: gap.name,
            labels: Vec::new(),
            old_path: gap.old_path,
            new_path: None,
            old_storage_schema: None,
            new_storage_schema: None,
            error: "contract is missing from the new deployment".to_string(),
            report: gap_report,
        });
        overall_safe = false;
    }

    // Process each regular pair with error-handling (per-pair failures do not abort the batch)
    for (i, pair) in pairs.iter().enumerate() {
        let contract_name = pair.name.clone();
        let contract_id = pair.id.clone();
        let contract_labels = pair.labels.clone();
        let settings = &pair.settings;
        let pair_suppressions = suppressions_for_pair(settings, &mut config_cache)?;
        let explain = settings.explain.value;
        let ascii = settings.ascii.value || args.ascii;
        let plain = args.plain;

        if !seen_names.insert(contract_name.clone()) {
            anyhow::bail!(
                "Duplicate contract name '{}' found in batch input; names must be unique",
                contract_name
            );
        }

        progress(format!(
            "📦 [{}/{}] Comparing contract pair: {}",
            i + 1 + gaps.len(),
            total,
            contract_name.bold()
        ));

        let mut pair_error = None;
        let report = match (
            load_wasm_input(
                &pair.old,
                &remote_config,
                &oci_config,
                args.no_symlinks,
                progress,
            ),
            load_wasm_input(
                &pair.new,
                &remote_config,
                &oci_config,
                args.no_symlinks,
                progress,
            ),
        ) {
            (Ok(old_wasm), Ok(new_wasm)) => {
                match load_pair_storage_schemas(pair).and_then(|storage_schemas| {
                    if let Some(storage_schemas) = storage_schemas.as_ref() {
                        let mut report =
                            soroban_upgrade_safeguard::compare_wasm_bytes_with_options(
                                &old_wasm.bytes,
                                &new_wasm.bytes,
                                &soroban_upgrade_safeguard::CompareOptions {
                                    suppressions: Some(&pair_suppressions),
                                    explain,
                                    strict: settings.strict.value,
                                    storage_schemas: Some((
                                        &storage_schemas.old,
                                        &storage_schemas.new,
                                    )),
                                    lineage_store: None,
                                },
                            )?;
                        report.set_no_timestamp(settings.no_timestamp.value);
                        Ok(report)
                    } else {
                        compare_contracts(
                            &ContractComparison {
                                old_bytes: &old_wasm.bytes,
                                old_path: &old_wasm.path,
                                new_bytes: &new_wasm.bytes,
                                new_path: &new_wasm.path,
                                suppressions: &pair_suppressions,
                                explain,
                                strict: settings.strict.value,
                                no_timestamp: settings.no_timestamp.value,
                                empirical: args.empirical || args.empirical_file.is_some(),
                                empirical_file: args.empirical_file.as_deref(),
                                contract_id: None,
                                rpc_url: None,
                                rpc_headers: &args.rpc_headers,
                                rpc_allow_id_mismatch: args.rpc_allow_id_mismatch,
                                lineage_store: None,
                            },
                            progress,
                        )
                    }
                }) {
                    Ok(report) => {
                        report.with_symlinks(old_wasm.symlink.clone(), new_wasm.symlink.clone())
                    }
                    Err(e) => {
                        pair_error = Some(e.to_string());
                        progress(format!(
                            "  ⚠️  Comparison failed for '{}': {}",
                            contract_name,
                            e.to_string().red()
                        ));
                        synthesize_error_report(
                            &contract_name,
                            &e.to_string(),
                            settings.strict.value,
                            settings.no_timestamp.value,
                        )
                        .with_symlinks(old_wasm.symlink.clone(), new_wasm.symlink.clone())
                    }
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                pair_error = Some(e.to_string());
                progress(format!(
                    "  ⚠️  Failed to load contract files for '{}': {}",
                    contract_name,
                    e.to_string().red()
                ));
                synthesize_error_report(
                    &contract_name,
                    &e.to_string(),
                    settings.strict.value,
                    settings.no_timestamp.value,
                )
            }
        };

        if !report.is_safe() {
            overall_safe = false;
        }

        let file_outputs: Vec<OutputSpec> = outputs
            .iter()
            .filter(|output| output.path.is_some())
            .cloned()
            .collect();
        render_to_outputs(
            &report,
            &file_outputs,
            explain,
            ascii,
            plain,
            width,
            Some(&contract_name),
            progress,
        )?;

        if let Some(output_dir) = args.per_contract_output_dir.as_deref() {
            let content = render_single(
                &report,
                args.format.unwrap_or(OutputFormat::Text),
                explain,
                ascii,
                plain,
                width,
            )?;
            write_report_file(
                output_dir,
                &contract_name,
                &contract_id,
                &args.per_contract_output_name_template,
                args.format.unwrap_or(OutputFormat::Text),
                &content,
            )?;
        }

        if let Some(error) = pair_error {
            results.push(BatchResult::Error {
                name: contract_name,
                id: contract_id,
                labels: contract_labels,
                old_path: pair.old.clone(),
                new_path: Some(pair.new.clone()),
                old_storage_schema: pair.old_storage_schema.clone(),
                new_storage_schema: pair.new_storage_schema.clone(),
                error,
                report,
            });
        } else {
            results.push(BatchResult::Success {
                name: contract_name,
                id: contract_id,
                labels: contract_labels,
                old_path: pair.old.clone(),
                new_path: pair.new.clone(),
                old_storage_schema: pair.old_storage_schema.clone(),
                new_storage_schema: pair.new_storage_schema.clone(),
                report,
            });
        }
        progress("\n----------------------------------------\n".to_string());
    }

    render_batch_summary(
        &BatchSummary {
            results: &results,
            overall_safe,
            total_pairs: total,
            strict: args.strict,
            ascii: args.ascii,
            plain: args.plain,
            width,
            resolved_manifest: resolved_manifest.as_ref(),
        },
        outputs,
        progress,
    )?;

    if !overall_safe {
        std::process::exit(1);
    }

    Ok(())
}

fn synthesize_error_report(
    name: &str,
    error_message: &str,
    strict: bool,
    no_timestamp: bool,
) -> report::SafetyReport {
    report::SafetyReport {
        call_abi: soroban_upgrade_safeguard::CallAbiCompatibility::default(),
        critical_count: 1,
        warning_count: 0,
        info_count: 0,
        suppressed_count: 0,
        suppressed_critical_count: 0,
        suppressed_warning_count: 0,
        suppressed_info_count: 0,
        total_findings: 1,
        is_safe: false,
        strict,
        critical_root_count: 1,
        cascade_critical_count: 0,
        rpc_provenance: None,
        old_symlink: None,
        new_symlink: None,
        old_interface_hash: None,
        new_interface_hash: None,
        no_timestamp,
        old_spec_summary: None,
        new_spec_summary: Some("(analysis failed)".to_string()),
        scope: report::AnalysisScope::default(),
        metrics: None,
        axis_verdicts: {
            let mut verdicts = std::collections::HashMap::new();
            verdicts.insert(diff::CompatibilityAxis::CallAbi, report::AxisStatus::Failed);
            verdicts.insert(
                diff::CompatibilityAxis::StorageLayout,
                report::AxisStatus::Passed,
            );
            verdicts.insert(
                diff::CompatibilityAxis::EventIndexer,
                report::AxisStatus::Passed,
            );
            verdicts.insert(
                diff::CompatibilityAxis::SourceLevel,
                report::AxisStatus::Passed,
            );
            verdicts.insert(
                diff::CompatibilityAxis::RuntimeSurface,
                report::AxisStatus::Passed,
            );
            verdicts
        },
        gated_axes: {
            let mut gated = std::collections::HashSet::new();
            gated.insert(diff::CompatibilityAxis::CallAbi);
            gated.insert(diff::CompatibilityAxis::StorageLayout);
            gated.insert(diff::CompatibilityAxis::RuntimeSurface);
            gated
        },
        findings_by_category: {
            let mut map = std::collections::HashMap::new();
            map.insert(
                "analysis-error".to_string(),
                vec![report::ReportedFinding {
                    rule_id: "analysis_error".to_string(),
                    finding: diff::Finding {
                        severity: diff::Severity::Critical,
                        axes: vec![diff::CompatibilityAxis::CallAbi],
                        category: "analysis-error".to_string(),
                        message: format!(
                            "Analysis of '{}' failed: {}", name, error_message
                        ),
                        type_name: None,
                        target: Some(name.to_string()),
                        root_target: None,
                    },
                    axes: vec![diff::CompatibilityAxis::CallAbi],
                    suppressed: false,
                    suppression_reason: None,
                    remediation: Some(
                        "Check the contract paths and ensure both WASM files exist and are valid Soroban contracts.".to_string()
                    ),
                }],
            );
            map
        },
        empirical: false,
        empirical_findings: Vec::new(),
        budget_violations: Vec::new(),
        settings: report::ReportSettings::default(),
    }
}

/// Everything the batch summary renders from.
///
/// Grouped into a struct rather than passed positionally, following
/// [`ContractComparison`] — the batch verdict, the per-contract reports, and the
/// manifest provenance are three different things and reading them by name at
/// the call site is worth more than the brevity.
enum BatchResult {
    Success {
        name: String,
        /// Stable identifier for CI annotations and reruns. See
        /// [`manifest::ResolvedPair::id`].
        id: String,
        /// Free-form grouping tags. See [`manifest::ResolvedPair::labels`].
        labels: Vec<String>,
        old_path: PathBuf,
        new_path: PathBuf,
        old_storage_schema: Option<PathBuf>,
        new_storage_schema: Option<PathBuf>,
        report: report::SafetyReport,
    },
    Error {
        name: String,
        id: String,
        labels: Vec<String>,
        old_path: PathBuf,
        new_path: Option<PathBuf>,
        old_storage_schema: Option<PathBuf>,
        new_storage_schema: Option<PathBuf>,
        error: String,
        report: report::SafetyReport,
    },
}

impl BatchResult {
    fn name(&self) -> &str {
        match self {
            Self::Success { name, .. } | Self::Error { name, .. } => name,
        }
    }

    fn labels(&self) -> &[String] {
        match self {
            Self::Success { labels, .. } | Self::Error { labels, .. } => labels,
        }
    }

    fn id(&self) -> &str {
        match self {
            Self::Success { id, .. } | Self::Error { id, .. } => id,
        }
    }

    fn report(&self) -> &report::SafetyReport {
        match self {
            Self::Success { report, .. } | Self::Error { report, .. } => report,
        }
    }

    fn coverage(&self) -> &str {
        match self {
            Self::Error { .. } => "error",
            Self::Success { .. } => {
                if self.report().scope().storage_analyzed() {
                    "schema-backed"
                } else {
                    "interface-only"
                }
            }
        }
    }

    /// This result's stable verdict category for the batch summary. Every
    /// result maps to exactly one, checked in priority order: a pair-level
    /// failure is always `Errored` regardless of what its synthesized report
    /// says; otherwise breaking changes make it `Unsafe` regardless of
    /// coverage; otherwise a report produced without a storage schema
    /// (interface-only) is `Incomplete` — safe as far as it could check, but
    /// not fully verified; anything else is `Safe`.
    fn verdict(&self) -> BatchVerdict {
        match self {
            Self::Error { .. } => BatchVerdict::Errored,
            Self::Success { report, .. } => {
                if !report.is_safe() {
                    BatchVerdict::Unsafe
                } else if !report.scope().storage_analyzed() {
                    BatchVerdict::Incomplete
                } else {
                    BatchVerdict::Safe
                }
            }
        }
    }
}

/// Stable, machine-readable batch-verdict categories. `as_str()` values are
/// part of the JSON output's public shape — do not rename without treating it
/// as a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchVerdict {
    /// No breaking changes, and storage layout was fully verified against a
    /// declared schema.
    Safe,
    /// Breaking changes were found (the report itself reports unsafe).
    Unsafe,
    /// The pair itself failed to produce a report (e.g. a load or schema
    /// error) — no verdict on compatibility was reached at all.
    Errored,
    /// No breaking changes were found, but coverage was reduced: no storage
    /// schema was declared, so storage-layout compatibility is interface-only
    /// rather than fully verified.
    Incomplete,
}

impl BatchVerdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Unsafe => "unsafe",
            Self::Errored => "errored",
            Self::Incomplete => "incomplete",
        }
    }
}

/// Compact counts of pair outcomes, grouped by [`BatchVerdict`]. Rendered as
/// a summary section before the detailed per-pair results in every aggregate
/// output format (text, Markdown, JSON). Purely a tally over existing
/// [`BatchResult`]s — it does not alter any per-pair finding or report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct BatchVerdictSummary {
    safe: usize,
    unsafe_count: usize,
    errored: usize,
    incomplete: usize,
}

impl BatchVerdictSummary {
    fn from_results(results: &[BatchResult]) -> Self {
        let mut summary = Self::default();
        for result in results {
            match result.verdict() {
                BatchVerdict::Safe => summary.safe += 1,
                BatchVerdict::Unsafe => summary.unsafe_count += 1,
                BatchVerdict::Errored => summary.errored += 1,
                BatchVerdict::Incomplete => summary.incomplete += 1,
            }
        }
        summary
    }

    fn total(&self) -> usize {
        self.safe + self.unsafe_count + self.errored + self.incomplete
    }

    fn to_json(self) -> serde_json::Value {
        // Keys are written as literals (rather than through `BatchVerdict::as_str()`)
        // so they stay simple, direct `json!` object keys; `verdict_key_matches_as_str`
        // guards the two from silently drifting apart.
        serde_json::json!({
            "safe": self.safe,
            "unsafe": self.unsafe_count,
            "errored": self.errored,
            "incomplete": self.incomplete,
            "total": self.total(),
        })
    }

    /// One-line rendering shared by the text and Markdown renderers:
    /// `2 safe, 1 unsafe, 1 errored, 1 incomplete (5 total)`.
    fn to_line(self) -> String {
        format!(
            "{} {}, {} {}, {} {}, {} {} ({} total)",
            self.safe,
            BatchVerdict::Safe.as_str(),
            self.unsafe_count,
            BatchVerdict::Unsafe.as_str(),
            self.errored,
            BatchVerdict::Errored.as_str(),
            self.incomplete,
            BatchVerdict::Incomplete.as_str(),
            self.total()
        )
    }
}

struct BatchSummary<'a> {
    results: &'a [BatchResult],
    overall_safe: bool,
    total_pairs: usize,
    /// The run-level `--strict` flag. Per-pair strictness lives in the manifest
    /// provenance; this is the CLI's own setting.
    strict: bool,
    ascii: bool,
    plain: bool,
    /// Resolved wrap width for text-format finding messages; see
    /// [`resolve_text_width`]. Has no effect on JSON or Markdown output.
    width: Option<usize>,
    /// `None` for directory-scan runs, which have no composition to describe.
    resolved_manifest: Option<&'a manifest::ResolvedManifest>,
}

fn render_batch_summary(
    summary: &BatchSummary<'_>,
    outputs: &[OutputSpec],
    progress: &dyn Fn(String),
) -> Result<()> {
    let BatchSummary {
        results,
        overall_safe,
        total_pairs,
        strict,
        ascii,
        plain,
        width,
        resolved_manifest,
    } = *summary;

    let verdict_summary = BatchVerdictSummary::from_results(results);

    for output in outputs {
        let content = match output.format {
            OutputFormat::Json => {
                let mut results_json = Vec::new();
                for result in results {
                    let mut entry = serde_json::json!({
                        "name": result.name(),
                        "id": result.id(),
                        "labels": result.labels(),
                        "coverage": result.coverage(),
                        "report": result.report().to_json(),
                    });
                    let object = entry
                        .as_object_mut()
                        .expect("batch result entry is an object");
                    match result {
                        BatchResult::Success {
                            old_path,
                            new_path,
                            old_storage_schema,
                            new_storage_schema,
                            ..
                        } => {
                            object.insert("old".to_string(), json_path(old_path));
                            object.insert("new".to_string(), json_path(new_path));
                            object.insert(
                                "old_storage_schema".to_string(),
                                json_path_opt(old_storage_schema.as_deref()),
                            );
                            object.insert(
                                "new_storage_schema".to_string(),
                                json_path_opt(new_storage_schema.as_deref()),
                            );
                        }
                        BatchResult::Error {
                            old_path,
                            new_path,
                            old_storage_schema,
                            new_storage_schema,
                            error,
                            ..
                        } => {
                            object.insert("error".to_string(), serde_json::json!(error));
                            object.insert("old".to_string(), json_path(old_path));
                            object.insert("new".to_string(), json_path_opt(new_path.as_deref()));
                            object.insert(
                                "old_storage_schema".to_string(),
                                json_path_opt(old_storage_schema.as_deref()),
                            );
                            object.insert(
                                "new_storage_schema".to_string(),
                                json_path_opt(new_storage_schema.as_deref()),
                            );
                        }
                    }
                    results_json.push(entry);
                }
                let mut batch_json = serde_json::json!({
                    "is_safe": overall_safe,
                    "strict": strict,
                    "total_pairs": total_pairs,
                    "summary": verdict_summary.to_json(),
                    "results": results_json,
                });
                // Only manifest runs have a composition to describe; directory
                // scans leave the key absent rather than emitting an empty one.
                if let Some(resolved) = resolved_manifest {
                    batch_json
                        .as_object_mut()
                        .expect("batch_json is constructed as an object")
                        .insert("manifest".to_string(), resolved.to_json());
                }
                serde_json::to_string_pretty(&batch_json)?
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

                markdown.push_str("### Verdict Summary\n\n");
                markdown.push_str("| Safe | Unsafe | Errored | Incomplete | Total |\n");
                markdown.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
                markdown.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n\n",
                    verdict_summary.safe,
                    verdict_summary.unsafe_count,
                    verdict_summary.errored,
                    verdict_summary.incomplete,
                    verdict_summary.total()
                ));

                markdown.push_str("### Summary\n\n");
                markdown.push_str(
                    "| Contract | Status | Scope | Coverage | Critical | Warning | Info | Suppressed | Labels |\n",
                );
                markdown
                    .push_str("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n");

                for result in results {
                    let report = result.report();
                    let status_str = if report.is_safe() {
                        "✅ PASSED"
                    } else {
                        "❌ FAILED"
                    };
                    markdown.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                        result.name(),
                        status_str,
                        report.scope().summary_line(),
                        result.coverage(),
                        report.critical_count(),
                        report.warning_count(),
                        report.info_count(),
                        report.suppressed_count(),
                        format_labels(result.labels(), "-")
                    ));
                }

                markdown.push_str("\n---\n\n");

                for result in results {
                    markdown.push_str(&format!("## Details: {}\n\n", result.name()));
                    if !result.labels().is_empty() {
                        markdown.push_str(&format!(
                            "**Labels**: {}\n\n",
                            format_labels(result.labels(), "")
                        ));
                    }
                    let report = result.report();
                    if let BatchResult::Error { error, .. } = result {
                        markdown.push_str(&format!("**Pair error**: `{}`\n\n", error));
                    }
                    let report_md = report.generate_summary_markdown();
                    let stripped_md = report_md.replace("# Soroban Upgrade Safety Report\n\n", "");
                    markdown.push_str(&stripped_md);
                    markdown.push_str("\n---\n\n");
                }

                // Convert the summary status markers this arm added directly
                // (the inner detail sections were already rendered ASCII above).
                markdown = destyle_text(markdown, ascii, plain);
                markdown
            }
            OutputFormat::Text => {
                let mut text = String::new();
                text.push_str("========================================\n");
                text.push_str("    SOROBAN BATCH SAFETY REPORT\n");
                text.push_str("========================================\n");
                let status = if overall_safe {
                    "✅ PASSED (All contracts safe)".green().bold().to_string()
                } else {
                    "❌ FAILED (Some contracts have breaking changes)"
                        .red()
                        .bold()
                        .to_string()
                };
                text.push_str(&format!("Overall Status: {}\n\n", status));
                text.push_str(&format!(
                    "Verdict Summary: {}\n\n",
                    verdict_summary.to_line()
                ));
                text.push_str("Summary of Contracts:\n");
                for result in results {
                    let report = result.report();
                    let status_str = if report.is_safe() {
                        "✅ PASSED".green().to_string()
                    } else {
                        "❌ FAILED".red().bold().to_string()
                    };
                    let labels_suffix = if result.labels().is_empty() {
                        String::new()
                    } else {
                        format!(" {{{}}}", format_labels(result.labels(), ""))
                    };
                    text.push_str(&format!(
                        "  - {}: {} [{}; {}] ({} critical, {} warnings, {} info, {} suppressed){}\n",
                        result.name().bold(),
                        status_str,
                        report.scope().summary_line(),
                        result.coverage(),
                        report.critical_count(),
                        report.warning_count(),
                        report.info_count(),
                        report.suppressed_count(),
                        labels_suffix
                    ));
                }

                text.push_str("\n========================================\n\n");

                for result in results {
                    let report = result.report();
                    text.push_str(&format!(
                        "=== Contract: {} ===\n",
                        result.name().bold().magenta()
                    ));
                    if !result.labels().is_empty() {
                        text.push_str(&format!("Labels: {}\n", format_labels(result.labels(), "")));
                    }
                    if let BatchResult::Error { error, .. } = result {
                        text.push_str(&format!("Pair error: {}\n", error));
                    }
                    let detail = report.generate_summary_text_with_width(false, width);
                    text.push_str(&destyle_text(detail, ascii, plain));
                    text.push_str("========================================\n\n");
                }
                destyle_text(text, ascii, plain)
            }
            OutputFormat::GithubActions => {
                let mut output = String::new();
                for result in results {
                    output.push_str(&format!("::group::{}\n", result.name()));
                    let report = result.report();
                    output.push_str(&render_github_actions(report));
                    output.push_str("::endgroup::\n");
                }
                output.push_str(&format!(
                    "Soroban Upgrade Safeguard: {}\n",
                    if overall_safe { "PASSED" } else { "FAILED" }
                ));
                output
            }
        };

        emit_output(output, &content)?;
        if output.path.is_none() && output.format != OutputFormat::Text {
            progress(format!(
                "  {} batch report written to stdout",
                output.format.to_string().to_lowercase()
            ));
        } else if let Some(path) = &output.path {
            progress(format!(
                "  {} batch report written to {}",
                output.format,
                path.display()
            ));
        }
    }

    Ok(())
}

fn run_single(
    args: &Args,
    outputs: &[OutputSpec],
    suppressions: &SuppressionConfig,
    progress: &dyn Fn(String),
) -> Result<()> {
    if args.interface_lockfile.is_some() && args.wasm_paths.len() != 1 {
        anyhow::bail!("--interface-lockfile requires exactly one candidate WASM path");
    }

    let (old_source, new_wasm_path) = match (args.wasm_paths.len(), &args.contract_id) {
        (1, None) if args.interface_lockfile.is_some() => (None, &args.wasm_paths[0]),
        (2, None) => (None, &args.wasm_paths[1]),
        (1, Some(_)) => (args.contract_id.as_deref(), &args.wasm_paths[0]),
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

    if old_source.is_none()
        && is_stdin_wasm_path(&args.wasm_paths[0])
        && is_stdin_wasm_path(new_wasm_path)
    {
        anyhow::bail!(
            "Cannot use '-' for both OLD_WASM and NEW_WASM because stdin can only be read once. \
             Provide one side as a file path."
        );
    }

    // Collect the actual file paths for watch mode
    let watch_paths: Vec<PathBuf> = if args.watch {
        let mut paths = Vec::new();
        if !is_batch_mode(args) {
            if old_source.is_none() && !args.wasm_paths.is_empty() {
                let p = args.wasm_paths[0].clone();
                if !is_stdin_wasm_path(&p) {
                    paths.push(p);
                }
            }
            let p = new_wasm_path.clone();
            if !is_stdin_wasm_path(&p) {
                paths.push(p);
            }
        }
        paths
    } else {
        Vec::new()
    };

    let run_comparison = |progress: &dyn Fn(String)| -> Result<bool> {
        progress("🔍 Soroban Upgrade Safeguard".to_string());
        progress("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());

        progress(format!(
            "\n{}",
            "📦 Loading and Parsing contracts...".cyan().bold()
        ));

        let remote_config = remote_fetch_config(args);
        let oci_config = oci_fetch_config(args);

        let new = load_wasm_input(
            new_wasm_path,
            &remote_config,
            &oci_config,
            args.no_symlinks,
            progress,
        )?;

        let mut store_opt = if let Some(ref path) = args.lineage_store {
            let mut store = if path.exists() {
                soroban_upgrade_safeguard::lineage::LineageStore::load_from_path(path)?
            } else {
                soroban_upgrade_safeguard::lineage::LineageStore::new(
                    args.contract_id.clone(),
                    args.contract_id.clone(),
                )
            };
            if let Some(max_v) = args.max_live_versions {
                store.policy.max_live_versions = Some(max_v);
            }
            if let Some(ref ret_v) = args.retire_version {
                store.retire_version(ret_v)?;
            }
            Some(store)
        } else {
            None
        };

        let safety_report = if let Some(lockfile_path) = &args.interface_lockfile {
            let lockfile_json = std::fs::read_to_string(lockfile_path).with_context(|| {
                format!(
                    "Failed to read interface lockfile '{}'.",
                    lockfile_path.display()
                )
            })?;
            progress(format!(
                "\n🔒 Checking exported interface against {}...",
                lockfile_path.display()
            ));
            soroban_upgrade_safeguard::compare_wasm_against_interface_lockfile(
                &lockfile_json,
                &new.bytes,
                &soroban_upgrade_safeguard::CompareOptions {
                    suppressions: Some(suppressions),
                    explain: args.explain,
                    strict: args.strict,
                    storage_schemas: None,
                    lineage_store: store_opt.as_ref(),
                },
            )?
            .with_symlinks(None, new.symlink.clone())
        } else {
            let old = if let Some(contract_id) = old_source {
                let rpc_url = args.rpc_url.as_ref().unwrap();
                loader::fetch_wasm_from_rpc_with_config(
                    contract_id,
                    &rpc_config(rpc_url, &args.rpc_headers)?
                        .with_id_mismatch_allowed(args.rpc_allow_id_mismatch),
                )?
            } else {
                load_wasm_input(
                    &args.wasm_paths[0],
                    &remote_config,
                    &oci_config,
                    args.no_symlinks,
                    progress,
                )?
            };
            compare_contracts(
                &ContractComparison {
                    old_bytes: &old.bytes,
                    old_path: &old.path,
                    new_bytes: &new.bytes,
                    new_path: &new.path,
                    suppressions,
                    explain: args.explain,
                    strict: args.strict,
                    no_timestamp: args.no_timestamp,
                    empirical: args.empirical || args.empirical_file.is_some(),
                    empirical_file: args.empirical_file.as_deref(),
                    contract_id: old_source,
                    rpc_url: args.rpc_url.as_deref(),
                    rpc_headers: &args.rpc_headers,
                    rpc_allow_id_mismatch: args.rpc_allow_id_mismatch,
                    lineage_store: store_opt.as_ref(),
                },
                progress,
            )?
            .with_symlinks(old.symlink.clone(), new.symlink.clone())
        };

        if let (Some(ref mut store), Some(ref version_id), Some(ref path)) =
            (&mut store_opt, &args.record_version, &args.lineage_store)
        {
            let new_meta = parser::extract_metadata(&new.bytes)?;
            let new_spec = spec::ContractSpec::from_entries(&new_meta.spec);
            let extracted = ExtractedSpec::new(&new.path, &new_meta, &new_spec);
            let spec_json = canonical_json_bytes(&extracted)
                .ok()
                .and_then(|b| String::from_utf8(b).ok());

            let record = soroban_upgrade_safeguard::lineage::LineageRecord {
                version_id: version_id.clone(),
                order: 0,
                created_at: "2026-08-25T00:00:00Z".to_string(),
                status: soroban_upgrade_safeguard::lineage::LiveStatus::Live,
                wasm_hash: loader::sha256_hex(&new.bytes),
                interface_hash: soroban_upgrade_safeguard::interface_hash::InterfaceHash::of_spec(
                    &new_spec,
                )
                .to_hex(),
                spec_json,
                storage_schema: None,
                metadata: std::collections::BTreeMap::new(),
            };
            store.record_version(record)?;
            store.save_to_path(path)?;
            progress(format!(
                "📜 Lineage store updated and saved to {}",
                path.display()
            ));
        }

        render_to_outputs(
            &safety_report,
            outputs,
            args.explain,
            args.ascii,
            args.plain,
            resolve_text_width(args.width, std::io::stdout().is_terminal()),
            None,
            progress,
        )?;

        let is_safe = safety_report.is_safe();
        if !is_safe {
            return Ok(false);
        }
        Ok(true)
    };

    let cycle_counter = std::cell::Cell::new(0u64);
    let status_path = args.watch_status_file.clone();
    let run_comparison_tracked = move |progress: &dyn Fn(String)| -> Result<bool> {
        let cycle = cycle_counter.get() + 1;
        cycle_counter.set(cycle);
        let status = soroban_upgrade_safeguard::watch_status::WatchStatus::starting(cycle);
        if let Some(ref path) = status_path {
            if let Err(e) = status.write_to(path) {
                eprintln!(
                    "Warning: failed to write watch status file {}: {e}",
                    path.display()
                );
            }
        }
        let result = run_comparison(progress);
        if let Some(ref path) = status_path {
            let final_status = match &result {
                Ok(is_safe) => status.clone().completed(*is_safe),
                Err(e) => status.clone().failed(e.to_string()),
            };
            if let Err(write_err) = final_status.write_to(path) {
                eprintln!(
                    "Warning: failed to write watch status file {}: {write_err}",
                    path.display()
                );
            }
        }
        result
    };

    let is_safe = run_comparison_tracked(&progress)?;

    if args.watch && !watch_paths.is_empty() {
        run_watch_mode(
            &watch_paths,
            args,
            outputs,
            suppressions,
            args.watch_debounce_ms,
            args.watch_status_file.as_deref(),
            run_comparison_tracked,
        )?;
    } else if args.watch {
        eprintln!(
            "Warning: --watch requires local file paths (stdin or RPC sources not supported)"
        );
    }

    if !is_safe {
        std::process::exit(1);
    }

    Ok(())
}

/// Lower bound for `--watch-debounce-ms`. Below this, the burst of events a
/// build tool emits for a single logical change (e.g. write-to-temp-then-
/// rename) would each trigger a separate re-run instead of being coalesced.
const WATCH_DEBOUNCE_MIN_MS: u64 = 10;

/// Upper bound for `--watch-debounce-ms`. Above this, watch mode would feel
/// unresponsive to a genuine single-file edit.
const WATCH_DEBOUNCE_MAX_MS: u64 = 60_000;

/// Default debounce window, matching the fixed value watch mode used before
/// this option existed.
const DEFAULT_WATCH_DEBOUNCE_MS: u64 = 300;

fn parse_watch_debounce_ms(s: &str) -> Result<u64, String> {
    let ms: u64 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid number of milliseconds"))?;
    if !(WATCH_DEBOUNCE_MIN_MS..=WATCH_DEBOUNCE_MAX_MS).contains(&ms) {
        return Err(format!(
            "watch debounce must be between {WATCH_DEBOUNCE_MIN_MS}ms and \
             {WATCH_DEBOUNCE_MAX_MS}ms, got {ms}ms"
        ));
    }
    Ok(ms)
}

fn is_batch_mode(args: &Args) -> bool {
    args.manifest.is_some() || (args.old_dir.is_some() && args.new_dir.is_some())
}

#[allow(clippy::too_many_arguments)]
fn render_to_outputs(
    report: &report::SafetyReport,
    outputs: &[OutputSpec],
    explain: bool,
    ascii: bool,
    plain: bool,
    width: Option<usize>,
    contract_name: Option<&str>,
    progress: &dyn Fn(String),
) -> Result<()> {
    for output in outputs {
        let content = render_single(report, output.format, explain, ascii, plain, width)?;
        emit_output(output, &content)?;

        if let Some(ref path) = output.path {
            let label = contract_name
                .map(|n| format!("{}.{}", n, output.format.file_extension()))
                .unwrap_or_else(|| path.to_string_lossy().to_string());
            progress(format!("  {} report written to {}", output.format, label));
        }
    }
    Ok(())
}

/// Render a pair's labels as a comma-joined list, or `empty` (e.g. `"-"` for
/// a table cell, `""` to omit the line entirely) when there are none. Kept to
/// plain ASCII rather than an em dash so it survives `--plain` unchanged.
fn format_labels(labels: &[String], empty: &str) -> String {
    if labels.is_empty() {
        empty.to_string()
    } else {
        labels.join(", ")
    }
}

/// Render a path into batch JSON with display normalization applied (see
/// [`loader::normalize_path_display`]), rather than `PathBuf`'s own
/// `Serialize` (which would embed the OS-native separator the run happened
/// to use).
fn json_path(path: &Path) -> serde_json::Value {
    serde_json::Value::String(loader::normalize_path_display(&path.display().to_string()))
}

fn json_path_opt(path: Option<&Path>) -> serde_json::Value {
    match path {
        Some(path) => json_path(path),
        None => serde_json::Value::Null,
    }
}

/// Resolve the wrap width for text-format finding messages.
///
/// `explicit` (`--width`) always wins, clamped up to
/// [`render::MIN_TEXT_WIDTH`]: a mistakenly tiny value is widened to a still
/// narrow but readable floor rather than rejected outright, since clamping a
/// display width is a much smaller intervention than failing the whole run.
///
/// Otherwise: there is nothing meaningful to detect for piped or redirected
/// output, so wrapping is off (`None`) unless `stdout_is_terminal`. When it
/// is a terminal, the `COLUMNS` environment variable is used if set to a
/// valid positive number — the same signal most shells export and the
/// conventional first thing a CLI checks — falling back to
/// [`render::DEFAULT_TEXT_WIDTH`] when `COLUMNS` is unset or not a number.
/// This is deliberately not a raw terminal-size ioctl query: `COLUMNS` needs
/// no new dependency and works the same way on every platform, and a fixed,
/// documented fallback for when it's absent is exactly what "detection with
/// a documented fallback" asks for.
fn resolve_text_width(explicit: Option<usize>, stdout_is_terminal: bool) -> Option<usize> {
    if let Some(width) = explicit {
        return Some(width.max(render::MIN_TEXT_WIDTH));
    }
    if !stdout_is_terminal {
        return None;
    }
    let detected = std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&w| w > 0);
    Some(detected.unwrap_or(render::DEFAULT_TEXT_WIDTH))
}

/// Apply `--ascii`/`--plain` marker and separator substitution to rendered
/// text/Markdown. `plain` implies (and supersedes) `ascii`.
fn destyle_text(text: String, ascii: bool, plain: bool) -> String {
    if plain {
        report::plainify(&text)
    } else if ascii {
        report::asciify_markers(&text)
    } else {
        text
    }
}

fn render_single(
    report: &report::SafetyReport,
    format: OutputFormat,
    explain: bool,
    ascii: bool,
    plain: bool,
    width: Option<usize>,
) -> Result<String> {
    // JSON carries the severity as a field rather than as a marker glyph, and
    // the GitHub Actions workflow-command syntax is already plain ASCII, so
    // `--ascii`/`--plain` only affect the human-readable formats. `width` is
    // narrower still: it only ever reaches `generate_summary_text_with_width`
    // below, so JSON and Markdown output are structurally incapable of being
    // affected by it.
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(&report.to_json())?),
        OutputFormat::Markdown => {
            let markdown = report.generate_summary_markdown();
            Ok(destyle_text(markdown, ascii, plain))
        }
        OutputFormat::Text => {
            let text = report.generate_summary_text_with_width(explain, width);
            Ok(destyle_text(text, ascii, plain))
        }
        OutputFormat::GithubActions => Ok(render_github_actions(report)),
    }
}

fn render_github_actions(report: &report::SafetyReport) -> String {
    let mut output = String::new();
    let mut categories: Vec<_> = report.findings_by_category().keys().collect();
    categories.sort();
    for category in categories {
        if let Some(findings) = report.findings_by_category().get(category) {
            for reported in findings {
                let finding = reported.finding();
                let level = if reported.suppressed() {
                    "notice"
                } else {
                    match finding.severity() {
                        diff::Severity::Critical => "error",
                        diff::Severity::Warning => "warning",
                        diff::Severity::Info => "notice",
                    }
                };
                let message = finding.message().replace(['\r', '\n'], " ");
                output.push_str(&format!("::{level}::[{category}] {message}\n"));
            }
        }
    }
    output.push_str(&format!(
        "Soroban Upgrade Safeguard: {}\n",
        if report.is_safe() { "PASSED" } else { "FAILED" }
    ));
    output
}

struct AtomicWriteCleanup<'a> {
    active: bool,
    temp_path: &'a Path,
}

impl<'a> Drop for AtomicWriteCleanup<'a> {
    fn drop(&mut self) {
        if self.active {
            let _ = std::fs::remove_file(self.temp_path);
        }
    }
}

/// Normalize text output to end with exactly one POSIX newline.
fn ensure_trailing_newline(content: &[u8]) -> Vec<u8> {
    let mut out = content.to_vec();
    while out.last() == Some(&b'\n') {
        out.pop();
    }
    out.push(b'\n');
    out
}

fn write_atomically(path: &Path, content: &[u8]) -> Result<()> {
    let content = ensure_trailing_newline(content);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("tmp")
    ));

    let mut cleanup = AtomicWriteCleanup {
        active: true,
        temp_path: &temp_path,
    };

    std::fs::write(&temp_path, content)?;

    if let Ok(metadata) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&temp_path, metadata.permissions());
    }

    std::fs::rename(&temp_path, path)?;
    cleanup.active = false;

    Ok(())
}

fn emit_output(spec: &OutputSpec, content: &str) -> Result<()> {
    match &spec.path {
        Some(path) => {
            write_atomically(path, content.as_bytes())
                .with_context(|| format!("Failed to write output file '{}'.", path.display()))?;
        }
        None => {
            println!("{content}");
        }
    }
    Ok(())
}

/// Set from the SIGTERM handler; polled by the watch loop at safe points
/// (between cycles, never mid-write) so shutdown never truncates a report or
/// the status file. `AtomicBool::store`/`load` are async-signal-safe, which
/// is why the handler does nothing else.
#[cfg(all(feature = "watch", unix))]
static WATCH_SIGTERM_RECEIVED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(feature = "watch", unix))]
extern "C" fn handle_watch_sigterm(_signum: libc::c_int) {
    WATCH_SIGTERM_RECEIVED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Install a SIGTERM handler that only records that a signal arrived,
/// overriding the default disposition (immediate termination, which could
/// otherwise cut off a report or status-file write that was in progress).
/// The watch loop itself decides when it is safe to actually stop.
#[cfg(all(feature = "watch", unix))]
fn install_watch_sigterm_handler() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_watch_sigterm as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(all(feature = "watch", not(unix)))]
fn install_watch_sigterm_handler() {
    // SIGTERM is a POSIX signal; there is no equivalent to intercept here.
    // On these platforms watch mode still exits via Ctrl+C, or is stopped by
    // the OS/service manager's default kill behavior for the process.
}

#[cfg(all(feature = "watch", unix))]
fn watch_shutdown_requested() -> bool {
    WATCH_SIGTERM_RECEIVED.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(all(feature = "watch", not(unix)))]
fn watch_shutdown_requested() -> bool {
    false
}

/// Watch mode: monitor input files and re-run on changes.
#[cfg(feature = "watch")]
fn run_watch_mode(
    watch_paths: &[PathBuf],
    _args: &Args,
    _outputs: &[OutputSpec],
    _suppressions: &SuppressionConfig,
    debounce_ms: u64,
    status_path: Option<&Path>,
    run_comparison: impl Fn(&dyn Fn(String)) -> Result<bool>,
) -> Result<()> {
    use notify::Watcher;
    use std::sync::mpsc;
    use std::time::Duration;

    install_watch_sigterm_handler();

    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        if let Ok(event) = res {
            tx.send(event).ok();
        }
    })
    .map_err(|e| anyhow::anyhow!("Failed to create file watcher: {e}"))?;

    for path in watch_paths {
        watcher
            .watch(path, notify::RecursiveMode::NonRecursive)
            .unwrap_or_else(|e| {
                eprintln!("Warning: cannot watch {}: {e}", path.display());
            });
    }

    eprintln!(
        "\n👀 Watch mode active (debounce: {debounce_ms}ms). Waiting for file changes... (Ctrl+C or SIGTERM to stop)\n"
    );

    let loop_result = (|| -> Result<()> {
        loop {
            if watch_shutdown_requested() {
                eprintln!("\n🛑 SIGTERM received, shutting down watch mode...\n");
                return Ok(());
            }

            match rx.recv_timeout(Duration::from_millis(debounce_ms)) {
                Ok(_event) => {
                    // Brief debounce window: wait for more events
                    loop {
                        match rx.recv_timeout(Duration::from_millis(50)) {
                            Ok(_) => {}
                            Err(mpsc::RecvTimeoutError::Timeout) => break,
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                return Err(anyhow::anyhow!("File watcher channel disconnected"));
                            }
                        }
                        if watch_shutdown_requested() {
                            break;
                        }
                    }

                    if watch_shutdown_requested() {
                        eprintln!("\n🛑 SIGTERM received, shutting down watch mode...\n");
                        return Ok(());
                    }

                    // Check that watched files exist before re-running
                    let all_exist = watch_paths.iter().all(|p| p.exists());
                    if !all_exist {
                        eprintln!("⚠️  Watched file(s) missing, waiting for them to reappear...");
                        // Poll until files exist or timeout
                        let start = std::time::Instant::now();
                        let timeout = Duration::from_secs(30);
                        loop {
                            if watch_paths.iter().all(|p| p.exists()) {
                                break;
                            }
                            if watch_shutdown_requested() {
                                eprintln!("\n🛑 SIGTERM received, shutting down watch mode...\n");
                                return Ok(());
                            }
                            if start.elapsed() > timeout {
                                eprintln!("⚠️  Timed out waiting for files to reappear");
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(200));
                        }
                    }

                    // Clear terminal
                    print!("\x1B[2J\x1B[H");

                    let progress = |line: String| {
                        eprintln!("{line}");
                    };

                    eprintln!("🔄 Change detected, re-running comparison...\n");

                    match run_comparison(&progress) {
                        Ok(safe) => {
                            if safe {
                                eprintln!("\n✅ Comparison passed");
                            } else {
                                eprintln!("\n❌ Comparison failed (breaking changes detected)");
                            }
                        }
                        Err(e) => {
                            eprintln!("\n⚠️  Error during comparison: {e:#}");
                        }
                    }

                    eprintln!(
                    "\n👀 Watch mode active (debounce: {debounce_ms}ms). Waiting for file changes... (Ctrl+C or SIGTERM to stop)\n"
                );
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // No event - if this is the first run, just continue
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(anyhow::anyhow!("File watcher channel disconnected"));
                }
            }
        }
    })();

    if let Some(path) = status_path {
        let status = soroban_upgrade_safeguard::watch_status::WatchStatus::starting(0).shutdown();
        if let Err(e) = status.write_to(path) {
            eprintln!(
                "Warning: failed to write watch status file {}: {e}",
                path.display()
            );
        }
    }

    loop_result
}

#[cfg(not(feature = "watch"))]
fn run_watch_mode(
    _watch_paths: &[PathBuf],
    _args: &Args,
    _outputs: &[OutputSpec],
    _suppressions: &SuppressionConfig,
    _debounce_ms: u64,
    _status_path: Option<&Path>,
    _run_comparison: impl Fn(&dyn Fn(String)) -> Result<bool>,
) -> Result<()> {
    eprintln!("Warning: --watch is not available in this build. Rebuild with the 'watch' feature enabled.");
    Ok(())
}

fn is_stdin_wasm_path(path: &Path) -> bool {
    path == Path::new("-")
}

/// Loads a WASM input that may be `-` for stdin, a local file path, an
/// `https://…#sha256=<hex>` remote reference, or an
/// `oci://registry/repository@sha256:<hex>` reference.
///
/// This is the single dispatch point shared by the comparison positional
/// arguments, `extract`, and batch manifest entries, so every WASM input
/// position gets HTTPS and OCI support uniformly.
fn load_wasm_input(
    path: &Path,
    remote_config: &RemoteFetchConfig,
    oci_config: &OciFetchConfig,
    reject_symlinks: bool,
    progress: &dyn Fn(String),
) -> Result<loader::WasmModule> {
    if is_stdin_wasm_path(path) {
        let mut stdin = std::io::stdin().lock();
        return Ok(loader::load_wasm_from_stdin(&mut stdin)?);
    }
    if let Some(remote) =
        RemoteRef::parse(&path.to_string_lossy()).map_err(|e| anyhow::anyhow!(e))?
    {
        let (module, artifact) = loader::load_wasm_from_url(&remote, remote_config)?;
        progress(format!(
            "🌐 Remote input: {} (sha256:{}, cache {}{})",
            artifact.final_url,
            artifact.sha256,
            artifact.cache_status,
            artifact
                .media_type
                .as_deref()
                .map(|m| format!(", {m}"))
                .unwrap_or_default()
        ));
        return Ok(module);
    }
    if let Some(reference) =
        OciReference::parse(&path.to_string_lossy()).map_err(|e| anyhow::anyhow!(e))?
    {
        let (module, artifact) = loader::load_wasm_from_oci(&reference, oci_config)?;
        progress(format!(
            "📦 OCI input: {}/{}@{} (manifest {}{}, cache {}, {})",
            artifact.registry,
            artifact.repository,
            artifact.layer_digest,
            artifact.manifest_digest,
            artifact
                .resolved_tag
                .as_deref()
                .map(|t| format!(", resolved from tag '{t}'"))
                .unwrap_or_default(),
            artifact.cache_status,
            artifact.media_type
        ));
        return Ok(module);
    }
    let module = loader::load_wasm_with_policy(path, reject_symlinks)?;
    if let Some(symlink) = &module.symlink {
        progress(format!(
            "🔗 Symlink input: {} -> {}",
            symlink.requested, symlink.resolved
        ));
    }
    Ok(module)
}

/// One pair the batch loop is about to run, with the settings it runs under.
///
/// Manifest mode resolves these through [`manifest::resolve`]; directory-scan
/// mode builds them from the command line alone. Both feed the same loop, so
/// per-pair settings need no special-casing there.
struct BatchPair {
    name: String,
    /// Stable identifier for CI annotations and reruns. See
    /// [`manifest::ResolvedPair::id`]; directory-scan mode has no manifest to
    /// read an explicit one from, so it always falls back to `name`, the same
    /// deterministic rule manifest mode uses when `id` is omitted.
    id: String,
    /// Free-form grouping tags for filtering and review. See
    /// [`manifest::ResolvedPair::labels`]; always empty in directory-scan
    /// mode, which has no manifest to read them from.
    labels: Vec<String>,
    old: PathBuf,
    new: PathBuf,
    old_storage_schema: Option<PathBuf>,
    new_storage_schema: Option<PathBuf>,
    settings: manifest::ResolvedSettings,
}

impl From<manifest::ResolvedPair> for BatchPair {
    fn from(p: manifest::ResolvedPair) -> Self {
        Self {
            name: p.name,
            id: p.id,
            labels: p.labels,
            old: p.old,
            new: p.new,
            old_storage_schema: p.old_storage_schema,
            new_storage_schema: p.new_storage_schema,
            settings: p.settings,
        }
    }
}

struct ContractComparison<'a> {
    old_bytes: &'a [u8],
    old_path: &'a str,
    new_bytes: &'a [u8],
    new_path: &'a str,
    suppressions: &'a SuppressionConfig,
    explain: bool,
    strict: bool,
    no_timestamp: bool,
    empirical: bool,
    empirical_file: Option<&'a Path>,
    contract_id: Option<&'a str>,
    rpc_url: Option<&'a str>,
    rpc_headers: &'a [String],
    rpc_allow_id_mismatch: bool,
    lineage_store: Option<&'a soroban_upgrade_safeguard::lineage::LineageStore>,
}

struct PairStorageSchemas {
    old: soroban_upgrade_safeguard::StorageSchema,
    new: soroban_upgrade_safeguard::StorageSchema,
}

fn load_pair_storage_schemas(pair: &BatchPair) -> Result<Option<PairStorageSchemas>> {
    match (&pair.old_storage_schema, &pair.new_storage_schema) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => anyhow::bail!(
            "partial storage schema declaration for '{}': both old_storage_schema and new_storage_schema are required",
            pair.name
        ),
        (Some(old_path), Some(new_path)) => Ok(Some(PairStorageSchemas {
            old: load_storage_schema(old_path)?,
            new: load_storage_schema(new_path)?,
        })),
    }
}

fn load_storage_schema(path: &Path) -> Result<soroban_upgrade_safeguard::StorageSchema> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read storage schema '{}'", path.display()))?;
    let format = if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        soroban_upgrade_safeguard::SchemaFormat::Json
    } else {
        soroban_upgrade_safeguard::SchemaFormat::Toml
    };
    soroban_upgrade_safeguard::StorageSchema::from_str(&content, format)
        .map_err(|error| anyhow::anyhow!("{}: {}", path.display(), error))
}

fn compare_contracts(
    comparison: &ContractComparison<'_>,
    progress: &dyn Fn(String),
) -> Result<report::SafetyReport> {
    let ContractComparison {
        old_bytes,
        old_path,
        new_bytes,
        new_path,
        suppressions,
        explain,
        strict,
        no_timestamp,
        empirical,
        empirical_file,
        contract_id,
        rpc_url,
        rpc_headers,
        rpc_allow_id_mismatch,
        lineage_store,
    } = comparison;
    let old_meta = parser::extract_metadata(old_bytes)?;
    let old_spec = spec::ContractSpec::from_entries(&old_meta.spec);
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ Old:".green().bold(),
        old_path,
        old_bytes.len()
    ));
    progress(format!("     ├─ {}", old_spec.summary().dimmed()));
    progress(format!(
        "     └─ {}",
        format!("sha256: {}", loader::sha256_hex(old_bytes)).dimmed()
    ));

    let new_meta = parser::extract_metadata(new_bytes)?;
    let new_spec = spec::ContractSpec::from_entries(&new_meta.spec);
    progress(format!(
        "  {} {} ({} bytes)",
        "✅ New:".green().bold(),
        new_path,
        new_bytes.len()
    ));
    progress(format!("     ├─ {}", new_spec.summary().dimmed()));
    progress(format!(
        "     └─ {}",
        format!("sha256: {}", loader::sha256_hex(new_bytes)).dimmed()
    ));

    progress(format!(
        "\n{}",
        "🔬 Analyzing structural compatibility...".cyan().bold()
    ));
    let mut diff_report = diff::compare(&old_spec, &new_spec);
    diff::compare_env_metadata(
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );
    diff::compare_host_imports(
        &old_meta.host_imports,
        &new_meta.host_imports,
        old_meta.env_meta.as_ref(),
        new_meta.env_meta.as_ref(),
        &mut diff_report,
    );
    diff::compare_runtime_surfaces(
        &old_meta.runtime_surface,
        &new_meta.runtime_surface,
        &mut diff_report,
    );

    let mut report = report::SafetyReport::with_suppressions_with_specs(
        &diff_report,
        suppressions,
        *explain,
        *strict,
        &old_spec,
        &new_spec,
    )
    .with_interface_hashes(old_spec.interface_hash(), new_spec.interface_hash());

    report.no_timestamp = *no_timestamp;
    let mut empirical_findings = Vec::new();
    let mut is_empirical = false;

    if *empirical {
        is_empirical = true;
        let mut entries = Vec::new();

        if let Some(file_path) = empirical_file {
            progress(format!(
                "📖 Loading empirical storage entries from: {}",
                file_path.display()
            ));
            match soroban_upgrade_safeguard::empirical::load_empirical_entries(file_path) {
                Ok(loaded) => {
                    progress(format!(
                        "✅ Loaded {} storage entries from file",
                        loaded.len()
                    ));
                    entries = loaded;
                }
                Err(e) => {
                    progress(format!("❌ Failed to load empirical storage file: {}", e));
                    return Err(anyhow::anyhow!("Empirical validation error: {}", e));
                }
            }
        } else if let (Some(cid), Some(rpc)) = (contract_id, rpc_url) {
            progress("🌐 Fetching contract instance storage from RPC...".to_string());
            match rpc_config(rpc, rpc_headers).and_then(|config| {
                let config = config.with_id_mismatch_allowed(*rpc_allow_id_mismatch);
                loader::fetch_instance_storage_from_rpc_with_provenance(cid, &config)
                    .map_err(|e| anyhow::anyhow!(e))
            }) {
                Ok((loaded, storage_provenance)) => {
                    if let Some(ref contract_provenance) = report.rpc_provenance {
                        if contract_provenance.ledger_sequence != storage_provenance.ledger_sequence
                        {
                            return Err(anyhow::anyhow!(soroban_upgrade_safeguard::error::Error::RpcSnapshotConsistency {
                                rpc_url: storage_provenance.rpc_endpoint,
                                details: format!("Empirical storage ledger {} does not match contract/code ledger {}", storage_provenance.ledger_sequence, contract_provenance.ledger_sequence),
                                attempts: 1,
                                observed_sequences: vec![contract_provenance.ledger_sequence, storage_provenance.ledger_sequence],
                            }));
                        }
                    }
                    progress(format!(
                        "✅ Fetched {} instance storage entries from RPC",
                        loaded.len()
                    ));
                    entries = loaded;
                    // Surface the sampled entry's durability (expiration) in
                    // the report even when contract/code provenance was
                    // never separately captured, without clobbering a
                    // code_hash the code-fetch path may have already set.
                    match report.rpc_provenance.as_mut() {
                        Some(existing) => {
                            existing.live_until_ledger_seq =
                                storage_provenance.live_until_ledger_seq;
                        }
                        None => {
                            report.rpc_provenance = Some(storage_provenance);
                        }
                    }
                }
                Err(e) => {
                    progress(format!(
                        "⚠️  Failed to fetch instance storage from RPC: {}",
                        e
                    ));
                    progress("Limits: Stellar RPC does not support wildcard ledger enumeration. Degrading gracefully.".to_string());
                }
            }
        } else {
            progress("⚠️  Empirical mode requested, but no local file (--empirical-file) or RPC source (--contract-id and --rpc-url) was provided.".to_string());
        }

        // Run empirical checks
        let structural_findings: Vec<diff::Finding> = diff_report.findings.clone();
        empirical_findings = soroban_upgrade_safeguard::empirical::run_empirical_check(
            &old_spec,
            &new_spec,
            &entries,
            &structural_findings,
        );
    }

    report.empirical = is_empirical;
    report.empirical_findings = empirical_findings;

    if report.empirical_findings.iter().any(|ef| !ef.is_success) {
        report.is_safe = false;
    }

    if let Some(store) = lineage_store {
        let lineage_report =
            soroban_upgrade_safeguard::lineage::validate_candidate_against_lineage(
                new_bytes,
                &new_spec,
                store,
                suppressions,
                *strict,
            )?;
        report.apply_lineage_report(&lineage_report, suppressions, *explain, *strict);
    }

    Ok(report)
}

/// Render `err` together with its full `source()` chain, so nested detail —
/// like a `require_reason` policy violation, or the underlying TOML parser's
/// own complaint — is never swallowed behind a generic top-level message.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(s) = source {
        message.push_str(": ");
        message.push_str(&s.to_string());
        source = s.source();
    }
    message
}

/// Validate a suppression config in isolation and exit with a status that
/// reflects the outcome: `0` when the config is valid, `1` when it is malformed
/// or names a category the tool never emits. Requires no WASM inputs.
fn validate_suppression_config(path: &Path) -> Result<()> {
    println!("Validating suppression config: {}", path.display());

    // Parsing (and file-read) problems surface here as a clear, specific error.
    let config = match SuppressionConfig::load_from_path(path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", format!("❌ {}", error_chain(&e)).red().bold());
            std::process::exit(1);
        }
    };

    println!("  Parsed {} rule(s).", config.rules.len());

    let validation = config.validate();
    if validation.is_valid() {
        println!("{}", "✅ Config is valid.".green().bold());
        return Ok(());
    }

    for (rule_number, category) in &validation.unknown_categories {
        eprintln!(
            "{}",
            format!(
                "❌ Rule #{rule_number}: unknown category '{category}' — the tool never emits \
                 this category, so this rule can never match.",
            )
            .red()
        );
    }
    for error in &validation.errors {
        eprintln!("{}", format!("❌ {error}").red());
    }
    eprintln!(
        "{}",
        format!(
            "\n{} rule(s) name an unknown category. Fix the category name(s) above.",
            validation.unknown_categories.len()
        )
        .red()
        .bold()
    );
    std::process::exit(1);
}

/// The command-line layer of the manifest precedence chain.
///
/// The implicit `.safeguard.toml` lookup is passed as `default_config` rather
/// than resolved here, so it lands at the built-in level of the chain and any
/// manifest naming a config outranks it.
fn cli_settings(args: &Args) -> Result<manifest::CliSettings> {
    let env_config = std::env::var_os(CONFIG_PATH_ENV_VAR).map(PathBuf::from);
    let default_config = (!args.no_config && args.config.is_none() && env_config.is_none())
        .then(|| PathBuf::from(DEFAULT_CONFIG_FILE))
        .filter(|path| path.exists());
    // Only searched once nothing more specific already resolved a path —
    // same reasoning as `default_config`, one tier further out.
    let ancestor_config = if default_config.is_none() {
        resolve_ancestor_config(!args.no_config && args.search_parent_config)?
    } else {
        None
    };

    Ok(manifest::CliSettings {
        config: args.config.clone(),
        env_config,
        default_config,
        ancestor_config,
        no_config: args.no_config,
        strict: args.strict,
        explain: args.explain,
        ascii: args.ascii,
        no_timestamp: args.no_timestamp,
        max_pairs: args.max_pairs,
    })
}

/// Load the suppression config a pair runs under, caching by resolved path so
/// twenty pairs sharing one config parse it once, then fold the pair's `[policy]`
/// overrides onto it.
fn suppressions_for_pair(
    settings: &manifest::ResolvedSettings,
    cache: &mut std::collections::HashMap<PathBuf, SuppressionConfig>,
) -> Result<SuppressionConfig> {
    let base = match settings.config.value.as_ref() {
        Some(path) => match cache.get(path) {
            Some(cached) => cached.clone(),
            None => {
                let loaded = SuppressionConfig::load_from_path(path).with_context(|| {
                    format!(
                        "Failed to load the suppression config '{}' named by the manifest \
                         (origin: {})",
                        path.display(),
                        settings.config.origin
                    )
                })?;
                cache.insert(path.to_path_buf(), loaded.clone());
                loaded
            }
        },
        None => SuppressionConfig::default(),
    };
    Ok(settings.apply_policy(base))
}

#[allow(dead_code)]
struct GapContract {
    name: String,
    old_path: PathBuf,
}

/// A `.wasm` file present in the new directory with no counterpart in the old
/// one.
///
/// This is deliberately *not* a [`GapContract`]. An old-only artifact is a
/// contract that disappeared, which is a breaking change and becomes a Critical
/// finding. A new-only artifact has nothing to be compared against, so it
/// cannot produce a verdict at all — but it is just as likely to be a rename
/// applied to one side only as it is a genuinely new contract, and the tool
/// cannot tell which from the file alone. Reporting it as a warning is what
/// keeps a one-sided rename from shipping as a contract nobody checked.
struct NewOnlyContract {
    name: String,
    new_path: PathBuf,
}

fn scan_directories(
    old_dir: &Path,
    new_dir: &Path,
    settings: &manifest::ResolvedSettings,
) -> Result<(Vec<BatchPair>, Vec<GapContract>, Vec<NewOnlyContract>)> {
    if !old_dir.is_dir() {
        anyhow::bail!("Old directory '{}' is not a directory", old_dir.display());
    }
    if !new_dir.is_dir() {
        anyhow::bail!("New directory '{}' is not a directory", new_dir.display());
    }

    let mut pairs = Vec::new();
    let mut gaps = Vec::new();
    for entry in std::fs::read_dir(old_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"))
        {
            let filename = path.file_name().unwrap();
            let new_path = new_dir.join(filename);
            let name = path.file_stem().and_then(|s| s.to_str()).map(String::from);
            if new_path.exists() {
                let derived = name
                    .clone()
                    .unwrap_or_else(|| filename.to_string_lossy().to_string());
                pairs.push(BatchPair {
                    name: derived.clone(),
                    id: derived,
                    labels: Vec::new(),
                    old: path,
                    new: new_path,
                    old_storage_schema: None,
                    new_storage_schema: None,
                    settings: settings.clone(),
                });
            } else {
                let gap_name = name.unwrap_or_else(|| filename.to_string_lossy().to_string());
                gaps.push(GapContract {
                    name: gap_name,
                    old_path: path,
                });
            }
        }
    }

    // The reverse sweep: new-side artifacts the old-side loop never looked at.
    // The match test mirrors that loop exactly — a pair is formed when the same
    // file name exists as a file on both sides — so the two views can never
    // disagree about what counts as matched.
    let mut new_only = Vec::new();
    for entry in std::fs::read_dir(new_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file()
            || !path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("wasm"))
        {
            continue;
        }
        let filename = path.file_name().unwrap();
        if old_dir.join(filename).is_file() {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(String::from)
            .unwrap_or_else(|| filename.to_string_lossy().to_string());
        new_only.push(NewOnlyContract {
            name,
            new_path: path,
        });
    }

    // `read_dir` yields entries in unspecified order; sort so the warning reads
    // the same way on every run and in every CI log.
    new_only.sort_by(|a, b| a.name.cmp(&b.name));

    if pairs.is_empty() && gaps.is_empty() {
        if new_only.is_empty() {
            anyhow::bail!("No .wasm files found in '{}'", old_dir.display());
        }
        // Every artifact sits on the new side only. Bailing with just "no files
        // in the old directory" would describe the symptom; reversed directory
        // arguments are by far the likeliest cause, so name it.
        anyhow::bail!(
            "No .wasm files found in '{}', but '{}' contains {} .wasm file(s). \
             Directory mode only compares files that share a name in both \
             directories — check that --old-dir and --new-dir are not reversed.",
            old_dir.display(),
            new_dir.display(),
            new_only.len(),
        );
    }

    Ok((pairs, gaps, new_only))
}

#[allow(dead_code)]
fn render_report(
    report: &report::SafetyReport,
    format: OutputFormat,
    explain: bool,
) -> Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(&report.to_json())?),
        OutputFormat::Markdown => Ok(report.generate_summary_markdown()),
        OutputFormat::Text => Ok(report.generate_summary_text(explain)),
        OutputFormat::GithubActions => Ok(render_github_actions(report)),
    }
}

fn write_report_file(
    output_dir: &Path,
    contract_name: &str,
    pair_id: &str,
    template: &str,
    format: OutputFormat,
    content: &str,
) -> Result<()> {
    let ext = match format {
        OutputFormat::Json => "json",
        OutputFormat::Markdown => "md",
        OutputFormat::Text => "txt",
        OutputFormat::GithubActions => "txt",
    };
    let filename = evaluate_template(template, contract_name, pair_id, ext)?;
    let output_path = output_dir.join(filename);
    write_atomically(&output_path, content.as_bytes())
        .with_context(|| format!("Failed to write output file '{}'.", output_path.display()))?;
    Ok(())
}

fn validate_template(template: &str) -> Result<()> {
    if template.contains('/') || template.contains('\\') {
        anyhow::bail!("Template cannot contain path separators: '{}'", template);
    }

    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '{' {
            let mut placeholder = String::new();
            let mut closed = false;
            while let Some(&next_ch) = chars.peek() {
                if next_ch == '}' {
                    chars.next();
                    closed = true;
                    break;
                } else {
                    placeholder.push(chars.next().unwrap());
                }
            }
            if !closed {
                anyhow::bail!("Unclosed placeholder in template: '{}'", template);
            }
            match placeholder.as_str() {
                "name" | "id" | "ext" => {}
                _ => anyhow::bail!("Unknown placeholder '{{{}}}' in template. Supported placeholders are: {{name}}, {{id}}, {{ext}}", placeholder),
            }
        } else if ch == '}' {
            anyhow::bail!("Unmatched closing brace in template: '{}'", template);
        }
    }

    let mocked = evaluate_template(template, "mock-name", "mock-id", "txt")?;
    if mocked.is_empty() || mocked == "." || mocked == ".." {
        anyhow::bail!(
            "Template '{}' resolves to an invalid empty or dot-only filename",
            template
        );
    }

    Ok(())
}

fn evaluate_template(template: &str, name: &str, id: &str, ext: &str) -> Result<String> {
    let name_sanitized = sanitize_component(name);
    let id_sanitized = sanitize_component(id);
    let ext_sanitized = sanitize_component(ext);

    if name_sanitized.is_empty() {
        anyhow::bail!("Contract name is empty");
    }
    if id_sanitized.is_empty() {
        anyhow::bail!("Pair identity is empty");
    }

    let mut result = template.to_string();
    result = result.replace("{name}", &name_sanitized);
    result = result.replace("{id}", &id_sanitized);
    result = result.replace("{ext}", &ext_sanitized);

    if result.contains('/') || result.contains('\\') {
        anyhow::bail!(
            "Template '{}' resolved to a path containing separators: '{}'",
            template,
            result
        );
    }

    if result.is_empty() || result == "." || result == ".." {
        anyhow::bail!(
            "Template '{}' resolved to an invalid filename: '{}'",
            template,
            result
        );
    }

    Ok(result)
}

fn sanitize_component(component: &str) -> String {
    let mut sanitized = String::new();
    for ch in component.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    sanitized
}

#[cfg(test)]
mod ancestor_config_tests {
    use super::*;

    /// A fresh scratch directory for one test, under the OS temp dir rather
    /// than `CARGO_TARGET_TMPDIR` — these tests build their own directory
    /// trees from scratch and never touch the process's real current
    /// directory (only `resolve_ancestor_config` does that, and only the
    /// `enabled: false` short-circuit, which never reaches it, is exercised
    /// here — everything else goes through `find_ancestor_configs`, which
    /// takes its starting point as a plain argument).
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "safeguard-ancestor-config-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("failed to create scratch dir");
        path
    }

    #[test]
    fn is_workspace_boundary_detects_a_git_directory() {
        let dir = scratch("git-dir");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        assert!(is_workspace_boundary(&dir));
    }

    #[test]
    fn is_workspace_boundary_detects_a_git_worktree_file() {
        // Worktrees and submodules use a `.git` *file* (a pointer to the
        // real git dir elsewhere), not a directory.
        let dir = scratch("git-file");
        std::fs::write(dir.join(".git"), "gitdir: /elsewhere/.git/worktrees/x\n").unwrap();
        assert!(is_workspace_boundary(&dir));
    }

    #[test]
    fn is_workspace_boundary_is_false_without_a_git_entry() {
        let dir = scratch("no-git");
        assert!(!is_workspace_boundary(&dir));
    }

    #[test]
    fn find_ancestor_configs_finds_nothing_below_an_empty_workspace() {
        let root = scratch("empty-workspace");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let nested = root.join("services").join("api").join("src");
        std::fs::create_dir_all(&nested).unwrap();

        assert!(find_ancestor_configs(&nested).is_empty());
    }

    #[test]
    fn find_ancestor_configs_finds_a_nested_ancestor_match() {
        let root = scratch("nested-match");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(DEFAULT_CONFIG_FILE), "").unwrap();
        let nested = root.join("services").join("api").join("src");
        std::fs::create_dir_all(&nested).unwrap();

        assert_eq!(
            find_ancestor_configs(&nested),
            vec![root.join(DEFAULT_CONFIG_FILE)]
        );
    }

    #[test]
    fn find_ancestor_configs_does_not_check_the_starting_directory_itself() {
        // `start` is covered by the separate, higher-priority
        // current-directory-default tier — the ancestor search must not
        // re-report it as if it were a distinct candidate.
        let root = scratch("skip-start");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(DEFAULT_CONFIG_FILE), "").unwrap();

        assert!(find_ancestor_configs(&root).is_empty());
    }

    #[test]
    fn find_ancestor_configs_stops_at_the_git_boundary() {
        // A .safeguard.toml ABOVE the workspace boundary must never surface.
        let outer = scratch("stops-at-boundary");
        let root = outer.join("repo");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(outer.join(DEFAULT_CONFIG_FILE), "").unwrap();
        let nested = root.join("src");
        std::fs::create_dir_all(&nested).unwrap();

        assert!(find_ancestor_configs(&nested).is_empty());
    }

    #[test]
    fn find_ancestor_configs_returns_every_candidate_nearest_first() {
        let root = scratch("multiple-candidates");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(DEFAULT_CONFIG_FILE), "").unwrap();
        let mid = root.join("services");
        std::fs::create_dir_all(&mid).unwrap();
        std::fs::write(mid.join(DEFAULT_CONFIG_FILE), "").unwrap();
        let nested = mid.join("api").join("src");
        std::fs::create_dir_all(&nested).unwrap();

        assert_eq!(
            find_ancestor_configs(&nested),
            vec![
                mid.join(DEFAULT_CONFIG_FILE),
                root.join(DEFAULT_CONFIG_FILE)
            ]
        );
    }

    #[test]
    fn resolve_ancestor_config_is_a_noop_when_disabled() {
        // Short-circuits before ever reading the real current directory, so
        // this is safe to run alongside every other test in this binary.
        assert_eq!(resolve_ancestor_config(false).unwrap(), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh scratch directory for one test, under the OS temp dir.
    fn scratch(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("safeguard-main-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("failed to create scratch dir");
        path
    }

    #[test]
    fn batch_verdict_summary_totals_and_line_format() {
        let summary = BatchVerdictSummary {
            safe: 2,
            unsafe_count: 1,
            errored: 1,
            incomplete: 1,
        };
        assert_eq!(summary.total(), 5);
        assert_eq!(
            summary.to_line(),
            "2 safe, 1 unsafe, 1 errored, 1 incomplete (5 total)"
        );
    }

    #[test]
    fn batch_verdict_summary_json_keys_match_as_str() {
        // Guards src/main.rs's `to_json()` literal keys against drifting away
        // from `BatchVerdict::as_str()`, since the JSON impl intentionally
        // writes them as plain literals rather than through the enum.
        let summary = BatchVerdictSummary {
            safe: 1,
            unsafe_count: 2,
            errored: 3,
            incomplete: 4,
        };
        let json = summary.to_json();
        assert_eq!(json[BatchVerdict::Safe.as_str()], 1);
        assert_eq!(json[BatchVerdict::Unsafe.as_str()], 2);
        assert_eq!(json[BatchVerdict::Errored.as_str()], 3);
        assert_eq!(json[BatchVerdict::Incomplete.as_str()], 4);
        assert_eq!(json["total"], 10);
    }

    #[test]
    fn batch_verdict_summary_default_is_all_zero() {
        let summary = BatchVerdictSummary::default();
        assert_eq!(summary.total(), 0);
        assert_eq!(
            summary.to_line(),
            "0 safe, 0 unsafe, 0 errored, 0 incomplete (0 total)"
        );
    }

    #[test]
    fn test_output_spec_from_str_format_only() {
        let spec: OutputSpec = "json".parse().unwrap();
        assert_eq!(spec.format, OutputFormat::Json);
        assert!(spec.path.is_none());
    }

    #[test]
    fn test_output_spec_from_str_format_with_path() {
        let spec: OutputSpec = "json:report.json".parse().unwrap();
        assert_eq!(spec.format, OutputFormat::Json);
        assert_eq!(spec.path.unwrap(), PathBuf::from("report.json"));
    }

    #[test]
    fn test_output_spec_from_str_markdown_with_path() {
        let spec: OutputSpec = "markdown:docs/report.md".parse().unwrap();
        assert_eq!(spec.format, OutputFormat::Markdown);
        assert_eq!(spec.path.unwrap(), PathBuf::from("docs/report.md"));
    }

    #[test]
    fn test_output_spec_from_str_invalid_format() {
        let result: Result<OutputSpec, String> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_output_spec_from_str_invalid_format_in_pair() {
        let result: Result<OutputSpec, String> = "invalid:path.txt".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_output_format_file_extension() {
        assert_eq!(OutputFormat::Json.file_extension(), "json");
        assert_eq!(OutputFormat::Markdown.file_extension(), "md");
        assert_eq!(OutputFormat::Text.file_extension(), "txt");
    }

    #[test]
    fn test_output_spec_default() {
        let spec: OutputSpec = "text".parse().unwrap();
        assert_eq!(spec.format, OutputFormat::Text);
        assert!(spec.path.is_none());
    }

    #[test]
    fn watch_debounce_default_is_accepted() {
        assert_eq!(
            parse_watch_debounce_ms(&DEFAULT_WATCH_DEBOUNCE_MS.to_string()).unwrap(),
            DEFAULT_WATCH_DEBOUNCE_MS
        );
    }

    #[test]
    fn watch_debounce_accepts_boundary_values() {
        assert_eq!(
            parse_watch_debounce_ms(&WATCH_DEBOUNCE_MIN_MS.to_string()).unwrap(),
            WATCH_DEBOUNCE_MIN_MS
        );
        assert_eq!(
            parse_watch_debounce_ms(&WATCH_DEBOUNCE_MAX_MS.to_string()).unwrap(),
            WATCH_DEBOUNCE_MAX_MS
        );
    }

    #[test]
    fn watch_debounce_rejects_out_of_range_values() {
        assert!(parse_watch_debounce_ms(&(WATCH_DEBOUNCE_MIN_MS - 1).to_string()).is_err());
        assert!(parse_watch_debounce_ms(&(WATCH_DEBOUNCE_MAX_MS + 1).to_string()).is_err());
        assert!(parse_watch_debounce_ms("0").is_err());
    }

    #[test]
    fn watch_debounce_rejects_non_numeric_values() {
        assert!(parse_watch_debounce_ms("fast").is_err());
        assert!(parse_watch_debounce_ms("").is_err());
        assert!(parse_watch_debounce_ms("-5").is_err());
    }

    // -----------------------------------------------------------------
    // resolve_text_width
    // -----------------------------------------------------------------

    #[test]
    fn resolve_text_width_is_none_when_not_a_terminal_and_no_explicit_width() {
        // Piped/redirected output: nothing meaningful to detect, and no
        // override given, so wrapping stays off.
        assert_eq!(resolve_text_width(None, false), None);
    }

    #[test]
    fn resolve_text_width_explicit_wins_even_when_not_a_terminal() {
        assert_eq!(resolve_text_width(Some(100), false), Some(100));
    }

    #[test]
    fn resolve_text_width_explicit_is_clamped_up_to_the_minimum() {
        assert_eq!(
            resolve_text_width(Some(1), false),
            Some(render::MIN_TEXT_WIDTH)
        );
        assert_eq!(
            resolve_text_width(Some(0), true),
            Some(render::MIN_TEXT_WIDTH)
        );
        // A value already at or above the floor passes through unchanged.
        assert_eq!(
            resolve_text_width(Some(render::MIN_TEXT_WIDTH), false),
            Some(render::MIN_TEXT_WIDTH)
        );
    }

    #[test]
    fn resolve_text_width_falls_back_to_the_default_on_a_terminal_without_columns() {
        // SAFETY: main.rs's tests run single-threaded-safe with respect to
        // this var (no other test in this binary reads or writes COLUMNS),
        // matching the existing precedent for env-var-scoped tests here.
        let prev = std::env::var("COLUMNS").ok();
        std::env::remove_var("COLUMNS");
        assert_eq!(
            resolve_text_width(None, true),
            Some(render::DEFAULT_TEXT_WIDTH)
        );
        if let Some(prev) = prev {
            std::env::set_var("COLUMNS", prev);
        }
    }

    #[test]
    fn resolve_text_width_uses_columns_when_set_on_a_terminal() {
        let prev = std::env::var("COLUMNS").ok();
        std::env::set_var("COLUMNS", "132");
        assert_eq!(resolve_text_width(None, true), Some(132));
        match prev {
            Some(prev) => std::env::set_var("COLUMNS", prev),
            None => std::env::remove_var("COLUMNS"),
        }
    }

    #[test]
    fn resolve_text_width_ignores_an_invalid_columns_value() {
        let prev = std::env::var("COLUMNS").ok();
        std::env::set_var("COLUMNS", "not-a-number");
        assert_eq!(
            resolve_text_width(None, true),
            Some(render::DEFAULT_TEXT_WIDTH)
        );
        std::env::set_var("COLUMNS", "0");
        assert_eq!(
            resolve_text_width(None, true),
            Some(render::DEFAULT_TEXT_WIDTH)
        );
        match prev {
            Some(prev) => std::env::set_var("COLUMNS", prev),
            None => std::env::remove_var("COLUMNS"),
        }
    }

    #[test]
    fn test_write_atomically_success() {
        let dir = scratch("atomic-success");
        let path = dir.join("report.json");
        let content = b"{\"safe\": true}";
        write_atomically(&path, content).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"safe\": true}\n");
    }

    #[test]
    fn test_write_atomically_normalizes_trailing_newlines() {
        let dir = scratch("atomic-newline");
        let path = dir.join("report.txt");
        for (input, expected) in [
            (b"no newline".as_slice(), b"no newline\n".as_slice()),
            (b"one newline\n".as_slice(), b"one newline\n".as_slice()),
            (b"extra newlines\n\n\n".as_slice(), b"extra newlines\n".as_slice()),
        ] {
            write_atomically(&path, input).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), expected);
        }
    }

    #[test]
    fn test_write_atomically_cleanup_on_failure() {
        let dir = scratch("atomic-failure");
        let temp_path = dir.join("report.json.tmp");
        std::fs::write(&temp_path, b"temp").unwrap();
        assert!(temp_path.exists());
        {
            let _cleanup = AtomicWriteCleanup {
                active: true,
                temp_path: &temp_path,
            };
        }
        assert!(!temp_path.exists());
    }

    #[test]
    fn test_write_atomically_preserves_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("atomic-perms");
        let path = dir.join("report.json");
        std::fs::write(&path, b"initial").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o400);
        std::fs::set_permissions(&path, perms).unwrap();

        let new_content = b"new content";
        write_atomically(&path, new_content).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new content\n");
        let final_perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(final_perms.mode() & 0o777, 0o400);
    }

    #[test]
    fn test_validate_template_valid() {
        assert!(validate_template("{name}_{id}.{ext}").is_ok());
        assert!(validate_template("{name}.{ext}").is_ok());
        assert!(validate_template("report_{id}").is_ok());
    }

    #[test]
    fn test_validate_template_invalid() {
        assert!(validate_template("{name}/{id}.{ext}").is_err());
        assert!(validate_template("{invalid}.{ext}").is_err());
        assert!(validate_template("{name").is_err());
        assert!(validate_template("}").is_err());
    }
}

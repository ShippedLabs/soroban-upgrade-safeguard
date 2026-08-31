use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::limits::{LimitsConfig, ResourcePolicy};
use crate::manifest::PolicyOverrides;
use crate::profile::{self, RawProfile};
use crate::suppression::{PolicyConfig, SuppressionConfig, SuppressionRule};

/// Output format for the safety report.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Markdown,
}

#[derive(clap::Parser, Debug, Clone, Default)]
#[command(
    author,
    version,
    about,
    long_about = None,
    override_usage = "soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --manifest <MANIFEST_PATH> [OPTIONS]\n       \
                      soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR> [OPTIONS]"
)]
pub struct Args {
    /// WASM paths: <OLD_WASM> <NEW_WASM> in local mode, or just <NEW_WASM> in RPC mode
    #[arg(value_name = "WASM", num_args = 0..=2)]
    pub wasm_paths: Vec<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Stellar/Soroban Contract ID to fetch from on-chain (e.g. C...)
    #[arg(long, value_name = "CONTRACT_ID", requires = "rpc_url")]
    pub contract_id: Option<String>,

    /// Stellar RPC URL (e.g. <https://soroban-testnet.stellar.org>)
    #[arg(long, value_name = "RPC_URL", requires = "contract_id")]
    pub rpc_url: Option<String>,

    /// Path to a suppression config acknowledging known, intentional breaking
    /// changes. When omitted, `.safeguard.toml` in the current directory is
    /// used if present; otherwise no suppressions are applied.
    #[arg(long, value_name = "CONFIG")]
    pub config: Option<PathBuf>,

    /// Print a concise remediation explanation for each finding.
    #[arg(long)]
    pub explain: bool,

    /// Exit with a non-zero code if any Warnings or Critical findings are found
    #[arg(long)]
    pub strict: bool,

    /// Do not color output
    #[arg(long)]
    pub no_color: bool,

    /// Path to a manifest file (TOML or JSON) containing contract pairs to compare
    #[arg(long, value_name = "MANIFEST_PATH")]
    pub manifest: Option<PathBuf>,

    /// Directory containing the old versions of the contracts for directory comparison
    #[arg(long, value_name = "OLD_DIR", requires = "new_dir")]
    pub old_dir: Option<PathBuf>,

    /// Directory containing the new versions of the contracts for directory comparison
    #[arg(long, value_name = "NEW_DIR", requires = "old_dir")]
    pub new_dir: Option<PathBuf>,

    /// Allow HTTP connections for RPC when the host is localhost/127.0.0.1.
    /// Without this flag only HTTPS URLs are accepted.
    #[arg(long)]
    pub allow_http_local: bool,

    /// Expected SHA-256 hash (hex) of the on-chain WASM baseline.
    /// When provided the tool verifies the hash of the fetched bytecode
    /// matches this value and fails immediately on mismatch.
    #[arg(long, value_name = "HEX_HASH")]
    pub expected_wasm_hash: Option<String>,

    /// Storage-schema manifest describing the OLD build's storage layout.
    ///
    /// Declares the storage-key types and internal value types that govern
    /// on-chain compatibility but need not appear in the exported spec. Must be
    /// given together with --new-storage-schema: detecting a layout change
    /// requires both snapshots.
    #[arg(long, value_name = "PATH", requires = "new_storage_schema")]
    pub old_storage_schema: Option<PathBuf>,

    /// Storage-schema manifest describing the NEW build's storage layout.
    #[arg(long, value_name = "PATH", requires = "old_storage_schema")]
    pub new_storage_schema: Option<PathBuf>,

    /// Maximum XDR decode depth per entry. Overrides `[limits]` in the config
    /// file and the built-in default. Guards against stack-overflow inputs.
    #[arg(long, value_name = "N")]
    pub max_xdr_depth: Option<u32>,

    /// Maximum bytes decoded per WASM custom section. Overrides `[limits]` and
    /// the default. Guards against oversized-length allocation inputs.
    #[arg(long, value_name = "BYTES")]
    pub max_xdr_len: Option<usize>,

    /// Maximum decoded spec entries, summed across all sections. Overrides
    /// `[limits]` and the default.
    #[arg(long, value_name = "N")]
    pub max_entries: Option<usize>,

    /// Maximum recursive type-walk depth (equality, rendering, cascade
    /// detection). Overrides `[limits]` and the default.
    #[arg(long, value_name = "N")]
    pub max_walk_depth: Option<usize>,

    /// Path to a persistent lineage store (JSON/TOML) tracking historical versions.
    #[arg(long, value_name = "PATH")]
    pub lineage_store: Option<PathBuf>,

    /// Record candidate build as a new version in the lineage store with this tag.
    #[arg(long, value_name = "VERSION_ID")]
    pub record_version: Option<String>,

    /// Mark an existing historical version as retired in the lineage store.
    #[arg(long, value_name = "VERSION_ID")]
    pub retire_version: Option<String>,

    /// Maximum live historical versions to validate candidate against.
    #[arg(long, value_name = "N")]
    pub max_live_versions: Option<usize>,

    /// Select a named policy profile from `[profiles.<name>]` in the config
    /// file. Overrides `default_profile`. See [`crate::profile`] for the
    /// schema, precedence, and inheritance rules.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub format: Option<OutputFormat>,
    pub explain: Option<bool>,
    pub strict: Option<bool>,
    pub no_color: Option<bool>,
    pub max_suppressions: Option<usize>,
    pub allow_targetless: Option<bool>,
    pub contract_id: Option<String>,
    pub rpc_url: Option<String>,
    pub manifest: Option<PathBuf>,
    pub old_dir: Option<PathBuf>,
    pub new_dir: Option<PathBuf>,
    pub wasm_paths: Option<Vec<PathBuf>>,
    pub limits: Option<LimitsConfig>,
    pub lineage_store: Option<PathBuf>,
    pub record_version: Option<String>,
    pub retire_version: Option<String>,
    pub max_live_versions: Option<usize>,
    #[serde(default, rename = "suppress")]
    pub suppress: Vec<SuppressionRule>,

    /// Axis gating at the base (root) config level, before any profile fold.
    /// Field-for-field with [`PolicyConfig`]; see [`crate::profile`].
    #[serde(default)]
    pub gating: PolicyOverrides,
    /// Profile selected when `--profile` and `SAFEGUARD_PROFILE` are both
    /// absent.
    #[serde(default)]
    pub default_profile: Option<String>,
    /// Named policy profiles, keyed by name. See [`crate::profile`].
    #[serde(default)]
    pub profiles: BTreeMap<String, RawProfile>,

    /// Contract pairs, present when this same file is also used as a batch
    /// manifest (`--manifest <this file>`). Accepted-but-unused here so a
    /// dual-purpose config/manifest file still loads under plain `--config`;
    /// [`crate::manifest`] parses the file independently (and does use this)
    /// when `--manifest` selects it.
    #[serde(default)]
    pub pairs: Vec<crate::manifest::RawPair>,

    /// Per-metric complexity budgets for the WASM code section.
    /// Exceeded budgets always gate `is_safe`, independent of `--strict`.
    /// See [`crate::wasm_complexity`] for metric names and semantics.
    #[serde(default, rename = "complexity_budget")]
    pub complexity_budget: Vec<crate::wasm_complexity::ComplexityBudgetEntryFile>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResolvedConfig {
    pub wasm_paths: Vec<PathBuf>,
    pub contract_id: Option<String>,
    pub rpc_url: Option<String>,
    pub config: Option<PathBuf>,
    pub format: OutputFormat,
    pub explain: bool,
    pub strict: bool,
    pub no_color: bool,
    pub manifest: Option<PathBuf>,
    pub old_dir: Option<PathBuf>,
    pub new_dir: Option<PathBuf>,
    pub policy: ResourcePolicy,
    pub suppressions: SuppressionConfig,
    pub expected_wasm_hash: Option<String>,
    pub lineage_store: Option<PathBuf>,
    pub record_version: Option<String>,
    pub retire_version: Option<String>,
    pub max_live_versions: Option<usize>,
    /// Axis gating after the profile fold. Not to be confused with
    /// [`Self::policy`], which is the *resource-limit* policy.
    pub gating: PolicyConfig,
    /// The selected profile (if any), its inheritance chain, and the origin
    /// of every profile-controlled setting. See [`crate::profile`].
    pub profile: profile::ResolvedProfile,
    /// Validated complexity budgets parsed from `[[complexity_budget]]` tables
    /// in the config file. Empty when no config file was loaded or no tables
    /// were declared.
    pub complexity_budget: crate::wasm_complexity::ComplexityBudgetConfig,
}

impl ResolvedConfig {
    pub fn resolve(args: Args) -> Result<Self> {
        // 1. Identify config file path
        let config_file_path = match &args.config {
            Some(path) => Some(path.clone()),
            None => {
                let default_path = Path::new(crate::suppression::DEFAULT_CONFIG_FILE);
                if default_path.exists() {
                    Some(default_path.to_path_buf())
                } else {
                    None
                }
            }
        };

        // 2. Load file if present
        let file_config = if let Some(path) = &config_file_path {
            let raw = std::fs::read_to_string(path).with_context(|| {
                format!(
                    "Failed to read suppression config file '{}'",
                    path.display()
                )
            })?;
            // Windows tooling commonly saves UTF-8 files with a leading BOM,
            // which TOML has no syntax for; strip it before parsing so it
            // doesn't surface as a confusing "unexpected character" error.
            let content = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
            let parsed: FileConfig = toml::from_str(content)
                .with_context(|| format!("Invalid suppression config file '{}'", path.display()))?;
            Some(parsed)
        } else {
            None
        };

        let base_dir = config_file_path
            .as_ref()
            .and_then(|p| p.parent())
            .unwrap_or_else(|| Path::new("."));

        // 3. Layer settings (CLI > Env > Config File > Defaults)
        let contract_id = args
            .contract_id
            .clone()
            .or_else(|| env_string("SAFEGUARD_CONTRACT_ID"))
            .or_else(|| file_config.as_ref().and_then(|fc| fc.contract_id.clone()));

        let rpc_url = args
            .rpc_url
            .clone()
            .or_else(|| env_string("SAFEGUARD_RPC_URL"))
            .or_else(|| file_config.as_ref().and_then(|fc| fc.rpc_url.clone()));

        let manifest = args
            .manifest
            .clone()
            .or_else(|| env_path("SAFEGUARD_MANIFEST"))
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|fc| fc.manifest.clone())
                    .map(|p| resolve_path(base_dir, p))
            });

        let old_dir = args
            .old_dir
            .clone()
            .or_else(|| env_path("SAFEGUARD_OLD_DIR"))
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|fc| fc.old_dir.clone())
                    .map(|p| resolve_path(base_dir, p))
            });

        let new_dir = args
            .new_dir
            .clone()
            .or_else(|| env_path("SAFEGUARD_NEW_DIR"))
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|fc| fc.new_dir.clone())
                    .map(|p| resolve_path(base_dir, p))
            });

        let wasm_paths = if !args.wasm_paths.is_empty() {
            args.wasm_paths.clone()
        } else if let Some(paths) = env_path_list("SAFEGUARD_WASM_PATHS") {
            paths
        } else if let Some(fc) = &file_config {
            fc.wasm_paths
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|p| resolve_path(base_dir, p))
                .collect()
        } else {
            Vec::new()
        };

        // Profile selection: `--profile` > `SAFEGUARD_PROFILE` > `default_profile`
        // in the file. Selecting a name that isn't declared, an inheritance
        // cycle, or a chain deeper than `profile::MAX_PROFILE_DEPTH` is a
        // hard error (see `crate::profile`).
        let selected_profile = args
            .profile
            .clone()
            .or_else(|| env_string("SAFEGUARD_PROFILE"))
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|fc| fc.default_profile.clone())
            });

        let base_values = profile::BaseValues {
            format: file_config.as_ref().and_then(|fc| fc.format),
            explain: file_config.as_ref().and_then(|fc| fc.explain),
            strict: file_config.as_ref().and_then(|fc| fc.strict),
            no_color: file_config.as_ref().and_then(|fc| fc.no_color),
            max_suppressions: file_config.as_ref().and_then(|fc| fc.max_suppressions),
            gating: file_config.as_ref().map(|fc| fc.gating).unwrap_or_default(),
            limits: file_config
                .as_ref()
                .and_then(|fc| fc.limits.clone())
                .unwrap_or_default(),
        };

        // `args.format` always carries a value (clap gives it a default), so
        // the CLI is treated as having set it only when it differs from the
        // compiled-in default — matching the pre-profile behavior.
        let cli_format = (args.format != OutputFormat::default()).then_some(args.format);

        let cli_overrides = profile::CliOverrides {
            format: cli_format.or_else(|| env_format("SAFEGUARD_FORMAT")),
            explain: args.explain || env_bool("SAFEGUARD_EXPLAIN").unwrap_or(false),
            strict: args.strict || env_bool("SAFEGUARD_STRICT").unwrap_or(false),
            no_color: args.no_color
                || env_bool("SAFEGUARD_NO_COLOR").unwrap_or(false)
                || env_bool("NO_COLOR").unwrap_or(false),
            max_suppressions: env_usize("SAFEGUARD_MAX_SUPPRESSIONS"),
            max_xdr_depth: args
                .max_xdr_depth
                .or_else(|| env_u32("SAFEGUARD_MAX_XDR_DEPTH")),
            max_xdr_len: args
                .max_xdr_len
                .or_else(|| env_usize("SAFEGUARD_MAX_XDR_LEN")),
            max_entries: args
                .max_entries
                .or_else(|| env_usize("SAFEGUARD_MAX_ENTRIES")),
            max_walk_depth: args
                .max_walk_depth
                .or_else(|| env_usize("SAFEGUARD_MAX_WALK_DEPTH")),
        };

        let empty_profiles = BTreeMap::new();
        let profiles_map = file_config
            .as_ref()
            .map(|fc| &fc.profiles)
            .unwrap_or(&empty_profiles);
        let resolved_profile = profile::resolve(
            profiles_map,
            selected_profile.as_deref(),
            base_values,
            cli_overrides,
        )?;

        let format = resolved_profile.format.value;
        let explain = resolved_profile.explain.value;
        let strict = resolved_profile.strict.value;
        let no_color = resolved_profile.no_color.value;

        let gating = PolicyConfig {
            gate_storage_layout: resolved_profile.gating.gate_storage_layout.value,
            gate_call_abi: resolved_profile.gating.gate_call_abi.value,
            gate_event_indexer: resolved_profile.gating.gate_event_indexer.value,
            gate_source_level: resolved_profile.gating.gate_source_level.value,
            gate_runtime_surface: resolved_profile.gating.gate_runtime_surface.value,
        };

        let policy = ResourcePolicy {
            max_xdr_depth: resolved_profile.limits.max_xdr_depth.value,
            max_xdr_len: resolved_profile.limits.max_xdr_len.value,
            max_entries: resolved_profile.limits.max_entries.value,
            max_walk_depth: resolved_profile.limits.max_walk_depth.value,
        };

        // Suppressions config resolution. `max_suppressions` is profile-controlled
        // (a "budget" setting), so it comes from the fold above rather than the
        // base file directly — see `crate::profile`.
        let mut suppressions = SuppressionConfig::default();
        if let Some(fc) = &file_config {
            suppressions.allow_targetless = fc.allow_targetless;
            suppressions.rules = fc.suppress.clone();
        }
        suppressions.max_suppressions = resolved_profile.max_suppressions.value;
        if let Some(v) = env_bool("SAFEGUARD_ALLOW_TARGETLESS") {
            suppressions.allow_targetless = Some(v);
        }

        let validation = suppressions.validate();
        if !validation.is_valid() {
            anyhow::bail!(
                "invalid suppression config: unknown categories {:?}; errors: {:?}",
                validation.unknown_categories,
                validation.errors
            );
        }

        let lineage_store = args
            .lineage_store
            .clone()
            .or_else(|| env_path("SAFEGUARD_LINEAGE_STORE"))
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|fc| fc.lineage_store.clone())
                    .map(|p| resolve_path(base_dir, p))
            });

        let record_version = args
            .record_version
            .clone()
            .or_else(|| env_string("SAFEGUARD_RECORD_VERSION"))
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|fc| fc.record_version.clone())
            });

        let retire_version = args
            .retire_version
            .clone()
            .or_else(|| env_string("SAFEGUARD_RETIRE_VERSION"))
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|fc| fc.retire_version.clone())
            });

        let max_live_versions = args
            .max_live_versions
            .or_else(|| env_usize("SAFEGUARD_MAX_LIVE_VERSIONS"))
            .or_else(|| file_config.as_ref().and_then(|fc| fc.max_live_versions));

        // Complexity budgets: validate raw entries from the config file.
        let raw_budgets = file_config
            .as_ref()
            .map(|fc| fc.complexity_budget.clone())
            .unwrap_or_default();
        let complexity_budget =
            crate::wasm_complexity::ComplexityBudgetConfig::from_file_entries(raw_budgets)
                .unwrap_or_else(|_errors| {
                    crate::wasm_complexity::ComplexityBudgetConfig::default()
                });

        Ok(Self {
            wasm_paths,
            contract_id,
            rpc_url,
            config: config_file_path,
            format,
            explain,
            strict,
            no_color,
            manifest,
            old_dir,
            new_dir,
            policy,
            suppressions,
            expected_wasm_hash: args.expected_wasm_hash.clone(),
            lineage_store,
            record_version,
            retire_version,
            max_live_versions,
            gating,
            profile: resolved_profile,
            complexity_budget,
        })
    }

    /// Centralized mode detection and validation.
    /// Ensures there are no conflicting options, missing dependencies, or invalid positional arg counts.
    pub fn validate_and_resolve_mode(&self) -> Result<RunMode> {
        let has_manifest = self.manifest.is_some();
        let has_dir_scan = self.old_dir.is_some() || self.new_dir.is_some();
        let has_rpc = self.contract_id.is_some() || self.rpc_url.is_some();

        if has_manifest && has_dir_scan {
            anyhow::bail!(
                "Cannot specify both --manifest and --old-dir/--new-dir at the same time"
            );
        }

        // Verify rpc settings are co-dependent
        if self.contract_id.is_some() != self.rpc_url.is_some() {
            anyhow::bail!("Both --contract-id and --rpc-url must be specified together");
        }

        // Check if batch mode is used
        let is_batch = has_manifest || has_dir_scan;
        if is_batch && !self.wasm_paths.is_empty() {
            anyhow::bail!("Cannot specify positional WASM paths when using batch mode (--manifest or --old-dir/--new-dir)");
        }

        if has_manifest {
            Ok(RunMode::Manifest)
        } else if has_dir_scan {
            if self.old_dir.is_none() || self.new_dir.is_none() {
                anyhow::bail!("Both --old-dir and --new-dir must be specified together for directory scanning");
            }
            Ok(RunMode::DirScan)
        } else if has_rpc {
            // RPC Mode: exactly 1 positional WASM path (the new one)
            match self.wasm_paths.len() {
                1 => Ok(RunMode::Rpc),
                2 => anyhow::bail!("When using --contract-id, provide only the NEW_WASM path as a positional argument"),
                _ => anyhow::bail!(
                    "Expected exactly 1 positional WASM path when using --contract-id.\n\n\
                     Usage: soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>"
                ),
            }
        } else {
            // Local Mode: exactly 2 positional WASM paths
            match self.wasm_paths.len() {
                2 => Ok(RunMode::Local),
                1 => anyhow::bail!(
                    "Missing OLD_WASM path. Provide two WASM files, or use --contract-id and --rpc-url \
                     to fetch the old contract from chain.\n\n\
                     Usage: soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>\n       \
                     soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>"
                ),
                _ => anyhow::bail!(
                    "Expected 2 WASM path arguments.\n\n\
                     Usage: soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>\n       \
                     soroban-upgrade-safeguard --contract-id <ID> --rpc-url <URL> <NEW_WASM>\n\n\
                     Or use batch mode:\n       \
                     soroban-upgrade-safeguard --manifest <MANIFEST_PATH>\n       \
                     soroban-upgrade-safeguard --old-dir <OLD_DIR> --new-dir <NEW_DIR>"
                ),
            }
        }
    }
}

/// The detected operating mode of the safeguard execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    Local,
    Rpc,
    Manifest,
    DirScan,
}

/// Anchor `path` on `base_dir` unless it is already absolute.
///
/// Shared with [`crate::manifest`], which anchors every relative manifest path
/// on the directory of the file that wrote it.
pub(crate) fn resolve_path(base_dir: &Path, path: PathBuf) -> PathBuf {
    let windows_absolute = path
        .to_str()
        .map(|value| {
            let bytes = value.as_bytes();
            bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'/' | b'\\')
        })
        .unwrap_or(false);
    if path.is_absolute() || windows_absolute {
        path
    } else {
        base_dir.join(path)
    }
}

fn env_bool(var_name: &str) -> Option<bool> {
    std::env::var(var_name).ok().and_then(|val| {
        let val_lower = val.to_lowercase();
        if val_lower == "true" || val_lower == "1" {
            Some(true)
        } else if val_lower == "false" || val_lower == "0" {
            Some(false)
        } else {
            None
        }
    })
}

fn env_usize(var_name: &str) -> Option<usize> {
    std::env::var(var_name)
        .ok()
        .and_then(|val| val.parse().ok())
}

fn env_u32(var_name: &str) -> Option<u32> {
    std::env::var(var_name)
        .ok()
        .and_then(|val| val.parse().ok())
}

fn env_string(var_name: &str) -> Option<String> {
    std::env::var(var_name).ok().filter(|s| !s.is_empty())
}

fn env_path(var_name: &str) -> Option<PathBuf> {
    std::env::var_os(var_name)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

fn env_path_list(var_name: &str) -> Option<Vec<PathBuf>> {
    std::env::var(var_name)
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.split(',')
                .map(|part| part.trim())
                .filter(|part| !part.is_empty())
                .map(PathBuf::from)
                .collect()
        })
}

fn env_format(var_name: &str) -> Option<OutputFormat> {
    std::env::var(var_name)
        .ok()
        .and_then(|val| match val.to_lowercase().as_str() {
            "text" => Some(OutputFormat::Text),
            "json" => Some(OutputFormat::Json),
            "markdown" => Some(OutputFormat::Markdown),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_path_absolute() {
        let base = Path::new("/base");
        let abs = PathBuf::from("c:/absolute/path.toml");
        assert_eq!(resolve_path(base, abs.clone()), abs);
    }

    #[test]
    fn test_resolve_path_relative() {
        let base = Path::new("/base/dir");
        let rel = PathBuf::from("relative/file.toml");
        assert_eq!(
            resolve_path(base, rel),
            Path::new("/base/dir").join("relative/file.toml")
        );
    }

    #[test]
    fn test_env_bool_parsing() {
        let var = "TEST_ENV_BOOL_VAR";

        std::env::set_var(var, "true");
        assert_eq!(env_bool(var), Some(true));

        std::env::set_var(var, "1");
        assert_eq!(env_bool(var), Some(true));

        std::env::set_var(var, "TRUE");
        assert_eq!(env_bool(var), Some(true));

        std::env::set_var(var, "false");
        assert_eq!(env_bool(var), Some(false));

        std::env::set_var(var, "0");
        assert_eq!(env_bool(var), Some(false));

        std::env::set_var(var, "invalid");
        assert_eq!(env_bool(var), None);

        std::env::remove_var(var);
        assert_eq!(env_bool(var), None);
    }

    #[test]
    fn test_env_usize_parsing() {
        let var = "TEST_ENV_USIZE_VAR";

        std::env::set_var(var, "12345");
        assert_eq!(env_usize(var), Some(12345));

        std::env::set_var(var, "invalid");
        assert_eq!(env_usize(var), None);

        std::env::remove_var(var);
        assert_eq!(env_usize(var), None);
    }

    #[test]
    fn test_env_u32_parsing() {
        let var = "TEST_ENV_U32_VAR";

        std::env::set_var(var, "999");
        assert_eq!(env_u32(var), Some(999));

        std::env::set_var(var, "invalid");
        assert_eq!(env_u32(var), None);

        std::env::remove_var(var);
        assert_eq!(env_u32(var), None);
    }

    #[test]
    fn test_env_string_parsing() {
        let var = "TEST_ENV_STRING_VAR";

        std::env::set_var(var, "hello");
        assert_eq!(env_string(var), Some("hello".to_string()));

        std::env::set_var(var, "");
        assert_eq!(env_string(var), None);

        std::env::remove_var(var);
        assert_eq!(env_string(var), None);
    }

    #[test]
    fn test_env_path_parsing() {
        let var = "TEST_ENV_PATH_VAR";

        std::env::set_var(var, "some/path/file.wasm");
        assert_eq!(env_path(var), Some(PathBuf::from("some/path/file.wasm")));

        std::env::set_var(var, "");
        assert_eq!(env_path(var), None);

        std::env::remove_var(var);
        assert_eq!(env_path(var), None);
    }

    #[test]
    fn test_env_path_list_parsing() {
        let var = "TEST_ENV_PATH_LIST_VAR";

        std::env::set_var(var, "a.wasm, b.wasm, c.wasm");
        assert_eq!(
            env_path_list(var),
            Some(vec![
                PathBuf::from("a.wasm"),
                PathBuf::from("b.wasm"),
                PathBuf::from("c.wasm")
            ])
        );

        std::env::set_var(var, "  path1 , , path2 ");
        assert_eq!(
            env_path_list(var),
            Some(vec![PathBuf::from("path1"), PathBuf::from("path2")])
        );

        std::env::set_var(var, "");
        assert_eq!(env_path_list(var), None);

        std::env::remove_var(var);
        assert_eq!(env_path_list(var), None);
    }

    #[test]
    fn test_env_format_parsing() {
        let var = "TEST_ENV_FORMAT_VAR";

        std::env::set_var(var, "text");
        assert_eq!(env_format(var), Some(OutputFormat::Text));

        std::env::set_var(var, "JSON");
        assert_eq!(env_format(var), Some(OutputFormat::Json));

        std::env::set_var(var, "markdown");
        assert_eq!(env_format(var), Some(OutputFormat::Markdown));

        std::env::set_var(var, "invalid");
        assert_eq!(env_format(var), None);

        std::env::remove_var(var);
        assert_eq!(env_format(var), None);
    }

    #[test]
    fn test_env_bool_parsing_edge_cases() {
        let var = "TEST_ENV_BOOL_EDGE";

        std::env::set_var(var, "  true  ");
        assert_eq!(env_bool(var), None);

        std::env::set_var(var, "yes");
        assert_eq!(env_bool(var), None);

        std::env::set_var(var, "no");
        assert_eq!(env_bool(var), None);

        std::env::set_var(var, "");
        assert_eq!(env_bool(var), None);

        std::env::remove_var(var);
    }

    #[test]
    fn test_env_usize_parsing_overflow() {
        let var = "TEST_ENV_USIZE_OVERFLOW";

        std::env::set_var(var, "-100");
        assert_eq!(env_usize(var), None);

        std::env::set_var(var, "99999999999999999999999999999999999999999999");
        assert_eq!(env_usize(var), None);

        std::env::remove_var(var);
    }

    #[test]
    fn test_env_u32_parsing_overflow() {
        let var = "TEST_ENV_U32_OVERFLOW";

        std::env::set_var(var, "-1");
        assert_eq!(env_u32(var), None);

        std::env::set_var(var, "4294967296");
        assert_eq!(env_u32(var), None);

        std::env::remove_var(var);
    }
}

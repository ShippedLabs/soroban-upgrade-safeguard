//! Composable batch manifests: includes, shared defaults, and per-pair overrides.
//!
//! A batch manifest lists the contract pairs a run compares. Historically it was
//! a flat `[[pairs]]` list and every other setting (`--strict`, `--config`, the
//! gating policy) was global to the whole run, so a team could not give one
//! contract in a twenty-contract manifest its own policy without splitting the
//! run into two invocations.
//!
//! This module adds three things on top of that list, keeping the old flat form
//! valid:
//!
//! - **`include`** — pull in another manifest file. Composition is depth-first
//!   in `include` order: a file's includes contribute before the file itself.
//!   Included files use the same schema, so any manifest can serve as a fragment.
//! - **`[defaults]`** — settings applied to every pair in the composition.
//! - **per-pair fields** — the same settings, on one `[[pairs]]` entry.
//!
//! ```toml
//! include = ["common/policy.toml"]
//!
//! [defaults]
//! base_dir = "artifacts"
//! strict   = false
//! config   = ".safeguard.toml"
//!
//! [defaults.policy]
//! gate_event_indexer = false
//!
//! [[pairs]]
//! old    = "token_v1.wasm"
//! new    = "token_v2.wasm"
//! name   = "token"
//! strict = true                 # per-pair override
//!
//! [pairs.policy]
//! gate_event_indexer = true
//! ```
//!
//! JSON manifests use the same shape; includes may mix formats freely, since the
//! parser picks per file.
//!
//! # Precedence
//!
//! Two rules, because one does not fit both kinds of setting.
//!
//! **Valued settings** — `config`, `policy.*`, `limits.*` — last writer wins:
//!
//! ```text
//! built-in default  <  SOROBAN_SAFEGUARD_CONFIG  <  CLI flag  <  included defaults  <  root [defaults]  <  pair field
//! ```
//!
//! `config` is the one valued setting with an environment-variable layer:
//! `SOROBAN_SAFEGUARD_CONFIG` lets a CI system set a config path once instead
//! of repeating `--config` on every invocation, but sits below `--config`
//! itself so an explicit flag always wins. The CLI (env var included) sits
//! *below* the manifest deliberately: it is the run-level fallback, and a
//! manifest naming a config is the more specific statement. `--no-config` is
//! the one exception — an explicit escape hatch that wins over everything.
//!
//! **Escalation booleans** — `strict`, `explain`, `ascii`, `no_timestamp` —
//! OR-chain: any layer may enable, none may disable. This mirrors
//! [`crate::config`]'s handling of `no_color`, and keeps `--strict` from being
//! silently weakened by a manifest, which for a safety gate is the behavior you
//! want. Note that `policy.gate_*` are booleans but are *valued*, not
//! escalation — being able to turn a gate off is the entire point of `[policy]`.
//!
//! # Path resolution
//!
//! Relative paths resolve against **the directory of the file that wrote them**,
//! never the process CWD, which is what makes a fragment relocatable.
//!
//! `base_dir` is deliberately **file-scoped** rather than part of the global
//! valued chain: a pair's `old`/`new` resolve against the pair's own `base_dir`,
//! else the `[defaults].base_dir` of the file that defined that pair, else that
//! file's own directory. Folding `base_dir` globally would let a root manifest
//! silently redirect a fragment's artifact lookups, defeating the point of
//! writing the fragment as a self-contained unit.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize, Serializer};

use crate::config::resolve_path;
use crate::dependency::ContractDependency;
use crate::limits::{LimitsConfig, ResourcePolicy};
use crate::suppression::{PolicyConfig, SuppressionConfig};

/// Maximum depth of the `include` chain.
///
/// Bounded so a mistake in a generated manifest fails fast with a readable chain
/// instead of recursing until the process runs out of stack. Eight is generous
/// for any layout a human would write by hand (org → team → service → local).
pub const MAX_INCLUDE_DEPTH: usize = 8;

/// Default ceiling on the total number of pairs a composed manifest may
/// contain, overridable with `--max-pairs`.
///
/// A malformed or accidentally generated manifest (a bad template loop, a
/// script gone wrong) can list thousands of pairs; without a cap the tool
/// would start loading and comparing WASM for every one of them before
/// anyone notices. 500 comfortably covers any manifest a human would compose
/// by hand, including a large monorepo, while still catching a runaway file.
///
/// Deliberately **not** overridable from within a manifest itself (no
/// `[defaults].max_pairs`): the whole point is a ceiling the manifest cannot
/// raise on its own, so the CLI is the only place it can be set.
pub const DEFAULT_MAX_PAIRS: usize = 500;

// ── Raw (on-disk) schema ─────────────────────────────────────────────────────

/// One manifest file exactly as written on disk, before composition.
///
/// Every struct in this schema uses `deny_unknown_fields` so a typo'd key is a
/// hard error rather than a silently ignored setting — composition multiplies
/// files, and a silently dropped `strict = true` in a fragment is precisely the
/// failure mode this feature must not introduce.
fn default_manifest_version() -> u32 {
    1
}

/// One manifest file exactly as written on disk, before composition.
///
/// Every struct in this schema uses `deny_unknown_fields` so a typo'd key is a
/// hard error rather than a silently ignored setting — composition multiplies
/// files, and a silently dropped `strict = true` in a fragment is precisely the
/// failure mode this feature must not introduce.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawManifest {
    /// The version of the manifest format.
    ///
    /// Defaults to `1` (the initial version) when omitted, preserving legacy
    /// behavior for manifests written before format versioning was introduced.
    /// Only version 1 is currently supported.
    #[serde(default = "default_manifest_version")]
    pub version: u32,
    /// Other manifest files to compose in, depth-first, in order.
    #[serde(default)]
    pub include: Vec<PathBuf>,
    /// Settings contributed to every pair in the composition.
    #[serde(default)]
    pub defaults: RawDefaults,
    /// The contract pairs this file declares.
    #[serde(default)]
    pub pairs: Vec<RawPair>,
    /// Declared `caller → callee` edges.
    ///
    /// Parsed and composed so a manifest written against the syntax documented
    /// in [`crate::dependency`] keeps loading. Propagation itself is not wired
    /// up; see `docs/batch_manifests.md`.
    #[serde(default)]
    pub dependencies: Vec<ContractDependency>,
}

impl Default for RawManifest {
    fn default() -> Self {
        Self {
            version: 1,
            include: Vec::new(),
            defaults: RawDefaults::default(),
            pairs: Vec::new(),
            dependencies: Vec::new(),
        }
    }
}

/// The `[defaults]` table: settings that apply to every pair.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawDefaults {
    /// Base directory for this file's relative `old`/`new` paths.
    #[serde(default)]
    pub base_dir: Option<PathBuf>,
    /// Suppression config applied to each pair.
    #[serde(default)]
    pub config: Option<PathBuf>,
    #[serde(default)]
    pub strict: Option<bool>,
    #[serde(default)]
    pub explain: Option<bool>,
    #[serde(default)]
    pub ascii: Option<bool>,
    #[serde(default)]
    pub no_timestamp: Option<bool>,
    /// Axis gating overrides folded onto the suppression config's policy.
    #[serde(default)]
    pub policy: PolicyOverrides,
    /// Resource limit overrides. Resolved and reported, not yet enforced.
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// One `[[pairs]]` entry: the two builds plus any per-pair overrides.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPair {
    /// The baseline build.
    pub old: PathBuf,
    /// The candidate build.
    pub new: PathBuf,
    /// Optional declared storage schema for the baseline build.
    #[serde(default, alias = "old-storage-schema")]
    pub old_storage_schema: Option<PathBuf>,
    /// Optional declared storage schema for the candidate build.
    #[serde(default, alias = "new-storage-schema")]
    pub new_storage_schema: Option<PathBuf>,
    /// Report name. Defaults to the file name of `new`.
    #[serde(default)]
    pub name: Option<String>,
    /// Stable identifier for CI annotations and reruns, independent of
    /// `name`. Defaults to the pair's resolved `name` when omitted. Must be
    /// non-empty and contain only ASCII letters, digits, `-`, `_`, and `.`
    /// when given explicitly; must be unique across the whole composition.
    #[serde(default)]
    pub id: Option<String>,
    /// Free-form grouping tags (service, deployment stage, ownership, ...),
    /// for filtering and review — never consulted for identity or the safety
    /// verdict. Each must be non-empty and contain only ASCII letters,
    /// digits, `-`, `_`, `.`, and `:` (for `key:value` tags like
    /// `stage:prod`); duplicates within one pair are folded down to their
    /// first occurrence. Unlike `id`, the same label is expected to repeat
    /// across many pairs — that repetition is the point.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Base directory for this pair's relative `old`/`new`.
    #[serde(default)]
    pub base_dir: Option<PathBuf>,
    #[serde(default)]
    pub config: Option<PathBuf>,
    #[serde(default)]
    pub strict: Option<bool>,
    #[serde(default)]
    pub explain: Option<bool>,
    #[serde(default)]
    pub ascii: Option<bool>,
    #[serde(default)]
    pub no_timestamp: Option<bool>,
    #[serde(default)]
    pub policy: PolicyOverrides,
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Partial overrides for [`PolicyConfig`].
///
/// [`PolicyConfig`] itself uses plain `bool` fields with defaulting getters, so
/// it cannot express "unset". This mirror uses `Option<bool>` so a layer can
/// override one gate without restating the rest — the same shape
/// [`LimitsConfig`] already uses for resource limits.
///
/// This must stay field-for-field in sync with [`PolicyConfig`]: a gate missing
/// here cannot be set in a manifest at all, and `deny_unknown_fields` turns the
/// attempt into a hard error. `every_policy_gate_is_overridable_from_a_manifest`
/// guards the pairing in both directions.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyOverrides {
    #[serde(default)]
    pub gate_storage_layout: Option<bool>,
    #[serde(default)]
    pub gate_call_abi: Option<bool>,
    #[serde(default)]
    pub gate_event_indexer: Option<bool>,
    #[serde(default)]
    pub gate_source_level: Option<bool>,
    #[serde(default)]
    pub gate_runtime_surface: Option<bool>,
}

impl PolicyOverrides {
    /// Fold these overrides onto `base`, keeping `base` for any unset field.
    ///
    /// Modeled on [`LimitsConfig::apply_to`].
    #[must_use]
    pub fn apply_to(&self, mut base: PolicyConfig) -> PolicyConfig {
        if let Some(v) = self.gate_storage_layout {
            base.gate_storage_layout = v;
        }
        if let Some(v) = self.gate_call_abi {
            base.gate_call_abi = v;
        }
        if let Some(v) = self.gate_event_indexer {
            base.gate_event_indexer = v;
        }
        if let Some(v) = self.gate_source_level {
            base.gate_source_level = v;
        }
        if let Some(v) = self.gate_runtime_surface {
            base.gate_runtime_surface = v;
        }
        base
    }
}

// ── Provenance ───────────────────────────────────────────────────────────────

/// Where a resolved value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The compiled-in default, because no layer set the value.
    BuiltIn,
    /// A command-line flag.
    Cli,
    /// An environment variable (e.g. `SOROBAN_SAFEGUARD_CONFIG`), read
    /// because no more specific layer set the value.
    Env,
    /// A manifest file, by path.
    File(PathBuf),
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::BuiltIn => write!(f, "built-in"),
            Origin::Cli => write!(f, "cli"),
            Origin::Env => write!(f, "env"),
            Origin::File(path) => {
                write!(
                    f,
                    "{}",
                    crate::loader::normalize_path_display(&path.display().to_string())
                )
            }
        }
    }
}

impl Serialize for Origin {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// A resolved value paired with the layer that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sourced<T> {
    pub value: T,
    pub origin: Origin,
}

impl<T> Sourced<T> {
    fn built_in(value: T) -> Self {
        Self {
            value,
            origin: Origin::BuiltIn,
        }
    }
}

// ── Resolved settings ────────────────────────────────────────────────────────

/// Axis gating after the precedence fold, one origin per gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedPolicy {
    pub gate_storage_layout: Sourced<bool>,
    pub gate_call_abi: Sourced<bool>,
    pub gate_event_indexer: Sourced<bool>,
    pub gate_source_level: Sourced<bool>,
    pub gate_runtime_surface: Sourced<bool>,
}

impl ResolvedPolicy {
    /// The overrides this resolution represents, for folding onto a
    /// [`PolicyConfig`] loaded from a suppression config.
    #[must_use]
    pub fn as_overrides(&self) -> PolicyOverrides {
        let set = |s: &Sourced<bool>| (s.origin != Origin::BuiltIn).then_some(s.value);
        PolicyOverrides {
            gate_storage_layout: set(&self.gate_storage_layout),
            gate_call_abi: set(&self.gate_call_abi),
            gate_event_indexer: set(&self.gate_event_indexer),
            gate_source_level: set(&self.gate_source_level),
            gate_runtime_surface: set(&self.gate_runtime_surface),
        }
    }
}

/// Resource limits after the precedence fold.
///
/// Resolved and reported for provenance; **not enforced** — `parser.rs` still
/// decodes with `Limits::none()`. See `docs/batch_manifests.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedLimits {
    pub max_xdr_depth: Sourced<u32>,
    pub max_xdr_len: Sourced<usize>,
    pub max_entries: Sourced<usize>,
    pub max_walk_depth: Sourced<usize>,
}

/// Every setting one pair runs with, each carrying its origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedSettings {
    /// Suppression config path. `None` means no config (the `--no-config`
    /// escape hatch, or simply nothing naming one).
    pub config: Sourced<Option<PathBuf>>,
    pub strict: Sourced<bool>,
    pub explain: Sourced<bool>,
    pub ascii: Sourced<bool>,
    pub no_timestamp: Sourced<bool>,
    pub policy: ResolvedPolicy,
    pub limits: ResolvedLimits,
}

impl ResolvedSettings {
    /// Fold this pair's policy overrides onto `config`'s own policy.
    ///
    /// Kept here rather than in the binary so it works whether or not the
    /// `unstable` feature makes [`SuppressionConfig::policy`] public.
    #[must_use]
    pub fn apply_policy(&self, mut config: SuppressionConfig) -> SuppressionConfig {
        config.policy = self.policy.as_overrides().apply_to(config.policy);
        config
    }
}

/// One fully resolved contract pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedPair {
    /// Report identity: the explicit `name`, else the file name of `new`.
    pub name: String,
    /// Stable identifier for CI annotations and reruns: the explicit `id`,
    /// else this pair's resolved `name`. Unique across the whole composition.
    pub id: String,
    /// Free-form grouping tags, deduplicated and in declaration order. Empty
    /// when the pair declared none. See [`RawPair::labels`].
    pub labels: Vec<String>,
    pub old: PathBuf,
    pub new: PathBuf,
    /// Optional schema paths, resolved against the manifest that declared the pair.
    pub old_storage_schema: Option<PathBuf>,
    pub new_storage_schema: Option<PathBuf>,
    /// The manifest file this pair was written in.
    pub defined_in: PathBuf,
    pub settings: ResolvedSettings,
}

/// A dependency edge plus the file that declared it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourcedDependency {
    #[serde(flatten)]
    pub dependency: ContractDependency,
    pub defined_in: PathBuf,
}

/// A whole composition, ready for the batch loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedManifest {
    /// The manifest named on the command line.
    pub root: PathBuf,
    /// Every file that contributed, first-visit order, root included.
    pub sources: Vec<PathBuf>,
    /// Pairs in composed order: each file's includes before its own `[[pairs]]`.
    pub pairs: Vec<ResolvedPair>,
    /// Declared dependency edges. Composed and reported, not propagated.
    pub dependencies: Vec<SourcedDependency>,
}

/// The command-line half of the precedence chain.
#[derive(Debug, Clone)]
pub struct CliSettings {
    /// `--config`.
    pub config: Option<PathBuf>,
    /// The `SOROBAN_SAFEGUARD_CONFIG` environment variable, read only when
    /// `--config` was not given. Sits above [`Self::default_config`] and
    /// below `--config` and every manifest layer: CI systems can set it once
    /// instead of repeating `--config` on every invocation, but an explicit
    /// flag or a manifest naming its own `config` still wins.
    pub env_config: Option<PathBuf>,
    /// The implicitly discovered `.safeguard.toml`, when one exists and
    /// neither `--config` nor the environment variable named one.
    ///
    /// This sits at the [`Origin::BuiltIn`] level — below `--config`, below
    /// the environment variable, and below every manifest layer — because it
    /// is exactly that: the compiled-in fallback the tool has always applied
    /// when nothing named a config. Keeping it in the chain rather than as a
    /// post-hoc `unwrap_or` means a manifest that names its own `config`
    /// overrides it, which is what a reader of the precedence table would
    /// expect.
    pub default_config: Option<PathBuf>,
    /// A `.safeguard.toml` found by `--search-parent-config` in an ancestor
    /// of the current directory, when nothing more specific (`--config`, the
    /// environment variable, or [`Self::default_config`]) named one.
    ///
    /// Sits at the same [`Origin::BuiltIn`] level as `default_config` — it is
    /// the same kind of thing, a compiled-in fallback, just with a wider
    /// search radius the caller opted into. Populating this field is where
    /// `--search-parent-config` is entirely gated: when the flag is off, the
    /// caller never computes a value for it, and this field is always `None`.
    pub ancestor_config: Option<PathBuf>,
    /// `--no-config`: wins over every layer and yields no suppression config.
    pub no_config: bool,
    pub strict: bool,
    pub explain: bool,
    pub ascii: bool,
    pub no_timestamp: bool,
    /// `--max-pairs`. Not part of the manifest schema — see
    /// [`DEFAULT_MAX_PAIRS`] for why it must stay CLI-only.
    pub max_pairs: usize,
}

impl Default for CliSettings {
    // Not `#[derive(Default)]`: `max_pairs` must default to
    // `DEFAULT_MAX_PAIRS`, not `usize`'s own zero default, or every existing
    // manifest would fail with `CliSettings::default()`.
    fn default() -> Self {
        Self {
            config: None,
            env_config: None,
            default_config: None,
            ancestor_config: None,
            no_config: false,
            strict: false,
            explain: false,
            ascii: false,
            no_timestamp: false,
            max_pairs: DEFAULT_MAX_PAIRS,
        }
    }
}

// ── Walking ──────────────────────────────────────────────────────────────────

/// One file's `[defaults]` contribution, with its paths already anchored.
#[derive(Debug, Clone)]
struct Layer {
    origin: Origin,
    config: Option<PathBuf>,
    strict: Option<bool>,
    explain: Option<bool>,
    ascii: Option<bool>,
    no_timestamp: Option<bool>,
    policy: PolicyOverrides,
    limits: LimitsConfig,
}

/// A pair as found during the walk, before the precedence fold.
#[derive(Debug, Clone)]
struct WalkedPair {
    raw: RawPair,
    defined_in: PathBuf,
    /// The directory this pair's relative `old`/`new` resolve against.
    base_dir: PathBuf,
}

#[derive(Debug, Default)]
struct Walk {
    layers: Vec<Layer>,
    pairs: Vec<WalkedPair>,
    dependencies: Vec<SourcedDependency>,
    sources: Vec<PathBuf>,
    seen_sources: HashSet<PathBuf>,
}

/// Resolve `root` and everything it includes into a ready-to-run composition.
///
/// Fails on include cycles, an include chain deeper than [`MAX_INCLUDE_DEPTH`],
/// more pairs than [`CliSettings::max_pairs`] (default [`DEFAULT_MAX_PAIRS`]),
/// duplicate pair identities, unknown fields, unreadable includes, and files
/// that parse as neither TOML nor JSON.
pub fn resolve(root: &Path, cli: &CliSettings) -> Result<ResolvedManifest> {
    let root = absolutize(root);
    let mut walk = Walk::default();
    let mut stack: Vec<PathBuf> = Vec::new();
    visit(&root, &mut walk, &mut stack, 0)?;

    if walk.pairs.is_empty() {
        bail!(
            "Manifest composition contains no comparison pairs. A manifest must declare at least one comparison pair.\n\
             Minimal valid shape:\n\
             \n\
             # TOML\n\
             [[pairs]]\n\
             name = \"my-contract\"\n\
             old = \"old.wasm\"\n\
             new = \"new.wasm\"\n\
             \n\
             # JSON\n\
             {{\n\
               \"pairs\": [\n\
                 {{\n\
                   \"name\": \"my-contract\",\n\
                   \"old\": \"old.wasm\",\n\
                   \"new\": \"new.wasm\"\n\
                 }}\n\
               ]\n\
             }}"
        );
    }

    // Checked ahead of the (more expensive) precedence fold, and long before
    // the batch loop would start loading WASM for each pair: a malformed or
    // accidentally generated manifest with thousands of pairs is rejected as
    // a configuration error, not run until something else gives out.
    if walk.pairs.len() > cli.max_pairs {
        bail!(
            "Manifest composition contains {} pairs, exceeding the maximum of {} (--max-pairs).\n  \
             root: {}\n\
             Raise --max-pairs if this many pairs is intentional, or check for a manifest \
             generation mistake.",
            walk.pairs.len(),
            cli.max_pairs,
            root.display()
        );
    }

    let pairs = fold_pairs(&walk, cli)?;

    Ok(ResolvedManifest {
        root,
        sources: walk.sources,
        pairs,
        dependencies: walk.dependencies,
    })
}

/// Depth-first walk: a file's includes contribute before the file itself.
fn visit(path: &Path, walk: &mut Walk, stack: &mut Vec<PathBuf>, depth: usize) -> Result<()> {
    if depth > MAX_INCLUDE_DEPTH {
        bail!(
            "Manifest include chain exceeds the maximum depth of {}:\n  {}",
            MAX_INCLUDE_DEPTH,
            chain_display(stack, path)
        );
    }

    // Cycle detection uses canonical paths so `./a.toml` and `a.toml` are the
    // same file; the reported chain keeps the paths as written for readability.
    let identity = canonical_identity(path);
    if stack
        .iter()
        .any(|entry| canonical_identity(entry) == identity)
    {
        bail!(
            "Manifest include cycle detected:\n  {}",
            chain_display(stack, path)
        );
    }

    let raw = parse_file(path).with_context(|| {
        if stack.is_empty() {
            format!("Failed to load manifest '{}'", path.display())
        } else {
            format!(
                "Failed to load included manifest '{}' (include chain: {})",
                path.display(),
                chain_display(stack, path)
            )
        }
    })?;

    if raw.version != 1 {
        bail!(
            "Unsupported manifest version. Supported version: 1, encountered: {} in '{}'",
            raw.version,
            path.display()
        );
    }

    let dir = parent_dir(path);
    stack.push(path.to_path_buf());

    for include in &raw.include {
        let target = resolve_path(&dir, include.clone());
        visit(&target, walk, stack, depth + 1)?;
    }

    stack.pop();

    if walk.seen_sources.insert(identity) {
        walk.sources.push(path.to_path_buf());
    }

    let origin = Origin::File(path.to_path_buf());
    walk.layers.push(Layer {
        origin: origin.clone(),
        config: raw.defaults.config.clone().map(|c| resolve_path(&dir, c)),
        strict: raw.defaults.strict,
        explain: raw.defaults.explain,
        ascii: raw.defaults.ascii,
        no_timestamp: raw.defaults.no_timestamp,
        policy: raw.defaults.policy,
        limits: raw.defaults.limits.clone(),
    });

    // `base_dir` is file-scoped: a pair anchors on its own `base_dir`, else this
    // file's `[defaults].base_dir`, else this file's directory. See the module
    // docs for why it is not part of the global valued chain.
    let file_base = raw
        .defaults
        .base_dir
        .clone()
        .map(|b| resolve_path(&dir, b))
        .unwrap_or_else(|| dir.clone());

    for pair in raw.pairs {
        let base_dir = pair
            .base_dir
            .clone()
            .map(|b| resolve_path(&dir, b))
            .unwrap_or_else(|| file_base.clone());
        walk.pairs.push(WalkedPair {
            raw: pair,
            defined_in: path.to_path_buf(),
            base_dir,
        });
    }

    for dependency in raw.dependencies {
        walk.dependencies.push(SourcedDependency {
            dependency,
            defined_in: path.to_path_buf(),
        });
    }

    Ok(())
}

/// Non-empty, and restricted to characters safe in CI annotations, file
/// names, and shell arguments — ASCII letters, digits, `-`, `_`, and `.`. (An
/// empty string vacuously passes the character check alone, hence the
/// explicit `is_empty` guard.)
fn is_valid_token(value: &str, extra: &[char]) -> bool {
    !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || extra.contains(&c)
        })
}

fn is_valid_pair_id(id: &str) -> bool {
    is_valid_token(id, &[])
}

/// Same base charset as [`is_valid_pair_id`], plus `:` — labels are meant for
/// `key:value`-style tags (`service:token`, `stage:prod`), which `id` has no
/// need for.
fn is_valid_label(label: &str) -> bool {
    is_valid_token(label, &[':'])
}

fn fold_pairs(walk: &Walk, cli: &CliSettings) -> Result<Vec<ResolvedPair>> {
    let mut resolved = Vec::with_capacity(walk.pairs.len());
    // Duplicate detection runs before any comparison, so a collision fails the
    // run with nothing written — the old code bailed mid-loop, after earlier
    // pairs had already produced report files.
    let mut names: HashMap<String, PathBuf> = HashMap::new();
    let mut ids: HashMap<String, (PathBuf, String)> = HashMap::new();

    for walked in &walk.pairs {
        let pair_layer = Layer {
            origin: Origin::File(walked.defined_in.clone()),
            config: walked
                .raw
                .config
                .clone()
                .map(|c| resolve_path(&parent_dir(&walked.defined_in), c)),
            strict: walked.raw.strict,
            explain: walked.raw.explain,
            ascii: walked.raw.ascii,
            no_timestamp: walked.raw.no_timestamp,
            policy: walked.raw.policy,
            limits: walked.raw.limits.clone(),
        };

        let settings = fold_settings(&walk.layers, &pair_layer, cli);

        let old = resolve_path(&walked.base_dir, walked.raw.old.clone());
        let new = resolve_path(&walked.base_dir, walked.raw.new.clone());

        // Identity derivation preserves the pre-composition behavior: explicit
        // `name`, else the file name of `new`.
        let name = walked.raw.name.clone().unwrap_or_else(|| {
            new.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.to_string())
                .unwrap_or_else(|| format!("pair_{}", resolved.len() + 1))
        });

        if let Some(previous) = names.get(&name) {
            bail!(
                "Duplicate contract name '{}' in the manifest composition.\n  \
                 first defined in: {}\n  also defined in:  {}\n\
                 Give one of them an explicit `name` so reports stay distinguishable.",
                name,
                previous.display(),
                walked.defined_in.display()
            );
        }
        names.insert(name.clone(), walked.defined_in.clone());

        // Pair ID: explicit `id`, validated, else the resolved `name`. The
        // fallback is not itself re-validated against the ID charset — it
        // reuses `name` verbatim, exactly as `name` has always behaved, so an
        // existing manifest that never sets `id` cannot start failing here.
        let id = match &walked.raw.id {
            Some(explicit) => {
                if !is_valid_pair_id(explicit) {
                    bail!(
                        "Invalid pair id '{}' for '{}' in {}.\n  \
                         IDs must be non-empty and contain only ASCII letters, digits, \
                         '-', '_', and '.'.",
                        explicit,
                        name,
                        walked.defined_in.display()
                    );
                }
                explicit.clone()
            }
            None => name.clone(),
        };

        if let Some((previous_file, previous_name)) = ids.get(&id) {
            bail!(
                "Duplicate pair id '{}' in the manifest composition.\n  \
                 first occurrence: pair '{}' in {}\n  \
                 duplicate: pair '{}' in {}\n\
                 Each pair must have a unique identifier. Give one of them an explicit `id` field.",
                id,
                previous_name,
                previous_file.display(),
                name,
                walked.defined_in.display()
            );
        }
        ids.insert(id.clone(), (walked.defined_in.clone(), name.clone()));

        // Labels: validated like `id`, but never checked for uniqueness —
        // the same label repeating across many pairs is the whole point.
        // Duplicates *within* one pair's own list are folded to their first
        // occurrence rather than rejected, since they carry no information.
        let mut labels: Vec<String> = Vec::with_capacity(walked.raw.labels.len());
        for label in &walked.raw.labels {
            if !is_valid_label(label) {
                bail!(
                    "Invalid label '{}' for '{}' in {}.\n  \
                     Labels must be non-empty and contain only ASCII letters, digits, \
                     '-', '_', '.', and ':'.",
                    label,
                    name,
                    walked.defined_in.display()
                );
            }
            if !labels.contains(label) {
                labels.push(label.clone());
            }
        }

        resolved.push(ResolvedPair {
            name,
            id,
            labels,
            old,
            new,
            old_storage_schema: walked
                .raw
                .old_storage_schema
                .clone()
                .map(|path| resolve_path(&parent_dir(&walked.defined_in), path)),
            new_storage_schema: walked
                .raw
                .new_storage_schema
                .clone()
                .map(|path| resolve_path(&parent_dir(&walked.defined_in), path)),
            defined_in: walked.defined_in.clone(),
            settings,
        });
    }

    Ok(resolved)
}

/// The precedence fold itself: built-in < CLI < defaults layers < pair.
fn fold_settings(layers: &[Layer], pair: &Layer, cli: &CliSettings) -> ResolvedSettings {
    let chain = || layers.iter().chain(std::iter::once(pair));

    // Escalation booleans: first layer to enable wins, nothing can disable.
    let escalate = |cli_value: bool, get: fn(&Layer) -> Option<bool>| {
        if cli_value {
            return Sourced {
                value: true,
                origin: Origin::Cli,
            };
        }
        for layer in chain() {
            if get(layer) == Some(true) {
                return Sourced {
                    value: true,
                    origin: layer.origin.clone(),
                };
            }
        }
        Sourced::built_in(false)
    };

    // Valued settings: last writer wins.
    let config = if cli.no_config {
        // The explicit escape hatch outranks every layer.
        Sourced {
            value: None,
            origin: Origin::Cli,
        }
    } else {
        let mut current = match (
            &cli.config,
            &cli.env_config,
            &cli.default_config,
            &cli.ancestor_config,
        ) {
            (Some(path), _, _, _) => Sourced {
                value: Some(path.clone()),
                origin: Origin::Cli,
            },
            (None, Some(path), _, _) => Sourced {
                value: Some(path.clone()),
                origin: Origin::Env,
            },
            (None, None, Some(path), _) => Sourced::built_in(Some(path.clone())),
            (None, None, None, Some(path)) => Sourced::built_in(Some(path.clone())),
            (None, None, None, None) => Sourced::built_in(None),
        };
        for layer in chain() {
            if let Some(path) = &layer.config {
                current = Sourced {
                    value: Some(path.clone()),
                    origin: layer.origin.clone(),
                };
            }
        }
        current
    };

    let gate = |get: fn(&PolicyOverrides) -> Option<bool>, default: bool| {
        let mut current = Sourced::built_in(default);
        for layer in chain() {
            if let Some(value) = get(&layer.policy) {
                current = Sourced {
                    value,
                    origin: layer.origin.clone(),
                };
            }
        }
        current
    };

    let base_limits = ResourcePolicy::default();
    macro_rules! limit {
        ($field:ident) => {{
            let mut current = Sourced::built_in(base_limits.$field);
            for layer in chain() {
                if let Some(value) = layer.limits.$field {
                    current = Sourced {
                        value,
                        origin: layer.origin.clone(),
                    };
                }
            }
            current
        }};
    }

    let defaults = PolicyConfig::default();

    ResolvedSettings {
        config,
        strict: escalate(cli.strict, |l| l.strict),
        explain: escalate(cli.explain, |l| l.explain),
        ascii: escalate(cli.ascii, |l| l.ascii),
        no_timestamp: escalate(cli.no_timestamp, |l| l.no_timestamp),
        policy: ResolvedPolicy {
            gate_storage_layout: gate(|p| p.gate_storage_layout, defaults.gate_storage_layout),
            gate_call_abi: gate(|p| p.gate_call_abi, defaults.gate_call_abi),
            gate_event_indexer: gate(|p| p.gate_event_indexer, defaults.gate_event_indexer),
            gate_source_level: gate(|p| p.gate_source_level, defaults.gate_source_level),
            gate_runtime_surface: gate(|p| p.gate_runtime_surface, defaults.gate_runtime_surface),
        },
        limits: ResolvedLimits {
            max_xdr_depth: limit!(max_xdr_depth),
            max_xdr_len: limit!(max_xdr_len),
            max_entries: limit!(max_entries),
            max_walk_depth: limit!(max_walk_depth),
        },
    }
}

/// Build a [`ResolvedSettings`] from the command line alone.
///
/// Used by directory-scan batch mode, which has no manifest but runs through the
/// same per-pair loop.
#[must_use]
pub fn cli_only_settings(cli: &CliSettings) -> ResolvedSettings {
    fold_settings(
        &[],
        &Layer {
            origin: Origin::Cli,
            config: None,
            strict: None,
            explain: None,
            ascii: None,
            no_timestamp: None,
            policy: PolicyOverrides::default(),
            limits: LimitsConfig::default(),
        },
        cli,
    )
}

// ── Parsing ──────────────────────────────────────────────────────────────────

/// Parse one manifest file as TOML or JSON.
///
/// Both parsers are tried, most-likely format first (by extension, else by the
/// first non-whitespace byte). When both fail, **both** errors are reported with
/// their line and column — the previous implementation discarded them and said
/// only "as either TOML or JSON", which is undebuggable once includes multiply
/// the number of candidate files.
fn parse_file(path: &Path) -> Result<RawManifest> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read manifest file: {}", path.display()))?;
    // Windows tooling commonly saves UTF-8 files with a leading BOM, which
    // neither TOML nor JSON has syntax for; strip it before parsing (and
    // before the format sniff below, which would otherwise see the BOM
    // instead of the manifest's real first character).
    let content = raw.strip_prefix('\u{feff}').unwrap_or(&raw);

    if content.trim().is_empty() {
        bail!(
            "Manifest file '{}' is empty. A manifest must declare at least one comparison pair.\n\
             Minimal valid shape:\n\
             \n\
             # TOML\n\
             [[pairs]]\n\
             name = \"my-contract\"\n\
             old = \"old.wasm\"\n\
             new = \"new.wasm\"\n\
             \n\
             # JSON\n\
             {{\n\
               \"pairs\": [\n\
                 {{\n\
                   \"name\": \"my-contract\",\n\
                   \"old\": \"old.wasm\",\n\
                   \"new\": \"new.wasm\"\n\
                 }}\n\
               ]\n\
             }}",
            path.display()
        );
    }

    let json_first = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        || content.trim_start().starts_with(['{', '[']);

    let toml_error = match toml::from_str::<RawManifest>(content) {
        Ok(manifest) => return Ok(manifest),
        Err(e) => e.to_string(),
    };
    let json_error = match serde_json::from_str::<RawManifest>(content) {
        Ok(manifest) => return Ok(manifest),
        Err(e) => format!("{e}"),
    };

    let (primary_label, primary, secondary_label, secondary) = if json_first {
        ("JSON", json_error, "TOML", toml_error)
    } else {
        ("TOML", toml_error, "JSON", json_error)
    };

    Err(anyhow!(
        "Failed to parse manifest '{}' as {primary_label} or {secondary_label}.\n  \
         {primary_label} error: {}\n  {secondary_label} error: {}",
        path.display(),
        primary.trim(),
        secondary.trim(),
    ))
}

// ── Path helpers ─────────────────────────────────────────────────────────────

fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

fn parent_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// A comparable identity for a path, falling back to the path itself when the
/// file cannot be canonicalized (it may not exist yet — the read that follows
/// reports that properly).
pub fn canonical_identity(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Render `path` for report-facing output (JSON, `--explain-manifest`) with
/// display normalization applied (see
/// [`crate::loader::normalize_path_display`]). Deliberately **not** used for
/// diagnostic-only messages like the include-cycle chain below, which show
/// the path exactly as the filesystem gave it to help track down the actual
/// file.
fn display_path(path: &Path) -> String {
    crate::loader::normalize_path_display(&path.display().to_string())
}

fn chain_display(stack: &[PathBuf], next: &Path) -> String {
    stack
        .iter()
        .map(|p| p.display().to_string())
        .chain(std::iter::once(next.display().to_string()))
        .collect::<Vec<_>>()
        .join(" → ")
}

// ── Presentation ─────────────────────────────────────────────────────────────

impl ResolvedManifest {
    /// The `manifest` block embedded in batch JSON output.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "root": display_path(&self.root),
            "sources": self
                .sources
                .iter()
                .map(|p| display_path(p))
                .collect::<Vec<_>>(),
            "pairs": self.pairs.iter().map(ResolvedPair::to_json).collect::<Vec<_>>(),
            "dependencies": self.dependencies,
        })
    }

    /// Human-readable resolution report for `--explain-manifest`.
    pub fn explain_text(&self) -> String {
        let mut out = String::new();
        out.push_str("Manifest resolution\n");
        out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        out.push_str(&format!("root:    {}\n", display_path(&self.root)));
        out.push_str("sources:\n");
        for source in &self.sources {
            out.push_str(&format!("  - {}\n", display_path(source)));
        }

        out.push_str(&format!("\npairs ({}):\n", self.pairs.len()));
        for (index, pair) in self.pairs.iter().enumerate() {
            out.push_str(&format!("\n  [{}] {}\n", index + 1, pair.name));
            out.push_str(&format!("      id:         {}\n", pair.id));
            if !pair.labels.is_empty() {
                out.push_str(&format!("      labels:     {}\n", pair.labels.join(", ")));
            }
            out.push_str(&format!(
                "      defined in: {}\n",
                display_path(&pair.defined_in)
            ));
            out.push_str(&format!("      old:        {}\n", display_path(&pair.old)));
            out.push_str(&format!("      new:        {}\n", display_path(&pair.new)));
            if let Some(path) = &pair.old_storage_schema {
                out.push_str(&format!("      old schema:  {}\n", display_path(path)));
            }
            if let Some(path) = &pair.new_storage_schema {
                out.push_str(&format!("      new schema:  {}\n", display_path(path)));
            }
            for (key, value, origin) in pair.settings.rows() {
                // Width covers the longest key (`policy.gate_runtime_surface`)
                // so the `=` column stays aligned across every row.
                out.push_str(&format!(
                    "      {key:<27} = {value:<12} ({origin})\n",
                    key = key,
                    value = value,
                    origin = origin
                ));
            }
        }

        if !self.dependencies.is_empty() {
            out.push_str(&format!(
                "\ndependencies ({}, declared only — not propagated):\n",
                self.dependencies.len()
            ));
            for dep in &self.dependencies {
                let functions = if dep.dependency.functions.is_empty() {
                    "*".to_string()
                } else {
                    dep.dependency.functions.join(", ")
                };
                out.push_str(&format!(
                    "  - {} → {} [{}]  ({})\n",
                    dep.dependency.caller,
                    dep.dependency.callee,
                    functions,
                    display_path(&dep.defined_in)
                ));
            }
        }

        out
    }
}

impl ResolvedPair {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "id": self.id,
            "labels": self.labels,
            "defined_in": display_path(&self.defined_in),
            "old": display_path(&self.old),
            "new": display_path(&self.new),
            "old_storage_schema": self.old_storage_schema.as_deref().map(display_path),
            "new_storage_schema": self.new_storage_schema.as_deref().map(display_path),
            "settings": self.settings.to_json(),
        })
    }
}

impl ResolvedSettings {
    /// `(key, rendered value, origin)` for every setting, in a stable order.
    fn rows(&self) -> Vec<(&'static str, String, String)> {
        let render_path = |s: &Sourced<Option<PathBuf>>| match &s.value {
            Some(path) => display_path(path),
            None => "(none)".to_string(),
        };
        vec![
            (
                "config",
                render_path(&self.config),
                self.config.origin.to_string(),
            ),
            (
                "strict",
                self.strict.value.to_string(),
                self.strict.origin.to_string(),
            ),
            (
                "explain",
                self.explain.value.to_string(),
                self.explain.origin.to_string(),
            ),
            (
                "ascii",
                self.ascii.value.to_string(),
                self.ascii.origin.to_string(),
            ),
            (
                "no_timestamp",
                self.no_timestamp.value.to_string(),
                self.no_timestamp.origin.to_string(),
            ),
            (
                "policy.gate_storage_layout",
                self.policy.gate_storage_layout.value.to_string(),
                self.policy.gate_storage_layout.origin.to_string(),
            ),
            (
                "policy.gate_call_abi",
                self.policy.gate_call_abi.value.to_string(),
                self.policy.gate_call_abi.origin.to_string(),
            ),
            (
                "policy.gate_event_indexer",
                self.policy.gate_event_indexer.value.to_string(),
                self.policy.gate_event_indexer.origin.to_string(),
            ),
            (
                "policy.gate_source_level",
                self.policy.gate_source_level.value.to_string(),
                self.policy.gate_source_level.origin.to_string(),
            ),
            (
                "policy.gate_runtime_surface",
                self.policy.gate_runtime_surface.value.to_string(),
                self.policy.gate_runtime_surface.origin.to_string(),
            ),
            (
                "limits.max_xdr_depth",
                self.limits.max_xdr_depth.value.to_string(),
                self.limits.max_xdr_depth.origin.to_string(),
            ),
            (
                "limits.max_xdr_len",
                self.limits.max_xdr_len.value.to_string(),
                self.limits.max_xdr_len.origin.to_string(),
            ),
            (
                "limits.max_entries",
                self.limits.max_entries.value.to_string(),
                self.limits.max_entries.origin.to_string(),
            ),
            (
                "limits.max_walk_depth",
                self.limits.max_walk_depth.value.to_string(),
                self.limits.max_walk_depth.origin.to_string(),
            ),
        ]
    }

    fn to_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "config".to_string(),
            serde_json::json!({
                "value": self.config.value.as_deref().map(display_path),
                "origin": self.config.origin,
            }),
        );
        map.insert("strict".to_string(), serde_json::json!(self.strict));
        map.insert("explain".to_string(), serde_json::json!(self.explain));
        map.insert("ascii".to_string(), serde_json::json!(self.ascii));
        map.insert(
            "no_timestamp".to_string(),
            serde_json::json!(self.no_timestamp),
        );
        map.insert("policy".to_string(), serde_json::json!(self.policy));
        map.insert("limits".to_string(), serde_json::json!(self.limits));
        serde_json::Value::Object(map)
    }
}

/// Named settings as a flat map, for callers that want key-addressed access.
#[must_use]
pub fn settings_map(settings: &ResolvedSettings) -> BTreeMap<String, String> {
    settings
        .rows()
        .into_iter()
        .map(|(key, value, _)| (key.to_string(), value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sus-manifest-{}-{}-{:?}",
            name,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        dir
    }

    fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("failed to create parent dir");
        }
        fs::write(&path, contents).expect("failed to write file");
        path
    }

    #[test]
    fn flat_manifest_still_resolves() {
        let dir = temp_dir("flat");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            name = "a"
            "#,
        );

        let resolved = resolve(&root, &CliSettings::default()).expect("resolve failed");
        assert_eq!(resolved.pairs.len(), 1);
        assert_eq!(resolved.pairs[0].name, "a");
        // Relative paths anchor on the manifest's own directory.
        assert_eq!(resolved.pairs[0].old, dir.join("a_v1.wasm"));
        assert_eq!(resolved.sources, vec![root]);
    }

    #[test]
    fn schema_paths_resolve_from_manifest_and_accept_hyphenated_aliases() {
        let dir = temp_dir("schema-paths");
        let root = write(
            &dir,
            "manifests/root.toml",
            r#"
            [[pairs]]
            old = "../wasm/a_v1.wasm"
            new = "../wasm/a_v2.wasm"
            old-storage-schema = "../schemas/a_v1.toml"
            new_storage_schema = "../schemas/a_v2.json"
            "#,
        );

        let resolved = resolve(&root, &CliSettings::default()).expect("resolve failed");
        let pair = &resolved.pairs[0];
        let manifest_dir = dir.join("manifests");
        assert_eq!(pair.old, manifest_dir.join("../wasm/a_v1.wasm"));
        assert_eq!(pair.new, manifest_dir.join("../wasm/a_v2.wasm"));
        assert_eq!(
            pair.old_storage_schema,
            Some(manifest_dir.join("../schemas/a_v1.toml"))
        );
        assert_eq!(
            pair.new_storage_schema,
            Some(manifest_dir.join("../schemas/a_v2.json"))
        );
    }

    #[test]
    fn name_defaults_to_new_file_name() {
        let dir = temp_dir("naming");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].name, "a_v2.wasm");
    }

    #[test]
    fn valued_settings_are_last_writer_wins() {
        let dir = temp_dir("valued");
        write(
            &dir,
            "frag.toml",
            r#"
            [defaults.policy]
            gate_event_indexer = true
            gate_source_level  = true
            "#,
        );
        let root = write(
            &dir,
            "root.toml",
            r#"
            include = ["frag.toml"]

            [defaults.policy]
            gate_source_level = false

            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"

            [pairs.policy]
            gate_call_abi = false
            "#,
        );

        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        let policy = &resolved.pairs[0].settings.policy;

        // Fragment sets it, nothing later overrides.
        assert!(policy.gate_event_indexer.value);
        assert_eq!(
            policy.gate_event_indexer.origin,
            Origin::File(dir.join("frag.toml"))
        );

        // Root [defaults] beats the included fragment.
        assert!(!policy.gate_source_level.value);
        assert_eq!(policy.gate_source_level.origin, Origin::File(root.clone()));

        // A pair can turn a gate off — gates are valued, not escalation.
        assert!(!policy.gate_call_abi.value);
        assert_eq!(policy.gate_call_abi.origin, Origin::File(root));

        // Untouched gate keeps the built-in default.
        assert!(policy.gate_storage_layout.value);
        assert_eq!(policy.gate_storage_layout.origin, Origin::BuiltIn);
    }

    #[test]
    fn escalation_booleans_or_chain_and_cannot_be_disabled() {
        let dir = temp_dir("escalate");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [defaults]
            strict = false

            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            strict = false

            [[pairs]]
            old = "b_v1.wasm"
            new = "b_v2.wasm"
            explain = true
            "#,
        );

        let cli = CliSettings {
            strict: true,
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();

        // `strict = false` everywhere cannot undo --strict.
        assert!(resolved.pairs[0].settings.strict.value);
        assert_eq!(resolved.pairs[0].settings.strict.origin, Origin::Cli);

        // A pair may escalate on its own.
        assert!(!resolved.pairs[0].settings.explain.value);
        assert!(resolved.pairs[1].settings.explain.value);
        assert_eq!(
            resolved.pairs[1].settings.explain.origin,
            Origin::File(root)
        );
    }

    #[test]
    fn manifest_config_outranks_cli_but_not_no_config() {
        let dir = temp_dir("config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [defaults]
            config = "team.safeguard.toml"

            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"

            [[pairs]]
            old = "b_v1.wasm"
            new = "b_v2.wasm"
            config = "b.safeguard.toml"
            "#,
        );

        let cli = CliSettings {
            config: Some(PathBuf::from("/cli/.safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(dir.join("team.safeguard.toml"))
        );
        assert_eq!(
            resolved.pairs[1].settings.config.value,
            Some(dir.join("b.safeguard.toml"))
        );

        let cli = CliSettings {
            config: Some(PathBuf::from("/cli/.safeguard.toml")),
            no_config: true,
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(resolved.pairs[0].settings.config.value, None);
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::Cli);
    }

    #[test]
    fn cli_config_is_the_fallback_when_no_layer_names_one() {
        let dir = temp_dir("config-fallback");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            config: Some(PathBuf::from("/cli/.safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(PathBuf::from("/cli/.safeguard.toml"))
        );
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::Cli);
    }

    #[test]
    fn discovered_default_config_sits_below_every_layer() {
        let dir = temp_dir("default-config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"

            [[pairs]]
            old = "b_v1.wasm"
            new = "b_v2.wasm"
            config = "b.safeguard.toml"
            "#,
        );
        let cli = CliSettings {
            default_config: Some(PathBuf::from(".safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();

        // Nothing else names a config: the discovered default applies, and says so.
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(PathBuf::from(".safeguard.toml"))
        );
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::BuiltIn);

        // A pair naming its own config outranks the discovered default.
        assert_eq!(
            resolved.pairs[1].settings.config.value,
            Some(dir.join("b.safeguard.toml"))
        );
        assert_eq!(resolved.pairs[1].settings.config.origin, Origin::File(root));
    }

    #[test]
    fn env_config_is_used_when_cli_config_and_manifest_layers_are_absent() {
        let dir = temp_dir("env-config-fallback");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            env_config: Some(PathBuf::from("/env/.safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(PathBuf::from("/env/.safeguard.toml"))
        );
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::Env);
    }

    #[test]
    fn cli_config_outranks_env_config() {
        let dir = temp_dir("cli-outranks-env-config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            config: Some(PathBuf::from("/cli/.safeguard.toml")),
            env_config: Some(PathBuf::from("/env/.safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(PathBuf::from("/cli/.safeguard.toml"))
        );
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::Cli);
    }

    #[test]
    fn env_config_outranks_discovered_default_config() {
        let dir = temp_dir("env-outranks-default-config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            env_config: Some(PathBuf::from("/env/.safeguard.toml")),
            default_config: Some(PathBuf::from(".safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(PathBuf::from("/env/.safeguard.toml"))
        );
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::Env);
    }

    #[test]
    fn no_config_outranks_env_config() {
        let dir = temp_dir("no-config-outranks-env-config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            env_config: Some(PathBuf::from("/env/.safeguard.toml")),
            no_config: true,
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(resolved.pairs[0].settings.config.value, None);
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::Cli);
    }

    // ── ancestor_config (--search-parent-config) ────────────────────────────

    #[test]
    fn ancestor_config_is_used_when_nothing_more_specific_resolves() {
        let dir = temp_dir("ancestor-config-fallback");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            ancestor_config: Some(PathBuf::from("/repo/.safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(PathBuf::from("/repo/.safeguard.toml"))
        );
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::BuiltIn);
    }

    #[test]
    fn default_config_outranks_ancestor_config() {
        let dir = temp_dir("default-outranks-ancestor-config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            default_config: Some(PathBuf::from(".safeguard.toml")),
            ancestor_config: Some(PathBuf::from("/repo/.safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(PathBuf::from(".safeguard.toml")),
            "the current-directory default must win over an ancestor match"
        );
    }

    #[test]
    fn env_config_outranks_ancestor_config() {
        let dir = temp_dir("env-outranks-ancestor-config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            env_config: Some(PathBuf::from("/env/.safeguard.toml")),
            ancestor_config: Some(PathBuf::from("/repo/.safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(PathBuf::from("/env/.safeguard.toml"))
        );
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::Env);
    }

    #[test]
    fn cli_config_outranks_ancestor_config() {
        let dir = temp_dir("cli-outranks-ancestor-config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            config: Some(PathBuf::from("/cli/.safeguard.toml")),
            ancestor_config: Some(PathBuf::from("/repo/.safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(PathBuf::from("/cli/.safeguard.toml"))
        );
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::Cli);
    }

    #[test]
    fn no_config_outranks_ancestor_config() {
        let dir = temp_dir("no-config-outranks-ancestor-config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let cli = CliSettings {
            ancestor_config: Some(PathBuf::from("/repo/.safeguard.toml")),
            no_config: true,
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(resolved.pairs[0].settings.config.value, None);
    }

    #[test]
    fn a_manifest_naming_its_own_config_outranks_ancestor_config() {
        let dir = temp_dir("manifest-outranks-ancestor-config");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            config = "team.safeguard.toml"
            "#,
        );
        let cli = CliSettings {
            ancestor_config: Some(PathBuf::from("/repo/.safeguard.toml")),
            ..CliSettings::default()
        };
        let resolved = resolve(&root, &cli).unwrap();
        assert_eq!(
            resolved.pairs[0].settings.config.value,
            Some(dir.join("team.safeguard.toml")),
            "a pair naming its own config is more specific than any CLI-level fallback"
        );
        assert_eq!(resolved.pairs[0].settings.config.origin, Origin::File(root));
    }

    #[test]
    fn includes_compose_depth_first_in_order() {
        let dir = temp_dir("depth-first");
        write(
            &dir,
            "b.toml",
            r#"
            [[pairs]]
            old = "b_v1.wasm"
            new = "b_v2.wasm"
            name = "b"
            "#,
        );
        write(
            &dir,
            "a.toml",
            r#"
            include = ["b.toml"]

            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            name = "a"
            "#,
        );
        let root = write(
            &dir,
            "root.toml",
            r#"
            include = ["a.toml"]

            [[pairs]]
            old = "r_v1.wasm"
            new = "r_v2.wasm"
            name = "root"
            "#,
        );

        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        let names: Vec<_> = resolved.pairs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["b", "a", "root"]);
        assert_eq!(
            resolved.sources,
            vec![dir.join("b.toml"), dir.join("a.toml"), root]
        );
    }

    #[test]
    fn base_dir_is_file_scoped() {
        let dir = temp_dir("base-dir");
        write(
            &dir,
            "team/frag.toml",
            r#"
            [defaults]
            base_dir = "../pool_artifacts"

            [[pairs]]
            old = "p_v1.wasm"
            new = "p_v2.wasm"
            name = "pool"
            "#,
        );
        let root = write(
            &dir,
            "root.toml",
            r#"
            include = ["team/frag.toml"]

            [defaults]
            base_dir = "root_artifacts"

            [[pairs]]
            old = "r_v1.wasm"
            new = "r_v2.wasm"
            name = "root"
            "#,
        );

        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        // The fragment keeps its own anchoring; the root's base_dir does not
        // reach into it.
        assert_eq!(
            resolved.pairs[0].old,
            dir.join("team/../pool_artifacts/p_v1.wasm")
        );
        assert_eq!(resolved.pairs[1].old, dir.join("root_artifacts/r_v1.wasm"));
    }

    #[test]
    fn absolute_pair_paths_ignore_base_dir() {
        let dir = temp_dir("absolute");
        let absolute = dir.join("elsewhere/x.wasm");
        let root = write(
            &dir,
            "root.toml",
            &format!(
                r#"
                [defaults]
                base_dir = "artifacts"

                [[pairs]]
                old = {:?}
                new = "y.wasm"
                name = "x"
                "#,
                absolute.to_str().unwrap()
            ),
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].old, absolute);
        assert_eq!(resolved.pairs[0].new, dir.join("artifacts/y.wasm"));
    }

    #[test]
    fn self_include_is_a_cycle() {
        let dir = temp_dir("self-cycle");
        let root = write(&dir, "root.toml", r#"include = ["root.toml"]"#);
        let error = resolve(&root, &CliSettings::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("include cycle"), "got: {error}");
    }

    #[test]
    fn mutual_include_reports_the_chain() {
        let dir = temp_dir("cycle");
        write(&dir, "b.toml", r#"include = ["a.toml"]"#);
        write(&dir, "a.toml", r#"include = ["b.toml"]"#);
        let root = write(&dir, "root.toml", r#"include = ["a.toml"]"#);

        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("include cycle"), "got: {error}");
        assert!(error.contains("a.toml → "), "chain missing: {error}");
        assert!(error.contains("b.toml"), "chain missing: {error}");
    }

    #[test]
    fn include_depth_is_capped() {
        let dir = temp_dir("depth");
        // A chain of MAX_INCLUDE_DEPTH + 1 includes below the root.
        let deepest = MAX_INCLUDE_DEPTH + 1;
        for level in 0..=deepest {
            let contents = if level == deepest {
                String::new()
            } else {
                format!("include = [\"level{}.toml\"]", level + 1)
            };
            write(&dir, &format!("level{level}.toml"), &contents);
        }
        let error = format!(
            "{:#}",
            resolve(&dir.join("level0.toml"), &CliSettings::default()).unwrap_err()
        );
        assert!(error.contains("maximum depth"), "got: {error}");
    }

    #[test]
    fn include_depth_at_the_cap_succeeds() {
        let dir = temp_dir("depth-ok");
        for level in 0..=MAX_INCLUDE_DEPTH {
            let contents = if level == MAX_INCLUDE_DEPTH {
                r#"
                [[pairs]]
                old = "a_v1.wasm"
                new = "a_v2.wasm"
                "#
                .to_string()
            } else {
                format!("include = [\"level{}.toml\"]", level + 1)
            };
            write(&dir, &format!("level{level}.toml"), &contents);
        }
        let resolved = resolve(&dir.join("level0.toml"), &CliSettings::default())
            .expect("a chain exactly at the cap must resolve");
        assert_eq!(resolved.pairs.len(), 1);
    }

    // ── max pairs ────────────────────────────────────────────────────────────

    /// A manifest body with `n` distinct pairs, none of which need to exist on
    /// disk — `resolve()` only resolves path strings, it never touches WASM.
    fn pairs_toml(n: usize) -> String {
        let mut out = String::new();
        for i in 0..n {
            out.push_str(&format!(
                "[[pairs]]\nold = \"a{i}_v1.wasm\"\nnew = \"a{i}_v2.wasm\"\n\n"
            ));
        }
        out
    }

    #[test]
    fn default_max_pairs_allows_an_ordinary_manifest() {
        let dir = temp_dir("max-pairs-default-ok");
        let root = write(&dir, "root.toml", &pairs_toml(3));
        let resolved = resolve(&root, &CliSettings::default())
            .expect("a manifest far under the default ceiling must resolve");
        assert_eq!(resolved.pairs.len(), 3);
    }

    #[test]
    fn default_max_pairs_rejects_a_manifest_over_the_default_ceiling() {
        let dir = temp_dir("max-pairs-default-over");
        let root = write(&dir, "root.toml", &pairs_toml(DEFAULT_MAX_PAIRS + 1));
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(
            error.contains(&format!("{} pairs", DEFAULT_MAX_PAIRS + 1)),
            "got: {error}"
        );
        assert!(
            error.contains(&format!("maximum of {DEFAULT_MAX_PAIRS}")),
            "got: {error}"
        );
        assert!(error.contains("--max-pairs"), "got: {error}");
    }

    #[test]
    fn custom_max_pairs_rejects_a_manifest_over_the_custom_limit() {
        let dir = temp_dir("max-pairs-custom-over");
        let root = write(&dir, "root.toml", &pairs_toml(3));
        let cli = CliSettings {
            max_pairs: 2,
            ..CliSettings::default()
        };
        let error = format!("{:#}", resolve(&root, &cli).unwrap_err());
        assert!(error.contains("3 pairs"), "got: {error}");
        assert!(error.contains("maximum of 2"), "got: {error}");
    }

    #[test]
    fn max_pairs_exactly_at_the_custom_limit_succeeds() {
        let dir = temp_dir("max-pairs-custom-boundary-ok");
        let root = write(&dir, "root.toml", &pairs_toml(3));
        let cli = CliSettings {
            max_pairs: 3,
            ..CliSettings::default()
        };
        let resolved =
            resolve(&root, &cli).expect("a manifest exactly at the limit must still resolve");
        assert_eq!(resolved.pairs.len(), 3);
    }

    #[test]
    fn max_pairs_one_over_the_custom_limit_is_rejected() {
        let dir = temp_dir("max-pairs-custom-boundary-over");
        let root = write(&dir, "root.toml", &pairs_toml(4));
        let cli = CliSettings {
            max_pairs: 3,
            ..CliSettings::default()
        };
        let error = format!("{:#}", resolve(&root, &cli).unwrap_err());
        assert!(error.contains("4 pairs"), "got: {error}");
        assert!(error.contains("maximum of 3"), "got: {error}");
    }

    #[test]
    fn max_pairs_check_counts_pairs_composed_across_includes() {
        // The cap applies to the whole composition, not per-file.
        let dir = temp_dir("max-pairs-across-includes");
        write(&dir, "frag.toml", &pairs_toml(2));
        let root = write(
            &dir,
            "root.toml",
            &format!("include = [\"frag.toml\"]\n\n{}", pairs_toml(2)),
        );
        let cli = CliSettings {
            max_pairs: 3,
            ..CliSettings::default()
        };
        let error = format!("{:#}", resolve(&root, &cli).unwrap_err());
        assert!(
            error.contains("4 pairs"),
            "included and root pairs must both count toward the cap, got: {error}"
        );
    }

    #[test]
    fn max_pairs_rejection_runs_before_the_precedence_fold() {
        // A manifest that would ALSO be rejected for a duplicate name must
        // report the pair-count violation instead: the cap is checked first,
        // ahead of the (more expensive) duplicate-detection fold.
        let dir = temp_dir("max-pairs-before-fold");
        let mut body = pairs_toml(3);
        body.push_str(
            "[[pairs]]\nold = \"dup_v1.wasm\"\nnew = \"dup_v2.wasm\"\nname = \"same\"\n\n",
        );
        body.push_str("[[pairs]]\nold = \"dup_v1.wasm\"\nnew = \"dup_v2.wasm\"\nname = \"same\"\n");
        let root = write(&dir, "root.toml", &body);
        let cli = CliSettings {
            max_pairs: 3,
            ..CliSettings::default()
        };
        let error = format!("{:#}", resolve(&root, &cli).unwrap_err());
        assert!(
            error.contains("maximum of 3"),
            "the pair-count cap must be reported ahead of the duplicate-name error, got: {error}"
        );
    }

    #[test]
    fn duplicate_names_name_both_files() {
        let dir = temp_dir("dupe");
        write(
            &dir,
            "frag.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            name = "token"
            "#,
        );
        let root = write(
            &dir,
            "root.toml",
            r#"
            include = ["frag.toml"]

            [[pairs]]
            old = "b_v1.wasm"
            new = "b_v2.wasm"
            name = "token"
            "#,
        );

        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(
            error.contains("Duplicate contract name 'token'"),
            "got: {error}"
        );
        assert!(error.contains("frag.toml"), "first file missing: {error}");
        assert!(error.contains("root.toml"), "second file missing: {error}");
    }

    // ── pair IDs ────────────────────────────────────────────────────────────

    #[test]
    fn id_defaults_to_the_resolved_name_when_omitted() {
        let dir = temp_dir("id-default");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old  = "a_v1.wasm"
            new  = "a_v2.wasm"
            name = "token"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].name, "token");
        assert_eq!(resolved.pairs[0].id, "token");
    }

    #[test]
    fn id_defaults_to_the_new_file_name_when_neither_name_nor_id_is_set() {
        let dir = temp_dir("id-default-filename");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].name, "a_v2.wasm");
        assert_eq!(resolved.pairs[0].id, "a_v2.wasm");
    }

    #[test]
    fn explicit_id_is_independent_of_name() {
        let dir = temp_dir("id-explicit");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old  = "a_v1.wasm"
            new  = "a_v2.wasm"
            name = "Token (v1 -> v2)"
            id   = "token-v1-v2"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].name, "Token (v1 -> v2)");
        assert_eq!(resolved.pairs[0].id, "token-v1-v2");
    }

    #[test]
    fn duplicate_explicit_ids_name_both_files() {
        let dir = temp_dir("id-dupe");
        write(
            &dir,
            "frag.toml",
            r#"
            [[pairs]]
            old  = "a_v1.wasm"
            new  = "a_v2.wasm"
            name = "token-a"
            id   = "shared-id"
            "#,
        );
        let root = write(
            &dir,
            "root.toml",
            r#"
            include = ["frag.toml"]

            [[pairs]]
            old  = "b_v1.wasm"
            new  = "b_v2.wasm"
            name = "token-b"
            id   = "shared-id"
            "#,
        );

        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(
            error.contains("Duplicate pair id 'shared-id'"),
            "got: {error}"
        );
        assert!(error.contains("frag.toml"), "first file missing: {error}");
        assert!(error.contains("root.toml"), "second file missing: {error}");
    }

    #[test]
    fn an_explicit_id_colliding_with_another_pairs_fallback_id_is_rejected() {
        // Pair 1 has no explicit id, so its id falls back to its name "dup".
        // Pair 2 explicitly claims "dup" too -> must still be caught.
        let dir = temp_dir("id-dupe-fallback");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old  = "a_v1.wasm"
            new  = "a_v2.wasm"
            name = "dup"

            [[pairs]]
            old  = "b_v1.wasm"
            new  = "b_v2.wasm"
            name = "token-b"
            id   = "dup"
            "#,
        );

        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("Duplicate pair id 'dup'"), "got: {error}");
    }

    #[test]
    fn empty_id_is_rejected() {
        let dir = temp_dir("id-empty");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            id  = ""
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("Invalid pair id"), "got: {error}");
    }

    #[test]
    fn id_with_whitespace_is_rejected() {
        let dir = temp_dir("id-whitespace");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            id  = "has space"
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(
            error.contains("Invalid pair id 'has space'"),
            "got: {error}"
        );
    }

    #[test]
    fn id_with_disallowed_characters_is_rejected() {
        let dir = temp_dir("id-bad-chars");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            id  = "token/v1"
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("Invalid pair id 'token/v1'"), "got: {error}");
    }

    #[test]
    fn id_allows_letters_digits_dash_underscore_dot() {
        let dir = temp_dir("id-valid-charset");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            id  = "Token-v1.2_beta"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].id, "Token-v1.2_beta");
    }

    #[test]
    fn a_name_with_characters_invalid_for_id_still_works_as_a_fallback() {
        // `name` has no charset restriction; a fallback id derived from it
        // must not be re-validated against the id charset, or an existing
        // manifest that never set `id` could start failing.
        let dir = temp_dir("id-fallback-not-revalidated");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old  = "a_v1.wasm"
            new  = "a_v2.wasm"
            name = "token (legacy name with spaces)"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default())
            .expect("a fallback id derived from an unrestricted name must not be rejected");
        assert_eq!(resolved.pairs[0].id, "token (legacy name with spaces)");
    }

    #[test]
    fn ids_are_unique_across_a_json_manifest_too() {
        let dir = temp_dir("id-json-dupe");
        let root = write(
            &dir,
            "root.json",
            r#"{"pairs":[
                {"old":"a_v1.wasm","new":"a_v2.wasm","name":"a","id":"same"},
                {"old":"b_v1.wasm","new":"b_v2.wasm","name":"b","id":"same"}
            ]}"#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("Duplicate pair id 'same'"), "got: {error}");
    }

    #[test]
    fn ids_accepted_in_a_json_manifest() {
        let dir = temp_dir("id-json-ok");
        let root = write(
            &dir,
            "root.json",
            r#"{"pairs":[{"old":"a_v1.wasm","new":"a_v2.wasm","name":"a","id":"a-1"}]}"#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].id, "a-1");
    }

    #[test]
    fn resolved_pair_json_includes_id() {
        let dir = temp_dir("id-json-output");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            id  = "a-1"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        let json = resolved.to_json();
        assert_eq!(json["pairs"][0]["id"], "a-1");
    }

    // ── labels ──────────────────────────────────────────────────────────────

    #[test]
    fn unlabeled_pair_has_an_empty_labels_list() {
        let dir = temp_dir("labels-none");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert!(resolved.pairs[0].labels.is_empty());
    }

    #[test]
    fn explicit_labels_are_accepted_and_ordered() {
        let dir = temp_dir("labels-explicit");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            labels = ["payments", "prod", "team-platform"]
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(
            resolved.pairs[0].labels,
            vec!["payments", "prod", "team-platform"]
        );
    }

    #[test]
    fn key_value_style_labels_with_a_colon_are_accepted() {
        // `:` is valid in labels (unlike in `id`) specifically for
        // `key:value` tags such as `service:token` / `stage:prod`.
        let dir = temp_dir("labels-colon");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            labels = ["service:token", "stage:prod"]
            "#,
        );
        let resolved =
            resolve(&root, &CliSettings::default()).expect("key:value labels must be accepted");
        assert_eq!(
            resolved.pairs[0].labels,
            vec!["service:token", "stage:prod"]
        );
    }

    #[test]
    fn a_colon_is_rejected_in_a_pair_id_even_though_labels_allow_it() {
        // Confirms the two validators genuinely diverge: `id` did not
        // silently inherit the wider label charset.
        let dir = temp_dir("id-rejects-colon");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            id  = "stage:prod"
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(
            error.contains("Invalid pair id 'stage:prod'"),
            "got: {error}"
        );
    }

    #[test]
    fn the_same_label_is_allowed_to_repeat_across_many_pairs() {
        // Labels group pairs together; the whole point is that many pairs
        // share one label. This must never be treated as a collision, unlike
        // `id`.
        let dir = temp_dir("labels-repeat-across-pairs");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            name   = "a"
            labels = ["prod"]

            [[pairs]]
            old    = "b_v1.wasm"
            new    = "b_v2.wasm"
            name   = "b"
            labels = ["prod"]

            [[pairs]]
            old    = "c_v1.wasm"
            new    = "c_v2.wasm"
            name   = "c"
            labels = ["prod"]
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default())
            .expect("repeated labels across pairs must not be rejected");
        assert_eq!(resolved.pairs.len(), 3);
        for pair in &resolved.pairs {
            assert_eq!(pair.labels, vec!["prod"]);
        }
    }

    #[test]
    fn duplicate_labels_within_one_pair_are_folded_to_first_occurrence() {
        let dir = temp_dir("labels-dedup-within-pair");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            labels = ["prod", "payments", "prod"]
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].labels, vec!["prod", "payments"]);
    }

    #[test]
    fn empty_label_is_rejected() {
        let dir = temp_dir("labels-empty");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            labels = [""]
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("Invalid label"), "got: {error}");
    }

    #[test]
    fn whitespace_label_is_rejected() {
        let dir = temp_dir("labels-whitespace");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            labels = ["has space"]
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("Invalid label 'has space'"), "got: {error}");
    }

    #[test]
    fn label_with_disallowed_characters_is_rejected() {
        let dir = temp_dir("labels-bad-chars");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            name   = "svc"
            labels = ["team/payments"]
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(
            error.contains("Invalid label 'team/payments'"),
            "got: {error}"
        );
        assert!(error.contains("svc"), "error should name the pair: {error}");
    }

    #[test]
    fn one_invalid_label_among_valid_ones_still_rejects_the_pair() {
        let dir = temp_dir("labels-mixed-validity");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            labels = ["prod", "bad label", "payments"]
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("Invalid label 'bad label'"), "got: {error}");
    }

    #[test]
    fn resolved_pair_json_includes_labels() {
        let dir = temp_dir("labels-json-output");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            labels = ["prod", "payments"]
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        let json = resolved.to_json();
        assert_eq!(
            json["pairs"][0]["labels"],
            serde_json::json!(["prod", "payments"])
        );
    }

    #[test]
    fn resolved_pair_json_has_an_empty_labels_array_when_unlabeled() {
        let dir = temp_dir("labels-json-empty");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        let json = resolved.to_json();
        assert_eq!(json["pairs"][0]["labels"], serde_json::json!([]));
    }

    #[test]
    fn labels_are_accepted_in_a_json_manifest() {
        let dir = temp_dir("labels-json-manifest");
        let root = write(
            &dir,
            "root.json",
            r#"{"pairs":[{"old":"a_v1.wasm","new":"a_v2.wasm","labels":["prod","payments"]}]}"#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].labels, vec!["prod", "payments"]);
    }

    #[test]
    fn labels_never_affect_pair_identity_or_duplicate_detection() {
        // Two pairs with the same label but different names/ids must resolve
        // fine; two pairs with the same name but different labels must still
        // collide on the name, unaffected by labels either way.
        let dir = temp_dir("labels-identity-independence");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old    = "a_v1.wasm"
            new    = "a_v2.wasm"
            name   = "token"
            labels = ["prod"]

            [[pairs]]
            old    = "b_v1.wasm"
            new    = "b_v2.wasm"
            name   = "token"
            labels = ["staging"]
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(
            error.contains("Duplicate contract name 'token'"),
            "differing labels must not mask a real name collision: {error}"
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let dir = temp_dir("unknown");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [defaults]
            strictt = true

            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("strictt"), "got: {error}");
    }

    #[test]
    fn both_parser_errors_are_reported() {
        let dir = temp_dir("parse-error");
        let root = write(&dir, "root.toml", "[[pairs]\nold = \"a\"\n");
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("TOML error:"), "got: {error}");
        assert!(error.contains("JSON error:"), "got: {error}");
        // The TOML parser reports a line/column span.
        assert!(error.contains("line 1"), "no position in: {error}");
    }

    #[test]
    fn json_manifests_parse() {
        let dir = temp_dir("json");
        let root = write(
            &dir,
            "root.json",
            r#"{"pairs":[{"old":"a_v1.wasm","new":"a_v2.wasm","name":"a"}]}"#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.pairs[0].name, "a");
    }

    #[test]
    fn includes_may_mix_formats() {
        let dir = temp_dir("mixed");
        write(
            &dir,
            "frag.json",
            r#"{"pairs":[{"old":"b_v1.wasm","new":"b_v2.wasm","name":"b"}]}"#,
        );
        let root = write(
            &dir,
            "root.toml",
            r#"
            include = ["frag.json"]

            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            name = "a"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        let names: Vec<_> = resolved.pairs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["b", "a"]);
    }

    #[test]
    fn missing_include_names_the_referring_file() {
        let dir = temp_dir("missing");
        let root = write(&dir, "root.toml", r#"include = ["nope.toml"]"#);
        let error = format!("{:#}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("nope.toml"), "got: {error}");
        assert!(error.contains("root.toml"), "referrer missing: {error}");
    }

    #[test]
    fn dependencies_are_composed_but_not_propagated() {
        let dir = temp_dir("deps");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "t_v1.wasm"
            new = "t_v2.wasm"
            name = "token"

            [[pairs]]
            old = "p_v1.wasm"
            new = "p_v2.wasm"
            name = "pool"

            [[dependencies]]
            caller = "pool"
            callee = "token"
            functions = ["transfer"]
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        assert_eq!(resolved.dependencies.len(), 1);
        assert_eq!(resolved.dependencies[0].dependency.caller, "pool");
        assert_eq!(resolved.dependencies[0].defined_in, root);
    }

    #[test]
    fn limits_fold_per_field() {
        let dir = temp_dir("limits");
        write(
            &dir,
            "frag.toml",
            r#"
            [defaults.limits]
            max_xdr_depth = 32
            max_entries   = 10
            "#,
        );
        let root = write(
            &dir,
            "root.toml",
            r#"
            include = ["frag.toml"]

            [defaults.limits]
            max_xdr_depth = 64

            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        let limits = &resolved.pairs[0].settings.limits;
        assert_eq!(limits.max_xdr_depth.value, 64);
        assert_eq!(limits.max_xdr_depth.origin, Origin::File(root));
        assert_eq!(limits.max_entries.value, 10);
        assert_eq!(
            limits.max_walk_depth.value,
            ResourcePolicy::default().max_walk_depth
        );
        assert_eq!(limits.max_walk_depth.origin, Origin::BuiltIn);
    }

    #[test]
    fn every_policy_gate_is_overridable_from_a_manifest() {
        // `PolicyOverrides` mirrors `suppression::PolicyConfig` field for field.
        // When a new axis is added there and not here, a manifest silently loses
        // the ability to configure it — and `deny_unknown_fields` turns the
        // attempt into a confusing hard error. This test pins the two together:
        // serializing a fully-populated override set must name every gate the
        // resolved policy reports, so adding an axis fails here first.
        let all_set = PolicyOverrides {
            gate_storage_layout: Some(false),
            gate_call_abi: Some(false),
            gate_event_indexer: Some(true),
            gate_source_level: Some(true),
            gate_runtime_surface: Some(false),
        };
        let folded = all_set.apply_to(PolicyConfig::default());
        assert!(!folded.gate_storage_layout);
        assert!(!folded.gate_call_abi);
        assert!(folded.gate_event_indexer);
        assert!(folded.gate_source_level);
        assert!(!folded.gate_runtime_surface);

        // Every gate the resolver reports must be settable through the schema.
        let reported: Vec<String> = cli_only_settings(&CliSettings::default())
            .rows()
            .into_iter()
            .filter(|(key, _, _)| key.starts_with("policy."))
            .map(|(key, _, _)| key.trim_start_matches("policy.").to_string())
            .collect();
        let settable = serde_json::to_value(all_set).expect("overrides must serialize");
        let settable = settable.as_object().expect("overrides is a map");
        for gate in &reported {
            assert!(
                settable.contains_key(gate),
                "gate '{gate}' is reported in provenance but cannot be set in a manifest; \
                 add it to PolicyOverrides"
            );
        }
        assert_eq!(reported.len(), settable.len(), "gates: {reported:?}");
    }

    #[test]
    fn a_manifest_can_override_the_runtime_surface_gate() {
        let dir = temp_dir("runtime-surface");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"

            [pairs.policy]
            gate_runtime_surface = false
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        let policy = &resolved.pairs[0].settings.policy;
        assert!(!policy.gate_runtime_surface.value);
        assert_eq!(policy.gate_runtime_surface.origin, Origin::File(root));

        let config = resolved.pairs[0]
            .settings
            .apply_policy(SuppressionConfig::default());
        assert!(!config.policy().gate_runtime_surface);
    }

    #[test]
    fn resolved_policy_folds_onto_a_suppression_config() {
        let settings = cli_only_settings(&CliSettings::default());
        let config = settings.apply_policy(SuppressionConfig::default());
        // Nothing overridden: the config's own policy survives untouched.
        assert!(config.policy().gate_call_abi);
        assert!(!config.policy().gate_event_indexer);

        let dir = temp_dir("apply-policy");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [defaults.policy]
            gate_call_abi      = false
            gate_event_indexer = true

            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).unwrap();
        let config = resolved.pairs[0]
            .settings
            .apply_policy(SuppressionConfig::default());
        assert!(!config.policy().gate_call_abi);
        assert!(config.policy().gate_event_indexer);
        assert!(config.policy().gate_storage_layout);
    }

    #[test]
    fn explain_text_lists_sources_and_origins() {
        let dir = temp_dir("explain");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [defaults]
            strict = true

            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            name = "a"
            "#,
        );
        let text = resolve(&root, &CliSettings::default())
            .unwrap()
            .explain_text();
        assert!(text.contains("root.toml"));
        assert!(text.contains("[1] a"));
        assert!(text.contains("strict"));
    }

    #[test]
    fn manifest_version_defaults_to_one() {
        let dir = temp_dir("version-default");
        let root = write(
            &dir,
            "root.toml",
            r#"
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).expect("resolve failed");
        assert_eq!(resolved.pairs.len(), 1);
    }

    #[test]
    fn manifest_version_supported_one_toml() {
        let dir = temp_dir("version-supported-toml");
        let root = write(
            &dir,
            "root.toml",
            r#"
            version = 1
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let resolved = resolve(&root, &CliSettings::default()).expect("resolve failed");
        assert_eq!(resolved.pairs.len(), 1);
    }

    #[test]
    fn manifest_version_supported_one_json() {
        let dir = temp_dir("version-supported-json");
        let root = write(
            &dir,
            "root.json",
            r#"{"version": 1, "pairs": [{"old": "a_v1.wasm", "new": "a_v2.wasm"}]}"#,
        );
        let resolved = resolve(&root, &CliSettings::default()).expect("resolve failed");
        assert_eq!(resolved.pairs.len(), 1);
    }

    #[test]
    fn manifest_version_mismatch_toml_rejected() {
        let dir = temp_dir("version-mismatch-toml");
        let root = write(
            &dir,
            "root.toml",
            r#"
            version = 2
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let error = resolve(&root, &CliSettings::default())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Unsupported manifest version"),
            "got: {error}"
        );
        assert!(error.contains("Supported version: 1"), "got: {error}");
        assert!(error.contains("encountered: 2"), "got: {error}");
    }

    #[test]
    fn manifest_version_mismatch_json_rejected() {
        let dir = temp_dir("version-mismatch-json");
        let root = write(
            &dir,
            "root.json",
            r#"{"version": 2, "pairs": [{"old": "a_v1.wasm", "new": "a_v2.wasm"}]}"#,
        );
        let error = resolve(&root, &CliSettings::default())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Unsupported manifest version"),
            "got: {error}"
        );
        assert!(error.contains("Supported version: 1"), "got: {error}");
        assert!(error.contains("encountered: 2"), "got: {error}");
    }

    #[test]
    fn manifest_version_mismatch_in_include_rejected() {
        let dir = temp_dir("version-mismatch-include");
        write(
            &dir,
            "frag.toml",
            r#"
            version = 2
            "#,
        );
        let root = write(
            &dir,
            "root.toml",
            r#"
            include = ["frag.toml"]
            [[pairs]]
            old = "a_v1.wasm"
            new = "a_v2.wasm"
            "#,
        );
        let error = resolve(&root, &CliSettings::default())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Unsupported manifest version"),
            "got: {error}"
        );
        assert!(error.contains("Supported version: 1"), "got: {error}");
        assert!(error.contains("encountered: 2"), "got: {error}");
    }

    #[test]
    fn manifest_whitespace_only_rejected() {
        let dir = temp_dir("manifest-whitespace");
        let root = write(&dir, "root.toml", "   \n\t  \n");
        // The "is empty" diagnostic is the underlying cause, wrapped by an
        // outer "Failed to load manifest" context; `to_string()` only shows
        // the outermost message, so the full chain is needed here (as the
        // CLI itself prints via `{:?}` when a run fails).
        let error = format!("{:?}", resolve(&root, &CliSettings::default()).unwrap_err());
        assert!(error.contains("is empty"), "got: {error}");
        assert!(error.contains("[[pairs]]"), "got: {error}");
        assert!(error.contains("\"pairs\":"), "got: {error}");
    }

    #[test]
    fn manifest_no_pairs_rejected() {
        let dir = temp_dir("manifest-no-pairs");
        let root = write(&dir, "root.toml", "version = 1");
        let error = resolve(&root, &CliSettings::default())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("contains no comparison pairs"),
            "got: {error}"
        );
        assert!(error.contains("[[pairs]]"), "got: {error}");
        assert!(error.contains("\"pairs\":"), "got: {error}");
    }
}

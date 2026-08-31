//! Incremental batch watch mode: re-run only the pairs a file-system change
//! actually affects, instead of recomputing every pair on every event.
//!
//! The one-shot batch loop recomputes the whole composition each run. For a
//! repository-scale manifest — dozens of contract pairs, each reading several
//! WASM builds, storage schemas, and a suppression config — a rebuild triggered
//! by a single file write must not recompute every pair. This module builds an
//! input dependency graph, maps normalized and debounced file-system events onto
//! the pairs that read the touched file, and reuses the last known result for
//! every pair the event did not touch.
//!
//! # Dependency graph
//!
//! For each pair the graph records every file it reads directly:
//!
//! - the `old` and `new` WASM builds,
//! - the optional `old_storage_schema` / `new_storage_schema` files,
//! - the pair's suppression config (the manifest-resolved `config` path).
//!
//! Manifest-mode runs add every file in the `include` chain as a *composition*
//! input: a change there resolves a fresh manifest, so pairs may appear,
//! disappear, or pick up new settings. Directory-mode runs add the two scanned
//! directories as *topology* inputs: a change there re-derives which pairs exist
//! (a file rename can promote a gap to a pair, demote one, or introduce a
//! new-only artifact). A single run-level input — the `--empirical-file`, when
//! present — is wired to every pair.
//!
//! # Event mapping
//!
//! Events are normalized to absolute, lexically-cleaned paths (so `./a.wasm`,
//! `a.wasm`, and an atomic replace of `a.wasm` all map to the same key), then
//! debounced into a single window. Within a window the affected set is:
//!
//! ```text
//!   manifest-source change      → resolve a fresh composition, then recompute
//!                                 every pair whose identity or settings changed
//!   dir-scan change             → re-derive the pair set, then recompute every
//!                                 pair added/removed/reconfigured
//!   direct input change         → recompute exactly the pairs that read it
//! ```
//!
//! Results for untouched pairs are carried over verbatim, then the full,
//! deterministically ordered aggregate verdict is re-rendered — a reader sees
//! the same report shape as a one-shot batch run, only recomputed lazily.
//!
//! # Fault tolerance
//!
//! A pair that fails to load or analyze becomes a `BatchResult::Error` and
//! nothing else is affected. A transient fault — a WASM copied into place via a
//! write-temp-then-rename, a manifest mid-edit, a directory momentarily
//! emptied — never terminates the watcher: the previous plan and results are
//! retained and the next event that resolves the file re-runs the affected pair.
//! Deleted and renamed inputs degrade to errors or disappear, and unaffected
//! contracts keep their last known verdict.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher};

use crate::{
    build_batch, compare_batch_pair, gap_to_result, handle_status_write,
    install_watch_sigterm_handler, oci_fetch_config, remote_fetch_config, render_batch_summary,
    render_gap_outputs, render_pair_outputs, resolve_text_width, watch_shutdown_requested, Args,
    BatchPair, BatchResult, BatchSummary, BuiltBatch, GapContract, NewOnlyContract, OutputSpec,
};
use soroban_upgrade_safeguard::manifest;

/// A resolved batch plus its input dependency graph.
struct BatchPlan {
    /// Contract name → pair, in deterministic name order.
    pairs: BTreeMap<String, BatchPair>,
    /// Normalized dependency file → names of the pairs that read it.
    inputs: HashMap<PathBuf, BTreeSet<String>>,
    /// Manifest `include`-chain files; a change re-resolves the composition.
    manifest_sources: Vec<PathBuf>,
    /// Directories watched recursively (directory-scan mode).
    dirs_to_scan: Vec<PathBuf>,
    /// Old-only artifacts (directory mode).
    gaps: Vec<GapContract>,
    /// New-only artifacts (directory mode).
    new_only: Vec<NewOnlyContract>,
    /// The composed manifest, when running in manifest mode.
    resolved_manifest: Option<manifest::ResolvedManifest>,
}

impl BatchPlan {
    fn from_built(built: BuiltBatch, args: &Args) -> Self {
        let pairs: BTreeMap<String, BatchPair> = built
            .pairs
            .into_iter()
            .map(|p| (p.name.clone(), p))
            .collect();
        let inputs = dependency_map(&pairs, args.empirical_file.as_deref());

        let manifest_sources = built
            .resolved_manifest
            .as_ref()
            .map(|m| {
                m.sources
                    .iter()
                    .map(|p| normalize_path(p))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let dirs_to_scan = if args.manifest.is_some() {
            Vec::new()
        } else {
            let mut dirs = Vec::new();
            if let Some(dir) = args.old_dir.as_deref() {
                dirs.push(normalize_path(dir));
            }
            if let Some(dir) = args.new_dir.as_deref() {
                dirs.push(normalize_path(dir));
            }
            dirs
        };

        Self {
            pairs,
            inputs,
            manifest_sources,
            dirs_to_scan,
            gaps: built.gaps,
            new_only: built.new_only,
            resolved_manifest: built.resolved_manifest,
        }
    }
}

/// Build the reverse dependency graph: every input file a pair reads, mapped
/// from its normalized absolute path to the name of each pair that reads it. A
/// run-level empirical file, when present, is wired to every pair.
fn dependency_map(
    pairs: &BTreeMap<String, BatchPair>,
    empirical: Option<&Path>,
) -> HashMap<PathBuf, BTreeSet<String>> {
    let mut inputs: HashMap<PathBuf, BTreeSet<String>> = HashMap::new();
    for (name, pair) in pairs {
        let name = name.clone();
        for file in pair_input_files(pair) {
            inputs
                .entry(normalize_path(&file))
                .or_default()
                .insert(name.clone());
        }
    }
    if let Some(empirical) = empirical {
        let all: BTreeSet<String> = pairs.keys().cloned().collect();
        inputs
            .entry(normalize_path(empirical))
            .or_default()
            .extend(all);
    }
    inputs
}

/// The files a single batch pair reads directly, before normalization.
fn pair_input_files(pair: &BatchPair) -> Vec<PathBuf> {
    let mut files = vec![pair.old.clone(), pair.new.clone()];
    if let Some(path) = &pair.old_storage_schema {
        files.push(path.clone());
    }
    if let Some(path) = &pair.new_storage_schema {
        files.push(path.clone());
    }
    if let Some(config) = &pair.settings.config.value {
        files.push(config.clone());
    }
    files
}

/// A deterministic fingerprint of the settings and paths that define a pair's
/// meaning. Two executions of the same pair under the same settings share a
/// fingerprint; a manifest edit that tightens `strict` or points a pair at a
/// different config changes it, and so triggers a recompute.
fn pair_fingerprint(pair: &BatchPair) -> u64 {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    pair.old.hash(&mut hasher);
    pair.new.hash(&mut hasher);
    pair.old_storage_schema.hash(&mut hasher);
    pair.new_storage_schema.hash(&mut hasher);
    pair.settings.config.value.hash(&mut hasher);
    pair.settings.strict.value.hash(&mut hasher);
    pair.settings.explain.value.hash(&mut hasher);
    pair.settings.ascii.value.hash(&mut hasher);
    pair.settings.no_timestamp.value.hash(&mut hasher);
    hasher.finish()
}

/// The set of pairs an event batch touches.
#[derive(Debug, Default)]
struct Affected {
    /// Names mapped directly from a touched input file.
    named: BTreeSet<String>,
    /// A manifest source changed: re-resolve the composition.
    manifest_changed: bool,
    /// A scanned-directory event: re-derive the pair topology.
    rescan: bool,
}

impl Affected {
    fn is_empty(&self) -> bool {
        self.named.is_empty() && !self.manifest_changed && !self.rescan
    }
}

/// Filesystem writes this watch run itself produces. `--watch` re-renders the
/// aggregate (and per-pair) reports into the output paths after every cycle; if
/// any of those paths live inside a watched directory, the watcher would see its
/// own writes and re-run forever. These paths are excluded from event mapping.
#[derive(Debug, Default)]
struct BatchIgnore {
    /// Exact output file paths, normalized.
    files: HashSet<PathBuf>,
    /// Output directories (e.g. `--per-contract-output-dir`); any event path
    /// beneath one is ignored.
    dirs: Vec<PathBuf>,
}

impl BatchIgnore {
    fn from_outputs(outputs: &[OutputSpec], args: &Args) -> Self {
        let mut ignore = Self::default();
        for output in outputs {
            if let Some(path) = &output.path {
                ignore.files.insert(normalize_path(path));
            }
        }
        if let Some(dir) = args.per_contract_output_dir.as_deref() {
            ignore.dirs.push(normalize_path(dir));
        }
        ignore
    }

    fn matches(&self, path: &Path) -> bool {
        let normalized = normalize_path(path);
        if self.files.contains(&normalized) {
            return true;
        }
        self.dirs.iter().any(|dir| normalized.starts_with(dir))
    }
}

/// Last-known pair results, kept in deterministic name order so the aggregate
/// report never reorders based on event timing.
struct ResultsCache {
    ordered: Vec<BatchResult>,
    index: HashMap<String, usize>,
}

impl ResultsCache {
    fn new() -> Self {
        Self {
            ordered: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Insert or replace a result, keeping the slice sorted by name.
    fn upsert(&mut self, result: BatchResult) {
        let name = result.name().to_string();
        if let Some(&idx) = self.index.get(&name) {
            self.ordered[idx] = result;
            return;
        }
        let pos = self.ordered.partition_point(|r| r.name() < name.as_str());
        self.ordered.insert(pos, result);
        self.rebuild_index();
    }

    fn remove(&mut self, name: &str) {
        if let Some(&idx) = self.index.get(name) {
            self.ordered.remove(idx);
            self.rebuild_index();
        }
    }

    fn contains(&self, name: &str) -> bool {
        self.index.contains_key(name)
    }

    fn results(&self) -> &[BatchResult] {
        &self.ordered
    }

    fn names(&self) -> impl Iterator<Item = &str> {
        self.ordered.iter().map(|r| r.name())
    }

    fn rebuild_index(&mut self) {
        self.index = self
            .ordered
            .iter()
            .enumerate()
            .map(|(i, r)| (r.name().to_string(), i))
            .collect();
    }
}

/// Make a path absolute against the current directory and lexically clean it so
/// `./a.wasm`, `a.wasm`, and a temp-rename of `a.wasm` map to the same key.
/// This is idempotent and does not require the path to exist, so it works for a
/// file that was just removed.
fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };

    let mut stack: Vec<PathBuf> = Vec::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => stack.push(PathBuf::from(prefix.as_os_str())),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if let Some(last) = stack.last() {
                    if last == Path::new("..") {
                        stack.push(PathBuf::from(".."));
                    } else {
                        stack.pop();
                    }
                } else {
                    stack.push(PathBuf::from(".."));
                }
            }
            Component::Normal(part) => stack.push(PathBuf::from(part)),
        }
    }

    let mut result = PathBuf::from(Component::RootDir.as_os_str());
    for part in stack {
        result.push(part);
    }
    result
}

/// Directories to watch for a given plan. Directory-scan roots are watched
/// recursively (builds can emit artifacts in subdirectories); every input
/// file's parent is watched non-recursively so a write-temp-then-rename of that
/// file is caught. The set is deduplicated and pruned of already-recursively
/// covered parents.
fn watch_dirs(plan: &BatchPlan) -> Vec<(PathBuf, RecursiveMode)> {
    let mut result: Vec<(PathBuf, RecursiveMode)> = Vec::new();
    let mut recursive_roots: Vec<PathBuf> = Vec::new();

    for dir in &plan.dirs_to_scan {
        recursive_roots.push(dir.clone());
        result.push((dir.clone(), RecursiveMode::Recursive));
    }

    let mut seen: HashSet<PathBuf> = result.iter().map(|(dir, _)| dir.clone()).collect();

    let mut consider = |path: &Path, seen: &mut HashSet<PathBuf>| {
        // Skip a parent that already falls under a recursively-watched root.
        if recursive_roots.iter().any(|root| path.starts_with(root)) {
            return;
        }
        if seen.insert(path.to_path_buf()) {
            result.push((path.to_path_buf(), RecursiveMode::NonRecursive));
        }
    };

    for file in plan.inputs.keys() {
        if let Some(parent) = file.parent() {
            if !parent.as_os_str().is_empty() {
                consider(parent, &mut seen);
            }
        }
    }
    for src in &plan.manifest_sources {
        if let Some(parent) = src.parent() {
            if !parent.as_os_str().is_empty() {
                consider(parent, &mut seen);
            }
        }
    }

    result
}

/// Map an event path to a pair and record whether it triggers a composition
/// re-resolve or a directory re-scan. Output files the watch run itself writes
/// are skipped. A scanned-directory event only triggers a re-scan when it could
/// change the pair topology: a `.wasm` artifact, or a file that is itself a
/// known input (a schema/config the pairs read). Transient build junk (`.tmp`,
/// write-temp-and-rename staging files) is ignored.
fn affected_by_paths(plan: &BatchPlan, paths: &[PathBuf], ignore: &BatchIgnore) -> Affected {
    let mut affected = Affected::default();
    for path in paths {
        let normalized = normalize_path(path);
        if ignore.matches(&normalized) {
            continue;
        }

        if plan.manifest_sources.iter().any(|s| s == &normalized) {
            affected.manifest_changed = true;
        }

        let is_known_input = plan.inputs.contains_key(&normalized);
        let is_wasm = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("wasm"));
        if plan.dirs_to_scan.iter().any(|d| normalized.starts_with(d))
            && (is_wasm || is_known_input)
        {
            affected.rescan = true;
        }

        if let Some(found) = plan.inputs.get(&normalized) {
            affected.named.extend(found.iter().cloned());
        }
    }
    affected
}

/// The directories a rebuilt plan wants to watch, reconciled against which
/// directories `watcher` is currently watching.
fn reconcile_watcher(
    watcher: &mut notify::RecommendedWatcher,
    plan: &BatchPlan,
    current: &mut Vec<(PathBuf, RecursiveMode)>,
) {
    let wanted = watch_dirs(plan);
    let wanted_set: HashSet<PathBuf> = wanted.iter().map(|(d, _)| d.clone()).collect();

    let stale: Vec<_> = current
        .iter()
        .filter(|(d, _)| !wanted_set.contains(d))
        .cloned()
        .collect();
    for (dir, _) in stale {
        let _ = watcher.unwatch(&dir);
        current.retain(|(d, _)| d != &dir);
    }

    let current_set: HashSet<PathBuf> = current.iter().map(|(d, _)| d.clone()).collect();
    for (dir, mode) in wanted {
        if !current_set.contains(&dir) {
            if let Err(e) = watcher.watch(&dir, mode) {
                eprintln!("Warning: cannot watch {}: {e}", dir.display());
            }
            current.push((dir, mode));
        }
    }
}

/// Whether a filesystem event describes a change we might need to act on.
///
/// `Access` events (an atime update from the watch process *reading* a watched
/// file while it compares, or from any unrelated reader) are pure noise: they
/// do not change content or topology but do recur as the watcher itself reads
/// its inputs, which would make every comparison re-trigger itself forever. Only
/// content/topology events (`Modify`, `Create`, `Remove`) are worth a re-run.
fn event_is_relevant(event: &notify::Event) -> bool {
    !matches!(
        event.kind,
        notify::EventKind::Access(_) | notify::EventKind::Any
    )
}

/// Collect the events that arrived within the debounce window after the first
/// (already-consumed) event, coalescing a burst such as write-temp-then-rename.
fn drain_events(rx: &mpsc::Receiver<notify::Event>, debounce_ms: u64) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(debounce_ms)) {
            Ok(event) => {
                if event_is_relevant(&event) {
                    paths.extend(event.paths);
                }
                if watch_shutdown_requested() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    paths
}

/// Entry point for `--watch` batch runs. Builds the initial plan and results,
/// renders the deterministic aggregate, then enters the event loop.
pub fn run_batch_watch(
    args: &Args,
    outputs: &[OutputSpec],
    progress: &dyn Fn(String),
) -> Result<()> {
    install_watch_sigterm_handler();

    let built = build_batch(args).context("Failed to resolve batch inputs for watch mode")?;
    let mut plan = BatchPlan::from_built(built, args);
    let mut results = ResultsCache::new();
    let mut fingerprints: HashMap<String, u64> = HashMap::new();
    let output_ignore = BatchIgnore::from_outputs(outputs, args);

    // Initial full cycle.
    run_cycle(
        &plan,
        &mut results,
        &mut fingerprints,
        args,
        outputs,
        progress,
        &BTreeSet::new(),
        true,
    )?;
    render_summary(&plan, &results, args, outputs, progress)?;
    report_new_only(&plan, progress);

    let mut cycle = 1u64;
    if args.watch_status_file.is_some() {
        let initial = soroban_upgrade_safeguard::watch_status::WatchStatus::starting(cycle);
        handle_status_write(&initial, args.watch_status_file.as_deref());
        let safe = results.results().iter().all(|r| r.report().is_safe());
        handle_status_write(&initial.completed(safe), args.watch_status_file.as_deref());
    }

    eprintln!(
        "\n👀 Watch mode active (debounce: {}ms) for {} pair(s). Waiting for file changes... (Ctrl+C or SIGTERM to stop)\n",
        args.watch_debounce_ms,
        plan.pairs.len()
    );

    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        if let Ok(event) = res {
            if event_is_relevant(&event) {
                tx.send(event).ok();
            }
        }
    })
    .map_err(|e| anyhow::anyhow!("Failed to create file watcher: {e}"))?;

    let mut current_dirs: Vec<(PathBuf, RecursiveMode)> = Vec::new();
    reconcile_watcher(&mut watcher, &plan, &mut current_dirs);

    loop {
        if watch_shutdown_requested() {
            eprintln!("\n🛑 SIGTERM received, shutting down watch mode...\n");
            break;
        }

        match rx.recv_timeout(Duration::from_millis(args.watch_debounce_ms)) {
            Ok(first) => {
                // The debounce window begins with the event that woke us; the
                // trailing drain collects the rest of the burst. Both count
                // toward the affected-pair set.
                let mut paths = first.paths;
                paths.extend(drain_events(&rx, args.watch_debounce_ms));
                if watch_shutdown_requested() {
                    eprintln!("\n🛑 SIGTERM received, shutting down watch mode...\n");
                    break;
                }

                let affected = affected_by_paths(&plan, &paths, &output_ignore);

                // An event batch that touched only ignored/output (or entirely
                // unmapped) files should not re-render anything.
                if affected.is_empty() {
                    continue;
                }

                // Structural change: re-resolve the composition or re-derive the
                // directory topology. Transient faults (a manifest mid-edit, a
                // directory momentarily emptied) keep the last known plan and
                // results, and the next event picks the file back up.
                let mut plan_rebuilt = false;
                if affected.manifest_changed || affected.rescan {
                    match build_batch(args) {
                        Ok(built) => {
                            let new_plan = BatchPlan::from_built(built, args);
                            reconcile_watcher(&mut watcher, &new_plan, &mut current_dirs);
                            plan = new_plan;
                            plan_rebuilt = true;
                            report_new_only(&plan, progress);
                        }
                        Err(e) => {
                            progress(format!(
                                "⚠️  Batch inputs changed but the composition could not be resolved: {e:#}\n   Retaining last known results and waiting for inputs to settle."
                            ));
                            continue;
                        }
                    }
                }

                cycle += 1;
                let status = soroban_upgrade_safeguard::watch_status::WatchStatus::starting(cycle);
                handle_status_write(&status, args.watch_status_file.as_deref());

                let recompute = impacted_pairs(&plan, &mut results, &mut fingerprints, &affected);
                let outcome = run_cycle(
                    &plan,
                    &mut results,
                    &mut fingerprints,
                    args,
                    outputs,
                    progress,
                    &recompute,
                    plan_rebuilt,
                );
                match outcome {
                    Ok(()) => match render_summary(&plan, &results, args, outputs, progress) {
                        Ok(()) => {
                            let safe = results.results().iter().all(|r| r.report().is_safe());
                            handle_status_write(
                                &status.completed(safe),
                                args.watch_status_file.as_deref(),
                            );
                        }
                        Err(e) => {
                            handle_status_write(
                                &status.failed(e.to_string()),
                                args.watch_status_file.as_deref(),
                            );
                            progress(format!("⚠️  Failed to render batch summary: {e:#}"));
                        }
                    },
                    Err(e) => {
                        handle_status_write(
                            &status.failed(e.to_string()),
                            args.watch_status_file.as_deref(),
                        );
                        progress(format!("⚠️  Error during comparison cycle: {e:#}"));
                    }
                }

                eprintln!(
                    "\n👀 Watch mode active (debounce: {}ms) for {} pair(s). Waiting for file changes... (Ctrl+C or SIGTERM to stop)\n",
                    args.watch_debounce_ms,
                    plan.pairs.len()
                );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {} // idle heart-beat; keep watching
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow::anyhow!("File watcher channel disconnected"));
            }
        }
    }

    if let Some(path) = args.watch_status_file.as_deref() {
        let status =
            soroban_upgrade_safeguard::watch_status::WatchStatus::starting(cycle).shutdown();
        handle_status_write(&status, Some(path));
    }

    Ok(())
}

/// Compute the set of pair names that must be recomputed this cycle.
///
/// An empty result set from the caller (initial run) means *everything*. On an
/// incremental cycle, recompute:
///
/// - pairs added since the last plan (new name),
/// - pairs whose fingerprint changed (a manifest edit re-pointed them),
/// - pairs named directly by a touched input file,
///
/// and drop cached results for names that no longer exist (in neither the pair
/// set nor the gap set).
fn impacted_pairs(
    plan: &BatchPlan,
    results: &mut ResultsCache,
    fingerprints: &mut HashMap<String, u64>,
    affected: &Affected,
) -> BTreeSet<String> {
    let mut recompute: BTreeSet<String> = BTreeSet::new();

    for (name, pair) in &plan.pairs {
        let fp = pair_fingerprint(pair);
        if fingerprints.get(name) != Some(&fp) {
            recompute.insert(name.clone());
        }
        if affected.named.contains(name) {
            recompute.insert(name.clone());
        }
    }

    let gap_names: HashSet<&str> = plan.gaps.iter().map(|g| g.name.as_str()).collect();
    let live: HashSet<&str> = plan.pairs.keys().map(|s| s.as_str()).collect();
    let stale: Vec<String> = results
        .names()
        .map(|n| n.to_string())
        .filter(|n| !live.contains(n.as_str()) && !gap_names.contains(n.as_str()))
        .collect();
    for name in stale {
        results.remove(&name);
        fingerprints.remove(&name);
    }

    recompute
}

/// Run the pairs in `recompute` and update the results cache. When `recompute`
/// is empty this is a full recompute of every pair in the plan. `recompute_gaps`
/// re-derives gap (old-only) results; it is set on structural cycles so a pair
/// demoted to a gap or a newly-detected gap gets the right report.
#[allow(clippy::too_many_arguments)]
fn run_cycle(
    plan: &BatchPlan,
    results: &mut ResultsCache,
    fingerprints: &mut HashMap<String, u64>,
    args: &Args,
    outputs: &[OutputSpec],
    progress: &dyn Fn(String),
    recompute: &BTreeSet<String>,
    recompute_gaps: bool,
) -> Result<()> {
    let remote_config = remote_fetch_config(args);
    let oci_config = oci_fetch_config(args);
    let width = resolve_text_width(args.width, std::io::stdout().is_terminal());
    let mut config_cache: HashMap<PathBuf, crate::SuppressionConfig> = HashMap::new();

    if recompute_gaps {
        for gap in &plan.gaps {
            let result = gap_to_result(gap, args);
            render_gap_outputs(&result, &gap.name, args, outputs, width, progress)?;
            results.upsert(result);
        }
    } else {
        for gap in &plan.gaps {
            if !results.contains(&gap.name) {
                let result = gap_to_result(gap, args);
                render_gap_outputs(&result, &gap.name, args, outputs, width, progress)?;
                results.upsert(result);
            }
        }
    }

    let target: Vec<String> = if recompute.is_empty() {
        plan.pairs.keys().cloned().collect()
    } else {
        recompute
            .iter()
            .filter(|name| plan.pairs.contains_key(*name))
            .cloned()
            .collect()
    };

    for name in &target {
        if let Some(pair) = plan.pairs.get(name) {
            let result = compare_batch_pair(
                pair,
                args,
                &remote_config,
                &oci_config,
                &mut config_cache,
                progress,
            );
            render_pair_outputs(&result, pair, args, outputs, width, progress)?;
            results.upsert(result);
            fingerprints.insert(name.clone(), pair_fingerprint(pair));
        }
    }

    Ok(())
}

/// Render the deterministic aggregate verdict for the current results.
fn render_summary(
    plan: &BatchPlan,
    results: &ResultsCache,
    args: &Args,
    outputs: &[OutputSpec],
    progress: &dyn Fn(String),
) -> Result<()> {
    let overall_safe = results.results().iter().all(|r| r.report().is_safe());
    let total_pairs = plan.pairs.len() + plan.gaps.len();
    let width = resolve_text_width(args.width, std::io::stdout().is_terminal());

    render_batch_summary(
        &BatchSummary {
            results: results.results(),
            overall_safe,
            total_pairs,
            strict: args.strict,
            ascii: args.ascii,
            plain: args.plain,
            width,
            resolved_manifest: plan.resolved_manifest.as_ref(),
        },
        outputs,
        progress,
    )?;
    Ok(())
}

/// Surface new-only artifacts (present in the new directory, absent from the
/// old one) the same way a one-shot batch run does. They are not comparison
/// pairs — there is no old build to judge them against — so they are reported
/// as a diagnostic rather than folded into any verdict.
fn report_new_only(plan: &BatchPlan, progress: &dyn Fn(String)) {
    if plan.new_only.is_empty() {
        return;
    }
    progress(format!(
        "Warning: {} .wasm file(s) in the new directory have no counterpart in \
         the old directory and were not compared:",
        plan.new_only.len()
    ));
    for contract in &plan.new_only {
        progress(format!(
            "  - {} ({})",
            contract.name,
            contract.new_path.display()
        ));
    }
    progress(
        "  A new contract is expected here; a renamed one is not. If any of these \
         is a rename, the old-side file must share its name for the upgrade to be \
         checked."
            .to_string(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf as P};

    fn settings() -> manifest::ResolvedSettings {
        manifest::cli_only_settings(&manifest::CliSettings::default())
    }

    fn pair(name: &str, old: &str, new: &str) -> BatchPair {
        BatchPair {
            name: name.to_string(),
            id: name.to_string(),
            labels: Vec::new(),
            old: P::from(old),
            new: P::from(new),
            old_storage_schema: None,
            new_storage_schema: None,
            settings: settings(),
        }
    }

    fn result(name: &str) -> BatchResult {
        BatchResult::Success {
            name: name.to_string(),
            id: name.to_string(),
            labels: Vec::new(),
            old_path: P::from("old.wasm"),
            new_path: P::from("new.wasm"),
            old_storage_schema: None,
            new_storage_schema: None,
            report: crate::report::SafetyReport::default(),
        }
    }

    #[test]
    fn normalize_path_is_absolute_clean_and_idempotent() {
        let a = normalize_path(Path::new("./a/./b.wasm"));
        let b = normalize_path(Path::new("a/b.wasm"));
        assert_eq!(a, b);
        assert!(a.is_absolute(), "normalized path must be absolute");
        let again = normalize_path(&a);
        assert_eq!(again, a, "normalization must be idempotent");
    }

    #[test]
    fn normalize_path_collapses_parent_segments() {
        let a = normalize_path(Path::new("artifacts/../old.wasm"));
        let b = normalize_path(Path::new("old.wasm"));
        assert_eq!(a, b);
    }

    #[test]
    fn normalize_path_handles_removed_and_atomic_replacement_paths() {
        // A path that no longer exists (a deleted file) must still normalize to
        // the same key the original input file registered under — this is what
        // lets a removal map onto its pair instead of being lost.
        let original = normalize_path(Path::new("target/wasm/contract.wasm"));
        let replaced = normalize_path(Path::new("./target/./wasm/contract.wasm"));
        assert_eq!(original, replaced);
        // And a write-temp-then-rename that lands on the same target path.
        let temp_rename = normalize_path(Path::new("target/wasm/contract.wasm"));
        assert_eq!(original, temp_rename);
    }

    #[test]
    fn dependency_map_wires_each_pair_to_its_input_files() {
        let mut pairs = BTreeMap::new();
        let mut p = pair("token", "old/token.wasm", "new/token.wasm");
        p.old_storage_schema = Some(P::from("schemas/old.toml"));
        p.new_storage_schema = Some(P::from("schemas/new.toml"));
        pairs.insert(p.name.clone(), p);
        pairs.insert(
            "pool".to_string(),
            pair("pool", "old/pool.wasm", "new/pool.wasm"),
        );

        let inputs = dependency_map(&pairs, None);
        assert_eq!(
            inputs[&normalize_path(Path::new("old/token.wasm"))].len(),
            1
        );
        assert!(inputs[&normalize_path(Path::new("old/token.wasm"))].contains("token"));
        assert_eq!(
            inputs[&normalize_path(Path::new("schemas/old.toml"))].len(),
            1
        );
        assert!(inputs[&normalize_path(Path::new("new/pool.wasm"))].contains("pool"));
    }

    #[test]
    fn empirical_file_is_wired_to_every_pair() {
        let mut pairs = BTreeMap::new();
        pairs.insert("token".to_string(), pair("token", "old.wasm", "new.wasm"));
        pairs.insert("pool".to_string(), pair("pool", "old2.wasm", "new.wasm"));
        let inputs = dependency_map(&pairs, Some(Path::new("emp.json")));
        assert_eq!(inputs[&normalize_path(Path::new("emp.json"))].len(), 2);
    }

    #[test]
    fn results_cache_keeps_render_order_deterministic() {
        let mut cache = ResultsCache::new();
        // Insert out of order; the cache must render in name order regardless.
        cache.upsert(result("zeta"));
        cache.upsert(result("alpha"));
        cache.upsert(result("mix"));
        let names: Vec<&str> = cache.results().iter().map(|r| r.name()).collect();
        assert_eq!(names, vec!["alpha", "mix", "zeta"]);

        // Replacing an existing key keeps the order and the slot count.
        cache.upsert(result("alpha"));
        let names: Vec<&str> = cache.results().iter().map(|r| r.name()).collect();
        assert_eq!(names, vec!["alpha", "mix", "zeta"]);
        assert_eq!(cache.results().len(), 3);
    }

    #[test]
    fn results_cache_removes_by_name() {
        let mut cache = ResultsCache::new();
        for name in ["n1", "n2", "n3"] {
            cache.upsert(result(name));
        }
        cache.remove("n2");
        assert!(!cache.contains("n2"));
        let names: Vec<&str> = cache.results().iter().map(|r| r.name()).collect();
        assert_eq!(names, vec!["n1", "n3"]);
    }

    #[test]
    fn fingerprint_changes_when_a_pair_config_changes() {
        let a = pair("aaa", "old.wasm", "new.wasm");
        let mut b = pair("aaa", "old.wasm", "new.wasm");
        b.settings.strict = manifest::Sourced {
            value: true,
            origin: manifest::Origin::BuiltIn,
        };
        assert_ne!(pair_fingerprint(&a), pair_fingerprint(&b));
        assert_eq!(pair_fingerprint(&a), pair_fingerprint(&a));
    }

    #[test]
    fn affected_maps_known_input_but_not_an_unknown_path() {
        let mut pairs = BTreeMap::new();
        pairs.insert("token".to_string(), pair("token", "old.wasm", "new.wasm"));
        let inputs = dependency_map(&pairs, None);
        let plan = BatchPlan {
            pairs,
            inputs,
            manifest_sources: Vec::new(),
            dirs_to_scan: vec![normalize_path(Path::new("dir"))],
            gaps: Vec::new(),
            new_only: Vec::new(),
            resolved_manifest: None,
        };
        let ignore = BatchIgnore::default();

        let affected_input = affected_by_paths(&plan, &[P::from("old.wasm")], &ignore);
        assert!(affected_input.named.contains("token"));
        assert!(!affected_input.rescan);

        let affected_dir = affected_by_paths(&plan, &[P::from("dir/other.wasm")], &ignore);
        assert!(affected_dir.rescan);
        assert!(affected_dir.named.is_empty());

        let affected_junk = affected_by_paths(&plan, &[P::from("dir/stage.tmp")], &ignore);
        assert!(!affected_junk.rescan);
        assert!(affected_junk.is_empty());

        let affected_unknown = affected_by_paths(&plan, &[P::from("unrelated.wasm")], &ignore);
        assert!(affected_unknown.named.is_empty());
    }
}

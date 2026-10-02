// SPDX-License-Identifier: MIT

//! A versioned, machine-readable export of the upgrade's impact graph:
//! which functions, types, storage declarations, and events exist on each
//! side of the upgrade, how they depend on one another, which findings
//! and cascades touch them, and which suppression policy covers which
//! finding.
//!
//! The diff engine already computes most of this internally
//! ([`crate::mapper::LayoutMapper`] for structural dependencies,
//! [`crate::diff::detect_cascading_layout_breaks`] for cascades,
//! [`crate::suppression::SuppressionConfig::matching_rule`] for policy) —
//! this module doesn't recompute any of that logic, it just assembles the
//! same facts into a graph shape external tooling (visualization,
//! release automation) can consume without parsing report prose.
//!
//! # Node identity
//!
//! A node's `id` is `"{kind}:{name}"` (e.g. `"function:transfer"`,
//! `"type:Balance"`, `"storage:balance_entry"`). These are deterministic —
//! the same contract spec always produces the same ids — but are not
//! guaranteed unique across two *different* contracts in a batch run,
//! which is why a batch export nests one graph per pair rather than
//! merging them (see `src/main.rs`'s batch JSON output).
//!
//! Finding nodes are the one exception: a `Finding` has no inherent name,
//! so its id is `"finding:{index:04}"` where `index` is its position
//! after sorting all findings by `(category, target, message)` — this
//! makes the id deterministic across repeated runs on the same input
//! without requiring findings to carry their own identifier.
//!
//! # Known simplification: cascade edges
//!
//! [`Finding::root_target`] is already flattened by cascade detection to
//! the *ultimate* root of a chain (`A -> B -> C` records `C`'s finding
//! with `root_target = A`, not `B`) — seen directly in
//! `detect_cascading_layout_breaks`. [`EdgeKind::Cascades`] edges here
//! mirror that: they run root → affected, not parent → child, so a
//! multi-hop chain renders as a star from the root rather than a path.
//! The intermediate hops are reconstructable from [`EdgeKind::DependsOn`]
//! edges (which are a full one-hop structural graph), just not from
//! `Cascades` edges alone.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::diff::{CompatibilityAxis, Finding};
use crate::spec::ContractSpec;
use crate::storage_schema::StorageSchema;
use crate::suppression::SuppressionConfig;

/// Current version of the impact-graph export format.
pub const IMPACT_GRAPH_SCHEMA_VERSION: u32 = 1;

/// The category [`detect_cascading_layout_breaks`](crate::diff) tags
/// every cascade finding with. Matched by string rather than imported as
/// a constant because `category` is a plain `String` on [`Finding`]
/// everywhere else too; see [`crate::category`].
const CASCADE_CATEGORY: &str = "Cascading Layout Break";

/// What kind of entity a node represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Function,
    /// A struct, enum, union, or error-enum (see [`GraphNode::subkind`] for
    /// which).
    Type,
    Storage,
    /// A [`NodeKind::Type`] whose name matches the diff engine's
    /// event-naming heuristic (see `crate::diff::is_event`), reclassified
    /// here rather than left as a plain type — consistent with how the
    /// diff engine already special-cases these for category selection.
    Event,
    Finding,
    /// A suppression rule that matched at least one finding in this run.
    Policy,
    /// A contract, used only by [`build_call_graph`]'s batch-level edges —
    /// never appears in a single-pair [`ImpactGraph`].
    Contract,
}

impl NodeKind {
    fn as_str(self) -> &'static str {
        match self {
            NodeKind::Function => "function",
            NodeKind::Type => "type",
            NodeKind::Storage => "storage",
            NodeKind::Event => "event",
            NodeKind::Finding => "finding",
            NodeKind::Policy => "policy",
            NodeKind::Contract => "contract",
        }
    }
}

/// Whether a node exists only on one side of the upgrade, on both with no
/// finding touching it, or on both with at least one finding touching it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Added,
    Removed,
    Retained,
    Changed,
    /// Applies to [`NodeKind::Finding`] and [`NodeKind::Policy`] nodes,
    /// which don't have an old/new-build presence of their own.
    NotApplicable,
}

/// How two nodes relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Direct (one-hop) structural dependency: the source's layout embeds
    /// the target (a struct field, an enum/union case payload).
    DependsOn,
    /// A cascading layout break reaching the target from the root cause.
    /// See the module docs for why this is root → affected, not
    /// parent → child.
    Cascades,
    /// A declared cross-contract call relationship (batch mode only; see
    /// [`build_call_graph`]).
    Calls,
    /// Links a finding node to the entity it concerns, or a policy node to
    /// the finding it suppresses.
    References,
}

impl EdgeKind {
    fn as_str(self) -> &'static str {
        match self {
            EdgeKind::DependsOn => "depends_on",
            EdgeKind::Cascades => "cascades",
            EdgeKind::Calls => "calls",
            EdgeKind::References => "references",
        }
    }
}

/// A single node in the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphNode {
    /// Stable, deterministic identifier — see the module docs.
    pub id: String,
    pub kind: NodeKind,
    /// Human-readable name (the bare function/type/storage/event name, the
    /// finding's message, or the policy rule's reason/id).
    pub label: String,
    pub status: NodeStatus,
    /// For [`NodeKind::Type`]: which spec map it came from
    /// (`"struct"`/`"enum"`/`"union"`/`"error_enum"`). `None` for every
    /// other kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subkind: Option<String>,
    /// Compatibility axes this node is implicated in, collected from every
    /// finding that references it. Empty when no finding does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub axes: Vec<CompatibilityAxis>,
}

/// A single edge in the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    /// Stable, deterministic identifier: `"{kind}:{source}->{target}"`.
    pub id: String,
    pub kind: EdgeKind,
    /// A node id (see [`GraphNode::id`]).
    pub source: String,
    /// A node id (see [`GraphNode::id`]).
    pub target: String,
    /// For [`EdgeKind::Calls`] edges built from a declared dependency with
    /// a non-empty watch list: the specific function names watched.
    /// Empty means "whole-interface dependency" (see
    /// [`crate::dependency::ContractDependency`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<String>,
}

/// Identity of one side of the upgrade (old or new build), as far as the
/// graph export cares — just enough to tell two exports apart, not a full
/// provenance record (see [`crate::rpc::RpcProvenance`] for that).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_hash: Option<String>,
}

impl BuildIdentity {
    pub fn new(sha256: Option<String>, interface_hash: Option<String>) -> Self {
        Self {
            sha256,
            interface_hash,
        }
    }
}

/// Caps on exported graph size, and what was actually included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
}

/// Default caps are generous for any realistically-sized single contract
/// (thousands of UDTs/functions would already be an unusual build) while
/// still bounding a maliciously or accidentally huge spec.
impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            max_nodes: 20_000,
            max_edges: 50_000,
        }
    }
}

/// Reports whether the exported graph was truncated to fit [`GraphLimits`],
/// and the true size before truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphLimitsSummary {
    pub max_nodes: usize,
    pub max_edges: usize,
    /// Nodes actually present in [`ImpactGraph::nodes`].
    pub node_count: usize,
    /// Edges actually present in [`ImpactGraph::edges`].
    pub edge_count: usize,
    /// The node count before any truncation. Equal to `node_count` unless
    /// `truncated` is `true`.
    pub total_nodes: usize,
    /// The edge count before any truncation. Equal to `edge_count` unless
    /// `truncated` is `true`.
    pub total_edges: usize,
    pub truncated: bool,
}

/// The exported graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImpactGraph {
    pub version: u32,
    pub old_build: BuildIdentity,
    pub new_build: BuildIdentity,
    /// Sorted by `id` — deterministic across repeated runs on the same
    /// input, independent of internal `HashMap` iteration order.
    pub nodes: Vec<GraphNode>,
    /// Sorted by `id` — see [`Self::nodes`].
    pub edges: Vec<GraphEdge>,
    pub limits: GraphLimitsSummary,
}

fn node_id(kind: NodeKind, name: &str) -> String {
    format!("{}:{}", kind.as_str(), name)
}

fn edge_id(kind: EdgeKind, source: &str, target: &str) -> String {
    format!("{}:{source}->{target}", kind.as_str())
}

/// Mirrors `crate::diff`'s event-naming heuristic (a private fn there) so
/// this module doesn't need to change that module's visibility. Kept as a
/// one-line duplicate rather than a shared helper: this *is* the whole
/// heuristic, and the two call sites independently choosing to drift
/// would be a much smaller problem than a shared one-liner being worth a
/// new module boundary.
fn is_event_name(name: &str) -> bool {
    name.to_lowercase().contains("event")
}

#[derive(Debug, Clone)]
struct NodeBuilder {
    kind: NodeKind,
    label: String,
    subkind: Option<String>,
    old_present: bool,
    new_present: bool,
    axes: HashSet<CompatibilityAxis>,
}

impl NodeBuilder {
    fn new(kind: NodeKind, label: impl Into<String>) -> Self {
        Self {
            kind,
            label: label.into(),
            subkind: None,
            old_present: false,
            new_present: false,
            axes: HashSet::new(),
        }
    }
}

/// Collect every function/type/event name declared in `spec`, tagged with
/// which side(s) of the upgrade it's present on.
fn collect_spec_nodes(
    spec: &ContractSpec,
    is_old: bool,
    nodes: &mut BTreeMap<String, NodeBuilder>,
    name_kind: &mut HashMap<String, NodeKind>,
) {
    for name in spec.functions.keys() {
        let id = node_id(NodeKind::Function, name);
        let entry = nodes
            .entry(id)
            .or_insert_with(|| NodeBuilder::new(NodeKind::Function, name.clone()));
        if is_old {
            entry.old_present = true;
        } else {
            entry.new_present = true;
        }
        name_kind
            .entry(name.clone())
            .or_insert(NodeKind::Function);
    }

    let udt_sources: [(&str, Vec<&String>); 4] = [
        ("struct", spec.structs.keys().collect()),
        ("enum", spec.enums.keys().collect()),
        ("union", spec.unions.keys().collect()),
        ("error_enum", spec.error_enums.keys().collect()),
    ];

    for (subkind, names) in udt_sources {
        for name in names {
            let kind = if is_event_name(name) {
                NodeKind::Event
            } else {
                NodeKind::Type
            };
            let id = node_id(kind, name);
            let entry = nodes
                .entry(id)
                .or_insert_with(|| NodeBuilder::new(kind, name.clone()));
            entry.subkind = Some(subkind.to_string());
            if is_old {
                entry.old_present = true;
            } else {
                entry.new_present = true;
            }
            name_kind.entry(name.clone()).or_insert(kind);
        }
    }
}

fn collect_storage_nodes(
    schema: &StorageSchema,
    is_old: bool,
    nodes: &mut BTreeMap<String, NodeBuilder>,
    name_kind: &mut HashMap<String, NodeKind>,
) {
    for decl in &schema.declarations {
        let id = node_id(NodeKind::Storage, &decl.name);
        let entry = nodes
            .entry(id)
            .or_insert_with(|| NodeBuilder::new(NodeKind::Storage, decl.name.clone()));
        if is_old {
            entry.old_present = true;
        } else {
            entry.new_present = true;
        }
        name_kind
            .entry(decl.name.clone())
            .or_insert(NodeKind::Storage);
    }
}

/// Resolve a finding's `target`/`type_name` to the node id it concerns,
/// when it concerns exactly one already-known node.
fn resolve_target_node(
    target: Option<&str>,
    type_name: Option<&str>,
    name_kind: &HashMap<String, NodeKind>,
) -> Option<String> {
    if let Some(t) = type_name {
        if let Some(kind) = name_kind.get(t) {
            return Some(node_id(*kind, t));
        }
    }
    let target = target?;
    if let Some(kind) = name_kind.get(target) {
        return Some(node_id(*kind, target));
    }
    if let Some((prefix, _rest)) = target.split_once('.') {
        if let Some(kind) = name_kind.get(prefix) {
            return Some(node_id(*kind, prefix));
        }
    }
    None
}

fn direct_dependency_edges(spec: &ContractSpec) -> HashSet<(String, String)> {
    let mapper = crate::mapper::LayoutMapper::new(spec);
    let reverse_deps = mapper.build_reverse_dependencies();
    let mut edges = HashSet::new();
    for (depended_upon, dependents) in reverse_deps {
        for dependent in dependents {
            edges.insert((dependent, depended_upon.clone()));
        }
    }
    edges
}

/// Assemble the impact graph for a single old/new contract comparison.
///
/// `findings` is the structural diff's finding list (e.g.
/// `DiffReport::findings`, or the structural subset of
/// `SafetyReport`'s); `suppressions` is whatever config was applied to
/// that comparison, used only to attribute [`NodeKind::Policy`] nodes —
/// this function does not re-run suppression matching logic beyond
/// calling [`SuppressionConfig::matching_rule`] once per finding.
pub fn build_impact_graph(
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
    findings: &[Finding],
    suppressions: &SuppressionConfig,
    storage_schemas: Option<(&StorageSchema, &StorageSchema)>,
    old_build: BuildIdentity,
    new_build: BuildIdentity,
    limits: &GraphLimits,
) -> ImpactGraph {
    let mut nodes: BTreeMap<String, NodeBuilder> = BTreeMap::new();
    let mut name_kind: HashMap<String, NodeKind> = HashMap::new();

    collect_spec_nodes(old_spec, true, &mut nodes, &mut name_kind);
    collect_spec_nodes(new_spec, false, &mut nodes, &mut name_kind);
    if let Some((old_schema, new_schema)) = storage_schemas {
        collect_storage_nodes(old_schema, true, &mut nodes, &mut name_kind);
        collect_storage_nodes(new_schema, false, &mut nodes, &mut name_kind);
    }

    let mut edge_set: BTreeMap<String, GraphEdge> = BTreeMap::new();
    for (source, target) in direct_dependency_edges(old_spec)
        .into_iter()
        .chain(direct_dependency_edges(new_spec))
    {
        let source_id = name_kind
            .get(&source)
            .map(|k| node_id(*k, &source))
            .unwrap_or_else(|| node_id(NodeKind::Type, &source));
        let target_id = name_kind
            .get(&target)
            .map(|k| node_id(*k, &target))
            .unwrap_or_else(|| node_id(NodeKind::Type, &target));
        let id = edge_id(EdgeKind::DependsOn, &source_id, &target_id);
        edge_set.entry(id.clone()).or_insert(GraphEdge {
            id,
            kind: EdgeKind::DependsOn,
            source: source_id,
            target: target_id,
            functions: Vec::new(),
        });
    }

    // Sort findings into a deterministic order before assigning ids, so a
    // finding's node id depends only on its own content, not on whatever
    // order the diff engine's internal maps happened to iterate in.
    let mut sorted_findings: Vec<&Finding> = findings.iter().collect();
    sorted_findings.sort_by(|a, b| {
        (
            &a.category,
            a.target.as_deref().unwrap_or(""),
            &a.message,
        )
            .cmp(&(&b.category, b.target.as_deref().unwrap_or(""), &b.message))
    });

    let mut referenced_node_ids: HashSet<String> = HashSet::new();
    let mut policy_nodes: BTreeMap<String, NodeBuilder> = BTreeMap::new();

    for (index, finding) in sorted_findings.into_iter().enumerate() {
        let finding_id = format!("finding:{index:04}");
        let mut finding_node = NodeBuilder::new(NodeKind::Finding, finding.message.clone());
        finding_node.axes = finding.axes.iter().copied().collect();
        // Finding nodes have no old/new-build presence of their own; both
        // flags stay false and `finalize_status` maps that to
        // `NotApplicable` for this kind.
        nodes.insert(finding_id.clone(), finding_node);

        if let Some(target_node_id) = resolve_target_node(
            finding.target.as_deref(),
            finding.type_name.as_deref(),
            &name_kind,
        ) {
            referenced_node_ids.insert(target_node_id.clone());
            if let Some(target_entry) = nodes.get_mut(&target_node_id) {
                target_entry.axes.extend(finding.axes.iter().copied());
            }
            let id = edge_id(EdgeKind::References, &finding_id, &target_node_id);
            edge_set.entry(id.clone()).or_insert(GraphEdge {
                id,
                kind: EdgeKind::References,
                source: finding_id.clone(),
                target: target_node_id,
                functions: Vec::new(),
            });
        }

        if finding.category == CASCADE_CATEGORY {
            if let (Some(root), Some(affected)) =
                (finding.root_target.as_deref(), finding.type_name.as_deref())
            {
                if let (Some(root_id), Some(affected_id)) = (
                    name_kind.get(root).map(|k| node_id(*k, root)),
                    name_kind.get(affected).map(|k| node_id(*k, affected)),
                ) {
                    let id = edge_id(EdgeKind::Cascades, &root_id, &affected_id);
                    edge_set.entry(id.clone()).or_insert(GraphEdge {
                        id,
                        kind: EdgeKind::Cascades,
                        source: root_id,
                        target: affected_id,
                        functions: Vec::new(),
                    });
                }
            }
        }

        if let Some(rule) = suppressions.matching_rule(finding) {
            let policy_name = rule
                .rule_id
                .clone()
                .unwrap_or_else(|| format!("{}|{}", rule.category(), rule.target().unwrap_or("")));
            let policy_id = node_id(NodeKind::Policy, &policy_name);
            let label = rule
                .reason()
                .map(|r| r.to_string())
                .unwrap_or_else(|| policy_name.clone());
            policy_nodes
                .entry(policy_id.clone())
                .or_insert_with(|| NodeBuilder::new(NodeKind::Policy, label));
            let id = edge_id(EdgeKind::References, &policy_id, &finding_id);
            edge_set.entry(id.clone()).or_insert(GraphEdge {
                id,
                kind: EdgeKind::References,
                source: policy_id,
                target: finding_id.clone(),
                functions: Vec::new(),
            });
        }
    }

    nodes.extend(policy_nodes);

    let mut graph_nodes: Vec<GraphNode> = nodes
        .into_iter()
        .map(|(id, builder)| {
            let status = match builder.kind {
                NodeKind::Finding | NodeKind::Policy | NodeKind::Contract => {
                    NodeStatus::NotApplicable
                }
                _ => match (builder.old_present, builder.new_present) {
                    (true, false) => NodeStatus::Removed,
                    (false, true) => NodeStatus::Added,
                    (true, true) => {
                        if referenced_node_ids.contains(&id) {
                            NodeStatus::Changed
                        } else {
                            NodeStatus::Retained
                        }
                    }
                    (false, false) => NodeStatus::NotApplicable,
                },
            };
            let mut axes: Vec<CompatibilityAxis> = builder.axes.into_iter().collect();
            axes.sort();
            GraphNode {
                id,
                kind: builder.kind,
                label: builder.label,
                status,
                subkind: builder.subkind,
                axes,
            }
        })
        .collect();
    graph_nodes.sort_by(|a, b| a.id.cmp(&b.id));

    let mut graph_edges: Vec<GraphEdge> = edge_set.into_values().collect();
    graph_edges.sort_by(|a, b| a.id.cmp(&b.id));

    let total_nodes = graph_nodes.len();
    let total_edges = graph_edges.len();
    let mut truncated = false;
    if graph_nodes.len() > limits.max_nodes {
        graph_nodes.truncate(limits.max_nodes);
        truncated = true;
    }
    if graph_edges.len() > limits.max_edges {
        graph_edges.truncate(limits.max_edges);
        truncated = true;
    }
    // A truncated node list can leave edges dangling (referencing a node
    // id that got cut); drop those rather than exporting an edge whose
    // endpoint a consumer can't find.
    if truncated {
        let kept_ids: HashSet<&str> = graph_nodes.iter().map(|n| n.id.as_str()).collect();
        graph_edges.retain(|e| kept_ids.contains(e.source.as_str()) && kept_ids.contains(e.target.as_str()));
    }

    ImpactGraph {
        version: IMPACT_GRAPH_SCHEMA_VERSION,
        old_build,
        new_build,
        limits: GraphLimitsSummary {
            max_nodes: limits.max_nodes,
            max_edges: limits.max_edges,
            node_count: graph_nodes.len(),
            edge_count: graph_edges.len(),
            total_nodes,
            total_edges,
            truncated,
        },
        nodes: graph_nodes,
        edges: graph_edges,
    }
}

/// Build batch-level `Calls` edges between declared contract dependencies
/// (`[[dependencies]]` entries in a batch manifest; see
/// [`crate::dependency::ContractDependency`]).
///
/// Node ids here are contract-qualified (`"contract:<name>"`) rather than
/// the function/type-qualified ids [`build_impact_graph`] produces,
/// because two different contracts in the same batch may both declare a
/// function or type with the same bare name — these nodes exist
/// specifically to avoid that collision when representing relationships
/// *between* a batch's per-pair graphs.
pub fn build_call_graph(
    dependencies: &[crate::dependency::ContractDependency],
) -> (Vec<GraphNode>, Vec<GraphEdge>) {
    let mut nodes: BTreeMap<String, GraphNode> = BTreeMap::new();
    let mut edges: BTreeMap<String, GraphEdge> = BTreeMap::new();

    for dep in dependencies {
        for name in [&dep.caller, &dep.callee] {
            let id = node_id(NodeKind::Contract, name);
            nodes.entry(id.clone()).or_insert_with(|| GraphNode {
                id,
                kind: NodeKind::Contract,
                label: name.clone(),
                status: NodeStatus::NotApplicable,
                subkind: None,
                axes: Vec::new(),
            });
        }

        let source_id = node_id(NodeKind::Contract, &dep.caller);
        let target_id = node_id(NodeKind::Contract, &dep.callee);
        let id = edge_id(EdgeKind::Calls, &source_id, &target_id);
        let mut functions = dep.functions.clone();
        functions.sort();
        functions.dedup();
        edges.insert(
            id.clone(),
            GraphEdge {
                id,
                kind: EdgeKind::Calls,
                source: source_id,
                target: target_id,
                functions,
            },
        );
    }

    (nodes.into_values().collect(), edges.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::Severity;
    use crate::suppression::{SuppressionConfig, SuppressionRule};
    use stellar_xdr::curr::{
        ScSpecTypeDef, ScSpecTypeUdt, ScSpecUdtStructFieldV0, ScSpecUdtStructV0, StringM, VecM,
    };

    fn udt_field(name: &str, type_: ScSpecTypeDef) -> ScSpecUdtStructFieldV0 {
        ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: name.try_into().unwrap(),
            type_,
        }
    }

    fn struct_def(name: &str, fields: Vec<ScSpecUdtStructFieldV0>) -> ScSpecUdtStructV0 {
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: name.try_into().unwrap(),
            fields: VecM::try_from(fields).unwrap(),
        }
    }

    fn udt_ref(name: &str) -> ScSpecTypeDef {
        ScSpecTypeDef::Udt(ScSpecTypeUdt {
            name: name.try_into().unwrap(),
        })
    }

    fn finding(category: &str, target: Option<&str>, type_name: Option<&str>) -> Finding {
        Finding {
            severity: Severity::Critical,
            axes: vec![CompatibilityAxis::StorageLayout],
            category: category.to_string(),
            message: format!("{category} on {target:?}"),
            type_name: type_name.map(|s| s.to_string()),
            target: target.map(|s| s.to_string()),
            root_target: None,
            change: None,
        }
    }

    #[test]
    fn added_removed_and_retained_nodes_are_classified() {
        let mut old_spec = ContractSpec::default();
        old_spec
            .structs
            .insert("Removed".to_string(), struct_def("Removed", vec![]));
        old_spec
            .structs
            .insert("Kept".to_string(), struct_def("Kept", vec![]));

        let mut new_spec = ContractSpec::default();
        new_spec
            .structs
            .insert("Kept".to_string(), struct_def("Kept", vec![]));
        new_spec
            .structs
            .insert("Added".to_string(), struct_def("Added", vec![]));

        let graph = build_impact_graph(
            &old_spec,
            &new_spec,
            &[],
            &SuppressionConfig::default(),
            None,
            BuildIdentity::default(),
            BuildIdentity::default(),
            &GraphLimits::default(),
        );

        let status_of = |id: &str| {
            graph
                .nodes
                .iter()
                .find(|n| n.id == id)
                .unwrap_or_else(|| panic!("missing node {id}, got {:?}", graph.nodes))
                .status
        };
        assert_eq!(status_of("type:Removed"), NodeStatus::Removed);
        assert_eq!(status_of("type:Added"), NodeStatus::Added);
        assert_eq!(status_of("type:Kept"), NodeStatus::Retained);
    }

    #[test]
    fn a_finding_marks_its_target_node_changed_and_links_to_it() {
        let mut old_spec = ContractSpec::default();
        old_spec
            .structs
            .insert("Balance".to_string(), struct_def("Balance", vec![]));
        let mut new_spec = ContractSpec::default();
        new_spec
            .structs
            .insert("Balance".to_string(), struct_def("Balance", vec![]));

        let findings = vec![finding(
            "Struct Field Type Changed",
            Some("Balance.amount"),
            Some("Balance"),
        )];

        let graph = build_impact_graph(
            &old_spec,
            &new_spec,
            &findings,
            &SuppressionConfig::default(),
            None,
            BuildIdentity::default(),
            BuildIdentity::default(),
            &GraphLimits::default(),
        );

        let balance = graph
            .nodes
            .iter()
            .find(|n| n.id == "type:Balance")
            .expect("Balance node present");
        assert_eq!(balance.status, NodeStatus::Changed);
        assert!(balance.axes.contains(&CompatibilityAxis::StorageLayout));

        let has_reference_edge = graph.edges.iter().any(|e| {
            e.kind == EdgeKind::References && e.target == "type:Balance" && e.source.starts_with("finding:")
        });
        assert!(has_reference_edge, "edges: {:?}", graph.edges);
    }

    #[test]
    fn mutually_recursive_types_produce_a_two_cycle_without_hanging() {
        let mut old_spec = ContractSpec::default();
        old_spec.structs.insert(
            "A".to_string(),
            struct_def("A", vec![udt_field("b", udt_ref("B"))]),
        );
        old_spec.structs.insert(
            "B".to_string(),
            struct_def("B", vec![udt_field("a", udt_ref("A"))]),
        );
        let new_spec = ContractSpec::default();

        // The call below must return (not hang) even though A and B each
        // depend on the other — this is the cycle test.
        let graph = build_impact_graph(
            &old_spec,
            &new_spec,
            &[],
            &SuppressionConfig::default(),
            None,
            BuildIdentity::default(),
            BuildIdentity::default(),
            &GraphLimits::default(),
        );

        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::DependsOn
            && e.source == "type:A"
            && e.target == "type:B"));
        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::DependsOn
            && e.source == "type:B"
            && e.target == "type:A"));
        // Both nodes present exactly once each, despite the cycle.
        assert_eq!(graph.nodes.iter().filter(|n| n.id == "type:A").count(), 1);
        assert_eq!(graph.nodes.iter().filter(|n| n.id == "type:B").count(), 1);
    }

    #[test]
    fn cascading_layout_break_produces_a_root_to_affected_edge() {
        let mut old_spec = ContractSpec::default();
        old_spec.structs.insert(
            "Wrapper".to_string(),
            struct_def("Wrapper", vec![udt_field("inner", udt_ref("Inner"))]),
        );
        old_spec
            .structs
            .insert("Inner".to_string(), struct_def("Inner", vec![]));
        let new_spec = ContractSpec::default();

        let mut cascade = finding("Cascading Layout Break", Some("Wrapper"), Some("Wrapper"));
        cascade.root_target = Some("Inner".to_string());

        let graph = build_impact_graph(
            &old_spec,
            &new_spec,
            &[cascade],
            &SuppressionConfig::default(),
            None,
            BuildIdentity::default(),
            BuildIdentity::default(),
            &GraphLimits::default(),
        );

        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::Cascades
            && e.source == "type:Inner"
            && e.target == "type:Wrapper"));
    }

    #[test]
    fn a_suppressed_finding_gets_a_policy_node_and_edge() {
        let mut old_spec = ContractSpec::default();
        old_spec
            .structs
            .insert("Balance".to_string(), struct_def("Balance", vec![]));
        // "Balance" was removed in the new build — that's what the
        // "Struct Removed" finding below is about.
        let new_spec = ContractSpec::default();

        let findings = vec![finding(
            "Struct Removed",
            Some("Balance"),
            Some("Balance"),
        )];

        let suppressions = SuppressionConfig {
            rules: vec![SuppressionRule::new(
                "Struct Removed",
                Some("Balance"),
                Some("accepted for v2"),
            )],
            ..Default::default()
        };

        let graph = build_impact_graph(
            &old_spec,
            &new_spec,
            &findings,
            &suppressions,
            None,
            BuildIdentity::default(),
            BuildIdentity::default(),
            &GraphLimits::default(),
        );

        let policy_node = graph
            .nodes
            .iter()
            .find(|n| n.kind == NodeKind::Policy)
            .expect("a policy node should exist");
        assert_eq!(policy_node.label, "accepted for v2");

        assert!(graph.edges.iter().any(|e| e.kind == EdgeKind::References
            && e.source == policy_node.id
            && e.target.starts_with("finding:")));
    }

    #[test]
    fn graph_is_truncated_and_reports_true_totals_when_over_limit() {
        let mut old_spec = ContractSpec::default();
        for i in 0..10 {
            old_spec
                .structs
                .insert(format!("Type{i}"), struct_def(&format!("Type{i}"), vec![]));
        }
        let new_spec = ContractSpec::default();

        let tiny_limits = GraphLimits {
            max_nodes: 3,
            max_edges: 100,
        };

        let graph = build_impact_graph(
            &old_spec,
            &new_spec,
            &[],
            &SuppressionConfig::default(),
            None,
            BuildIdentity::default(),
            BuildIdentity::default(),
            &tiny_limits,
        );

        assert!(graph.limits.truncated);
        assert_eq!(graph.limits.node_count, 3);
        assert_eq!(graph.nodes.len(), 3);
        assert_eq!(graph.limits.total_nodes, 10);
    }

    #[test]
    fn event_named_types_are_classified_as_event_nodes() {
        let mut old_spec = ContractSpec::default();
        old_spec.structs.insert(
            "TransferEvent".to_string(),
            struct_def("TransferEvent", vec![]),
        );
        let mut new_spec = ContractSpec::default();
        new_spec.structs.insert(
            "TransferEvent".to_string(),
            struct_def("TransferEvent", vec![]),
        );

        let graph = build_impact_graph(
            &old_spec,
            &new_spec,
            &[],
            &SuppressionConfig::default(),
            None,
            BuildIdentity::default(),
            BuildIdentity::default(),
            &GraphLimits::default(),
        );

        let node = graph
            .nodes
            .iter()
            .find(|n| n.label == "TransferEvent")
            .expect("event node present");
        assert_eq!(node.kind, NodeKind::Event);
        assert_eq!(node.id, "event:TransferEvent");
    }

    #[test]
    fn call_graph_builds_contract_qualified_nodes_and_edges() {
        let deps = vec![crate::dependency::ContractDependency {
            caller: "Token".to_string(),
            callee: "Pool".to_string(),
            functions: vec!["swap".to_string(), "swap".to_string()],
        }];

        let (nodes, edges) = build_call_graph(&deps);

        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().any(|n| n.id == "contract:Token"));
        assert!(nodes.iter().any(|n| n.id == "contract:Pool"));
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, EdgeKind::Calls);
        assert_eq!(edges[0].functions, vec!["swap".to_string()]);
    }
}

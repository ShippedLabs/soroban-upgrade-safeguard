# Impact Graph Export

`soroban-upgrade-safeguard` already builds dependency information
internally to explain cascading breaks (which struct embeds which, which
finding's break propagates to which other type). `--impact-graph` exports
that same information as a versioned, machine-readable graph — functions,
types, storage declarations, events, findings, and suppression policy
decisions, as nodes, with their dependency/cascade/reference relationships
as edges — so reviewers and release tooling can consume it directly
instead of parsing report text.

## Usage

```bash
soroban-upgrade-safeguard old.wasm new.wasm --impact-graph --format json
```

This adds an `impact_graph` field to the JSON report (`SafetyReport`'s
`to_json()`/`RenderableReport`). Text and Markdown output show only a
short summary (node/edge counts, and whether the graph was truncated) —
see [Known limitations](#known-limitations) for why the full graph isn't
rendered as text. Works identically for batch runs (`--manifest`/
`--old-dir`+`--new-dir`): each pair's own `results[i].report.impact_graph`
is populated the same way.

Fetch the JSON Schema for the graph shape on its own (without running a
comparison):

```bash
soroban-upgrade-safeguard print-schema --target impact-graph
```

## Format

```json
{
  "version": 1,
  "old_build": { "sha256": "...", "interface_hash": "..." },
  "new_build": { "sha256": "...", "interface_hash": "..." },
  "nodes": [
    {
      "id": "type:Balance",
      "kind": "type",
      "label": "Balance",
      "status": "changed",
      "subkind": "struct",
      "axes": ["storage_layout"]
    }
  ],
  "edges": [
    {
      "id": "references:finding:0000->type:Balance",
      "kind": "references",
      "source": "finding:0000",
      "target": "type:Balance",
      "functions": []
    }
  ],
  "limits": {
    "max_nodes": 20000,
    "max_edges": 50000,
    "node_count": 2,
    "edge_count": 1,
    "total_nodes": 2,
    "total_edges": 1,
    "truncated": false
  }
}
```

### Node identity

A node's `id` is `"{kind}:{name}"` — e.g. `"function:transfer"`,
`"type:Balance"`, `"storage:balance_entry"`, `"event:TransferEvent"`.
These are deterministic (the same contract spec always produces the same
ids) but **not** guaranteed unique across two *different* contracts in a
batch run — that's why batch output nests one graph per pair rather than
merging them, mirroring how `report.to_json()` is already nested per pair
today.

`finding` nodes are the one exception: a finding has no inherent name, so
its id is `"finding:{index:04}"`, where `index` is its position after
sorting every finding in the comparison by `(category, target, message)`.
This makes finding ids deterministic across repeated runs on the same
input without requiring findings to carry their own identifier — but it
means a finding's id is **not** stable across *different* runs whose
finding set differs (adding or removing an unrelated finding elsewhere
can shift every later index). Don't treat finding ids as a durable
cross-run key; `target`/`category` on the node (via its `label` and the
edges touching it) are the durable parts.

### Node kinds

| Kind | Source | Notes |
| --- | --- | --- |
| `function` | `ContractSpec.functions` | identity is name only (Soroban has no overloading) |
| `type` | `ContractSpec.structs`/`.enums`/`.unions`/`.error_enums` | `subkind` says which map |
| `storage` | a supplied `StorageSchema`'s declarations | only present when a storage schema was supplied; see [Known limitations](#known-limitations) |
| `event` | a `type` node whose name matches the diff engine's event-naming heuristic (contains `"event"`, case-insensitively) | reclassified from `type`, not a separate spec source — see [Known limitations](#known-limitations) |
| `finding` | the structural diff's findings | `label` is the finding's message |
| `policy` | a suppression rule that matched at least one finding | `label` is the rule's reason, or its id/category+target if no reason was given |
| `contract` | [`build_call_graph`](#call-edges-cross-contract) only | never appears in a single-pair graph |

### Node status

`added` / `removed` / `retained` / `changed` for `function`/`type`/
`storage`/`event` nodes (based on presence in the old/new spec, and
whether any finding references the node); `not_applicable` for
`finding`/`policy`/`contract` nodes, which don't have an old/new-build
presence of their own.

### Edge kinds

| Kind | Meaning | Direction |
| --- | --- | --- |
| `depends_on` | direct (one-hop) structural dependency — the source's layout embeds the target (a struct field, an enum/union case payload) | dependent → depended-upon |
| `cascades` | a cascading layout break reaching the target from its ultimate root cause | root → affected (see caveat below) |
| `calls` | a declared cross-contract call relationship (batch mode only) | caller contract → callee contract |
| `references` | links a finding node to the entity it concerns, or a policy node to the finding it suppresses | finding → entity, or policy → finding |

**Cascade edges are root → affected, not parent → child.** The diff
engine's own `Finding::root_target` is already flattened: a chain
`A -> B -> C` records `C`'s finding with `root_target = A`, not `B`. This
export mirrors that rather than re-deriving the intermediate hop, so a
multi-level cascade renders as a star from the root. The intermediate
hops are still reconstructable from `depends_on` edges (a full one-hop
graph), just not from `cascades` edges alone.

### Call edges (cross-contract)

`crate::impact_graph::build_call_graph` turns a batch manifest's declared
`[[dependencies]]` (`crate::dependency::ContractDependency`) into
`contract`-kind nodes and `calls` edges. **This is not wired into the CLI
yet** — like `crate::dependency::DependencyGraph::propagate` itself (see
its own doc comments), it's a tested library function with no call site
in `main.rs`. A consumer that wants cross-contract call edges today needs
to call it directly against a resolved manifest's dependency list.

## Resource limits

`GraphLimits { max_nodes: 20_000, max_edges: 50_000 }` (in
`src/impact_graph.rs`) bounds the exported graph size. When exceeded, the
node/edge lists are truncated (lowest-sorted-id-first, so truncation is
deterministic) and `limits.truncated` is `true`, with `limits.total_nodes`/
`limits.total_edges` reporting the true pre-truncation size. Edges whose
endpoint got truncated away are dropped rather than left dangling.

These limits are **not yet configurable** via a CLI flag or
`.safeguard.toml` — unlike `src/limits.rs`'s `ResourcePolicy` (which
bounds *input* decoding and has both a config table and would-be CLI
flags), this is a smaller, separate struct specific to *output* sizing.
Wiring it into the same two-tier config idiom is a reasonable follow-up,
not done here to keep this change's surface smaller.

## Example visualization consumer

`examples/impact_graph_to_dot.py` reads an exported report (or a bare
`ImpactGraph` object) and emits [Graphviz](https://graphviz.org/) DOT:

```bash
soroban-upgrade-safeguard old.wasm new.wasm --impact-graph --format json > report.json
python3 examples/impact_graph_to_dot.py report.json > graph.dot
dot -Tsvg graph.dot -o graph.svg
```

Pure Python standard library, no dependencies. It's a minimal example —
color-by-kind, style-by-edge-kind, a truncation warning note — meant as a
starting point for a real consumer (a web UI, a different layout engine,
a diff view across runs), not a polished tool.

## Known limitations

- **Storage nodes require a supplied schema.** There's no first-class
  "storage declaration" derived from the WASM spec itself — Soroban specs
  don't carry one. Storage nodes only appear when `old_storage_schema`/
  `new_storage_schema` are threaded into `build_impact_graph`, which the
  CLI wiring in this change does not yet do (it always passes `None`).
  Until that's wired up, every exported graph has zero `storage` nodes
  regardless of `--old-storage-schema`/`--new-storage-schema`.
- **Event classification is a name heuristic**, not a real schema: a
  `type` node becomes an `event` node purely because its name contains
  `"event"` (case-insensitive) — the same heuristic `src/diff.rs`'s
  category selection already uses. `src/classification.rs` has a much
  richer, configurable `ClassificationConfig`/`TypeClass::Event` model,
  but it has no call sites anywhere in the diff/report pipeline today
  (confirmed by grep) — it would be a better source of truth once wired
  up, but reusing dead code here would just be two independently-drifting
  heuristics instead of one.
- **No call-graph within a single contract.** `calls` edges only exist at
  the batch, cross-contract level (declared dependencies), and even that
  isn't wired into the CLI yet (see [Call edges](#call-edges-cross-contract)).
  There's no "function A calls function B" edge within one contract —
  nothing in a Soroban spec or this tool's existing analysis currently
  derives that from WASM bytecode.
- **No `--impact-graph-file` side-channel export.** The graph is only
  available embedded in the JSON report today (`--impact-graph --format
  json`). A separate atomically-written file (mirroring `--metrics-file`'s
  pattern) is a natural follow-up, not implemented in this change.
- **Not wired into the Python/Node bindings** (`bindings/python`,
  `bindings/node`; see `docs/bindings.md`) — those wrap a narrower
  `binding_api::CompareRequest` that doesn't request a graph.

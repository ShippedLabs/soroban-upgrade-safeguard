#!/usr/bin/env python3
"""Example visualization consumer for soroban-upgrade-safeguard's impact graph.

Reads the `impact_graph` object this tool exports (either the whole JSON
report from `--format json --impact-graph`, or a bare `ImpactGraph` object
on its own) and emits a Graphviz DOT file. Render it with Graphviz itself:

    soroban-upgrade-safeguard old.wasm new.wasm --impact-graph --format json > report.json
    python3 examples/impact_graph_to_dot.py report.json > graph.dot
    dot -Tsvg graph.dot -o graph.svg

No third-party dependencies — stdlib `json` only — so it runs anywhere
Python 3 does, without needing this project's own Rust toolchain.

This is intentionally a minimal example, not a polished tool: it shows
how to walk the graph's documented shape (see docs/impact-graph.md) and
turn it into *some* visualization, as a starting point for a real
consumer (a web UI, a different graph layout engine, a diffing view
across multiple runs, ...).
"""

import json
import sys

# One fill color per node kind, chosen only for visual distinction --
# pick whatever palette suits your own rendering.
NODE_COLORS = {
    "function": "#cce5ff",
    "type": "#d4edda",
    "storage": "#fff3cd",
    "event": "#e2d9f3",
    "finding": "#f8d7da",
    "policy": "#d6d8d9",
    "contract": "#ffe5d0",
}

EDGE_STYLES = {
    "depends_on": "solid",
    "cascades": "bold",
    "calls": "dashed",
    "references": "dotted",
}


def dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def load_graph(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Accept either a full report (graph under "impact_graph") or a bare
    # ImpactGraph object (e.g. what --impact-graph-file would write, once
    # that side-channel export exists -- see docs/impact-graph.md).
    if "impact_graph" in data:
        graph = data["impact_graph"]
    else:
        graph = data
    if graph is None:
        raise SystemExit(
            "No impact graph found. Re-run with --impact-graph, e.g.:\n"
            "  soroban-upgrade-safeguard old.wasm new.wasm --impact-graph --format json"
        )
    return graph


def node_label(node: dict) -> str:
    """Build the node's DOT label, already escaped.

    Returns a string ready to drop straight into `label="..."` — the
    `\\n` here is DOT's own line-break escape inside a label, so it must
    survive `dot_escape` untouched; escaping each raw piece first and
    joining with it (rather than escaping the whole combined string
    afterward) keeps that `\\n` from being doubled into a literal
    backslash-n.
    """
    label = dot_escape(node.get("label", node["id"]))
    status = node.get("status")
    if status and status != "not_applicable":
        return f"{label}\\n({dot_escape(status)})"
    return label


def render_dot(graph: dict) -> str:
    lines = ["digraph impact_graph {", '  rankdir="LR";', "  node [style=filled];"]

    for node in graph.get("nodes", []):
        kind = node.get("kind", "type")
        color = NODE_COLORS.get(kind, "#ffffff")
        shape = "ellipse" if kind in ("finding", "policy") else "box"
        lines.append(
            '  "{id}" [label="{label}", fillcolor="{color}", shape={shape}];'.format(
                id=dot_escape(node["id"]),
                label=node_label(node),
                color=color,
                shape=shape,
            )
        )

    for edge in graph.get("edges", []):
        kind = edge.get("kind", "depends_on")
        style = EDGE_STYLES.get(kind, "solid")
        label = kind
        functions = edge.get("functions") or []
        if functions:
            label += ": " + ", ".join(functions)
        lines.append(
            '  "{src}" -> "{dst}" [label="{label}", style={style}];'.format(
                src=dot_escape(edge["source"]),
                dst=dot_escape(edge["target"]),
                label=dot_escape(label),
                style=style,
            )
        )

    limits = graph.get("limits") or {}
    if limits.get("truncated"):
        lines.append(
            '  limits_warning [shape=note, label="truncated: {shown} of {total} nodes shown", fontcolor=red];'.format(
                shown=limits.get("node_count"), total=limits.get("total_nodes")
            )
        )

    lines.append("}")
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <report.json>", file=sys.stderr)
        raise SystemExit(2)

    graph = load_graph(sys.argv[1])
    print(render_dot(graph))


if __name__ == "__main__":
    main()

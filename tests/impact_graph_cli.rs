//! CLI-level coverage for `--impact-graph` and `print-schema --target
//! impact-graph`: the graph fixtures the unit tests in
//! `src/impact_graph.rs` don't reach, because they go through the full
//! CLI pipeline (WASM parsing, spec extraction, diffing) rather than a
//! hand-built `ContractSpec`.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn wasm(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

fn run_json(old: &str, new: &str, extra_args: &[&str]) -> (Value, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .arg(wasm(old))
        .arg(wasm(new))
        .args(["--format", "json", "--no-color"])
        .args(extra_args)
        .output()
        .expect("failed to run binary");

    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let json: Value = serde_json::from_str(&stdout).expect("stdout was not valid JSON");
    let code = output.status.code().expect("process terminated by signal");
    (json, code)
}

#[test]
fn without_the_flag_no_impact_graph_is_present() {
    let (json, _code) = run_json("v1.wasm", "v2.wasm", &[]);
    assert!(
        json.get("impact_graph").is_none(),
        "impact_graph should be absent unless --impact-graph is passed"
    );
}

#[test]
fn impact_graph_flag_adds_a_versioned_graph_to_the_json_report() {
    let (json, _code) = run_json("v1.wasm", "v2.wasm", &["--impact-graph"]);
    let graph = json
        .get("impact_graph")
        .expect("impact_graph should be present when --impact-graph is passed");

    assert_eq!(graph["version"], 1);
    assert!(graph["nodes"].is_array());
    assert!(graph["edges"].is_array());

    let nodes = graph["nodes"].as_array().unwrap();
    assert!(!nodes.is_empty(), "comparing two non-trivial contracts should yield at least one node");

    // Every node must have a recognizable kind and a non-empty id — this
    // is a schema-shape smoke test, not a specific-content assertion,
    // since the exact structural diff between v1/v2 is covered by other
    // test files.
    let allowed_kinds = ["function", "type", "storage", "event", "finding", "policy", "contract"];
    for node in nodes {
        let kind = node["kind"].as_str().expect("node kind should be a string");
        assert!(allowed_kinds.contains(&kind), "unexpected node kind: {kind}");
        assert!(!node["id"].as_str().unwrap_or("").is_empty());
    }

    let allowed_edge_kinds = ["depends_on", "cascades", "calls", "references"];
    for edge in graph["edges"].as_array().unwrap() {
        let kind = edge["kind"].as_str().expect("edge kind should be a string");
        assert!(allowed_edge_kinds.contains(&kind), "unexpected edge kind: {kind}");
    }
}

#[test]
fn impact_graph_output_is_deterministic_across_repeated_runs() {
    let (first, _) = run_json("v1.wasm", "v2.wasm", &["--impact-graph", "--no-timestamp"]);
    let (second, _) = run_json("v1.wasm", "v2.wasm", &["--impact-graph", "--no-timestamp"]);
    assert_eq!(
        first["impact_graph"], second["impact_graph"],
        "the same inputs must produce byte-for-byte the same graph every run"
    );
}

#[test]
fn print_schema_impact_graph_target_emits_a_draft_07_schema() {
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-upgrade-safeguard"))
        .args(["print-schema", "--target", "impact-graph"])
        .output()
        .expect("failed to run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout was not valid UTF-8");
    let schema: Value = serde_json::from_str(&stdout).expect("schema output was not valid JSON");
    assert_eq!(
        schema["$schema"],
        "http://json-schema.org/draft-07/schema#"
    );
    let defs_key = if schema.get("definitions").is_some() {
        "definitions"
    } else {
        "$defs"
    };
    assert!(
        schema[defs_key].get("GraphNode").is_some() || schema["properties"].get("nodes").is_some(),
        "schema should describe the graph's node shape somewhere, got: {schema}"
    );
}

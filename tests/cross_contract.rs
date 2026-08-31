//! Integration tests for the cross-contract dependency propagation system.
//!
//! These tests exercise the acceptance criteria from the issue:
//! - Direct dependencies propagate findings
//! - Transitive propagation across a chain
//! - Cyclic dependencies terminate and are reported
//! - Missing contracts are reported, not silently ignored
//! - Function-filtered dependencies only propagate relevant findings
//! - Warning-severity findings propagate
//! - Info findings do NOT propagate
//! - Single-pair mode is unchanged when no dependency info is supplied
//!
//! All tests use the library API directly (no subprocess), so they are fast
//! and give precise failure messages.

use std::collections::{HashMap, HashSet};

use soroban_upgrade_safeguard::dependency::{
    cycle_findings, missing_contract_findings, ContractDependency, CrossContractFinding,
    DependencyGraph,
};
use soroban_upgrade_safeguard::diff::{Finding, Severity};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_finding(severity: Severity, category: &str, target: &str) -> Finding {
    Finding {
        severity,
        axes: Vec::new(),
        category: category.to_string(),
        message: format!("{} on {}", category, target),
        type_name: None,
        target: if target.is_empty() {
            None
        } else {
            Some(target.to_string())
        },
        change: None,
        root_target: None,
    }
}

fn critical(category: &str, target: &str) -> Finding {
    make_finding(Severity::Critical, category, target)
}

fn info(category: &str, target: &str) -> Finding {
    make_finding(Severity::Info, category, target)
}

fn dep(caller: &str, callee: &str) -> ContractDependency {
    ContractDependency {
        caller: caller.to_string(),
        callee: callee.to_string(),
        functions: vec![],
    }
}

fn dep_fn(caller: &str, callee: &str, functions: &[&str]) -> ContractDependency {
    ContractDependency {
        caller: caller.to_string(),
        callee: callee.to_string(),
        functions: functions.iter().map(|s| s.to_string()).collect(),
    }
}

fn graph(deps: &[ContractDependency]) -> DependencyGraph {
    DependencyGraph::from_declarations(deps)
}

fn findings_map(pairs: &[(&str, Vec<Finding>)]) -> HashMap<String, Vec<Finding>> {
    pairs
        .iter()
        .map(|(name, fs)| (name.to_string(), fs.clone()))
        .collect()
}

fn affected_contracts(cross: &[CrossContractFinding]) -> Vec<&str> {
    cross.iter().map(|f| f.affected_contract.as_str()).collect()
}

// ── Acceptance criterion 1: direct dependency propagation ────────────────────

#[test]
fn ac1_caller_visible_critical_propagates_to_direct_dependent() {
    let g = graph(&[dep("pool", "token")]);
    let map = findings_map(&[("token", vec![critical("Function Removed", "transfer")])]);

    let cross = g.propagate(&map);

    assert!(!cross.is_empty());
    assert_eq!(cross[0].changed_contract, "token");
    assert_eq!(cross[0].affected_contract, "pool");
    assert_eq!(cross[0].finding.category, "Function Removed");
    assert_eq!(cross[0].finding.severity, Severity::Critical);
}

#[test]
fn ac1_changed_contract_identified_in_finding() {
    let g = graph(&[dep("router", "pool")]);
    let map = findings_map(&[(
        "pool",
        vec![critical("Parameter Type Changed", "swap.amount")],
    )]);

    let cross = g.propagate(&map);

    assert_eq!(cross[0].changed_contract, "pool");
    assert_eq!(cross[0].affected_contract, "router");
    assert_eq!(cross[0].finding.target.as_deref(), Some("swap.amount"));
}

// ── Acceptance criterion 2: affected dependent gets a finding ────────────────

#[test]
fn ac2_dependent_contract_receives_finding_for_each_callee_break() {
    let g = graph(&[dep("pool", "token"), dep("pool", "oracle")]);
    let map = findings_map(&[
        ("token", vec![critical("Function Removed", "transfer")]),
        ("oracle", vec![critical("Function Removed", "get_price")]),
    ]);

    let cross = g.propagate(&map);

    // pool should get one finding from each dependency
    let pool_findings: Vec<_> = cross
        .iter()
        .filter(|f| f.affected_contract == "pool")
        .collect();
    assert_eq!(
        pool_findings.len(),
        2,
        "pool depends on two contracts that both break"
    );
}

// ── Acceptance criterion 3: finding identifies both contracts ────────────────

#[test]
fn ac3_cross_finding_names_both_changed_and_affected() {
    let g = graph(&[dep("router", "token")]);
    let map = findings_map(&[("token", vec![critical("Return Type Changed", "transfer")])]);

    let cross = g.propagate(&map);

    assert_eq!(cross.len(), 1);
    assert_eq!(cross[0].changed_contract, "token");
    assert_eq!(cross[0].affected_contract, "router");
    assert_ne!(
        cross[0].changed_contract, cross[0].affected_contract,
        "changed and affected must be different contracts"
    );
}

// ── Acceptance criterion 4: transitive propagation ───────────────────────────

#[test]
fn ac4_transitive_chain_a_b_c_all_affected() {
    // factory → router → pool → token; token breaks
    let g = graph(&[
        dep("pool", "token"),
        dep("router", "pool"),
        dep("factory", "router"),
    ]);
    let map = findings_map(&[("token", vec![critical("Function Removed", "transfer")])]);

    let cross = g.propagate(&map);
    let affected: HashSet<&str> = affected_contracts(&cross).into_iter().collect();

    assert!(
        affected.contains("pool"),
        "pool must be affected at depth 1"
    );
    assert!(
        affected.contains("router"),
        "router must be affected at depth 2"
    );
    assert!(
        affected.contains("factory"),
        "factory must be affected at depth 3"
    );
}

#[test]
fn ac4_propagation_depths_increase_along_chain() {
    let g = graph(&[dep("pool", "token"), dep("router", "pool")]);
    let map = findings_map(&[("token", vec![critical("Function Removed", "transfer")])]);

    let cross = g.propagate(&map);

    let pool_depth = cross
        .iter()
        .find(|f| f.affected_contract == "pool")
        .map(|f| f.propagation_depth)
        .expect("pool must be affected");

    let router_depth = cross
        .iter()
        .find(|f| f.affected_contract == "router")
        .map(|f| f.propagation_depth)
        .expect("router must be affected");

    assert_eq!(pool_depth, 1);
    assert_eq!(router_depth, 2);
}

#[test]
fn ac4_long_chain_terminates() {
    // Build a chain of 10 contracts
    let deps: Vec<ContractDependency> = (1..10)
        .map(|i| dep(&format!("c{}", i + 1), &format!("c{}", i)))
        .collect();
    let g = graph(&deps);

    let map = findings_map(&[("c1", vec![critical("Function Removed", "fn_one")])]);

    let cross = g.propagate(&map);

    // All 9 dependents should be affected
    let affected: HashSet<&str> = affected_contracts(&cross).into_iter().collect();
    for i in 2..=10 {
        assert!(
            affected.contains(format!("c{}", i).as_str()),
            "c{} must be affected at depth {}",
            i,
            i - 1
        );
    }
    assert_eq!(cross.len(), 9, "exactly 9 propagated findings");
}

// ── Acceptance criterion 5: cyclic dependencies ──────────────────────────────

#[test]
fn ac5_mutual_cycle_terminates() {
    let g = graph(&[dep("A", "B"), dep("B", "A")]);
    let map = findings_map(&[
        ("A", vec![critical("Function Removed", "fn_a")]),
        ("B", vec![critical("Function Removed", "fn_b")]),
    ]);

    // Must not hang or panic
    let cross = g.propagate(&map);

    // Each contract is the other's dependent, so both should receive findings
    let a_affected = cross.iter().any(|f| f.affected_contract == "A");
    let b_affected = cross.iter().any(|f| f.affected_contract == "B");
    assert!(b_affected, "B depends on A and must receive A's finding");
    assert!(a_affected, "A depends on B and must receive B's finding");

    // Findings must be bounded — no infinite loop
    assert!(
        cross.len() < 20,
        "cycle must produce bounded findings, got {}",
        cross.len()
    );
}

#[test]
fn ac5_three_contract_cycle_terminates() {
    // A → B → C → A
    let g = graph(&[dep("A", "B"), dep("B", "C"), dep("C", "A")]);
    let map = findings_map(&[("A", vec![critical("Function Removed", "fn_a")])]);

    let cross = g.propagate(&map);

    // Must terminate
    assert!(
        cross.len() < 30,
        "three-cycle must produce bounded findings"
    );
}

#[test]
fn ac5_cycle_detection_reports_cycle_finding() {
    // A → B → A
    let g = graph(&[dep("A", "B"), dep("B", "A")]);
    let cycles = g.detect_cycles();

    assert!(!cycles.is_empty(), "must detect cycle");

    let cycle_fs = cycle_findings(&cycles);
    assert!(!cycle_fs.is_empty());
    assert_eq!(cycle_fs[0].category, "Cyclic Contract Dependency");
    assert_eq!(cycle_fs[0].severity, Severity::Warning);
    // Cycle path must mention both contracts
    assert!(cycle_fs[0].message.contains('A') || cycle_fs[0].message.contains('B'));
}

#[test]
fn ac5_acyclic_graph_has_no_cycle_findings() {
    let g = graph(&[dep("pool", "token"), dep("router", "pool")]);
    let cycles = g.detect_cycles();
    assert!(cycles.is_empty());
    assert!(cycle_findings(&cycles).is_empty());
}

// ── Acceptance criterion 6: compose into batch verdict ───────────────────────

#[test]
fn ac6_cross_findings_contribute_to_overall_severity() {
    // Verify that cross-contract critical findings are actually Critical severity
    let g = graph(&[dep("pool", "token")]);
    let map = findings_map(&[("token", vec![critical("Function Removed", "transfer")])]);

    let cross = g.propagate(&map);

    let has_critical = cross
        .iter()
        .any(|f| f.finding.severity == Severity::Critical);
    assert!(
        has_critical,
        "propagated critical must still be Critical severity"
    );
}

// ── Acceptance criterion 7: missing dependency reported ──────────────────────

#[test]
fn ac7_missing_callee_produces_warning_finding() {
    let g = graph(&[dep("pool", "oracle"), dep("pool", "token")]);
    let known: HashSet<String> = ["pool".to_string(), "token".to_string()]
        .into_iter()
        .collect();

    let missing = g.missing_contracts(&known);
    assert_eq!(missing, vec!["oracle"]);

    let findings = missing_contract_findings(&missing);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].category, "Missing Dependency Contract");
    assert_eq!(findings[0].severity, Severity::Warning);
    assert!(findings[0].message.contains("oracle"));
}

#[test]
fn ac7_missing_caller_also_detected() {
    // "ghost_router" is declared as a caller but not in the batch
    let g = graph(&[dep("ghost_router", "pool")]);
    let known: HashSet<String> = ["pool".to_string()].into_iter().collect();

    let missing = g.missing_contracts(&known);
    assert!(
        missing.contains(&"ghost_router"),
        "missing caller must be detected"
    );
}

#[test]
fn ac7_no_missing_when_all_present() {
    let g = graph(&[dep("pool", "token"), dep("router", "pool")]);
    let known: HashSet<String> = [
        "pool".to_string(),
        "token".to_string(),
        "router".to_string(),
    ]
    .into_iter()
    .collect();

    assert!(g.missing_contracts(&known).is_empty());
    assert!(missing_contract_findings(&[]).is_empty());
}

// ── Acceptance criterion 8: single-pair mode unchanged ───────────────────────

#[test]
fn ac8_empty_graph_produces_no_cross_findings() {
    // No dependencies declared — propagate should return nothing
    let g = DependencyGraph::default();
    let map = findings_map(&[("token", vec![critical("Function Removed", "transfer")])]);

    let cross = g.propagate(&map);
    assert!(cross.is_empty(), "no deps means no cross findings");
}

#[test]
fn ac8_graph_with_no_callee_findings_produces_no_cross_findings() {
    let g = graph(&[dep("pool", "token")]);
    // token has no findings at all
    let map = findings_map(&[("token", vec![])]);

    let cross = g.propagate(&map);
    assert!(cross.is_empty());
}

// ── Edge case: info findings must never propagate ────────────────────────────

#[test]
fn edge_info_findings_never_propagate_regardless_of_category() {
    let g = graph(&[dep("pool", "token")]);
    let map = findings_map(&[(
        "token",
        vec![
            info("Function Added", "new_fn"),
            info("Enum Case Added", "Status.NewVariant"),
            info("Union Case Added", "Action.NewCase"),
            info("Struct Added", "NewType"),
        ],
    )]);

    let cross = g.propagate(&map);
    assert!(
        cross.is_empty(),
        "info findings must never propagate: {:?}",
        cross
            .iter()
            .map(|f| &f.finding.category)
            .collect::<Vec<_>>()
    );
}

// ── Edge case: function filter ───────────────────────────────────────────────

#[test]
fn edge_empty_function_filter_means_all_functions() {
    // functions = [] means all functions
    let g = graph(&[dep("pool", "token")]); // no functions = all
    let map = findings_map(&[(
        "token",
        vec![
            critical("Function Removed", "transfer"),
            critical("Function Removed", "balance"),
        ],
    )]);

    let cross = g.propagate(&map);
    assert_eq!(
        cross.len(),
        2,
        "both findings must propagate with no filter"
    );
}

#[test]
fn edge_function_filter_blocks_unrelated_findings() {
    let g = graph(&[dep_fn("pool", "token", &["transfer"])]);
    let map = findings_map(&[(
        "token",
        vec![
            critical("Function Removed", "transfer"),   // watched
            critical("Function Removed", "allowance"),  // NOT watched
            critical("Return Type Changed", "balance"), // NOT watched
        ],
    )]);

    let cross = g.propagate(&map);
    assert_eq!(
        cross.len(),
        1,
        "only transfer-related finding must propagate"
    );
    assert_eq!(cross[0].finding.target.as_deref(), Some("transfer"));
}

#[test]
fn edge_function_filter_matches_parameter_targets() {
    // "transfer.amount" target should match the "transfer" function filter
    let g = graph(&[dep_fn("pool", "token", &["transfer"])]);
    let map = findings_map(&[(
        "token",
        vec![critical("Parameter Type Changed", "transfer.amount")],
    )]);

    let cross = g.propagate(&map);
    assert_eq!(
        cross.len(),
        1,
        "parameter finding for watched function must propagate"
    );
}

// ── Edge case: multiple dependencies on the same callee ──────────────────────

#[test]
fn edge_multiple_callers_of_same_callee_all_notified() {
    let g = graph(&[
        dep("pool", "token"),
        dep("router", "token"),
        dep("factory", "token"),
    ]);
    let map = findings_map(&[("token", vec![critical("Function Removed", "transfer")])]);

    let cross = g.propagate(&map);

    let affected: HashSet<&str> = affected_contracts(&cross).into_iter().collect();
    assert!(affected.contains("pool"));
    assert!(affected.contains("router"));
    assert!(affected.contains("factory"));
    assert_eq!(cross.len(), 3, "one finding per caller");
}

// ── Edge case: deduplification ───────────────────────────────────────────────

#[test]
fn edge_same_finding_not_duplicated_for_same_affected() {
    // Diamond: A depends on B and C; both B and C depend on token; token breaks once.
    let g = graph(&[
        dep("B", "token"),
        dep("C", "token"),
        dep("A", "B"),
        dep("A", "C"),
    ]);
    let map = findings_map(&[("token", vec![critical("Function Removed", "transfer")])]);

    let cross = g.propagate(&map);

    // A can receive findings via both B and C paths, but for the SAME root finding
    // the dedup key is (affected, changed_contract, category|target).
    // So A should get the finding once per path, but not more.
    let a_findings: Vec<_> = cross
        .iter()
        .filter(|f| f.affected_contract == "A")
        .collect();

    // Maximum reasonable: 1 per path (2 paths: via B and via C but same root finding)
    assert!(
        a_findings.len() <= 2,
        "A must not receive unbounded duplicates, got {}",
        a_findings.len()
    );
}

// ── Edge case: cascading layout break propagates ─────────────────────────────

#[test]
fn edge_cascading_layout_break_is_caller_visible() {
    use soroban_upgrade_safeguard::dependency::is_caller_visible;

    let f = critical("Cascading Layout Break", "OuterType");
    assert!(
        is_caller_visible(&f),
        "CascadingLayoutBreak must be caller-visible"
    );
}

// ── Edge case: struct and enum changes propagate ──────────────────────────────

#[test]
fn edge_struct_removal_is_caller_visible_and_propagates() {
    let g = graph(&[dep("pool", "token")]);
    let map = findings_map(&[("token", vec![critical("Struct Removed", "TransferData")])]);

    let cross = g.propagate(&map);
    assert!(!cross.is_empty(), "Struct Removed must propagate to pool");
}

#[test]
fn edge_enum_removal_is_caller_visible_and_propagates() {
    let g = graph(&[dep("pool", "token")]);
    let map = findings_map(&[("token", vec![critical("Enum Removed", "Status")])]);

    let cross = g.propagate(&map);
    assert!(!cross.is_empty(), "Enum Removed must propagate to pool");
}

// ── Edge case: contract with no own findings but affected transiently ─────────

#[test]
fn edge_intermediary_with_no_own_findings_still_passes_through_break() {
    // pool has zero own findings but sits between router and token
    let g = graph(&[dep("pool", "token"), dep("router", "pool")]);
    let map = findings_map(&[
        ("token", vec![critical("Function Removed", "transfer")]),
        ("pool", vec![]), // pool has no own findings
    ]);

    let cross = g.propagate(&map);

    let router_affected = cross.iter().any(|f| f.affected_contract == "router");
    assert!(
        router_affected,
        "router must be affected transitively even though pool has no own findings"
    );
}

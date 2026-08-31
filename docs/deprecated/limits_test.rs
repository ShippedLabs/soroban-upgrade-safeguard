//! Regression tests for the resource-limit hardening (issue #52).
//!
//! Each test feeds an adversarial shape — a deeply nested type, an oversized
//! length relative to the byte budget, or an excessive entry count — and asserts
//! a *controlled* [`LimitError`] rather than a panic, a multi-gigabyte
//! allocation, or a stack overflow. The tests completing at all is itself part of
//! the guarantee: a `SIGABRT` (stack overflow) or OOM cannot be caught, so the
//! only way these return is if the depth/length/count guards trip *before* the
//! dangerous operation.

use std::path::PathBuf;
use std::process::Command;

use soroban_upgrade_safeguard::limits::{find_limit_error, EntryKind, LimitError};
use soroban_upgrade_safeguard::mapper::{try_type_to_string, TOO_DEEP_SENTINEL};
use soroban_upgrade_safeguard::parser::extract_metadata_with_policy;
use soroban_upgrade_safeguard::{compare_wasm_bytes_with_policy, ResourcePolicy};
use stellar_xdr::curr::{
    Limited, ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef, ScSpecTypeVec, StringM, VecM, WriteXdr,
};

// --- helpers ---------------------------------------------------------------

fn wasm_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("wasm")
        .join(name)
}

/// A `Vec<Vec<...<u32>>>` nested `depth` levels deep. The innermost `u32` leaf
/// sits at recursion depth `depth`.
fn nested_vec_type(depth: usize) -> ScSpecTypeDef {
    let mut t = ScSpecTypeDef::U32;
    for _ in 0..depth {
        t = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
            element_type: Box::new(t),
        }));
    }
    t
}

/// XDR bytes for a single `ScSpecEntry::FunctionV0` named `name`, with no inputs
/// or outputs. Concatenating these produces a valid `contractspecv0` payload.
fn spec_function_entry_bytes(name: &str) -> Vec<u8> {
    let entry = ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
        doc: StringM::default(),
        name: name.try_into().unwrap(),
        inputs: VecM::default(),
        outputs: VecM::default(),
    });
    let mut writer = Limited::new(Vec::new(), ResourcePolicy::default().xdr_limits());
    entry.write_xdr(&mut writer).unwrap();
    writer.inner
}

/// LEB128-encode an unsigned integer (WASM section sizes use this).
fn leb128(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out
}

/// Wrap `sections` (each a `(name, data)` pair) into a minimal but valid WASM
/// module, one custom section per pair.
fn wasm_with_custom_sections(sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    for (name, data) in sections {
        let mut payload = Vec::new();
        payload.extend(leb128(name.len()));
        payload.extend(name.as_bytes());
        payload.extend_from_slice(data);

        wasm.push(0x00); // custom section id
        wasm.extend(leb128(payload.len()));
        wasm.extend(payload);
    }
    wasm
}

/// A WASM module whose single `contractspecv0` section holds `count` function
/// entries.
fn wasm_with_spec_entries(count: usize) -> Vec<u8> {
    let mut data = Vec::new();
    for i in 0..count {
        data.extend(spec_function_entry_bytes(&format!("f{i}")));
    }
    wasm_with_custom_sections(&[("contractspecv0", data)])
}

// --- criterion 11: deeply nested type -> graceful WalkDepthExceeded ---------

#[test]
fn deeply_nested_type_walk_errors_gracefully() {
    // 5000 levels would overflow the native stack with the old derived recursion.
    let deep = nested_vec_type(5000);

    let err = try_type_to_string(&deep, 0, 128)
        .expect_err("a 5000-deep type must exceed the 128 walk-depth budget");
    assert_eq!(err, LimitError::WalkDepthExceeded { limit: 128 });
}

#[test]
fn walk_depth_boundary_is_inclusive() {
    // A type whose leaf sits at exactly `depth` renders at max == depth, and is
    // rejected at max == depth - 1. This pins the "exactly at the limit" edge.
    let depth = 40;
    let t = nested_vec_type(depth);

    assert!(
        try_type_to_string(&t, 0, depth).is_ok(),
        "a type nested to exactly the limit must render"
    );
    assert_eq!(
        try_type_to_string(&t, 0, depth - 1),
        Err(LimitError::WalkDepthExceeded { limit: depth - 1 }),
        "one level past the limit must error"
    );
}

#[test]
fn infallible_type_to_string_falls_back_to_sentinel() {
    // The public infallible renderer must never panic on a deep type; it returns
    // the sentinel instead (default walk depth is 128).
    let deep = nested_vec_type(1000);
    let rendered = soroban_upgrade_safeguard::mapper::type_to_string(&deep);
    assert_eq!(rendered, TOO_DEEP_SENTINEL);
}

#[test]
fn deeply_nested_type_through_pipeline_errors() {
    // A deep type reaching the equality path (both sides share the deep chain,
    // differing only at the leaf) must surface a LimitError, not overflow.
    use soroban_upgrade_safeguard::spec::ContractSpec;

    let make_spec = |leaf: ScSpecTypeDef| {
        let mut chain = leaf;
        for _ in 0..2000 {
            chain = ScSpecTypeDef::Vec(Box::new(ScSpecTypeVec {
                element_type: Box::new(chain),
            }));
        }
        let mut spec = ContractSpec::default();
        spec.functions.insert(
            "f".to_string(),
            ScSpecFunctionV0 {
                doc: StringM::default(),
                name: "f".try_into().unwrap(),
                inputs: VecM::default(),
                outputs: VecM::try_from(vec![chain]).unwrap(),
            },
        );
        spec
    };

    let old = make_spec(ScSpecTypeDef::U32);
    let new = make_spec(ScSpecTypeDef::I32);

    let policy = ResourcePolicy::default();
    let err = soroban_upgrade_safeguard::diff::compare_with_policy(&old, &new, &policy)
        .expect_err("2000-deep type must exceed the default walk depth");
    assert!(matches!(err, LimitError::WalkDepthExceeded { .. }));
}

// --- criterion 12: oversized length -> graceful XdrLengthExceeded -----------

#[test]
fn oversized_length_relative_to_budget_errors_before_allocation() {
    // A real spec section decoded under a tiny byte budget must fail via the
    // length backpressure (consume_len) rather than reading/allocating the whole
    // thing. `max_xdr_len = 4` is exhausted after the first few field reads.
    let wasm = std::fs::read(wasm_fixture("v1.wasm")).expect("v1.wasm fixture");

    let policy = ResourcePolicy {
        max_xdr_len: 4,
        ..ResourcePolicy::default()
    };
    let err = extract_metadata_with_policy(&wasm, &policy)
        .expect_err("a 4-byte budget cannot decode the real spec section");
    assert_eq!(
        find_limit_error(&err),
        Some(&LimitError::XdrLengthExceeded { limit: 4 }),
        "must be a controlled length-limit error, got: {err:?}"
    );
}

// --- criterion 13: excessive entry count -> graceful EntryCountExceeded -----

#[test]
fn entry_count_cap_is_enforced_within_a_section() {
    let wasm = wasm_with_spec_entries(10);
    let policy = ResourcePolicy {
        max_entries: 5,
        ..ResourcePolicy::default()
    };

    let err = extract_metadata_with_policy(&wasm, &policy)
        .expect_err("10 entries must exceed the cap of 5");
    assert_eq!(
        find_limit_error(&err),
        Some(&LimitError::EntryCountExceeded {
            limit: 5,
            kind: EntryKind::Spec
        })
    );
}

#[test]
fn entry_count_cap_spans_multiple_sections() {
    // Two sections of 3 entries each (6 total) must trip a cap of 5 — proving the
    // count accumulates across sections, not per-section.
    let section = |n: usize| {
        let mut data = Vec::new();
        for i in 0..n {
            data.extend(spec_function_entry_bytes(&format!("f{i}")));
        }
        data
    };
    let wasm = wasm_with_custom_sections(&[
        ("contractspecv0", section(3)),
        ("contractspecv0", section(3)),
    ]);

    let policy = ResourcePolicy {
        max_entries: 5,
        ..ResourcePolicy::default()
    };
    let err = extract_metadata_with_policy(&wasm, &policy)
        .expect_err("6 entries across two sections must exceed the cap of 5");
    assert!(matches!(
        find_limit_error(&err),
        Some(LimitError::EntryCountExceeded {
            limit: 5,
            kind: EntryKind::Spec
        })
    ));
}

#[test]
fn entry_count_exactly_at_cap_is_accepted() {
    // Exactly `max_entries` entries must decode; the cap rejects only the excess.
    let wasm = wasm_with_spec_entries(5);
    let policy = ResourcePolicy {
        max_entries: 5,
        ..ResourcePolicy::default()
    };
    let meta = extract_metadata_with_policy(&wasm, &policy)
        .expect("exactly the cap of entries must be accepted");
    assert_eq!(meta.spec.len(), 5);
}

// --- criterion 10: defaults accept the real fixtures -----------------------

#[test]
fn default_policy_accepts_all_fixtures() {
    let policy = ResourcePolicy::default();
    for name in ["v1.wasm", "v2.wasm", "v3.wasm"] {
        let bytes = std::fs::read(wasm_fixture(name)).expect("fixture must exist");
        extract_metadata_with_policy(&bytes, &policy)
            .unwrap_or_else(|e| panic!("default policy must decode {name}: {e:?}"));
    }
    // And a full comparison round-trips under the default policy.
    let v1 = std::fs::read(wasm_fixture("v1.wasm")).unwrap();
    let v2 = std::fs::read(wasm_fixture("v2.wasm")).unwrap();
    compare_wasm_bytes_with_policy(&v1, &v2, &policy)
        .expect("default policy must compare real fixtures");
}

// --- criterion 6: CLI exits with the dedicated code 2 ----------------------

#[test]
fn cli_exits_2_on_resource_limit_violation() {
    let bin = env!("CARGO_BIN_EXE_soroban-upgrade-safeguard");
    let v1 = wasm_fixture("v1.wasm");

    // A tiny byte budget forces XdrLengthExceeded during metadata extraction.
    let output = Command::new(bin)
        .arg(&v1)
        .arg(&v1)
        .args(["--max-xdr-len", "4"])
        .output()
        .expect("failed to run the safeguard binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "a resource-limit violation must exit with code 2, not 1 (findings) or 0"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Resource limit exceeded"),
        "stderr should carry the dedicated limit message, got: {stderr}"
    );
}

#[test]
fn cli_normal_run_is_unaffected_by_generous_limits() {
    // Sanity: with default (generous) limits, the fixture comparison behaves as
    // before — identical inputs are safe and exit 0.
    let bin = env!("CARGO_BIN_EXE_soroban-upgrade-safeguard");
    let v1 = wasm_fixture("v1.wasm");

    let output = Command::new(bin)
        .arg(&v1)
        .arg(&v1)
        .output()
        .expect("failed to run the safeguard binary");
    assert_eq!(output.status.code(), Some(0));
}

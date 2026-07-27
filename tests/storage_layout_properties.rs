//! Property tests over internal storage-layout edits.
//!
//! Each test states a property that must hold for *every* edit of a given shape,
//! then checks it against the whole (small, bounded) space of those edits rather
//! than a random sample. For layouts of four or five members the space is small
//! enough to enumerate exhaustively, which is strictly stronger than sampling
//! and keeps the tests deterministic with no extra dependency.
//!
//! The property under test throughout: **when a storage schema is supplied, an
//! edit that changes the on-chain layout must be detected as Critical.** These
//! are exactly the edits that are invisible in the exported interface, so before
//! the schema input existed every one of them was reported as safe.

use soroban_upgrade_safeguard::diff::{compare_storage_schemas, DiffReport, Severity};
use soroban_upgrade_safeguard::storage_schema::{ResolvedStorageSchema, StorageSchema};

/// Build and resolve a single-struct schema under the given role.
fn struct_schema(role: &str, name: &str, fields: &[(&str, &str)]) -> ResolvedStorageSchema {
    let mut src = format!("[[{role}]]\nname = \"{name}\"\nkind = \"struct\"\n");
    for (field_name, field_type) in fields {
        src.push_str(&format!(
            "[[{role}.field]]\nname = \"{field_name}\"\ntype = \"{field_type}\"\n"
        ));
    }
    resolve(&src)
}

/// Build and resolve a single-union schema under the given role.
fn union_schema(role: &str, name: &str, variants: &[(&str, &[&str])]) -> ResolvedStorageSchema {
    let mut src = format!("[[{role}]]\nname = \"{name}\"\nkind = \"union\"\n");
    for (variant_name, payload) in variants {
        src.push_str(&format!("[[{role}.variant]]\nname = \"{variant_name}\"\n"));
        if !payload.is_empty() {
            let rendered: Vec<String> = payload.iter().map(|t| format!("\"{t}\"")).collect();
            src.push_str(&format!("type = [{}]\n", rendered.join(", ")));
        }
    }
    resolve(&src)
}

fn resolve(src: &str) -> ResolvedStorageSchema {
    let schema = StorageSchema::from_toml_str(src)
        .unwrap_or_else(|e| panic!("generated manifest should parse: {e}\n{src}"));
    schema
        .validate()
        .unwrap_or_else(|e| panic!("generated manifest should validate: {e}\n{src}"));
    schema
        .resolve()
        .unwrap_or_else(|e| panic!("generated manifest should resolve: {e}\n{src}"))
}

fn criticals(report: &DiffReport) -> Vec<&str> {
    report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .map(|f| f.category.as_str())
        .collect()
}

/// Every permutation of `items`, including the identity.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.is_empty() {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for index in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(index);
        for mut tail in permutations(&rest) {
            let mut candidate = vec![head.clone()];
            candidate.append(&mut tail);
            out.push(candidate);
        }
    }
    out
}

const BASE_FIELDS: [(&str, &str); 4] = [
    ("collateral", "i128"),
    ("debt", "i128"),
    ("opened_at", "u64"),
    ("owner", "Address"),
];

/// Property: reordering the fields of an internal storage struct is Critical,
/// for every reordering that actually moves a field.
#[test]
fn every_reordering_of_an_internal_struct_is_critical() {
    let baseline = struct_schema("value_type", "PositionState", &BASE_FIELDS);
    let mut checked = 0;

    for candidate in permutations(&BASE_FIELDS) {
        if candidate == BASE_FIELDS.to_vec() {
            // The identity permutation must instead be silent.
            let report = compare_storage_schemas(
                &baseline,
                &struct_schema("value_type", "PositionState", &candidate),
            );
            assert!(
                report.findings.is_empty(),
                "an unchanged layout must produce no findings"
            );
            continue;
        }

        let report = compare_storage_schemas(
            &baseline,
            &struct_schema("value_type", "PositionState", &candidate),
        );
        let names: Vec<&str> = candidate.iter().map(|(n, _)| *n).collect();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.severity == Severity::Critical),
            "reordering to {names:?} moves stored bytes and must be Critical, \
             but only found: {:?}",
            report
                .findings
                .iter()
                .map(|f| (&f.category, &f.severity))
                .collect::<Vec<_>>()
        );
        checked += 1;
    }

    assert_eq!(checked, 23, "all 24 permutations minus the identity");
}

/// Property: inserting a field anywhere except the very end shifts every later
/// field, so it is Critical. Appending at the end is a migration concern only.
#[test]
fn inserting_a_field_is_critical_everywhere_except_the_end() {
    let baseline = struct_schema("value_type", "PositionState", &BASE_FIELDS);

    for position in 0..=BASE_FIELDS.len() {
        let mut fields = BASE_FIELDS.to_vec();
        fields.insert(position, ("inserted", "u32"));
        let report = compare_storage_schemas(
            &baseline,
            &struct_schema("value_type", "PositionState", &fields),
        );

        if position == BASE_FIELDS.len() {
            assert!(
                criticals(&report).is_empty(),
                "appending at the end must not be Critical, got {:?}",
                criticals(&report)
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|f| f.severity == Severity::Warning),
                "appending still needs a migration and must warn"
            );
        } else {
            assert!(
                !criticals(&report).is_empty(),
                "inserting at position {position} shifts later fields and must be Critical"
            );
        }
    }
}

/// Property: removing any field of an internal storage struct is Critical.
#[test]
fn removing_any_field_of_an_internal_struct_is_critical() {
    let baseline = struct_schema("value_type", "PositionState", &BASE_FIELDS);

    for position in 0..BASE_FIELDS.len() {
        let mut fields = BASE_FIELDS.to_vec();
        let removed = fields.remove(position);
        let report = compare_storage_schemas(
            &baseline,
            &struct_schema("value_type", "PositionState", &fields),
        );
        assert!(
            !criticals(&report).is_empty(),
            "removing '{}' must be Critical",
            removed.0
        );
    }
}

/// Property: changing the type of any field is Critical, for every field and
/// every replacement type that differs from the original.
#[test]
fn changing_any_field_type_is_critical() {
    let baseline = struct_schema("value_type", "PositionState", &BASE_FIELDS);
    let replacements = ["u32", "String", "Address", "Bytes", "Vec<u32>", "Option<u64>"];

    for position in 0..BASE_FIELDS.len() {
        for replacement in replacements {
            if BASE_FIELDS[position].1 == replacement {
                continue;
            }
            let mut fields = BASE_FIELDS.to_vec();
            fields[position].1 = replacement;
            let report = compare_storage_schemas(
                &baseline,
                &struct_schema("value_type", "PositionState", &fields),
            );
            assert!(
                !criticals(&report).is_empty(),
                "changing '{}' to `{replacement}` must be Critical",
                BASE_FIELDS[position].0
            );
        }
    }
}

const BASE_VARIANTS: [(&str, &[&str]); 4] = [
    ("Admin", &[]),
    ("Position", &["Address"]),
    ("Allowance", &["Address", "Address"]),
    ("Paused", &[]),
];

/// Property: reordering storage-key variants changes which discriminant
/// addresses which entry, so every non-identity reordering is Critical.
#[test]
fn every_reordering_of_storage_key_variants_is_critical() {
    let baseline = union_schema("storage_key", "DataKey", &BASE_VARIANTS);

    for candidate in permutations(&BASE_VARIANTS) {
        let report = compare_storage_schemas(
            &baseline,
            &union_schema("storage_key", "DataKey", &candidate),
        );

        if candidate == BASE_VARIANTS.to_vec() {
            assert!(report.findings.is_empty(), "identity must be silent");
            continue;
        }

        let names: Vec<&str> = candidate.iter().map(|(n, _)| *n).collect();
        assert!(
            !criticals(&report).is_empty(),
            "reordering discriminants to {names:?} must be Critical"
        );
    }
}

/// Property: renaming any storage-key variant shifts what its discriminant
/// addresses, and is Critical wherever it appears.
#[test]
fn renaming_any_storage_key_variant_is_critical() {
    let baseline = union_schema("storage_key", "DataKey", &BASE_VARIANTS);

    for position in 0..BASE_VARIANTS.len() {
        let mut variants = BASE_VARIANTS.to_vec();
        let original = variants[position].0;
        variants[position].0 = "Renamed";
        let report = compare_storage_schemas(
            &baseline,
            &union_schema("storage_key", "DataKey", &variants),
        );
        assert!(
            !criticals(&report).is_empty(),
            "renaming variant '{original}' must be Critical"
        );
    }
}

/// Property: changing a storage-key variant's payload changes the key bytes,
/// and is Critical for every variant that carries one.
#[test]
fn changing_a_storage_key_payload_is_critical() {
    let baseline = union_schema("storage_key", "DataKey", &BASE_VARIANTS);

    for position in 0..BASE_VARIANTS.len() {
        if BASE_VARIANTS[position].1.is_empty() {
            continue; // void variants carry no payload to change
        }
        let mut variants = BASE_VARIANTS.to_vec();
        variants[position].1 = &["u32"];
        let report = compare_storage_schemas(
            &baseline,
            &union_schema("storage_key", "DataKey", &variants),
        );
        assert!(
            !criticals(&report).is_empty(),
            "changing the payload of '{}' must be Critical",
            BASE_VARIANTS[position].0
        );
    }
}

/// Property: the same edit is judged more harshly on a key than on a value,
/// because a key's bytes decide where data lives.
#[test]
fn appending_is_critical_for_keys_but_only_a_warning_for_values() {
    let extended: Vec<(&str, &str)> = BASE_FIELDS
        .iter()
        .copied()
        .chain(std::iter::once(("market", "u32")))
        .collect();

    let value_report = compare_storage_schemas(
        &struct_schema("value_type", "Thing", &BASE_FIELDS),
        &struct_schema("value_type", "Thing", &extended),
    );
    assert!(
        criticals(&value_report).is_empty(),
        "appending to a value type is a migration concern, not corruption"
    );

    let key_report = compare_storage_schemas(
        &struct_schema("storage_key", "Thing", &BASE_FIELDS),
        &struct_schema("storage_key", "Thing", &extended),
    );
    assert!(
        !criticals(&key_report).is_empty(),
        "appending to a key changes the entry address and orphans all data"
    );
}

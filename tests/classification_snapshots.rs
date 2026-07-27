//! Snapshot tests pinning the exact findings produced for the classification
//! failure modes the old name-substring heuristic got wrong, and for renames.
//!
//! Each test asserts the full `(severity, category, target, classification)`
//! tuple of every finding, so a regression shows up as a diff rather than as a
//! silently reworded message. The point is to lock in three things:
//!
//! 1. A name containing "event" does not make a type an event (false positive).
//! 2. An event whose name lacks "event" is still classifiable (false negative).
//! 3. `category` is structural in every case, so the suppression key never
//!    moves when classification changes.

use soroban_upgrade_safeguard::classification::ClassificationConfig;
use soroban_upgrade_safeguard::diff::{compare_with_classification, DiffReport};
use soroban_upgrade_safeguard::spec::ContractSpec;
use stellar_xdr::curr::{
    ScSpecTypeDef, ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0,
    StringM, VecM,
};

/// Build a spec containing the given structs.
fn spec_with_structs(structs: &[(&str, &[(&str, ScSpecTypeDef)])]) -> ContractSpec {
    let mut spec = ContractSpec::default();
    for (name, fields) in structs {
        let xdr_fields: Vec<ScSpecUdtStructFieldV0> = fields
            .iter()
            .map(|(fname, ftype)| ScSpecUdtStructFieldV0 {
                doc: StringM::default(),
                name: (*fname).try_into().unwrap(),
                type_: ftype.clone(),
            })
            .collect();
        spec.structs.insert(
            name.to_string(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: (*name).try_into().unwrap(),
                fields: VecM::try_from(xdr_fields).unwrap(),
            },
        );
    }
    spec
}

/// Build a spec containing the given unit enums.
fn spec_with_enums(enums: &[(&str, &[(&str, u32)])]) -> ContractSpec {
    let mut spec = ContractSpec::default();
    for (name, cases) in enums {
        let xdr_cases: Vec<ScSpecUdtEnumCaseV0> = cases
            .iter()
            .map(|(cname, value)| ScSpecUdtEnumCaseV0 {
                doc: StringM::default(),
                name: (*cname).try_into().unwrap(),
                value: *value,
            })
            .collect();
        spec.enums.insert(
            name.to_string(),
            ScSpecUdtEnumV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: (*name).try_into().unwrap(),
                cases: VecM::try_from(xdr_cases).unwrap(),
            },
        );
    }
    spec
}

/// Render a report as sorted `severity | category | target | class` lines —
/// the snapshot form. `class` is `-` when the finding carries no classification.
fn snapshot(report: &DiffReport) -> String {
    let mut lines: Vec<String> = report
        .findings
        .iter()
        .map(|f| {
            let class = match &f.classification {
                None => "-".to_string(),
                Some(c) if c.is_heuristic() => "event(heuristic)".to_string(),
                Some(c) if c.is_event() => "event(declared)".to_string(),
                Some(_) => "storage".to_string(),
            };
            format!(
                "{:?} | {} | {} | {}",
                f.severity,
                f.category,
                f.target.as_deref().unwrap_or("-"),
                class
            )
        })
        .collect();
    lines.sort();
    lines.join("\n")
}

fn config(events: &[&str], storage: &[&str], name_heuristic: bool) -> ClassificationConfig {
    ClassificationConfig {
        events: events.iter().map(|s| s.to_string()).collect(),
        storage: storage.iter().map(|s| s.to_string()).collect(),
        name_heuristic,
    }
}

// ---------------------------------------------------------------------------
// False positives: names that contain "event" but are not events
// ---------------------------------------------------------------------------

#[test]
fn substring_name_is_not_an_event_by_default() {
    // `PreventList` contains "event" (pr-EVENT-list) and `EventCounterCache` is
    // a storage struct that merely counts events. Neither is an event, and with
    // no configuration the tool must not claim otherwise.
    let old = spec_with_structs(&[
        ("PreventList", &[("addrs", ScSpecTypeDef::Bytes)]),
        ("EventCounterCache", &[("count", ScSpecTypeDef::U64)]),
    ]);
    let new = spec_with_structs(&[
        ("PreventList", &[]),
        ("EventCounterCache", &[("count", ScSpecTypeDef::Bool)]),
    ]);

    let report = compare_with_classification(&old, &new, &ClassificationConfig::none());

    assert_eq!(
        snapshot(&report),
        "\
Critical | Struct Field Removed | PreventList.addrs | storage
Critical | Struct Field Type Changed | EventCounterCache.count | storage"
    );
}

#[test]
fn storage_list_defeats_the_heuristic_for_a_false_positive() {
    // Even with the heuristic switched on, an explicit `storage` entry wins —
    // so a team can opt into the heuristic without having to accept its
    // mistakes.
    let old = spec_with_structs(&[("PreventList", &[("addrs", ScSpecTypeDef::Bytes)])]);
    let new = spec_with_structs(&[("PreventList", &[])]);

    let report = compare_with_classification(&old, &new, &config(&[], &["PreventList"], true));

    assert_eq!(
        snapshot(&report),
        "Critical | Struct Field Removed | PreventList.addrs | storage"
    );
}

#[test]
fn the_heuristic_is_labeled_as_a_guess_when_it_fires() {
    // With the heuristic on and nothing declared, `PreventList` *is* classified
    // as an event — wrongly. The report must say the classification was guessed
    // so a reviewer can see where the claim came from.
    let old = spec_with_structs(&[("PreventList", &[("addrs", ScSpecTypeDef::Bytes)])]);
    let new = spec_with_structs(&[("PreventList", &[])]);

    let report = compare_with_classification(&old, &new, &config(&[], &[], true));

    assert_eq!(
        snapshot(&report),
        "Critical | Struct Field Removed | PreventList.addrs | event(heuristic)"
    );
    assert!(
        report.findings[0].message.contains("name heuristic"),
        "a guessed classification must be labeled as such: {}",
        report.findings[0].message
    );
}

// ---------------------------------------------------------------------------
// False negatives: genuine events whose names lack "event"
// ---------------------------------------------------------------------------

#[test]
fn genuine_event_without_the_substring_is_classifiable() {
    // `Transfer` is a real event. The substring heuristic could never find it;
    // declaring it under `[classification]` does.
    let old = spec_with_enums(&[("Transfer", &[("Sent", 1), ("Received", 2)])]);
    let new = spec_with_enums(&[("Transfer", &[("Sent", 9), ("Received", 2)])]);

    let report = compare_with_classification(&old, &new, &config(&["Transfer"], &[], false));

    assert_eq!(
        snapshot(&report),
        "Critical | Enum Case Value Changed | Transfer.Sent | event(declared)"
    );
    assert!(
        !report.findings[0].message.contains("heuristic"),
        "a declared classification is not a guess"
    );
}

#[test]
fn classification_changes_wording_but_never_the_category() {
    // The same structural change, classified three different ways, must always
    // produce the same category and target — the suppression key. Only the
    // classification metadata differs.
    let old = spec_with_structs(&[("Payload", &[("amount", ScSpecTypeDef::I128)])]);
    let new = spec_with_structs(&[("Payload", &[])]);

    let keys: Vec<(String, Option<String>)> = [
        ClassificationConfig::none(),
        config(&["Payload"], &[], false),
        config(&[], &["Payload"], true),
    ]
    .iter()
    .map(|cfg| {
        let report = compare_with_classification(&old, &new, cfg);
        assert_eq!(report.findings.len(), 1);
        (
            report.findings[0].category.clone(),
            report.findings[0].target.clone(),
        )
    })
    .collect();

    assert_eq!(
        keys[0], keys[1],
        "declaring a type an event must not move its suppression key"
    );
    assert_eq!(
        keys[1], keys[2],
        "declaring a type storage must not move its suppression key"
    );
    assert_eq!(
        keys[0],
        (
            "Struct Field Removed".to_string(),
            Some("Payload.amount".to_string())
        )
    );
}

// ---------------------------------------------------------------------------
// Type identity
// ---------------------------------------------------------------------------

#[test]
fn pure_rename_is_informational_not_a_delete_plus_add() {
    let old = spec_with_structs(&[(
        "Balance",
        &[
            ("amount", ScSpecTypeDef::I128),
            ("owner", ScSpecTypeDef::Bytes),
        ],
    )]);
    let new = spec_with_structs(&[(
        "Account",
        &[
            ("amount", ScSpecTypeDef::I128),
            ("owner", ScSpecTypeDef::Bytes),
        ],
    )]);

    let report = compare_with_classification(&old, &new, &ClassificationConfig::none());

    assert_eq!(
        snapshot(&report),
        "Info | Type Renamed | Account | storage",
        "an identical layout under a new name is not a breaking change"
    );
}

#[test]
fn rename_with_field_changes_reports_the_rename_and_the_break() {
    let old = spec_with_structs(&[(
        "Balance",
        &[
            ("amount", ScSpecTypeDef::I128),
            ("owner", ScSpecTypeDef::Bytes),
        ],
    )]);
    // Renamed *and* the amount widened: the rename is informational context,
    // the type change is the actual break.
    let new = spec_with_structs(&[(
        "Account",
        &[
            ("amount", ScSpecTypeDef::Bool),
            ("owner", ScSpecTypeDef::Bytes),
        ],
    )]);

    let report = compare_with_classification(&old, &new, &ClassificationConfig::none());

    assert_eq!(
        snapshot(&report),
        "\
Critical | Struct Field Type Changed | Account.amount | storage
Warning | Type Renamed With Changes | Account | storage"
    );
}

#[test]
fn unrelated_delete_and_add_are_not_matched_as_a_rename() {
    let old = spec_with_structs(&[("Balance", &[("amount", ScSpecTypeDef::I128)])]);
    let new = spec_with_structs(&[(
        "Widget",
        &[
            ("color", ScSpecTypeDef::Bytes),
            ("size", ScSpecTypeDef::U32),
        ],
    )]);

    let report = compare_with_classification(&old, &new, &ClassificationConfig::none());

    assert_eq!(
        snapshot(&report),
        "\
Critical | Struct Removed | Balance | storage
Info | Struct Added | Widget | storage",
        "types sharing no structure must stay a removal plus an addition"
    );
}

#[test]
fn swapped_names_are_not_treated_as_the_same_type() {
    // `Alpha` and `Beta` trade layouts. Matching on name alone would report only
    // field-level edits, quietly treating two full replacements as edits.
    let old = spec_with_structs(&[
        (
            "Alpha",
            &[("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        ),
        (
            "Beta",
            &[("x", ScSpecTypeDef::Bytes), ("y", ScSpecTypeDef::Bytes)],
        ),
    ]);
    let new = spec_with_structs(&[
        (
            "Alpha",
            &[("x", ScSpecTypeDef::Bytes), ("y", ScSpecTypeDef::Bytes)],
        ),
        (
            "Beta",
            &[("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)],
        ),
    ]);

    let report = compare_with_classification(&old, &new, &ClassificationConfig::none());

    // Both names exist in both specs, so they are compared in place: every
    // field of each is replaced. The critical findings must not be lost.
    let criticals = report
        .findings
        .iter()
        .filter(|f| format!("{:?}", f.severity) == "Critical")
        .count();
    assert!(
        criticals >= 4,
        "a full layout replacement under a reused name must stay critical, got:\n{}",
        snapshot(&report)
    );
}

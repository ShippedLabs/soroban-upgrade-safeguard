//! Declared data migrations, and verification that they actually cover the
//! breaking changes they claim.
//!
//! ## Why this exists
//!
//! When the analyzer finds a genuine breaking change, the honest production
//! answer is usually not "ignore it" — it is "we ship a migration alongside the
//! upgrade that reads the old layout and rewrites it". [`crate::suppression`]
//! cannot express that. A suppression records that a human *looked* at a
//! finding; it does not record that anything was *done*, and nothing checks
//! that a migration exists, that it covers every affected type, or that it runs
//! before the new code reads the old data. A correctly migrated upgrade and an
//! ignored one come out of the report looking identical.
//!
//! This module adds the missing axis: **remediation**. A team declares a
//! migration, lists the types it rewrites and the exact findings it resolves,
//! and the tool verifies the claim. A finding covered by a verified migration
//! is reported as *migrated* — visibly distinct from *suppressed*. A finding a
//! migration claims but does not actually cover still fails the gate.
//!
//! ## File format (`.safeguard.toml`)
//!
//! ```toml
//! [[migration]]
//! id          = "v3-widen-balance"
//! description = "Reads each Data entry, widens amount u64 -> i128, rewrites it."
//! # Every breaking finding on these types must be claimed below, or it is a gap.
//! migrates    = ["Data"]
//! # Attests that the migration runs before any new-code read of the old layout.
//! runs_before_read = true
//!
//!   # One entry per finding this migration resolves.
//!   [[migration.covers]]
//!   category = "Struct Field Type Changed"
//!   target   = "Data.amount"
//!   change   = "U64 -> I128"   # pins the claim to *this* change
//! ```
//!
//! ## What is verified
//!
//! A migration only covers anything when it is **verified**, which requires all
//! of:
//!
//! 1. `runs_before_read = true`. The tool cannot see execution order from a
//!    WASM spec, so ordering is an explicit attestation rather than a proof —
//!    but an unattested migration covers nothing, so the attestation cannot be
//!    skipped by accident.
//! 2. A non-empty `migrates` list. This is what makes coverage checkable: every
//!    breaking finding on a listed type must be claimed, or it is reported as a
//!    gap and stays open. Without it a migration would be a suppression with
//!    extra steps.
//!
//! Then, per claim:
//!
//! - The claim must match a real finding on `category` + `target`. If it
//!   matches nothing, the declaration is **stale** — the change it was written
//!   against is gone (reverted, or the type no longer exists).
//! - If the claim pins `change`, it must equal the finding's own
//!   [`Finding::change`] fingerprint. A field that used to widen `U64 -> I128`
//!   and now narrows `U64 -> U32` is a *different* change, and a migration
//!   written for the first one must not silently keep covering the second.
//! - The claimed finding must belong to a type listed in `migrates`, so the
//!   scope a migration declares and the findings it claims cannot drift apart.
//! - The claimed finding must be about a user-defined type at all. A function
//!   signature change is an interface break, not a data break; no data
//!   migration fixes it, and claiming one is reported rather than honored.
//!   Suppression remains the honest answer for those.
//!
//! Findings claimed by **two** migrations are covered by neither: ambiguous
//! ownership is not verification, and double-applying a rewrite is its own bug.
//!
//! ## Cascades
//!
//! A `Cascading Layout Break` on `Wrapper` exists only because `Wrapper` embeds
//! a type that broke. When every breaking finding on that root type is covered
//! by a verified migration, the dependent inherits the coverage — rewriting the
//! root's stored data necessarily rewrites the embedded copy. Inheritance is
//! transitive and is reported as such (`migrated via Data`), never silently.
//!
//! ## Batch mode
//!
//! A single `.safeguard.toml` may describe several contracts. `contracts = [..]`
//! scopes a migration to named contracts; a migration with no `contracts` key
//! applies everywhere.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::diff::{Finding, Severity};

/// One declared migration: what it rewrites, and which findings it resolves.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MigrationDeclaration {
    /// A short, stable identifier surfaced in the report (e.g. `"v3-widen-balance"`).
    pub id: String,
    /// Optional prose describing what the migration does.
    #[serde(default)]
    pub description: Option<String>,
    /// The user-defined types this migration rewrites. Every breaking finding
    /// on one of these types must be claimed in [`Self::covers`] or it is
    /// reported as a coverage gap and stays open.
    #[serde(default)]
    pub migrates: BTreeSet<String>,
    /// Attests that the migration runs before any new-code read of the old
    /// layout. Required: an unattested migration covers nothing.
    #[serde(default)]
    pub runs_before_read: bool,
    /// Contract names this migration applies to, for a config shared across a
    /// batch run. Empty means "every contract".
    #[serde(default)]
    pub contracts: BTreeSet<String>,
    /// The specific findings this migration resolves.
    #[serde(default)]
    pub covers: Vec<CoverageClaim>,
}

/// A claim that one specific finding is resolved by the enclosing migration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoverageClaim {
    /// The finding category to match exactly (e.g. `"Struct Field Type Changed"`).
    pub category: String,
    /// The exact [`Finding::target`] to match (e.g. `"Data.amount"`).
    #[serde(default)]
    pub target: Option<String>,
    /// The [`Finding::change`] fingerprint this claim is pinned to (e.g.
    /// `"U64 -> I128"`). When present it must match exactly, so the claim goes
    /// stale if the underlying change is later replaced by a different one.
    /// When omitted the claim matches on category and target alone.
    #[serde(default)]
    pub change: Option<String>,
}

impl MigrationDeclaration {
    /// Whether this declaration applies to `contract` (`None` when the caller
    /// has no contract name to match against).
    pub fn applies_to(&self, contract: Option<&str>) -> bool {
        self.contracts.is_empty() || contract.is_some_and(|c| self.contracts.contains(c))
    }
}

impl CoverageClaim {
    /// Whether this claim addresses `finding` at all, ignoring the `change` pin.
    fn addresses(&self, finding: &Finding) -> bool {
        self.category == finding.category && self.target.as_deref() == finding.target.as_deref()
    }

    /// Whether the pinned `change`, if any, still matches the finding's own.
    fn change_matches(&self, finding: &Finding) -> bool {
        match &self.change {
            None => true,
            Some(pinned) => finding.change.as_deref() == Some(pinned.as_str()),
        }
    }
}

/// How a finding came to be covered by a migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingCoverage {
    /// The [`MigrationDeclaration::id`] that covers this finding.
    pub migration: String,
    /// For a cascade finding that inherited coverage, the root type whose
    /// migration it inherited. `None` when the finding was claimed directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

impl FindingCoverage {
    /// Whether this coverage was inherited from a migrated root type rather
    /// than claimed directly.
    pub fn is_inherited(&self) -> bool {
        self.via.is_some()
    }
}

/// What kind of problem a [`MigrationDiagnostic`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    /// The migration does not attest that it runs before the old layout is read.
    OrderingUnattested,
    /// The migration lists no types, so its coverage cannot be checked.
    NoTypesDeclared,
    /// A claim matches no finding, or matches one whose change now differs.
    StaleClaim,
    /// A claim names a finding on a type the migration does not list in `migrates`.
    ClaimOutsideScope,
    /// A claim names a finding no data migration can resolve (not about a type).
    NotMigratable,
    /// Two or more migrations claim the same finding.
    DuplicateClaim,
    /// A breaking finding on a migrated type that no migration claims.
    CoverageGap,
    /// A migrated type has no findings at all in this comparison.
    NoFindingsForType,
}

/// One problem found while verifying the declared migrations.
///
/// Diagnostics never fail the run on their own. They fail it the honest way:
/// a claim that does not verify covers nothing, so the finding it named stays
/// open and fails the gate exactly as it would have with no declaration at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationDiagnostic {
    pub kind: DiagnosticKind,
    /// The migration this is about, when it is about one in particular.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migration: Option<String>,
    /// The finding category involved, when the diagnostic is about a claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The finding target involved, when the diagnostic is about a claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// A ready-to-print explanation, including what to do about it.
    pub message: String,
}

impl MigrationDiagnostic {
    fn about_migration(kind: DiagnosticKind, migration: &str, message: String) -> Self {
        Self {
            kind,
            migration: Some(migration.to_string()),
            category: None,
            target: None,
            message,
        }
    }

    fn about_claim(
        kind: DiagnosticKind,
        migration: Option<&str>,
        category: &str,
        target: Option<&str>,
        message: String,
    ) -> Self {
        Self {
            kind,
            migration: migration.map(str::to_string),
            category: Some(category.to_string()),
            target: target.map(str::to_string),
            message,
        }
    }
}

/// Where an upgrade stands on remediation, as opposed to acknowledgement.
///
/// Computed over the findings that would otherwise fail the gate, excluding
/// suppressed ones — suppression is the other axis and is reported separately,
/// so an upgrade that suppresses everything is not thereby "migrated".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    /// Nothing needed migrating (no breaking findings left to handle).
    #[default]
    NotApplicable,
    /// Every breaking finding is covered by a verified migration.
    FullyMigrated,
    /// Some breaking findings are covered; others remain open.
    PartiallyMigrated,
    /// Breaking findings exist and none are covered by a verified migration.
    Unhandled,
}

impl MigrationStatus {
    /// A short label for the report.
    pub fn label(self) -> &'static str {
        match self {
            MigrationStatus::NotApplicable => "not applicable",
            MigrationStatus::FullyMigrated => "fully migrated",
            MigrationStatus::PartiallyMigrated => "partially migrated",
            MigrationStatus::Unhandled => "unhandled",
        }
    }

    /// Classify an upgrade from the number of breaking findings that need
    /// remediation and the number a verified migration covers.
    pub fn classify(needing_migration: usize, covered: usize) -> Self {
        if needing_migration == 0 {
            MigrationStatus::NotApplicable
        } else if covered == needing_migration {
            MigrationStatus::FullyMigrated
        } else if covered > 0 {
            MigrationStatus::PartiallyMigrated
        } else {
            MigrationStatus::Unhandled
        }
    }
}

/// The result of verifying declared migrations against a set of findings.
#[derive(Debug, Clone, Default)]
pub struct MigrationAudit {
    /// Coverage per finding, positionally parallel to the findings that were
    /// audited.
    coverage: Vec<Option<FindingCoverage>>,
    /// Everything that did not verify, in a stable order.
    diagnostics: Vec<MigrationDiagnostic>,
    /// Whether any migration declaration applied to this comparison at all.
    declared: bool,
}

impl MigrationAudit {
    /// Coverage for the finding at `index`, if it is covered.
    pub fn coverage_of(&self, index: usize) -> Option<&FindingCoverage> {
        self.coverage.get(index).and_then(Option::as_ref)
    }

    /// Every diagnostic raised while verifying the declarations.
    pub fn diagnostics(&self) -> &[MigrationDiagnostic] {
        &self.diagnostics
    }

    /// Whether any migration declaration applied to this comparison.
    pub fn has_declarations(&self) -> bool {
        self.declared
    }

    /// How many findings ended up covered.
    pub fn covered_count(&self) -> usize {
        self.coverage.iter().filter(|c| c.is_some()).count()
    }
}

/// Whether a finding is the kind that a data migration is expected to resolve.
///
/// Informational findings (a new struct, a doc change) need no remediation, so
/// leaving one unclaimed is not a coverage gap.
fn needs_migration(finding: &Finding) -> bool {
    matches!(finding.severity, Severity::Critical | Severity::Warning)
}

/// Verify `migrations` against `findings` for the contract named `contract`.
///
/// Returns coverage parallel to `findings` plus every diagnostic raised. See
/// the module docs for what "verified" requires; the short version is that a
/// migration covers nothing unless it attests its ordering, declares the types
/// it rewrites, and claims findings that actually exist and still match.
pub fn audit(
    findings: &[Finding],
    migrations: &[MigrationDeclaration],
    contract: Option<&str>,
) -> MigrationAudit {
    let mut diagnostics = Vec::new();
    // Claimants per finding index, so a finding claimed twice can be detected
    // rather than silently going to whichever migration was parsed first.
    let mut claimants: Vec<Vec<String>> = vec![Vec::new(); findings.len()];

    let applicable: Vec<&MigrationDeclaration> = migrations
        .iter()
        .filter(|m| m.applies_to(contract))
        .collect();

    let mut verified: Vec<&MigrationDeclaration> = Vec::new();
    for migration in &applicable {
        if !migration.runs_before_read {
            diagnostics.push(MigrationDiagnostic::about_migration(
                DiagnosticKind::OrderingUnattested,
                &migration.id,
                format!(
                    "Migration '{}' does not attest its ordering, so it covers nothing. \
                     A migration that runs after the new code reads the old layout is not a \
                     migration — it is a crash. Set `runs_before_read = true` once that is \
                     genuinely true.",
                    migration.id
                ),
            ));
            continue;
        }
        if migration.migrates.is_empty() {
            diagnostics.push(MigrationDiagnostic::about_migration(
                DiagnosticKind::NoTypesDeclared,
                &migration.id,
                format!(
                    "Migration '{}' lists no types in `migrates`, so its coverage cannot be \
                     checked and it covers nothing. List every type it rewrites; each one's \
                     breaking findings are then required to be claimed.",
                    migration.id
                ),
            ));
            continue;
        }
        verified.push(migration);
    }

    // 1. Direct claims.
    for migration in &verified {
        for claim in &migration.covers {
            record_claim(findings, migration, claim, &mut claimants, &mut diagnostics);
        }
    }

    // 2. Resolve claims into coverage, rejecting anything claimed twice.
    let mut coverage: Vec<Option<FindingCoverage>> = vec![None; findings.len()];
    for (index, ids) in claimants.iter().enumerate() {
        match ids.len() {
            0 => {}
            1 => {
                coverage[index] = Some(FindingCoverage {
                    migration: ids[0].clone(),
                    via: None,
                })
            }
            _ => diagnostics.push(MigrationDiagnostic::about_claim(
                DiagnosticKind::DuplicateClaim,
                None,
                &findings[index].category,
                findings[index].target.as_deref(),
                format!(
                    "Migrations {} all claim this finding. Ambiguous ownership is not \
                     verification — and two rewrites of the same data is its own bug — so it \
                     is covered by none of them. Leave the claim on exactly one migration.",
                    quoted_list(ids)
                ),
            )),
        }
    }

    // 3. Cascade inheritance: a dependent whose root is fully migrated is
    //    migrated too. `root_target` already names the ultimate root of the
    //    chain, so one pass covers `A -> B -> C` embeddings of any depth.
    inherit_through_cascades(findings, &mut coverage);

    // 4. Gaps: a breaking finding on a migrated type that nothing covers.
    for migration in &verified {
        for type_name in &migration.migrates {
            let mut seen_any = false;
            for (index, finding) in findings.iter().enumerate() {
                if finding.type_name.as_deref() != Some(type_name.as_str()) {
                    continue;
                }
                seen_any = true;
                if !needs_migration(finding) || coverage[index].is_some() {
                    continue;
                }
                diagnostics.push(MigrationDiagnostic::about_claim(
                    DiagnosticKind::CoverageGap,
                    Some(&migration.id),
                    &finding.category,
                    finding.target.as_deref(),
                    format!(
                        "Migration '{}' declares that it migrates '{}', but does not cover this \
                         finding on it. A partly migrated type is still a broken type, so this \
                         still fails. Add a `[[migration.covers]]` entry for it, or drop '{}' \
                         from `migrates` if the migration really does not handle it.",
                        migration.id, type_name, type_name
                    ),
                ));
            }
            if !seen_any {
                diagnostics.push(MigrationDiagnostic::about_migration(
                    DiagnosticKind::NoFindingsForType,
                    &migration.id,
                    format!(
                        "Migration '{}' declares that it migrates '{}', but this comparison has \
                         no findings for that type. The type may have been renamed or removed, \
                         or the migration may already have shipped — either way the declaration \
                         is stale and should be deleted.",
                        migration.id, type_name
                    ),
                ));
            }
        }
    }

    diagnostics.sort_by(|a, b| {
        (
            a.migration.as_deref(),
            a.category.as_deref(),
            a.target.as_deref(),
        )
            .cmp(&(
                b.migration.as_deref(),
                b.category.as_deref(),
                b.target.as_deref(),
            ))
    });

    MigrationAudit {
        coverage,
        diagnostics,
        declared: !applicable.is_empty(),
    }
}

/// Match one claim against the findings, recording either a claimant or the
/// reason the claim did not verify.
fn record_claim(
    findings: &[Finding],
    migration: &MigrationDeclaration,
    claim: &CoverageClaim,
    claimants: &mut [Vec<String>],
    diagnostics: &mut Vec<MigrationDiagnostic>,
) {
    let addressed: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| claim.addresses(f))
        .map(|(i, _)| i)
        .collect();

    if addressed.is_empty() {
        diagnostics.push(MigrationDiagnostic::about_claim(
            DiagnosticKind::StaleClaim,
            Some(&migration.id),
            &claim.category,
            claim.target.as_deref(),
            format!(
                "Migration '{}' claims a finding that this comparison does not produce. The \
                 change it was written for is gone — reverted, or the type no longer exists — \
                 so the claim is stale and covers nothing. Delete it.",
                migration.id
            ),
        ));
        return;
    }

    let matched: Vec<usize> = addressed
        .iter()
        .copied()
        .filter(|&i| claim.change_matches(&findings[i]))
        .collect();

    if matched.is_empty() {
        let actual = findings[addressed[0]].change.as_deref();
        diagnostics.push(MigrationDiagnostic::about_claim(
            DiagnosticKind::StaleClaim,
            Some(&migration.id),
            &claim.category,
            claim.target.as_deref(),
            format!(
                "Migration '{}' is pinned to `change = \"{}\"`, but the change here is {}. \
                 This is a different change than the migration was written against, so the \
                 claim is stale and covers nothing. Re-read the migration against the current \
                 change, then update the pin.",
                migration.id,
                claim.change.as_deref().unwrap_or_default(),
                actual
                    .map(|c| format!("`{c}`"))
                    .unwrap_or_else(|| "not a change this category records".to_string()),
            ),
        ));
        return;
    }

    for index in matched {
        let finding = &findings[index];
        let Some(type_name) = finding.type_name.as_deref() else {
            diagnostics.push(MigrationDiagnostic::about_claim(
                DiagnosticKind::NotMigratable,
                Some(&migration.id),
                &finding.category,
                finding.target.as_deref(),
                format!(
                    "Migration '{}' claims a finding that is not about a stored type. This is \
                     an interface break, not a data break: no rewrite of stored data fixes a \
                     caller. If it is genuinely acceptable, `[[suppress]]` is the honest way to \
                     say so.",
                    migration.id
                ),
            ));
            continue;
        };

        if !migration.migrates.contains(type_name) {
            diagnostics.push(MigrationDiagnostic::about_claim(
                DiagnosticKind::ClaimOutsideScope,
                Some(&migration.id),
                &finding.category,
                finding.target.as_deref(),
                format!(
                    "Migration '{}' claims a finding on '{}', which it does not list in \
                     `migrates`. Add '{}' there so the rest of its findings are checked for \
                     coverage too; claiming one field of a type the migration does not declare \
                     is how a half-migration hides.",
                    migration.id, type_name, type_name
                ),
            ));
            continue;
        }

        claimants[index].push(migration.id.clone());
    }
}

/// Let cascade findings inherit the coverage of the root type they came from.
///
/// A `Cascading Layout Break` on `Wrapper` exists only because `Wrapper` embeds
/// a type that broke. If every breaking finding on that root is covered, then
/// rewriting the root's stored data necessarily rewrote the embedded copy, and
/// the dependent is covered too.
///
/// [`Finding::root_target`] already names the *ultimate* root of a cascade
/// chain (diff-layer cascade detection flattens `A -> B -> C` to `root_target
/// = A` at every step), so a single pass is enough — no fixpoint needed.
fn inherit_through_cascades(findings: &[Finding], coverage: &mut [Option<FindingCoverage>]) {
    // Which types are fully covered: at least one breaking finding, and
    // every one of them covered.
    let mut totals: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        let Some(type_name) = finding.type_name.as_deref() else {
            continue;
        };
        if !needs_migration(finding) {
            continue;
        }
        let entry = totals.entry(type_name).or_insert((0, 0));
        entry.0 += 1;
        if coverage[index].is_some() {
            entry.1 += 1;
        }
    }

    for index in 0..findings.len() {
        if coverage[index].is_some() {
            continue;
        }
        let Some(root) = findings[index].root_target.as_deref() else {
            continue;
        };
        match totals.get(root) {
            Some(&(total, covered)) if total > 0 && total == covered => {}
            _ => continue,
        }

        // Attribute the inheritance to the migration that covers the root.
        let Some(migration) = findings
            .iter()
            .enumerate()
            .find(|(i, f)| {
                f.type_name.as_deref() == Some(root) && needs_migration(f) && coverage[*i].is_some()
            })
            .and_then(|(i, _)| coverage[i].as_ref())
            .map(|c| c.migration.clone())
        else {
            continue;
        };

        coverage[index] = Some(FindingCoverage {
            migration,
            via: Some(root.to_string()),
        });
    }
}

/// Render ids as `'a', 'b' and 'c'` for a diagnostic message.
fn quoted_list(ids: &[String]) -> String {
    let quoted: Vec<String> = ids.iter().map(|id| format!("'{id}'")).collect();
    match quoted.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {}", rest.join(", "), last),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a finding for audit tests.
    fn finding(
        severity: Severity,
        category: &str,
        type_name: Option<&str>,
        target: Option<&str>,
        change: Option<&str>,
    ) -> Finding {
        Finding {
            severity,
            axes: Vec::new(),
            category: category.to_string(),
            message: "irrelevant to the audit".to_string(),
            type_name: type_name.map(str::to_string),
            target: target.map(str::to_string),
            change: change.map(str::to_string),
            root_target: None,
        }
    }

    /// A cascade finding on `dependent`, rooted at `root`.
    fn cascade(dependent: &str, root: &str) -> Finding {
        Finding {
            root_target: Some(root.to_string()),
            ..finding(
                Severity::Critical,
                "Cascading Layout Break",
                Some(dependent),
                Some(dependent),
                None,
            )
        }
    }

    fn parse(toml_str: &str) -> Vec<MigrationDeclaration> {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default, rename = "migration")]
            migrations: Vec<MigrationDeclaration>,
        }
        toml::from_str::<Wrapper>(toml_str).unwrap().migrations
    }

    /// The canonical happy path: one type, one finding, one claim.
    const WIDEN_BALANCE: &str = r#"
        [[migration]]
        id = "widen-balance"
        migrates = ["Data"]
        runs_before_read = true

          [[migration.covers]]
          category = "Struct Field Type Changed"
          target = "Data.amount"
          change = "U64 -> I128"
    "#;

    fn amount_widened() -> Finding {
        finding(
            Severity::Critical,
            "Struct Field Type Changed",
            Some("Data"),
            Some("Data.amount"),
            Some("U64 -> I128"),
        )
    }

    #[test]
    fn a_fully_covered_type_is_migrated_with_no_diagnostics() {
        let findings = vec![amount_widened()];
        let audit = audit(&findings, &parse(WIDEN_BALANCE), None);

        assert_eq!(
            audit.coverage_of(0).map(|c| c.migration.as_str()),
            Some("widen-balance")
        );
        assert!(!audit.coverage_of(0).unwrap().is_inherited());
        assert_eq!(audit.diagnostics(), &[], "a verified migration is quiet");
        assert_eq!(audit.covered_count(), 1);
    }

    #[test]
    fn an_unclaimed_field_of_a_migrated_struct_is_a_gap_and_stays_open() {
        // The migration handles `amount` but the upgrade also drops `memo`.
        let findings = vec![
            amount_widened(),
            finding(
                Severity::Critical,
                "Struct Field Removed",
                Some("Data"),
                Some("Data.memo"),
                None,
            ),
        ];
        let audit = audit(&findings, &parse(WIDEN_BALANCE), None);

        assert!(audit.coverage_of(0).is_some());
        assert!(audit.coverage_of(1).is_none(), "the gap must stay open");

        let gaps: Vec<_> = audit
            .diagnostics()
            .iter()
            .filter(|d| d.kind == DiagnosticKind::CoverageGap)
            .collect();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].target.as_deref(), Some("Data.memo"));
    }

    #[test]
    fn a_pin_that_no_longer_matches_the_change_goes_stale() {
        // Same category and target, but the field now narrows instead.
        let findings = vec![finding(
            Severity::Critical,
            "Struct Field Type Changed",
            Some("Data"),
            Some("Data.amount"),
            Some("U64 -> U32"),
        )];
        let audit = audit(&findings, &parse(WIDEN_BALANCE), None);

        assert!(
            audit.coverage_of(0).is_none(),
            "a migration written for a different change must not keep covering"
        );
        let stale: Vec<_> = audit
            .diagnostics()
            .iter()
            .filter(|d| d.kind == DiagnosticKind::StaleClaim)
            .collect();
        assert_eq!(stale.len(), 1);
        assert!(stale[0].message.contains("U64 -> U32"));
    }

    #[test]
    fn a_claim_matching_nothing_is_stale_rather_than_dormant() {
        // The type is gone entirely: no findings at all mention it.
        let findings = vec![finding(
            Severity::Critical,
            "Function Removed",
            None,
            Some("legacy_init"),
            None,
        )];
        let audit = audit(&findings, &parse(WIDEN_BALANCE), None);

        assert_eq!(audit.covered_count(), 0);
        let kinds: Vec<_> = audit.diagnostics().iter().map(|d| d.kind).collect();
        assert!(kinds.contains(&DiagnosticKind::StaleClaim));
        assert!(kinds.contains(&DiagnosticKind::NoFindingsForType));
    }

    #[test]
    fn an_unpinned_claim_still_matches_on_category_and_target() {
        let migrations = parse(
            r#"
            [[migration]]
            id = "widen-balance"
            migrates = ["Data"]
            runs_before_read = true

              [[migration.covers]]
              category = "Struct Field Type Changed"
              target = "Data.amount"
            "#,
        );
        let findings = vec![amount_widened()];
        assert_eq!(audit(&findings, &migrations, None).covered_count(), 1);
    }

    #[test]
    fn a_cascade_inherits_coverage_from_its_migrated_root() {
        let findings = vec![amount_widened(), cascade("Wrapper", "Data")];
        let audit = audit(&findings, &parse(WIDEN_BALANCE), None);

        let inherited = audit.coverage_of(1).expect("cascade must inherit");
        assert_eq!(inherited.migration, "widen-balance");
        assert_eq!(inherited.via.as_deref(), Some("Data"));
        assert_eq!(audit.diagnostics(), &[]);
    }

    #[test]
    fn cascade_inheritance_is_transitive() {
        // Outer embeds Wrapper embeds Data; only Data is migrated directly.
        // Diff-layer cascade detection already flattens `root_target` to the
        // ultimate root at every step of the chain, so both cascade findings
        // are rooted directly at "Data", not at their immediate parent.
        let findings = vec![
            cascade("Outer", "Data"),
            cascade("Wrapper", "Data"),
            amount_widened(),
        ];
        let audit = audit(&findings, &parse(WIDEN_BALANCE), None);

        assert_eq!(audit.coverage_of(0).unwrap().via.as_deref(), Some("Data"));
        assert_eq!(audit.coverage_of(1).unwrap().via.as_deref(), Some("Data"));
        assert_eq!(audit.covered_count(), 3);
    }

    #[test]
    fn a_cascade_does_not_inherit_from_a_partly_migrated_root() {
        let findings = vec![
            amount_widened(),
            finding(
                Severity::Critical,
                "Struct Field Removed",
                Some("Data"),
                Some("Data.memo"),
                None,
            ),
            cascade("Wrapper", "Data"),
        ];
        let audit = audit(&findings, &parse(WIDEN_BALANCE), None);

        assert!(
            audit.coverage_of(2).is_none(),
            "the dependent is still broken while the root is only half handled"
        );
    }

    #[test]
    fn a_migration_that_does_not_attest_ordering_covers_nothing() {
        let migrations = parse(
            r#"
            [[migration]]
            id = "widen-balance"
            migrates = ["Data"]

              [[migration.covers]]
              category = "Struct Field Type Changed"
              target = "Data.amount"
            "#,
        );
        let audit = audit(&[amount_widened()], &migrations, None);

        assert_eq!(audit.covered_count(), 0);
        assert_eq!(
            audit.diagnostics()[0].kind,
            DiagnosticKind::OrderingUnattested
        );
    }

    #[test]
    fn a_migration_with_no_declared_types_covers_nothing() {
        let migrations = parse(
            r#"
            [[migration]]
            id = "widen-balance"
            runs_before_read = true

              [[migration.covers]]
              category = "Struct Field Type Changed"
              target = "Data.amount"
            "#,
        );
        let audit = audit(&[amount_widened()], &migrations, None);

        assert_eq!(audit.covered_count(), 0);
        assert_eq!(audit.diagnostics()[0].kind, DiagnosticKind::NoTypesDeclared);
    }

    #[test]
    fn two_migrations_claiming_one_finding_cover_it_with_neither() {
        let migrations = parse(
            r#"
            [[migration]]
            id = "first"
            migrates = ["Data"]
            runs_before_read = true
              [[migration.covers]]
              category = "Struct Field Type Changed"
              target = "Data.amount"

            [[migration]]
            id = "second"
            migrates = ["Data"]
            runs_before_read = true
              [[migration.covers]]
              category = "Struct Field Type Changed"
              target = "Data.amount"
            "#,
        );
        let audit = audit(&[amount_widened()], &migrations, None);

        assert_eq!(audit.covered_count(), 0);
        let dupes: Vec<_> = audit
            .diagnostics()
            .iter()
            .filter(|d| d.kind == DiagnosticKind::DuplicateClaim)
            .collect();
        assert_eq!(dupes.len(), 1);
        assert!(dupes[0].message.contains("'first' and 'second'"));
    }

    #[test]
    fn a_claim_on_an_interface_break_is_rejected_not_honored() {
        let migrations = parse(
            r#"
            [[migration]]
            id = "reinit"
            migrates = ["Data"]
            runs_before_read = true

              [[migration.covers]]
              category = "Function Signature Changed"
              target = "initialize"
            "#,
        );
        let findings = vec![
            finding(
                Severity::Critical,
                "Function Signature Changed",
                None,
                Some("initialize"),
                Some("1 params -> 2 params"),
            ),
            amount_widened(),
        ];
        let audit = audit(&findings, &migrations, None);

        assert!(audit.coverage_of(0).is_none());
        let kinds: Vec<_> = audit.diagnostics().iter().map(|d| d.kind).collect();
        assert!(kinds.contains(&DiagnosticKind::NotMigratable));
    }

    #[test]
    fn a_claim_on_a_type_outside_migrates_is_rejected() {
        let migrations = parse(
            r#"
            [[migration]]
            id = "widen-balance"
            migrates = ["Data"]
            runs_before_read = true

              [[migration.covers]]
              category = "Struct Field Removed"
              target = "Other.gone"
            "#,
        );
        let findings = vec![
            amount_widened(),
            finding(
                Severity::Critical,
                "Struct Field Removed",
                Some("Other"),
                Some("Other.gone"),
                None,
            ),
        ];
        let audit = audit(&findings, &migrations, None);

        assert!(audit.coverage_of(1).is_none());
        let kinds: Vec<_> = audit.diagnostics().iter().map(|d| d.kind).collect();
        assert!(kinds.contains(&DiagnosticKind::ClaimOutsideScope));
    }

    #[test]
    fn contract_scoping_applies_only_to_the_named_contracts() {
        let migrations = parse(
            r#"
            [[migration]]
            id = "widen-balance"
            migrates = ["Data"]
            runs_before_read = true
            contracts = ["token"]

              [[migration.covers]]
              category = "Struct Field Type Changed"
              target = "Data.amount"
            "#,
        );
        let findings = vec![amount_widened()];

        assert_eq!(
            audit(&findings, &migrations, Some("token")).covered_count(),
            1
        );

        // For another contract the declaration is simply not in scope: no
        // coverage, and no diagnostics about someone else's migration.
        let other = audit(&findings, &migrations, Some("pool"));
        assert_eq!(other.covered_count(), 0);
        assert_eq!(other.diagnostics(), &[]);
        assert!(!other.has_declarations());
    }

    #[test]
    fn info_findings_are_not_coverage_gaps() {
        let findings = vec![
            amount_widened(),
            finding(
                Severity::Info,
                "Struct Documentation Changed",
                Some("Data"),
                Some("Data"),
                None,
            ),
        ];
        let audit = audit(&findings, &parse(WIDEN_BALANCE), None);

        assert_eq!(audit.diagnostics(), &[], "a doc change needs no migration");
    }

    #[test]
    fn status_classifies_the_three_verdicts() {
        assert_eq!(
            MigrationStatus::classify(0, 0),
            MigrationStatus::NotApplicable
        );
        assert_eq!(
            MigrationStatus::classify(3, 3),
            MigrationStatus::FullyMigrated
        );
        assert_eq!(
            MigrationStatus::classify(3, 1),
            MigrationStatus::PartiallyMigrated
        );
        assert_eq!(MigrationStatus::classify(3, 0), MigrationStatus::Unhandled);
    }
}

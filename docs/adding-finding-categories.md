# Adding a New Finding Category

This guide walks through every coordinated change required to introduce a new
finding category safely. Categories have stable IDs, fixed severities, axes,
structured guidance, and test coverage, so getting them right requires touching
several modules together. Follow each section in order and use the checklist at
the end to confirm nothing was missed before opening a pull request.

## Table of Contents

1. [What is a finding category?](#what-is-a-finding-category)
2. [Required source changes](#required-source-changes)
3. [Stable identifiers](#stable-identifiers)
4. [Output fields](#output-fields)
5. [Writing the detection rule](#writing-the-detection-rule)
6. [Suppression implications](#suppression-implications)
7. [Documentation updates](#documentation-updates)
8. [Schema and migration implications](#schema-and-migration-implications)
9. [Testing checklist](#testing-checklist)
10. [Full contributor checklist](#full-contributor-checklist)

---

## What is a finding category?

A finding category is the primary label attached to every finding the tool
emits. It is the string a user writes in `.safeguard.toml` to suppress a known
break, and the field JSON consumers use to route reports to the right
handler. Because both suppression rules and downstream consumers depend on the
exact string, categories are **stable identifiers**: once a category string
ships, it must not be renamed or removed without a documented deprecation.

---

## Required source changes

Adding a category requires editing the following files. Each is explained in its
own section below.

| File | What changes |
| --- | --- |
| `src/category.rs` | Add the enum variant, string, severity, trigger description, and remediation |
| `src/diff.rs` | Add the comparison logic and push a `Finding` |
| `docs/finding-categories.md` | Regenerated from `category.rs` — do not edit by hand |

No other files require structural changes for a basic category, but some
optional paths may touch `src/render.rs` (axis assignment) and test fixture
sources under `tests/fixtures/`.

---

## Stable identifiers

### The category string

The category string is defined by `FindingCategory::as_str()` in
`src/category.rs`. It is the single source of truth. Every reference to the
category in user-facing output, suppression matching, and JSON reports derives
from this method.

Rules for choosing a string:

- Use title case, space-separated words: `"Struct Field Removed"` not
  `"struct_field_removed"`.
- Be specific enough that two distinct conditions cannot share the same label.
- Do not reuse a string that appeared in a prior release, even if the old
  category was removed. Consumers and suppression files written against the old
  string would silently match the new, unrelated condition.

### Adding the enum variant

```rust
// src/category.rs — FindingCategory enum
pub enum FindingCategory {
    // … existing variants …
    MyNewCategory,  // ← add here
}
```

Then add a corresponding arm to every `match self` block in the same file:

1. `as_str(self)` — the stable category string.
2. `severity(self)` — the default `Severity` (see [Choosing a severity](#choosing-a-severity)).
3. `trigger_description(self)` — one sentence explaining what triggers the
   finding.
4. `remediation(self)` — one to three sentences of actionable guidance for the
   developer who encounters this finding.
5. `all()` — insert the variant in domain order (function findings together,
   struct findings together, etc.).

The test `all_categories_have_unique_strings` will catch a duplicated string,
and `from_str_roundtrips_all_categories` will catch a missing entry in `all()`.

### Choosing a severity

| Severity | Use when |
| --- | --- |
| `Critical` | The change will corrupt stored on-chain data, break callers, or prevent the contract from functioning. |
| `Warning` | The change may require a migration, raises the protocol requirement, or affects external systems in a non-fatal way. |
| `Info` | The change is additive and safe, or is cosmetic. |

Lean toward the stricter level only when the risk is real — overusing
`Critical` trains users to dismiss the report.

---

## Output fields

Every `Finding` carries these fields, which appear in all output formats:

| Field | Source | Notes |
| --- | --- | --- |
| `category` | `FindingCategory::as_str()` | Stable; used for suppression |
| `severity` | `FindingCategory::severity()` | May be overridden at construction |
| `message` | Constructed in `diff.rs` | Names the type, field, and what changed |
| `target` | Constructed in `diff.rs` | E.g. `"MyStruct.my_field"` |
| `type_name` | `Some(name)` when cascade detection is needed | See below |

If your finding concerns a user-defined type that other types embed (a struct
field, an enum case payload, a union case payload), set `type_name` to
`Some(type_name_string)` on the `Finding`. The cascade detector in `diff.rs`
walks the reverse-dependency graph built by `mapper.rs` and emits a
`CascadingLayoutBreak` finding for each type that transitively embeds the broken
type. Omitting `type_name` disables cascade detection for that finding.

---

## Writing the detection rule

Most rules belong in `src/diff.rs`. The general pattern:

```rust
// Inside compare_my_domain() in diff.rs
if old_value != new_value {
    findings.push(Finding {
        category: FindingCategory::MyNewCategory.as_str().to_owned(),
        severity: FindingCategory::MyNewCategory.severity(),
        message: format!(
            "'{}': the relevant thing changed from {:?} to {:?}",
            type_or_function_name, old_value, new_value
        ),
        target: Some(format!("{}.{}", container_name, member_name)),
        type_name: Some(container_name.to_owned()), // if cascade detection needed
        ..Finding::default()
    });
}
```

Call your new comparison function from the top-level `compare()` function so it
runs on every analysis.

**Message quality rules:**
- Name the exact type, field, or parameter that changed.
- State what the old value was and what the new value is, where that
  information is available without truncation.
- Do not repeat the category string verbatim in the message — the category is
  already a separate field.

---

## Suppression implications

The category string returned by `as_str()` is what users write in
`.safeguard.toml` to suppress a finding:

```toml
[[suppress]]
category = "My New Category"
target   = "MyContract.my_function"
author   = "alice@example.com"
reason   = "Intentional rename during v2 migration."
expiry   = "2027-03-01"
```

This has two consequences when introducing a new category:

1. **Never rename a shipped string.** If a category string must change, treat
   the old string as a deprecated alias in the suppression engine rather than
   removing it. Renaming silently breaks every suppression rule already written
   against the old string.
2. **The suppression key is the category string, not the finding type.**
   Classification (storage vs. event) does not change the category string, so a
   suppression rule written for `"Struct Field Removed"` continues to match
   regardless of whether the type is later reclassified as an event. Do not
   create a separate `"Event Schema Removed"` variant just to carry a different
   suppression key — the event-vs-storage distinction is presentational, not
   structural.

For a full description of the suppression security model — fingerprints, expiry,
author accountability — see [Suppression Security Policy](suppression_security_policy.md).

---

## Documentation updates

### `docs/finding-categories.md`

This file is **generated from `src/category.rs`**. Do not edit it by hand —
the test `generated_markdown_matches_committed_file` will fail if the committed
file diverges from what `FindingCategory::generate_markdown_reference()` would
produce.

To regenerate the file after adding your category, run:

```bash
cargo test --test snapshot_tests
```

If the generated output differs from the committed file the test will print a
diff path. Copy the generated file into place and commit it alongside your
source changes:

```bash
cp /tmp/finding-categories.generated.md docs/finding-categories.md
```

### `docs/contributing.md`

The "Adding a New Detection Rule" section in the contributing guide lists the
general steps for `diff.rs`. If your category involves a new kind of comparison
function (not just an additional arm in an existing `match`), add a note there
explaining when the new function is called.

### Snapshot tests

Text, Markdown, and JSON output are covered by snapshot tests in
`tests/snapshot_tests.rs`. If your new category fires on any existing test
fixture, the snapshots will diverge. Update them with:

```bash
UPDATE_SNAPSHOTS=1 cargo test --test snapshot_tests
```

Review the diff in `tests/snapshots/` to confirm the new finding appears in the
expected output, then commit the updated snapshots.

---

## Schema and migration implications

The `category` field in the JSON report is a plain string. Adding a new
category string is an **additive change** to the report schema: old consumers
that do not recognize the new string must tolerate it gracefully (see
[Report Schema Compatibility Policy](report_schema_compatibility.md)).

No migration step is needed when adding a category, because existing saved
reports simply do not contain the new category string — there is no old data to
transform. A migration step is required only when renaming or removing a
category string in a way that would cause saved reports to fail validation.

For guidance on when a `report_schema_version` bump and a migration step are
required, see [Report Schema Migrations](report_migrations.md).

---

## Testing checklist

Every new category needs at minimum:

- [ ] A unit test in `src/diff.rs` (or the relevant module) that constructs a
  minimal before/after spec pair where the condition is true and asserts the
  finding is emitted with the correct category string and severity.
- [ ] A unit test that constructs a compatible pair (the condition is not true)
  and asserts no finding of that category is emitted.
- [ ] A test that verifies the cascade detector fires when a type carrying the
  new finding is embedded in another type (required only if `type_name` is set).
- [ ] Updated snapshots if the new category fires on an existing fixture.
- [ ] `cargo test` passing clean, including `generated_markdown_matches_committed_file`.

---

## Full contributor checklist

Use this list when opening a pull request for a new finding category:

- [ ] Added `MyNewCategory` variant to `FindingCategory` enum in `src/category.rs`
- [ ] Added `as_str()` arm returning the chosen stable category string
- [ ] Added `severity()` arm with the appropriate default severity
- [ ] Added `trigger_description()` arm with a one-sentence description
- [ ] Added `remediation()` arm with actionable guidance
- [ ] Inserted the variant in `all()` in domain order
- [ ] Added the comparison logic in `src/diff.rs` and called it from `compare()`
- [ ] Set `type_name` on the `Finding` if cascade detection is relevant
- [ ] Regenerated `docs/finding-categories.md` and committed the update
- [ ] Updated snapshots (`UPDATE_SNAPSHOTS=1 cargo test --test snapshot_tests`) if affected
- [ ] Added at least one positive test (finding fires) and one negative test (no false positive)
- [ ] Confirmed `cargo fmt --check`, `cargo clippy`, `cargo build`, and `cargo test` all pass
- [ ] Opened the pull request with a link to the relevant issue

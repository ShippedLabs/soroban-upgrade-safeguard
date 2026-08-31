# Report Schema Migrations

Saved JSON reports (`--format json`, or a report re-rendered later with the
`render` subcommand) are durable artifacts — a CI pipeline archives them,
an audit trail depends on them, a dashboard ingests them months after the
run that produced them. As the report shape evolves, an old saved report
needs an explicit, testable path forward rather than a growing pile of
`#[serde(default)]` annotations quietly reinterpreting old data as if it
always meant what a field means today.

```bash
soroban-upgrade-safeguard upgrade-report old_report.json --output upgraded.json
```

- [Schema versions](#schema-versions)
- [The `upgrade-report` command](#the-upgrade-report-command)
- [What migration preserves](#what-migration-preserves)
- [Migration records](#migration-records)
- [Determinism and idempotency](#determinism-and-idempotency)
- [Errors](#errors)
- [Adding a new migration](#adding-a-new-migration)

## Schema versions

Every report carries `report_schema_version`. Two versions exist today:

- **Version 0** (implicit) — any document with the field _absent entirely_.
  This names every report written before `report_schema_version` existed at
  all. Nothing in the tool ever writes a document at this version on
  purpose; it exists only to describe old data honestly.
- **Version 1** (current) — what `--format json` writes today, and the only
  version [`RenderableReport`](../src/render.rs) directly deserializes.

Before this framework, an absent `report_schema_version` field was treated
as _current_ by a serde default — correct only because the shape has never
actually changed since the field was introduced. That coincidence is no
longer load-bearing: version 0 is now a first-class, migrated version like
any other, and the next real schema break gets a real migration step instead
of another silent default.

## The `upgrade-report` command

```bash
soroban-upgrade-safeguard upgrade-report <REPORT_JSON | -> [--output PATH]
```

- Reads a file, or `-` for stdin.
- Writes the upgraded, canonical JSON to stdout, or to `--output PATH`.
- Prints a one-line summary to stderr: either the version transition and
  step count, or that the document was already current.
- Exits non-zero (with the error on stderr) for a document this build
  cannot read at all.

`render` and any other JSON consumer still only understand
[`REPORT_SCHEMA_VERSION`](../src/render.rs) directly — `upgrade-report` is
the explicit step that gets an older document there.

## What migration preserves

A migration step transforms the raw JSON `Value`, not a typed struct, so it
can move data whose _old_ shape this build's Rust types don't represent —
but the result always deserializes into today's `RenderableReport`. That
means, through migration:

- **Findings** — category, message, rule ID, target, root target, axes.
- **Suppressions** — `suppressed` and `suppression_reason` on each finding.
- **Axis verdicts and gating** — `axis_verdicts`, `gated_axes`.
- **Scope** — what was analyzed and the storage-coverage summary.
- **Hashes** — `old_interface_hash`, `new_interface_hash`.
- **Provenance** — tool version, timestamp, inputs, RPC metadata.
- **Verdict** — `is_safe`, `strict`, severity counts, recommended bump.

Nothing here is defaulted or inferred; the version-0→1 step is a version
stamp because version 0 and version 1 are, structurally, the same shape —
version 0 simply predates the field that says so. A future step that
actually changes a field's meaning must transform the data explicitly, the
same way, rather than lean on a struct-level default.

## Migration records

An upgraded document carries its own history, under `migration`:

```json
{
  "report_schema_version": 1,
  "migration": {
    "original_schema_version": 0,
    "steps": [
      {
        "from": 0,
        "to": 1,
        "description": "Stamp the implicit pre-versioning shape as schema version 1. ..."
      }
    ],
    "migrated_to": 1,
    "migration_tool_version": "0.1.0"
  }
}
```

`migration` is absent on a report written directly by a live run, and on a
document that was already current when `upgrade-report` ran — it appears
only once a document has actually been migrated, so its presence itself
tells you the document didn't start life at the current version.

## Determinism and idempotency

The same input always produces the same output, and running
`upgrade-report` again on an already-upgraded document is a byte-for-byte
no-op: the document is already at [`REPORT_SCHEMA_VERSION`], so zero new
steps apply, and the `migration` record from the first run is preserved
exactly rather than overwritten. This is what makes it safe to run
`upgrade-report` unconditionally over an archive of reports spanning
several schema versions, or repeatedly in a pipeline step that doesn't know
in advance which stored reports need it.

## Errors

| Condition                                                                | What happens                                                      |
| :----------------------------------------------------------------------- | :---------------------------------------------------------------- |
| Malformed JSON                                                           | Rejected with the underlying parse error.                         |
| Valid JSON, but not a report (e.g. a JSON array, or an unrelated object) | Rejected, naming what was expected.                               |
| `report_schema_version` present but not a plain non-negative integer     | Rejected, naming the field.                                       |
| `report_schema_version` newer than this build supports                   | Rejected, naming the found and supported versions.                |
| A gap in the migration registry (a version with no registered next step) | Rejected — a defect in the tool's own coverage, never guessed at. |

None of these fall back to a best-effort reinterpretation. A document this
build cannot place on a real path to [`REPORT_SCHEMA_VERSION`] fails loudly
instead.

## Adding a new migration

For the full compatibility contract covering stable fields, additive fields,
enum values, rule IDs, and consumer guidance, see
[Report Schema Compatibility Policy](report_schema_compatibility.md).

When [`REPORT_SCHEMA_VERSION`](../src/render.rs) needs to move to `N+1`:

1. Bump `REPORT_SCHEMA_VERSION`.
2. Add one `MigrationStep { from: N, to: N + 1, .. }` to the `MIGRATIONS`
   registry in [`src/migration.rs`](../src/migration.rs), with an `apply`
   function that transforms the raw `Value` and a `description` explaining
   what changed and why the transformation is correct.
3. Freeze a fixture for version `N` under
   `tests/fixtures/report_migrations/` (copy a real report of that version,
   don't hand-write one) so the migration has a real, committed input to
   run against and the old shape can never silently drift out from under
   the test.
4. Add round-trip and idempotency tests exercising the new step, mirroring
   [`tests/report_migrations.rs`](../tests/report_migrations.rs).

Never edit an existing `MigrationStep` once it has shipped — a document
written against version `N` must always migrate the same way, forever.

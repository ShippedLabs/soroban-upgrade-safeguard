# Report Schema Compatibility Policy

The JSON output produced by `--format json` is the integration surface for
dashboards, bots, CI pipelines, and audit archives. This document defines
which fields are stable, which are additive, which are deprecated, and how
consumers should handle unknown fields and unsupported future versions.

## Table of Contents

1. [Stability classifications](#stability-classifications)
2. [Top-level fields](#top-level-fields)
3. [Finding fields](#finding-fields)
4. [Enum values](#enum-values)
5. [Rule IDs](#rule-ids)
6. [Schema versioning](#schema-versioning)
7. [Handling unknown additive fields](#handling-unknown-additive-fields)
8. [Handling unsupported future versions](#handling-unsupported-future-versions)
9. [Deprecated fields](#deprecated-fields)
10. [Consumer checklist](#consumer-checklist)

---

## Stability classifications

Every field and enum value in the JSON output is classified as one of:

| Classification | Meaning |
| :--- | :--- |
| **Stable** | Present in every report at this schema version. Will not be removed or renamed within a schema version. Type and semantics are fixed. |
| **Additive** | May be absent in older reports at the same schema version. Consumers must treat an absent additive field as if it had its zero/empty value. Will not be removed within a schema version once introduced. |
| **Conditional** | Present only when certain conditions are met (e.g. suppression was active, RPC mode was used). Semantically absent when the condition does not apply. |
| **Deprecated** | Still emitted for backward compatibility but scheduled for removal. Do not build new logic against deprecated fields; migrate to the replacement. |

---

## Top-level fields

### Stable

| Field | Type | Notes |
| :--- | :--- | :--- |
| `report_schema_version` | `integer` | Absent on schema-version-0 documents (treat absence as `0`). Present and equal to `1` on all current output. |
| `is_safe` | `boolean` | `true` when the upgrade has zero ungated critical findings; `false` otherwise. This is the primary gate field. |
| `strict` | `boolean` | Whether `--strict` mode was active. When `true`, warnings also gate `is_safe`. |
| `counts.critical` | `integer` | Total critical findings including suppressed ones. |
| `counts.warning` | `integer` | Total warning findings including suppressed ones. |
| `counts.info` | `integer` | Total info findings including suppressed ones. |
| `suppressed_count` | `integer` | Findings acknowledged by the suppression config. |
| `total_findings` | `integer` | Sum of all findings regardless of severity or suppression. |
| `recommended_bump` | `string` | One of `"none"`, `"patch"`, `"minor"`, `"major"`. |
| `findings_by_category` | `object` | Keys are category strings (see [Rule IDs](#rule-ids)); values are arrays of finding objects. Key order is alphabetical and stable across runs. |
| `provenance.tool_version` | `string` | `CARGO_PKG_VERSION` of the binary that produced the report. |

### Additive

| Field | Type | Default when absent | Notes |
| :--- | :--- | :--- | :--- |
| `provenance.timestamp` | `string` | `""` | ISO 8601 / RFC 3339. Empty when `--no-timestamp` was active. |
| `provenance.inputs` | `array<string>` | `[]` | Input paths, contract IDs, or content hashes. |
| `provenance.ledger_sequence` | `integer` | absent | Set only in RPC mode. |
| `provenance.network` | `string` | absent | Set only in RPC mode. |
| `provenance.rpc_endpoint` | `string` | absent | Sanitized URL. Set only in RPC mode. |
| `provenance.code_hash` | `string` | absent | SHA-256 hex of fetched WASM. Set only in RPC mode. |
| `provenance.live_until_ledger_seq` | `integer` | absent | Ledger sequence until which the sampled ledger entry is live (`liveUntilLedgerSeq`). Set only in RPC mode, and only when the endpoint reported a TTL for the sampled entry. |
| `scope` | `object` | `{}` | Analysis scope summary (what dimensions were checked). |
| `storage_coverage` | `string` | `""` | Human-readable storage coverage description. |
| `old_interface_hash` | `string` | absent | Hex interface hash of the old build. |
| `new_interface_hash` | `string` | absent | Hex interface hash of the new build. |
| `axis_verdicts` | `object` | `{}` | Per-axis `"passed"` / `"warning"` / `"failed"` verdict. Keys are axis names (see [Enum values](#enum-values)). |
| `gated_axes` | `array<string>` | `[]` | Axes whose findings contribute to `is_safe`. |
| `findings_by_axis` | `object` | `{}` | Same finding objects as `findings_by_category`, grouped by axis key instead of category string. |
| `call_abi` | `object` | `{}` | Directional call-ABI compatibility verdicts. |
| `empirical` | `boolean` | `false` | Whether empirical storage validation was active. |
| `empirical_findings` | `array` | `[]` | Present only when `empirical` is `true`. |

### Conditional

| Field | Present when |
| :--- | :--- |
| `migration` | The document was processed by `upgrade-report` and at least one migration step ran. Absent on a report written directly by a live run and on already-current documents passed through `upgrade-report` with no steps applied. |

---

## Finding fields

Each object inside a `findings_by_category` or `findings_by_axis` array has
these fields.

### Stable

| Field | Type | Notes |
| :--- | :--- | :--- |
| `severity` | `string` | One of `"critical"`, `"warning"`, `"info"` (lowercase). |
| `category` | `string` | Exact category string. Stable across tool versions; see [Rule IDs](#rule-ids). |
| `message` | `string` | Human-readable description of the change. **Not stable** — do not parse or match on message text. Use `category` and `target` instead. |

### Additive

| Field | Type | Default when absent | Notes |
| :--- | :--- | :--- | :--- |
| `rule_id` | `string` | `""` | Snake-case stable identifier independent of the human-readable category label. Preferred over `category` for programmatic matching. |
| `target` | `string` | absent | Structured path to the affected entity, e.g. `"Data.amount"`. Use this for suppression and routing. |
| `root_target` | `string` | absent | The original entity that triggered a cascade. Present only on `Cascading Layout Break` findings. |
| `type_name` | `string` | absent | Name of the affected user-defined type. Used by cascade detection; useful for grouping findings by type. |
| `axes` | `array<string>` | `[]` | Compatibility axes this finding was classified under. |
| `suppressed` | `boolean` | `false` | `true` when this finding was acknowledged by a suppression rule. Suppressed findings are included in the output but do not contribute to `is_safe`. |
| `suppression_reason` | `string` | absent | The `reason` from the matching suppression rule. Present only when `suppressed` is `true`. |
| `remediation` | `string` | absent | Actionable guidance text. Present only when `--explain` was passed. |

---

## Enum values

The following string enumerations appear in the JSON output. New values may
be added in a future minor release; consumers must handle unknown values
gracefully (e.g. treat an unknown severity as `"info"`, treat an unknown axis
as unrecognized rather than crashing).

### `severity`

| Value | Meaning |
| :--- | :--- |
| `"critical"` | Change will break callers or corrupt stored data. |
| `"warning"` | Change may require migration or affects external systems. |
| `"info"` | Additive or cosmetic change. |

### Compatibility axes (`axis_verdicts` keys, `axes` array values, `gated_axes` values)

| Value | Meaning |
| :--- | :--- |
| `"storage_layout"` | On-chain serialization compatibility. |
| `"call_abi"` | Public function call interface compatibility. |
| `"event_indexer"` | Off-chain event schema compatibility. |
| `"source_level"` | Source-code-level API compatibility. |
| `"runtime_surface"` | WASM runtime feature compatibility (imports, memory, tables). |

### `axis_verdicts` values

| Value | Meaning |
| :--- | :--- |
| `"passed"` | No findings on this axis, or all findings are suppressed. |
| `"warning"` | Warning-level findings present; does not gate `is_safe` unless `--strict`. |
| `"failed"` | Critical findings present; gates `is_safe`. |

### `recommended_bump`

| Value | Meaning |
| :--- | :--- |
| `"none"` | No changes detected. |
| `"patch"` | Only informational findings. |
| `"minor"` | Warning-level findings present. |
| `"major"` | Critical findings present. |

---

## Rule IDs

A `rule_id` is a snake_case string that is **stable across tool versions**
and **independent of the human-readable `category` label**. Prefer `rule_id`
over `category` for programmatic routing, because the human-readable label
can receive wording updates without the rule ID changing.

`category` strings are also stable (they are the suppression key), but they
are title-case and contain spaces. Both are safe to use; `rule_id` is the
canonical machine key.

The full list of rule IDs is in the
[Finding Category Reference](finding-categories.md). Consumers should ignore
unknown rule IDs rather than rejecting the document — new rules are added as
minor releases and their presence in a report does not change the semantics
of existing fields.

---

## Schema versioning

Every report carries `report_schema_version` as a top-level integer.

| Version | Status | Notes |
| :--- | :--- | :--- |
| `0` (absent field) | Legacy | Structurally identical to version 1. Produced before the field existed. Migrate with `upgrade-report`. |
| `1` | Current | All output from the current release. |

The version number advances **only** when a field's meaning changes, a field
is removed, or the structure changes in a way that cannot be described as
purely additive. Adding a new optional field does **not** bump the schema
version.

Full migration documentation, including what each step preserves and how to
add a new step when the schema next needs a breaking change, is in
[Report Schema Migrations](report_migrations.md).

---

## Handling unknown additive fields

**Consumers must ignore unknown fields** in the JSON output. This is the
single most important rule for forward compatibility.

The tool adds new optional fields in minor releases without bumping
`report_schema_version`. A consumer that rejects unknown fields will break on
the next minor release. A consumer that ignores them will continue working
indefinitely until it chooses to adopt the new field.

In practice:

- In languages with typed deserialization (Rust `serde`, Python `dataclasses`,
  TypeScript interfaces), configure the deserializer to ignore extra keys.
- In JavaScript / TypeScript, reading known keys from a plain `JSON.parse`
  result already achieves this — do not use a strict schema validator that
  rejects unknown properties.
- In Python, use `dacite.from_dict` with `strict=False`, or simply access
  fields as dictionary keys and handle `KeyError` / `.get()` for optional ones.

Concrete example — a consumer that is safe across additive changes:

```python
import json

def is_upgrade_safe(report_path: str) -> bool:
    with open(report_path) as f:
        report = json.load(f)

    # Always check the schema version before reading any fields.
    schema_version = report.get("report_schema_version", 0)
    if schema_version > 1:  # replace 1 with the version you were built against
        raise ValueError(f"Unsupported schema version {schema_version}")

    # Read only what you need; ignore everything else.
    return report["is_safe"]
```

---

## Handling unsupported future versions

When `report_schema_version` is higher than the version your consumer was
built against, **reject the document** rather than attempting to read it.
A higher version may have changed the meaning of a field you depend on.

```python
SUPPORTED_SCHEMA_VERSION = 1

def load_report(path: str) -> dict:
    with open(path) as f:
        report = json.load(f)
    version = report.get("report_schema_version", 0)
    if version > SUPPORTED_SCHEMA_VERSION:
        raise ValueError(
            f"Report uses schema version {version}, but this consumer "
            f"only supports up to version {SUPPORTED_SCHEMA_VERSION}. "
            f"Upgrade the consumer or run `upgrade-report` to downgrade the report."
        )
    return report
```

Options when you encounter an unsupported version:

1. **Upgrade your consumer** to understand the new version. Check the release
   notes for the breaking change description.
2. **Use `upgrade-report` in reverse** — this is not supported. The tool only
   migrates forward. Produce a new report with the version of the tool your
   consumer supports.
3. **Re-run the comparison** with the version of the tool your consumer
   supports, if the input WASMs are still available.

Do not fall back to a best-effort read of a newer version. A field whose
meaning changed in the new version will silently produce wrong results.

---

## Deprecated fields

No fields are currently deprecated. When a field is deprecated in a future
release, it will be listed here with:

- the field name and location in the document,
- the tool version when it was deprecated,
- the tool version when it will be removed (at least one major version
  after deprecation),
- and the replacement field or approach.

Until that list is non-empty, all emitted fields are either stable, additive,
or conditional as described above.

---

## Consumer checklist

Use this list when building or auditing a JSON consumer:

- [ ] Read `report_schema_version` before accessing any other field. Treat
  an absent field as version `0`.
- [ ] Reject documents whose `report_schema_version` exceeds the version you
  were built against.
- [ ] Treat a missing `report_schema_version` as version `0` and run
  `upgrade-report` before processing, or handle version-0 documents
  directly (they are structurally identical to version 1).
- [ ] Use `is_safe` as the primary gate, not `counts.critical`. `is_safe`
  already accounts for `--strict` mode, suppressed findings, and gated axes.
- [ ] Prefer `rule_id` over `category` for programmatic routing of findings.
- [ ] Use `target` (not `message`) for matching findings to specific entities.
  Message text is not stable.
- [ ] Ignore unknown top-level fields and unknown fields inside finding objects.
- [ ] Handle unknown enum values (severity, axis names, bump levels) without
  crashing — treat them as unrecognized rather than invalid.
- [ ] Treat absent additive fields as their zero/empty value (see the tables
  above for defaults).
- [ ] Check `suppressed` on each finding before routing it to an alert or
  failure path — suppressed findings are intentionally acknowledged.
- [ ] For long-term archives, run `upgrade-report` on stored documents before
  each use so the consumer always reads the current schema version.

---

*This document is cross-referenced from the JSON output documentation in
[documentation.md](documentation.md#json-schema) and from the migration
guide in [report_migrations.md](report_migrations.md).*

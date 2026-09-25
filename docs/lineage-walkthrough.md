# Lineage Tracking Walkthrough

This guide follows one contract through four releases and shows how
`--lineage-store`, `--record-version`, `--retire-version`, and
`--max-live-versions` work together. Each flag makes sense once you see the
whole sequence.

For the ledger file format, see
[Persistent Compatibility Lineage Ledger](lineage_model.md). For a short
reference on each flag, see
[Validating against historical versions](../README.md#validating-against-historical-versions-lineage-tracking)
in the README.

## What one run does

Every run that passes `--lineage-store` goes through these steps in order:

1. **Load** the store from `--lineage-store <PATH>`. If the file does not
   exist, the run starts with an empty in-memory store.
2. **Apply `--max-live-versions <N>`**, if given, to the store's policy.
3. **Apply `--retire-version <ID>`**, if given, by marking that entry
   `Retired`. An ID that is not in the store is ignored without an error.
4. **Compare** `<OLD_WASM>` against `<NEW_WASM>` in the usual way. Then
   validate `<NEW_WASM>` against every entry that is still live. Each
   mismatch is reported under the category
   `Historical Lineage Break (<version_id>)`.
5. **Record `<NEW_WASM>`** as a new `Live` entry with `--record-version <ID>`,
   if given, and **write the whole store** back to `<PATH>`.
6. **Render** the report and exit with the combined verdict.

Two points follow from this order:

- **Nothing is saved to disk unless `--record-version` is given.** Step 5
  is the only step that writes the file. A retirement or a
  `--max-live-versions` cap without `--record-version` affects only the
  current run.
- **Recording does not depend on the verdict.** A candidate that fails the
  comparison is still recorded, because step 5 runs before the exit code is
  decided. Pass `--record-version` only for builds you actually ship.

## Setup

The examples use four builds of one contract and a store at
`./lineage.json`:

```text
wasm/v1.wasm   # first release: writes a `Position` struct to storage
wasm/v2.wasm   # adds functions, leaves `Position` alone
wasm/v3.wasm   # adds functions, never reads `Position`
wasm/v4.wasm   # the candidate: changes a field in `Position`
```

Commit `lineage.json` to the repository, or keep it in a CI cache. It is the
record of what has shipped.

## Step 1: Record the first release

The comparison command always needs an `<OLD_WASM>` and a `<NEW_WASM>`, and
`--record-version` always records `<NEW_WASM>`. The first release has no
predecessor, so compare it with itself. The run is a clean no-op, and it
creates the store:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v1.wasm \
  --lineage-store ./lineage.json \
  --record-version v1.0.0
```

The progress output ends with
`📜 Lineage store updated and saved to ./lineage.json`. The file now holds
one `Live` entry, `v1.0.0`, with `order: 1`. The entry stores the build's
wasm hash, its interface hash, and its full spec JSON. Later runs validate
against the stored spec, so you don't need to keep `v1.wasm`.

## Step 2: Ship v2 and v3

Compare each release with the one before it and record it:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --lineage-store ./lineage.json \
  --record-version v2.0.0

soroban-upgrade-safeguard ./wasm/v2.wasm ./wasm/v3.wasm \
  --lineage-store ./lineage.json \
  --record-version v3.0.0
```

The `v3.0.0` run validates the candidate against `v1.0.0` and `v2.0.0`
before it records `v3.0.0`. After both runs, the store holds three live
entries:

| `version_id` | `order` | `status` |
|---|---|---|
| `v1.0.0` | 1 | `Live` |
| `v2.0.0` | 2 | `Live` |
| `v3.0.0` | 3 | `Live` |

Each new entry gets the next `order`. Order, not the version string,
decides what "most recent" means in step 4.

## Step 3: Validate a candidate against the whole lineage

Before you ship `v4`, check it without recording it. Leave out
`--record-version`, so the store is not changed:

```bash
soroban-upgrade-safeguard ./wasm/v3.wasm ./wasm/v4.wasm \
  --lineage-store ./lineage.json
```

The `v3` → `v4` comparison alone passes, because `v3` never touches
`Position`. The lineage check also compares `v4` with each live entry, so
the change to `Position` shows up against `v1.0.0`. It is reported in its
own category, and the message names the version whose data would break:

```text
Historical Lineage Break (v1.0.0)
  [Historical Version 'v1.0.0' (order 1)] ...
```

Historical findings count toward the verdict in the same way as direct
findings. A Critical break fails the run, and so does any Warning under
`--strict`. `.safeguard.toml` suppression rules match them by the original
finding, so you can acknowledge a known historical break in the same way as
any other break.

At this point you have two options:

- **Fix `v4`** so it still reads `Position` the way `v1.0.0` wrote it.
- **Retire `v1.0.0`**, but only if nothing on-chain still holds data in the
  `v1.0.0` layout, for example because you have migrated it. See step 4.

## Step 4: Retire a version you no longer need to support

`--retire-version` runs before validation, so you can preview the effect
without saving anything:

```bash
# Preview: v1.0.0 is excluded from this run only; lineage.json is unchanged
soroban-upgrade-safeguard ./wasm/v3.wasm ./wasm/v4.wasm \
  --lineage-store ./lineage.json \
  --retire-version v1.0.0
```

To make the retirement permanent, ship `v4` in the same invocation. Adding
`--record-version` causes the store to be written, so both the retirement
and the new entry are saved:

```bash
soroban-upgrade-safeguard ./wasm/v3.wasm ./wasm/v4.wasm \
  --lineage-store ./lineage.json \
  --retire-version v1.0.0 \
  --record-version v4.0.0
```

| `version_id` | `order` | `status` |
|---|---|---|
| `v1.0.0` | 1 | `Retired` |
| `v2.0.0` | 2 | `Live` |
| `v3.0.0` | 3 | `Live` |
| `v4.0.0` | 4 | `Live` |

Retired entries stay in the file for audit purposes, but candidates are no
longer validated against them.

## Step 5: Cap the lineage with `--max-live-versions`

As a contract's history grows, you may decide that only the most recent
releases still matter. `--max-live-versions <N>` limits validation to the
`N` live entries with the highest `order`. Retired entries are removed
first and do not count toward `N`:

```bash
# Validate v5 against v3.0.0 and v4.0.0 only (v2.0.0 is live but outside the cap)
soroban-upgrade-safeguard ./wasm/v4.wasm ./wasm/v5.wasm \
  --lineage-store ./lineage.json \
  --max-live-versions 2
```

The cap is saved in the file. If you combine `--max-live-versions` with
`--record-version`, the cap is written to the store's `policy` block and
applies to every later run, even runs that don't pass the flag. To change
it, pass a new value in a recording run. No flag removes it, so to go back
to no cap, delete `max_live_versions` from the file by hand.

Use `--max-live-versions` to limit how far back validation looks, and
`--retire-version` for specific versions you know are safe to drop. Retiring
is explicit, and the cap removes old versions automatically as new ones are
recorded.

## A CI recipe

A typical pipeline validates on every pull request and records on release:

```bash
# On every pull request: validate the candidate, never write the store
soroban-upgrade-safeguard ./baseline.wasm ./target/contract.wasm \
  --lineage-store ./lineage.json

# On a release tag: validate, record, then commit the updated store
soroban-upgrade-safeguard ./baseline.wasm ./target/contract.wasm \
  --lineage-store ./lineage.json \
  --record-version "$RELEASE_TAG"
git add lineage.json && git commit -m "lineage: record $RELEASE_TAG"
```

Because recording does not depend on the verdict, make the recording step
run only after the gate has passed. For example, put it in a release job
that depends on the PR check.

## Pitfalls

- **Use a new ID for each recording.** Currently, if you pass
  `--record-version` with an ID that is already in the store, the run fails
  with `invalid order 0` and does not update the store. The run exits
  before it renders the report. If you need to amend an entry, edit
  `lineage.json` directly.
- **Without `--lineage-store`, the lineage flags do nothing.**
  `--record-version`, `--retire-version`, and `--max-live-versions` are
  accepted without it, but they have no effect and produce no warning.
- **Retiring an unknown ID has no effect.** If you mistype an ID in
  `--retire-version`, the run does not fail, and nothing is retired.
- **The store is always written as JSON.** A store loaded from a `.toml`
  file is saved back to the same path in JSON format. It still loads
  correctly on the next run, but the TOML formatting is lost.
- **Entries without a `spec_json` are skipped.** Entries recorded by
  `--record-version` always include one. A hand-written entry with no
  `spec_json` stays in the store but is never validated against.

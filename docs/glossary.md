# Glossary of Terms

This glossary defines the core terminology used throughout Soroban Upgrade Safeguard reports, configuration files, and documentation.

## Core Concepts

### Finding
A single detected change or issue between two contract builds. Each finding has a category, severity, optional axis assignment, and descriptive details about what changed. Findings are the fundamental unit of analysis output — everything the tool reports is structured as a finding.

**Example:** A finding with category `Function Removed` indicates that a function present in the old build is missing from the new build.

**See also:** [Finding Category Reference](finding-categories.md)

### Category
The stable identifier attached to every finding that classifies the type of change. Categories have fixed strings (e.g., `Function Removed`, `Struct Field Added`) that never change between versions, making them safe to use in suppression rules and automated systems.

**Example categories:** `Function Removed`, `Struct Field Reordered`, `Enum Case Added`

**See also:** [Finding Category Reference](finding-categories.md)

### Severity
The impact level of a finding, determining whether it fails a run and how it's displayed. There are three severity levels:

- **Critical** (🔴) — Breaking changes that corrupt data or break integrations; always fail the run
- **Warning** (🟡) — Potentially breaking changes that require review; fail the run only with `--strict`
- **Info** (🔵) — Non-breaking changes for awareness; never fail the run

**See also:** [Severity Levels](documentation.md#severity-levels)

### Verdict
The final pass/fail decision for a comparison or validation run. A verdict can be:

- **PASSED** ✅ — No critical findings (or no warnings when using `--strict`)
- **FAILED** ❌ — Critical findings present (or warnings when using `--strict`)
- **SUPPRESSED** 🔕 — All findings were suppressed by configuration

The verdict determines the exit code and appears at the top of every report.

**See also:** [Exit Codes and CI Integration](documentation.md#exit-codes-and-ci-integration)

## Analysis Targets

### Target
A specific element in a contract's interface being analyzed, such as a function, struct, enum, or field. Findings describe changes to targets by comparing the old and new versions.

**Examples:**
- Function target: `initialize`
- Struct target: `TokenMetadata`
- Field target: `TokenMetadata.decimals`

### Baseline
The old or original contract build being compared against. In RPC mode, this is the on-chain deployed contract; in local mode, it's the first WASM file argument.

**See also:** [Comparing against a deployed contract](../README.md#comparing-against-a-deployed-contract-rpc-baseline)

### Candidate
The new or proposed contract build being validated. This is the upgrade you want to deploy, compared against the baseline to detect breaking changes.

## Change Propagation

### Cascade
When a change in one type propagates to affect all types that embed or reference it. For example, if a struct has a breaking field change, every other struct that contains that struct as a field also has a breaking change — this is a cascade.

**Example:** If `Address` struct changes a field, and `Transfer` struct contains an `Address` field, the tool reports both:
1. The direct break in `Address`
2. A `Cascading Layout Break` finding in `Transfer`

**See also:** [Cascading Layout Breaks](documentation.md#cascading-layout-breaks)

### Dependency Graph
The internal representation of how types reference each other. The tool builds a dependency graph to trace cascading breaks and identify all affected types when a low-level type changes.

## Policy and Control

### Suppression
A configuration rule that acknowledges a known, intentional breaking change so it no longer fails the run. Suppressed findings still appear in reports but are marked as `[SUPPRESSED]` and don't affect the exit code.

**Configuration location:** `.safeguard.toml` file

**Example:**
```toml
[[suppress]]
category = "Function Removed"
target = "deprecated_v1_transfer"
reason = "Planned removal in v2.0.0 - clients migrated to new_transfer"
```

**See also:** [Suppressing Known Breaking Changes](documentation.md#suppressing-known-breaking-changes)

### Axis
A dimension of compatibility analysis that groups related findings. Axes let you apply different policies to different aspects of a contract. The three main axes are:

- **`exported_interface`** — Public functions and types that external callers use
- **`storage_layout`** — Persistent data structures that must remain compatible
- **`event_indexer`** — Event schemas that off-chain indexers depend on

**Example use:** You might allow breaking changes to events (indexers can be updated) while keeping storage layout strict (data must not corrupt).

**See also:** [Multi-Axis Compatibility](multi_axis_compatibility.md)

### Policy
The configuration that controls which findings fail a run. Policies can:
- Enable or disable strict mode per axis
- Set compatibility budgets (maximum allowed findings)
- Configure custom severity overrides
- Control which axes are validated

**Configuration location:** `.safeguard.toml` under `[policy]`

**See also:** [Named Policy Profiles](named_policy_profiles.md)

### Policy Profile
A named set of compatibility rules that can be selected from configuration or the CLI. Policy profiles allow one repository to apply different validation policies for different contexts — such as relaxed rules during local development, stricter enforcement in pull requests, and release-specific validation for production candidates — without duplicating suppression rules or maintaining separate configuration files.

**Use with:** `--profile <NAME>` flag or `SOROBAN_SAFEGUARD_PROFILE` environment variable

**Example profiles:** `dev` (permissive), `pr` (strict), `release` (comprehensive), `emergency` (minimal)

**See also:** [Named Policy Profiles](named_policy_profiles.md)

### Compatibility Budget
A bounded **count** of findings allowed at a given scope, evaluated after
analysis without changing how any individual finding is classified,
suppressed, or gated. Where axis gating and `--strict` are boolean ("does
this kind of finding fail the run?"), a budget is numeric: "how many of
these are allowed before it does?" — e.g. "at most 3 new events this
release" or "zero warnings from this specific rule." A budget's scope can be
`global`, a specific `axis`, or a specific `rule_id`, and a narrower scope
replaces a broader one for the findings it covers rather than stacking with
it.

**Configuration location:** `[[budget]]` tables in `.safeguard.toml`,
alongside any `[[suppress]]` rules.

**Example:**
```toml
[[budget]]
scope  = "axis"
axis   = "event_indexer"
metric = "raw"
limit  = 3
```

An exceeded budget is reported separately from ordinary findings as a
`BudgetViolation`, and **always fails the run** — independent of `--strict`
and axis gating — since a configured budget is an explicit opt-in a team
chose rather than a default.

**See also:** [Compatibility Budgets](compatibility_budgets.md)

## Report Elements

### Provenance
Metadata about how a report was generated, including tool version, timestamps, input identifiers, resolved symlink targets, and RPC endpoints used. Provenance makes reports auditable and reproducible.

**Location in JSON reports:** `provenance` object at the report root

**See also:** [Report Provenance Fields](report-provenance.md)

### Interface Hash
A stable SHA-256 digest of a contract's normalized exported interface. Two builds with the same interface hash expose identical public APIs. Useful as a cache key or quick compatibility check.

**Generate with:** `soroban-upgrade-safeguard extract <WASM> --hash-only`

**See also:** [Inspecting a single build](../README.md#inspecting-a-single-build)

### Lockfile
A committed JSON snapshot of a contract's exported interface. CI validates that candidate builds match the lockfile, preventing accidental interface changes. Update the lockfile with `--force` when interface changes are intentional.

**Generate with:** `soroban-upgrade-safeguard lockfile <WASM> --output contract.interface.lock.json`

**See also:** [Pinning an interface with a lockfile](../README.md#pinning-an-interface-with-a-lockfile)

### Attestation
A signed, versioned in-toto statement — wrapped in a DSSE envelope — that
cryptographically binds an analysis run to its inputs and verdict. It
records the tool version, the old and new WASM and extracted-spec digests,
storage schema digests, resolved policy, the report digest, and both
directional call-ABI verdicts, so a report's provenance can be verified
offline by someone who received the envelope, the public key, and the
artifacts, but didn't run the comparison themselves.

**Generate with:**
```bash
soroban-upgrade-safeguard attest report.json \
  --old-wasm old.wasm --new-wasm new.wasm \
  --private-key signing-key.pk8 --key-id release-key \
  --output report.dsse.json
```

**Verify with:**
```bash
soroban-upgrade-safeguard verify-attestation report.dsse.json \
  --trusted-key release-key=public-key.raw \
  --report report.json --old-wasm old.wasm --new-wasm new.wasm
```

**See also:** [Signed safeguard attestations](attestations.md)

### Impact Graph
A versioned, machine-readable node and edge graph of a comparison's functions, types, storage declarations, events, findings, and suppression policy decisions, linked by dependency, cascade, and reference edges. It is embedded in the JSON report as `impact_graph` so reviewers and release tooling can consume it directly instead of parsing report text.

**Use with:** `soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> --impact-graph --format json`

**See also:** [Impact Graph Export](impact-graph.md)

## Historical Tracking

### Lineage
A persistent ledger of all historical contract versions. Lineage tracking validates a candidate against every past version still marked "live," not just the immediate predecessor, catching breaks in data written by old releases.

**Configuration:** `--lineage-store <PATH>` points to the lineage JSON file

**See also:** [Lineage Tracking Walkthrough](lineage-walkthrough.md)

### Live Version
A historical contract version in the lineage that is still active and must be compatible with new candidates. Versions can be retired when they're no longer deployed.

### Retired Version
A historical version removed from active lineage validation. Retired versions are kept in the lineage file for audit trails but don't block new deployments.

## Validation Modes

### Structural Analysis
The default validation mode that compares the declared types and interfaces in contract specs. Structural analysis checks if shapes and signatures are compatible without needing actual storage data.

**Limitation:** Cannot validate internal types not exposed in the contract spec.

**See also:** [What a Passing Verdict Guarantees](documentation.md#what-a-passing-verdict-guarantees)

### Decoder Registry
The registry that selects a build's contract-spec decoder using the interface version recorded in its `contractenvmetav0` WASM custom section.

**Use with:** `soroban-upgrade-safeguard extract <WASM>`

**See also:** [Protocol-Versioned Contract-Spec Decoder Registry](decoder_registry.md)

### Empirical Validation
Advanced validation mode that decodes real ledger storage entries against the new contract spec. This catches breaks in actual deployed data that structural analysis might miss.

**Enable with:** `--empirical-file <JSON>`

**See also:** [Empirical Storage Validation Mode](empirical_validation.md)

### Storage Schema
An optional declaration of internal storage types that don't appear in the exported spec. Providing a storage schema closes the gap in structural analysis by validating persistence layer types.

**Format:** JSON or TOML file declaring storage keys and value types

**See also:** [Storage Schema Cookbook](storage-schema-cookbook.md)

## Special Markings

### Contradicted Finding
A structural break flagged by analysis, but empirical validation found that all sampled real storage data still decodes successfully. Marked `[CONTRADICTED]` in reports.

**Interpretation:** The change looks breaking structurally but hasn't actually broken deployed data (yet).

### Unconfirmed Finding
A structural break flagged by analysis, but no matching storage data was found in the empirical sample to test. Status is unknown for actual deployed data.

## Input Sources

### Batch Manifest
A TOML or JSON file that lists the baseline and candidate contract pairs one run compares.

**Use with:** `soroban-upgrade-safeguard --manifest release.toml`

**See also:** [Batch Manifests](batch_manifests.md)

### RPC Baseline
A baseline contract fetched directly from the network using `--contract-id` and `--rpc-url`. The tool retrieves and hash-verifies the on-chain WASM before comparison.

**See also:** [Choosing an Input Source](choosing-an-input-source.md)

### Digest-Pinned URL
An HTTPS URL with a mandatory `#sha256=<hex>` fragment that specifies the expected content hash. The tool verifies downloaded bytes match the digest before using them.

**Example:** `https://cdn.example.com/contract.wasm#sha256=3b1a2c9e...`

**See also:** [Remote HTTPS Inputs](remote-https-inputs.md)

### Metadata Cache
A content-addressed on-disk cache of the decoded contract model for a WASM build, keyed by the WASM's SHA-256 hash, the tool version, and the settings that affect decoding. A hit skips re-parsing the WASM, which speeds up repeated CI and watch runs. Findings, suppression decisions, and verdicts are never cached, and any key mismatch is a miss rather than a stale hit.

**Use with:** `soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM> --metadata-cache-dir <DIR>` (also `--no-metadata-cache` and `--clear-metadata-cache`)

**See also:** [Content-Addressed Metadata Cache](metadata_cache.md)

## Related Resources

- [Finding Category Reference](finding-categories.md) — Complete list of all finding categories
- [Documentation](documentation.md) — Full explanation of analysis and concepts
- [Suppression Security Policy](suppression_security_policy.md) — Best practices for suppression rules
- [Multi-Axis Compatibility](multi_axis_compatibility.md) — Deep dive into axes and policies

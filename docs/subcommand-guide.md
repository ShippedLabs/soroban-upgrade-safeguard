# Which Subcommand Do I Want?

`soroban-upgrade-safeguard` has many subcommands. This guide maps common goals to the right one. All flags mentioned here are described in `--help` for the relevant subcommand.

## Goal → subcommand

| I want to… | Use |
|------------|-----|
| Check whether upgrading a contract from one build to another is safe | Default comparison: `soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>` |
| Check a candidate build against the contract currently deployed on-chain | Default comparison with `--contract-id` and `--rpc-url` |
| Fail CI only on Critical findings (default) or on Warnings too | Default comparison; add `--strict` to also gate on Warnings |
| See a remediation hint alongside each finding | Add `--explain` to any comparison run |
| Inspect a single build's exported interface without comparing it to another | [`extract`](#extract) |
| Get the interface hash of a single build for scripting or cache keys | `extract <WASM> --hash-only` |
| Pin a contract's public interface and make CI fail if it drifts | [`lockfile`](#lockfile) |
| Re-render a saved JSON report as text or Markdown | [`render`](#render) |
| Migrate a saved JSON report to the latest schema | [`upgrade-report`](#upgrade-report) |
| Generate a `.safeguard.toml` suppression config from the current findings | [`init`](#init) |
| Sign a report as an in-toto attestation for supply-chain auditability | [`attest`](#attest) |
| Verify a signed attestation and every artifact it references, offline | [`verify-attestation`](#verify-attestation) |
| Process many comparison jobs from stdin in a streaming pipeline | [`stream`](#stream) |
| Check whether a single contract spec is structurally well-formed | [`lint`](#lint) |
| Verify RPC connectivity and the JSON-RPC response format | [`preflight`](#preflight) |
| List every finding category with severity, trigger, and remediation | [`categories`](#categories) |
| Compare all contracts in two directories at once | `--old-dir` / `--new-dir` (no subcommand) |
| Compare many named contract pairs in one run | `--manifest` (no subcommand) |
| Re-run the comparison automatically whenever a WASM file changes | Add `--watch` to any comparison run |

---

## Subcommand details

### `extract`

Prints one build's decoded interface as JSON. Use it to inspect a WASM or archive its interface without separate Stellar tooling. `--hash-only` prints only the stable interface hash, suitable for scripting and cache keys.

```bash
soroban-upgrade-safeguard extract ./wasm/v1.wasm
soroban-upgrade-safeguard extract ./wasm/v1.wasm --hash-only
```

### `lockfile`

Writes a committed JSON snapshot of one build's exported interface. Commit the file and use it as a CI gate: the comparison fails (with categorized findings) if the candidate's interface drifts from the snapshot. Regenerate with `--force` when a change is intentional.

```bash
soroban-upgrade-safeguard lockfile ./wasm/v1.wasm --output ./wasm/contract.interface.lock.json
soroban-upgrade-safeguard ./wasm/candidate.wasm --interface-lockfile ./wasm/contract.interface.lock.json
```

See [Pinning an interface with a lockfile](../README.md#pinning-an-interface-with-a-lockfile).

### `render`

Turns a saved JSON report back into human-readable text or Markdown, without the original WASM files. Accepts a path or `-` for stdin.

```bash
soroban-upgrade-safeguard render report.json --format markdown
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --format json | soroban-upgrade-safeguard render - --format text
```

### `upgrade-report`

Migrates a saved JSON report to the latest schema version. Use it to make older stored reports compatible with the current `render` subcommand.

```bash
soroban-upgrade-safeguard upgrade-report old-report.json --output migrated-report.json
```

See [Report Migrations](report_migrations.md).

### `init`

Generates a `.safeguard.toml` suppression config from the findings a comparison currently produces. Every finding becomes a commented-out `[[suppress]]` block; rules are inactive until you review, fill in a `reason`, and uncomment them. Use `--force` to regenerate the file after resolving some breaks.

```bash
soroban-upgrade-safeguard init ./wasm/v1.wasm ./wasm/v2.wasm
```

See [Suppressing known breaking changes](../README.md#suppressing-known-breaking-changes).

### `attest`

Creates a signed DSSE in-toto attestation that binds a saved report, the input WASMs, resolved policy, and the tool version into a verifiable bundle. Use it for supply-chain auditability or when a compliance process requires a signed verdict.

```bash
soroban-upgrade-safeguard attest report.json \
  --old-wasm old.wasm --new-wasm new.wasm \
  --private-key signing-key.pk8 --key-id release-key \
  --output report.dsse.json
```

See [Signed Attestations](attestations.md).

### `verify-attestation`

Verifies an attestation produced by `attest`, offline, against a set of trusted public keys. Checks the signature, re-hashes every artifact, and confirms the policy binding. Fails if anything does not match.

```bash
soroban-upgrade-safeguard verify-attestation report.dsse.json \
  --trusted-key release-key=public-key.raw \
  --report report.json --old-wasm old.wasm --new-wasm new.wasm
```

See [Signed Attestations](attestations.md).

### `stream`

Runs in JSON Lines batch mode: reads one comparison job per line on stdin, writes one result per line to stdout. Use it when a build pipeline needs to drive many comparisons programmatically without shelling out once per pair.

```bash
echo '{"old":"v1.wasm","new":"v2.wasm"}' | soroban-upgrade-safeguard stream
```

See `soroban-upgrade-safeguard stream --help` for the input and output schemas.

### `lint`

Validates one contract spec (and, optionally, a declared storage schema) in isolation — "is this artifact well-formed?" — without comparing it to another build. It uses a separate rule namespace and exit-code set from the upgrade-compatibility analysis.

```bash
soroban-upgrade-safeguard lint ./wasm/v1.wasm
soroban-upgrade-safeguard lint ./wasm/v1.wasm --storage-schema schema.json --strict
```

See [Lint Rules Reference](lint_rules_reference.md) for the full rule catalog and exit codes.

### `preflight`

Checks that an RPC endpoint is reachable, responds to a `getNetwork` call, and returns a JSON-RPC 2.0 compliant response — without fetching any contract code. Use it to validate endpoint configuration before a production run.

```bash
soroban-upgrade-safeguard preflight --rpc-url https://soroban-testnet.stellar.org
```

See [RPC Security Checklist](rpc-security-checklist.md).

### `categories`

Lists every finding category the analysis may emit, with its default severity, trigger description, and remediation guidance. `--format json` produces a machine-readable array for scripting. Generated from the same source of truth the comparison uses, so it can never drift.

```bash
soroban-upgrade-safeguard categories
soroban-upgrade-safeguard categories --format json
```

See [Finding Category Reference](finding-categories.md) for the full documented taxonomy.

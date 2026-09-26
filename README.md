# Soroban Upgrade Safeguard 🛡️

![Soroban Upgrade Safeguard Demo](assets/demo.png)

A powerful CLI tool to analyze and validate Soroban smart contract upgrades on the Stellar network. It detects breaking changes in storage layout, function signatures, and event schemas before you deploy.

## Features

- **Storage Layout Protection**: Detects field removals, reorderings, and type changes in structs and enums that would corrupt on-chain data.
- **Function Signature Validation**: Flags changes in function names, parameters, and return types that break integration with existing clients/contracts.
- **Event Schema Analysis**: Heuristically identifies event-related types and ensures their structure remains backwards compatible for indexers.
- **Cascading Break Detection**: Uses dependency graphing to track how a change in a low-level type affects all parent structures.
- **Rich CLI Output**: Beautiful, color-coded reports with actionable severity levels (Critical, Warning, Info).
- **CI/CD Friendly**: Exits with a non-zero code if critical breaking changes are detected.
- **Suppression Config**: Acknowledge known, intentional breaking changes (e.g. a planned migration) in a `.safeguard.toml` so they no longer fail the run — while still listing them in the report.
- **Interface Hash**: A stable, order-independent SHA-256 over the normalised spec. Two builds with the same hash expose the same interface, which makes it a cheap cache key and a direct answer to "did this change the interface?".
- **Spec Extraction**: `extract` dumps a single build's decoded interface as JSON, so you can inspect a WASM or archive its interface without separate Stellar tooling.
- **Interface Lockfiles**: Commit a reviewable interface snapshot and make CI fail when a candidate build drifts from it.
- **Re-renderable Reports**: `render` turns a saved JSON report back into text or Markdown, so a stored verdict can be presented any number of ways without the original WASM files.
- **Multi-Format Output**: Emit the same report as JSON, Markdown, and text simultaneously — each to its own file or stdout — in a single run.
- **Watch Mode**: Continuously monitor input WASM files for changes and automatically re-run the comparison on every build.
- **Lineage Tracking**: Validate a candidate build against every historical version still marked live in a persistent lineage store, not just the immediate predecessor — catching a break in data an older release wrote that the immediate predecessor never touched.
- **Provenance Metadata**: Every report includes the tool version, a timestamp, and input identifiers for full auditability (`--no-timestamp` for deterministic snapshot testing).
- **Signed Attestations**: Bind reports, artifacts, extracted specs, policy, and verdicts in canonical in-toto statements with offline DSSE verification.
- **Finding Category Catalog**: `categories` lists every finding category with its severity, trigger, and remediation — in human-readable text or machine-readable JSON — generated from the same source of truth the analysis uses, so it can never drift.
- **GitHub Action**: Reusable action that posts the Markdown report as a PR comment and updates it in-place on subsequent pushes.

## Installation

```bash
cargo install --path .
```

## Usage

Compare two WASM contract builds to see if the upgrade is safe:

```bash
soroban-upgrade-safeguard <OLD_WASM> <NEW_WASM>
```

### Example

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm
```

### Subcommands

Running the tool with two WASM paths, as in the example above, compares
them. The following subcommands do other jobs. Run
`soroban-upgrade-safeguard <SUBCOMMAND> --help` to see a subcommand's
flags.

| Subcommand | What it does | Details |
|------------|--------------|---------|
| `extract` | Prints one build's decoded interface as JSON, or only its interface hash with `--hash-only` | [Inspecting a single build](#inspecting-a-single-build) |
| `lockfile` | Writes a committed snapshot of one build's exported interface | [Pinning an interface with a lockfile](#pinning-an-interface-with-a-lockfile) |
| `render` | Renders a saved JSON report as text or Markdown | [Re-rendering a saved report](#re-rendering-a-saved-report) |
| `upgrade-report` | Migrates a saved JSON report to the latest schema version | [Report migrations](docs/report_migrations.md) |
| `init` | Generates a `.safeguard.toml` suppression config from the current findings | [Suppressing known breaking changes](#suppressing-known-breaking-changes) |
| `attest` | Creates a signed DSSE in-toto attestation for a saved report | [Signing and verifying reports](#signing-and-verifying-reports) |
| `verify-attestation` | Verifies an attestation and every artifact it references, offline | [Signing and verifying reports](#signing-and-verifying-reports) |
| `stream` | Runs in JSON Lines batch mode: reads one job per line on stdin and writes one result per line to stdout | `stream --help` |
| `lint` | Checks one contract spec, and optionally a storage schema, for structural problems without comparing it to another build | [Lint rules reference](docs/lint_rules_reference.md) |
| `preflight` | Checks RPC connectivity and the JSON-RPC response format without fetching any contract code | [RPC security checklist](docs/rpc-security-checklist.md) |

### Strict mode

By default the command exits `0` unless it finds **Critical** breaking changes
(or a structural error). **Warning** and **Info** findings are reported but do
not affect the exit status:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm
```

Pass `--strict` to also fail the run when **Warning** findings are present.
The exit code is then non-zero if any unsuppressed Warning or Critical findings
are found; **Info** findings never affect it:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --strict
```

A manifest can enable strict mode per pair (`strict = true`), but it cannot
disable `--strict` passed on the command line.

### Remediation guidance

Pass `--explain` to include a concise remediation explanation alongside each
finding. Instead of only describing what changed, the output tells you what to
do about it:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --explain
```

The guidance appears in text, Markdown, and GitHub Actions output — every
format that has a natural place for per-finding detail. It is especially useful
when reading a report for the first time: rather than cross-referencing the
finding categories documentation, the explanation for each issue is right there
in the output. A manifest can also enable it per run (`explain = true`), and
`--explain` passed on the command line cannot be disabled by a manifest.

### ASCII output

Terminals and log viewers that cannot render emoji can use `--ascii` to
replace the marker glyphs with plain-text equivalents:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --ascii
```

Severity markers render as `[CRITICAL]`, `[WARN]`, `[INFO]`, and `[WARNING]`,
and verdict markers as `[PASS]`, `[FAIL]`, and `[SUPPRESSED]`, so the report
stays readable in any log viewer. `--ascii` only swaps the markers — it does
not disable color. Pass `--no-color` to turn color off, or `--plain` for fully
plain output (which implies both `--no-color` and `--ascii` and also strips
the remaining decorative separators).

### Controlling color output

`--color` controls when ANSI color is emitted:

- **`auto`** (default) — color only when stdout is a terminal and `NO_COLOR`
  is not set.
- **`always`** — color even when stdout is piped or redirected, for piping
  into a viewer (e.g. `less -R`, `bat`) that renders ANSI itself.
- **`never`** — never emit color.

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --color always | less -R
```

`--no-color` takes precedence over `--color`: if both are given, output is
uncolored regardless of the `--color` value.

### Comparing against a deployed contract (RPC baseline)

Fetch the baseline directly from an on-chain contract instead of a local file
— `<CONTRACT_ID>` is fetched over RPC, `<NEW_WASM>` is read from disk:

```bash
soroban-upgrade-safeguard \
  --contract-id <CONTRACT_ID> \
  --rpc-url <RPC_URL> \
  <NEW_WASM>
```

For example:

```bash
soroban-upgrade-safeguard \
  --contract-id CABCD1234... \
  --rpc-url https://soroban-testnet.stellar.org \
  ./wasm/v2.wasm
```

See [Zero-Trust RPC Baseline Retrieval](docs/documentation.md#zero-trust-rpc-baseline-retrieval)
for the hash-verification pipeline, transport security rules, and
authenticated-endpoint guidance to use before pointing this at production,
and the [RPC Security Checklist](docs/rpc-security-checklist.md) for an
operational checklist covering endpoint trust, credentials, and report
retention.

#### Authenticating to a private RPC endpoint

If your RPC provider requires an authentication header, use `--rpc-header
NAME=ENV_VAR` to attach it. The flag takes the literal header name and the name
of an environment variable whose value is the secret — the secret is **never
passed on the command line**, only read from the environment at runtime:

```bash
export STELLAR_RPC_TOKEN=my-secret-token

soroban-upgrade-safeguard \
  --contract-id CABCD1234... \
  --rpc-url https://my-private-rpc.example.com \
  --rpc-header "Authorization=STELLAR_RPC_TOKEN" \
  ./wasm/v2.wasm
```

This keeps credentials out of shell history, process listings, and CI logs.
The flag can be repeated to attach multiple headers. The environment variable
must be set when the tool runs; if it is absent, the run fails with an error
that names the missing variable without printing any value.

#### Non-standard JSON-RPC providers

Some RPC providers do not echo the request `id` back in their responses, which
violates the JSON-RPC 2.0 spec. By default the tool rejects such responses to
avoid silently processing an unrelated reply. Pass `--rpc-allow-id-mismatch`
to accept a response whose `id` is missing or does not match the request's:

```bash
soroban-upgrade-safeguard \
  --contract-id CABCD1234... \
  --rpc-url https://non-standard-provider.example.com \
  --rpc-allow-id-mismatch \
  ./wasm/v2.wasm
```

This flag is **off by default**. Only use it when you have confirmed that your
specific provider does not echo request IDs correctly — do not enable it as a
general workaround, since the ID check exists to guard against receiving a
response meant for a different request.

#### Pinning the expected baseline hash

Fetching a baseline over RPC means trusting the endpoint to answer with the
bytes actually deployed. `--expected-wasm-hash` removes that trust: it asserts
the SHA-256 of the on-chain WASM baseline, so the comparison fails if the
fetched — or locally loaded — baseline is not the bytes you expected.

The value is a 64-character hex SHA-256 digest, upper or lower case:

```bash
soroban-upgrade-safeguard \
  --contract-id CABCD1234... \
  --rpc-url https://soroban-testnet.stellar.org \
  --expected-wasm-hash 31fc0a23f04c6fc647ac44ba791228d8f0f12308685f0ac3798d37c79518906b \
  ./wasm/v2.wasm
```

On a mismatch the run **fails immediately with exit code 1, before any
comparison is performed**, and prints both digests so you can see which build
you actually got:

```
Error: Baseline hash mismatch for 'CABCD1234...'
  expected: 0000000000000000000000000000000000000000000000000000000000000000
  actual:   31fc0a23f04c6fc647ac44ba791228d8f0f12308685f0ac3798d37c79518906b
```

Failing before the comparison is deliberate: a report built against an
unverified baseline is exactly what this flag exists to prevent, so no verdict
is emitted at all rather than one that looks authoritative but compares the
candidate to the wrong build.

A value that is not a 64-character hex digest is rejected as a **configuration
error**, worded differently from a mismatch — a wrong flag and a wrong
deployment need to send you to different places.

The flag also works with a local baseline, where it pins which build a
comparison was run against for the audit trail. Note that RPC mode already
verifies the fetched bytecode against the on-chain contract instance hash on
every run; this flag adds the second, independent check that the on-chain build
is the specific one you reviewed.

#### Local RPC endpoints

Without `--allow-http-local`, only `https://` RPC URLs are accepted. Pass it
to allow plain `http://` connections for RPC when the host is `localhost` or
`127.0.0.1` — what a local test validator needs, since it typically has no
TLS certificate:

```bash
soroban-upgrade-safeguard \
  --contract-id CABCD1234... \
  --rpc-url http://localhost:8000/soroban/rpc \
  --allow-http-local \
  ./wasm/v2.wasm
```

It only relaxes the check for a local host: a remote `http://` URL is
rejected whether or not `--allow-http-local` is set.

### Validating against captured storage entries

Structural comparison answers whether the *shapes* the new build declares are
compatible with the old ones. Empirical validation answers a narrower, more
concrete question: does the data that actually exists still decode under the new
spec? Point `--empirical-file` at a JSON file of captured ledger/storage entries
to run that check offline, alongside the normal structural analysis:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --empirical-file ./ledger_snapshot.json
```

The structural findings are still produced in full; the empirical results are
layered onto them. A flagged layout change whose sampled data still decodes is
marked `[CONTRADICTED]` rather than failing the run, while an entry that really
does fail to decode under the new spec fails the run outright, regardless of
`--strict`.

See [Input JSON Format](docs/empirical_validation.md#input-json-format) for the
accepted file shapes, and the
[empirical validation guide](docs/empirical_validation.md) for RPC-based
sampling and the limits of the check.

### Inspecting a single build

```bash
# The full decoded interface as JSON
soroban-upgrade-safeguard extract ./wasm/v1.wasm

# Just the interface hash, for scripting and cache keys
soroban-upgrade-safeguard extract ./wasm/v1.wasm --hash-only
```

### Pinning an interface with a lockfile

Generate a lockfile from the build whose public interface you intend to protect:

```bash
soroban-upgrade-safeguard lockfile ./wasm/v1.wasm \
  --output ./wasm/contract.interface.lock.json
```

Commit the resulting JSON file. It contains the interface hash and the structured
functions and user-defined types, with stable ordering and without build-specific
paths. When an interface change is intentional, regenerate it with `--force` and
review the lockfile diff as part of the same change:

```bash
soroban-upgrade-safeguard lockfile ./wasm/v2.wasm \
  --output ./wasm/contract.interface.lock.json --force
```

Use the committed lockfile as a CI gate for a candidate build:

```bash
soroban-upgrade-safeguard ./wasm/candidate.wasm \
  --interface-lockfile ./wasm/contract.interface.lock.json \
  --format json
```

The command exits successfully when the exported interface matches. A drift exits
non-zero and reports the same categorized findings as a normal two-build comparison.
Lockfile checks cover the exported interface only; use the regular comparison mode
for environment metadata, host imports, runtime surface, storage schemas, or
empirical validation.

### Re-rendering a saved report

`render` accepts either a saved JSON report path or `-` to read the JSON from
stdin, and prints it as `text` (the default) or `markdown` — `json` is not a
render target, since re-rendering a saved JSON document as JSON would just be
a copy.

```bash
# From a saved file
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --format json > report.json
soroban-upgrade-safeguard render report.json --format markdown

# From stdin, piped straight from a comparison run
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --format json \
  | soroban-upgrade-safeguard render - --format text
```

### Upgrading a saved report

`upgrade-report` migrates a saved JSON report to the latest schema version, so
an older stored report stays consumable as the format evolves. Running it on a
report already at the latest version is safe — the document is re-emitted
unchanged with no modifications:

```bash
soroban-upgrade-safeguard upgrade-report report.json

# Write the upgraded report to a file instead of stdout
soroban-upgrade-safeguard upgrade-report report.json --output report-upgraded.json

# Read from stdin, write to stdout — useful in pipelines
soroban-upgrade-safeguard upgrade-report -
```

The command prints a migration summary to stderr: either how many schema steps
were applied, or a note that the report was already at the latest version. The
exit code is non-zero only if the input cannot be parsed at all.

See [Report Schema Compatibility](docs/report_schema_compatibility.md) for the
schema version history and the compatibility policy that governs what each
version is allowed to change.

### Signing and verifying reports

```bash
soroban-upgrade-safeguard attest report.json \
  --old-wasm old.wasm --new-wasm new.wasm \
  --private-key signing-key.pk8 --key-id release-key \
  --output report.dsse.json

soroban-upgrade-safeguard verify-attestation report.dsse.json \
  --trusted-key release-key=public-key.raw \
  --report report.json --old-wasm old.wasm --new-wasm new.wasm
```

See the [attestation guide](docs/attestations.md) for predicate details,
resolved policy binding, offline verification, and key-handling guidance.

Use `-` for one positional WASM to read it from stdin, for example when a build
artifact is piped from another command:

```bash
cat ./wasm/v2.wasm | soroban-upgrade-safeguard ./wasm/v1.wasm -
```

Only one positional input may be `-`; using `-` for both `OLD_WASM` and
`NEW_WASM` is rejected because stdin can only be consumed once.

### Validating a single contract spec (lint)

`lint` validates one contract spec, and optionally a storage schema, for graph
and schema integrity — independent of any comparison against another build. Use
it to check a single artifact in isolation, for example to catch structural
problems before including a build in a multi-contract release:

```bash
soroban-upgrade-safeguard lint ./wasm/v1.wasm
```

Pass `--storage-schema` to also validate a declared storage schema alongside the
spec. The schema file may be JSON or TOML, inferred from the extension:

```bash
soroban-upgrade-safeguard lint ./wasm/v1.wasm --storage-schema ./schemas/v1.json
```

Exit codes differ from the comparison command:

- `0`: no findings, or only warning/info findings without `--strict`.
- `2`: at least one error-severity finding (the artifact is structurally
  invalid).
- `3`: only warning/info findings, but `--strict` was passed.

`--format json` or `--format markdown` produces machine-readable output.
`--explain` includes a remediation explanation alongside each finding. See
[Lint Rules Reference](docs/lint_rules_reference.md) for the full set of checks
`lint` runs.

### Listing finding categories

Enumerate every finding category the analysis may emit, with its default
severity, what triggers it, and how to remediate it:

```bash
soroban-upgrade-safeguard categories
```

For scripting and CI, `--format json` prints a machine-readable array, one
object per category (`category`, `severity`, `trigger_description`,
`remediation`):

```bash
soroban-upgrade-safeguard categories --format json
```

Both formats are generated from the same source of truth the comparison
analysis uses, so the listing can never drift from the categories the tool
actually emits. See [docs/finding-categories.md](docs/finding-categories.md) for
the full documented taxonomy.

### Checking RPC connectivity (preflight)

`preflight` validates RPC connectivity and the JSON-RPC response format without
fetching any contract code. Use it to diagnose an endpoint before a real run,
confirm authentication headers work, or verify that a provider echoes request
IDs correctly — none of which require a contract ID:

```bash
soroban-upgrade-safeguard preflight --rpc-url https://soroban-testnet.stellar.org
```

The check confirms three things in sequence:

- **Transport**: the endpoint responds to an HTTP request (status code reported).
- **Protocol**: the response is valid JSON-RPC 2.0 with a matching request `id`.
- **Capability**: a lightweight probe method (`getLatestLedger`) succeeds and
  returns the latest ledger sequence number.

No contract code is fetched during a preflight check. A passing result confirms
endpoint connectivity only — it does not verify that any specific contract or
network is compatible with your build. See
[RPC Security Checklist](docs/rpc-security-checklist.md) for the operational
checklist covering endpoint trust, credentials, and report retention.

`--format json` emits a machine-readable summary of the three checks. The
command exits non-zero when any check fails.

### Symlinked inputs

By default a symlinked WASM input is **followed** — through however many hops
the chain has — and the resolved target is recorded in the report's provenance,
so a verdict can always be traced to the bytes it actually judged:

```
Symlink:  ./wasm/current.wasm -> /builds/2024-06-11/token.wasm
```

The same pair appears in Markdown, and in JSON as `provenance.symlinks[]` with
`requested` and `resolved` entries. This matters because a path like
`./wasm/current.wasm` can point at a different build tomorrow; without the
resolved target, two reports that name the same input could describe different
bytecode with nothing to tell them apart.

`--no-symlinks` rejects such an input instead of following it, for pipelines
where an input must be a direct file:

```bash
soroban-upgrade-safeguard ./wasm/current.wasm ./wasm/v2.wasm --no-symlinks
```

```
Error: Symlink input rejected by policy: './wasm/current.wasm' resolves to
'/builds/2024-06-11/token.wasm'. Pass a direct file, or drop --no-symlinks to
allow symlinked inputs.
```

The rejection names the resolved target as well as the link, so a failure tells
you what would have been analyzed rather than only that something was refused.
It exits non-zero without comparing anything.

Two limits are worth knowing:

- The check applies to the **final component** of the path, including a chain of
  several links. A symlinked *parent directory* is not rejected, so
  `--no-symlinks` is not a guarantee that no part of the path traversed a link.
- It applies only to local paths. Reading from stdin (`-`), an RPC baseline, an
  `https://` reference, or an `oci://` reference has no symlink to resolve, and
  the flag has no effect on them.

A broken link or a symlink cycle is always an error, named as such, whether or
not `--no-symlinks` is in effect.

Because a resolved target is absolute, it can reveal a username or workspace
layout. Pass `--redact-paths` when a report is published somewhere the local
filesystem layout should not be exposed:

```bash
soroban-upgrade-safeguard ./wasm/current.wasm ./wasm/v2.wasm --redact-paths
```

It replaces local filesystem paths in report provenance — currently, resolved
symlink targets — with a stable, non-identifying label. Interface hashes,
contract IDs, and RPC endpoints are already sanitized and are unaffected by
this flag.

### Fetching inputs over HTTPS

You can pass an `https://` URL anywhere the tool accepts a local WASM or
spec path. This includes the positional WASM arguments,
`--old-storage-schema` / `--new-storage-schema`, and manifest
`pairs.old` / `pairs.new`. Each URL must end with the expected
`#sha256=<hex>` digest. A URL without one is rejected before any request is
made:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm \
  "https://releases.example.com/v2/contract.wasm#sha256=3b1a2c9e..."
```

Every fetch is limited in size, time, and number of redirects. The
following flags control these limits:

| Flag | Default | What it limits |
|------|---------|----------------|
| `--remote-max-bytes <BYTES>` | `67108864` (64 MiB) | Size of the response body. The body is read only up to this limit, whatever `Content-Length` says, and a larger artifact fails the run. |
| `--remote-timeout-secs <SECONDS>` | `30` | Total time for a single request. |
| `--remote-max-redirects <COUNT>` | `5` | Number of redirects followed before the fetch fails. `0` means no redirects are followed. |

The limits apply to every `https://` input in the run, and each input is
limited separately. For example, you might raise the size limit for an
unusually large artifact, and allow no redirects when the URL points
straight at object storage:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm \
  "https://releases.example.com/v2/contract.wasm#sha256=3b1a2c9e..." \
  --remote-max-bytes 134217728 \
  --remote-timeout-secs 60 \
  --remote-max-redirects 0
```

Verified downloads are cached by digest, so the limits apply only when an
artifact is actually downloaded. A cache hit skips the network entirely. To
make every run download again, pass `--no-remote-cache`.
`--show-config` prints the limits that are in effect, under `remote_fetch.*`,
with `default` or `cli` next to each value to show where it came from. The
following protections can't be turned off with any flag: every redirect
must stay on `https://`, and `Authorization` and `Cookie` headers are never
sent to a redirect target.

See [Remote HTTPS Inputs](docs/remote-https-inputs.md) for the digest
format, caching, and error messages.

### Validating against historical versions (lineage tracking)

A two-build comparison only ever checks a candidate against its immediate
predecessor. That misses a real failure mode: a contract that accumulates
deployed versions over time can have storage entries written by an *old*
release (`v1.0.0`) that no intermediate release ever touched again. If a
later candidate (`v4.0.0`) changes or removes a type `v1.0.0` wrote but
`v3.0.0` never read, comparing only `v3.0.0` vs `v4.0.0` reports a clean
pass — and the old entries fail to decode on-chain the moment something
finally reads them.

`--lineage-store <PATH>` points at a persistent JSON/TOML ledger of a
contract's historical versions. When it's given, the candidate build is
validated against **every version in the store still marked live**, not just
the `<OLD_WASM>` you passed on the command line — each historical mismatch is
reported as its own `Historical Lineage Break (<version_id>)` finding,
attributed to the version whose data it would break:

```bash
soroban-upgrade-safeguard ./wasm/v3.wasm ./wasm/v4.wasm \
  --lineage-store ./lineage.json
```

If the path doesn't exist yet, the run starts from an empty in-memory ledger
instead of failing — you don't need to hand-write one to get started. Nothing
is written to disk from `--lineage-store` alone, though; see
[Recording a version](#recording-a-version) below for how entries actually get
persisted into the file.

#### Capping the live-version window

`--max-live-versions <N>` limits validation to the `N` most recently recorded
live versions, ordered by when they were added to the store. Use it when a
contract has accumulated a long history but only the recent tail still matters
for on-chain compatibility, to bound the validation cost without retiring older
entries:

```bash
soroban-upgrade-safeguard ./wasm/v3.wasm ./wasm/v4.wasm \
  --lineage-store ./lineage.json \
  --max-live-versions 5
```

Versions beyond the cap are excluded from that run's lineage check only —
`--max-live-versions` does not remove or retire anything from the store. Already
retired versions do not count toward the cap: the limit applies exclusively to
live entries, so retiring several old versions first has the same effect as
lowering `--max-live-versions` by that amount.

See [Persistent Compatibility Lineage Ledger](docs/lineage_model.md) for the
full ledger file format and fields, and the
[Lineage Tracking Walkthrough](docs/lineage-walkthrough.md) for a worked
example that uses all four lineage flags across several releases.

#### Recording a version

`--record-version <VERSION_ID>` records the candidate (`<NEW_WASM>`) as a new
entry in the lineage store once the run finishes — its own wasm hash,
interface hash, and full spec JSON, tagged with the ID you give it and marked
`Live`. This is how a lineage builds up over time: run it once per release you
ship, and later candidates get validated against everything you've recorded
so far.

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --lineage-store ./lineage.json \
  --record-version v2.0.0
```

`--record-version` requires `--lineage-store` — without it, the flag is
accepted but has nothing to write to, so it's a silent no-op. Recording
happens **after** the comparison completes and is not gated on the verdict:
a candidate that fails the comparison is still recorded if you asked for it,
so a rejected build doesn't silently vanish from the history the next
candidate gets checked against. Each `<VERSION_ID>` can be recorded only
once. Currently, re-using an ID that is already in the store fails the run
with an `invalid order 0` integrity error and leaves the file unchanged. To
amend an existing entry, edit the store directly.

#### Retiring a version

`--retire-version <VERSION_ID>` marks an existing entry in the lineage store
as `Retired`, so later candidates stop being validated against it. Use it
once you're confident nothing on-chain still depends on the data shape a
given historical version wrote — a version you've since migrated away from,
or one you know was never deployed widely enough to matter:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --lineage-store ./lineage.json \
  --retire-version v1.0.0
```

Like `--record-version`, it requires `--lineage-store` and is otherwise a
silent no-op — and retiring a `<VERSION_ID>` that isn't in the store is *also*
a silent no-op rather than an error, so a typo won't fail your run but won't
retire anything either. Retiring happens **before** validation, so the
version is already excluded from that same run's lineage check.

**`--retire-version` on its own does not persist.** The store is only
written back to `--lineage-store`'s path when `--record-version` is also
given — so `--retire-version` alone updates the in-memory ledger for this
run's validation but leaves the file on disk untouched, and the retirement
won't apply to the *next* run either. To make a retirement durable, pair it
with `--record-version` in the same invocation, usually when you record the
next release:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --lineage-store ./lineage.json \
  --retire-version v1.0.0 \
  --record-version v2.0.0
```

### Suppressing known breaking changes

If a breaking change is deliberate and already accounted for, list it in a
`.safeguard.toml` so it no longer fails the run. Matching is exact (by
`category` and `target`), and suppressed findings are still shown in the report,
marked `[SUPPRESSED]`:

```toml
[[suppress]]
category = "Struct Field Removed"
target   = "ConfigData.threshold"
reason   = "Planned storage migration in v2."
```

The tool auto-loads `.safeguard.toml` from the current directory, or use
`--config <PATH>` to point at another file. See
[`.safeguard.example.toml`](.safeguard.example.toml) for a documented template
and the [documentation](docs/documentation.md#suppressing-known-breaking-changes)
for the full `target` convention.

#### Generating a starting config with `init`

Rather than writing suppression rules by hand, `init` generates a `.safeguard.toml`
from the findings a comparison currently produces:

```bash
soroban-upgrade-safeguard init ./wasm/v1.wasm ./wasm/v2.wasm
```

Every finding becomes a commented-out `[[suppress]]` block. The generated rules
are **inactive by default** — they have no effect until you review each one,
add a `reason`, and remove the leading `#`:

```toml
# Auto-generated suppression config
# This file was generated by `soroban-upgrade-safeguard init`.
# Each suppression entry requires a reason to be filled in.
# Remove the '#' to uncomment and activate each suppression.

# Suppressions are commented out by default. Edit this file and
# remove the '#' before each [[suppress]] block you want to apply.

# [[suppress]]
# category = "Struct Field Removed"
# target   = "ConfigData.threshold"
# reason   = "TODO: Add justification for suppressing this rule."
```

Once you have reviewed an entry and filled in a reason, activate it:

```toml
[[suppress]]
category = "Struct Field Removed"
target   = "ConfigData.threshold"
reason   = "Planned storage migration in v2; old data backfilled on read."
```

If `.safeguard.toml` already exists, `init` refuses to overwrite it. Pass
`--force` when you intentionally want to regenerate it from a fresh set of
findings — for example, after resolving some breaks and wanting to reset the
baseline:

```bash
soroban-upgrade-safeguard init ./wasm/v1.wasm ./wasm/v2.wasm --force
```

The `--force` flag only controls overwrite behavior; it does not bypass the
`reason` requirement. Every rule you uncomment must still carry a non-blank
`reason` before it is valid, and the tool will reject the config on the next run
if any activated rule is missing one.

`init` is a starting point, not a blanket acknowledgement. Leaving a rule
commented out means it has not been reviewed; activating one without a reason is
a hard error. The goal is a config where every active entry represents a
deliberate, understood decision.

##### Suppression init workflow

The typical workflow for turning raw findings into reviewed suppressions:

**Step 1 — Generate the file**

```bash
soroban-upgrade-safeguard init ./wasm/v1.wasm ./wasm/v2.wasm
```

This creates `.safeguard.toml` with one commented-out block per finding. The
file is safe to commit at this point: all rules are inactive and have no effect
on the comparison verdict.

**Step 2 — Review each entry**

Open `.safeguard.toml` and read every `# [[suppress]]` block carefully. For
each one, decide whether the break is deliberate and fully understood. Only
uncomment a rule you are prepared to justify.

**Step 3 — Supply a reason and activate**

Remove the leading `#` from a block and fill in the `reason` field:

```toml
[[suppress]]
category = "Struct Field Removed"
target   = "ConfigData.threshold"
reason   = "Planned storage migration in v2; old entries backfilled on first read."
```

Leave blocks you are not ready to justify commented out — an entry with `# [[suppress]]`
does nothing and will not cause errors.

**Step 4 — Verify the config loads**

Re-run the comparison to confirm the activated rules are accepted:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm
```

Any uncommented block that is still missing a `reason` is rejected as a hard
error before the comparison runs. Fix or re-comment those entries and re-run.

**Regenerating after resolving some breaks**

Once you have addressed some findings and want a fresh starting file that
reflects only the remaining breaks, use `--force`:

```bash
soroban-upgrade-safeguard init ./wasm/v1.wasm ./wasm/v2.wasm --force
```

`--force` overwrites the existing `.safeguard.toml`. It does not activate any
rules or bypass the reason requirement — it only controls whether the file may
be replaced. Carry any active rules you still need over from the old file
manually before committing.

#### Ignoring configuration entirely

Config is discovered automatically, from several places in turn: `--config`,
then the `SOROBAN_SAFEGUARD_CONFIG` environment variable, then a
`.safeguard.toml` in the current directory, then — with `--search-parent-config`
— an ancestor directory. In batch mode a manifest may name one too.

`--no-config` turns all of that off and runs with no suppressions at all. It is
an escape hatch, not another layer in the chain: it outranks every source above,
the manifest included, so nothing in the environment or the working tree can
quietly re-enable a suppression.

```bash
# Judge the upgrade on the tool's own rules, ignoring any ambient .safeguard.toml
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --no-config
```

That makes it the flag to reach for when a run has to be reproducible or
self-contained — verifying what a report would look like with nothing
acknowledged, reproducing a CI result on a developer machine that has its own
`.safeguard.toml`, or auditing whether a gate passes on its merits rather than
on its suppressions.

`--no-config` and `--config <PATH>` are **mutually exclusive**: passing both is
rejected as a command-line error rather than resolved by precedence, since one
asks for a specific config and the other for none, and guessing which was meant
is exactly the wrong behavior for a safety gate. `--search-parent-config` is
rejected alongside `--no-config` for the same reason. To run against a known
config instead of the ambient one, pass `--config <PATH>` on its own.

#### Seeing what actually resolved

With config arriving from flags, environment variables, a config file, and — in
batch mode — a manifest, "which layer won?" stops being obvious. `--show-config`
answers it directly: it prints the fully resolved configuration with the origin
of every value, then **exits without analyzing any WASM inputs**. No positional
arguments are needed, and nothing is loaded, parsed, or compared.

```bash
soroban-upgrade-safeguard --show-config
```

Each line is a dotted path, the resolved value, and the layer that decided it:

```
config_file = .safeguard.toml  (auto-discovered .safeguard.toml)
input.expected_wasm_hash = <none>  (default)
input.no_symlinks = false  (default)
batch.max_pairs = 500  (default)
output.format = text  (default)
output.strict = true  (cli)
output.no_color = true  (env (NO_COLOR))
suppression_policy.max_suppressions = 10  (config file)
```

The source label is the whole point: `cli`, `env (VAR_NAME)`, `config file`, or
`default`. A value you expected to come from your `.safeguard.toml` showing up as
`(default)` is the fastest way to catch a config that never loaded, a mistyped
key, or a flag quietly overriding the file.

**Secrets are never printed.** RPC header values are not even resolved during
`--show-config` — only the name of the environment variable that would supply
them at run time, with the value shown as `<redacted>`:

```
input.rpc_headers[0].name = Authorization  (cli)
input.rpc_headers[0].value_from_env = STELLAR_RPC_TOKEN  (cli)
input.rpc_headers[0].value = <redacted>  (cli)
```

That makes the output safe to redirect into a CI log or paste into a bug report.

`--format json` produces the same data machine-readable, as a nested tree whose
leaves are `{"value": ..., "source": ...}` objects — useful for asserting on
resolved config in CI, or diffing what two environments actually resolve:

```bash
soroban-upgrade-safeguard --show-config --format json > resolved-config.json
```

Any other `--format` prints the text listing above.

#### Validating a config without any WASM inputs

While editing or authoring a `.safeguard.toml`, you often want to know whether
the file is structurally valid without running a full comparison. `--validate-config`
does exactly that: it parses and validates the suppression config at the given
path, reports any errors, and then exits — no WASM inputs are needed or loaded.

```bash
soroban-upgrade-safeguard --validate-config .safeguard.toml
```

This is the flag to reach for while iterating on suppression rules: it gives
immediate feedback on syntax mistakes, unknown fields, or malformed `target`
patterns before you point the tool at real WASM files.

### Output format

By default, and whenever `--format` is omitted, the report prints as
colored, human-readable **text**. Select another format explicitly with
`--format`:

```bash
# JSON, for scripting and CI
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --format json

# Markdown, for PR descriptions and comments
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --format markdown
```

#### Accepted format names

Format names are case-insensitive, so `JSON`, `Json`, and `json` are all
accepted. Some formats also have a short alias. Aliases are accepted only
in the `FORMAT` part of an [`--output`](#multiple-output-formats) spec,
such as `md:report.md`, not as a `--format` value:

| Format | `--format` value | Alias in `--output` | Output |
|--------|------------------|---------------------|--------|
| Text (default) | `text` | — | Colored, human-readable report |
| JSON | `json` | — | One machine-readable JSON document |
| Markdown | `markdown` | `md` | Markdown for PR descriptions and comments |
| GitHub Actions | `github-actions` | `gha` | GitHub Actions workflow annotations |

```bash
# Equivalent: long name with --format, alias in an --output spec
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --format markdown
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --output md

# Rejected: --format does not accept aliases
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --format md
```

An unknown name is rejected, and the error lists the supported values.
Subcommands that take `--format` use the same case-insensitive matching and
also accept no aliases. Some of them accept fewer formats:

| Subcommand | `--format` values | Default |
|------------|-------------------|---------|
| `render` | `text`, `markdown` | `text` |
| `lint` | `text`, `json`, `markdown` | `text` |
| `preflight` | `text`, `json`, `markdown`, `github-actions` | `text` |

### Wrapping text output

Finding messages in **text** output word-wrap to fit the terminal. `--width
<COLUMNS>` overrides that detection with a fixed column count, useful when
producing a text report for a fixed-width medium:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --width 100
```

Without `--width`, wrapping is detected only when stdout is a terminal: the
`COLUMNS` environment variable if set and valid, else 80 columns. Piped or
redirected output is left unwrapped unless `--width` is given explicitly.
`--width` never affects JSON or Markdown output, which have no line-width
concept.

### Multiple output formats

`--output` accepts a `FORMAT:PATH` specification or a bare path, and can be
repeated to write several destinations in a single run:

- **`FORMAT:PATH`** (e.g. `json:report.json`) writes that format to that
  file, regardless of `--format`.
- **A bare path** (e.g. `report.md`) writes to that file using the format
  selected by `--format`, or **text** (the default) if `--format` is omitted.

```bash
# Write JSON to a file, Markdown to another, and print text to stdout
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --output json:report.json \
  --output markdown:report.md

# A bare path resolves its format from --format: this writes Markdown to report.md
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --format markdown \
  --output report.md

# Write to stdout only (default)
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm

# Explicit stdout format with file output
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --format text \
  --output json:ci-report.json
```

### Quiet output

`--quiet` suppresses everything the tool narrates *about* the run: the banner and
separator lines, the per-file loading and spec-summary lines, config-discovery
notes, batch pair headers, and the `report written to <path>` confirmations.

It does not remove anything from the report. Every format you selected is still
produced in full, with the same findings, to the same destination. The verdict
and the exit code are also unchanged — `--quiet` only decides what gets narrated,
never what gets analyzed, reported, or gated on.

```bash
# CI: only the JSON report reaches the log, with no surrounding progress text
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --format json --quiet

# Still exits non-zero on breaking changes, so this remains a working gate
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --quiet --output json:report.json || echo "upgrade rejected"
```

Note that progress output already avoids stdout whenever stdout carries a
machine-readable report — with `--format json` it is written to stderr instead.
`--quiet` goes further and silences it on both streams, which is what you want
when a CI log should contain the report and nothing else.

### Watch mode

Re-run the comparison automatically when input files change:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --watch
```

Watch mode:
- Monitors both WASM files for changes using filesystem notifications.
- Debounces rapid writes (e.g. from build tools) with a 300ms window by default.
- Clears the terminal screen and re-renders the report on each change.
- Handles transient missing files gracefully (e.g. build tools that delete and recreate).
- Keeps the process running regardless of comparison verdict (non-zero exit codes do NOT exit the watcher).
- Exit with `Ctrl+C`.

#### Tuning the debounce window

A build tool rarely produces one clean filesystem event per build — a
write-to-temp-then-rename, or several passes over an output directory, can
each fire their own notification. The debounce window coalesces a burst of
events for the same underlying change into a single re-run instead of
triggering one per event. `--watch-debounce-ms <MILLISECONDS>` overrides the
300ms default, between a 10ms floor and a 60000ms (60s) ceiling — out-of-range
or non-numeric values are rejected before watch mode starts:

```bash
# A build pipeline that touches the output file several times in quick
# succession: widen the window so those all collapse into one re-run.
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --watch --watch-debounce-ms 750

# A fast, single-write build: tighten it for a snappier turnaround.
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm --watch --watch-debounce-ms 50
```

Too low and a single logical change can trigger several re-runs before the
build finishes writing; too high and watch mode feels unresponsive to a
genuine edit. The flag applies to every form of watch mode — a single pair, a
directory comparison, or a batch manifest.

Watch mode also works at repository scale, for both directory comparisons and
batch manifests. In that case it builds an input dependency graph instead of
re-running the whole batch on every write:

```bash
# watch a whole directory comparison
soroban-upgrade-safeguard --old-dir ./artifacts/v1 --new-dir ./artifacts/v2 --watch

# watch a batch manifest (TOML or JSON, `include` chain included)
soroban-upgrade-safeguard --manifest release.toml --watch
```

For a batch, every pair's inputs — its two WASM builds, its storage schemas,
its suppression config, and the manifest file(s) that defined it — are tracked.
Filesystem events are normalized and debounced, then mapped to only the pairs
that actually read the touched file. Untouched pairs keep their last known
verdict, and the full, deterministically ordered aggregate report is re-rendered
after each cycle. Specifically:

- A **WASM/schema/config** change re-analyzes exactly the pairs that read it.
- A **manifest edit** re-resolves the composition (pairs may appear, disappear,
  or pick up new settings) and re-analyzes only the pairs whose identity or
  settings changed.
- A **directory scan** change re-derives the pair set: a removed artifact becomes
  a Critical gap, a restored one heals, a newly added pair appears.
- **Atomic replacement** (a build tool writing to a temp file then renaming it
  into place, possibly several times in quick succession) is coalesced into a
  single cycle, and the watch process's own report/status writes are ignored so
  it never reacts to itself.
- A pair that fails to load or analyze is isolated as its own error while every
  unrelated contract retains its result; a transiently missing or mid-edit input
  is reported without terminating the watcher.

Use `--watch-status-file <path>` with any watch mode to have the process write
an atomically-updated JSON status document (state, cycle number, timestamps,
verdict) that an external build system or service manager can poll cheaply.

### Comparing two directories of builds

When the old and new builds of several contracts sit in two directories, compare
them all in one run:

```bash
soroban-upgrade-safeguard --old-dir ./artifacts/v1 --new-dir ./artifacts/v2
```

Pairs are formed by file name: every `.wasm` file in the old directory is
matched with the file of the same name in the new directory, and the file stem
becomes the contract's name in the report.

```text
artifacts/
├── v1/                 ├── v2/
│   ├── token.wasm      │   ├── token.wasm     → pair "token"
│   └── vault.wasm      │   └── vault.wasm     → pair "vault"
```

An old artifact with no file of that name in the new directory is not skipped:
it is reported as a Critical finding under its own name — a contract that
disappeared from a release is exactly the kind of accident this gate exists to
catch — so the run fails. The reverse case, a new artifact with no old
counterpart, has nothing to compare against; it is listed as a warning on stderr
and does not affect the verdict.

### Comparing many contracts at once

A manifest lists the pairs one run compares. The minimal form is one
`[[pairs]]` entry per contract, each naming an old build, a new build, and the
name the pair reports under:

```toml
# release.toml
[[pairs]]
name = "token"
old  = "artifacts/v1/token.wasm"
new  = "artifacts/v2/token.wasm"

[[pairs]]
name = "vault"
old  = "artifacts/v1/vault.wasm"
new  = "artifacts/v2/vault.wasm"
```

```bash
soroban-upgrade-safeguard --manifest release.toml
```

Relative paths resolve against the directory of the manifest that wrote them, not
the working directory, so the file above works from anywhere in the repository.

Beyond that, a manifest can share settings across pairs, pull in other manifests,
and hold a single contract to a stricter bar — see
[Batch Manifests](docs/batch_manifests.md) for the full schema:

```toml
include = ["common/policy.toml"]   # share a policy across manifests

[defaults]
base_dir = "artifacts"             # relative paths resolve against the manifest
strict   = false

[[pairs]]
old    = "token_v1.wasm"
new    = "token_v2.wasm"
name   = "token"
old_storage_schema = "schemas/token_v1.json"
new_storage_schema = "schemas/token_v2.json"
strict = true                      # this one contract is held to a stricter bar

[pairs.policy]
gate_event_indexer = true
```

Settings resolve as `built-in < CLI < included defaults < root [defaults] < pair`,
except `--strict`/`--explain`, which a manifest may enable but never disable.
To see exactly where each value came from without running any comparison:

```bash
soroban-upgrade-safeguard --manifest release.toml --explain-manifest
```

#### Naming each pair

`name` gives a pair a stable identity in the results. It is optional — when
omitted, a pair is identified by the file name of its `new` build, so
`token_v2.wasm` reports as `token_v2.wasm`:

```toml
[[pairs]]
old  = "token_v1.wasm"
new  = "token_v2.wasm"
name = "token"
```

That name is what every batch output keys off:

- the summary line and the `=== Contract: token ===` detail heading in text output;
- the summary table row and the `## Details: token` heading in Markdown;
- the `results[].name` field in JSON;
- the `::group::token` log group in GitHub Actions output;
- the file name written under `--per-contract-output-dir`.

It also identifies a pair that *fails*: a pair whose comparison errors is
reported under its name rather than a path, so the failing entry is
recognisable at a glance. Because identity has to be unambiguous, two pairs
resolving to the same name is a hard error, raised before any comparison runs
and naming both manifests involved — which is the usual reason to set `name`
explicitly, since two teams' `v2.wasm` files would otherwise collide.

For a stable identifier meant for tooling rather than people — one that survives
a name being reworded — use the separate [`id`](docs/batch_manifests.md#pair-ids)
field.

#### Capping how many pairs a manifest may contain

[`--max-pairs <N>`](docs/batch_manifests.md#--max-pairs) bounds the total number
of pairs a composed manifest may contain — every pair from every included file,
summed together. The default is **500**: generous enough for any manifest a
person would compose by hand, including a large monorepo, while still catching a
runaway one.

The check runs as soon as the composition is parsed, **before any WASM is
loaded** for any pair. A bad template loop or a script gone wrong can emit
thousands of pairs, and the failure should be a configuration error naming the
count — not the tool grinding through comparisons until something else gives
out:

```bash
soroban-upgrade-safeguard --manifest release.toml --max-pairs 50
```

```
Manifest composition contains 812 pairs, exceeding the maximum of 500 (--max-pairs).
  root: /repo/release.toml
Raise --max-pairs if this many pairs is intentional, or check for a manifest
generation mistake.
```

The limit **cannot be raised from inside a manifest**. There is no
`[defaults].max_pairs` and no per-pair equivalent, and because the manifest
schema rejects unknown keys, writing one is a hard parse error rather than a
setting that is quietly ignored. The ceiling exists to guard against the
manifest itself going wrong, so the command line is the only place it can be
set — a file cannot raise the limit that is there to bound it.

See [Batch Manifests](docs/batch_manifests.md) for the full schema, includes,
schema coverage rules, path rules, and JSON provenance.

### Deterministic output for snapshot testing

By default, every report includes a timestamp in the provenance metadata for full auditability. Use `--no-timestamp` to suppress only the provenance timestamp, enabling reproducible snapshot tests and deterministic artifact generation:

```bash
soroban-upgrade-safeguard ./wasm/v1.wasm ./wasm/v2.wasm \
  --format json --no-timestamp > report.json
```

This flag omits only the provenance timestamp field from the report metadata. All other timestamp information (such as build timestamps embedded in the WASM itself) remains unchanged. The normal timestamped behavior is the default and should be used for production workflows where auditability is important.

### GitHub Action

A reusable GitHub Action is provided to run the safeguard tool and post
the Markdown report as a pull request comment. It updates the comment
in-place on subsequent pushes.

**Workflow example** (`.github/workflows/safeguard-report.yml`):

```yaml
name: Soroban Upgrade Safety Report

on:
  pull_request:
    paths:
      - 'wasm/**/*.wasm'

jobs:
  safeguard-report:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      - name: Build safeguard
        run: cargo build --release
      - name: Add to PATH
        run: echo "${{ github.workspace }}/target/release" >> "$GITHUB_PATH"
      - name: Run Soroban Upgrade Safeguard
        uses: ./.github/actions/soroban-upgrade-safeguard
        with:
          old-wasm: ./wasm/v1.wasm
          new-wasm: ./wasm/v2.wasm
          token: ${{ secrets.GITHUB_TOKEN }}
          args: --strict --explain
```

The action uses the GitHub CLI (`gh`) to manage comments. It searches for
an existing comment containing the hidden marker
`<!-- soroban-upgrade-safeguard-report -->` and updates it, or creates a new
one if none exists. The action requires `pull-requests: write` permission.

If run on a forked PR without write permissions, the action logs a warning
and exits gracefully — the report is still generated but the comment is not
posted.

## How it Works

The tool parses the `contractspecv0` custom sections from both WASM files, decodes the XDR representations of the contract's interface, and performs a deep structural comparison. It builds a type dependency map to identify when a simple change in a shared struct might cascade into breaking multiple storage entries.

## Severity Levels

- **🔴 CRITICAL**: Breaking changes that WILL cause data corruption, serialization panics, or broken integrations. **Do not deploy.**
- **🟡 WARNING**: Changes that might affect external systems but won't necessarily corrupt local storage (e.g., adding elective parameters if supported).
- **🔵 INFO**: Informational logs about additions or non-breaking modifications.

## Documentation

More detailed guides live in the [docs](docs/) folder:

- [Documentation](docs/documentation.md): full explanation of how the analysis pipeline works, severity levels, cascading layout breaks, and CI integration.
- [Finding Category Reference](docs/finding-categories.md): every category emitted by the tool, with severity, trigger, and remediation guidance — the exact strings to use in suppression rules.
- [Batch Manifests](docs/batch_manifests.md): the manifest schema, composing manifests with `include`, shared `[defaults]`, per-pair overrides, precedence, and resolution provenance.
- [Contributing](docs/contributing.md): development setup, project structure, testing, and how to add new detection rules.
- [Signed Attestations](docs/attestations.md): DSSE signing, the in-toto predicate, offline verification, and security guidance.
- [RPC Security Checklist](docs/rpc-security-checklist.md): operational checklist for endpoint trust, HTTPS, expected-hash pinning, credentials, and report retention when fetching a baseline over RPC.
- [Remote HTTPS Inputs](docs/remote-https-inputs.md): digest-pinned `https://` inputs, fetch limits, caching, and error messages.
- [Storage Schema Cookbook](docs/storage-schema-cookbook.md): worked examples for declaring storage schemas — common key enums, nested values, optional fields, and partial coverage.
- [Lineage Tracking Walkthrough](docs/lineage-walkthrough.md): a worked example of recording historical versions, validating a candidate against them, retiring versions, and capping the number of live versions with `--lineage-store`.
- [Troubleshooting Loader Failures](docs/loader-troubleshooting.md): what to do about malformed WASM, missing custom sections, unsupported formats, and resource-limit rejections.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full text.

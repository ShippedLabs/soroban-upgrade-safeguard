# Signed Policy Bundles

Named local policy profiles (`src/profile.rs`, see
[Named Policy Profiles](named_policy_profiles.md)) are useful within one
repository. An organization running this tool across many repositories may
instead want one centrally governed compatibility policy, resource limits,
and rule documentation, distributed and verified the same way everywhere.
`--policy-bundle` is that: a small, versioned, **signed** document a run
can opt into.

> **Status**: first-pass implementation. Capability-registry overrides and
> resource-limit merging are defined in the format and unit-tested, but not
> yet wired into live WASM parsing or host-import classification; batch
> mode (`--manifest`/`--old-dir`+`--new-dir`) doesn't support
> `--policy-bundle` yet. See [Scope of this pass](#scope-of-this-pass).

## Why this is safe to let a remote source affect a run at all

Three properties work together so that "fetch and apply a document from
an organization-controlled source" doesn't become a new way to weaken a
gate without review:

1. **Opt-in.** Nothing changes unless `--policy-bundle` is passed. There
   is no default bundle, no ambient config file equivalent, no
   environment variable.
2. **Verified before anything is applied.** A bundle that fails
   verification for *any* reason — wrong payload type, non-canonical
   payload, unsupported version, no signature from a trusted key, or an
   expired bundle — is rejected outright. The run aborts before any WASM
   is loaded, with no partial application.
3. **Can only tighten, never loosen.** Even a fully verified bundle
   cannot turn off a gate, remove a require-reason rule, or loosen a
   resource limit the local repository or CLI flags already set. See
   [Precedence](#precedence-a-bundle-can-only-tighten-never-loosen).

## Usage

```bash
soroban-upgrade-safeguard old.wasm new.wasm \
  --policy-bundle https://policy.example.org/baseline.json#sha256=<hex> \
  --trusted-bundle-key org-2026=org-public-key.raw
```

or from a local file:

```bash
soroban-upgrade-safeguard old.wasm new.wasm \
  --policy-bundle ./org-baseline.bundle.json \
  --trusted-bundle-key org-2026=org-public-key.raw
```

`--trusted-bundle-key` is repeatable (`ID=PATH`, PATH containing a raw
32-byte Ed25519 public key) — the same key format `verify-attestation`'s
`--trusted-key` uses, and operators who already manage attestation keys
can reuse them here. A bundle verifies if *any one* of its signatures
matches a key given here.

A remote `--policy-bundle` source must be an `https://host/path#sha256=<hex>`
reference — the same digest-pinned form `https://` WASM inputs use — and
is fetched, digest-verified, and cached exactly the way those are (see
[Remote HTTPS Inputs](remote-https-inputs.md)): `--remote-max-bytes`,
`--remote-timeout-secs`, `--remote-cache-dir`, and `--no-remote-cache` all
apply to a bundle fetch too. A second run against the same URL is served
from the local content-addressed cache without any network access,
exactly like a cached WASM artifact — this is what makes the whole
pipeline usable offline once a bundle has been fetched once.

## What's checked, and the exit behavior on failure

`verify_bundle_envelope` (`src/policy_bundle.rs`) checks, in order:

- The envelope is valid JSON in the DSSE shape (`payloadType`/`payload`/`signatures`).
- `payloadType` is exactly `application/vnd.soroban-upgrade-safeguard.policy-bundle+json`
  — deliberately different from report attestations'
  (`application/vnd.in-toto+json`), so the two can never be confused.
- The payload decodes to a `PolicyBundle` matching the schema exactly
  (`#[serde(deny_unknown_fields)]` — an unrecognized field, including an
  attempt to smuggle in a `suppress`/`migration` table, is a malformed
  bundle, not a silently-ignored extra key).
- The payload is in canonical JSON form (the same canonicalization
  reports are signed over) — a payload that was re-encoded or re-ordered
  after signing is rejected even if every other check would pass.
- `version` matches the schema version this build supports.
- `expires_at`, if present, is in the future (checked against the
  verifying machine's clock, passed in explicitly so tests can control it).
- At least one signature verifies against a key in `--trusted-bundle-key`.

Any failure — the whole run aborts with a non-zero exit, before any WASM
is loaded, with every reason listed in the error message. There is no
"partially trusted" outcome and no flag to downgrade a failure to a
warning.

## Record: what a bundle supplies, and never supplies

| Field | Governance data a bundle supplies |
| --- | --- |
| `policy` | The five axis gate flags (`gate_storage_layout`, `gate_call_abi`, `gate_event_indexer`, `gate_source_level`, `gate_runtime_surface`) |
| `require_reason` | Rule IDs / axes that must carry a non-blank suppression reason |
| `limits` | Resource-limit overrides (`max_xdr_depth`, `max_xdr_len`, `max_entries`, `max_walk_depth`) — merged, not yet enforced; see [Scope](#scope-of-this-pass) |
| `rule_metadata` | Per-category documentation (description, remediation, a suggested default severity) |
| `capability_overrides` | Organization-supplied additions to the host-import capability registry — carried, not yet consulted; see [Scope](#scope-of-this-pass) |

A bundle has **no field** for suppression rules, data migrations, or
credentials of any kind. This isn't just a convention — attempting to add
a `suppress`/`migration` table to a bundle payload makes it fail to
deserialize at all (an unknown-field error), well before signature
verification is even reached. A bundle can tell a run *how to judge*
findings; it can never pre-acknowledge a specific one, and acknowledging
a specific finding stays a local, human, auditable decision in the
repository's own `.safeguard.toml`.

## Precedence: a bundle can only tighten, never loosen

`apply_bundle_policy` merges a verified bundle's `policy`/`require_reason`
into the local `SuppressionConfig` with an **OR-union**: a gate or
require-reason entry the bundle wants is added to what local config
already has; nothing local config already enforces can be turned off by
a bundle. Concretely:

```text
effective.gate_X = local.gate_X || bundle.gate_X
effective.require_reason.{rule_ids,axes} = local ∪ bundle
```

`merge_limits` is the resource-limit analog, with a minimum instead of an
OR: for each cap, whichever of the local and bundle value is *smaller*
(more restrictive) wins; a cap only one side sets applies as given.

Both rules mean the same thing from opposite directions: a compromised or
simply overzealous bundle source can only make a run **stricter** than
the operator intended, and a run's own local settings can never be
silently weakened by a bundle, no matter what the bundle says.

## Provenance

A successful run's report carries a `policy_bundle` field
(`SafetyReport::policy_bundle`/`RenderableReport.policy_bundle`, i.e.
present in `--format json` output) recording the bundle's source (a
redacted URL or local path), its digest, every signer identity that
verified, its `bundle_id`, and its schema version. Text and Markdown
output show a one-line summary. Since a failed bundle aborts the run
before a report exists at all, a report carrying this field is, by
construction, always describing a **verified** bundle — there is no
"applied but unverified" state to distinguish in the output.

## Signing a bundle

There is no `sign-policy-bundle` CLI subcommand in this pass — sign one
with the library directly:

```rust
use soroban_upgrade_safeguard::attestation::Ed25519Signer;
use soroban_upgrade_safeguard::policy_bundle::{sign_bundle, PolicyBundle};

let signer = Ed25519Signer::from_pkcs8("org-2026", &private_key_bytes)?;
let envelope = sign_bundle(&bundle, &signer)?;
std::fs::write("bundle.json", serde_json::to_vec_pretty(&envelope)?)?;
```

This reuses `AttestationSigner`/`Ed25519Signer` directly — the same
signing trait and implementation report attestations use (see
[Signed safeguard attestations](attestations.md) for generating a key
pair with `openssl` if you don't already have one). Ed25519 signatures
are deterministic for a given key and message, so signing the same
bundle twice with the same key produces a byte-identical envelope — this
is exercised directly in `src/policy_bundle.rs`'s test suite as a
deterministic signing vector.

## Scope of this pass

- **Resource limits** (`merge_limits`) are a pure, tested merge function,
  but the main comparison pipeline doesn't thread *any* `.safeguard.toml`
  `[limits]` table into live WASM parsing today either —
  `ResourcePolicy::default()` is used unconditionally outside `lint`. This
  is a pre-existing gap, not one introduced by policy bundles, and fixing
  it is out of scope here.
- **Capability overrides** round-trip through the format and are
  accessible via `PolicyBundle::capability_overrides()`, but are not yet
  consulted by `crate::capability::lookup` (the live host-import
  classification path).
- **Batch mode** (`--manifest`/`--old-dir`+`--new-dir`) rejects
  `--policy-bundle` outright with a clear error rather than silently
  ignoring it. Applying a bundle per-pair is a follow-up.
- **Key rotation** works by configuring multiple `--trusted-bundle-key`
  entries (any one valid signature suffices) and reissuing bundles signed
  with the new key; there's no dedicated rotation tooling beyond that.

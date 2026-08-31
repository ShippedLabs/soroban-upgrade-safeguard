# Named Policy Profiles

One repository often needs different policies for local development, pull
requests, release candidates, and emergency validation. Maintaining a
separate `.safeguard.toml` per situation duplicates the `[[suppress]]`
records and classification data every profile shares; editing one file in
place makes a run hard to reproduce — which policy was actually in effect?

Named profiles let one config file declare several policy variants:

```toml
strict = false

[[suppress]]
category = "Struct Field Removed"
target   = "ConfigData.threshold"
reason   = "Planned storage migration in v2 drops the unused threshold field."

[profiles.dev]
format = "text"

[profiles.pr]
inherits = "dev"
strict   = true

[profiles.pr.gating]
gate_event_indexer = true
```

See `.safeguard.profiles.example.toml` for a complete, runnable example with a
four-level `dev → pr → release → emergency` chain.

- [What a profile controls](#what-a-profile-controls)
- [Selecting a profile](#selecting-a-profile)
- [Inheritance](#inheritance)
- [Precedence](#precedence)
- [Provenance](#provenance)
- [Errors](#errors)

## What a profile controls

A profile is **policy only**. `[[suppress]]` records and classification data
stay in the file itself, shared by every profile — a review of a suppressed
finding doesn't change when someone switches from `dev` to `release`.

| Category | Fields                                                                                                                 |
| :------- | :--------------------------------------------------------------------------------------------------------------------- |
| Output   | `format`, `no_color`, `explain`                                                                                        |
| Severity | `strict`                                                                                                               |
| Budget   | `max_suppressions`                                                                                                     |
| Limit    | `[limits]` — `max_xdr_depth`, `max_xdr_len`, `max_entries`, `max_walk_depth`                                           |
| Gating   | `[gating]` — `gate_storage_layout`, `gate_call_abi`, `gate_event_indexer`, `gate_source_level`, `gate_runtime_surface` |

Every field is optional, in both the base configuration and a profile. An
omitted field simply does not contribute a layer to the fold — see
[Precedence](#precedence).

## Selecting a profile

```bash
soroban-upgrade-safeguard old.wasm new.wasm --profile pr
```

Precedence for _which_ profile runs, highest first:

1. `--profile <name>`
2. `SAFEGUARD_PROFILE` environment variable
3. `default_profile` in the config file

A bare invocation with none of these runs against the base configuration
alone — unchanged from before profiles existed. This is deliberate:
**existing `.safeguard.toml` files without a `[profiles.*]` table or
`--profile` flag behave exactly as they did before this feature.**

## Inheritance

A profile may declare `inherits = "<name>"` to build on another named
profile:

```toml
[profiles.release]
inherits = "pr"
format   = "json"
```

`release`'s own fields win over anything `pr` (or whatever `pr` itself
inherits from) sets — the chain is walked root-to-leaf and folded in that
order, most specific last. See [Precedence](#precedence) for exactly how a
field is chosen when more than one layer sets it.

Chains are bounded at **8** levels deep and may not cycle (including
self-inheritance, `inherits = "<own name>"`); both are hard errors that print
the full chain, e.g. `a -> b -> c -> a`. Selecting or inheriting from a name
that isn't declared under `[profiles.*]` is also a hard error.

## Precedence

Two rules, matching how [batch manifests](batch_manifests.md) already split
"valued" settings from "escalation" ones.

### Valued settings — last writer wins

`format`, `max_suppressions`, `[gating].*`, and `[limits].*`:

```text
built-in default  <  base configuration  <  inherited profiles (root to leaf)  <  selected profile  <  CLI / environment
```

"Inherited profiles" and "selected profile" are really one ordered fold: the
selected profile is the leaf of its own inheritance chain, so its fields are
simply applied last, after every ancestor.

```bash
# Emits JSON even though `release` sets `format = "json"` — the CLI is the
# most specific layer.
soroban-upgrade-safeguard old.wasm new.wasm --profile release --format markdown
```

`[gating].*` are booleans but are **valued**, not escalation: a profile must
be able to turn a gate _off_, which is the entire point of naming one.
Turning a gate off changes the verdict, not visibility — the underlying
findings are still counted and still appear in the report.

### Escalation booleans — OR-chain

`strict`, `explain`, and `no_color`: any layer may turn them **on**, no layer
may turn them **off**.

```toml
strict = true          # base configuration

[profiles.dev]
strict = false          # cannot weaken the base configuration's `strict = true`
```

This mirrors how `no_color` already resolves elsewhere in `src/config.rs` and
keeps a `dev`-style profile from silently disabling a safety gate that a
stricter layer asked for. `--strict` on the CLI always wins outright,
regardless of what any profile sets.

## Provenance

The resolved outcome is deterministic and fully recorded — not just the
final values, but which layer produced each one — so a CI log can answer
"why did this run behave the way it did?" without re-deriving the fold by
hand. `ResolvedConfig::resolve` returns this as `profile: ResolvedProfile`,
which serializes as part of the library's JSON output:

```json
{
  "selected": "release",
  "chain": ["dev", "pr", "release"],
  "format": { "value": "json", "origin": "profile 'release'" },
  "strict": { "value": true, "origin": "profile 'pr'" },
  "gating": {
    "gate_event_indexer": { "value": true, "origin": "profile 'pr'" }
  }
}
```

Every profile-controlled field carries a `value` and an `origin` — one of
`"built-in"`, `"base config"`, `"profile '<name>'"`, or `"cli"` — so it is
always possible to point at exactly the layer responsible for a given
setting.

## Errors

All of these fail before any WASM comparison happens:

| Condition                                | What the error tells you                           |
| :--------------------------------------- | :------------------------------------------------- |
| Selected profile not declared            | The missing name.                                  |
| Inherited profile not declared           | The missing name and the chain that referenced it. |
| Inheritance cycle                        | The full chain, e.g. `a -> b -> c -> a`.           |
| Inheritance depth > 8                    | The chain and the cap.                             |
| Unknown field in `[profiles.<name>]`     | The offending key and the profile it is in.        |
| Wrong value type (e.g. `strict = "yes"`) | The field, the profile, and the expected type.     |

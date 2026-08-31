# Storage Schema Cookbook

Worked examples for the declared storage schema — the `{"declarations": [...]}`
JSON/TOML manifest accepted by `lint --storage-schema` and by
`--old-storage-schema`/`--new-storage-schema` on a comparison run. If you
haven't read it yet, start with [Inferred Storage Schemas](storage-inference.md)
for the underlying model: the tool statically scans a compiled WASM for
recognizable storage host calls (`get`/`set`/`remove`/`has`/`extend_ttl`) and
reconciles what it observed against what you declared.

This page is example-first. Each recipe shows a realistic contract layout,
the schema you'd write for it, and what the resulting scope and findings look
like.

## The declaration shape

A schema is a flat list of declarations — one per storage operation you want
to account for, not a definition of your types' fields:

```json
{
  "declarations": [
    {
      "name": "admin-key",
      "function": "set_admin",
      "operation": "set",
      "durability": "instance",
      "key_type": "DataKey::Admin",
      "value_type": "Address"
    }
  ]
}
```

| Field        | Required | Meaning                                                                 |
| ------------ | -------- | ------------------------------------------------------------------------ |
| `name`       | yes      | A label for the declaration; shown in findings. Must be non-empty.       |
| `function`   | no       | The exported/internal function this operation happens in. Omit to match any function. |
| `operation`  | yes      | One of `get`, `set`, `remove`, `has`, `extend_ttl`.                      |
| `durability` | no       | One of `instance`, `persistent`, `temporary`. Omit to match any durability. |
| `key_type`   | no       | The key's type, spelled the same way the tool prints types elsewhere (see below). |
| `value_type` | no       | The value's type, same spelling convention.                              |

`key_type`/`value_type` are free-form type-spelling strings, not embedded
field definitions — the schema records *what* is stored under a key, not the
shape of the struct itself. Use the same spelling the report already uses for
a type (`Address`, `Map<Address, i128>`, `Option<Address>`, a bare
user-defined name like `PositionState`), so a type named in a finding can be
pasted straight into a declaration.

TOML uses the same shape with `[[declarations]]` table arrays instead of a
JSON list.

## Recipe 1 — a single admin key

The simplest contract: one instance key holding an `Address`.

```json
{
  "declarations": [
    {
      "name": "admin-key",
      "function": "set_admin",
      "operation": "set",
      "durability": "instance",
      "key_type": "DataKey::Admin",
      "value_type": "Address"
    }
  ]
}
```

```bash
soroban-upgrade-safeguard lint ./contract.wasm --storage-schema ./schema.json
```

If the compiled contract's `set_admin` function performs exactly one
`instance`-durability `set` host call, the declaration is matched and the
report reads:

```
Storage schema: compatible
Coverage: complete (0 gaps)
- inferred Set in set_admin: key=unknown, value=unknown, durability=instance, confidence=host_call_only
```

Note `key=unknown, value=unknown` in the *inferred* line even though you
declared concrete types: today the static analyzer proves `operation`,
`function`, and `durability` from the host-call evidence, but does not yet
prove a `key_type`/`value_type` from data flow. Declaring them anyway is
still worthwhile — it documents the layout for readers, and the reconciler
will start enforcing them the moment inference can supply one, with no
schema changes required on your side.

## Recipe 2 — a shared key enum across several functions

"Common key enums" in practice means several declarations sharing the same
`key_type`, one per function that touches a variant of it — not one
declaration per enum variant. A token contract with:

```rust
enum DataKey {
    Admin,
    Balance(Address),
    Allowance(Address, Address),
}
```

is declared as one entry per storage-touching function:

```json
{
  "declarations": [
    {
      "name": "read-admin",
      "function": "admin",
      "operation": "get",
      "durability": "instance",
      "key_type": "DataKey",
      "value_type": "Address"
    },
    {
      "name": "write-balance",
      "function": "transfer",
      "operation": "set",
      "durability": "persistent",
      "key_type": "DataKey",
      "value_type": "i128"
    },
    {
      "name": "read-allowance",
      "function": "allowance",
      "operation": "get",
      "durability": "temporary",
      "key_type": "DataKey",
      "value_type": "i128"
    }
  ]
}
```

Each declaration is matched independently against the observation for its
`function`/`operation`/`durability` triple. A contract that adds a fourth
`DataKey` variant (say `Frozen(Address)`) needs a new declaration for
whatever function reads or writes it — the schema doesn't need to enumerate
the enum's variants itself, only the operations your compiled code performs.

## Recipe 3 — nested values

A lending contract that stores a collection keyed by address, where each
entry is itself a struct:

```rust
struct PositionState { collateral: i128, debt: i128 }
```

stored as `Map<Address, PositionState>`, or as a per-position record under
`DataKey::Position(Address)` with the struct itself as the value — either
way, the container/nested spelling goes straight into `value_type`:

```json
{
  "declarations": [
    {
      "name": "positions-map",
      "function": "open_position",
      "operation": "set",
      "durability": "persistent",
      "key_type": "DataKey::Positions",
      "value_type": "Map<Address, PositionState>"
    },
    {
      "name": "position-entry",
      "function": "close_position",
      "operation": "remove",
      "durability": "persistent",
      "key_type": "DataKey::Position",
      "value_type": "PositionState"
    }
  ]
}
```

Nesting composes the same way the type-spelling table describes it
elsewhere: `Vec<CollateralEntry>`, `Map<Address, Vec<PositionState>>`, and so
on are all valid `value_type` strings. The schema treats a nested type as an
opaque name — it doesn't reach inside `PositionState` to check field order.
Field-level layout protection for a type like this comes from declaring it
as an *exported* type (or via the standard interface comparison, if it's
exported); the storage schema's job here is only to confirm the operation
touching it is accounted for.

## Recipe 4 — optional fields

`Option<T>` is a real, distinct on-chain type — a `Some`/`None` tag plus a
payload — not "this key might be absent." A beneficiary that a position may
or may not have:

```json
{
  "declarations": [
    {
      "name": "position-beneficiary",
      "function": "set_beneficiary",
      "operation": "set",
      "durability": "persistent",
      "key_type": "DataKey::Beneficiary",
      "value_type": "Option<Address>"
    }
  ]
}
```

Spell it `Option<Address>`, not `Address` — the two are different wire
types, and if a future `TypeContradiction` check catches a mismatch here, it
means the compiled contract stopped wrapping the value in `Option` (or
started to), which is exactly the kind of change that breaks existing
callers deserializing the old shape.

Don't confuse this with a declaration you simply choose not to write — an
*absent* declaration is not "an optional field," it's an undeclared
operation (see Recipe 5).

## Recipe 5 — partial coverage

Two different things can make a schema "incomplete," and the report
distinguishes them:

- **Coverage gaps** — the analyzer found a storage-related call it couldn't
  prove enough about (an indirect call, a branch-dependent path). This is
  about the analyzer's own confidence in the compiled bytecode and shows up
  regardless of what you declared: `Coverage: incomplete (N gaps)`.
- **Declaration mismatches** — your schema and the analyzer's observations
  disagree. An observed operation with no matching declaration becomes
  `MissingDeclaration`; a declaration that no observation ever matched
  becomes `UnobservedDeclaration`. This is `Storage schema: mismatch`, a
  Critical finding, independent of coverage gaps.

A schema that only declares part of a contract's real storage surface — say,
you cover `deposit` and `withdraw` but forget `liquidate` — produces a
`MissingDeclaration` for whatever `liquidate` actually does on-chain:

```json
{
  "declarations": [
    { "name": "deposit-write", "function": "deposit", "operation": "set", "key_type": "DataKey::Position" },
    { "name": "withdraw-write", "function": "withdraw", "operation": "set", "key_type": "DataKey::Position" }
  ]
}
```

```
Storage schema: mismatch
Coverage: complete (0 gaps)
- inferred Set in deposit: key=unknown, value=unknown, durability=unknown, confidence=host_call_only
- inferred Set in withdraw: key=unknown, value=unknown, durability=unknown, confidence=host_call_only
- inferred Remove in liquidate: key=unknown, value=unknown, durability=unknown, confidence=host_call_only
- missing declaration for Remove in liquidate (unknown durability)
```

The reverse also happens: refactor `liquidate` away and leave its
declaration behind, and it becomes `declaration <name> was not observed`
(`UnobservedDeclaration`) — a stale entry pointing at code that no longer
exists.

In a two-build comparison (`--old-storage-schema`/`--new-storage-schema`),
each side is reconciled independently and any mismatch on either side is
reported as a `Storage Schema Mismatch` Critical finding. By default this
fails the run the same way any other Critical finding does
(`policy.gate_storage_layout` defaults to `true`); pass `--strict` to force
the gate on regardless of policy, or acknowledge a specific mismatch in
`.safeguard.toml` the same way you would any other finding — see
[Suppressing Known Breaking Changes](documentation.md#suppressing-known-breaking-changes).

## Quick reference

| You want to show...        | Do this                                                                 |
| --------------------------- | -------------------------------------------------------------------------- |
| A shared key enum           | One declaration per function that touches it, all sharing `key_type`.      |
| A nested/composite value    | Spell it as a container: `Vec<T>`, `Map<K, V>`, or a bare struct name.     |
| An optional stored field    | `Option<T>` as the `value_type`, distinct from plain `T`.                   |
| Only part of the surface    | Declare only what you've reviewed; expect `MissingDeclaration` for the rest until you catch up. |
| A stale/removed declaration | Delete it, or expect `UnobservedDeclaration` to flag it.                    |

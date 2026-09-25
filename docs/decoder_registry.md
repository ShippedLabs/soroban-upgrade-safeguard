# Protocol-Versioned Contract-Spec Decoder Registry

## Overview

The Soroban XDR contract-spec format is versioned through the interface
version packed into the `contractenvmetav0` WASM custom section:

```
interface_version = (protocol_version << 32) | pre_release_version
```

Prior to this feature, `extract_metadata` always decoded
`contractspecv0` bytes using a single hard-coded schema.  When a future
protocol version extends or changes the spec encoding, a hard-coded decoder
would either silently misparse the bytes or crash.

The `decoder_registry` module replaces this with an explicit dispatch table:
each registered decoder owns a **version predicate** that declares which
interface versions it handles.  The parser resolves the version from
`contractenvmetav0` first, then dispatches the `contractspecv0` bytes to the
matching decoder.  If no decoder matches, the parse fails with a dedicated
`Error::UnsupportedDecoderVersion` rather than a silent misparse.

## Architecture

```
contractenvmetav0 → InterfaceVersion(protocol, pre_release)
                             │
                    SpecDecoderRegistry::decode()
                             │
               ┌─────────────────────────────┐
               │  registered decoder entries  │
               │  tried in registration order │
               │                             │
               │  [0] legacy-no-version      │ ← matches None (no env-meta)
               │  [1] soroban-v0-p20-23      │ ← matches protocol 20–23
               └─────────────────────────────┘
                             │
                  ┌──────────┴──────────────────┐
                  │                             │
              Decoded{entries,           UnsupportedVersion
               section_meta}                   │
                  │                        Error::UnsupportedDecoderVersion
              PartialDecode{entries,
               skipped_bytes,
               section_meta}
```

## Supported Protocol Versions

| Decoder name | Version range | Schema |
|---|---|---|
| `legacy-no-version` | no env-meta | `stellar-xdr` v21 |
| `soroban-v0-protocol-20-23` | protocol 20–23 | `stellar-xdr` v21 |

## Version Metadata Preservation

Every successful decode carries a [`SectionVersionMeta`] that records:

- `interface_version` — the exact `InterfaceVersion` used to select the decoder.
- `decoder_name` — the name of the decoder entry that handled the section.
- `version_owned` — `true` when the predicate explicitly owns this version
  (e.g. `ProtocolRange { min: 20, max: 23 }`); `false` when matched via
  `AnyVersion` fallback (a weaker claim worth a warning).

This allows callers to inspect which schema was used without re-parsing the
env-meta section.

## Adding a New Protocol Version

### Case 1: Same XDR schema (most common)

Simply extend `SUPPORTED_PROTOCOL_MAX` in `src/decoder_registry.rs`:

```rust
pub const SUPPORTED_PROTOCOL_MAX: u32 = 24; // was 23
```

### Case 2: New XDR schema (breaking wire format change)

1. Write a new `DecodeFn` that decodes bytes under the new schema:

   ```rust
   pub fn decode_spec_v1(data: &[u8]) -> Result<Vec<ScSpecEntry>, Error> {
       // decode using the new stellar-xdr crate / XDR variant
   }
   ```

2. Register it with an appropriate `VersionPredicate`:

   ```rust
   // In SpecDecoderRegistry::new():
   registry.register(DecoderEntry {
       name: "soroban-v1-protocol-24",
       predicate: VersionPredicate::ExactProtocol(24),
       decode: decode_spec_v1,
   });
   ```

3. Add a compatibility test that feeds a WASM with the new protocol version
   through `extract_metadata_with_registry` and asserts a clean decode.

4. Add a cross-version safety test that verifies `decode_spec_v1` is **not**
   called for protocol 23 (the previous version).

5. Update this document.

**Never** catch an `UnsupportedDecoderVersion` error and fall through to a
direct XDR decode — that is the exact anti-pattern the registry exists to
prevent.

## Preventing Cross-Version Schema Misuse

The registry only dispatches to the entry whose predicate matches the version.
It never falls through to a "close enough" match.

For code paths that call `entry.decode` directly (bypassing the registry),
use `validate_version_ownership` to guard the call:

```rust
use soroban_upgrade_safeguard::decoder_registry::validate_version_ownership;

// Returns Err(UnsupportedDecoderVersion) if the predicate does not own version.
validate_version_ownership(&entry, version)?;
(entry.decode)(data)
```

This prevents a decoder written for one version from silently parsing
another version's layout.

## Forward-Compatible Decoding

When a future protocol adds new `ScSpecEntry` variants that the current
`stellar-xdr` crate does not recognise, the XDR cursor stops at the first
unknown discriminant.  Two strategies are available:

### Hard fail (default, `SpecDecoderRegistry::decode`)

The decoder returns what it decoded so far as an error.  `extract_metadata`
propagates this as `Error::UnsupportedDecoderVersion`.  Analysis is halted.
This is the conservative choice.

### Partial recovery (`SpecDecoderRegistry::decode_forward_compat`)

Catches the decode error and returns a `DecodeOutcome::PartialDecode` with:
- `entries` — the entries decoded before the first unknown field.
- `skipped_bytes` — how many bytes were not decoded.
- `section_meta` — version metadata for the section.

`extract_metadata` emits a `warning:` to stderr for partial decodes and
continues with the decoded subset.  `SorobanMetadata::spec_version_verified`
remains `true` but callers should treat the spec as possibly incomplete.

A `spec_version_verified = false` value after parsing indicates the spec was
decoded without version verification (no `contractspecv0` section present).

### ForwardCompatResult helper

```rust
let result = ForwardCompatResult::partial(entries, skipped_bytes);
assert!(!result.complete);
assert_eq!(result.skipped_bytes, 42);
```

## Error Behaviour

### Unsupported version

```
Error::SectionExtraction {
    section_name: "contractspecv0",
    ...
    source: Some(Error::UnsupportedDecoderVersion {
        version_display: Some("protocol 255"),
        message: "no decoder supports protocol 255; registered decoders: [...]; upgrade the tool...",
    })
}
```

### Malformed version marker

A WASM that carries a `contractenvmetav0` section with an interface version
encoding `protocol = 0` (or any out-of-range value) will be treated as
`UnsupportedVersion` rather than silently decoded under the wrong schema.

## Testing

```sh
# All decoder-registry unit tests (version predicate, round-trips, dispatch,
# section metadata, forward compat, validate_version_ownership, malformed
# version markers)
cargo test decoder_registry

# Parser integration tests that use the registry
cargo test extract_metadata_rejects_unsupported_future_protocol
cargo test extract_metadata_sets_spec_version_verified_for_known_protocol
cargo test extract_metadata_with_registry_custom_decoder_accepted

# Integration test file covering all supported versions
cargo test --test decoder_registry_compat
```

## Adding a Review Checklist for New Protocol Versions

When a PR adds or changes a registered decoder, verify:

- [ ] The new `VersionPredicate` does not overlap with an existing entry
  (overlapping predicates are not an error but the first match silently wins).
- [ ] `validate_version_ownership` is used in any direct `entry.decode` calls.
- [ ] `SUPPORTED_PROTOCOL_MAX` (or `SUPPORTED_PROTOCOL_MIN`) is updated.
- [ ] A compatibility test exists for every supported protocol version.
- [ ] A rejection test exists for the version just above the new maximum.
- [ ] Forward-compat tests exist if the new protocol may introduce unknown fields.
- [ ] This document is updated.

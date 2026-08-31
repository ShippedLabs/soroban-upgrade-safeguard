# Troubleshooting Loader Failures

A practical guide to what goes wrong while a WASM file is being loaded and
decoded, organized around the message you're actually looking at. If a run
fails before it gets to comparing anything, it's almost always one of the
four categories below.

Start here: run the failing input through `extract` on its own. It isolates
loading/decoding from the two-build comparison and prints exactly what the
tool managed to pull out of the file:

```bash
soroban-upgrade-safeguard extract ./the-file-in-question.wasm
```

If `extract` fails, the problem is in loading — read on. If `extract`
succeeds but returns an interface with far fewer functions/types than you
expect, jump to [Missing custom sections](#missing-custom-sections) below —
that case doesn't fail at all, it just quietly gives you less than you
think it did.

## 1. Malformed WASM

**Representative messages:**

```
Error: WASM validation error: 'new.wasm' does not appear to be a valid WASM binary (bad magic bytes)
```

```
Error: WASM validation error at byte offset 1042: WASM validation failed for 'new.wasm'

Caused by:
    ...parser error describing the malformed structure...
```

**Cause:** The file's first four bytes aren't the WASM magic header
(`\0asm`), or the header is fine but a full structural parse fails
somewhere past it. Common real-world triggers:

- You pointed the tool at something that isn't a WASM binary at all — a
  `.wat` text file, a stripped/renamed archive, an HTML error page saved by
  a failed `curl`/download, or an empty file.
- A build or download was truncated (CI artifact upload cut short, a
  network fetch that didn't complete, a git-lfs pointer file checked out
  instead of the real binary).
- The bytes are a real but corrupted WASM module (bit flip, partial
  overwrite).

**Next action:**

1. Confirm the file is what you think it is: `file ./new.wasm` should say
   `WebAssembly (wasm) binary module`, and the first four bytes should be
   `00 61 73 6d` (`file -b --mime-type` or a hex dump both work).
2. If it's a `.wat` file, compile it first (`wat2wasm`) — the tool only
   accepts the binary format.
3. If it came from a download or artifact transfer, re-fetch it and compare
   file size / hash against the source. A byte offset in the error message
   points at roughly where the parser gave up; a truncated file usually
   fails right at or near the end.
4. If it's a genuinely corrupted build output, rebuild from source rather
   than trying to repair the binary.

## 2. Missing custom sections

This is the case that **doesn't produce an error at all**, which is exactly
why it belongs in a troubleshooting guide: the loader treats an absent
`contractspecv0` or `contractenvmetav0` custom section as "this build has
none of that," not as a failure. A WASM module with no `contractspecv0`
section loads successfully and decodes to an interface with zero functions
and zero types.

**Symptom:** The comparison reports "no relevant changes detected" when you
know the contracts differ, or `extract` returns a suspiciously small
`functions`/`structs`/`enums` list.

**Cause, almost always:** The WASM you're pointing at wasn't built with the
Soroban SDK's contract macros, or was post-processed by a step that strips
custom sections (some `wasm-opt`/`wasm-strip` invocations, or a generic
"minify the binary" release step) after the SDK originally emitted them.

**Next action:**

1. Run `extract` and check the counts in the JSON output. Zero of
   everything is the tell.
2. If you have `wasm-objdump` or similar available, list the module's
   custom sections directly and confirm `contractspecv0` isn't there.
3. Check your build pipeline for a post-build optimization/stripping step
   and either skip it for the artifact you feed this tool, or configure it
   to preserve custom sections (most `wasm-opt`-based steps have a flag for
   this — check the tool's own docs, since the exact flag varies).
4. Build straight from the SDK's own build command
   (`stellar contract build` / `cargo build --target wasm32v1-none`,
   depending on your SDK version) without an extra optimization pass, and
   confirm `extract` now reports a non-empty interface.

A custom section that **is present but fails to decode** is a different,
genuinely erroneous case — see the next section.

## 3. Unsupported formats

**Representative messages:**

```
Error: Contract 'CABCD...' is a built-in Stellar Asset contract and does not have WASM bytecode
```

```
Error: Failed to decode contractspecv0 section 0 at byte offset 512

Caused by:
    ...XDR decode error describing the entry that failed...
```

```
Error: ScSpecEntry XDR decode failed at entry index 3 (byte offset 890)
```

**Cause:**

- **Built-in asset contracts.** In RPC mode (`--contract-id`/`--rpc-url`),
  a `StellarAsset` contract has no WASM bytecode at all — it's implemented
  natively by the network, not deployed code. There is nothing for the
  loader to fetch; this isn't a bug, it's the wrong kind of contract ID for
  this tool.
- **A present-but-corrupt custom section.** The section exists but its
  contents don't decode as valid XDR — different from the "missing"
  section case above, and a real error rather than an empty result.
- **An XDR shape newer than this build understands.** Occasionally a newer
  Soroban SDK introduces a spec entry variant that an older
  `soroban-upgrade-safeguard` build's pinned `stellar-xdr` version doesn't
  know how to decode.

**Next action:**

1. For the built-in asset case: don't run this tool against it — there's
   no upgrade to validate. If you're scripting contract IDs from a larger
   list, filter out asset contracts before invoking the tool.
2. For a corrupt-section decode failure on a build you control: rebuild
   from source; a decode failure inside a section that's otherwise present
   points at a genuinely malformed build artifact, not a transient issue.
3. If the contract was built with a Soroban SDK release newer than this
   tool has been tested against, check for a newer
   `soroban-upgrade-safeguard` release before assuming the contract itself
   is broken.

## 4. Resource limits

**Representative messages:**

```
XDR nesting exceeded the maximum decode depth of 64 (raise `max_xdr_depth`)
a declared XDR length exceeded the per-section byte budget of 33554432 (raise `max_xdr_len`)
type nesting exceeded the maximum walk depth of 128 (raise `max_walk_depth`)
spec entry count exceeded the maximum of 100000 (raise `max_entries`)
```

These appear as the `Caused by:` tail of a `SectionExtraction`/decode error,
naming exactly which of the four limits tripped and the flag that controls
it.

**Cause:** The input WASM's embedded `contractspecv0`/`contractenvmetav0`
sections are treated as untrusted input — deliberately, since RPC mode
decodes whatever bytecode a remote endpoint hands back. A crafted or
corrupted section can claim an enormous length or nest a type far deeper
than any real contract needs; the tool rejects it with a controlled error
instead of allocating unbounded memory or overflowing the stack. See
[Resource Limits and Hardening Against Malicious Input](documentation.md#resource-limits-and-hardening-against-malicious-input)
for the full policy and defaults.

**Next action:**

1. **Local file, your own build:** this almost never happens for a
   legitimate contract — the defaults comfortably cover real-world specs.
   Treat it as a signal something is wrong with the build (a codegen bug
   producing pathological nesting, a corrupted artifact) before reaching
   for the override flags.
2. **RPC mode, a contract ID you don't control:** treat the rejection as
   the safeguard working as intended. Don't raise the limits just to get
   past it unless you have an independent reason to trust that specific
   contract is legitimately large.
3. **A known-large legitimate contract:** raise only the specific limit
   named in the message, either per-run (`--max-xdr-depth`,
   `--max-xdr-len`, `--max-entries`, `--max-walk-depth`) or via a
   `[limits]` table in `.safeguard.toml`.
4. Note that a resource-limit rejection currently exits with the same
   status code as any other run-ending error from this command (`1`) —
   don't rely on a distinct exit code to detect this case in a script;
   match on the message text instead, or use `--format json` and inspect
   stderr.

## Other load failures you might hit

Not unique to WASM decoding, but surfaced through the same loader:

- **File not found / unreadable:** `File access error for '<path>': ...` —
  the path is wrong, or (on Unix) permission bits block reading. Confirm
  the path and that the invoking user can read it.
- **Symlink rejected:** `Symlink input rejected by policy: '<path>'
  resolves to '<target>'` — you passed `--no-symlinks` and an input path
  is, or passes through, a symlink. Either point at the resolved file
  directly or drop `--no-symlinks`.
- **RPC transport/protocol errors:** covered separately in the
  [RPC Security Checklist](rpc-security-checklist.md) and
  [Zero-Trust RPC Baseline Retrieval](documentation.md#zero-trust-rpc-baseline-retrieval) —
  these come from the network layer, not the WASM loader itself.

## Quick reference

| You see...                                            | Category                | Section                                              |
| ------------------------------------------------------- | ------------------------ | ------------------------------------------------------- |
| "does not appear to be a valid WASM binary"              | Malformed WASM            | [§1](#1-malformed-wasm)                                  |
| A passing run with an empty/near-empty interface         | Missing custom sections   | [§2](#2-missing-custom-sections)                        |
| "is a built-in Stellar Asset contract"                    | Unsupported formats       | [§3-unsupported-formats](#3-unsupported-formats)         |
| "Failed to decode contractspecv0 section"                 | Unsupported formats       | [§3-unsupported-formats](#3-unsupported-formats)         |
| "exceeded the maximum ... (raise \`max_...\`)"            | Resource limits           | [§4-resource-limits](#4-resource-limits)                 |

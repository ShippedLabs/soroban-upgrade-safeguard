# soroban-upgrade-safeguard (Node.js bindings)

Native Node.js bindings for the `soroban-upgrade-safeguard` Soroban
contract-upgrade safety analyzer, built on
[napi-rs](https://napi.rs). No subprocess, no CLI, no network access —
comparisons run in-process against a compiled native addon.

> **Status**: first-pass bindings covering byte/file comparisons with
> storage-schema and suppression-policy inputs, built for the current
> host only (no prebuilt multi-platform binaries yet). RPC-backed
> comparisons, lineage validation, and complexity budgets are not yet
> exposed — see `docs/bindings.md` in the main repository for scope and
> the version-compatibility policy.

## Installation

Not yet published; build it from source with a Rust toolchain installed:

```bash
cd bindings/node
npm install        # pulls in @napi-rs/cli as a dev dependency
npm run build:debug   # or: npm run build (release)
```

This produces `soroban_upgrade_safeguard.node` in this directory, which
`index.js` loads directly. Then, from your project:

```js
const safeguard = require('/path/to/bindings/node');
```

(Once packaged, this would simply be `require('soroban-upgrade-safeguard')`
after `npm install`.)

## Usage

```js
const { compareBytes, SafeguardError } = require('soroban-upgrade-safeguard');
const fs = require('fs');

const oldWasm = fs.readFileSync('old.wasm');
const newWasm = fs.readFileSync('new.wasm');

try {
  const report = compareBytes(oldWasm, newWasm, { explain: true });
  console.log(report.is_safe, report.critical_count);
} catch (err) {
  if (err instanceof SafeguardError) {
    console.error(`comparison failed (${err.kind}): ${err.details}`);
  }
  throw err;
}
```

`compareFiles` takes paths instead of buffers and does the file reading on
the Rust side:

```js
const report = compareFiles('old.wasm', 'new.wasm');
```

### Storage schemas and suppression policy

```js
const report = compareBytes(oldWasm, newWasm, {
  strict: true,
  suppressionsToml: fs.readFileSync('.safeguard.toml', 'utf8'),
  oldStorageSchema: fs.readFileSync('old_schema.toml', 'utf8'),
  newStorageSchema: fs.readFileSync('new_schema.toml', 'utf8'),
  // oldStorageSchemaFormat / newStorageSchemaFormat default to "toml";
  // pass "json" if your schema files are JSON.
});
```

### Errors

Every failure throws `SafeguardError` (exported alongside `compareBytes`),
never a bare `Error` with only a message — `err.kind` is the stable
identifier (matching the Rust library's `ErrorKind`, e.g.
`"WasmValidation"`, `"InvalidInput"`) and `err.details` is a free-text
explanation for humans. Match on `.kind`, not on `.details` or
`.message`, since wording may change between releases.

Internally, the native addon (`index.js`'s `native.compareBytes`/
`native.compareFiles`) never throws — it returns a tagged
`{ ok, report, error }` object, which `index.js` turns into the
throw-on-failure behavior shown above. Call the native functions directly
(`require('./soroban_upgrade_safeguard.node')`) if you'd rather handle the
tagged result yourself.

## Report shape

`compareBytes`/`compareFiles` return a plain object built directly from
the same report model the CLI's `--format json` emits — see the main
repository's `src/render.rs` for field documentation, and `print-schema`
(a CLI subcommand) for the full JSON Schema. There is no intermediate
JSON string: the Rust report's `serde` model is converted directly into
JS values via napi-rs.

## Compatibility

See `docs/bindings.md` in the main repository for the version-compatibility
policy between this package's version and the underlying Rust engine
(`engineVersion()` reports the engine build this addon was compiled
against).

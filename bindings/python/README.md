# soroban-upgrade-safeguard (Python bindings)

Native Python bindings for the `soroban-upgrade-safeguard` Soroban
contract-upgrade safety analyzer, built on [PyO3](https://pyo3.rs) and
[pythonize](https://docs.rs/pythonize). No subprocess, no CLI, no
network access — comparisons run in-process against a compiled Rust
extension.

> **Status**: first-pass bindings covering byte/file comparisons with
> storage-schema and suppression-policy inputs. RPC-backed comparisons,
> lineage validation, and complexity budgets are not yet exposed — see
> `docs/bindings.md` in the main repository for scope and the
> version-compatibility policy.

## Installation

This package is not yet published; build and install it from source with
[maturin](https://www.maturin.rs/):

```bash
pip install maturin
cd bindings/python
maturin develop            # builds the extension and installs it into your active venv
# or, for a wheel you can distribute:
maturin build --release
pip install target/wheels/soroban_upgrade_safeguard-*.whl
```

Requires a Rust toolchain (stable) to build from source — there are no
prebuilt wheels yet.

## Usage

```python
import soroban_upgrade_safeguard as safeguard

with open("old.wasm", "rb") as f:
    old_wasm = f.read()
with open("new.wasm", "rb") as f:
    new_wasm = f.read()

try:
    report = safeguard.compare_bytes(old_wasm, new_wasm, explain=True)
except safeguard.SafeguardError as exc:
    print(f"comparison failed ({exc.kind}): {exc.details}")
    raise

print(report["is_safe"], report["critical_count"])
```

`compare_files` takes paths instead of bytes and does the file reading on
the Rust side:

```python
report = safeguard.compare_files("old.wasm", "new.wasm")
```

### Storage schemas and suppression policy

```python
report = safeguard.compare_bytes(
    old_wasm,
    new_wasm,
    strict=True,
    suppressions_toml=open(".safeguard.toml").read(),
    old_storage_schema=open("old_schema.toml").read(),
    new_storage_schema=open("new_schema.toml").read(),
    # old_storage_schema_format / new_storage_schema_format default to "toml";
    # pass "json" if your schema files are JSON.
)
```

### Errors

Every failure raises `soroban_upgrade_safeguard.SafeguardError`, never a
bare string — `exc.kind` is the stable identifier (matching the Rust
library's `ErrorKind`, e.g. `"WasmValidation"`, `"InvalidInput"`) and
`exc.details` is a free-text explanation for humans. Match on `.kind`,
not on the text of `.details` or `str(exc)`, since wording may change
between releases.

## Report shape

`compare_bytes`/`compare_files` return a plain `dict` built directly from
the same report model the CLI's `--format json` emits — see the main
repository's `docs/empirical_validation.md` and `src/render.rs` for field
documentation, and `print-schema` (a CLI subcommand) for the full JSON
Schema. There is no intermediate JSON string: the Rust report's `serde`
model is walked directly into Python `dict`/`list`/`str`/`int`/`float`/
`bool`/`None` values.

## Compatibility

See `docs/bindings.md` in the main repository for the version-compatibility
policy between this package's version and the underlying Rust engine
(`soroban_upgrade_safeguard.engine_version()` reports the engine build this
extension was compiled against).

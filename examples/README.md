# Examples

Small things to try the tool against without writing your own contracts.

## Sample contract pair

The repository ships a pair of mock contracts with a deliberate upgrade break.
Their prebuilt builds and sources are:

| Build | WASM | Source |
| --- | --- | --- |
| Old (v1) | [tests/wasm/v1.wasm](../tests/wasm/v1.wasm) | [tests/fixtures/v1/src/lib.rs](../tests/fixtures/v1/src/lib.rs) |
| New (v2) | [tests/wasm/v2.wasm](../tests/wasm/v2.wasm) | [tests/fixtures/v2/src/lib.rs](../tests/fixtures/v2/src/lib.rs) |

Going from v1 to v2 the source changes:

- `ConfigData` loses its `threshold` field.
- `StatusEvent::Paused` changes from `2` to `3`, and `Archived` is added.
- `initialize` takes an extra `u32` argument and no longer returns a value.

Compare the pair:

```bash
soroban-upgrade-safeguard tests/wasm/v1.wasm tests/wasm/v2.wasm
```

The text report is printed to the terminal and the command exits non-zero
because the upgrade has critical breaks. For a machine-readable report, with no
timestamp so it is stable between runs:

```bash
soroban-upgrade-safeguard tests/wasm/v1.wasm tests/wasm/v2.wasm \
  --format json --no-timestamp > report.json
```

To rebuild the WASM files from the sources, run
[tests/build_fixtures.sh](../tests/build_fixtures.sh).

## Impact graph to Graphviz

[impact_graph_to_dot.py](./impact_graph_to_dot.py) turns the impact graph from a
JSON report into a Graphviz DOT file:

```bash
soroban-upgrade-safeguard tests/wasm/v1.wasm tests/wasm/v2.wasm \
  --impact-graph --format json > report.json
python3 examples/impact_graph_to_dot.py report.json > graph.dot
dot -Tsvg graph.dot -o graph.svg
```

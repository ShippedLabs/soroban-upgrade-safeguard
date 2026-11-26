"""Cross-language parity: the Python binding's report must match the CLI's
`--format json` report for the same inputs, field for field.

Not wired into any CI job yet (see `docs/bindings.md`), and not run as
part of this change — it requires the extension to be built first
(`maturin develop`) and the main crate's binary to be built
(`cargo build`). Run manually with:

    cd bindings/python
    maturin develop
    cargo build --manifest-path ../../Cargo.toml --bin soroban-upgrade-safeguard
    python -m pytest tests/test_parity.py
"""

import json
import pathlib
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WASM_DIR = REPO_ROOT / "tests" / "wasm"
CLI_BIN = REPO_ROOT / "target" / "debug" / "soroban-upgrade-safeguard"


def _run_cli(old: pathlib.Path, new: pathlib.Path) -> dict:
    result = subprocess.run(
        [str(CLI_BIN), str(old), str(new), "--format", "json", "--no-color"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.skipif(not CLI_BIN.exists(), reason="CLI binary not built; run `cargo build` first")
def test_compare_bytes_matches_cli_json():
    safeguard = pytest.importorskip(
        "soroban_upgrade_safeguard",
        reason="extension not built; run `maturin develop` in bindings/python first",
    )

    old_path = WASM_DIR / "v1.wasm"
    new_path = WASM_DIR / "v2.wasm"

    cli_report = _run_cli(old_path, new_path)
    py_report = safeguard.compare_bytes(old_path.read_bytes(), new_path.read_bytes())

    # The binding's request model doesn't enable env-metadata/host-import/
    # storage-schema policy the CLI's plain two-positional-arg invocation
    # also doesn't enable, so a bare comparison should match exactly on
    # every field that doesn't depend on wall-clock time.
    for key in ("is_safe", "critical_count", "warning_count", "info_count"):
        assert py_report[key] == cli_report[key], f"field {key!r} diverged"

    assert py_report["findings_by_category"] == cli_report["findings_by_category"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))

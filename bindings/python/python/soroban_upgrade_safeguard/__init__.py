"""Native Python bindings for soroban-upgrade-safeguard.

Example
-------
>>> import soroban_upgrade_safeguard as safeguard
>>> with open("old.wasm", "rb") as f:
...     old_wasm = f.read()
>>> with open("new.wasm", "rb") as f:
...     new_wasm = f.read()
>>> report = safeguard.compare_bytes(old_wasm, new_wasm)
>>> report["is_safe"]
True

Every comparison returns a plain ``dict`` matching the CLI's
``--format json`` report shape (see ``docs/`` in the main repository for
the full schema, or call ``soroban_upgrade_safeguard.report_schema()``
once that's wired up in a later pass). Failures raise `SafeguardError`,
never a bare string.
"""

from ._native import SafeguardError, compare_bytes, compare_files, engine_version

__all__ = [
    "SafeguardError",
    "compare_bytes",
    "compare_files",
    "engine_version",
    "__version__",
]

__version__ = "0.1.0"

from typing import Any, Optional

class SafeguardError(Exception):
    kind: str
    details: str

def compare_bytes(
    old_wasm: bytes,
    new_wasm: bytes,
    *,
    explain: bool = False,
    strict: bool = False,
    contract: Optional[str] = None,
    suppressions_toml: Optional[str] = None,
    old_storage_schema: Optional[str] = None,
    old_storage_schema_format: Optional[str] = None,
    new_storage_schema: Optional[str] = None,
    new_storage_schema_format: Optional[str] = None,
) -> dict[str, Any]: ...
def compare_files(
    old_path: str,
    new_path: str,
    *,
    explain: bool = False,
    strict: bool = False,
    contract: Optional[str] = None,
    suppressions_toml: Optional[str] = None,
    old_storage_schema: Optional[str] = None,
    old_storage_schema_format: Optional[str] = None,
    new_storage_schema: Optional[str] = None,
    new_storage_schema_format: Optional[str] = None,
) -> dict[str, Any]: ...
def engine_version() -> str: ...

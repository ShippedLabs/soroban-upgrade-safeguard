# Inferred Storage Schemas

The storage analyzer scans Soroban SDK-generated WASM for recognizable storage
host calls. It reports the operation and durability when the import name makes
those facts explicit. Keys and values are only populated when the WASM data
flow proves a type; generic `Val` operands remain unknown.

Unknown, indirect, branch-dependent, and unsupported compiler paths are emitted
as coverage gaps. A gap is never converted into an inferred type. This keeps a
passing result honest: `complete: false` means the tool did not have enough
evidence to certify all storage access.

Schemas can be supplied as JSON or TOML declarations. Use
`StorageSchema::reconcile` for one build or `compare_storage_schemas` for an
old/new pair. Results include confidence, mismatches, and coverage gaps and can
be rendered as structured JSON, text, or Markdown.

For worked examples — common key enums, nested values, optional fields, and
partial coverage, each with the resulting scope and finding behavior — see
the [Storage Schema Cookbook](storage-schema-cookbook.md).

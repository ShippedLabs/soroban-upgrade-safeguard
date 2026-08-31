# Empirical Validation Type-Mapping Specification

This document provides the formal type-mapping specification used by `soroban-upgrade-safeguard`'s empirical storage validation engine to decode and validate concrete on-chain `ScVal` XDR objects against expected `ScSpecTypeDef` schemas.

---

## 1. Primitive Type Mappings

Each primitive type in the Soroban Contract Spec corresponds to a specific XDR variant in `ScVal`. Any other variant will trigger a validation error.

| Contract Spec Type | Expected `ScVal` Variant | Validation Logic |
| :--- | :--- | :--- |
| `Val` | Any | Accepts any `ScVal` payload. |
| `Bool` | `ScVal::Bool(bool)` | Must be boolean. |
| `Void` | `ScVal::Void` | Must be void. |
| `Error` | `ScVal::Error(ScError)` | Must be a contract or system error code. |
| `U32` | `ScVal::U32(u32)` | Must be unsigned 32-bit integer. |
| `I32` | `ScVal::I32(i32)` | Must be signed 32-bit integer. |
| `U64` | `ScVal::U64(u64)` | Must be unsigned 64-bit integer. |
| `I64` | `ScVal::I64(i64)` | Must be signed 64-bit integer. |
| `Timepoint` | `ScVal::Timepoint(u64)` | Must be a Timepoint (unsigned 64-bit). |
| `Duration` | `ScVal::Duration(u64)` | Must be a Duration (unsigned 64-bit). |
| `U128` | `ScVal::U128(UInt128Parts)`| Must be unsigned 128-bit integer. |
| `I128` | `ScVal::I128(Int128Parts)` | Must be signed 128-bit integer. |
| `U256` | `ScVal::U256(UInt256Parts)`| Must be unsigned 256-bit integer. |
| `I256` | `ScVal::I256(Int256Parts)` | Must be signed 256-bit integer. |
| `Bytes` | `ScVal::Bytes(VecM<u8>)` | Must be a byte vector. |
| `String` | `ScVal::String(StringM)` | Must be a string. |
| `Symbol` | `ScVal::Symbol(ScSymbol)` | Must be a symbol. |
| `Address` | `ScVal::Address(ScAddress)` | Must be an address (Contract or Account). |

---

## 2. Container Type Mappings

### 2.1 Option
- **Schema**: `ScSpecTypeDef::Option(ScSpecTypeOption)`
- **Valid Values**:
  - `ScVal::Void` (representing `None`).
  - Any valid `ScVal` matching the nested `value_type` schema (representing `Some(value)`).

### 2.2 Result
- **Schema**: `ScSpecTypeDef::Result(ScSpecTypeResult)`
- **Valid Values**:
  - `ScVal::Error(ScError)` (representing `Err(error_type)`).
  - Any valid `ScVal` matching the `ok_type` schema (representing `Ok(value)`).

### 2.3 Vec
- **Schema**: `ScSpecTypeDef::Vec(ScSpecTypeVec)`
- **Valid Values**:
  - `ScVal::Vec(ScVec)`: Each item in `ScVec` must recursively validate against `element_type`.

### 2.4 Map
- **Schema**: `ScSpecTypeDef::Map(ScSpecTypeMap)`
- **Valid Values**:
  - `ScVal::Map(ScMap)`: Each key-value entry in `ScMap` must have a key validating against `key_type` and a value validating against `value_type`.

### 2.5 Tuple
- **Schema**: `ScSpecTypeDef::Tuple(ScSpecTypeTuple)`
- **Valid Values**:
  - `ScVal::Vec(ScVec)`: The length of the vector must match the tuple size. Each element at index `i` must recursively validate against the corresponding tuple type at index `i`.

### 2.6 BytesN
- **Schema**: `ScSpecTypeDef::BytesN(ScSpecTypeBytesN)`
- **Valid Values**:
  - `ScVal::Bytes(VecM<u8>)`: The length of the byte array must be exactly `n` bytes.

---

## 3. User-Defined Type (UDT) Mappings

### 3.1 Structs
Structs can be represented in two layouts:

1. **Map Layout (Named Fields)**:
   - Value must be `ScVal::Map(ScMap)`.
   - For each field in the struct definition:
     - Search for an entry in the map where the key is `ScVal::Symbol` matching the field name.
     - Validate the entry value against the field's schema.
     - If the field is missing, validation fails unless the field is an `Option` type.
     
2. **Vec Layout (Tuple/Unnamed Fields)**:
   - Value must be `ScVal::Vec(ScVec)`.
   - Length must match the field count.
   - Each element at index `i` is validated against the corresponding field schema.

### 3.2 Enums
Enums represent a set of integer values or simple symbolic tags:
- **Symbol representation**: `ScVal::Symbol` matching one of the defined variants.
- **Integer representation**: `ScVal::U32` or `ScVal::I32` matching one of the defined variant integer values.
- **Vec representation**: `ScVal::Vec` where the first element is `ScVal::Symbol` matching the variant name.

### 3.3 Tagged Unions
Unions represent variants that carry optional payloads:
- **Void Variant**: `ScVal::Symbol` or a single-element `ScVal::Vec` containing the variant name.
- **Tuple Variant**: `ScVal::Vec` where the first element is `ScVal::Symbol` representing the variant name, and subsequent elements represent the variant's payload fields.

---

## 4. Appendix: Troubleshooting Decode Errors

Common decode errors emitted during empirical checks and their root causes:

### 4.1 `expected u128, got ScVal::U64(...)`
- **Cause**: A struct or union field was upgraded from `u64` to `u128` (or vice-versa). 
- **Remediation**: Revert the type change or implement a custom state migration contract.

### 4.2 `missing required field 'X'`
- **Cause**: A new required field `X` was added to a struct. Stored layout map entries created by the old code do not have this field.
- **Remediation**: Wrap the new field in an `Option` type so it can default to `None` when loading old entries, or perform a manual state initialization.

### 4.3 `tuple size mismatch (expected X, got Y)`
- **Cause**: An unnamed tuple struct or positional tuple had fields added or removed.
- **Remediation**: Do not add/remove fields from tuples since they rely on strict indexing. Instead, define a new named struct or tag version.

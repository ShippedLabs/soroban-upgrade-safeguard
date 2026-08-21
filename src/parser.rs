use std::io::Cursor;
use stellar_xdr::curr::{Limited, Limits, ReadXdr, ScEnvMetaEntry, ScSpecEntry};
use wasmparser::{CompositeType, Parser, Payload, TypeRef, ValType};

use crate::error::Error;
use crate::storage_inference::{infer_storage, StorageInference};

/// The resolved parameter/result types of a function import, when the
/// import's declared type index could be resolved against the module's type
/// section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSignature {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

/// A single function import declared by a WASM module, keyed the same way
/// the WASM binary format itself keys it: a `(module, name)` pair. For
/// Soroban host functions, `module`/`name` are short wire codes (e.g.
/// `("l", "_")` is `put_contract_data`) — see [`crate::capability`] for the
/// mapping to human-readable capability metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedFunction {
    pub module: String,
    pub name: String,
    /// `None` when the import's type index could not be resolved (e.g. it
    /// pointed past the end of the type section); callers must not infer
    /// a signature change from a missing signature on either side.
    pub signature: Option<ImportSignature>,
}

/// Decoded contents of a contract's `contractenvmetav0` custom section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractEnvMeta {
    pub entries: Vec<ScEnvMetaEntry>,
}

impl ContractEnvMeta {
    /// The packed Soroban interface version, when present.
    pub fn interface_version(&self) -> Option<u64> {
        self.entries
            .iter()
            .map(|entry| match entry {
                ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(version) => *version,
            })
            .next()
    }

    /// Ledger / protocol version (high 32 bits of the interface version).
    pub fn protocol_version(&self) -> Option<u32> {
        self.interface_version().map(|v| (v >> 32) as u32)
    }

    /// Pre-release component of the interface version (low 32 bits).
    pub fn pre_release_version(&self) -> Option<u32> {
        self.interface_version().map(|v| v as u32)
    }

    /// Short human-readable summary for report messages.
    pub fn summary(&self) -> String {
        if let Some(version) = self.interface_version() {
            format!("protocol {}, pre-release {}", version >> 32, version as u32)
        } else if self.entries.is_empty() {
            "empty".to_string()
        } else {
            format!("{} environment metadata entries", self.entries.len())
        }
    }
}

/// Represents the extracted Soroban-specific custom sections from a WASM module.
#[derive(Debug, Default)]
pub struct SorobanMetadata {
    pub spec: Vec<ScSpecEntry>,
    pub env_meta: Option<ContractEnvMeta>,
    /// Conservative observations from SDK-generated storage host calls.
    pub storage: StorageInference,
    /// Every function import declared by the module, in declaration order.
    pub host_imports: Vec<ImportedFunction>,
}

/// Decodes concatenated ScSpecEntry XDR objects from raw bytes.
///
/// Soroban custom sections contain multiple XDR-encoded entries back to back.
/// We wrap the data in a `Limited<Cursor>` and call `read_xdr` in a loop,
/// checking the cursor position to detect when all bytes are consumed.
fn decode_spec_entries(data: &[u8]) -> Result<Vec<ScSpecEntry>, Error> {
    let cursor = Cursor::new(data);
    let mut limited = Limited::new(cursor, Limits::none());
    let mut entries = Vec::new();

    while (limited.inner.position() as usize) < data.len() {
        let entry_index = entries.len();
        let byte_offset = limited.inner.position();
        let entry = ScSpecEntry::read_xdr(&mut limited).map_err(|e| Error::XdrDecoding {
            entry_index: Some(entry_index),
            byte_offset: Some(byte_offset),
            details: "Failed to decode ScSpecEntry XDR".to_string(),
            source: Some(Box::new(e)),
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Decodes concatenated ScEnvMetaEntry XDR objects from raw bytes.
fn decode_env_meta_entries(data: &[u8]) -> Result<Vec<ScEnvMetaEntry>, Error> {
    let cursor = Cursor::new(data);
    let mut limited = Limited::new(cursor, Limits::none());
    let mut entries = Vec::new();

    while (limited.inner.position() as usize) < data.len() {
        let entry = ScEnvMetaEntry::read_xdr(&mut limited).map_err(|e| Error::XdrDecoding {
            entry_index: None,
            byte_offset: None,
            details: "Failed to decode ScEnvMetaEntry XDR".to_string(),
            source: Some(Box::new(e)),
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Decodes a `contractenvmetav0` section into a comparable representation.
pub fn decode_env_meta(data: &[u8]) -> Result<ContractEnvMeta, Error> {
    let entries = decode_env_meta_entries(data)?;
    Ok(ContractEnvMeta { entries })
}

/// Parses the WASM bytes to extract Soroban-specific custom sections and decodes them.
pub fn extract_metadata(bytes: &[u8]) -> Result<SorobanMetadata, Error> {
    let mut metadata = SorobanMetadata::default();
    let parser = Parser::new(0);

    let mut spec_section_index = 0usize;
    // Function types declared by the module's type section, in declaration
    // order across all rec groups; `None` for a non-func composite type
    // (structs/arrays from the GC proposal, which Soroban contracts do not
    // use, but which still occupy a slot in the shared type index space).
    let mut func_types: Vec<Option<wasmparser::FuncType>> = Vec::new();

    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| Error::WasmValidation {
            path: None,
            details: "Failed to parse WASM payload".to_string(),
            byte_offset: None,
            source: Some(Box::new(e)),
        })?;

        match payload {
            Payload::TypeSection(reader) => {
                for rec_group in reader {
                    let rec_group = rec_group.map_err(|e| Error::WasmValidation {
                        path: None,
                        details: "Failed to parse WASM type section".to_string(),
                        byte_offset: None,
                        source: Some(Box::new(e)),
                    })?;
                    for sub_type in rec_group.into_types() {
                        let func_type = match sub_type.composite_type {
                            CompositeType::Func(func_type) => Some(func_type),
                            _ => None,
                        };
                        func_types.push(func_type);
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| Error::WasmValidation {
                        path: None,
                        details: "Failed to parse WASM import section".to_string(),
                        byte_offset: None,
                        source: Some(Box::new(e)),
                    })?;

                    if let TypeRef::Func(type_index) = import.ty {
                        let signature = func_types
                            .get(type_index as usize)
                            .and_then(|entry| entry.as_ref())
                            .map(|func_type| ImportSignature {
                                params: func_type.params().to_vec(),
                                results: func_type.results().to_vec(),
                            });
                        metadata.host_imports.push(ImportedFunction {
                            module: import.module.to_string(),
                            name: import.name.to_string(),
                            signature,
                        });
                    }
                }
            }
            Payload::CustomSection(section) => match section.name() {
                "contractspecv0" => {
                    let section_index = spec_section_index;
                    spec_section_index += 1;

                    let entries = decode_spec_entries(section.data()).map_err(|e| {
                        Error::SectionExtraction {
                            section_name: "contractspecv0".to_string(),
                            section_index,
                            byte_offset: section.data_offset() as u64,
                            details: String::new(),
                            source: Some(Box::new(e)),
                        }
                    })?;
                    metadata.spec.extend(entries);
                }
                "contractenvmetav0" => {
                    metadata.env_meta = decode_env_meta(section.data()).ok();
                }
                _ => {}
            },
            _ => {}
        }
    }

    metadata.storage = infer_storage(bytes).map_err(|details| Error::WasmValidation {
        path: None,
        details: format!("Storage analysis failed: {details}"),
        byte_offset: None,
        source: None,
    })?;

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use stellar_xdr::curr::{ScEnvMetaEntry, WriteXdr};

    fn encode_interface_version(protocol: u32, pre_release: u32) -> Vec<u8> {
        let version = ((protocol as u64) << 32) | (pre_release as u64);
        let entry = ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(version);
        let cursor = Cursor::new(Vec::new());
        let mut limited = Limited::new(cursor, Limits::none());
        entry.write_xdr(&mut limited).unwrap();
        limited.inner.into_inner()
    }

    fn fixture_contractspec_bytes() -> Vec<u8> {
        let wasm = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm"),
        )
        .expect("v1.wasm fixture must exist");

        for payload in Parser::new(0).parse_all(&wasm) {
            if let Payload::CustomSection(section) = payload.expect("valid wasm payload") {
                if section.name() == "contractspecv0" {
                    return section.data().to_vec();
                }
            }
        }

        panic!("v1.wasm fixture must contain a contractspecv0 section");
    }

    fn wasm_with_custom_section(name: &str, data: &[u8]) -> Vec<u8> {
        let section_size = 1 + name.len() + data.len();
        assert!(
            section_size < 128,
            "test helper only encodes small sections"
        );

        let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        wasm.push(0);
        wasm.push(section_size as u8);
        wasm.push(name.len() as u8);
        wasm.extend_from_slice(name.as_bytes());
        wasm.extend_from_slice(data);
        wasm
    }

    fn uleb(mut value: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn wasm_string(s: &str) -> Vec<u8> {
        let mut out = uleb(s.len() as u32);
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn wasm_section(id: u8, body: Vec<u8>) -> Vec<u8> {
        let mut out = vec![id];
        out.extend(uleb(body.len() as u32));
        out.extend(body);
        out
    }

    /// Builds a minimal WASM module with a type section declaring
    /// `func_param_counts` (each `(params, results)` pair becomes one func
    /// type of that many i32 params/results) and an import section
    /// declaring `imports` as `(module, name, type_index)` function imports.
    fn wasm_with_imports(func_signatures: &[(u32, u32)], imports: &[(&str, &str, u32)]) -> Vec<u8> {
        let mut type_body = uleb(func_signatures.len() as u32);
        for &(params, results) in func_signatures {
            type_body.push(0x60); // func type tag
            type_body.extend(uleb(params));
            type_body.extend(std::iter::repeat_n(0x7f, params as usize)); // i32
            type_body.extend(uleb(results));
            type_body.extend(std::iter::repeat_n(0x7f, results as usize)); // i32
        }

        let mut import_body = uleb(imports.len() as u32);
        for &(module, name, type_index) in imports {
            import_body.extend(wasm_string(module));
            import_body.extend(wasm_string(name));
            import_body.push(0x00); // external kind: func
            import_body.extend(uleb(type_index));
        }

        let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        wasm.extend(wasm_section(1, type_body));
        wasm.extend(wasm_section(2, import_body));
        wasm
    }

    #[test]
    fn extract_metadata_resolves_recognized_and_unknown_host_imports() {
        // type 0: () -> ()          type 1: (i32) -> ()
        let wasm = wasm_with_imports(
            &[(0, 0), (1, 0)],
            &[
                ("l", "_", 0),       // put_contract_data (recognized, protocol 20)
                ("zz", "custom", 1), // unrecognized provider-specific import
            ],
        );

        let metadata = extract_metadata(&wasm).expect("valid minimal module");
        assert_eq!(metadata.host_imports.len(), 2);

        let put_contract_data = &metadata.host_imports[0];
        assert_eq!(put_contract_data.module, "l");
        assert_eq!(put_contract_data.name, "_");
        let sig = put_contract_data
            .signature
            .as_ref()
            .expect("type index 0 must resolve");
        assert!(sig.params.is_empty());
        assert!(sig.results.is_empty());

        let unknown = &metadata.host_imports[1];
        assert_eq!(unknown.module, "zz");
        assert_eq!(unknown.name, "custom");
        let sig = unknown
            .signature
            .as_ref()
            .expect("type index 1 must resolve");
        assert_eq!(sig.params, vec![ValType::I32]);
        assert!(sig.results.is_empty());
    }

    #[test]
    fn extract_metadata_leaves_signature_none_for_an_out_of_range_type_index() {
        let wasm = wasm_with_imports(&[(0, 0)], &[("l", "_", 7)]);
        let metadata = extract_metadata(&wasm).expect("valid minimal module");

        assert_eq!(metadata.host_imports.len(), 1);
        assert!(metadata.host_imports[0].signature.is_none());
    }

    #[test]
    fn extract_metadata_reports_no_host_imports_for_a_module_without_any() {
        let wasm = wasm_with_custom_section("contractenvmetav0", &encode_interface_version(20, 0));
        let metadata = extract_metadata(&wasm).expect("valid minimal module");
        assert!(metadata.host_imports.is_empty());
    }

    #[test]
    fn decode_env_meta_reads_interface_version() {
        let bytes = encode_interface_version(21, 0);
        let meta = decode_env_meta(&bytes).unwrap();

        assert_eq!(meta.protocol_version(), Some(21));
        assert_eq!(meta.pre_release_version(), Some(0));
        assert_eq!(meta.interface_version(), Some(21 << 32));
    }

    #[test]
    fn decode_env_meta_rejects_truncated_bytes() {
        let bytes = encode_interface_version(21, 0);
        assert!(decode_env_meta(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn decode_spec_entries_reports_entry_index_and_offset_for_truncated_bytes() {
        let bytes = fixture_contractspec_bytes();
        let decoded_entries = decode_spec_entries(&bytes).expect("fixture spec must decode");
        assert!(
            decoded_entries.len() > 1,
            "fixture should contain enough entries to verify the failing index"
        );

        let error =
            decode_spec_entries(&bytes[..bytes.len() - 1]).expect_err("truncated spec must fail");
        let message = error.to_string();

        assert!(
            message.contains(&format!("entry index {}", decoded_entries.len() - 1)),
            "error should name the failing entry index, got: {message}"
        );
        assert!(
            message.contains("byte offset"),
            "error should name the failing byte offset, got: {message}"
        );
    }

    #[test]
    fn extract_metadata_reports_contractspec_section_offset_for_decode_errors() {
        let wasm = wasm_with_custom_section("contractspecv0", &[0x00]);
        let error = extract_metadata(&wasm).expect_err("invalid spec section must fail");
        let mut messages = vec![error.to_string()];
        use std::error::Error as StdError;
        let mut current = StdError::source(&error);
        while let Some(err) = current {
            messages.push(err.to_string());
            current = err.source();
        }

        assert!(
            messages.iter().any(|message| {
                message.contains("contractspecv0 section 0") && message.contains("byte offset")
            }),
            "error chain should name the contractspecv0 section offset, got: {messages:?}"
        );
        assert!(
            messages.iter().any(|message| {
                message.contains("ScSpecEntry XDR") && message.contains("entry index 0")
            }),
            "error chain should include the failing spec entry index, got: {messages:?}"
        );
    }

    #[test]
    fn extract_metadata_skips_invalid_env_meta_without_error() {
        let wasm = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wasm/v1.wasm"),
        )
        .expect("v1.wasm fixture must exist");

        let metadata = extract_metadata(&wasm).expect("valid wasm must parse");
        assert!(
            metadata.env_meta.is_some(),
            "fixture wasm should contain decodable env metadata"
        );
    }
}

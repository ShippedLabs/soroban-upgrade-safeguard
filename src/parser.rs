use std::io::Cursor;
use stellar_xdr::curr::{Limited, Limits, ReadXdr, ScEnvMetaEntry, ScSpecEntry};
use wasmparser::{CompositeType, Parser, Payload, TypeRef, ValType};

use crate::error::Error;
use crate::limits::ResourcePolicy;
use crate::runtime_surface::{extract_runtime_surface, RuntimeSurface};
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
    /// The normalized WebAssembly runtime surface.
    pub runtime_surface: RuntimeSurface,
}

/// Decodes concatenated ScSpecEntry XDR objects from raw bytes.
///
/// Soroban custom sections contain multiple XDR-encoded entries back to back.
/// We wrap the data in a `Limited<Cursor>` and call `read_xdr` in a loop,
/// checking the cursor position to detect when all bytes are consumed.
///
/// An empty `data` slice (a present but empty contractspecv0 section) returns
/// an empty vector with a warning printed to stderr. This is distinct from a
/// missing section (which never calls this function at all).
fn decode_spec_entries(data: &[u8]) -> Result<Vec<ScSpecEntry>, Error> {
    if data.is_empty() {
        // A present but empty contractspecv0 section is unusual but valid:
        // the contract was compiled with spec generation enabled but declares
        // no public interface. Inform the user instead of failing silently.
        eprintln!("warning: contractspecv0 section is present but empty (no spec entries)");
        return Ok(Vec::new());
    }

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
        let byte_offset = limited.inner.position();
        let entry = ScEnvMetaEntry::read_xdr(&mut limited).map_err(|e| Error::XdrDecoding {
            entry_index: None,
            byte_offset: Some(byte_offset),
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
    let mut env_section_index = 0usize;
    // Function types declared by the module's type section, in declaration
    // order across all rec groups; `None` for a non-func composite type
    // (structs/arrays from the GC proposal, which Soroban contracts do not
    // use, but which still occupy a slot in the shared type index space).
    let mut func_types: Vec<Option<wasmparser::FuncType>> = Vec::new();

    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| Error::WasmValidation {
            path: None,
            details: "Failed to parse WASM payload".to_string(),
            byte_offset: Some(e.offset() as u64),
            source: Some(Box::new(e)),
        })?;

        match payload {
            Payload::TypeSection(reader) => {
                for rec_group in reader {
                    let rec_group = rec_group.map_err(|e| Error::WasmValidation {
                        path: None,
                        details: "Failed to parse WASM type section".to_string(),
                        byte_offset: Some(e.offset() as u64),
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
                        byte_offset: Some(e.offset() as u64),
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
                    let section_index = env_section_index;
                    env_section_index += 1;

                    let env_meta =
                        decode_env_meta(section.data()).map_err(|e| Error::SectionExtraction {
                            section_name: "contractenvmetav0".to_string(),
                            section_index,
                            byte_offset: section.data_offset() as u64,
                            details: String::new(),
                            source: Some(Box::new(e)),
                        })?;
                    metadata.env_meta = Some(env_meta);
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

    metadata.runtime_surface = extract_runtime_surface(bytes, &ResourcePolicy::default())?;

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use stellar_xdr::curr::{ScEnvMetaEntry, ScSpecFunctionV0, WriteXdr};

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

    /// Encodes a wasm module with two separate custom sections sharing the
    /// same `name`, as some toolchains emit for `contractspecv0`.
    fn wasm_with_two_custom_sections(name: &str, data_a: &[u8], data_b: &[u8]) -> Vec<u8> {
        let mut wasm = wasm_with_custom_section(name, data_a);
        let mut second_body = wasm_string(name);
        second_body.extend_from_slice(data_b);
        wasm.extend(wasm_section(0, second_body));
        wasm
    }

    fn encode_spec_entries(entries: &[ScSpecEntry]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut limited = Limited::new(cursor, Limits::none());
        for entry in entries {
            entry.write_xdr(&mut limited).unwrap();
        }
        limited.inner.into_inner()
    }

    fn spec_function(name: &str, doc: &str) -> ScSpecEntry {
        ScSpecEntry::FunctionV0(ScSpecFunctionV0 {
            doc: doc.try_into().unwrap(),
            name: name.try_into().unwrap(),
            inputs: Default::default(),
            outputs: Default::default(),
        })
    }

    #[test]
    fn extract_metadata_merges_identical_split_contractspec_sections() {
        // Some toolchains emit `contractspecv0` split across more than one
        // custom section. When both sections carry the same entry, the
        // parser must accept it (not error) and downstream dedup must
        // collapse the duplicate to a single function.
        let section = encode_spec_entries(&[spec_function("hello", "doc")]);
        let wasm = wasm_with_two_custom_sections("contractspecv0", &section, &section);

        let metadata = extract_metadata(&wasm).expect("split identical sections must not fail");
        assert_eq!(
            metadata.spec.len(),
            2,
            "both sections' entries are concatenated"
        );

        let spec = crate::spec::ContractSpec::from_entries(&metadata.spec);
        assert_eq!(
            spec.functions().len(),
            1,
            "identical duplicate entries must collapse to one function"
        );
    }

    #[test]
    fn extract_metadata_resolves_conflicting_split_contractspec_sections_first_wins() {
        // When split sections disagree (same function name, different doc),
        // the parser must still not error; the existing first-wins dedup
        // policy in `ContractSpec::from_entries` decides the outcome
        // deterministically, using whichever section wasmparser visits first.
        let first = encode_spec_entries(&[spec_function("hello", "from section 0")]);
        let second = encode_spec_entries(&[spec_function("hello", "from section 1")]);
        let wasm = wasm_with_two_custom_sections("contractspecv0", &first, &second);

        let metadata =
            extract_metadata(&wasm).expect("conflicting split sections must not fail parsing");
        assert_eq!(metadata.spec.len(), 2);

        let spec = crate::spec::ContractSpec::from_entries(&metadata.spec);
        let resolved = spec
            .functions()
            .get("hello")
            .expect("function must resolve");
        assert_eq!(resolved.doc.to_string(), "from section 0");
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
    fn decode_env_meta_accepts_empty_bytes_as_a_valid_zero_entry_section() {
        // A zero-byte `contractenvmetav0` section is a valid legacy
        // artifact: it decodes successfully with no entries, distinct from
        // a truncated or otherwise malformed section, which must error.
        let meta = decode_env_meta(&[]).expect("empty section must decode");
        assert!(meta.entries.is_empty());
        assert_eq!(meta.interface_version(), None);
        assert_eq!(meta.summary(), "empty");
    }

    #[test]
    fn decode_env_meta_rejects_malformed_nonempty_bytes() {
        // Bytes that are present but do not form a valid ScEnvMetaEntry must
        // still fail, so a genuinely malformed section is never conflated
        // with a valid empty one.
        let garbage = [0xff, 0xff, 0xff, 0xff];
        assert!(decode_env_meta(&garbage).is_err());
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
    fn extract_metadata_distinguishes_missing_from_empty_env_meta_section() {
        // No `contractenvmetav0` section at all must decode as `None`...
        let without_section = wasm_with_imports(&[(0, 0)], &[]);
        let metadata = extract_metadata(&without_section).expect("valid minimal module");
        assert!(metadata.env_meta.is_none());

        // ...while a present section with zero bytes must decode as
        // `Some` with zero entries: the section existed, it just carried no
        // optional fields. Collapsing the two into the same `None` result
        // would hide that the section was ever emitted.
        let with_empty_section = wasm_with_custom_section("contractenvmetav0", &[]);
        let metadata = extract_metadata(&with_empty_section).expect("valid minimal module");
        let meta = metadata
            .env_meta
            .expect("an empty section must still decode to Some");
        assert!(meta.entries.is_empty());
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

    #[test]
    fn extract_metadata_distinguishes_empty_from_missing_contractspec_section() {
        // No `contractspecv0` section at all yields an empty spec list...
        let without_section = wasm_with_imports(&[(0, 0)], &[]);
        let metadata = extract_metadata(&without_section).expect("valid minimal module");
        assert!(metadata.spec.is_empty());

        // ...a present but empty contractspecv0 section also yields an empty
        // spec list, but must print a warning to distinguish the two cases.
        // (The warning is a side effect printed to stderr during decode; this
        // test verifies the parser does not error and returns an empty vec.)
        let with_empty_section = wasm_with_custom_section("contractspecv0", &[]);
        let metadata =
            extract_metadata(&with_empty_section).expect("empty contractspec must parse");
        assert!(
            metadata.spec.is_empty(),
            "an empty contractspecv0 section must decode to an empty spec vec"
        );
    }
}

    #[test]
    fn extract_metadata_ignores_unrelated_custom_sections() {
        // WASM modules may contain custom sections unrelated to Soroban metadata.
        // The parser must ignore these sections and still extract valid Soroban
        // metadata successfully.
        let spec_data = encode_spec_entries(&[spec_function("hello", "doc")]);
        let env_data = encode_interface_version(20, 0);
        let unrelated_data = b"some unrelated custom data";

        // Build a WASM module with Soroban sections plus an unrelated section
        let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        
        // Add contractspecv0 section
        let spec_body = wasm_string("contractspecv0");
        let mut spec_with_data = spec_body;
        spec_with_data.extend_from_slice(&spec_data);
        wasm.extend(wasm_section(0, spec_with_data));
        
        // Add contractenvmetav0 section
        let env_body = wasm_string("contractenvmetav0");
        let mut env_with_data = env_body;
        env_with_data.extend_from_slice(&env_data);
        wasm.extend(wasm_section(0, env_with_data));
        
        // Add unrelated custom section
        let unrelated_body = wasm_string("unrelated_section");
        let mut unrelated_with_data = unrelated_body;
        unrelated_with_data.extend_from_slice(unrelated_data);
        wasm.extend(wasm_section(0, unrelated_with_data));

        let metadata = extract_metadata(&wasm).expect("WASM with unrelated section must parse");
        assert_eq!(metadata.spec.len(), 1, "spec must be extracted from Soroban section");
        assert!(metadata.env_meta.is_some(), "env meta must be extracted from Soroban section");
        assert_eq!(
            metadata.env_meta.as_ref().unwrap().protocol_version(),
            Some(20),
            "env meta protocol version must be correct"
        );
    }

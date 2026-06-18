use anyhow::{Context, Result};
use std::io::Cursor;
use stellar_xdr::curr::{Limited, Limits, ReadXdr, ScSpecEntry};
use wasmparser::{Parser, Payload};

/// Represents the extracted Soroban-specific custom sections from a WASM module.
#[derive(Debug, Default)]
pub struct SorobanMetadata {
    pub spec: Vec<ScSpecEntry>,
    pub env_meta: Option<Vec<u8>>,
}

/// Decodes concatenated ScSpecEntry XDR objects from raw bytes.
///
/// Soroban custom sections contain multiple XDR-encoded entries back to back.
/// We wrap the data in a `Limited<Cursor>` and call `read_xdr` in a loop,
/// checking the cursor position to detect when all bytes are consumed.
fn decode_spec_entries(data: &[u8]) -> Result<Vec<ScSpecEntry>> {
    let cursor = Cursor::new(data);
    let mut limited = Limited::new(cursor, Limits::none());
    let mut entries = Vec::new();

    while (limited.inner.position() as usize) < data.len() {
        let entry =
            ScSpecEntry::read_xdr(&mut limited).context("Failed to decode ScSpecEntry XDR")?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Parses the WASM bytes to extract Soroban-specific custom sections and decodes them.
pub fn extract_metadata(bytes: &[u8]) -> Result<SorobanMetadata> {
    let mut metadata = SorobanMetadata::default();
    let parser = Parser::new(0);

    for payload in parser.parse_all(bytes) {
        if let Payload::CustomSection(section) = payload.context("Failed to parse WASM payload")? {
            match section.name() {
                "contractspecv0" => {
                    let entries = decode_spec_entries(section.data())
                        .context("Failed to decode contractspecv0 section")?;
                    metadata.spec.extend(entries);
                }
                "contractenvmetav0" => {
                    metadata.env_meta = Some(section.data().to_vec());
                }
                _ => {}
            }
        }
    }

    Ok(metadata)
}

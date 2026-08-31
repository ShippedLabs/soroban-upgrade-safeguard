use std::collections::HashSet;
use stellar_xdr::curr::{ContractDataEntry, ScSpecTypeDef, ScSpecUdtUnionCaseV0, ScVal};

use crate::diff::Finding;
use crate::spec::ContractSpec;
use serde_json::Value;
use std::path::Path;
use stellar_xdr::curr::{LedgerEntry, LedgerEntryData, Limits, ReadXdr};

/// An empirical finding representing the validation result of a specific storage entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmpiricalFinding {
    pub entry_key_desc: String,
    pub type_name: String,
    pub path: String,
    pub error: Option<String>,
    pub is_success: bool,
}

/// Helper to load storage entries from a JSON file offline.
pub fn load_empirical_entries(path: &Path) -> Result<Vec<ContractDataEntry>, crate::error::Error> {
    let content = std::fs::read_to_string(path).map_err(|e| crate::error::Error::FileAccess {
        path: path.to_path_buf(),
        details: format!("Failed to read empirical file: {}", e),
        source: Some(Box::new(e)),
    })?;

    let val: Value =
        serde_json::from_str(&content).map_err(|e| crate::error::Error::XdrDecoding {
            entry_index: None,
            byte_offset: None,
            details: format!("Failed to parse empirical JSON: {}", e),
            source: Some(Box::new(e)),
        })?;

    let mut raw_strings = Vec::new();
    if let Some(arr) = val.as_array() {
        for v in arr {
            if let Some(s) = v.as_str() {
                raw_strings.push(s.to_string());
            } else if let Some(xdr_val) = v.get("xdr").and_then(|x| x.as_str()) {
                raw_strings.push(xdr_val.to_string());
            }
        }
    } else if let Some(entries) = val.get("entries").and_then(|e| e.as_array()) {
        for v in entries {
            if let Some(s) = v.as_str() {
                raw_strings.push(s.to_string());
            } else if let Some(xdr_val) = v.get("xdr").and_then(|x| x.as_str()) {
                raw_strings.push(xdr_val.to_string());
            }
        }
    } else {
        return Err(crate::error::Error::InvalidInput {
            details: "Empirical JSON must be an array of strings or contain an 'entries' array"
                .to_string(),
        });
    }

    let mut contract_entries = Vec::new();
    for (i, raw_b64) in raw_strings.iter().enumerate() {
        if let Ok(entry) = LedgerEntry::from_xdr_base64(raw_b64, Limits::none()) {
            if let LedgerEntryData::ContractData(cd) = entry.data {
                contract_entries.push(cd);
            }
        } else if let Ok(cd) = ContractDataEntry::from_xdr_base64(raw_b64, Limits::none()) {
            contract_entries.push(cd);
        } else {
            return Err(crate::error::Error::XdrDecoding {
                entry_index: Some(i),
                byte_offset: None,
                details: format!(
                    "Failed to decode base64 XDR as LedgerEntry or ContractDataEntry: {}",
                    raw_b64
                ),
                source: None,
            });
        }
    }

    Ok(contract_entries)
}

/// Helper to check if a type is an Option.
fn is_option_type(t: &ScSpecTypeDef) -> bool {
    matches!(t, ScSpecTypeDef::Option(_))
}

/// Recursively validate a concrete ScVal against a spec type definition.
pub fn validate_scval_type(
    val: &ScVal,
    type_def: &ScSpecTypeDef,
    spec: &ContractSpec,
    path: &str,
) -> Result<(), String> {
    match type_def {
        ScSpecTypeDef::Val => Ok(()), // generic Val accepts anything
        ScSpecTypeDef::Bool => match val {
            ScVal::Bool(_) => Ok(()),
            _ => Err(format!("{}: expected bool, got {:?}", path, val)),
        },
        ScSpecTypeDef::Void => match val {
            ScVal::Void => Ok(()),
            _ => Err(format!("{}: expected void, got {:?}", path, val)),
        },
        ScSpecTypeDef::Error => match val {
            ScVal::Error(_) => Ok(()),
            _ => Err(format!("{}: expected Error, got {:?}", path, val)),
        },
        ScSpecTypeDef::U32 => match val {
            ScVal::U32(_) => Ok(()),
            _ => Err(format!("{}: expected u32, got {:?}", path, val)),
        },
        ScSpecTypeDef::I32 => match val {
            ScVal::I32(_) => Ok(()),
            _ => Err(format!("{}: expected i32, got {:?}", path, val)),
        },
        ScSpecTypeDef::U64 => match val {
            ScVal::U64(_) => Ok(()),
            _ => Err(format!("{}: expected u64, got {:?}", path, val)),
        },
        ScSpecTypeDef::I64 => match val {
            ScVal::I64(_) => Ok(()),
            _ => Err(format!("{}: expected i64, got {:?}", path, val)),
        },
        ScSpecTypeDef::Timepoint => match val {
            ScVal::Timepoint(_) => Ok(()),
            _ => Err(format!("{}: expected Timepoint, got {:?}", path, val)),
        },
        ScSpecTypeDef::Duration => match val {
            ScVal::Duration(_) => Ok(()),
            _ => Err(format!("{}: expected Duration, got {:?}", path, val)),
        },
        ScSpecTypeDef::U128 => match val {
            ScVal::U128(_) => Ok(()),
            _ => Err(format!("{}: expected u128, got {:?}", path, val)),
        },
        ScSpecTypeDef::I128 => match val {
            ScVal::I128(_) => Ok(()),
            _ => Err(format!("{}: expected i128, got {:?}", path, val)),
        },
        ScSpecTypeDef::U256 => match val {
            ScVal::U256(_) => Ok(()),
            _ => Err(format!("{}: expected u256, got {:?}", path, val)),
        },
        ScSpecTypeDef::I256 => match val {
            ScVal::I256(_) => Ok(()),
            _ => Err(format!("{}: expected i256, got {:?}", path, val)),
        },
        ScSpecTypeDef::Bytes => match val {
            ScVal::Bytes(_) => Ok(()),
            _ => Err(format!("{}: expected Bytes, got {:?}", path, val)),
        },
        ScSpecTypeDef::String => match val {
            ScVal::String(_) => Ok(()),
            _ => Err(format!("{}: expected String, got {:?}", path, val)),
        },
        ScSpecTypeDef::Symbol => match val {
            ScVal::Symbol(_) => Ok(()),
            _ => Err(format!("{}: expected Symbol, got {:?}", path, val)),
        },
        ScSpecTypeDef::Address => match val {
            ScVal::Address(_) => Ok(()),
            _ => Err(format!("{}: expected Address, got {:?}", path, val)),
        },
        ScSpecTypeDef::Option(opt) => match val {
            ScVal::Void => Ok(()),
            _ => validate_scval_type(val, &opt.value_type, spec, path),
        },
        ScSpecTypeDef::Result(res) => match val {
            ScVal::Error(_) => {
                validate_scval_type(val, &res.error_type, spec, &format!("{}.ResultErr", path))
            }
            _ => validate_scval_type(val, &res.ok_type, spec, &format!("{}.ResultOk", path)),
        },
        ScSpecTypeDef::Vec(vec_def) => match val {
            ScVal::Vec(Some(sc_vec)) => {
                for (i, elem) in sc_vec.0.iter().enumerate() {
                    validate_scval_type(
                        elem,
                        &vec_def.element_type,
                        spec,
                        &format!("{}[{}]", path, i),
                    )?;
                }
                Ok(())
            }
            _ => Err(format!("{}: expected Vec, got {:?}", path, val)),
        },
        ScSpecTypeDef::Map(map_def) => match val {
            ScVal::Map(Some(sc_map)) => {
                for (i, entry) in sc_map.0.iter().enumerate() {
                    validate_scval_type(
                        &entry.key,
                        &map_def.key_type,
                        spec,
                        &format!("{}.key[{}]", path, i),
                    )?;
                    validate_scval_type(
                        &entry.val,
                        &map_def.value_type,
                        spec,
                        &format!("{}.val[{}]", path, i),
                    )?;
                }
                Ok(())
            }
            _ => Err(format!("{}: expected Map, got {:?}", path, val)),
        },
        ScSpecTypeDef::Tuple(tuple_def) => match val {
            ScVal::Vec(Some(sc_vec)) => {
                let elements = &sc_vec.0;
                let expected_types = &tuple_def.value_types;
                if elements.len() != expected_types.len() {
                    return Err(format!(
                        "{}: tuple size mismatch (expected {}, got {})",
                        path,
                        expected_types.len(),
                        elements.len()
                    ));
                }
                for (i, (elem, expected_t)) in
                    elements.iter().zip(expected_types.iter()).enumerate()
                {
                    validate_scval_type(elem, expected_t, spec, &format!("{}.{}", path, i))?;
                }
                Ok(())
            }
            _ => Err(format!("{}: expected Tuple (Vec), got {:?}", path, val)),
        },
        ScSpecTypeDef::BytesN(b_def) => match val {
            ScVal::Bytes(bytes) => {
                if bytes.0.len() == b_def.n as usize {
                    Ok(())
                } else {
                    Err(format!(
                        "{}: expected BytesN({}), got bytes of length {}",
                        path,
                        b_def.n,
                        bytes.0.len()
                    ))
                }
            }
            _ => Err(format!("{}: expected BytesN, got {:?}", path, val)),
        },
        ScSpecTypeDef::Udt(udt_def) => {
            let udt_name = udt_def.name.to_string();
            validate_scval_udt(val, &udt_name, spec, path)
        }
    }
}

/// Validate a concrete ScVal against a spec User-Defined Type (UDT).
pub fn validate_scval_udt(
    val: &ScVal,
    udt_name: &str,
    spec: &ContractSpec,
    path: &str,
) -> Result<(), String> {
    if let Some(struct_def) = spec.structs.get(udt_name) {
        match val {
            ScVal::Map(Some(sc_map)) => {
                let entries = &sc_map.0;
                for field in struct_def.fields.iter() {
                    let f_name = field.name.to_string();
                    let found_entry = entries.iter().find(|e| match &e.key {
                        ScVal::Symbol(sym) => sym.to_string() == f_name,
                        _ => false,
                    });
                    match found_entry {
                        Some(entry) => {
                            validate_scval_type(
                                &entry.val,
                                &field.type_,
                                spec,
                                &format!("{}.{}", path, f_name),
                            )?;
                        }
                        None => {
                            if !is_option_type(&field.type_) {
                                return Err(format!(
                                    "{}: missing required field '{}'",
                                    path, f_name
                                ));
                            }
                        }
                    }
                }
                Ok(())
            }
            ScVal::Vec(Some(sc_vec)) => {
                let elements = &sc_vec.0;
                if elements.len() != struct_def.fields.len() {
                    return Err(format!(
                        "{}: struct field count mismatch (expected {}, got {})",
                        path,
                        struct_def.fields.len(),
                        elements.len()
                    ));
                }
                for (elem, field) in elements.iter().zip(struct_def.fields.iter()) {
                    validate_scval_type(
                        elem,
                        &field.type_,
                        spec,
                        &format!("{}.{}", path, field.name),
                    )?;
                }
                Ok(())
            }
            _ => Err(format!(
                "{}: expected struct '{}', got {:?}",
                path, udt_name, val
            )),
        }
    } else if let Some(enum_def) = spec.enums.get(udt_name) {
        match val {
            ScVal::Symbol(sym) => {
                let name = sym.to_string();
                if enum_def.cases.iter().any(|c| c.name.to_string() == name) {
                    Ok(())
                } else {
                    Err(format!(
                        "{}: invalid enum variant '{}' for enum '{}'",
                        path, name, udt_name
                    ))
                }
            }
            ScVal::Vec(Some(sc_vec)) => {
                let elements = &sc_vec.0;
                if elements.is_empty() {
                    return Err(format!("{}: empty vec for enum '{}'", path, udt_name));
                }
                match &elements[0] {
                    ScVal::Symbol(sym) => {
                        let name = sym.to_string();
                        if enum_def.cases.iter().any(|c| c.name.to_string() == name) {
                            Ok(())
                        } else {
                            Err(format!(
                                "{}: invalid enum variant '{}' for enum '{}'",
                                path, name, udt_name
                            ))
                        }
                    }
                    _ => Err(format!(
                        "{}: expected Symbol as enum variant name, got {:?}",
                        path, elements[0]
                    )),
                }
            }
            ScVal::U32(v) => {
                if enum_def.cases.iter().any(|c| c.value == *v) {
                    Ok(())
                } else {
                    Err(format!(
                        "{}: invalid enum value {} for enum '{}'",
                        path, v, udt_name
                    ))
                }
            }
            ScVal::I32(v) => {
                if enum_def.cases.iter().any(|c| c.value as i32 == *v) {
                    Ok(())
                } else {
                    Err(format!(
                        "{}: invalid enum value {} for enum '{}'",
                        path, v, udt_name
                    ))
                }
            }
            _ => Err(format!(
                "{}: expected enum '{}', got {:?}",
                path, udt_name, val
            )),
        }
    } else if let Some(union_def) = spec.unions.get(udt_name) {
        match val {
            ScVal::Symbol(sym) => {
                let name = sym.to_string();
                let case = union_def.cases.iter().find(|c| match c {
                    ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string() == name,
                    ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string() == name,
                });
                match case {
                    Some(ScSpecUdtUnionCaseV0::VoidV0(_)) => Ok(()),
                    Some(ScSpecUdtUnionCaseV0::TupleV0(t)) if t.type_.is_empty() => Ok(()),
                    Some(_) => Err(format!(
                        "{}: union variant '{}' expects payload values",
                        path, name
                    )),
                    None => Err(format!(
                        "{}: invalid union variant '{}' for union '{}'",
                        path, name, udt_name
                    )),
                }
            }
            ScVal::Vec(Some(sc_vec)) => {
                let elements = &sc_vec.0;
                if elements.is_empty() {
                    return Err(format!("{}: empty vec for union '{}'", path, udt_name));
                }
                match &elements[0] {
                    ScVal::Symbol(sym) => {
                        let name = sym.to_string();
                        let case = union_def.cases.iter().find(|c| match c {
                            ScSpecUdtUnionCaseV0::VoidV0(v) => v.name.to_string() == name,
                            ScSpecUdtUnionCaseV0::TupleV0(t) => t.name.to_string() == name,
                        });
                        match case {
                            Some(ScSpecUdtUnionCaseV0::VoidV0(_)) => {
                                if elements.len() == 1 {
                                    Ok(())
                                } else {
                                    Err(format!(
                                        "{}: union variant '{}' expects no payload",
                                        path, name
                                    ))
                                }
                            }
                            Some(ScSpecUdtUnionCaseV0::TupleV0(t)) => {
                                let payload_types = &t.type_;
                                if elements.len() - 1 != payload_types.len() {
                                    return Err(format!("{}: union variant '{}' payload count mismatch (expected {}, got {})", path, name, payload_types.len(), elements.len() - 1));
                                }
                                for (i, (elem, expected_t)) in
                                    elements[1..].iter().zip(payload_types.iter()).enumerate()
                                {
                                    validate_scval_type(
                                        elem,
                                        expected_t,
                                        spec,
                                        &format!("{}.{}[{}]", path, name, i),
                                    )?;
                                }
                                Ok(())
                            }
                            None => Err(format!(
                                "{}: invalid union variant '{}' for union '{}'",
                                path, name, udt_name
                            )),
                        }
                    }
                    _ => Err(format!(
                        "{}: expected Symbol as union variant name, got {:?}",
                        path, elements[0]
                    )),
                }
            }
            _ => Err(format!(
                "{}: expected union '{}', got {:?}",
                path, udt_name, val
            )),
        }
    } else {
        Err(format!("{}: unknown UDT '{}'", path, udt_name))
    }
}

/// Recursively find all sub-values in `val` that decode successfully as `udt_name` under `old_spec`.
pub fn find_scval_candidates(
    val: &ScVal,
    udt_name: &str,
    old_spec: &ContractSpec,
    candidates: &mut Vec<ScVal>,
) {
    if validate_scval_udt(val, udt_name, old_spec, udt_name).is_ok() && !candidates.contains(val) {
        candidates.push(val.clone());
    }
    match val {
        ScVal::Vec(Some(sc_vec)) => {
            for elem in sc_vec.0.iter() {
                find_scval_candidates(elem, udt_name, old_spec, candidates);
            }
        }
        ScVal::Map(Some(sc_map)) => {
            for entry in sc_map.0.iter() {
                find_scval_candidates(&entry.key, udt_name, old_spec, candidates);
                find_scval_candidates(&entry.val, udt_name, old_spec, candidates);
            }
        }
        _ => {}
    }
}

/// Runs empirical check for structural findings using sampled storage entries.
pub fn run_empirical_check(
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
    entries: &[ContractDataEntry],
    structural_findings: &[Finding],
) -> Vec<EmpiricalFinding> {
    let mut empirical_findings = Vec::new();
    let mut checked_types = HashSet::new();

    for finding in structural_findings {
        if let Some(ref udt_name) = finding.type_name {
            if !checked_types.insert(udt_name.clone()) {
                continue;
            }

            // Find all candidates for this type in our storage entries
            let mut candidates = Vec::new();
            for entry in entries {
                find_scval_candidates(&entry.key, udt_name, old_spec, &mut candidates);
                find_scval_candidates(&entry.val, udt_name, old_spec, &mut candidates);
            }

            for cand in candidates {
                let desc = format!("{:?}", cand);
                match validate_scval_udt(&cand, udt_name, new_spec, udt_name) {
                    Ok(()) => {
                        empirical_findings.push(EmpiricalFinding {
                            entry_key_desc: desc,
                            type_name: udt_name.clone(),
                            path: udt_name.to_string(),
                            error: None,
                            is_success: true,
                        });
                    }
                    Err(e) => {
                        empirical_findings.push(EmpiricalFinding {
                            entry_key_desc: desc,
                            type_name: udt_name.clone(),
                            path: udt_name.to_string(),
                            error: Some(e),
                            is_success: false,
                        });
                    }
                }
            }
        }
    }

    empirical_findings
}

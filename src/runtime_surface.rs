//! WebAssembly module runtime surface model, parser, and comparison.
//!
//! Beyond contract specs, imports, and exports, other WebAssembly module
//! sections dictate runtime behavior, resource bounds, initialization,
//! indirect-call dispatch, and proposal requirements.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use wasmparser::{DataKind, ElementItems, ElementKind, Parser, Payload, RefType, TypeRef, ValType};

use crate::category::FindingCategory;
use crate::diff::{CompatibilityAxis, DiffReport, Finding, Severity};
use crate::error::Error;
use crate::limits::{EntryKind, LimitError, ResourcePolicy};

/// A normalized WebAssembly memory declaration (imported or defined locally).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDeclaration {
    /// Resource index within the module's memory index space.
    pub index: u32,
    /// `Some((module, name))` if this memory is imported from host/environment.
    pub imported: Option<(String, String)>,
    /// Minimum initial pages (in 64 KiB units).
    pub initial_pages: u64,
    /// Maximum pages, if bounded.
    pub maximum_pages: Option<u64>,
    /// Whether the memory is shared across threads.
    pub shared: bool,
    /// Whether the memory uses 64-bit pointers (memory64 proposal).
    pub memory64: bool,
}

impl MemoryDeclaration {
    pub fn is_imported(&self) -> bool {
        self.imported.is_some()
    }
}

/// A normalized WebAssembly table declaration (imported or defined locally).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDeclaration {
    /// Resource index within the module's table index space.
    pub index: u32,
    /// `Some((module, name))` if this table is imported.
    pub imported: Option<(String, String)>,
    /// The element type (e.g. "funcref", "externref").
    pub element_type: String,
    /// Minimum initial elements.
    pub initial_elements: u64,
    /// Maximum elements, if bounded.
    pub maximum_elements: Option<u64>,
    /// Whether the table uses 64-bit indexing (table64 proposal).
    pub table64: bool,
}

impl TableDeclaration {
    pub fn is_imported(&self) -> bool {
        self.imported.is_some()
    }
}

/// A normalized WebAssembly global variable declaration (imported or defined locally).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalDeclaration {
    /// Resource index within the module's global index space.
    pub index: u32,
    /// `Some((module, name))` if this global is imported.
    pub imported: Option<(String, String)>,
    /// Value type of the global (e.g. "i32", "i64", "f32", "f64", "v128", "funcref", "externref").
    pub val_type: String,
    /// Whether the global is mutable (`mut`) or constant.
    pub mutable: bool,
    /// Whether the global is shared.
    pub shared: bool,
}

impl GlobalDeclaration {
    pub fn is_imported(&self) -> bool {
        self.imported.is_some()
    }
}

/// A normalized summary of an element segment used for indirect call tables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementSegmentSummary {
    /// Element segment index.
    pub index: u32,
    /// Mode: "active", "passive", or "declared".
    pub mode: String,
    /// Target table index if active.
    pub table_index: Option<u32>,
    /// Number of function/element items in this segment.
    pub element_count: usize,
    /// Element type.
    pub element_type: String,
}

/// A normalized summary of data segments in the module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSegmentSummary {
    /// Total number of data segments.
    pub count: usize,
    /// Number of active data segments (loaded into memory at instantiation).
    pub active_count: usize,
    /// Number of passive data segments (copied via memory.init).
    pub passive_count: usize,
    /// Total bytes declared across all data segments.
    pub total_bytes: usize,
}

/// Complete normalized runtime surface of a WebAssembly module.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSurface {
    /// Normalized memory declarations in index order.
    pub memories: Vec<MemoryDeclaration>,
    /// Normalized table declarations in index order.
    pub tables: Vec<TableDeclaration>,
    /// Normalized global declarations in index order.
    pub globals: Vec<GlobalDeclaration>,
    /// Module start function index, if present.
    pub start_function: Option<u32>,
    /// Normalized element segment summaries.
    pub element_segments: Vec<ElementSegmentSummary>,
    /// Data segments summary.
    pub data_segments: DataSegmentSummary,
    /// WebAssembly proposals and features required by the bytecode.
    pub proposals: BTreeSet<String>,
}

fn val_type_to_string(vt: ValType) -> String {
    match vt {
        ValType::I32 => "i32".to_string(),
        ValType::I64 => "i64".to_string(),
        ValType::F32 => "f32".to_string(),
        ValType::F64 => "f64".to_string(),
        ValType::V128 => "v128".to_string(),
        ValType::Ref(rt) => ref_type_to_string(rt),
    }
}

fn ref_type_to_string(rt: RefType) -> String {
    if rt == RefType::FUNCREF {
        "funcref".to_string()
    } else if rt == RefType::EXTERNREF {
        "externref".to_string()
    } else {
        format!("{rt}")
    }
}

/// Extract and normalize the runtime surface from raw WASM bytecode, enforcing resource limits.
pub fn extract_runtime_surface(
    bytes: &[u8],
    policy: &ResourcePolicy,
) -> Result<RuntimeSurface, Error> {
    let mut surface = RuntimeSurface::default();
    let parser = Parser::new(0);

    let mut entry_count: usize = 0;
    let mut next_memory_index: u32 = 0;
    let mut next_table_index: u32 = 0;
    let mut next_global_index: u32 = 0;

    let mut check_entry_limit = |count: usize| -> Result<(), Error> {
        entry_count = entry_count.saturating_add(count);
        if entry_count > policy.max_entries {
            return Err(Error::LimitExceeded {
                details: format!(
                    "Runtime surface entry count {entry_count} exceeded policy limit {}",
                    policy.max_entries
                ),
                source: Some(Box::new(LimitError::EntryCountExceeded {
                    limit: policy.max_entries,
                    kind: EntryKind::Spec,
                })),
            });
        }
        Ok(())
    };

    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| Error::WasmValidation {
            path: None,
            details: "Failed to parse WASM payload for runtime surface".to_string(),
            byte_offset: Some(e.offset() as u64),
            source: Some(Box::new(e)),
        })?;

        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| Error::WasmValidation {
                        path: None,
                        details: "Failed to parse WASM import in runtime surface".to_string(),
                        byte_offset: Some(e.offset() as u64),
                        source: Some(Box::new(e)),
                    })?;

                    check_entry_limit(1)?;

                    let module = import.module.to_string();
                    let name = import.name.to_string();

                    match import.ty {
                        TypeRef::Memory(mem_ty) => {
                            if mem_ty.memory64 {
                                surface.proposals.insert("memory64".to_string());
                            }
                            if mem_ty.shared {
                                surface.proposals.insert("threads".to_string());
                            }

                            surface.memories.push(MemoryDeclaration {
                                index: next_memory_index,
                                imported: Some((module, name)),
                                initial_pages: mem_ty.initial,
                                maximum_pages: mem_ty.maximum,
                                shared: mem_ty.shared,
                                memory64: mem_ty.memory64,
                            });
                            next_memory_index += 1;
                        }
                        TypeRef::Table(tab_ty) => {
                            let elem_str = ref_type_to_string(tab_ty.element_type);
                            if elem_str != "funcref" {
                                surface.proposals.insert("reference-types".to_string());
                            }

                            surface.tables.push(TableDeclaration {
                                index: next_table_index,
                                imported: Some((module, name)),
                                element_type: elem_str,
                                initial_elements: tab_ty.initial as u64,
                                maximum_elements: tab_ty.maximum.map(|m| m as u64),
                                table64: false,
                            });
                            next_table_index += 1;
                        }
                        TypeRef::Global(glob_ty) => {
                            if glob_ty.mutable {
                                surface.proposals.insert("mutable-globals".to_string());
                            }
                            let val_str = val_type_to_string(glob_ty.content_type);
                            if val_str == "v128" {
                                surface.proposals.insert("simd128".to_string());
                            } else if val_str == "externref" || val_str == "funcref" {
                                surface.proposals.insert("reference-types".to_string());
                            }

                            surface.globals.push(GlobalDeclaration {
                                index: next_global_index,
                                imported: Some((module, name)),
                                val_type: val_str,
                                mutable: glob_ty.mutable,
                                shared: false,
                            });
                            next_global_index += 1;
                        }
                        _ => {}
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem_ty = mem.map_err(|e| Error::WasmValidation {
                        path: None,
                        details: "Failed to parse WASM memory section".to_string(),
                        byte_offset: Some(e.offset() as u64),
                        source: Some(Box::new(e)),
                    })?;

                    check_entry_limit(1)?;

                    if mem_ty.memory64 {
                        surface.proposals.insert("memory64".to_string());
                    }
                    if mem_ty.shared {
                        surface.proposals.insert("threads".to_string());
                    }

                    surface.memories.push(MemoryDeclaration {
                        index: next_memory_index,
                        imported: None,
                        initial_pages: mem_ty.initial,
                        maximum_pages: mem_ty.maximum,
                        shared: mem_ty.shared,
                        memory64: mem_ty.memory64,
                    });
                    next_memory_index += 1;
                }
            }
            Payload::TableSection(reader) => {
                for tab in reader {
                    let tab = tab.map_err(|e| Error::WasmValidation {
                        path: None,
                        details: "Failed to parse WASM table section".to_string(),
                        byte_offset: Some(e.offset() as u64),
                        source: Some(Box::new(e)),
                    })?;

                    check_entry_limit(1)?;

                    let tab_ty = tab.ty;
                    let elem_str = ref_type_to_string(tab_ty.element_type);
                    if elem_str != "funcref" {
                        surface.proposals.insert("reference-types".to_string());
                    }

                    surface.tables.push(TableDeclaration {
                        index: next_table_index,
                        imported: None,
                        element_type: elem_str,
                        initial_elements: tab_ty.initial as u64,
                        maximum_elements: tab_ty.maximum.map(|m| m as u64),
                        table64: false,
                    });
                    next_table_index += 1;
                }
            }
            Payload::GlobalSection(reader) => {
                for glob in reader {
                    let glob = glob.map_err(|e| Error::WasmValidation {
                        path: None,
                        details: "Failed to parse WASM global section".to_string(),
                        byte_offset: Some(e.offset() as u64),
                        source: Some(Box::new(e)),
                    })?;

                    check_entry_limit(1)?;

                    let glob_ty = glob.ty;
                    let val_str = val_type_to_string(glob_ty.content_type);
                    if val_str == "v128" {
                        surface.proposals.insert("simd128".to_string());
                    } else if val_str == "externref" || val_str == "funcref" {
                        surface.proposals.insert("reference-types".to_string());
                    }

                    surface.globals.push(GlobalDeclaration {
                        index: next_global_index,
                        imported: None,
                        val_type: val_str,
                        mutable: glob_ty.mutable,
                        shared: false,
                    });
                    next_global_index += 1;
                }
            }
            Payload::StartSection { func, .. } => {
                surface.start_function = Some(func);
            }
            Payload::ElementSection(reader) => {
                for (elem_idx, elem) in reader.into_iter().enumerate() {
                    let elem = elem.map_err(|e| Error::WasmValidation {
                        path: None,
                        details: "Failed to parse WASM element section".to_string(),
                        byte_offset: Some(e.offset() as u64),
                        source: Some(Box::new(e)),
                    })?;

                    check_entry_limit(1)?;

                    let (mode, table_index) = match elem.kind {
                        ElementKind::Active { table_index, .. } => {
                            ("active".to_string(), Some(table_index.unwrap_or(0)))
                        }
                        ElementKind::Passive => {
                            surface.proposals.insert("bulk-memory".to_string());
                            ("passive".to_string(), None)
                        }
                        ElementKind::Declared => {
                            surface.proposals.insert("reference-types".to_string());
                            ("declared".to_string(), None)
                        }
                    };

                    let (elem_type, count) = match elem.items {
                        ElementItems::Functions(funcs) => {
                            ("funcref".to_string(), funcs.count() as usize)
                        }
                        ElementItems::Expressions(ref_ty, exprs) => {
                            let elem_s = ref_type_to_string(ref_ty);
                            if elem_s != "funcref" {
                                surface.proposals.insert("reference-types".to_string());
                            }
                            (elem_s, exprs.count() as usize)
                        }
                    };

                    surface.element_segments.push(ElementSegmentSummary {
                        index: elem_idx as u32,
                        mode,
                        table_index,
                        element_count: count,
                        element_type: elem_type,
                    });
                }
            }
            Payload::DataSection(reader) => {
                for data in reader {
                    let data = data.map_err(|e| Error::WasmValidation {
                        path: None,
                        details: "Failed to parse WASM data section".to_string(),
                        byte_offset: Some(e.offset() as u64),
                        source: Some(Box::new(e)),
                    })?;

                    check_entry_limit(1)?;

                    let len = data.data.len();
                    surface.data_segments.count += 1;
                    surface.data_segments.total_bytes =
                        surface.data_segments.total_bytes.saturating_add(len);

                    match data.kind {
                        DataKind::Active { .. } => {
                            surface.data_segments.active_count += 1;
                        }
                        DataKind::Passive => {
                            surface.proposals.insert("bulk-memory".to_string());
                            surface.data_segments.passive_count += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if surface.memories.len() > 1 {
        surface.proposals.insert("multi-memory".to_string());
    }
    if surface.tables.len() > 1 {
        surface.proposals.insert("reference-types".to_string());
    }

    Ok(surface)
}

/// Compares two runtime surfaces and appends findings to `report`.
pub fn compare_runtime_surfaces(
    old: &RuntimeSurface,
    new: &RuntimeSurface,
    report: &mut DiffReport,
) {
    compare_memories(old, new, report);
    compare_tables(old, new, report);
    compare_globals(old, new, report);
    compare_start_function(old, new, report);
    compare_element_segments(old, new, report);
    compare_data_segments(old, new, report);
    compare_proposals(old, new, report);
}

fn compare_memories(old: &RuntimeSurface, new: &RuntimeSurface, report: &mut DiffReport) {
    let max_len = old.memories.len().max(new.memories.len());

    for i in 0..max_len {
        let old_mem = old.memories.get(i);
        let new_mem = new.memories.get(i);

        match (old_mem, new_mem) {
            (None, Some(mem)) => {
                let severity = if mem.is_imported() {
                    Severity::Critical
                } else {
                    Severity::Info
                };
                let origin = if mem.is_imported() {
                    format!(
                        "imported as `{}::{}`",
                        mem.imported.as_ref().unwrap().0,
                        mem.imported.as_ref().unwrap().1
                    )
                } else {
                    "defined locally".to_string()
                };
                report.findings.push(Finding {
                    severity,
                    axes: vec![CompatibilityAxis::RuntimeSurface],
                    category: FindingCategory::MemoryAdded.as_str().to_string(),
                    message: format!(
                        "Memory {} added ({origin}, initial: {} pages / {} KiB, maximum: {}).",
                        mem.index,
                        mem.initial_pages,
                        mem.initial_pages * 64,
                        format_max_pages(mem.maximum_pages),
                    ),
                    type_name: None,
                    target: Some(format!("memory[{}]", mem.index)),
                    change: None,
                    root_target: None,
                });
            }
            (Some(mem), None) => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    axes: vec![CompatibilityAxis::RuntimeSurface],
                    category: FindingCategory::MemoryRemoved.as_str().to_string(),
                    message: format!(
                        "Memory {} was removed (previously initial: {} pages / {} KiB, maximum: {}).",
                        mem.index,
                        mem.initial_pages,
                        mem.initial_pages * 64,
                        format_max_pages(mem.maximum_pages),
                    ),
                    type_name: None,
                    target: Some(format!("memory[{}]", mem.index)),
                    change: None,
                    root_target: None,
                });
            }
            (Some(old_m), Some(new_m)) => {
                if old_m.imported != new_m.imported {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        axes: vec![CompatibilityAxis::RuntimeSurface],
                        category: FindingCategory::MemoryLimitsChanged.as_str().to_string(),
                        message: format!(
                            "Memory {} origin changed from {} to {}.",
                            old_m.index,
                            format_origin(&old_m.imported),
                            format_origin(&new_m.imported),
                        ),
                        type_name: None,
                        target: Some(format!("memory[{}]", old_m.index)),
                        change: None,
                        root_target: None,
                    });
                }

                if old_m.memory64 != new_m.memory64 || old_m.shared != new_m.shared {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        axes: vec![CompatibilityAxis::RuntimeSurface],
                        category: FindingCategory::MemoryLimitsChanged.as_str().to_string(),
                        message: format!(
                            "Memory {} type properties changed (memory64: {} -> {}, shared: {} -> {}).",
                            old_m.index, old_m.memory64, new_m.memory64, old_m.shared, new_m.shared
                        ),
                        type_name: None,
                        target: Some(format!("memory[{}].type", old_m.index)),
                        change: None,
                        root_target: None,
                    });
                }

                if old_m.initial_pages != new_m.initial_pages {
                    let severity = if new_m.initial_pages > old_m.initial_pages {
                        Severity::Warning
                    } else {
                        Severity::Info
                    };
                    report.findings.push(Finding {
                        severity,
                        axes: vec![CompatibilityAxis::RuntimeSurface],
                        category: FindingCategory::MemoryLimitsChanged.as_str().to_string(),
                        message: format!(
                            "Memory {} initial pages changed from {} ({} KiB) to {} ({} KiB).",
                            old_m.index,
                            old_m.initial_pages,
                            old_m.initial_pages * 64,
                            new_m.initial_pages,
                            new_m.initial_pages * 64,
                        ),
                        type_name: None,
                        target: Some(format!("memory[{}].min", old_m.index)),
                        change: None,
                        root_target: None,
                    });
                }

                if old_m.maximum_pages != new_m.maximum_pages {
                    let severity = match (old_m.maximum_pages, new_m.maximum_pages) {
                        (Some(_), None) => Severity::Info,
                        (None, Some(_)) => Severity::Warning,
                        (Some(old_max), Some(new_max)) if new_max < old_max => Severity::Warning,
                        _ => Severity::Info,
                    };
                    report.findings.push(Finding {
                        severity,
                        axes: vec![CompatibilityAxis::RuntimeSurface],
                        category: FindingCategory::MemoryLimitsChanged.as_str().to_string(),
                        message: format!(
                            "Memory {} maximum pages changed from {} to {}.",
                            old_m.index,
                            format_max_pages(old_m.maximum_pages),
                            format_max_pages(new_m.maximum_pages),
                        ),
                        type_name: None,
                        target: Some(format!("memory[{}].max", old_m.index)),
                        change: None,
                        root_target: None,
                    });
                }
            }
            (None, None) => {}
        }
    }
}

fn compare_tables(old: &RuntimeSurface, new: &RuntimeSurface, report: &mut DiffReport) {
    let max_len = old.tables.len().max(new.tables.len());

    for i in 0..max_len {
        let old_tab = old.tables.get(i);
        let new_tab = new.tables.get(i);

        match (old_tab, new_tab) {
            (None, Some(tab)) => {
                let severity = if tab.is_imported() {
                    Severity::Critical
                } else {
                    Severity::Info
                };
                report.findings.push(Finding {
                    severity,
                    axes: vec![CompatibilityAxis::RuntimeSurface],
                    category: FindingCategory::TableAdded.as_str().to_string(),
                    message: format!(
                        "Table {} added (element_type: {}, initial: {}, maximum: {}).",
                        tab.index,
                        tab.element_type,
                        tab.initial_elements,
                        format_max_elements(tab.maximum_elements),
                    ),
                    type_name: None,
                    target: Some(format!("table[{}]", tab.index)),
                    change: None,
                    root_target: None,
                });
            }
            (Some(tab), None) => {
                report.findings.push(Finding {
                    severity: Severity::Critical,
                    axes: vec![CompatibilityAxis::RuntimeSurface],
                    category: FindingCategory::TableRemoved.as_str().to_string(),
                    message: format!(
                        "Table {} was removed (previously element_type: {}, initial: {}, maximum: {}).",
                        tab.index,
                        tab.element_type,
                        tab.initial_elements,
                        format_max_elements(tab.maximum_elements),
                    ),
                    type_name: None,
                    target: Some(format!("table[{}]", tab.index)),
                    change: None,
                    root_target: None,
                });
            }
            (Some(old_t), Some(new_t)) => {
                if old_t.element_type != new_t.element_type {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        axes: vec![CompatibilityAxis::RuntimeSurface],
                        category: FindingCategory::TableElementTypeChanged
                            .as_str()
                            .to_string(),
                        message: format!(
                            "Table {} element type changed from `{}` to `{}`.",
                            old_t.index, old_t.element_type, new_t.element_type
                        ),
                        type_name: None,
                        target: Some(format!("table[{}].element_type", old_t.index)),
                        change: None,
                        root_target: None,
                    });
                }

                if old_t.initial_elements != new_t.initial_elements {
                    let severity = if new_t.initial_elements < old_t.initial_elements {
                        Severity::Warning
                    } else {
                        Severity::Info
                    };
                    report.findings.push(Finding {
                        severity,
                        axes: vec![CompatibilityAxis::RuntimeSurface],
                        category: FindingCategory::TableLimitsChanged.as_str().to_string(),
                        message: format!(
                            "Table {} initial elements changed from {} to {}.",
                            old_t.index, old_t.initial_elements, new_t.initial_elements
                        ),
                        type_name: None,
                        target: Some(format!("table[{}].min", old_t.index)),
                        change: None,
                        root_target: None,
                    });
                }

                if old_t.maximum_elements != new_t.maximum_elements {
                    report.findings.push(Finding {
                        severity: Severity::Info,
                        axes: vec![CompatibilityAxis::RuntimeSurface],
                        category: FindingCategory::TableLimitsChanged.as_str().to_string(),
                        message: format!(
                            "Table {} maximum elements changed from {} to {}.",
                            old_t.index,
                            format_max_elements(old_t.maximum_elements),
                            format_max_elements(new_t.maximum_elements),
                        ),
                        type_name: None,
                        target: Some(format!("table[{}].max", old_t.index)),
                        change: None,
                        root_target: None,
                    });
                }
            }
            (None, None) => {}
        }
    }
}

fn compare_globals(old: &RuntimeSurface, new: &RuntimeSurface, report: &mut DiffReport) {
    let max_len = old.globals.len().max(new.globals.len());

    for i in 0..max_len {
        let old_glob = old.globals.get(i);
        let new_glob = new.globals.get(i);

        match (old_glob, new_glob) {
            (None, Some(glob)) => {
                let severity = if glob.is_imported() {
                    Severity::Critical
                } else {
                    Severity::Info
                };
                report.findings.push(Finding {
                    severity,
                    axes: vec![CompatibilityAxis::RuntimeSurface],
                    category: FindingCategory::GlobalAdded.as_str().to_string(),
                    message: format!(
                        "Global {} added (type: {}, mutable: {}, {}).",
                        glob.index,
                        glob.val_type,
                        glob.mutable,
                        format_origin(&glob.imported)
                    ),
                    type_name: None,
                    target: Some(format!("global[{}]", glob.index)),
                    change: None,
                    root_target: None,
                });
            }
            (Some(glob), None) => {
                let severity = if glob.is_imported() {
                    Severity::Critical
                } else {
                    Severity::Warning
                };
                report.findings.push(Finding {
                    severity,
                    axes: vec![CompatibilityAxis::RuntimeSurface],
                    category: FindingCategory::GlobalRemoved.as_str().to_string(),
                    message: format!(
                        "Global {} was removed (previously type: {}, mutable: {}, {}).",
                        glob.index,
                        glob.val_type,
                        glob.mutable,
                        format_origin(&glob.imported)
                    ),
                    type_name: None,
                    target: Some(format!("global[{}]", glob.index)),
                    change: None,
                    root_target: None,
                });
            }
            (Some(old_g), Some(new_g)) => {
                if old_g.val_type != new_g.val_type {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        axes: vec![CompatibilityAxis::RuntimeSurface],
                        category: FindingCategory::GlobalTypeChanged.as_str().to_string(),
                        message: format!(
                            "Global {} type changed from `{}` to `{}`.",
                            old_g.index, old_g.val_type, new_g.val_type
                        ),
                        type_name: None,
                        target: Some(format!("global[{}].type", old_g.index)),
                        change: None,
                        root_target: None,
                    });
                }

                if old_g.mutable != new_g.mutable {
                    report.findings.push(Finding {
                        severity: Severity::Critical,
                        axes: vec![CompatibilityAxis::RuntimeSurface],
                        category: FindingCategory::GlobalMutabilityChanged
                            .as_str()
                            .to_string(),
                        message: format!(
                            "Global {} mutability changed from `{}` to `{}`.",
                            old_g.index,
                            if old_g.mutable { "mut" } else { "const" },
                            if new_g.mutable { "mut" } else { "const" }
                        ),
                        type_name: None,
                        target: Some(format!("global[{}].mutability", old_g.index)),
                        change: None,
                        root_target: None,
                    });
                }
            }
            (None, None) => {}
        }
    }
}

fn compare_start_function(old: &RuntimeSurface, new: &RuntimeSurface, report: &mut DiffReport) {
    match (old.start_function, new.start_function) {
        (None, Some(func)) => {
            report.findings.push(Finding {
                severity: Severity::Critical,
                axes: vec![CompatibilityAxis::RuntimeSurface],
                category: FindingCategory::StartFunctionAdded.as_str().to_string(),
                message: format!(
                    "Start function added (function index {func}); module now executes initialization code on instantiation."
                ),
                type_name: None,
                target: Some("start_function".to_string()),
                change: None,
                root_target: None,
            });
        }
        (Some(func), None) => {
            report.findings.push(Finding {
                severity: Severity::Warning,
                axes: vec![CompatibilityAxis::RuntimeSurface],
                category: FindingCategory::StartFunctionRemoved.as_str().to_string(),
                message: format!(
                    "Start function (function index {func}) was removed; module initialization behavior changed."
                ),
                type_name: None,
                target: Some("start_function".to_string()),
                change: None,
                root_target: None,
            });
        }
        (Some(old_func), Some(new_func)) if old_func != new_func => {
            report.findings.push(Finding {
                severity: Severity::Warning,
                axes: vec![CompatibilityAxis::RuntimeSurface],
                category: FindingCategory::StartFunctionChanged.as_str().to_string(),
                message: format!("Start function changed from index {old_func} to {new_func}."),
                type_name: None,
                target: Some("start_function".to_string()),
                change: None,
                root_target: None,
            });
        }
        _ => {}
    }
}

fn compare_element_segments(old: &RuntimeSurface, new: &RuntimeSurface, report: &mut DiffReport) {
    let old_count: usize = old.element_segments.iter().map(|e| e.element_count).sum();
    let new_count: usize = new.element_segments.iter().map(|e| e.element_count).sum();

    if old.element_segments.len() != new.element_segments.len() || old_count != new_count {
        let severity = if new_count < old_count {
            Severity::Warning
        } else {
            Severity::Info
        };

        report.findings.push(Finding {
            severity,
            axes: vec![CompatibilityAxis::RuntimeSurface],
            category: FindingCategory::ElementSegmentChanged.as_str().to_string(),
            message: format!(
                "Indirect-call element segments changed (segment count: {} -> {}, total elements: {} -> {}).",
                old.element_segments.len(),
                new.element_segments.len(),
                old_count,
                new_count
            ),
            type_name: None,
            target: Some("element_segments".to_string()),
            change: None,
            root_target: None,
        });
    }
}

fn compare_data_segments(old: &RuntimeSurface, new: &RuntimeSurface, report: &mut DiffReport) {
    if old.data_segments != new.data_segments {
        let old_d = &old.data_segments;
        let new_d = &new.data_segments;

        report.findings.push(Finding {
            severity: Severity::Info,
            axes: vec![CompatibilityAxis::RuntimeSurface],
            category: FindingCategory::DataSegmentChanged.as_str().to_string(),
            message: format!(
                "Data segments changed (segments: {} [active: {}, passive: {}] -> {} [active: {}, passive: {}], bytes: {} -> {}).",
                old_d.count,
                old_d.active_count,
                old_d.passive_count,
                new_d.count,
                new_d.active_count,
                new_d.passive_count,
                old_d.total_bytes,
                new_d.total_bytes
            ),
            type_name: None,
            target: Some("data_segments".to_string()),
            change: None,
            root_target: None,
        });
    }
}

fn compare_proposals(old: &RuntimeSurface, new: &RuntimeSurface, report: &mut DiffReport) {
    for prop in new.proposals.difference(&old.proposals) {
        report.findings.push(Finding {
            severity: Severity::Warning,
            axes: vec![CompatibilityAxis::RuntimeSurface],
            category: FindingCategory::WasmProposalAdded.as_str().to_string(),
            message: format!(
                "WebAssembly proposal/feature `{prop}` is newly required by the upgraded module."
            ),
            type_name: None,
            target: Some(format!("proposal.{prop}")),
            change: None,
            root_target: None,
        });
    }

    for prop in old.proposals.difference(&new.proposals) {
        report.findings.push(Finding {
            severity: Severity::Info,
            axes: vec![CompatibilityAxis::RuntimeSurface],
            category: FindingCategory::WasmProposalRemoved.as_str().to_string(),
            message: format!(
                "WebAssembly proposal/feature `{prop}` is no longer required by the upgraded module."
            ),
            type_name: None,
            target: Some(format!("proposal.{prop}")),
            change: None,
            root_target: None,
        });
    }
}

fn format_max_pages(max: Option<u64>) -> String {
    match max {
        Some(m) => format!("Some({m} pages / {} KiB)", m * 64),
        None => "None (unbounded)".to_string(),
    }
}

fn format_max_elements(max: Option<u64>) -> String {
    match max {
        Some(m) => format!("Some({m})"),
        None => "None (unbounded)".to_string(),
    }
}

fn format_origin(imported: &Option<(String, String)>) -> String {
    match imported {
        Some((m, n)) => format!("imported from `{m}::{n}`"),
        None => "defined locally".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_memory_limit_changes() {
        let old = RuntimeSurface {
            memories: vec![MemoryDeclaration {
                index: 0,
                imported: None,
                initial_pages: 1,
                maximum_pages: Some(16),
                shared: false,
                memory64: false,
            }],
            ..Default::default()
        };

        let new = RuntimeSurface {
            memories: vec![MemoryDeclaration {
                index: 0,
                imported: None,
                initial_pages: 4,
                maximum_pages: None,
                shared: false,
                memory64: false,
            }],
            ..Default::default()
        };

        let mut report = DiffReport::default();
        compare_runtime_surfaces(&old, &new, &mut report);

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].category, "Memory Limits Changed");
        assert_eq!(report.findings[0].target, Some("memory[0].min".to_string()));
        assert_eq!(report.findings[1].category, "Memory Limits Changed");
        assert_eq!(report.findings[1].target, Some("memory[0].max".to_string()));
    }

    #[test]
    fn detects_start_function_addition() {
        let old = RuntimeSurface::default();
        let new = RuntimeSurface {
            start_function: Some(2),
            ..Default::default()
        };

        let mut report = DiffReport::default();
        compare_runtime_surfaces(&old, &new, &mut report);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].category, "Start Function Added");
        assert_eq!(*report.findings[0].severity(), Severity::Critical);
    }
}

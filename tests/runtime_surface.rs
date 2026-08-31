//! Comprehensive integration tests for WASM runtime surface comparisons.

use soroban_upgrade_safeguard::diff::CompatibilityAxis;
use soroban_upgrade_safeguard::report::AxisStatus;
use soroban_upgrade_safeguard::suppression::SuppressionConfig;
use soroban_upgrade_safeguard::{
    compare_wasm_bytes, compare_wasm_bytes_with_options, CompareOptions,
};

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

/// A builder to construct precise WASM modules for runtime surface testing.
#[derive(Default)]
struct WasmBuilder {
    imports: Vec<Vec<u8>>,
    types: Vec<Vec<u8>>,
    memories: Vec<Vec<u8>>,
    tables: Vec<Vec<u8>>,
    globals: Vec<Vec<u8>>,
    start_func: Option<u32>,
    elements: Vec<Vec<u8>>,
    data: Vec<Vec<u8>>,
}

impl WasmBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn add_type_func(mut self, params: &[u8], results: &[u8]) -> Self {
        let mut t = vec![0x60];
        t.extend(uleb(params.len() as u32));
        t.extend_from_slice(params);
        t.extend(uleb(results.len() as u32));
        t.extend_from_slice(results);
        self.types.push(t);
        self
    }

    fn add_imported_memory(
        mut self,
        module: &str,
        name: &str,
        initial: u32,
        maximum: Option<u32>,
    ) -> Self {
        let mut imp = wasm_string(module);
        imp.extend(wasm_string(name));
        imp.push(0x02); // memory import
        if let Some(max) = maximum {
            imp.push(0x01); // flags: has max
            imp.extend(uleb(initial));
            imp.extend(uleb(max));
        } else {
            imp.push(0x00); // flags: no max
            imp.extend(uleb(initial));
        }
        self.imports.push(imp);
        self
    }

    fn add_imported_global(
        mut self,
        module: &str,
        name: &str,
        val_type: u8,
        mutable: bool,
    ) -> Self {
        let mut imp = wasm_string(module);
        imp.extend(wasm_string(name));
        imp.push(0x03); // global import
        imp.push(val_type);
        imp.push(if mutable { 0x01 } else { 0x00 });
        self.imports.push(imp);
        self
    }

    fn add_memory(mut self, initial: u32, maximum: Option<u32>) -> Self {
        let mut mem = Vec::new();
        if let Some(max) = maximum {
            mem.push(0x01); // has max
            mem.extend(uleb(initial));
            mem.extend(uleb(max));
        } else {
            mem.push(0x00); // no max
            mem.extend(uleb(initial));
        }
        self.memories.push(mem);
        self
    }

    fn add_table(mut self, elem_type: u8, initial: u32, maximum: Option<u32>) -> Self {
        let mut tab = Vec::new();
        tab.push(elem_type);
        if let Some(max) = maximum {
            tab.push(0x01);
            tab.extend(uleb(initial));
            tab.extend(uleb(max));
        } else {
            tab.push(0x00);
            tab.extend(uleb(initial));
        }
        self.tables.push(tab);
        self
    }

    fn add_global(mut self, val_type: u8, mutable: bool, init_val: i32) -> Self {
        let mut glob = Vec::new();
        glob.push(val_type);
        glob.push(if mutable { 0x01 } else { 0x00 });
        // init expr (e.g. i32.const <val>, end)
        glob.push(0x41); // i32.const
        glob.extend(uleb(init_val as u32));
        glob.push(0x0b); // end
        self.globals.push(glob);
        self
    }

    fn set_start(mut self, func_index: u32) -> Self {
        self.start_func = Some(func_index);
        self
    }

    fn add_active_element(mut self, table_index: u32, funcs: &[u32]) -> Self {
        let mut elem = Vec::new();
        elem.push(0x00); // active, table 0 implicit or segment header 0
        elem.push(0x41); // i32.const 0
        elem.extend(uleb(table_index));
        elem.push(0x0b); // end
        elem.extend(uleb(funcs.len() as u32));
        for f in funcs {
            elem.extend(uleb(*f));
        }
        self.elements.push(elem);
        self
    }

    fn add_data_segment(mut self, bytes: &[u8]) -> Self {
        let mut d = vec![0x00, 0x41, 0x00, 0x0b]; // active on memory 0, i32.const 0, end
        d.extend(uleb(bytes.len() as u32));
        d.extend_from_slice(bytes);
        self.data.push(d);
        self
    }

    fn build(self) -> Vec<u8> {
        let mut wasm = Vec::from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

        if !self.types.is_empty() {
            let mut body = uleb(self.types.len() as u32);
            for t in self.types {
                body.extend(t);
            }
            wasm.extend(wasm_section(1, body));
        }

        if !self.imports.is_empty() {
            let mut body = uleb(self.imports.len() as u32);
            for imp in self.imports {
                body.extend(imp);
            }
            wasm.extend(wasm_section(2, body));
        }

        if !self.memories.is_empty() {
            let mut body = uleb(self.memories.len() as u32);
            for mem in self.memories {
                body.extend(mem);
            }
            wasm.extend(wasm_section(5, body));
        }

        if !self.tables.is_empty() {
            let mut body = uleb(self.tables.len() as u32);
            for tab in self.tables {
                body.extend(tab);
            }
            wasm.extend(wasm_section(4, body));
        }

        if !self.globals.is_empty() {
            let mut body = uleb(self.globals.len() as u32);
            for glob in self.globals {
                body.extend(glob);
            }
            wasm.extend(wasm_section(6, body));
        }

        if let Some(start) = self.start_func {
            wasm.extend(wasm_section(8, uleb(start)));
        }

        if !self.elements.is_empty() {
            let mut body = uleb(self.elements.len() as u32);
            for elem in self.elements {
                body.extend(elem);
            }
            wasm.extend(wasm_section(9, body));
        }

        if !self.data.is_empty() {
            let mut body = uleb(self.data.len() as u32);
            for d in self.data {
                body.extend(d);
            }
            wasm.extend(wasm_section(11, body));
        }

        wasm
    }
}

fn has_category(report: &soroban_upgrade_safeguard::SafetyReport, cat: &str) -> bool {
    report
        .findings_by_category()
        .get(cat)
        .is_some_and(|f| !f.is_empty())
}

#[test]
fn test_memory_limits_changes_detected() {
    let old_wasm = WasmBuilder::new().add_memory(2, Some(16)).build();
    let new_wasm = WasmBuilder::new().add_memory(1, Some(32)).build();

    let report = compare_wasm_bytes(&old_wasm, &new_wasm).expect("compare succeeds");
    assert!(has_category(&report, "Memory Limits Changed"));

    let findings = &report.findings_by_category()["Memory Limits Changed"];
    assert!(findings
        .iter()
        .any(|f| f.finding.target.as_deref() == Some("memory[0].min")));
    assert!(findings
        .iter()
        .any(|f| f.finding.target.as_deref() == Some("memory[0].max")));
}

#[test]
fn test_memory_added_and_removed() {
    let old_wasm = WasmBuilder::new().add_memory(1, None).build();
    let new_wasm = WasmBuilder::new().build();

    let report = compare_wasm_bytes(&old_wasm, &new_wasm).expect("compare succeeds");
    assert!(has_category(&report, "Memory Removed"));
    assert_eq!(
        report.axis_verdicts.get(&CompatibilityAxis::RuntimeSurface),
        Some(&AxisStatus::Failed)
    );

    let report_rev = compare_wasm_bytes(&new_wasm, &old_wasm).expect("compare succeeds");
    assert!(has_category(&report_rev, "Memory Added"));
}

#[test]
fn test_imported_memory_addition_is_critical() {
    let old_wasm = WasmBuilder::new().build();
    let new_wasm = WasmBuilder::new()
        .add_imported_memory("env", "memory", 1, Some(10))
        .build();

    let report = compare_wasm_bytes(&old_wasm, &new_wasm).expect("compare succeeds");
    assert!(has_category(&report, "Memory Added"));
    assert_eq!(
        report.axis_verdicts.get(&CompatibilityAxis::RuntimeSurface),
        Some(&AxisStatus::Failed)
    );
}

#[test]
fn test_table_element_type_and_limits_changed() {
    // 0x70 is funcref, 0x6f is externref
    let old_wasm = WasmBuilder::new().add_table(0x70, 10, Some(20)).build();
    let new_wasm = WasmBuilder::new().add_table(0x6f, 5, Some(20)).build();

    let report = compare_wasm_bytes(&old_wasm, &new_wasm).expect("compare succeeds");
    assert!(has_category(&report, "Table Element Type Changed"));
    assert!(has_category(&report, "Table Limits Changed"));
    assert!(has_category(&report, "WASM Proposal Added"));
}

#[test]
fn test_global_type_and_mutability_changed() {
    // 0x7f is i32, 0x7e is i64
    let old_wasm = WasmBuilder::new()
        .add_global(0x7f, false, 0)
        .add_imported_global("env", "g", 0x7f, false)
        .build();
    let new_wasm = WasmBuilder::new()
        .add_global(0x7e, true, 0)
        .add_imported_global("env", "g", 0x7f, true)
        .build();

    let report = compare_wasm_bytes(&old_wasm, &new_wasm).expect("compare succeeds");
    assert!(has_category(&report, "Global Type Changed"));
    assert!(has_category(&report, "Global Mutability Changed"));
    assert!(has_category(&report, "WASM Proposal Added"));
}

#[test]
fn test_start_function_addition_and_removal() {
    let no_start = WasmBuilder::new().add_type_func(&[], &[]).build();
    let with_start = WasmBuilder::new()
        .add_type_func(&[], &[])
        .set_start(0)
        .build();

    let report_add = compare_wasm_bytes(&no_start, &with_start).expect("compare succeeds");
    assert!(has_category(&report_add, "Start Function Added"));
    assert_eq!(
        report_add
            .axis_verdicts
            .get(&CompatibilityAxis::RuntimeSurface),
        Some(&AxisStatus::Failed)
    );

    let report_rem = compare_wasm_bytes(&with_start, &no_start).expect("compare succeeds");
    assert!(has_category(&report_rem, "Start Function Removed"));
}

#[test]
fn test_element_and_data_segments_comparison() {
    let old_wasm = WasmBuilder::new()
        .add_table(0x70, 4, None)
        .add_active_element(0, &[0, 1])
        .add_data_segment(b"hello")
        .build();

    let new_wasm = WasmBuilder::new()
        .add_table(0x70, 4, None)
        .add_active_element(0, &[0, 1, 2, 3])
        .add_data_segment(b"hello world")
        .build();

    let report = compare_wasm_bytes(&old_wasm, &new_wasm).expect("compare succeeds");
    assert!(has_category(&report, "Element Segment Changed"));
    assert!(has_category(&report, "Data Segment Changed"));
}

#[test]
fn test_suppression_of_runtime_surface_findings() {
    let old_wasm = WasmBuilder::new().add_memory(2, Some(16)).build();
    let new_wasm = WasmBuilder::new().add_memory(1, Some(32)).build();

    let config_toml = r#"
    [[suppress]]
    category = "Memory Limits Changed"
    target   = "memory[0].min"
    reason   = "Intentional memory shrink for testing"
    "#;
    let config: SuppressionConfig = toml::from_str(config_toml).unwrap();

    let options = CompareOptions {
        suppressions: Some(&config),
        explain: false,
        strict: true,
        storage_schemas: None,
        lineage_store: None,
        contract: None,
    };

    let report =
        compare_wasm_bytes_with_options(&old_wasm, &new_wasm, &options).expect("compare succeeds");

    assert_eq!(report.suppressed_count, 1);
    assert_eq!(
        report.findings_by_category()["Memory Limits Changed"].len(),
        2
    );
    let min_finding = report.findings_by_category()["Memory Limits Changed"]
        .iter()
        .find(|f| f.finding.target.as_deref() == Some("memory[0].min"))
        .unwrap();
    assert!(min_finding.suppressed);
}

#[test]
fn test_rendering_outputs_contain_runtime_surface() {
    let old_wasm = WasmBuilder::new().add_memory(2, Some(16)).build();
    let new_wasm = WasmBuilder::new().add_memory(1, Some(32)).build();

    let report = compare_wasm_bytes(&old_wasm, &new_wasm).expect("compare succeeds");
    let renderable = report.to_renderable();

    let text = renderable.to_text(false);
    assert!(text.contains("Runtime Surface"));
    assert!(text.contains("Memory 0 initial pages changed"));

    let md = renderable.to_markdown();
    assert!(md.contains("Runtime Surface"));
    assert!(md.contains("Memory Limits Changed"));
    assert!(md.contains("Runtime Surface Compatibility"));

    let json = serde_json::to_string_pretty(&renderable).expect("render json");
    assert!(json.contains("runtime_surface"));
    assert!(json.contains("Memory Limits Changed"));
}

#[test]
fn test_gating_policy_allows_disabling_runtime_surface_axis() {
    let old_wasm = WasmBuilder::new().add_memory(1, None).build();
    let new_wasm = WasmBuilder::new().build(); // Removes memory -> Critical

    let config_toml = r#"
    [policy]
    gate_runtime_surface = false
    "#;
    let config: SuppressionConfig = toml::from_str(config_toml).unwrap();

    let options = CompareOptions {
        suppressions: Some(&config),
        explain: false,
        strict: false,
        storage_schemas: None,
        lineage_store: None,
        contract: None,
    };

    let report =
        compare_wasm_bytes_with_options(&old_wasm, &new_wasm, &options).expect("compare succeeds");

    // Because gate_runtime_surface is false, the axis verdict is Warning (non-gated) instead of Failed
    assert_eq!(
        report.axis_verdicts.get(&CompatibilityAxis::RuntimeSurface),
        Some(&AxisStatus::Warning)
    );
    assert!(report.is_safe());
}

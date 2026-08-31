use soroban_upgrade_safeguard::diff::{Finding, Severity};
use soroban_upgrade_safeguard::empirical::{
    load_empirical_entries, run_empirical_check, validate_scval_type, validate_scval_udt,
};
use soroban_upgrade_safeguard::spec::ContractSpec;
use std::fs::File;
use std::io::Write;
use stellar_xdr::curr::{
    ContractDataDurability, ContractDataEntry, Limits, ScAddress, ScMap, ScMapEntry, ScSpecTypeDef,
    ScSpecUdtStructFieldV0, ScSpecUdtStructV0, ScVal, StringM, VecM, WriteXdr,
};

fn make_contract_data_entry(key: ScVal, val: ScVal) -> ContractDataEntry {
    ContractDataEntry {
        ext: stellar_xdr::curr::ExtensionPoint::V0,
        contract: ScAddress::Contract(stellar_xdr::curr::Hash([0; 32])),
        key,
        val,
        durability: ContractDataDurability::Persistent,
    }
}

#[test]
fn test_primitive_validation() {
    let spec = ContractSpec::default();

    // Test basic types
    let val_u32 = ScVal::U32(42);
    assert!(validate_scval_type(&val_u32, &ScSpecTypeDef::U32, &spec, "test").is_ok());
    assert!(validate_scval_type(&val_u32, &ScSpecTypeDef::I32, &spec, "test").is_err());

    let val_bool = ScVal::Bool(true);
    assert!(validate_scval_type(&val_bool, &ScSpecTypeDef::Bool, &spec, "test").is_ok());
    assert!(validate_scval_type(&val_bool, &ScSpecTypeDef::U32, &spec, "test").is_err());
}

#[test]
fn test_struct_validation() {
    let mut old_spec = ContractSpec::default();
    let fields = vec![
        ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: "field_a".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
        ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: "field_b".try_into().unwrap(),
            type_: ScSpecTypeDef::U128,
        },
    ];
    let struct_name = "MyStruct".to_string();
    old_spec.structs.insert(
        struct_name.clone(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "MyStruct".try_into().unwrap(),
            fields: VecM::try_from(fields).unwrap(),
        },
    );

    // Map-based struct value representing { field_a: 42, field_b: 100 }
    let struct_val = ScVal::Map(Some(ScMap(
        vec![
            ScMapEntry {
                key: ScVal::Symbol("field_a".try_into().unwrap()),
                val: ScVal::U32(42),
            },
            ScMapEntry {
                key: ScVal::Symbol("field_b".try_into().unwrap()),
                val: ScVal::U128(stellar_xdr::curr::UInt128Parts { hi: 0, lo: 100 }),
            },
        ]
        .try_into()
        .unwrap(),
    )));

    // Validate against old spec
    assert!(validate_scval_udt(&struct_val, "MyStruct", &old_spec, "struct_test").is_ok());

    // Validate against a new spec where MyStruct field_b is now U32 (breaking layout!)
    let mut new_spec = ContractSpec::default();
    let new_fields = vec![
        ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: "field_a".try_into().unwrap(),
            type_: ScSpecTypeDef::U32,
        },
        ScSpecUdtStructFieldV0 {
            doc: StringM::default(),
            name: "field_b".try_into().unwrap(),
            type_: ScSpecTypeDef::U32, // type changed
        },
    ];
    new_spec.structs.insert(
        struct_name.clone(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "MyStruct".try_into().unwrap(),
            fields: VecM::try_from(new_fields).unwrap(),
        },
    );

    let res = validate_scval_udt(&struct_val, "MyStruct", &new_spec, "struct_test");
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("expected u32"));
}

#[test]
fn test_json_loading_and_empirical_check() {
    let mut old_spec = ContractSpec::default();
    let fields = vec![ScSpecUdtStructFieldV0 {
        doc: StringM::default(),
        name: "amount".try_into().unwrap(),
        type_: ScSpecTypeDef::U64,
    }];
    old_spec.structs.insert(
        "Balance".to_string(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "Balance".try_into().unwrap(),
            fields: VecM::try_from(fields).unwrap(),
        },
    );

    let mut new_spec = ContractSpec::default();
    let new_fields = vec![ScSpecUdtStructFieldV0 {
        doc: StringM::default(),
        name: "amount".try_into().unwrap(),
        type_: ScSpecTypeDef::U128, // Type changed
    }];
    new_spec.structs.insert(
        "Balance".to_string(),
        ScSpecUdtStructV0 {
            doc: StringM::default(),
            lib: StringM::default(),
            name: "Balance".try_into().unwrap(),
            fields: VecM::try_from(new_fields).unwrap(),
        },
    );

    // Create entry key and value
    let key = ScVal::Symbol("my_balance".try_into().unwrap());
    let val = ScVal::Map(Some(ScMap(
        vec![ScMapEntry {
            key: ScVal::Symbol("amount".try_into().unwrap()),
            val: ScVal::U64(500),
        }]
        .try_into()
        .unwrap(),
    )));

    let entry = make_contract_data_entry(key, val);
    let entry_b64 = entry.to_xdr_base64(Limits::none()).unwrap();

    // Create a temporary JSON file
    let dir = std::env::temp_dir();
    let file_path = dir.join("empirical_test.json");
    let mut file = File::create(&file_path).unwrap();
    let json_content = serde_json::to_string(&vec![entry_b64]).unwrap();
    file.write_all(json_content.as_bytes()).unwrap();

    // Load entries
    let loaded = load_empirical_entries(&file_path).expect("failed to load JSON");
    assert_eq!(loaded.len(), 1);

    // Run empirical check
    let structural_findings = vec![Finding {
        axes: Vec::new(),
        severity: Severity::Critical,
        category: "Struct Field Type Changed".to_string(),
        message: "Struct field changed type".to_string(),
        type_name: Some("Balance".to_string()),
        target: Some("Balance.amount".to_string()),
        change: None,
        root_target: None,
    }];

    let results = run_empirical_check(&old_spec, &new_spec, &loaded, &structural_findings);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].is_success,
        "empirical check must catch type mismatch"
    );
    assert!(results[0].error.as_ref().unwrap().contains("expected u128"));

    // Clean up
    std::fs::remove_file(file_path).ok();
}

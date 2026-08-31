//! Directional Soroban call-ABI compatibility analysis.
//!
//! Call compatibility is a value-flow question. Arguments are encoded by a
//! client and decoded by a contract, while return values are encoded by the
//! contract and decoded by the client. Consequently the same type evolution
//! can have a different answer in each upgrade direction.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use stellar_xdr::curr::{ScSpecTypeDef, ScSpecUdtUnionCaseV0};

use crate::spec::ContractSpec;

/// The consumer/provider pairing being evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallDirection {
    OldClientToNewContract,
    NewClientToOldContract,
}

/// One concrete Soroban value-flow incompatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallAbiBreak {
    pub function: String,
    pub path: String,
    pub reason: String,
}

/// Compatibility for one consumer-to-provider direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectionalCallVerdict {
    pub direction: CallDirection,
    pub compatible: bool,
    pub breaks: Vec<CallAbiBreak>,
}

impl DirectionalCallVerdict {
    fn new(direction: CallDirection, breaks: Vec<CallAbiBreak>) -> Self {
        Self {
            direction,
            compatible: breaks.is_empty(),
            breaks,
        }
    }
}

/// Both directional call-ABI conclusions for an upgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallAbiCompatibility {
    pub old_client_to_new_contract: DirectionalCallVerdict,
    pub new_client_to_old_contract: DirectionalCallVerdict,
}

impl Default for CallAbiCompatibility {
    fn default() -> Self {
        Self {
            old_client_to_new_contract: DirectionalCallVerdict::new(
                CallDirection::OldClientToNewContract,
                Vec::new(),
            ),
            new_client_to_old_contract: DirectionalCallVerdict::new(
                CallDirection::NewClientToOldContract,
                Vec::new(),
            ),
        }
    }
}

impl CallAbiCompatibility {
    /// Legacy aggregate view: call ABI is compatible only when both flows are.
    pub fn compatible(&self) -> bool {
        self.old_client_to_new_contract.compatible && self.new_client_to_old_contract.compatible
    }
}

/// Compute both call directions from Soroban invocation and value conversion
/// rules. Parameter names do not participate in invocation; order and arity do.
pub fn compare(old: &ContractSpec, new: &ContractSpec) -> CallAbiCompatibility {
    CallAbiCompatibility {
        old_client_to_new_contract: compare_direction(
            CallDirection::OldClientToNewContract,
            old,
            new,
        ),
        new_client_to_old_contract: compare_direction(
            CallDirection::NewClientToOldContract,
            new,
            old,
        ),
    }
}

fn compare_direction(
    direction: CallDirection,
    client: &ContractSpec,
    contract: &ContractSpec,
) -> DirectionalCallVerdict {
    let mut breaks = Vec::new();

    for (name, client_fn) in &client.functions {
        let Some(contract_fn) = contract.functions.get(name) else {
            breaks.push(CallAbiBreak {
                function: name.clone(),
                path: format!("function.{name}"),
                reason: "the client invokes a function that the provider does not export"
                    .to_string(),
            });
            continue;
        };

        if client_fn.inputs.len() != contract_fn.inputs.len() {
            breaks.push(CallAbiBreak {
                function: name.clone(),
                path: format!("function.{name}.arguments"),
                reason: format!(
                    "the client sends {} positional arguments but the provider requires {}",
                    client_fn.inputs.len(),
                    contract_fn.inputs.len()
                ),
            });
        } else {
            for (index, (produced, consumed)) in client_fn
                .inputs
                .iter()
                .zip(contract_fn.inputs.iter())
                .enumerate()
            {
                let path = format!("function.{name}.argument[{index}]");
                let mut visiting = HashSet::new();
                check_value_flow(
                    &produced.type_,
                    client,
                    &consumed.type_,
                    contract,
                    &path,
                    &mut visiting,
                    &mut breaks,
                    name,
                );
            }
        }

        if client_fn.outputs.len() != contract_fn.outputs.len() {
            breaks.push(CallAbiBreak {
                function: name.clone(),
                path: format!("function.{name}.return"),
                reason: format!(
                    "the provider returns {} values but the client decodes {}",
                    contract_fn.outputs.len(),
                    client_fn.outputs.len()
                ),
            });
        } else {
            for (index, (consumed, produced)) in client_fn
                .outputs
                .iter()
                .zip(contract_fn.outputs.iter())
                .enumerate()
            {
                let path = format!("function.{name}.return[{index}]");
                let mut visiting = HashSet::new();
                check_value_flow(
                    produced,
                    contract,
                    consumed,
                    client,
                    &path,
                    &mut visiting,
                    &mut breaks,
                    name,
                );
            }
        }
    }

    breaks.sort_by(|a, b| {
        a.function
            .cmp(&b.function)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.reason.cmp(&b.reason))
    });
    DirectionalCallVerdict::new(direction, breaks)
}

#[allow(clippy::too_many_arguments)]
fn check_value_flow(
    producer: &ScSpecTypeDef,
    producer_spec: &ContractSpec,
    consumer: &ScSpecTypeDef,
    consumer_spec: &ContractSpec,
    path: &str,
    visiting: &mut HashSet<(String, String)>,
    breaks: &mut Vec<CallAbiBreak>,
    function: &str,
) {
    // `Val` is the untyped Soroban value: a consumer accepting Val can receive
    // every encoded value. A producer typed only as Val cannot promise that a
    // more specific decoder will succeed.
    if matches!(consumer, ScSpecTypeDef::Val) {
        return;
    }

    let mismatch = |reason: String, breaks: &mut Vec<CallAbiBreak>| {
        breaks.push(CallAbiBreak {
            function: function.to_string(),
            path: path.to_string(),
            reason,
        });
    };

    match (producer, consumer) {
        (ScSpecTypeDef::Option(a), ScSpecTypeDef::Option(b)) => check_value_flow(
            &a.value_type,
            producer_spec,
            &b.value_type,
            consumer_spec,
            &format!("{path}.some"),
            visiting,
            breaks,
            function,
        ),
        (ScSpecTypeDef::Vec(a), ScSpecTypeDef::Vec(b)) => check_value_flow(
            &a.element_type,
            producer_spec,
            &b.element_type,
            consumer_spec,
            &format!("{path}[*]"),
            visiting,
            breaks,
            function,
        ),
        (ScSpecTypeDef::Map(a), ScSpecTypeDef::Map(b)) => {
            check_value_flow(
                &a.key_type,
                producer_spec,
                &b.key_type,
                consumer_spec,
                &format!("{path}.key"),
                visiting,
                breaks,
                function,
            );
            check_value_flow(
                &a.value_type,
                producer_spec,
                &b.value_type,
                consumer_spec,
                &format!("{path}.value"),
                visiting,
                breaks,
                function,
            );
        }
        (ScSpecTypeDef::Tuple(a), ScSpecTypeDef::Tuple(b)) => {
            if a.value_types.len() != b.value_types.len() {
                mismatch(
                    format!(
                        "the encoded tuple has {} elements but the decoder requires {}",
                        a.value_types.len(),
                        b.value_types.len()
                    ),
                    breaks,
                );
            } else {
                for (index, (a, b)) in a.value_types.iter().zip(b.value_types.iter()).enumerate() {
                    check_value_flow(
                        a,
                        producer_spec,
                        b,
                        consumer_spec,
                        &format!("{path}[{index}]"),
                        visiting,
                        breaks,
                        function,
                    );
                }
            }
        }
        (ScSpecTypeDef::Result(a), ScSpecTypeDef::Result(b)) => {
            check_value_flow(
                &a.ok_type,
                producer_spec,
                &b.ok_type,
                consumer_spec,
                &format!("{path}.ok"),
                visiting,
                breaks,
                function,
            );
            check_value_flow(
                &a.error_type,
                producer_spec,
                &b.error_type,
                consumer_spec,
                &format!("{path}.err"),
                visiting,
                breaks,
                function,
            );
        }
        (ScSpecTypeDef::Udt(a), ScSpecTypeDef::Udt(b)) => check_udt_flow(
            &a.name.to_string(),
            producer_spec,
            &b.name.to_string(),
            consumer_spec,
            path,
            visiting,
            breaks,
            function,
        ),
        _ if producer == consumer => {}
        _ => mismatch(
            format!(
                "the producer encodes `{}` but the consumer decodes `{}`",
                crate::mapper::type_to_string(producer),
                crate::mapper::type_to_string(consumer)
            ),
            breaks,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn check_udt_flow(
    producer_name: &str,
    producer_spec: &ContractSpec,
    consumer_name: &str,
    consumer_spec: &ContractSpec,
    path: &str,
    visiting: &mut HashSet<(String, String)>,
    breaks: &mut Vec<CallAbiBreak>,
    function: &str,
) {
    let pair = (producer_name.to_string(), consumer_name.to_string());
    if !visiting.insert(pair.clone()) {
        return;
    }

    if let (Some(a), Some(b)) = (
        producer_spec.structs.get(producer_name),
        consumer_spec.structs.get(consumer_name),
    ) {
        // Soroban named structs convert to a map. Their required symbol-keyed
        // field set must match; field declaration order is not wire-significant.
        let a_fields: std::collections::HashMap<_, _> = a
            .fields
            .iter()
            .map(|field| (field.name.to_string(), &field.type_))
            .collect();
        let b_fields: std::collections::HashMap<_, _> = b
            .fields
            .iter()
            .map(|field| (field.name.to_string(), &field.type_))
            .collect();
        let a_names: HashSet<_> = a_fields.keys().cloned().collect();
        let b_names: HashSet<_> = b_fields.keys().cloned().collect();
        if a_names != b_names {
            breaks.push(CallAbiBreak {
                function: function.to_string(),
                path: path.to_string(),
                reason: format!(
                    "the encoded struct fields {:?} do not match required fields {:?}",
                    sorted(a_names),
                    sorted(b_names)
                ),
            });
        } else {
            for name in sorted(a_names) {
                check_value_flow(
                    a_fields[&name],
                    producer_spec,
                    b_fields[&name],
                    consumer_spec,
                    &format!("{path}.{name}"),
                    visiting,
                    breaks,
                    function,
                );
            }
        }
    } else if let (Some(a), Some(b)) = (
        producer_spec.enums.get(producer_name),
        consumer_spec.enums.get(consumer_name),
    ) {
        let produced: HashSet<u32> = a.cases.iter().map(|case| case.value).collect();
        let accepted: HashSet<u32> = b.cases.iter().map(|case| case.value).collect();
        for value in sorted(produced.difference(&accepted).copied().collect()) {
            breaks.push(CallAbiBreak {
                function: function.to_string(),
                path: format!("{path}.case[{value}]"),
                reason: format!("the producer may encode enum discriminant {value}, which the consumer does not define"),
            });
        }
    } else if let (Some(a), Some(b)) = (
        producer_spec.unions.get(producer_name),
        consumer_spec.unions.get(consumer_name),
    ) {
        let b_cases: std::collections::HashMap<_, _> = b
            .cases
            .iter()
            .map(|case| (union_case_name(case), case))
            .collect();
        for a_case in a.cases.iter() {
            let case_name = union_case_name(a_case);
            let Some(b_case) = b_cases.get(&case_name) else {
                breaks.push(CallAbiBreak {
                    function: function.to_string(),
                    path: format!("{path}.case.{case_name}"),
                    reason: "the producer may encode a union case the consumer does not define"
                        .to_string(),
                });
                continue;
            };
            match (a_case, *b_case) {
                (ScSpecUdtUnionCaseV0::VoidV0(_), ScSpecUdtUnionCaseV0::VoidV0(_)) => {}
                (ScSpecUdtUnionCaseV0::TupleV0(a), ScSpecUdtUnionCaseV0::TupleV0(b))
                    if a.type_.len() == b.type_.len() =>
                {
                    for (index, (a, b)) in a.type_.iter().zip(b.type_.iter()).enumerate() {
                        check_value_flow(
                            a,
                            producer_spec,
                            b,
                            consumer_spec,
                            &format!("{path}.case.{case_name}[{index}]"),
                            visiting,
                            breaks,
                            function,
                        );
                    }
                }
                _ => breaks.push(CallAbiBreak {
                    function: function.to_string(),
                    path: format!("{path}.case.{case_name}"),
                    reason: "the union case payload shape differs from the consumer decoder"
                        .to_string(),
                }),
            }
        }
    } else if let (Some(a), Some(b)) = (
        producer_spec.error_enums.get(producer_name),
        consumer_spec.error_enums.get(consumer_name),
    ) {
        let produced: HashSet<u32> = a.cases.iter().map(|case| case.value).collect();
        let accepted: HashSet<u32> = b.cases.iter().map(|case| case.value).collect();
        for value in sorted(produced.difference(&accepted).copied().collect()) {
            breaks.push(CallAbiBreak {
                function: function.to_string(),
                path: format!("{path}.error[{value}]"),
                reason: format!("the producer may encode contract error {value}, which the consumer does not define"),
            });
        }
    } else {
        breaks.push(CallAbiBreak {
            function: function.to_string(),
            path: path.to_string(),
            reason: format!(
                "the producer type `{producer_name}` and consumer type `{consumer_name}` are not the same Soroban UDT kind"
            ),
        });
    }

    visiting.remove(&pair);
}

fn union_case_name(case: &ScSpecUdtUnionCaseV0) -> String {
    match case {
        ScSpecUdtUnionCaseV0::VoidV0(case) => case.name.to_string(),
        ScSpecUdtUnionCaseV0::TupleV0(case) => case.name.to_string(),
    }
}

fn sorted<T: Ord>(values: HashSet<T>) -> Vec<T> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort();
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{
        ScSpecFunctionInputV0, ScSpecFunctionV0, ScSpecTypeOption, ScSpecTypeResult, ScSpecTypeUdt,
        ScSpecUdtEnumCaseV0, ScSpecUdtEnumV0, ScSpecUdtStructFieldV0, ScSpecUdtStructV0, StringM,
        VecM,
    };

    fn function(
        name: &str,
        inputs: Vec<ScSpecTypeDef>,
        outputs: Vec<ScSpecTypeDef>,
    ) -> ScSpecFunctionV0 {
        ScSpecFunctionV0 {
            doc: StringM::default(),
            name: name.try_into().unwrap(),
            inputs: VecM::try_from(
                inputs
                    .into_iter()
                    .enumerate()
                    .map(|(i, type_)| ScSpecFunctionInputV0 {
                        doc: StringM::default(),
                        name: format!("p{i}").try_into().unwrap(),
                        type_,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
            outputs: VecM::try_from(outputs).unwrap(),
        }
    }

    fn one_function(input: ScSpecTypeDef, output: ScSpecTypeDef) -> ContractSpec {
        let mut spec = ContractSpec::default();
        spec.functions
            .insert("call".into(), function("call", vec![input], vec![output]));
        spec
    }

    fn udt(name: &str) -> ScSpecTypeDef {
        ScSpecTypeDef::Udt(ScSpecTypeUdt {
            name: name.try_into().unwrap(),
        })
    }

    fn add_struct(spec: &mut ContractSpec, fields: Vec<(&str, ScSpecTypeDef)>) {
        spec.structs.insert(
            "Data".into(),
            ScSpecUdtStructV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Data".try_into().unwrap(),
                fields: VecM::try_from(
                    fields
                        .into_iter()
                        .map(|(name, type_)| ScSpecUdtStructFieldV0 {
                            doc: StringM::default(),
                            name: name.try_into().unwrap(),
                            type_,
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
            },
        );
    }

    fn add_enum(spec: &mut ContractSpec, values: &[u32]) {
        spec.enums.insert(
            "Choice".into(),
            ScSpecUdtEnumV0 {
                doc: StringM::default(),
                lib: StringM::default(),
                name: "Choice".try_into().unwrap(),
                cases: VecM::try_from(
                    values
                        .iter()
                        .map(|value| ScSpecUdtEnumCaseV0 {
                            doc: StringM::default(),
                            name: format!("C{value}").try_into().unwrap(),
                            value: *value,
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
            },
        );
    }

    #[test]
    fn function_addition_only_breaks_new_clients_calling_old_contract() {
        let old = ContractSpec::default();
        let mut new = ContractSpec::default();
        new.functions
            .insert("added".into(), function("added", vec![], vec![]));
        let result = compare(&old, &new);
        assert!(result.old_client_to_new_contract.compatible);
        assert!(!result.new_client_to_old_contract.compatible);
        assert_eq!(
            result.new_client_to_old_contract.breaks[0].path,
            "function.added"
        );
    }

    #[test]
    fn parameter_arity_breaks_both_directions() {
        let mut old = ContractSpec::default();
        let mut new = ContractSpec::default();
        old.functions.insert(
            "call".into(),
            function("call", vec![ScSpecTypeDef::U32], vec![]),
        );
        new.functions.insert(
            "call".into(),
            function("call", vec![ScSpecTypeDef::U32, ScSpecTypeDef::U32], vec![]),
        );
        let result = compare(&old, &new);
        assert!(!result.old_client_to_new_contract.compatible);
        assert!(!result.new_client_to_old_contract.compatible);
    }

    #[test]
    fn enum_addition_is_directional_for_arguments_and_returns() {
        let mut old = one_function(udt("Choice"), udt("Choice"));
        let mut new = one_function(udt("Choice"), udt("Choice"));
        add_enum(&mut old, &[1]);
        add_enum(&mut new, &[1, 2]);
        let result = compare(&old, &new);
        let old_to_new = &result.old_client_to_new_contract.breaks;
        let new_to_old = &result.new_client_to_old_contract.breaks;
        assert!(old_to_new
            .iter()
            .any(|b| b.path.ends_with("return[0].case[2]")));
        assert!(new_to_old
            .iter()
            .any(|b| b.path.ends_with("argument[0].case[2]")));
    }

    #[test]
    fn nested_result_path_identifies_the_breaking_arm_and_field() {
        let nested_old = ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
            ok_type: Box::new(udt("Data")),
            error_type: Box::new(ScSpecTypeDef::U32),
        }));
        let nested_new = ScSpecTypeDef::Result(Box::new(ScSpecTypeResult {
            ok_type: Box::new(udt("Data")),
            error_type: Box::new(ScSpecTypeDef::U32),
        }));
        let mut old = one_function(ScSpecTypeDef::U32, nested_old);
        let mut new = one_function(ScSpecTypeDef::U32, nested_new);
        add_struct(&mut old, vec![("value", ScSpecTypeDef::U32)]);
        add_struct(&mut new, vec![("value", ScSpecTypeDef::U64)]);
        let result = compare(&old, &new);
        assert_eq!(
            result.old_client_to_new_contract.breaks[0].path,
            "function.call.return[0].ok.value"
        );
    }

    #[test]
    fn val_consumer_accepts_specific_values_but_specific_consumer_rejects_val() {
        let old = one_function(ScSpecTypeDef::U32, ScSpecTypeDef::U32);
        let new = one_function(ScSpecTypeDef::Val, ScSpecTypeDef::Val);
        let result = compare(&old, &new);
        assert!(result
            .old_client_to_new_contract
            .breaks
            .iter()
            .all(|b| !b.path.contains("argument")));
        assert!(result
            .new_client_to_old_contract
            .breaks
            .iter()
            .any(|b| b.path.contains("argument")));
        assert!(result
            .old_client_to_new_contract
            .breaks
            .iter()
            .any(|b| b.path.contains("return")));
    }

    #[test]
    fn option_recursion_reports_some_path() {
        let old = one_function(
            ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
                value_type: Box::new(ScSpecTypeDef::U32),
            })),
            ScSpecTypeDef::U32,
        );
        let new = one_function(
            ScSpecTypeDef::Option(Box::new(ScSpecTypeOption {
                value_type: Box::new(ScSpecTypeDef::U64),
            })),
            ScSpecTypeDef::U32,
        );
        assert!(compare(&old, &new).old_client_to_new_contract.breaks[0]
            .path
            .ends_with("argument[0].some"));
    }
}

# Finding Category Reference

Every category that the comparison analysis may emit, grouped by domain, with its default severity, what triggers it, and remediation guidance.

> **Note**: For suppression rules, match on the exact **category string** shown in the table. See [Suppressing Known Breaking Changes](../docs/documentation.md#suppressing-known-breaking-changes) for details.

| Category | Default Severity | Trigger | Remediation |
| --- | --- | --- | --- |
| `Environment` | 🔵 Info | The environment metadata (protocol version, SDK version) between the two contracts differs. | Verify that the target network supports the new protocol version and adjust any SDK/tooling dependencies accordingly. |
| `Function Removed` | 🔴 Critical | A function that existed in the old contract is absent from the new contract. | This is a breaking change. If the function is no longer needed, deprecate it in client integrations. Otherwise, restore the function signature. |
| `Function Documentation Changed` | 🔵 Info | A function's doc string changed between the two builds. | No code changes required. Ensure client/consumer integrations are aware of the updated documentation/behavior. |
| `Function Added` | 🔵 Info | A new function appears in the new contract that did not exist in the old contract. | No action required. Inform client integrations about the availability of the new function. |
| `Function Signature Changed` | 🔴 Critical | The number of parameters in a function changed. | This is a breaking change. Update call sites, SDKs, and tests to match the new parameter structure. |
| `Parameter Renamed` | 🟡 Warning | A parameter changed its name while keeping its position. | This is a breaking change for named-argument RPC systems. Update all client integrations to use the new parameter name. |
| `Parameter Reordered` | 🔴 Critical | The set of parameter names is unchanged, but their positional order differs. | This is a breaking change. Reordering parameters breaks positional RPC invocation. Restore the original parameter order. |
| `Parameter Type Changed` | 🔴 Critical | A parameter's type changed (and it is not a BytesN size change). | This is a breaking change. Update caller arguments and client SDKs to match the new parameter type. |
| `Return Type Changed` | 🔴 Critical | The return type count or types of a function changed. | This is a breaking change. Update caller expectations and client SDKs to match the new return type. |
| `BytesN Size Changed` | 🔴 Critical | A fixed-size byte array (BytesN) changed its size, altering its binary encoding. | This is a breaking change. Changing the size of a fixed-size byte array alters its binary encoding. Revert the size or migrate data that depends on the original byte length. |
| `Event Definition Removed` | 🔴 Critical | An event-related struct was removed entirely. | This is a breaking change. Update or remove downstream event indexing or monitoring systems that consume this event. |
| `Struct Removed` | 🔴 Critical | A non-event struct was removed entirely. | This is a breaking change. Ensure no stored data or active interfaces reference this struct. If they do, restore the struct. |
| `Struct Documentation Changed` | 🔵 Info | A struct's doc string changed. | No code changes required. Ensure documentation changes are aligned with the struct's intended usage. |
| `Struct Added` | 🔵 Info | A new struct was added. | No action required. New structs can be safely integrated into storage layouts or interface parameters. |
| `Struct Field Removed` | 🔴 Critical | A field was removed from a non-event struct. | This is a breaking change. Removing fields breaks serialized storage layouts. Restore the field or perform a state migration. |
| `Struct Field Reordered` | 🔴 Critical | Fields in a non-event struct were reordered (positional names differ). | This is a breaking change. Reordering fields breaks positional serialization layouts. Restore the original field order. |
| `Struct Field Type Changed` | 🔴 Critical | A field type in a non-event struct changed (not a BytesN resize). | This is a breaking change. Changing field types breaks layout serialization. Revert the type change or migrate existing data. |
| `Struct Field Added` | 🟡 Warning | A new field was appended to a struct. | Warning: Ensure existing storage entries are migrated or initialized with correct default values for the new field. |
| `Event Schema Removed` | 🔴 Critical | A field was removed from an event-related struct. | This is a breaking change. Update event indexers and consumers that expect this field to be present. |
| `Event Schema Reordered` | 🔴 Critical | Fields in an event-related struct were reordered. | This is a breaking change. Update event indexers and consumers to handle the new positional field order. |
| `Event Schema Type Changed` | 🔴 Critical | A field type in an event-related struct changed. | This is a breaking change. Update event indexers and consumers to handle the new field type. |
| `Event Enum Removed` | 🔴 Critical | An event-related enum was removed entirely. | This is a breaking change. Downstream event consumers or indexers relying on this enum will fail. Restore the enum. |
| `Enum Removed` | 🔴 Critical | A non-event enum was removed entirely. | This is a breaking change. Stored data or parameters using this enum will be invalid. Restore the enum. |
| `Enum Documentation Changed` | 🔵 Info | An enum's doc string changed. | No code changes required. Ensure the updated docs are clear for consumers. |
| `Enum Added` | 🔵 Info | A new enum was added. | No action required. Ensure consumers are aware of the new enum type if needed. |
| `Enum Case Removed` | 🔴 Critical | A case was removed from a non-event enum. | This is a breaking change. On-chain data or parameters using this case will be invalid. Restore the case. |
| `Enum Case Value Changed` | 🔴 Critical | A case value changed in a non-event enum. | This is a breaking change. Modifying case values breaks serialization/deserialization. Revert the value change. |
| `Enum Case Added` | 🔵 Info | A new case was added to a non-event enum. | No action required. Ensure consumers can handle the new case gracefully. |
| `Event Enum Case Removed` | 🔴 Critical | A case was removed from an event-related enum. | This is a breaking change. Downstream event indexers or consumers relying on this case will fail. Restore the case. |
| `Event Enum Case Value Changed` | 🔴 Critical | A case value changed in an event-related enum. | This is a breaking change. Downstream event indexers or consumers relying on these values will fail. Revert the value change. |
| `Event Enum Case Added` | 🔵 Info | A new case was added to an event-related enum. | No action required. Update event indexers and consumers to handle the new event enum case if necessary. |
| `Union Removed` | 🔴 Critical | A union was removed entirely. | This is a breaking change. Stored data or parameters using this union will be invalid. Restore the union. |
| `Union Added` | 🔵 Info | A new union was added. | No action required. Ensure consumers are aware of the new union type if needed. |
| `Union Case Removed` | 🔴 Critical | A case was removed from a union. | This is a breaking change. On-chain data using this union case will be invalid. Restore the case. |
| `Union Case Reordered` | 🔴 Critical | Union cases were reordered (positional names differ). | This is a breaking change. Reordering union cases breaks positional discriminant serialization. Restore the original case order. |
| `Union Case Type Changed` | 🔴 Critical | A union case payload type changed. | This is a breaking change. Changing union case payload types breaks layout serialization. Revert the type change or migrate existing data. |
| `Union Case Added` | 🔵 Info | A new case was appended to a union. | No action required. Ensure consumers can handle the new union case gracefully. |
| `Error Enum Removed` | 🔴 Critical | An error enum was removed entirely. | This is a breaking change. Clients matching on these error codes will break. Restore the error enum. |
| `Error Enum Added` | 🔵 Info | A new error enum was added. | No action required. Inform client integrations about the new error enum if needed. |
| `Error Enum Case Removed` | 🔴 Critical | A case was removed from an error enum. | This is a breaking change. Clients matching on this error code will break. Restore the case. |
| `Error Enum Case Value Changed` | 🔴 Critical | A case value changed in an error enum. | This is a breaking change. Modifying error case values breaks error-code compatibility. Revert the value change. |
| `Error Enum Case Added` | 🔵 Info | A new case was added to an error enum. | No action required. Ensure clients can handle the new error case gracefully. |
| `Type Kind Changed` | 🔴 Critical | A type kept its name but changed its kind (e.g. struct → enum). | This is a breaking change. The type kept its name but is now a different kind of type (struct, enum, union, or error enum), so its serialized layout changed entirely. Stored data written as the old kind cannot be decoded as the new one. Restore the original kind, or migrate the stored data and give the replacement a new name. |
| `Cascading Layout Break` | 🔴 Critical | A type embeds another type that has a critical layout break. | This is a breaking change. A nested user-defined type has a breaking layout change. Resolve the break in the referenced type. |
| `Host Import Added` | 🟡 Warning | The new contract imports a recognized Soroban host function that the old contract did not import. | Verify the target network has activated the required protocol version before deploying, and that any client tooling accounts for the new capability. |
| `Host Import Removed` | 🔵 Info | A recognized Soroban host function that the old contract imported is no longer imported by the new contract. | No action is typically required. If external tooling detects the old capability to gate behavior, update it to stop expecting the import. |
| `Host Import Signature Changed` | 🟡 Warning | The same module/name import appears in both builds, but its resolved parameter or result types differ. | Investigate why the same import now resolves to a different function type. For a recognized capability this should not happen and may indicate a toolchain or build issue; for an unrecognized import, confirm the provider did not change its calling convention. |
| `Unknown Host Import` | 🟡 Warning | An import's module/name pair is not present in the host import capability registry, so its protocol requirement cannot be determined. | Manually verify the protocol or provider requirement for this import, then consider proposing it for addition to the capability registry so future comparisons classify it automatically. |
| `Protocol Requirement Raised` | 🟡 Warning | The minimum Stellar protocol version implied by the new contract's recognized host imports is higher than the old contract's. | Confirm the target network has activated the reported protocol version before deploying the upgrade, and update deployment documentation accordingly. |
| `Protocol Environment Mismatch` | 🔴 Critical | A contract's declared environment metadata protocol version is lower than the minimum protocol implied by its own recognized host imports. | This indicates the build's declared environment metadata undersells what it actually requires. Rebuild with a matching SDK/toolchain version, or investigate how the binary was produced. |

use crate::diff::Severity;

/// Every finding category emitted by the comparison analysis.
///
/// This is the single source of truth for category strings, default
/// severities, trigger descriptions, and remediation guidance.  All
/// category string literals in [`crate::diff`] are derived from this
/// enum so that adding, removing, or renaming a category is a single
/// change that also updates the reference documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingCategory {
    Environment,
    FunctionRemoved,
    FunctionDocumentationChanged,
    FunctionAdded,
    FunctionSignatureChanged,
    ParameterRenamed,
    ParameterReordered,
    ParameterTypeChanged,
    ReturnTypeChanged,
    BytesNSizeChanged,
    EventDefinitionRemoved,
    StructRemoved,
    StructDocumentationChanged,
    StructAdded,
    StructFieldRemoved,
    StructFieldReordered,
    StructFieldTypeChanged,
    StructFieldAdded,
    EventSchemaRemoved,
    EventSchemaReordered,
    EventSchemaTypeChanged,
    EventEnumRemoved,
    EnumRemoved,
    EnumDocumentationChanged,
    EnumAdded,
    EnumCaseRemoved,
    EnumCaseValueChanged,
    EnumCaseAdded,
    EventEnumCaseRemoved,
    EventEnumCaseValueChanged,
    EventEnumCaseAdded,
    UnionRemoved,
    UnionAdded,
    UnionCaseRemoved,
    UnionCaseReordered,
    UnionCaseTypeChanged,
    UnionCaseAdded,
    ErrorEnumRemoved,
    ErrorEnumAdded,
    ErrorEnumCaseRemoved,
    ErrorEnumCaseValueChanged,
    ErrorEnumCaseAdded,
    TypeKindChanged,
    CascadingLayoutBreak,
    HostImportAdded,
    HostImportRemoved,
    HostImportSignatureChanged,
    UnknownHostImport,
    ProtocolRequirementRaised,
    ProtocolEnvironmentMismatch,
    MemoryAdded,
    MemoryRemoved,
    MemoryLimitsChanged,
    TableAdded,
    TableRemoved,
    TableLimitsChanged,
    TableElementTypeChanged,
    GlobalAdded,
    GlobalRemoved,
    GlobalMutabilityChanged,
    GlobalTypeChanged,
    StartFunctionAdded,
    StartFunctionRemoved,
    StartFunctionChanged,
    ElementSegmentChanged,
    DataSegmentChanged,
    WasmProposalAdded,
    WasmProposalRemoved,
}

impl std::str::FromStr for FindingCategory {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FindingCategory::find_by_name(s).ok_or(())
    }
}

impl FindingCategory {
    /// The exact category string used in findings and suppression rules.
    /// These strings are **stable** — renaming a variant here changes
    /// `as_str` and all downstream category references.
    pub fn as_str(self) -> &'static str {
        match self {
            FindingCategory::Environment => "Environment",
            FindingCategory::FunctionRemoved => "Function Removed",
            FindingCategory::FunctionDocumentationChanged => "Function Documentation Changed",
            FindingCategory::FunctionAdded => "Function Added",
            FindingCategory::FunctionSignatureChanged => "Function Signature Changed",
            FindingCategory::ParameterRenamed => "Parameter Renamed",
            FindingCategory::ParameterReordered => "Parameter Reordered",
            FindingCategory::ParameterTypeChanged => "Parameter Type Changed",
            FindingCategory::ReturnTypeChanged => "Return Type Changed",
            FindingCategory::BytesNSizeChanged => "BytesN Size Changed",
            FindingCategory::EventDefinitionRemoved => "Event Definition Removed",
            FindingCategory::StructRemoved => "Struct Removed",
            FindingCategory::StructDocumentationChanged => "Struct Documentation Changed",
            FindingCategory::StructAdded => "Struct Added",
            FindingCategory::StructFieldRemoved => "Struct Field Removed",
            FindingCategory::StructFieldReordered => "Struct Field Reordered",
            FindingCategory::StructFieldTypeChanged => "Struct Field Type Changed",
            FindingCategory::StructFieldAdded => "Struct Field Added",
            FindingCategory::EventSchemaRemoved => "Event Schema Removed",
            FindingCategory::EventSchemaReordered => "Event Schema Reordered",
            FindingCategory::EventSchemaTypeChanged => "Event Schema Type Changed",
            FindingCategory::EventEnumRemoved => "Event Enum Removed",
            FindingCategory::EnumRemoved => "Enum Removed",
            FindingCategory::EnumDocumentationChanged => "Enum Documentation Changed",
            FindingCategory::EnumAdded => "Enum Added",
            FindingCategory::EnumCaseRemoved => "Enum Case Removed",
            FindingCategory::EnumCaseValueChanged => "Enum Case Value Changed",
            FindingCategory::EnumCaseAdded => "Enum Case Added",
            FindingCategory::EventEnumCaseRemoved => "Event Enum Case Removed",
            FindingCategory::EventEnumCaseValueChanged => "Event Enum Case Value Changed",
            FindingCategory::EventEnumCaseAdded => "Event Enum Case Added",
            FindingCategory::UnionRemoved => "Union Removed",
            FindingCategory::UnionAdded => "Union Added",
            FindingCategory::UnionCaseRemoved => "Union Case Removed",
            FindingCategory::UnionCaseReordered => "Union Case Reordered",
            FindingCategory::UnionCaseTypeChanged => "Union Case Type Changed",
            FindingCategory::UnionCaseAdded => "Union Case Added",
            FindingCategory::ErrorEnumRemoved => "Error Enum Removed",
            FindingCategory::ErrorEnumAdded => "Error Enum Added",
            FindingCategory::ErrorEnumCaseRemoved => "Error Enum Case Removed",
            FindingCategory::ErrorEnumCaseValueChanged => "Error Enum Case Value Changed",
            FindingCategory::ErrorEnumCaseAdded => "Error Enum Case Added",
            FindingCategory::TypeKindChanged => "Type Kind Changed",
            FindingCategory::CascadingLayoutBreak => "Cascading Layout Break",
            FindingCategory::HostImportAdded => "Host Import Added",
            FindingCategory::HostImportRemoved => "Host Import Removed",
            FindingCategory::HostImportSignatureChanged => "Host Import Signature Changed",
            FindingCategory::UnknownHostImport => "Unknown Host Import",
            FindingCategory::ProtocolRequirementRaised => "Protocol Requirement Raised",
            FindingCategory::ProtocolEnvironmentMismatch => "Protocol Environment Mismatch",
            FindingCategory::MemoryAdded => "Memory Added",
            FindingCategory::MemoryRemoved => "Memory Removed",
            FindingCategory::MemoryLimitsChanged => "Memory Limits Changed",
            FindingCategory::TableAdded => "Table Added",
            FindingCategory::TableRemoved => "Table Removed",
            FindingCategory::TableLimitsChanged => "Table Limits Changed",
            FindingCategory::TableElementTypeChanged => "Table Element Type Changed",
            FindingCategory::GlobalAdded => "Global Added",
            FindingCategory::GlobalRemoved => "Global Removed",
            FindingCategory::GlobalMutabilityChanged => "Global Mutability Changed",
            FindingCategory::GlobalTypeChanged => "Global Type Changed",
            FindingCategory::StartFunctionAdded => "Start Function Added",
            FindingCategory::StartFunctionRemoved => "Start Function Removed",
            FindingCategory::StartFunctionChanged => "Start Function Changed",
            FindingCategory::ElementSegmentChanged => "Element Segment Changed",
            FindingCategory::DataSegmentChanged => "Data Segment Changed",
            FindingCategory::WasmProposalAdded => "WASM Proposal Added",
            FindingCategory::WasmProposalRemoved => "WASM Proposal Removed",
        }
    }

    /// The default severity for this category.
    ///
    /// Note: [`Environment`](FindingCategory::Environment) may be
    /// promoted to `Warning` at runtime when the protocol version
    /// changes; the default returned here is `Info`.
    pub fn severity(self) -> Severity {
        match self {
            FindingCategory::Environment => Severity::Info,
            FindingCategory::FunctionRemoved => Severity::Critical,
            FindingCategory::FunctionDocumentationChanged => Severity::Info,
            FindingCategory::FunctionAdded => Severity::Info,
            FindingCategory::FunctionSignatureChanged => Severity::Critical,
            FindingCategory::ParameterRenamed => Severity::Warning,
            FindingCategory::ParameterReordered => Severity::Critical,
            FindingCategory::ParameterTypeChanged => Severity::Critical,
            FindingCategory::ReturnTypeChanged => Severity::Critical,
            FindingCategory::BytesNSizeChanged => Severity::Critical,
            FindingCategory::EventDefinitionRemoved => Severity::Critical,
            FindingCategory::StructRemoved => Severity::Critical,
            FindingCategory::StructDocumentationChanged => Severity::Info,
            FindingCategory::StructAdded => Severity::Info,
            FindingCategory::StructFieldRemoved => Severity::Critical,
            FindingCategory::StructFieldReordered => Severity::Critical,
            FindingCategory::StructFieldTypeChanged => Severity::Critical,
            FindingCategory::StructFieldAdded => Severity::Warning,
            FindingCategory::EventSchemaRemoved => Severity::Critical,
            FindingCategory::EventSchemaReordered => Severity::Critical,
            FindingCategory::EventSchemaTypeChanged => Severity::Critical,
            FindingCategory::EventEnumRemoved => Severity::Critical,
            FindingCategory::EnumRemoved => Severity::Critical,
            FindingCategory::EnumDocumentationChanged => Severity::Info,
            FindingCategory::EnumAdded => Severity::Info,
            FindingCategory::EnumCaseRemoved => Severity::Critical,
            FindingCategory::EnumCaseValueChanged => Severity::Critical,
            FindingCategory::EnumCaseAdded => Severity::Info,
            FindingCategory::EventEnumCaseRemoved => Severity::Critical,
            FindingCategory::EventEnumCaseValueChanged => Severity::Critical,
            FindingCategory::EventEnumCaseAdded => Severity::Info,
            FindingCategory::UnionRemoved => Severity::Critical,
            FindingCategory::UnionAdded => Severity::Info,
            FindingCategory::UnionCaseRemoved => Severity::Critical,
            FindingCategory::UnionCaseReordered => Severity::Critical,
            FindingCategory::UnionCaseTypeChanged => Severity::Critical,
            FindingCategory::UnionCaseAdded => Severity::Info,
            FindingCategory::ErrorEnumRemoved => Severity::Critical,
            FindingCategory::ErrorEnumAdded => Severity::Info,
            FindingCategory::ErrorEnumCaseRemoved => Severity::Critical,
            FindingCategory::ErrorEnumCaseValueChanged => Severity::Critical,
            FindingCategory::ErrorEnumCaseAdded => Severity::Info,
            FindingCategory::TypeKindChanged => Severity::Critical,
            FindingCategory::CascadingLayoutBreak => Severity::Critical,
            FindingCategory::HostImportAdded => Severity::Warning,
            FindingCategory::HostImportRemoved => Severity::Info,
            FindingCategory::HostImportSignatureChanged => Severity::Warning,
            FindingCategory::UnknownHostImport => Severity::Warning,
            FindingCategory::ProtocolRequirementRaised => Severity::Warning,
            FindingCategory::ProtocolEnvironmentMismatch => Severity::Critical,
            FindingCategory::MemoryAdded => Severity::Info,
            FindingCategory::MemoryRemoved => Severity::Critical,
            FindingCategory::MemoryLimitsChanged => Severity::Warning,
            FindingCategory::TableAdded => Severity::Info,
            FindingCategory::TableRemoved => Severity::Critical,
            FindingCategory::TableLimitsChanged => Severity::Warning,
            FindingCategory::TableElementTypeChanged => Severity::Critical,
            FindingCategory::GlobalAdded => Severity::Info,
            FindingCategory::GlobalRemoved => Severity::Warning,
            FindingCategory::GlobalMutabilityChanged => Severity::Critical,
            FindingCategory::GlobalTypeChanged => Severity::Critical,
            FindingCategory::StartFunctionAdded => Severity::Critical,
            FindingCategory::StartFunctionRemoved => Severity::Warning,
            FindingCategory::StartFunctionChanged => Severity::Warning,
            FindingCategory::ElementSegmentChanged => Severity::Info,
            FindingCategory::DataSegmentChanged => Severity::Info,
            FindingCategory::WasmProposalAdded => Severity::Warning,
            FindingCategory::WasmProposalRemoved => Severity::Info,
        }
    }

    /// A short description of what triggers this finding.
    pub fn trigger_description(self) -> &'static str {
        match self {
            FindingCategory::Environment => {
                "The environment metadata (protocol version, SDK version) between the two contracts differs."
            }
            FindingCategory::FunctionRemoved => {
                "A function that existed in the old contract is absent from the new contract."
            }
            FindingCategory::FunctionDocumentationChanged => {
                "A function's doc string changed between the two builds."
            }
            FindingCategory::FunctionAdded => {
                "A new function appears in the new contract that did not exist in the old contract."
            }
            FindingCategory::FunctionSignatureChanged => {
                "The number of parameters in a function changed."
            }
            FindingCategory::ParameterRenamed => {
                "A parameter changed its name while keeping its position."
            }
            FindingCategory::ParameterReordered => {
                "The set of parameter names is unchanged, but their positional order differs."
            }
            FindingCategory::ParameterTypeChanged => {
                "A parameter's type changed (and it is not a BytesN size change)."
            }
            FindingCategory::ReturnTypeChanged => {
                "The return type count or types of a function changed."
            }
            FindingCategory::BytesNSizeChanged => {
                "A fixed-size byte array (BytesN) changed its size, altering its binary encoding."
            }
            FindingCategory::EventDefinitionRemoved => {
                "An event-related struct was removed entirely."
            }
            FindingCategory::StructRemoved => {
                "A non-event struct was removed entirely."
            }
            FindingCategory::StructDocumentationChanged => {
                "A struct's doc string changed."
            }
            FindingCategory::StructAdded => {
                "A new struct was added."
            }
            FindingCategory::StructFieldRemoved => {
                "A field was removed from a non-event struct."
            }
            FindingCategory::StructFieldReordered => {
                "Fields in a non-event struct were reordered (positional names differ)."
            }
            FindingCategory::StructFieldTypeChanged => {
                "A field type in a non-event struct changed (not a BytesN resize)."
            }
            FindingCategory::StructFieldAdded => {
                "A new field was appended to a struct."
            }
            FindingCategory::EventSchemaRemoved => {
                "A field was removed from an event-related struct."
            }
            FindingCategory::EventSchemaReordered => {
                "Fields in an event-related struct were reordered."
            }
            FindingCategory::EventSchemaTypeChanged => {
                "A field type in an event-related struct changed."
            }
            FindingCategory::EventEnumRemoved => {
                "An event-related enum was removed entirely."
            }
            FindingCategory::EnumRemoved => {
                "A non-event enum was removed entirely."
            }
            FindingCategory::EnumDocumentationChanged => {
                "An enum's doc string changed."
            }
            FindingCategory::EnumAdded => {
                "A new enum was added."
            }
            FindingCategory::EnumCaseRemoved => {
                "A case was removed from a non-event enum."
            }
            FindingCategory::EnumCaseValueChanged => {
                "A case value changed in a non-event enum."
            }
            FindingCategory::EnumCaseAdded => {
                "A new case was added to a non-event enum."
            }
            FindingCategory::EventEnumCaseRemoved => {
                "A case was removed from an event-related enum."
            }
            FindingCategory::EventEnumCaseValueChanged => {
                "A case value changed in an event-related enum."
            }
            FindingCategory::EventEnumCaseAdded => {
                "A new case was added to an event-related enum."
            }
            FindingCategory::UnionRemoved => {
                "A union was removed entirely."
            }
            FindingCategory::UnionAdded => {
                "A new union was added."
            }
            FindingCategory::UnionCaseRemoved => {
                "A case was removed from a union."
            }
            FindingCategory::UnionCaseReordered => {
                "Union cases were reordered (positional names differ)."
            }
            FindingCategory::UnionCaseTypeChanged => {
                "A union case payload type changed."
            }
            FindingCategory::UnionCaseAdded => {
                "A new case was appended to a union."
            }
            FindingCategory::ErrorEnumRemoved => {
                "An error enum was removed entirely."
            }
            FindingCategory::ErrorEnumAdded => {
                "A new error enum was added."
            }
            FindingCategory::ErrorEnumCaseRemoved => {
                "A case was removed from an error enum."
            }
            FindingCategory::ErrorEnumCaseValueChanged => {
                "A case value changed in an error enum."
            }
            FindingCategory::ErrorEnumCaseAdded => {
                "A new case was added to an error enum."
            }
            FindingCategory::TypeKindChanged => {
                "A type kept its name but changed its kind (e.g. struct → enum)."
            }
            FindingCategory::CascadingLayoutBreak => {
                "A type embeds another type that has a critical layout break."
            }
            FindingCategory::HostImportAdded => {
                "The new contract imports a recognized Soroban host function that the old contract did not import."
            }
            FindingCategory::HostImportRemoved => {
                "A recognized Soroban host function that the old contract imported is no longer imported by the new contract."
            }
            FindingCategory::HostImportSignatureChanged => {
                "The same module/name import appears in both builds, but its resolved parameter or result types differ."
            }
            FindingCategory::UnknownHostImport => {
                "An import's module/name pair is not present in the host import capability registry, so its protocol requirement cannot be determined."
            }
            FindingCategory::ProtocolRequirementRaised => {
                "The minimum Stellar protocol version implied by the new contract's recognized host imports is higher than the old contract's."
            }
            FindingCategory::ProtocolEnvironmentMismatch => {
                "A contract's declared environment metadata protocol version is lower than the minimum protocol implied by its own recognized host imports."
            }
            FindingCategory::MemoryAdded => {
                "A WebAssembly memory declaration was added in the new contract build."
            }
            FindingCategory::MemoryRemoved => {
                "A WebAssembly memory declaration that existed in the old contract was removed."
            }
            FindingCategory::MemoryLimitsChanged => {
                "The initial pages, maximum pages, origin, or 64-bit/shared properties of a memory declaration changed."
            }
            FindingCategory::TableAdded => {
                "A WebAssembly table declaration was added in the new contract build."
            }
            FindingCategory::TableRemoved => {
                "A WebAssembly table declaration that existed in the old contract was removed."
            }
            FindingCategory::TableLimitsChanged => {
                "The initial or maximum element capacity of a table declaration changed."
            }
            FindingCategory::TableElementTypeChanged => {
                "The element type of a WebAssembly table changed (e.g. funcref vs externref)."
            }
            FindingCategory::GlobalAdded => {
                "A WebAssembly global variable declaration was added in the new contract build."
            }
            FindingCategory::GlobalRemoved => {
                "A WebAssembly global variable declaration that existed in the old contract was removed."
            }
            FindingCategory::GlobalMutabilityChanged => {
                "The mutability of a WebAssembly global variable changed between mutable and constant."
            }
            FindingCategory::GlobalTypeChanged => {
                "The value type of a WebAssembly global variable changed."
            }
            FindingCategory::StartFunctionAdded => {
                "A start function was added; the module will now execute initialization bytecode upon instantiation."
            }
            FindingCategory::StartFunctionRemoved => {
                "The module start function was removed; initialization bytecode will no longer execute automatically."
            }
            FindingCategory::StartFunctionChanged => {
                "The start function index changed to a different function."
            }
            FindingCategory::ElementSegmentChanged => {
                "Indirect-call element segments or table population counts changed."
            }
            FindingCategory::DataSegmentChanged => {
                "Data segment counts, active/passive modes, or byte payloads changed."
            }
            FindingCategory::WasmProposalAdded => {
                "The upgraded module requires a new WebAssembly proposal/feature not required by the previous build."
            }
            FindingCategory::WasmProposalRemoved => {
                "A WebAssembly proposal/feature required by the old contract is no longer required."
            }
        }
    }

    /// Remediation guidance for this finding category.
    pub fn remediation(self) -> &'static str {
        match self {
            FindingCategory::Environment => {
                "Verify that the target network supports the new protocol version and adjust any SDK/tooling dependencies accordingly."
            }
            FindingCategory::FunctionRemoved => {
                "This is a breaking change. If the function is no longer needed, deprecate it in client integrations. Otherwise, restore the function signature."
            }
            FindingCategory::FunctionDocumentationChanged => {
                "No code changes required. Ensure client/consumer integrations are aware of the updated documentation/behavior."
            }
            FindingCategory::FunctionAdded => {
                "No action required. Inform client integrations about the availability of the new function."
            }
            FindingCategory::FunctionSignatureChanged => {
                "This is a breaking change. Update call sites, SDKs, and tests to match the new parameter structure."
            }
            FindingCategory::ParameterRenamed => {
                "This is a breaking change for named-argument RPC systems. Update all client integrations to use the new parameter name."
            }
            FindingCategory::ParameterReordered => {
                "This is a breaking change. Reordering parameters breaks positional RPC invocation. Restore the original parameter order."
            }
            FindingCategory::ParameterTypeChanged => {
                "This is a breaking change. Update caller arguments and client SDKs to match the new parameter type."
            }
            FindingCategory::ReturnTypeChanged => {
                "This is a breaking change. Update caller expectations and client SDKs to match the new return type."
            }
            FindingCategory::BytesNSizeChanged => {
                "This is a breaking change. Changing the size of a fixed-size byte array alters its binary encoding. Revert the size or migrate data that depends on the original byte length."
            }
            FindingCategory::EventDefinitionRemoved => {
                "This is a breaking change. Update or remove downstream event indexing or monitoring systems that consume this event."
            }
            FindingCategory::StructRemoved => {
                "This is a breaking change. Ensure no stored data or active interfaces reference this struct. If they do, restore the struct."
            }
            FindingCategory::StructDocumentationChanged => {
                "No code changes required. Ensure documentation changes are aligned with the struct's intended usage."
            }
            FindingCategory::StructAdded => {
                "No action required. New structs can be safely integrated into storage layouts or interface parameters."
            }
            FindingCategory::StructFieldRemoved => {
                "This is a breaking change. Removing fields breaks serialized storage layouts. Restore the field or perform a state migration."
            }
            FindingCategory::StructFieldReordered => {
                "This is a breaking change. Reordering fields breaks positional serialization layouts. Restore the original field order."
            }
            FindingCategory::StructFieldTypeChanged => {
                "This is a breaking change. Changing field types breaks layout serialization. Revert the type change or migrate existing data."
            }
            FindingCategory::StructFieldAdded => {
                "Warning: Ensure existing storage entries are migrated or initialized with correct default values for the new field."
            }
            FindingCategory::EventSchemaRemoved => {
                "This is a breaking change. Update event indexers and consumers that expect this field to be present."
            }
            FindingCategory::EventSchemaReordered => {
                "This is a breaking change. Update event indexers and consumers to handle the new positional field order."
            }
            FindingCategory::EventSchemaTypeChanged => {
                "This is a breaking change. Update event indexers and consumers to handle the new field type."
            }
            FindingCategory::EventEnumRemoved => {
                "This is a breaking change. Downstream event consumers or indexers relying on this enum will fail. Restore the enum."
            }
            FindingCategory::EnumRemoved => {
                "This is a breaking change. Stored data or parameters using this enum will be invalid. Restore the enum."
            }
            FindingCategory::EnumDocumentationChanged => {
                "No code changes required. Ensure the updated docs are clear for consumers."
            }
            FindingCategory::EnumAdded => {
                "No action required. Ensure consumers are aware of the new enum type if needed."
            }
            FindingCategory::EnumCaseRemoved => {
                "This is a breaking change. On-chain data or parameters using this case will be invalid. Restore the case."
            }
            FindingCategory::EnumCaseValueChanged => {
                "This is a breaking change. Modifying case values breaks serialization/deserialization. Revert the value change."
            }
            FindingCategory::EnumCaseAdded => {
                "No action required. Ensure consumers can handle the new case gracefully."
            }
            FindingCategory::EventEnumCaseRemoved => {
                "This is a breaking change. Downstream event indexers or consumers relying on this case will fail. Restore the case."
            }
            FindingCategory::EventEnumCaseValueChanged => {
                "This is a breaking change. Downstream event indexers or consumers relying on these values will fail. Revert the value change."
            }
            FindingCategory::EventEnumCaseAdded => {
                "No action required. Update event indexers and consumers to handle the new event enum case if necessary."
            }
            FindingCategory::UnionRemoved => {
                "This is a breaking change. Stored data or parameters using this union will be invalid. Restore the union."
            }
            FindingCategory::UnionAdded => {
                "No action required. Ensure consumers are aware of the new union type if needed."
            }
            FindingCategory::UnionCaseRemoved => {
                "This is a breaking change. On-chain data using this union case will be invalid. Restore the case."
            }
            FindingCategory::UnionCaseReordered => {
                "This is a breaking change. Reordering union cases breaks positional discriminant serialization. Restore the original case order."
            }
            FindingCategory::UnionCaseTypeChanged => {
                "This is a breaking change. Changing union case payload types breaks layout serialization. Revert the type change or migrate existing data."
            }
            FindingCategory::UnionCaseAdded => {
                "No action required. Ensure consumers can handle the new union case gracefully."
            }
            FindingCategory::ErrorEnumRemoved => {
                "This is a breaking change. Clients matching on these error codes will break. Restore the error enum."
            }
            FindingCategory::ErrorEnumAdded => {
                "No action required. Inform client integrations about the new error enum if needed."
            }
            FindingCategory::ErrorEnumCaseRemoved => {
                "This is a breaking change. Clients matching on this error code will break. Restore the case."
            }
            FindingCategory::ErrorEnumCaseValueChanged => {
                "This is a breaking change. Modifying error case values breaks error-code compatibility. Revert the value change."
            }
            FindingCategory::ErrorEnumCaseAdded => {
                "No action required. Ensure clients can handle the new error case gracefully."
            }
            FindingCategory::TypeKindChanged => {
                "This is a breaking change. The type kept its name but is now a different kind of type (struct, enum, union, or error enum), so its serialized layout changed entirely. Stored data written as the old kind cannot be decoded as the new one. Restore the original kind, or migrate the stored data and give the replacement a new name."
            }
            FindingCategory::CascadingLayoutBreak => {
                "This is a breaking change. A nested user-defined type has a breaking layout change. Resolve the break in the referenced type."
            }
            FindingCategory::HostImportAdded => {
                "Verify the target network has activated the required protocol version before deploying, and that any client tooling accounts for the new capability."
            }
            FindingCategory::HostImportRemoved => {
                "No action is typically required. If external tooling detects the old capability to gate behavior, update it to stop expecting the import."
            }
            FindingCategory::HostImportSignatureChanged => {
                "Investigate why the same import now resolves to a different function type. For a recognized capability this should not happen and may indicate a toolchain or build issue; for an unrecognized import, confirm the provider did not change its calling convention."
            }
            FindingCategory::UnknownHostImport => {
                "Manually verify the protocol or provider requirement for this import, then consider proposing it for addition to the capability registry so future comparisons classify it automatically."
            }
            FindingCategory::ProtocolRequirementRaised => {
                "Confirm the target network has activated the reported protocol version before deploying the upgrade, and update deployment documentation accordingly."
            }
            FindingCategory::ProtocolEnvironmentMismatch => {
                "This indicates the build's declared environment metadata undersells what it actually requires. Rebuild with a matching SDK/toolchain version, or investigate how the binary was produced."
            }
            FindingCategory::MemoryAdded => {
                "If memory was newly added or imported, verify that the host runtime environment allocates sufficient memory pages for execution."
            }
            FindingCategory::MemoryRemoved => {
                "This is a breaking change. Removing memory will cause traps in any contract functions or external callers expecting memory access. Restore the memory declaration."
            }
            FindingCategory::MemoryLimitsChanged => {
                "Ensure memory page limits do not exceed the maximum allowed by the Soroban host environment, and that initial memory requirements remain compatible with callers."
            }
            FindingCategory::TableAdded => {
                "No action required if table is defined locally. For imported tables, verify the host provides the required table resource."
            }
            FindingCategory::TableRemoved => {
                "This is a breaking change. Removing a table breaks indirect function call dispatch (`call_indirect`). Restore the table."
            }
            FindingCategory::TableLimitsChanged => {
                "Ensure table element limits do not prevent indirect function call dispatch."
            }
            FindingCategory::TableElementTypeChanged => {
                "This is a breaking change. Changing table element types breaks indirect-call signatures and reference types. Revert the element type."
            }
            FindingCategory::GlobalAdded => {
                "No action required for internal compiler globals. For imported globals, confirm the host environment supplies the variable."
            }
            FindingCategory::GlobalRemoved => {
                "Removing global variables may alter internal state or host bindings. Ensure dependent functions are updated."
            }
            FindingCategory::GlobalMutabilityChanged => {
                "This is a breaking change. Changing a global from mutable to immutable (or vice versa) breaks initialization and mutation semantics. Restore the original mutability."
            }
            FindingCategory::GlobalTypeChanged => {
                "This is a breaking change. Modifying global variable types breaks internal operations and any host bindings. Revert the type change."
            }
            FindingCategory::StartFunctionAdded => {
                "Warning: Start functions execute automatically during module instantiation before any contract method is called. Verify that this initialization logic is safe and intentional."
            }
            FindingCategory::StartFunctionRemoved => {
                "Verify that module initialization is not required or has been moved to an explicit contract initialization function."
            }
            FindingCategory::StartFunctionChanged => {
                "Verify that the updated start function performs the intended module initialization without unintended side effects."
            }
            FindingCategory::ElementSegmentChanged => {
                "Ensure indirect call dispatch tables have sufficient entries for all function pointers used by the contract."
            }
            FindingCategory::DataSegmentChanged => {
                "No action typically required for internal data segment compiler optimizations unless active segment offsets exceed memory bounds."
            }
            FindingCategory::WasmProposalAdded => {
                "Verify that the target network and Soroban host environment support this WebAssembly proposal (e.g. SIMD, multi-memory, memory64)."
            }
            FindingCategory::WasmProposalRemoved => {
                "No action required. The contract has simplified its runtime feature requirements."
            }
        }
    }

    /// All defined finding categories, ordered by domain.
    pub fn all() -> &'static [FindingCategory] {
        &[
            FindingCategory::Environment,
            FindingCategory::FunctionRemoved,
            FindingCategory::FunctionDocumentationChanged,
            FindingCategory::FunctionAdded,
            FindingCategory::FunctionSignatureChanged,
            FindingCategory::ParameterRenamed,
            FindingCategory::ParameterReordered,
            FindingCategory::ParameterTypeChanged,
            FindingCategory::ReturnTypeChanged,
            FindingCategory::BytesNSizeChanged,
            FindingCategory::EventDefinitionRemoved,
            FindingCategory::StructRemoved,
            FindingCategory::StructDocumentationChanged,
            FindingCategory::StructAdded,
            FindingCategory::StructFieldRemoved,
            FindingCategory::StructFieldReordered,
            FindingCategory::StructFieldTypeChanged,
            FindingCategory::StructFieldAdded,
            FindingCategory::EventSchemaRemoved,
            FindingCategory::EventSchemaReordered,
            FindingCategory::EventSchemaTypeChanged,
            FindingCategory::EventEnumRemoved,
            FindingCategory::EnumRemoved,
            FindingCategory::EnumDocumentationChanged,
            FindingCategory::EnumAdded,
            FindingCategory::EnumCaseRemoved,
            FindingCategory::EnumCaseValueChanged,
            FindingCategory::EnumCaseAdded,
            FindingCategory::EventEnumCaseRemoved,
            FindingCategory::EventEnumCaseValueChanged,
            FindingCategory::EventEnumCaseAdded,
            FindingCategory::UnionRemoved,
            FindingCategory::UnionAdded,
            FindingCategory::UnionCaseRemoved,
            FindingCategory::UnionCaseReordered,
            FindingCategory::UnionCaseTypeChanged,
            FindingCategory::UnionCaseAdded,
            FindingCategory::ErrorEnumRemoved,
            FindingCategory::ErrorEnumAdded,
            FindingCategory::ErrorEnumCaseRemoved,
            FindingCategory::ErrorEnumCaseValueChanged,
            FindingCategory::ErrorEnumCaseAdded,
            FindingCategory::TypeKindChanged,
            FindingCategory::CascadingLayoutBreak,
            FindingCategory::HostImportAdded,
            FindingCategory::HostImportRemoved,
            FindingCategory::HostImportSignatureChanged,
            FindingCategory::UnknownHostImport,
            FindingCategory::ProtocolRequirementRaised,
            FindingCategory::ProtocolEnvironmentMismatch,
            FindingCategory::MemoryAdded,
            FindingCategory::MemoryRemoved,
            FindingCategory::MemoryLimitsChanged,
            FindingCategory::TableAdded,
            FindingCategory::TableRemoved,
            FindingCategory::TableLimitsChanged,
            FindingCategory::TableElementTypeChanged,
            FindingCategory::GlobalAdded,
            FindingCategory::GlobalRemoved,
            FindingCategory::GlobalMutabilityChanged,
            FindingCategory::GlobalTypeChanged,
            FindingCategory::StartFunctionAdded,
            FindingCategory::StartFunctionRemoved,
            FindingCategory::StartFunctionChanged,
            FindingCategory::ElementSegmentChanged,
            FindingCategory::DataSegmentChanged,
            FindingCategory::WasmProposalAdded,
            FindingCategory::WasmProposalRemoved,
        ]
    }

    /// Look up a variant by its exact category string.
    pub fn find_by_name(s: &str) -> Option<FindingCategory> {
        FindingCategory::all()
            .iter()
            .find(|c| c.as_str() == s)
            .copied()
    }

    /// Generate the full finding-category reference as Markdown.
    pub fn generate_markdown_reference() -> String {
        let mut md = String::new();
        md.push_str("# Finding Category Reference\n\n");
        md.push_str("Every category that the comparison analysis may emit, grouped by ");
        md.push_str("domain, with its default severity, what triggers it, and ");
        md.push_str("remediation guidance.\n\n");

        md.push_str("> **Note**: For suppression rules, match on the exact ");
        md.push_str("**category string** shown in the table. ");
        md.push_str("See [Suppressing Known Breaking Changes](../docs/documentation.md#suppressing-known-breaking-changes) ");
        md.push_str("for details.\n\n");

        let mut table = String::from("| Category | Default Severity | Trigger | Remediation |\n");
        table.push_str("| --- | --- | --- | --- |\n");

        for cat in FindingCategory::all() {
            let severity_str = match cat.severity() {
                Severity::Critical => "🔴 Critical",
                Severity::Warning => "🟡 Warning",
                Severity::Info => "🔵 Info",
            };

            table.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                cat.as_str(),
                severity_str,
                cat.trigger_description(),
                cat.remediation(),
            ));
        }

        md.push_str(&table);
        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_categories_have_unique_strings() {
        let mut seen = std::collections::HashSet::new();
        for cat in FindingCategory::all() {
            let s = cat.as_str();
            assert!(seen.insert(s), "Duplicate category string: '{}'", s);
        }
    }

    #[test]
    fn every_category_has_guidance() {
        for cat in FindingCategory::all() {
            let guidance = cat.remediation();
            assert!(
                !guidance.is_empty(),
                "Category '{}' has empty remediation guidance",
                cat.as_str()
            );
        }
    }

    #[test]
    fn every_category_has_trigger_description() {
        for cat in FindingCategory::all() {
            let desc = cat.trigger_description();
            assert!(
                !desc.is_empty(),
                "Category '{}' has empty trigger description",
                cat.as_str()
            );
        }
    }

    #[test]
    fn from_str_roundtrips_all_categories() {
        for cat in FindingCategory::all() {
            let s = cat.as_str();
            let back = FindingCategory::find_by_name(s);
            assert_eq!(back, Some(*cat), "from_str('{}') did not round-trip", s);
        }
    }

    #[test]
    fn generated_markdown_matches_committed_file() {
        let generated = FindingCategory::generate_markdown_reference();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs")
            .join("finding-categories.md");
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));

        // Git may materialize this text file with CRLF on Windows. Compare the
        // logical Markdown content rather than platform-specific line endings.
        if generated != committed.replace("\r\n", "\n") {
            // Write the generated content to a temp file for comparison.
            let tmp = std::env::temp_dir().join("finding-categories.generated.md");
            std::fs::write(&tmp, &generated).expect("Failed to write generated content");
            panic!(
                "docs/finding-categories.md is out of date!\n\
                 Generated content written to {}.\n\
                 To update: cp {} {}",
                tmp.display(),
                tmp.display(),
                path.display()
            );
        }
    }
}

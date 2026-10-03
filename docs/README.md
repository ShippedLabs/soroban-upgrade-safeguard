# Documentation Index

This folder contains comprehensive guides for using Soroban Upgrade Safeguard. Start with the main [README](../README.md) for installation and basic usage, then explore the guides below based on what you need.

## Getting Started

- [**glossary.md**](glossary.md) — Definitions of core terms used in reports and configuration (finding, category, axis, verdict, suppression, cascade, etc.)
- [**documentation.md**](documentation.md) — Full explanation of how the analysis pipeline works, severity levels, cascading layout breaks, and CI integration
- [**subcommand-guide.md**](subcommand-guide.md) — Task-oriented guide mapping common goals to the right subcommand
- [**choosing-an-input-source.md**](choosing-an-input-source.md) — Comparison of local file, stdin, RPC, HTTPS, and OCI input sources and when to use each
- [**contributing.md**](contributing.md) — Development setup, project structure, testing, and how to add new detection rules

## Finding Categories and Rules

- [**finding-categories.md**](finding-categories.md) — Every category emitted by the tool with severity, trigger, and remediation guidance
- [**adding-finding-categories.md**](adding-finding-categories.md) — Guide for contributors on adding new finding categories safely
- [**lint_rules_reference.md**](lint_rules_reference.md) — Reference for all lint rules that validate single contract specs
- [**compatibility_rules_reference.md**](compatibility_rules_reference.md) — Detailed reference for compatibility checking rules

## Configuration and Policies

- [**batch_manifests.md**](batch_manifests.md) — Manifest schema for comparing multiple contract pairs, with includes, defaults, and overrides
- [**config-resolution.md**](config-resolution.md) — How suppression config is resolved from CLI flags, environment variables, and file discovery
- [**compatibility_budgets.md**](compatibility_budgets.md) — Setting bounded limits on finding counts per axis, rule, or globally
- [**named_policy_profiles.md**](named_policy_profiles.md) — Creating and using named policy profiles for different validation scenarios
- [**multi_axis_compatibility.md**](multi_axis_compatibility.md) — Understanding and configuring multi-axis compatibility analysis
- [**multi_axis_policy_tutorial.md**](multi_axis_policy_tutorial.md) — Step-by-step tutorial for setting up multi-axis policies
- [**protocol_policy.md**](protocol_policy.md) — Protocol-level policy configuration and enforcement
- [**semver_policy.md**](semver_policy.md) — Semantic versioning policy guidance for contract upgrades
- [**suppression_security_policy.md**](suppression_security_policy.md) — Security considerations and best practices for suppression rules

## Input Sources and Remote Fetching

- [**remote-https-inputs.md**](remote-https-inputs.md) — Digest-pinned HTTPS inputs, fetch limits, caching, and error messages
- [**rpc-security-checklist.md**](rpc-security-checklist.md) — Operational checklist for RPC endpoint trust, authentication, and security
- [**rpc-header-convention.md**](rpc-header-convention.md) — How to use custom headers for RPC authentication
- [**loader-troubleshooting.md**](loader-troubleshooting.md) — Diagnosing malformed WASM, missing custom sections, and loader errors

## Storage and Validation

- [**storage-schema-cookbook.md**](storage-schema-cookbook.md) — Worked examples for declaring storage schemas with common patterns
- [**storage-inference.md**](storage-inference.md) — How the tool infers storage layout from contract specs
- [**empirical_validation.md**](empirical_validation.md) — Using real ledger data to validate upgrades against actual storage entries
- [**empirical_validation_architecture.md**](empirical_validation_architecture.md) — Technical architecture of the empirical validation system
- [**empirical_validation_spec.md**](empirical_validation_spec.md) — Specification for empirical validation input formats and behavior

## Lineage and Historical Tracking

- [**lineage_model.md**](lineage_model.md) — Persistent compatibility lineage ledger format and semantics
- [**lineage-walkthrough.md**](lineage-walkthrough.md) — Worked example of recording, validating, and retiring historical versions

## Attestations and Security

- [**attestations.md**](attestations.md) — DSSE signing, in-toto predicates, and offline verification
- [**report-provenance.md**](report-provenance.md) — Every field in the report provenance block with types and meanings

## Reports and Output

- [**report_migrations.md**](report_migrations.md) — How to upgrade saved JSON reports to the latest schema version
- [**report_schema_compatibility.md**](report_schema_compatibility.md) — Schema version history and compatibility policy

## Advanced Features

- [**metadata_cache.md**](metadata_cache.md) — How the metadata cache works and when it's used
- [**wasm_complexity.md**](wasm_complexity.md) — WASM complexity analysis and limits
- [**decoder_registry.md**](decoder_registry.md) — Registry of supported decoder types and formats
- [**capability-registry.md**](capability-registry.md) — Soroban host import capability registry and maintenance
- [**capability-reference.md**](capability-reference.md) — Complete reference of recognized Soroban host imports

## Testing and Validation

- [**oracle_differential_tests.md**](oracle_differential_tests.md) — Differential testing against reference implementations
- [**real_world_corpus_issues.md**](real_world_corpus_issues.md) — Known issues and edge cases from real-world contract corpus

## GitHub Actions and CI/CD

- [**github-action-examples.md**](github-action-examples.md) — Examples of using the GitHub Action in workflows
- [**workflow-examples/**](workflow-examples/) — Complete workflow files for different CI/CD scenarios:
  - [**pr-check.yml**](workflow-examples/pr-check.yml) — PR validation workflow
  - [**release-gate.yml**](workflow-examples/release-gate.yml) — Release gating workflow
  - [**fork-pr.yml**](workflow-examples/fork-pr.yml) — Handling PRs from forks
  - [**checks-publisher.yml**](workflow-examples/checks-publisher.yml) — Publishing check results

## API and Migration

- [**api_migration.md**](api_migration.md) — Guide for migrating to new API versions with hardening changes
- [**unstable_api_guide.md**](unstable_api_guide.md) — Using unstable APIs and understanding stability guarantees
- [**bindings.md**](bindings.md) — Python (PyO3) and Node.js (napi-rs) native bindings: scope, installation, error/report conversion model, version compatibility, and current limitations
- [**impact-graph.md**](impact-graph.md) — `--impact-graph`'s versioned node/edge export of functions, types, storage, events, findings, and policy decisions: format, node/edge kind reference, resource limits, and an example Graphviz consumer
- [**policy-bundles.md**](policy-bundles.md) — `--policy-bundle`'s centrally governed, signed compatibility policy: trust model, verification, precedence rules, and provenance

## Version History and Compatibility

- [**compatibility-table.md**](compatibility-table.md) — Release compatibility matrix for Rust toolchain, Soroban protocol, and schema versions
- [**api-changes/**](api-changes/) — Detailed API change documentation:
  - [**0.2.0-changelog.md**](api-changes/0.2.0-changelog.md) — Breaking changes in version 0.2.0
  - [**composable-batch-manifests.md**](api-changes/composable-batch-manifests.md) — Introduction of composable manifest system

## Architecture and Internals

- [**safeguard_architecture.md**](safeguard_architecture.md) — Overall architecture and design principles of the tool

## Deprecated

- [**deprecated/**](deprecated/) — Deprecated documentation and code samples retained for reference

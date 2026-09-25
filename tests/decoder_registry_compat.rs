//! Compatibility tests for the protocol-versioned decoder registry.
//!
//! These tests verify the acceptance criteria for Issue 3:
//!
//! 1. Every supported protocol version is accepted.
//! 2. Unsupported/future versions are rejected with a clear diagnostic.
//! 3. Malformed version markers are rejected, not silently misparsed.
//! 4. A decoder for one version is never called for another version's data
//!    (cross-version safety via `validate_version_ownership`).
//! 5. The `SectionVersionMeta` carried in `DecodeOutcome` is accurate.
//! 6. `ForwardCompatResult` and `decode_forward_compat` behave correctly.
//! 7. `supports_version` returns correct results for known and unknown versions.
//! 8. `registered_decoders` lists all entries.
//!
//! All tests are hermetic and synthesise version values in-process.

use soroban_upgrade_safeguard::decoder_registry::{
    decode_spec_v0, validate_version_ownership, DecodeOutcome, DecoderEntry, ForwardCompatResult,
    InterfaceVersion, SectionVersionMeta, SpecDecoderRegistry, VersionPredicate,
    SUPPORTED_PROTOCOL_MAX, SUPPORTED_PROTOCOL_MIN,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ver(protocol: u32) -> Option<InterfaceVersion> {
    Some(InterfaceVersion {
        protocol,
        pre_release: 0,
    })
}

fn ver_pre(protocol: u32, pre_release: u32) -> Option<InterfaceVersion> {
    Some(InterfaceVersion {
        protocol,
        pre_release,
    })
}

// ---------------------------------------------------------------------------
// 1. Every supported protocol version is accepted
// ---------------------------------------------------------------------------

#[test]
fn all_supported_protocol_versions_stable_accepted() {
    let reg = SpecDecoderRegistry::default();
    for protocol in SUPPORTED_PROTOCOL_MIN..=SUPPORTED_PROTOCOL_MAX {
        let outcome = reg.decode(b"", ver(protocol));
        assert!(
            outcome.is_decoded(),
            "protocol {protocol} (stable) must be accepted by the default registry"
        );
        assert!(
            outcome.is_complete(),
            "protocol {protocol} stable decode must be complete"
        );
    }
}

#[test]
fn all_supported_protocol_versions_prerelease_accepted() {
    let reg = SpecDecoderRegistry::default();
    for protocol in SUPPORTED_PROTOCOL_MIN..=SUPPORTED_PROTOCOL_MAX {
        for pre in [1u32, 2, 255] {
            let outcome = reg.decode(b"", ver_pre(protocol, pre));
            assert!(
                outcome.is_decoded(),
                "protocol {protocol} pre-release {pre} must be accepted"
            );
        }
    }
}

#[test]
fn legacy_no_version_accepted() {
    let reg = SpecDecoderRegistry::default();
    let outcome = reg.decode(b"", None);
    assert!(outcome.is_decoded(), "legacy no-version contract must be accepted");
    assert!(outcome.is_complete());
}

// ---------------------------------------------------------------------------
// 2. Unsupported/future versions are rejected
// ---------------------------------------------------------------------------

#[test]
fn future_protocol_just_above_max_rejected() {
    let reg = SpecDecoderRegistry::default();
    let outcome = reg.decode(b"", ver(SUPPORTED_PROTOCOL_MAX + 1));
    assert!(
        !outcome.is_decoded(),
        "protocol {} (above max) must be rejected",
        SUPPORTED_PROTOCOL_MAX + 1
    );
}

#[test]
fn future_protocol_255_rejected() {
    let reg = SpecDecoderRegistry::default();
    let outcome = reg.decode(b"", ver(255));
    assert!(!outcome.is_decoded(), "protocol 255 must be rejected");
    if let DecodeOutcome::UnsupportedVersion { message, .. } = outcome {
        assert!(
            message.contains("upgrade the tool") || message.contains("no decoder"),
            "unsupported message must name the required capability: {message}"
        );
    } else {
        panic!("expected UnsupportedVersion");
    }
}

#[test]
fn unsupported_version_message_names_all_registered_decoders() {
    let reg = SpecDecoderRegistry::default();
    if let DecodeOutcome::UnsupportedVersion { message, .. } = reg.decode(b"", ver(255)) {
        assert!(
            message.contains("soroban-v0-protocol-20-23"),
            "message must mention registered decoder name: {message}"
        );
        assert!(
            message.contains("legacy-no-version"),
            "message must mention legacy decoder: {message}"
        );
    } else {
        panic!("expected UnsupportedVersion");
    }
}

#[test]
fn unsupported_version_carries_the_version_in_outcome() {
    let reg = SpecDecoderRegistry::default();
    let v = ver(200);
    let outcome = reg.decode(b"", v);
    assert_eq!(outcome.version(), v);
}

// ---------------------------------------------------------------------------
// 3. Malformed version markers are rejected
// ---------------------------------------------------------------------------

#[test]
fn protocol_zero_with_present_version_rejected() {
    // A raw interface version of 0 encodes protocol=0, pre_release=0.
    // Protocol 0 has a present (non-None) version so NoVersion won't match,
    // and 0 is outside [20, 23] so the range decoder won't match either.
    let reg = SpecDecoderRegistry::default();
    let outcome = reg.decode(b"", ver(0));
    assert!(
        !outcome.is_decoded(),
        "protocol 0 with present version must be rejected (not silently misparsed)"
    );
}

#[test]
fn max_u32_protocol_rejected() {
    let reg = SpecDecoderRegistry::default();
    let v = Some(InterfaceVersion {
        protocol: u32::MAX,
        pre_release: u32::MAX,
    });
    let outcome = reg.decode(b"", v);
    assert!(!outcome.is_decoded(), "max-u32 protocol must be rejected");
}

#[test]
fn protocol_just_below_min_with_present_version_rejected() {
    // Protocol 19 has a version present in env-meta but is not in [20, 23].
    // NoVersion only matches None, so this should be rejected.
    let reg = SpecDecoderRegistry::default();
    if SUPPORTED_PROTOCOL_MIN > 0 {
        let outcome = reg.decode(b"", ver(SUPPORTED_PROTOCOL_MIN - 1));
        assert!(
            !outcome.is_decoded(),
            "protocol {} (below min, version present) must be rejected",
            SUPPORTED_PROTOCOL_MIN - 1
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Cross-version safety: validate_version_ownership
// ---------------------------------------------------------------------------

#[test]
fn validate_ownership_accepts_matching_version() {
    let entry = DecoderEntry {
        name: "p20",
        predicate: VersionPredicate::ExactProtocol(20),
        decode: decode_spec_v0,
    };
    assert!(validate_version_ownership(&entry, ver(20)).is_ok());
}

#[test]
fn validate_ownership_rejects_wrong_version() {
    let entry = DecoderEntry {
        name: "p20",
        predicate: VersionPredicate::ExactProtocol(20),
        decode: decode_spec_v0,
    };
    let err = validate_version_ownership(&entry, ver(21)).unwrap_err();
    // The error must name the decoder and explain the rejection
    let msg = err.to_string();
    assert!(
        msg.contains("p20") || msg.contains("cross-version"),
        "error must name the decoder: {msg}"
    );
}

#[test]
fn validate_ownership_rejects_none_for_range_decoder() {
    let entry = DecoderEntry {
        name: "range",
        predicate: VersionPredicate::ProtocolRange {
            min: SUPPORTED_PROTOCOL_MIN,
            max: SUPPORTED_PROTOCOL_MAX,
        },
        decode: decode_spec_v0,
    };
    // None means no env-meta section; the range decoder does not own that
    assert!(validate_version_ownership(&entry, None).is_err());
}

#[test]
fn validate_ownership_accepts_none_for_no_version_decoder() {
    let entry = DecoderEntry {
        name: "legacy",
        predicate: VersionPredicate::NoVersion,
        decode: decode_spec_v0,
    };
    assert!(validate_version_ownership(&entry, None).is_ok());
}

#[test]
fn registry_never_calls_decoder_for_unowned_version() {
    // A registry with only a p20-specific decoder must not decode p21 data.
    let mut reg = SpecDecoderRegistry { entries: Vec::new() };
    reg.register(DecoderEntry {
        name: "p20-only",
        predicate: VersionPredicate::ExactProtocol(20),
        decode: decode_spec_v0,
    });
    // Feed p21
    let outcome = reg.decode(b"", ver(21));
    assert!(!outcome.is_decoded(), "p20-only must not decode p21");
    // Feed p20 — should succeed
    let ok = reg.decode(b"", ver(20));
    assert!(ok.is_decoded(), "p20-only must decode p20");
}

// ---------------------------------------------------------------------------
// 5. SectionVersionMeta accuracy
// ---------------------------------------------------------------------------

#[test]
fn section_meta_version_matches_input() {
    let reg = SpecDecoderRegistry::default();
    for protocol in SUPPORTED_PROTOCOL_MIN..=SUPPORTED_PROTOCOL_MAX {
        let v = ver(protocol);
        if let DecodeOutcome::Decoded { section_meta, .. } = reg.decode(b"", v) {
            assert_eq!(
                section_meta.interface_version,
                v,
                "section_meta.interface_version must match for protocol {protocol}"
            );
            assert!(
                section_meta.version_owned,
                "range predicate must set version_owned=true for protocol {protocol}"
            );
        } else {
            panic!("protocol {protocol} should produce a Decoded outcome");
        }
    }
}

#[test]
fn section_meta_decoder_name_for_range() {
    let reg = SpecDecoderRegistry::default();
    if let DecodeOutcome::Decoded { section_meta, .. } = reg.decode(b"", ver(21)) {
        assert_eq!(section_meta.decoder_name, "soroban-v0-protocol-20-23");
    } else {
        panic!("expected Decoded outcome");
    }
}

#[test]
fn section_meta_decoder_name_for_legacy() {
    let reg = SpecDecoderRegistry::default();
    if let DecodeOutcome::Decoded { section_meta, .. } = reg.decode(b"", None) {
        assert_eq!(section_meta.decoder_name, "legacy-no-version");
        assert!(section_meta.interface_version.is_none());
    } else {
        panic!("expected Decoded outcome for legacy");
    }
}

#[test]
fn section_meta_version_owned_false_for_any_version_decoder() {
    let mut reg = SpecDecoderRegistry { entries: Vec::new() };
    reg.register(DecoderEntry {
        name: "catch-all",
        predicate: VersionPredicate::AnyVersion,
        decode: decode_spec_v0,
    });
    if let DecodeOutcome::Decoded { section_meta, .. } = reg.decode(b"", ver(99)) {
        assert!(
            !section_meta.version_owned,
            "AnyVersion must produce version_owned=false"
        );
    } else {
        panic!("expected Decoded");
    }
}

#[test]
fn section_meta_summary_is_human_readable() {
    let meta = SectionVersionMeta {
        interface_version: ver(21),
        decoder_name: "soroban-v0-protocol-20-23",
        version_owned: true,
    };
    let s = meta.summary();
    assert!(s.contains("soroban-v0-protocol-20-23"), "summary: {s}");
    assert!(s.contains("protocol 21"), "summary: {s}");
}

// ---------------------------------------------------------------------------
// 6. ForwardCompatResult and decode_forward_compat
// ---------------------------------------------------------------------------

#[test]
fn forward_compat_result_complete_fields() {
    let r = ForwardCompatResult::complete(vec![]);
    assert!(r.complete);
    assert_eq!(r.skipped_bytes, 0);
    assert!(r.entries.is_empty());
}

#[test]
fn forward_compat_result_partial_fields() {
    let r = ForwardCompatResult::partial(vec![], 16);
    assert!(!r.complete);
    assert_eq!(r.skipped_bytes, 16);
}

#[test]
fn decode_forward_compat_empty_data_complete() {
    let reg = SpecDecoderRegistry::default();
    let outcome = reg.decode_forward_compat(b"", ver(20));
    assert!(outcome.is_decoded());
    assert!(outcome.is_complete(), "empty data must decode completely");
}

#[test]
fn decode_forward_compat_unsupported_version_still_rejects() {
    let reg = SpecDecoderRegistry::default();
    let outcome = reg.decode_forward_compat(b"", ver(255));
    assert!(
        !outcome.is_decoded(),
        "decode_forward_compat must still reject unsupported versions"
    );
}

#[test]
fn decode_forward_compat_carries_section_meta() {
    let reg = SpecDecoderRegistry::default();
    let outcome = reg.decode_forward_compat(b"", ver(22));
    if let DecodeOutcome::Decoded { section_meta, .. } = outcome {
        assert_eq!(
            section_meta.interface_version,
            ver(22)
        );
    } else {
        panic!("expected Decoded outcome");
    }
}

// ---------------------------------------------------------------------------
// 7. supports_version
// ---------------------------------------------------------------------------

#[test]
fn supports_version_true_for_all_supported() {
    let reg = SpecDecoderRegistry::default();
    for protocol in SUPPORTED_PROTOCOL_MIN..=SUPPORTED_PROTOCOL_MAX {
        assert!(
            reg.supports_version(ver(protocol)),
            "must support protocol {protocol}"
        );
    }
    assert!(reg.supports_version(None), "must support legacy no-version");
}

#[test]
fn supports_version_false_for_unsupported() {
    let reg = SpecDecoderRegistry::default();
    assert!(!reg.supports_version(ver(255)));
    assert!(!reg.supports_version(ver(0)));
    assert!(!reg.supports_version(ver(SUPPORTED_PROTOCOL_MAX + 1)));
}

// ---------------------------------------------------------------------------
// 8. registered_decoders lists all entries
// ---------------------------------------------------------------------------

#[test]
fn registered_decoders_contains_all_builtin_entries() {
    let reg = SpecDecoderRegistry::default();
    let decoders = reg.registered_decoders();
    let names: Vec<&str> = decoders.iter().map(|(n, _)| *n).collect();
    assert!(
        names.contains(&"legacy-no-version"),
        "must list legacy-no-version: {names:?}"
    );
    assert!(
        names.contains(&"soroban-v0-protocol-20-23"),
        "must list soroban-v0-protocol-20-23: {names:?}"
    );
}

#[test]
fn registered_decoders_descriptions_are_human_readable() {
    let reg = SpecDecoderRegistry::default();
    for (name, desc) in reg.registered_decoders() {
        assert!(!desc.is_empty(), "decoder '{name}' has empty description");
        // Descriptions should mention a version or "legacy"
        assert!(
            desc.contains("protocol")
                || desc.contains("legacy")
                || desc.contains("version")
                || desc.contains("any"),
            "decoder '{name}' description is not human-readable: {desc}"
        );
    }
}

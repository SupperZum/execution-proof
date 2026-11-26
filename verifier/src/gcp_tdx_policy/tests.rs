use super::*;

fn policy() -> GcpTdxModulePolicyV1 {
    GcpTdxModulePolicyV1 {
        version: GCP_TDX_POLICY_VERSION,
        purpose: GCP_TDX_POLICY_PURPOSE.into(),
        expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
        allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
    }
}

fn facts() -> GcpTdxModuleFacts {
    GcpTdxModuleFacts {
        mr_seam: policy().expected_mr_seam,
        td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
    }
}

#[test]
fn independently_selected_module_and_allowmask_control_predicate() {
    let selected = policy();
    assert_eq!(selected.check_facts(&facts()), Ok(()));
    assert_eq!(
        GcpTdxModulePolicyV1::decode(&selected.encode().unwrap()).unwrap(),
        selected
    );
    let mut strict = selected;
    strict.allowed_td_attributes = 0;
    assert_eq!(
        strict.check_facts(&facts()),
        Err(VerificationError::Invalid("gcp_tdx_attributes"))
    );
    let mut no_attributes = facts();
    no_attributes.td_attributes = 0;
    assert_eq!(strict.check_facts(&no_attributes), Ok(()));
}

#[test]
fn debug_and_migration_are_rejected_even_when_policy_tries_allowing_them() {
    for (flag, reason) in [
        (TD_ATTRIBUTE_DEBUG, "gcp_tdx_debug"),
        (TD_ATTRIBUTE_MIGRATABLE, "gcp_tdx_migratable"),
    ] {
        let mut public = facts();
        public.td_attributes |= flag;
        assert_eq!(
            policy().check_facts(&public),
            Err(VerificationError::Invalid(reason))
        );
        let mut untrusted_policy = policy();
        untrusted_policy.allowed_td_attributes |= flag;
        assert_eq!(
            untrusted_policy.check_facts(&public),
            Err(VerificationError::Invalid("gcp_tdx_policy_attributes"))
        );
    }
}

#[test]
fn every_unrecognized_attribute_bit_is_rejected() {
    for bit in 0..64 {
        if GCP_TDX_ALLOWED_ATTRIBUTES & (1 << bit) != 0 {
            continue;
        }
        let mut public = facts();
        public.td_attributes |= 1 << bit;
        assert!(
            policy().check_facts(&public).is_err(),
            "attribute bit {bit}"
        );
    }
}

#[test]
fn module_mismatch_and_malformed_measurements_reject() {
    let mut public = facts();
    public.mr_seam = "34".repeat(48);
    assert_eq!(
        policy().check_facts(&public),
        Err(VerificationError::Invalid("gcp_tdx_module_mismatch"))
    );
    for malformed in ["AB".repeat(48), "12".repeat(47), "gg".repeat(48)] {
        public.mr_seam = malformed.clone();
        assert!(policy().check_facts(&public).is_err());
        let mut selected = policy();
        selected.expected_mr_seam = malformed;
        assert!(selected.validate().is_err());
    }
    let mut selected = policy();
    selected.expected_mr_seam = "00".repeat(48);
    assert!(selected.validate().is_err());
    // Even mutually matching public fields cannot enroll an unknown module.
    selected.expected_mr_seam = "34".repeat(48);
    public.mr_seam.clone_from(&selected.expected_mr_seam);
    assert_eq!(
        selected.check_facts(&public),
        Err(VerificationError::Invalid("gcp_tdx_policy_module"))
    );
}

#[test]
fn unknown_version_purpose_fields_and_oversize_policy_reject() {
    let mut selected = policy();
    selected.version = 2;
    assert!(selected.check_facts(&facts()).is_err());
    assert!(GcpTdxModulePolicyV1::decode(&serde_json::to_vec(&selected).unwrap()).is_err());
    selected = policy();
    selected.purpose = "qlad.execution-proof.verifier-trust.v1".into();
    assert!(selected.check_facts(&facts()).is_err());
    let wire = String::from_utf8(policy().encode().unwrap()).unwrap();
    for field in ["\"version\":1,", "\"unknown\":0,"] {
        let malformed = wire.replacen('{', &format!("{{{field}"), 1);
        assert!(GcpTdxModulePolicyV1::decode(malformed.as_bytes()).is_err());
    }
    assert!(matches!(
        GcpTdxModulePolicyV1::decode(&vec![b' '; MAX_GCP_TDX_POLICY_BYTES + 1]),
        Err(VerificationError::ResourceLimit(_))
    ));
}

//! Materialize dynamic trust fields only from authenticated selected issuers.
//! Firmware/module/instance expectations are exclusively external basis fields.
use super::*;
use execution_proof_contract::{
    admission::{
        gcp::{verify_gcp_admission_authorization_historical, GcpAdmissionExpectations},
        AdmissionAuthorizationV1,
    },
    execution::ExecutionRecord,
    gcp_artifact::ArtifactVerificationExpectations,
    gcp_artifact::GcpQuoteFraming,
    gcp_bootstrap::{
        bootstrap_context_sha384, verify_bootstrap_possession, verify_challenge_signature,
    },
    gcp_credential::{verify_credential_metadata_historical, GcpDeliveryExpectations},
    gcp_policy_receipt::{verify_policy_aggregate, GcpAggregateExpectations},
    gcp_profile::{verify_gcp_qualification_historical, GcpQualificationExpectations},
    gcp_startup::verify_attempt_plan,
    verify_launch_grant_historical, GrantExpectations,
};
use execution_proof_handoff::rootfs_custody::{AdmissionBundle, MAX_PROVENANCE_BYTES};
use execution_proof_verifier::gcp_boot_evidence::QuotePaddingPolicy;
use execution_proof_verifier::{
    gcp_schema::GcpQuoteTrust,
    schema::{AdmissionTrust, CredentialTrust, GrantTrust},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Basis {
    version: u16,
    purpose: String,
    grant: GrantTrust,
    aggregate_public_key: [u8; 32],
    aggregate_scope: AggregateScope,
    admission: AdmissionBasis,
    credential: CredentialBasis,
    quote: GcpQuoteTrust,
    qualification: GcpQualificationExpectations,
    artifacts: ArtifactVerificationExpectations,
    workload_id: String,
    attempt_id: String,
    selected_manifest_sha256: String,
    effective_launch_sha384: String,
    container_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregateScope {
    audience: String,
    issuer: String,
    as_policy_id: String,
    as_policy_sha384: String,
    as_data_sha384: Option<String>,
    kbs_policy_id: String,
    kbs_policy_sha384: String,
    resource_path: [String; 3],
    workflow_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionBasis {
    audience: String,
    issuer: String,
    admission_policy_sha384: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialBasis {
    audience: String,
    issuer: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparationSelection {
    version: u16,
    purpose: String,
    basis: Pin,
    protected_export: Pin,
    bootstrap_transcript: Pin,
    signed_bootstrap_challenge: Pin,
    original_policy_archive: Pin,
    policy_transcript: Pin,
    signed_qualification: Pin,
    signed_plan: Pin,
}
fn identifier(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"_.:-".contains(&v)),
        "basis identifier rejected",
    )
}
fn raw_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    hex(value, N)?;
    let mut raw = [0; N];
    for (out, pair) in raw
        .iter_mut()
        .zip(value.as_bytes().as_chunks::<2>().0.iter())
    {
        *out = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(raw)
}
impl Basis {
    fn validate(&self) -> Result<()> {
        require(
            self.version == 1 && self.purpose == "onb17.manual-normal-trust-basis.v1",
            "trust basis domain rejected",
        )?;
        let prefix = env!("PROOF_WORKLOAD_PREFIX");
        require(
            !prefix.is_empty()
                && !prefix.starts_with("qexp-")
                && self.workload_id.starts_with(prefix)
                && self.attempt_id.starts_with(prefix)
                && self.workload_id.len() > prefix.len()
                && self.attempt_id.len() > prefix.len(),
            "normal selected workload/attempt required",
        )?;
        for id in [
            &self.workload_id,
            &self.attempt_id,
            &self.container_id,
            &self.grant.audience,
            &self.grant.authority,
            &self.grant.tenant,
            &self.aggregate_scope.audience,
            &self.aggregate_scope.issuer,
            &self.aggregate_scope.as_policy_id,
            &self.aggregate_scope.kbs_policy_id,
            &self.aggregate_scope.workflow_id,
            &self.admission.audience,
            &self.admission.issuer,
            &self.credential.audience,
            &self.credential.issuer,
            &self.quote.audience,
            &self.qualification.issuer,
        ] {
            identifier(id)?;
        }
        for path in &self.aggregate_scope.resource_path {
            identifier(path)?;
        }
        hex(&self.selected_manifest_sha256, 32)?;
        for value in [
            &self.effective_launch_sha384,
            &self.grant.profile_sha384,
            &self.grant.launch_policy_sha384,
            &self.grant.image_policy_sha384,
            &self.aggregate_scope.as_policy_sha384,
            &self.aggregate_scope.kbs_policy_sha384,
            &self.admission.admission_policy_sha384,
            &self.quote.trust_snapshot_sha384,
        ] {
            hex(value, 48)?;
        }
        if let Some(value) = &self.aggregate_scope.as_data_sha384 {
            hex(value, 48)?;
        }
        self.quote.boot_binding.validate()?;
        self.quote.boot_policy.validate()?;
        self.quote.module_policy.validate()?;
        self.qualification.evidence_refs.validate()?;
        let b = self.quote.boot_binding.digest_sha384()?;
        let framing = match self.quote.boot_policy.quote_padding {
            QuotePaddingPolicy::ExactFrame => GcpQuoteFraming::ExactFrame,
            QuotePaddingPolicy::GcpTsmZeroPadded8000 => GcpQuoteFraming::GcpTsmZeroPadded8000,
        };
        require(
            self.grant.profile_sha384 == b
                && self.qualification.boot_binding_sha384 == b
                && self.artifacts.boot_binding == self.quote.boot_binding
                && self.aggregate_scope.as_policy_sha384 == self.grant.launch_policy_sha384
                && self.artifacts.pe_authenticode_sha384
                    == self.quote.boot_policy.expected_pe_sha384
                && self.artifacts.firmware_mrtd == self.quote.boot_policy.expected_firmware_mrtd
                && self.artifacts.module_policy_sha384 == self.qualification.module_policy_sha384
                && self.artifacts.quote_framing == framing
                && self.qualification.pe_sha384 == self.quote.boot_policy.expected_pe_sha384
                && self.qualification.firmware_mrtd
                    == self.quote.boot_policy.expected_firmware_mrtd
                && self.qualification.module_policy_sha384
                    == hash(&self.quote.module_policy.encode()?),
            "static basis profile/policy differs",
        )?;
        let keys = [
            self.grant.authority_public_key,
            self.aggregate_public_key,
            self.qualification.qualification_public_key,
            self.artifacts.build_public_key,
            self.artifacts.reference_public_key,
        ];
        require(
            keys.iter()
                .enumerate()
                .all(|(i, key)| *key != [0; 32] && !keys[..i].contains(key)),
            "static basis root separation",
        )
    }
    fn aggregate_matches(&self, aggregate: &GcpLaunchPolicyAggregateV2) -> Result<()> {
        let s = &self.aggregate_scope;
        require(
            aggregate.audience == s.audience
                && aggregate.issuer == s.issuer
                && aggregate.as_evaluation.policy_id == s.as_policy_id
                && aggregate.as_evaluation.policy_sha384 == s.as_policy_sha384
                && aggregate.as_evaluation.data_sha384 == s.as_data_sha384
                && aggregate.kbs_evaluation.policy_id == s.kbs_policy_id
                && aggregate.kbs_evaluation.policy_sha384 == s.kbs_policy_sha384
                && aggregate.request.method == "GET"
                && aggregate.request.plugin == "resource"
                && aggregate.request.resource_path == s.resource_path
                && aggregate.request.workflow_id == s.workflow_id,
            "trusted aggregate differs from independently selected policy scope",
        )
    }
}
pub(super) fn check_basis(path: &Path) -> Result<()> {
    let basis: Basis = json(&read(path, MAX_TRUST_BYTES)?)?;
    basis.validate()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicySelection {
    version: u16,
    purpose: String,
    issuer_config: Pin,
    collateral: Pin,
    signed_qualification: Pin,
    authority_public_key: Pin,
}
fn policy_bytes(
    config: &execution_proof_issuer::gcp::GcpIssuerConfig,
    authority: &[u8; 32],
    q_digest: &str,
) -> Result<Vec<u8>> {
    hex(q_digest, 48)?;
    let mut policy = b"QLAD-GCP-ISSUER-POLICY-ADMISSION-v1\0".to_vec();
    for raw in [
        authority.as_slice(),
        serde_json::to_vec(config)?.as_slice(),
        q_digest.as_bytes(),
    ] {
        policy.extend_from_slice(&u32::try_from(raw.len())?.to_be_bytes());
        policy.extend_from_slice(raw);
    }
    require(
        policy.len() <= MAX_OBJECT_BYTES,
        "admission policy object bound",
    )?;
    Ok(policy)
}
pub(super) fn admission_policy(selection_path: &Path, output: &Path) -> Result<()> {
    let s: PolicySelection = json(&read(selection_path, 64 << 10)?)?;
    require(
        s.version == 1 && s.purpose == "onb17.manual-admission-policy-selection.v1",
        "admission policy selection rejected",
    )?;
    let mut inputs = Inputs { total: 0 };
    let mut config: execution_proof_issuer::gcp::GcpIssuerConfig =
        json(&inputs.get(&s.issuer_config, MAX_TRUST_BYTES)?)?;
    let collateral = inputs.get(&s.collateral, 4 << 20)?;
    json::<serde_json::Value>(&collateral)?;
    require(
        config.collateral_json.is_empty() || config.collateral_json == collateral,
        "effective issuer collateral differs",
    )?;
    config.collateral_json = collateral;
    let authority: [u8; 32] = inputs
        .get(&s.authority_public_key, 32)?
        .try_into()
        .map_err(|_| "public authority key length")?;
    require(
        authority != [0; 32]
            && ![
                config.tenant_public_key,
                config.policy_admission.kbs_proof_public_key,
                config.qualification.qualification_public_key,
            ]
            .contains(&authority),
        "admission policy root separation",
    )?;
    let q_raw = inputs.get(&s.signed_qualification, 16 << 10)?;
    json::<serde_json::Value>(&q_raw)?;
    let q = verify_gcp_qualification_historical(&q_raw, &config.qualification)?;
    let policy = policy_bytes(&config, &authority, q.digest_sha384())?;
    let parent = output.parent().ok_or("output parent required")?;
    canonical(parent)?;
    require(
        output
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|name| {
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || b"-_.".contains(&v))
            }),
        "simple output filename required",
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    file.write_all(&policy)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"purpose":"onb17.manual-admission-policy-materialized.v1",
        "sha384":hash(&policy),"bytes":policy.len(),"execution_verified":false})
    );
    Ok(())
}

fn prepare(selection_path: &Path) -> Result<(Vec<u8>, Vec<u8>, String)> {
    let s: PreparationSelection = json(&read(selection_path, 64 << 10)?)?;
    require(
        s.version == 1 && s.purpose == "onb17.manual-trust-preparation-selection.v1",
        "trust preparation selection rejected",
    )?;
    let mut inputs = Inputs { total: 0 };
    let basis_raw = inputs.get(&s.basis, MAX_TRUST_BYTES)?;
    let basis: Basis = json(&basis_raw)?;
    basis.validate()?;
    let export = inputs.get(&s.protected_export, 12 << 20)?;
    json::<serde_json::Value>(&export)?;
    let boot = bootstrap(
        &inputs.get(&s.bootstrap_transcript, 4 << 20)?,
        inputs.get(&s.signed_bootstrap_challenge, 16 << 10)?,
    )?;
    let q = inputs.get(&s.signed_qualification, 16 << 10)?;
    json::<serde_json::Value>(&q)?;
    let policy: PolicyTranscript = json(&inputs.get(&s.policy_transcript, 17 << 20)?)?;
    let mut objects = vec![];
    let receipt = original_archive(
        &inputs.get(&s.original_policy_archive, 8 << 20)?,
        &policy,
        &mut objects,
    )?;
    let pack = GcpEvidencePackV2::from_protected_export(&export, receipt, objects, boot, q)?;
    let admission = AdmissionBundle::decode(&pack.execution.admission, MAX_PROVENANCE_BYTES)?;
    require(
        admission.aggregate == policy.signed_aggregate,
        "protected/original aggregate bytes differ",
    )?;
    let grant = verify_launch_grant_historical(
        &admission.grant,
        &GrantExpectations {
            authority_public_key: basis.grant.authority_public_key,
            audience: basis.grant.audience.clone(),
            authority: basis.grant.authority.clone(),
            tenant: basis.grant.tenant.clone(),
            profile_sha384: basis.grant.profile_sha384.clone(),
            launch_policy_sha384: basis.grant.launch_policy_sha384.clone(),
            image_policy_sha384: basis.grant.image_policy_sha384.clone(),
        },
    )?;
    let binding = grant.binding();
    require(
        binding.workload_id == basis.workload_id
            && binding.attempt_id == basis.attempt_id
            && binding.container_role == "application-init"
            && binding.selected_manifest_sha256 == basis.selected_manifest_sha256
            && binding.effective_launch_sha384 == basis.effective_launch_sha384,
        "authenticated grant differs from selected intent",
    )?;
    let boot = &pack.bootstrap;
    verify_challenge_signature(
        &boot.signed_challenge,
        &basis.grant.authority_public_key,
        &boot.challenge,
    )?;
    verify_bootstrap_possession(
        &boot.challenge,
        &boot.binding,
        &boot.evidence,
        &boot.recorder_public_key,
        &boot.possession_signature,
    )?;
    require(
        ![
            basis.grant.authority_public_key,
            basis.aggregate_public_key,
            basis.qualification.qualification_public_key,
            basis.artifacts.build_public_key,
            basis.artifacts.reference_public_key,
        ]
        .contains(&boot.recorder_public_key),
        "recorder/static root separation",
    )?;
    require(
        boot.challenge.boot_binding == basis.quote.boot_binding
            && boot.challenge.authority == binding.authority
            && boot.challenge.tenant == binding.tenant
            && boot.challenge.workload_id == binding.workload_id
            && boot.challenge.attempt_id == binding.attempt_id
            && boot.challenge.audience == basis.grant.audience
            && binding.challenge_sha384 == boot.challenge.digest_sha384()?
            && binding.bootstrap_context_sha384
                == bootstrap_context_sha384(&boot.challenge, &boot.binding, &boot.evidence)?
            && binding.boot_id == boot.binding.boot_id
            && binding.channel_key_sha384 == boot.binding.recorder_key_sha384,
        "authenticated bootstrap/grant context mismatch",
    )?;
    let signed: Signed<GcpLaunchPolicyAggregateV2> = json(&admission.aggregate)?;
    basis.aggregate_matches(&signed.statement)?;
    let aggregate_expected = signed.statement;
    let expected = || GcpAggregateExpectations {
        kbs_proof_public_key: basis.aggregate_public_key,
        boot_binding: basis.quote.boot_binding.clone(),
        expected: aggregate_expected.clone(),
    };
    let aggregate = verify_policy_aggregate(&admission.aggregate, &grant, &expected())?;
    let signed_admission: Signed<AdmissionAuthorizationV1> = json(&admission.receipt)?;
    let guest_nonce = signed_admission.statement.guest_nonce;
    let accepted = verify_gcp_admission_authorization_historical(
        &admission.receipt,
        &grant,
        &aggregate,
        &GcpAdmissionExpectations {
            authority_public_key: basis.grant.authority_public_key,
            aggregate: expected(),
            audience: basis.admission.audience.clone(),
            issuer: basis.admission.issuer.clone(),
            boot_id: binding.boot_id.clone(),
            attempt_id: binding.attempt_id.clone(),
            guest_nonce: guest_nonce.clone(),
            admission_policy_sha384: basis.admission.admission_policy_sha384.clone(),
        },
    )?;
    verify_credential_metadata_historical(
        &pack.execution.credential_receipt,
        &grant,
        &aggregate,
        &GcpDeliveryExpectations {
            aggregate: expected(),
            audience: basis.credential.audience.clone(),
            issuer: basis.credential.issuer.clone(),
            keywrap_sha384: boot.binding.keywrap_key_sha384.clone(),
        },
    )?;
    let plan_raw = inputs.get(&s.signed_plan, 32 << 10)?;
    json::<serde_json::Value>(&plan_raw)?;
    let plan = verify_attempt_plan(
        &plan_raw,
        &basis.grant.authority_public_key,
        &grant,
        &aggregate,
        &basis.quote.boot_binding,
    )?;
    require(
        plan.container_id == basis.container_id
            && plan.execution_audience == basis.quote.audience
            && plan.trust_snapshot_sha384 == basis.quote.trust_snapshot_sha384
            && plan.admission_policy_sha384 == basis.admission.admission_policy_sha384,
        "authenticated plan differs from preexecution selection",
    )?;
    let qualification =
        verify_gcp_qualification_historical(&pack.qualification, &basis.qualification)?;
    require(
        grant.validity().not_before >= boot.challenge.validity.not_before
            && grant.validity().expires <= boot.challenge.validity.expires
            && boot.challenge.validity.not_before >= qualification.validity().not_before
            && boot.challenge.validity.expires <= qualification.validity().expires,
        "authenticated Q/bootstrap/grant windows differ",
    )?;
    let record = ExecutionRecord::decode(&pack.execution.record)?;
    require(
        record.grant_sha384 == grant.grant_digest()
            && record.admission_context_sha384 == accepted.context_digest()
            && record.candidate_spec_sha384 == basis.effective_launch_sha384
            && record.task.container_id == basis.container_id,
        "record differs from authenticated attempt selection",
    )?;
    let challenge = GcpQuoteChallenge::new(
        basis.quote.audience.clone(),
        raw_hex::<32>(&plan.execution_nonce_hex)?,
        &record,
        basis.quote.boot_binding.clone(),
        raw_hex::<48>(&basis.quote.trust_snapshot_sha384)?,
    )?;
    let trust = GcpTrustConfigV2 {
        version: 2,
        purpose: execution_proof_verifier::gcp_schema::GCP_TRUST_PURPOSE.into(),
        grant: basis.grant,
        aggregate_public_key: basis.aggregate_public_key,
        aggregate_expected,
        admission: AdmissionTrust {
            audience: basis.admission.audience,
            issuer: basis.admission.issuer,
            boot_id: binding.boot_id.clone(),
            attempt_id: binding.attempt_id.clone(),
            guest_nonce,
            admission_policy_sha384: basis.admission.admission_policy_sha384,
        },
        credential: CredentialTrust {
            audience: basis.credential.audience,
            issuer: basis.credential.issuer,
            keywrap_sha384: boot.binding.keywrap_key_sha384.clone(),
        },
        quote: basis.quote,
        qualification: basis.qualification,
        artifacts: basis.artifacts,
    };
    Ok((trust.encode()?, challenge.encode()?, hash(&basis_raw)))
}
pub(super) fn run(selection_path: &Path, output: &Path) -> Result<()> {
    let (trust, challenge, basis_hash) = prepare(selection_path)?;
    canonical(output.parent().ok_or("output parent required")?)?;
    let name = output
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("output name required")?;
    require(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"-_".contains(&v)),
        "simple output name required",
    )?;
    fs::create_dir(output)?;
    fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
    let receipt = serde_json::json!({"purpose":"onb17.manual-trust-prepared.v1","basis_sha384":basis_hash,
        "trust_sha384":hash(&trust),"challenge_sha384":hash(&challenge),"trusted_issuer_records_authenticated":true,
        "public_graph_authenticated":false,"hardware_verification_run":false,"execution_verified":false});
    let receipt_raw = serde_json::to_vec(&receipt)?;
    for (name, raw) in [
        ("trust.json", trust.as_slice()),
        ("challenge.json", challenge.as_slice()),
        ("trust-preparation.json", receipt_raw.as_slice()),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(output.join(name))?;
        file.write_all(raw)?;
        file.sync_all()?;
    }
    File::open(output)?.sync_all()?;
    File::open(output.parent().ok_or("output parent required")?)?.sync_all()?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use execution_proof_contract::{
        gcp_boot_binding::GcpBootBindingV1,
        gcp_profile::{
            GcpProducerQualificationV1, GcpQualificationEvidenceRefs, GCP_QUALIFICATION_CLAIM,
            GCP_QUALIFICATION_PROFILE, GCP_QUALIFICATION_PURPOSE,
        },
        ValidityWindow,
    };
    use execution_proof_issuer::gcp::{GcpIssuerConfig, GcpPolicyAdmissionConfig};
    use execution_proof_verifier::{
        gcp_boot_evidence::{GcpBootEvidencePolicy, GcpInstanceIdentity},
        gcp_tdx_policy::{
            GcpTdxModulePolicyV1, GCP_TDX_POLICY_PURPOSE, INTEL_TDX_MODULE_1_5_34_MR_SEAM,
        },
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    fn key(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }
    fn public(seed: u8) -> [u8; 32] {
        key(seed).public_key().as_ref().try_into().unwrap()
    }
    fn fixture() -> (Basis, GcpIssuerConfig, Vec<u8>) {
        let binding = GcpBootBindingV1::new([10; 48], [11; 48], [12; 48], [13; 48]).unwrap();
        let b = binding.digest_sha384().unwrap();
        let module = GcpTdxModulePolicyV1 {
            version: 1,
            purpose: GCP_TDX_POLICY_PURPOSE.into(),
            expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
            allowed_td_attributes: 1 << 28,
        };
        let boot = GcpBootEvidencePolicy {
            expected_pe_sha384: "55".repeat(48),
            expected_firmware_mrtd: "66".repeat(48),
            expected_instance: GcpInstanceIdentity {
                instance_id: 123,
                numerical_project_id: 456,
                zone: "fixture-a".into(),
            },
            quote_padding: QuotePaddingPolicy::GcpTsmZeroPadded8000,
        };
        let refs = GcpQualificationEvidenceRefs {
            artifact_closure_sha384: "e1".repeat(48),
            firmware_causality_sha384: "e2".repeat(48),
            producer_isolation_sha384: "e3".repeat(48),
            no_state_copy_sha384: "e4".repeat(48),
            qualification_review_sha384: "e5".repeat(48),
        };
        let qualification = GcpQualificationExpectations {
            qualification_public_key: public(4),
            issuer: "fixture-qualification".into(),
            boot_binding_sha384: b.clone(),
            pe_sha384: boot.expected_pe_sha384.clone(),
            firmware_mrtd: boot.expected_firmware_mrtd.clone(),
            module_policy_sha384: hash(&module.encode().unwrap()),
            evidence_refs: refs.clone(),
        };
        let q = GcpProducerQualificationV1 {
            version: 1,
            purpose: GCP_QUALIFICATION_PURPOSE.into(),
            profile: GCP_QUALIFICATION_PROFILE.into(),
            claim: GCP_QUALIFICATION_CLAIM.into(),
            qualification_id: "synthetic-unit-only".into(),
            issuer: qualification.issuer.clone(),
            boot_binding_sha384: b.clone(),
            pe_sha384: qualification.pe_sha384.clone(),
            firmware_mrtd: qualification.firmware_mrtd.clone(),
            module_policy_sha384: qualification.module_policy_sha384.clone(),
            evidence_refs: refs,
            validity: ValidityWindow {
                not_before: 1,
                expires: 1000,
            },
        };
        let sig = key(4)
            .sign(&q.signing_bytes().unwrap())
            .as_ref()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        let q_raw = serde_json::to_vec(&Signed {
            statement: q,
            signature: sig,
        })
        .unwrap();
        let artifacts = ArtifactVerificationExpectations {
            build_public_key: public(5),
            reference_public_key: public(6),
            build_issuer: "fixture-builder".into(),
            reference_issuer: "fixture-reference".into(),
            boot_binding: binding.clone(),
            pe_authenticode_sha384: boot.expected_pe_sha384.clone(),
            firmware_mrtd: boot.expected_firmware_mrtd.clone(),
            module_policy_sha384: qualification.module_policy_sha384.clone(),
            firmware_endorsement_sha384: "88".repeat(48),
            quote_framing: GcpQuoteFraming::GcpTsmZeroPadded8000,
        };
        let config = GcpIssuerConfig {
            authorization_ttl_secs: 300,
            authority: "fixture-authority".into(),
            tenant: "fixture-tenant".into(),
            audience: "fixture-launch".into(),
            tenant_public_key: public(2),
            boot_binding: binding.clone(),
            launch_policy_sha384: "21".repeat(48),
            image_policy_sha384: "22".repeat(48),
            boot_policy: boot.clone(),
            module_policy: module.clone(),
            qualification: qualification.clone(),
            policy_admission: GcpPolicyAdmissionConfig {
                kbs_proof_public_key: public(3),
                aggregate_audience: "fixture-policy".into(),
                aggregate_issuer: "fixture-kbs".into(),
                as_policy_id: "fixture-as".into(),
                as_policy_sha384: "21".repeat(48),
                as_data_sha384: None,
                kbs_policy_id: "fixture-resource".into(),
                kbs_policy_sha384: "23".repeat(48),
                resource_path: ["fixture".into(), "manual".into(), "resource".into()],
                workflow_id: "fixture-workflow".into(),
                receipt_audience: "fixture-admission".into(),
            },
            pregrant_worker_path: PathBuf::from("/usr/bin/true"),
            pregrant_worker_sha384: hash(&fs::read("/usr/bin/true").unwrap()),
            collateral_json: b"{\"public_collateral\":true}".to_vec(),
        };
        let p = &config.policy_admission;
        let basis = Basis {
            version: 1,
            purpose: "onb17.manual-normal-trust-basis.v1".into(),
            grant: GrantTrust {
                authority_public_key: public(1),
                audience: config.audience.clone(),
                authority: config.authority.clone(),
                tenant: config.tenant.clone(),
                profile_sha384: b,
                launch_policy_sha384: config.launch_policy_sha384.clone(),
                image_policy_sha384: config.image_policy_sha384.clone(),
            },
            aggregate_public_key: public(3),
            aggregate_scope: AggregateScope {
                audience: p.aggregate_audience.clone(),
                issuer: p.aggregate_issuer.clone(),
                as_policy_id: p.as_policy_id.clone(),
                as_policy_sha384: p.as_policy_sha384.clone(),
                as_data_sha384: None,
                kbs_policy_id: p.kbs_policy_id.clone(),
                kbs_policy_sha384: p.kbs_policy_sha384.clone(),
                resource_path: p.resource_path.clone(),
                workflow_id: p.workflow_id.clone(),
            },
            admission: AdmissionBasis {
                audience: p.receipt_audience.clone(),
                issuer: config.authority.clone(),
                admission_policy_sha384: "24".repeat(48),
            },
            credential: CredentialBasis {
                audience: "fixture-delivery".into(),
                issuer: p.aggregate_issuer.clone(),
            },
            quote: GcpQuoteTrust {
                audience: "fixture-exec".into(),
                boot_binding: binding,
                trust_snapshot_sha384: "25".repeat(48),
                boot_policy: boot,
                module_policy: module,
            },
            qualification,
            artifacts,
            workload_id: concat!(env!("PROOF_WORKLOAD_PREFIX"), "workload").into(),
            attempt_id: concat!(env!("PROOF_WORKLOAD_PREFIX"), "attempt").into(),
            selected_manifest_sha256: "26".repeat(32),
            effective_launch_sha384: "27".repeat(48),
            container_id: "fixture-container".into(),
        };
        (basis, config, q_raw)
    }
    #[test]
    fn static_basis_validates_external_scope_without_learning_measurements() {
        let (basis, _, _) = fixture();
        basis.validate().unwrap();
        let (mut basis, _, _) = fixture();
        basis.quote.boot_policy.expected_firmware_mrtd = "ff".repeat(48);
        assert!(basis.validate().is_err());
        let (mut basis, _, _) = fixture();
        basis.qualification.evidence_refs.no_state_copy_sha384 = "00".repeat(48);
        assert!(basis.validate().is_err());
        let (mut basis, _, _) = fixture();
        basis.aggregate_public_key = basis.grant.authority_public_key;
        assert!(basis.validate().is_err());
        let (mut basis, _, _) = fixture();
        basis.workload_id = "qexp-fixture-workload".into();
        assert!(basis.validate().is_err());
    }
    #[test]
    fn public_policy_bytes_match_actual_issuer_identity_hash() {
        struct Clock;
        impl execution_proof_issuer::IssuerClock for Clock {
            fn now_unix_seconds(
                &self,
            ) -> std::result::Result<u64, execution_proof_issuer::ClockError> {
                Ok(100)
            }
        }
        let (_, config, q_raw) = fixture();
        let q = verify_gcp_qualification_historical(&q_raw, &config.qualification).unwrap();
        let bytes = policy_bytes(&config, &public(1), q.digest_sha384()).unwrap();
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("public-policy-unit-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        let issuer = execution_proof_issuer::gcp::GcpIssuer::initialize_new_with_clock(
            &path.join("issuer.sqlite"),
            config,
            &q_raw,
            key(1),
            1,
            std::sync::Arc::new(Clock),
        )
        .unwrap();
        assert_eq!(issuer.admission_policy_sha384(), hash(&bytes));
        drop(issuer);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn effective_collateral_and_qualification_digest_change_policy_identity() {
        let (_, mut config, q_raw) = fixture();
        let q = verify_gcp_qualification_historical(&q_raw, &config.qualification).unwrap();
        let original = policy_bytes(&config, &public(1), q.digest_sha384()).unwrap();
        config.collateral_json.clear();
        assert_ne!(
            hash(&original),
            hash(&policy_bytes(&config, &public(1), q.digest_sha384()).unwrap())
        );
        assert_ne!(
            hash(&original),
            hash(&policy_bytes(&config, &public(1), &"ff".repeat(48)).unwrap())
        );
    }
    #[test]
    fn wrong_qualification_signature_is_rejected() {
        let (_, config, q_raw) = fixture();
        let mut q: serde_json::Value = serde_json::from_slice(&q_raw).unwrap();
        q["signature"] = "00".repeat(64).into();
        assert!(verify_gcp_qualification_historical(
            &serde_json::to_vec(&q).unwrap(),
            &config.qualification
        )
        .is_err());
    }
    #[test]
    fn dynamic_aggregate_cannot_replace_selected_policy_or_request_scope() {
        let (basis, _, _) = fixture();
        let s = &basis.aggregate_scope;
        let aggregate:GcpLaunchPolicyAggregateV2=serde_json::from_value(serde_json::json!({
            "version":2,"purpose":"qlad.execution-proof.gcp-kbs-policy-aggregate.v2","audience":s.audience,
            "issuer":s.issuer,"profile":"onb17.gcp-kbs-combined-policy-only.v2","grant_sha384":"11".repeat(48),
            "authority_key_sha384":"12".repeat(48),"session_id":"13".repeat(32),"nonce":"fixture-nonce",
            "runtime_sha384":"14".repeat(48),"boot_binding_sha384":basis.grant.profile_sha384,"evidence_sha384":"16".repeat(48),
            "recorder_key_sha384":"17".repeat(48),"request":{"method":"GET","plugin":"resource",
                "resource_path":s.resource_path,"workflow_id":s.workflow_id,"request_nonce":"fixture-request"},
            "as_evaluation":{"policy_id":s.as_policy_id,"policy_sha384":s.as_policy_sha384,"input_sha384":"19".repeat(48),"data_sha384":null},
            "kbs_evaluation":{"policy_id":s.kbs_policy_id,"policy_sha384":s.kbs_policy_sha384,"input_sha384":"21".repeat(48),"data_sha384":"22".repeat(48)}
        })).unwrap();
        basis.aggregate_matches(&aggregate).unwrap();
        for mutation in 0..4 {
            let mut actual = aggregate.clone();
            match mutation {
                0 => actual.as_evaluation.policy_sha384 = "ff".repeat(48),
                1 => actual.kbs_evaluation.policy_id = "other-policy".into(),
                2 => actual.request.resource_path[0] = "other".into(),
                _ => actual.request.workflow_id = "other-workflow".into(),
            };
            assert!(basis.aggregate_matches(&actual).is_err());
        }
    }
}

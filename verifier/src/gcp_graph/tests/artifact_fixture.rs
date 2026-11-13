//! Synthetic signed public objects for graph tests only; no production roots.
use execution_proof_contract::{gcp_artifact::*, gcp_boot_binding::GcpBootBindingV1, Signed};
use ring::{
    digest,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::Serialize;
pub(super) type ArtifactFixture = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    ArtifactVerificationExpectations,
);
struct ArtifactFixtureFields {
    c: Vec<u8>,
    d: Vec<u8>,
    a: Vec<u8>,
    v: Vec<u8>,
    expected: ArtifactVerificationExpectations,
}
fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}
fn pubkey(seed: u8) -> [u8; 32] {
    key(seed).public_key().as_ref().try_into().unwrap()
}
fn signed<T: Serialize + Clone>(value: &T, bytes: &[u8], seed: u8) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: value.clone(),
        signature: crate::hex(key(seed).sign(bytes).as_ref()),
    })
    .unwrap()
}
fn sha384(bytes: &[u8]) -> String {
    crate::hash(bytes)
}
fn raw_hash(bytes: &[u8]) -> [u8; 48] {
    digest::digest(&digest::SHA384, bytes)
        .as_ref()
        .try_into()
        .unwrap()
}
fn config(roots: [[u8; 32]; 3], launchhash: String, imagehash: String) -> ClosedBootConfigV1 {
    ClosedBootConfigV1 {
        version: 1,
        purpose: CLOSED_BOOT_CONFIG_PURPOSE.into(),
        roots: ClosedBootRootsV1 {
            authority_public_key: roots[0],
            build_public_key: pubkey(201),
            reference_public_key: pubkey(202),
            kbs_proof_public_key: roots[1],
            qualification_public_key: roots[2],
            authority_tls_roots_sha384: "51".repeat(48),
            kbs_tls_roots_sha384: "52".repeat(48),
        },
        authority: "authority".into(),
        tenant: "tenant".into(),
        grant_audience: "launch".into(),
        aggregate_audience: "policy".into(),
        admission_receipt_audience: "admission".into(),
        authority_https_origin: "https://authority.example:8443".into(),
        kbs_https_origin: "https://kbs.example".into(),
        resource_path: ["default".into(), "credentials".into(), "gcp".into()],
        workflow_id: "workflow".into(),
        launch_policy_sha384: launchhash,
        image_policy_sha384: imagehash,
        rpc_policy_sha384: "41".repeat(48),
        device_policy_sha384: "42".repeat(48),
        writer_policy_sha384: "43".repeat(48),
        rpc_policy_path: "/onb17/policy/rpc.json".into(),
        device_policy_path: "/onb17/policy/device.json".into(),
        writer_policy_path: "/onb17/policy/writer.json".into(),
        launch_policy_path: "/onb17/policy/launch.rego".into(),
        image_policy_path: "/onb17/policy/image.json".into(),
        authority_tls_roots_path: "/onb17/roots/authority.pem".into(),
        kbs_tls_roots_path: "/onb17/roots/kbs.pem".into(),
        bootstrap_path: "/onb17/bin/bootstrap".into(),
        cdh_path: "/onb17/bin/cdh".into(),
        kata_agent_path: "/onb17/bin/kata-agent".into(),
        allowed_roles: [
            GcpBootRole::Bootstrap,
            GcpBootRole::Cdh,
            GcpBootRole::KataAgent,
        ],
        custody_transport: "private-unix-seqpacket".into(),
        host_transport: "vsock".into(),
        management_relay: None,
        generic_attestation_rpc_enabled: false,
        limits: ClosedBootLimitsV1 {
            pending_records: 4,
            pending_bytes: 32 << 20,
            quote_attempts: 3,
            quote_timeout_seconds: 30,
            pending_timeout_seconds: 300,
            evidence_bytes: 1 << 20,
            envelope_bytes: 4 << 20,
            pack_bytes: 16 << 20,
        },
    }
}
pub(super) fn artifact_fixture(
    roots: [[u8; 32]; 3],
    launchhash: String,
    imagehash: String,
    pe: String,
    firmware: String,
    module: String,
) -> ArtifactFixture {
    let c = config(roots, launchhash, imagehash);
    let c_wire = c.encode().unwrap();
    let mut leaves = vec![
        (
            ProducerLeafKind::BootstrapBinary,
            c.bootstrap_path.clone(),
            "61".repeat(48),
        ),
        (
            ProducerLeafKind::CdhBinary,
            c.cdh_path.clone(),
            "62".repeat(48),
        ),
        (
            ProducerLeafKind::KataAgentBinary,
            c.kata_agent_path.clone(),
            "63".repeat(48),
        ),
        (
            ProducerLeafKind::RpcPolicy,
            "/onb17/policy/rpc.json".into(),
            c.rpc_policy_sha384.clone(),
        ),
        (
            ProducerLeafKind::DevicePolicy,
            "/onb17/policy/device.json".into(),
            c.device_policy_sha384.clone(),
        ),
        (
            ProducerLeafKind::WriterPolicy,
            "/onb17/policy/writer.json".into(),
            c.writer_policy_sha384.clone(),
        ),
        (
            ProducerLeafKind::LaunchPolicy,
            "/onb17/policy/launch.rego".into(),
            c.launch_policy_sha384.clone(),
        ),
        (
            ProducerLeafKind::ImagePolicy,
            "/onb17/policy/image.json".into(),
            c.image_policy_sha384.clone(),
        ),
        (
            ProducerLeafKind::TlsRoots,
            "/onb17/roots/authority.pem".into(),
            c.roots.authority_tls_roots_sha384.clone(),
        ),
        (
            ProducerLeafKind::TlsRoots,
            "/onb17/roots/kbs.pem".into(),
            c.roots.kbs_tls_roots_sha384.clone(),
        ),
    ]
    .into_iter()
    .map(|(kind, path, sha384)| ProducerLeafV1 {
        kind,
        path,
        sha384,
        size_bytes: 128,
    })
    .collect::<Vec<_>>();
    leaves.sort_by(|a, b| a.path.cmp(&b.path));
    let d = ProducerCoreV1 {
        version: 1,
        purpose: PRODUCER_CORE_PURPOSE.into(),
        config_sha384: sha384(&c_wire),
        leaves,
    }
    .encode()
    .unwrap();
    let a = BootArtifactManifestV1 {
        version: 1,
        purpose: BOOT_ARTIFACT_MANIFEST_PURPOSE.into(),
        build_id: "SOFTWARE-TEST-ONLY".into(),
        issuer: "builder".into(),
        config_sha384: sha384(&c_wire),
        producer_core_sha384: sha384(&d),
        pe_file_sha384: "71".repeat(48),
        pe_authenticode_sha384: pe,
        source_tree_sha384: "73".repeat(48),
        toolchain_sha384: "74".repeat(48),
        kernel_config_sha384: "75".repeat(48),
        component_closure_sha384: "76".repeat(48),
        build_recipe_sha384: "77".repeat(48),
        measurement_recipe: GCP_MEASUREMENT_RECIPE.into(),
    };
    let a_wire = signed(&a, &a.signing_bytes().unwrap(), 201);
    let v = ReferencePolicySetV1 {
        version: 1,
        purpose: REFERENCE_POLICY_SET_PURPOSE.into(),
        reference_id: "reference-test".into(),
        issuer: "reference".into(),
        artifact_manifest_sha384: sha384(&a_wire),
        firmware_mrtd: firmware,
        pe_authenticode_sha384: a.pe_authenticode_sha384.clone(),
        module_policy_sha384: module,
        firmware_endorsement_sha384: "83".repeat(48),
        platform_profile: GCP_PLATFORM_PROFILE.into(),
        measurement_recipe: GCP_MEASUREMENT_RECIPE.into(),
        required_events_profile: GCP_REQUIRED_EVENTS_PROFILE.into(),
        quote_framing: GcpQuoteFraming::GcpTsmZeroPadded8000,
        required_rtmrs: [0, 1, 2, 3],
    };
    let v_wire = signed(&v, &v.signing_bytes().unwrap(), 202);
    let mut f = ArtifactFixtureFields {
        c: c_wire,
        d,
        a: a_wire,
        v: v_wire,
        expected: ArtifactVerificationExpectations {
            build_public_key: pubkey(201),
            reference_public_key: pubkey(202),
            build_issuer: "builder".into(),
            reference_issuer: "reference".into(),
            boot_binding: GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap(),
            pe_authenticode_sha384: a.pe_authenticode_sha384,
            firmware_mrtd: v.firmware_mrtd,
            module_policy_sha384: v.module_policy_sha384,
            firmware_endorsement_sha384: v.firmware_endorsement_sha384,
            quote_framing: v.quote_framing,
        },
    };
    f.expected.boot_binding = GcpBootBindingV1::new(
        raw_hash(&f.c),
        raw_hash(&f.d),
        raw_hash(&f.a),
        raw_hash(&f.v),
    )
    .unwrap();
    (f.c, f.d, f.a, f.v, f.expected)
}

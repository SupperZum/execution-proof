//! Synthetic signed public artifact fixtures, not deployed measurements or
//! qualification. No fixture roots are available in a non-test build.
use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

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
fn raw_hash(bytes: &[u8]) -> [u8; 48] {
    hex_bytes(&sha384(bytes), 48).unwrap().try_into().unwrap()
}
struct Fixture {
    c: Vec<u8>,
    d: Vec<u8>,
    a: Vec<u8>,
    v: Vec<u8>,
    expected: ArtifactVerificationExpectations,
}
fn bind(f: &mut Fixture) {
    f.expected.boot_binding = GcpBootBindingV1::new(
        raw_hash(&f.c),
        raw_hash(&f.d),
        raw_hash(&f.a),
        raw_hash(&f.v),
    )
    .unwrap();
}
fn verify(f: &Fixture) -> Result<AuthenticatedArtifacts, Error> {
    verify_artifacts(&f.c, &f.d, &f.a, &f.v, &f.expected)
}
fn config() -> ClosedBootConfigV1 {
    ClosedBootConfigV1 {
        version: 1,
        purpose: CLOSED_BOOT_CONFIG_PURPOSE.into(),
        roots: ClosedBootRootsV1 {
            authority_public_key: pubkey(1),
            build_public_key: pubkey(2),
            reference_public_key: pubkey(3),
            kbs_proof_public_key: pubkey(4),
            qualification_public_key: pubkey(5),
            authority_tls_roots_sha384: "51".repeat(48),
            kbs_tls_roots_sha384: "52".repeat(48),
        },
        authority: "authority".into(),
        tenant: "tenant".into(),
        grant_audience: "issuer".into(),
        aggregate_audience: "verifier".into(),
        admission_receipt_audience: "cdh".into(),
        authority_https_origin: "https://authority.example:8443".into(),
        kbs_https_origin: "https://kbs.example".into(),
        resource_path: ["repo".into(), "resource".into(), "key".into()],
        workflow_id: "kms-direct".into(),
        launch_policy_sha384: "31".repeat(48),
        image_policy_sha384: "32".repeat(48),
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
fn fixture() -> Fixture {
    let c = config();
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
        pe_authenticode_sha384: "72".repeat(48),
        source_tree_sha384: "73".repeat(48),
        toolchain_sha384: "74".repeat(48),
        kernel_config_sha384: "75".repeat(48),
        component_closure_sha384: "76".repeat(48),
        build_recipe_sha384: "77".repeat(48),
        measurement_recipe: GCP_MEASUREMENT_RECIPE.into(),
    };
    let a_wire = signed(&a, &a.signing_bytes().unwrap(), 2);
    let v = ReferencePolicySetV1 {
        version: 1,
        purpose: REFERENCE_POLICY_SET_PURPOSE.into(),
        reference_id: "reference-test".into(),
        issuer: "reference".into(),
        artifact_manifest_sha384: sha384(&a_wire),
        firmware_mrtd: "81".repeat(48),
        pe_authenticode_sha384: a.pe_authenticode_sha384.clone(),
        module_policy_sha384: "82".repeat(48),
        firmware_endorsement_sha384: "83".repeat(48),
        platform_profile: GCP_PLATFORM_PROFILE.into(),
        measurement_recipe: GCP_MEASUREMENT_RECIPE.into(),
        required_events_profile: GCP_REQUIRED_EVENTS_PROFILE.into(),
        quote_framing: GcpQuoteFraming::GcpTsmZeroPadded8000,
        required_rtmrs: [0, 1, 2, 3],
    };
    let v_wire = signed(&v, &v.signing_bytes().unwrap(), 3);
    let mut f = Fixture {
        c: c_wire,
        d,
        a: a_wire,
        v: v_wire,
        expected: ArtifactVerificationExpectations {
            build_public_key: pubkey(2),
            reference_public_key: pubkey(3),
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
    bind(&mut f);
    f
}

#[test]
fn selected_roots_authenticate_exact_noncircular_public_graph() {
    let f = fixture();
    let data = verify(&f).unwrap();
    assert_eq!(data.config(), &config());
    assert_eq!(
        data.producer_core().config_sha384,
        f.expected.boot_binding.config_sha384
    );
    assert_eq!(
        data.manifest().pe_authenticode_sha384,
        f.expected.pe_authenticode_sha384
    );
    assert_eq!(
        data.reference().artifact_manifest_sha384,
        f.expected.boot_binding.artifact_manifest_sha384
    );
}
#[test]
fn whitespace_key_order_or_signature_wire_changes_are_not_hash_equivalent() {
    let mut f = fixture();
    f.c.push(b' ');
    assert!(verify(&f).is_err());
    bind(&mut f);
    assert!(verify(&f).is_err());
    let mut f = fixture();
    f.a = serde_json::to_vec_pretty(&serde_json::from_slice::<serde_json::Value>(&f.a).unwrap())
        .unwrap();
    assert!(verify(&f).is_err());
    bind(&mut f);
    assert!(verify(&f).is_err());
    let mut f = fixture();
    f.v.push(b' ');
    assert!(verify(&f).is_err());
}
#[test]
fn foreign_build_reference_and_self_enrolled_roots_are_rejected() {
    for which in 0..4 {
        let mut f = fixture();
        match which {
            0 => {
                let a: Signed<BootArtifactManifestV1> = serde_json::from_slice(&f.a).unwrap();
                f.a = signed(&a.statement, &a.statement.signing_bytes().unwrap(), 9);
                let mut v: Signed<ReferencePolicySetV1> = serde_json::from_slice(&f.v).unwrap();
                v.statement.artifact_manifest_sha384 = sha384(&f.a);
                f.v = signed(&v.statement, &v.statement.signing_bytes().unwrap(), 3);
                bind(&mut f);
            }
            1 => {
                let v: Signed<ReferencePolicySetV1> = serde_json::from_slice(&f.v).unwrap();
                f.v = signed(&v.statement, &v.statement.signing_bytes().unwrap(), 9);
                bind(&mut f);
            }
            2 => f.expected.build_public_key = pubkey(9),
            _ => f.expected.reference_public_key = pubkey(9),
        }
        assert!(verify(&f).is_err());
    }
    let mut f = fixture();
    f.expected.reference_public_key = f.expected.build_public_key;
    assert!(verify(&f).is_err());
}
#[test]
fn every_independent_reference_and_exact_relation_is_checked() {
    for which in 0..7 {
        let mut f = fixture();
        match which {
            0 => f.expected.pe_authenticode_sha384 = "91".repeat(48),
            1 => f.expected.firmware_mrtd = "91".repeat(48),
            2 => f.expected.module_policy_sha384 = "91".repeat(48),
            3 => f.expected.firmware_endorsement_sha384 = "91".repeat(48),
            4 => f.expected.quote_framing = GcpQuoteFraming::ExactFrame,
            5 => f.expected.build_issuer = "other".into(),
            _ => f.expected.reference_issuer = "other".into(),
        }
        assert!(verify(&f).is_err());
    }
    let mut f = fixture();
    let mut a: Signed<BootArtifactManifestV1> = serde_json::from_slice(&f.a).unwrap();
    a.statement.config_sha384 = "91".repeat(48);
    f.a = signed(&a.statement, &a.statement.signing_bytes().unwrap(), 2);
    let mut v: Signed<ReferencePolicySetV1> = serde_json::from_slice(&f.v).unwrap();
    v.statement.artifact_manifest_sha384 = sha384(&f.a);
    f.v = signed(&v.statement, &v.statement.signing_bytes().unwrap(), 3);
    bind(&mut f);
    assert!(verify(&f).is_err());
}
#[test]
fn backward_cycle_fields_unknown_peers_and_duplicate_json_fields_are_rejected() {
    let f = fixture();
    for (index, field) in [
        (0, "boot_binding_sha384"),
        (1, "producer_core_sha384"),
        (2, "reference_policy_sha384"),
        (3, "boot_binding_sha384"),
    ] {
        let original = [&f.c, &f.d, &f.a, &f.v][index];
        let mut value: serde_json::Value = serde_json::from_slice(original).unwrap();
        if index >= 2 {
            value["statement"][field] = "91".repeat(48).into();
        } else {
            value[field] = "91".repeat(48).into();
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut copy = fixture();
        match index {
            0 => copy.c = bytes,
            1 => copy.d = bytes,
            2 => copy.a = bytes,
            _ => copy.v = bytes,
        }
        bind(&mut copy);
        assert!(verify(&copy).is_err());
    }
    let c = String::from_utf8(f.c).unwrap();
    let duplicate = c.replacen("{", "{\"version\":1,", 1);
    assert!(ClosedBootConfigV1::decode(duplicate.as_bytes()).is_err());
}
#[test]
fn stable_config_rejects_mutable_paths_raw_quote_rpc_and_unimplemented_limits() {
    for path in [
        "/tmp/cdh",
        "/run/cdh",
        "/proc/self/exe",
        "/onb17/../cdh",
        "relative/cdh",
        "/onb17//cdh",
        "/onb17/$HOME",
    ] {
        let mut c = config();
        c.cdh_path = path.into();
        assert!(c.validate().is_err());
    }
    for origin in [
        "http://authority.example",
        "https://user@authority.example",
        "https://authority.example/path",
        "https://authority.example?x",
        "https://authority.example:0",
        "https://authority.example:65536",
        "https://authority.example:0443",
    ] {
        let mut c = config();
        c.authority_https_origin = origin.into();
        assert!(c.validate().is_err());
    }
    let mut c = config();
    c.generic_attestation_rpc_enabled = true;
    assert!(c.validate().is_err());
    let mut c = config();
    c.limits.pending_records = 5;
    assert!(c.validate().is_err());
    let mut c = config();
    c.roots.build_public_key = c.roots.authority_public_key;
    assert!(c.validate().is_err());
}
#[test]
fn core_paths_kinds_and_size_budgets_are_closed() {
    let f = fixture();
    let core = ProducerCoreV1::decode(&f.d).unwrap();
    let mut oversized = core.clone();
    for leaf in oversized.leaves.iter_mut().take(3) {
        leaf.size_bytes = MAX_PRODUCER_LEAF_BYTES;
    }
    assert!(oversized.validate().is_err());
    let mut moved = core.clone();
    moved
        .leaves
        .iter_mut()
        .find(|l| l.kind == ProducerLeafKind::RpcPolicy)
        .unwrap()
        .path = "/onb17/policy/unused-rpc.json".into();
    assert!(moved.validate().is_ok());
    assert!(moved
        .check_config(&ClosedBootConfigV1::decode(&f.c).unwrap())
        .is_err());
    for which in 0..5 {
        let mut d = core.clone();
        match which {
            0 => d.leaves.push(d.leaves[0].clone()),
            1 => d.leaves[0].size_bytes = MAX_PRODUCER_LEAF_BYTES + 1,
            2 => d.leaves[0].size_bytes = 0,
            3 => d.leaves.reverse(),
            _ => d.leaves = vec![d.leaves[0].clone(); MAX_PRODUCER_LEAVES + 1],
        }
        assert!(d.validate().is_err());
    }
    let mut f = fixture();
    let mut d = ProducerCoreV1::decode(&f.d).unwrap();
    d.leaves
        .iter_mut()
        .find(|l| l.kind == ProducerLeafKind::RpcPolicy)
        .unwrap()
        .kind = ProducerLeafKind::Data;
    f.d = d.encode().unwrap();
    let mut a: Signed<BootArtifactManifestV1> = serde_json::from_slice(&f.a).unwrap();
    a.statement.producer_core_sha384 = sha384(&f.d);
    f.a = signed(&a.statement, &a.statement.signing_bytes().unwrap(), 2);
    let mut v: Signed<ReferencePolicySetV1> = serde_json::from_slice(&f.v).unwrap();
    v.statement.artifact_manifest_sha384 = sha384(&f.a);
    f.v = signed(&v.statement, &v.statement.signing_bytes().unwrap(), 3);
    bind(&mut f);
    assert!(verify(&f).is_err());
}
#[test]
fn oversized_wire_inputs_and_unknown_platform_domains_are_rejected() {
    let f = fixture();
    assert!(verify_artifacts(
        &vec![b' '; MAX_CONFIG_BYTES + 1],
        &f.d,
        &f.a,
        &f.v,
        &f.expected
    )
    .is_err());
    assert!(verify_artifacts(
        &f.c,
        &vec![b' '; MAX_CORE_BYTES + 1],
        &f.a,
        &f.v,
        &f.expected
    )
    .is_err());
    assert!(verify_artifacts(
        &f.c,
        &f.d,
        &vec![b' '; MAX_MANIFEST_BYTES + 1],
        &f.v,
        &f.expected
    )
    .is_err());
    assert!(verify_artifacts(
        &f.c,
        &f.d,
        &f.a,
        &vec![b' '; MAX_REFERENCE_BYTES + 1],
        &f.expected
    )
    .is_err());
    let mut v: Signed<ReferencePolicySetV1> = serde_json::from_slice(&f.v).unwrap();
    v.statement.platform_profile = "unreviewed-platform".into();
    assert!(v.statement.signing_bytes().is_err());
    v.statement.platform_profile = GCP_PLATFORM_PROFILE.into();
    v.statement.required_rtmrs = [0, 1, 2, 2];
    assert!(v.statement.signing_bytes().is_err());
}

#[test]
fn manifest_and_reference_transcripts_match_independent_python_vectors() {
    let manifest = BootArtifactManifestV1 {
        version: 1,
        purpose: BOOT_ARTIFACT_MANIFEST_PURPOSE.into(),
        build_id: "artifact-golden".into(),
        issuer: "builder".into(),
        config_sha384: "01".repeat(48),
        producer_core_sha384: "02".repeat(48),
        pe_file_sha384: "03".repeat(48),
        pe_authenticode_sha384: "04".repeat(48),
        source_tree_sha384: "05".repeat(48),
        toolchain_sha384: "06".repeat(48),
        kernel_config_sha384: "07".repeat(48),
        component_closure_sha384: "08".repeat(48),
        build_recipe_sha384: "09".repeat(48),
        measurement_recipe: GCP_MEASUREMENT_RECIPE.into(),
    };
    let a = manifest.signing_bytes().unwrap();
    assert_eq!(a.len(), 625);
    assert_eq!(sha384(&a),"c3947d3456e59e0cec7b3101cb35e6cf98a5bb7e5b4e6c45faa2a5a82ca14798ea9f2d0100c86eed8a9951d0b5ee4dd4");
    let reference = ReferencePolicySetV1 {
        version: 1,
        purpose: REFERENCE_POLICY_SET_PURPOSE.into(),
        reference_id: "reference-golden".into(),
        issuer: "reference".into(),
        artifact_manifest_sha384: "11".repeat(48),
        firmware_mrtd: "12".repeat(48),
        pe_authenticode_sha384: "13".repeat(48),
        module_policy_sha384: "14".repeat(48),
        firmware_endorsement_sha384: "15".repeat(48),
        platform_profile: GCP_PLATFORM_PROFILE.into(),
        measurement_recipe: GCP_MEASUREMENT_RECIPE.into(),
        required_events_profile: GCP_REQUIRED_EVENTS_PROFILE.into(),
        quote_framing: GcpQuoteFraming::GcpTsmZeroPadded8000,
        required_rtmrs: [0, 1, 2, 3],
    };
    let v = reference.signing_bytes().unwrap();
    assert_eq!(v.len(), 529);
    assert_eq!(sha384(&v),"02e5e3ffc92b60db0025078c0970706e214e4a2aac13c1ea4ef8e2d9bf14c8b144f3f27a2829d6a9b3eb85ee8bc9b645");
}

fn relay_config() -> GcpManagementRelayConfigV1 {
    GcpManagementRelayConfigV1 {
        version: 1,
        purpose: "onb17.gcp-management-tls-relay.v1".into(),
        listen_ip: "0.0.0.0".into(),
        server_name: "podvm-server".into(),
        client_ca_pem_sha384: "91".repeat(48),
        server_cert_pem_sha384: "92".repeat(48),
        client_leaf_der_sha384: "93".repeat(48),
        max_connections: 8,
        handshake_milliseconds: 10000,
        dial_milliseconds: 5000,
        idle_milliseconds: 30000,
        session_milliseconds: 300000,
        max_bytes: 64 << 20,
    }
}
fn relay() -> GcpManagementRelayV1 {
    GcpManagementRelayV1 {
        executable_path: "/onb17/bin/management-relay".into(),
        configuration_path: "/onb17/management/relay.json".into(),
        configuration_sha384: sha384(&relay_config().encode().unwrap()),
        client_ca_path: "/onb17/management/client-ca.pem".into(),
        client_ca_sha384: "91".repeat(48),
        server_certificate_path: "/onb17/management/server-cert.pem".into(),
        server_certificate_sha384: "92".repeat(48),
        client_leaf_der_sha384: "93".repeat(48),
        uid: 1001,
        gid: 1001,
    }
}
#[test]
fn optional_management_role_preserves_vsock_wire_and_rejects_mixed_transport() {
    let c = config();
    let bytes = c.encode().unwrap();
    assert!(!String::from_utf8(bytes.clone())
        .unwrap()
        .contains("management_relay"));
    assert!(ClosedBootConfigV1::decode(&bytes)
        .unwrap()
        .management_relay
        .is_none());
    let mut tcp = c.clone();
    tcp.host_transport = "tcp_tls13_mtls".into();
    assert!(tcp.validate().is_err());
    tcp.management_relay = Some(relay());
    assert!(tcp.validate().is_ok());
    let mut mixed = tcp.clone();
    mixed.host_transport = "vsock".into();
    assert!(mixed.validate().is_err());
    for transport in ["tcp", "tls12", "tcp_tls12_mtls", "tcp_tls13"] {
        let mut bad = tcp.clone();
        bad.host_transport = transport.into();
        assert!(bad.validate().is_err());
    }
    let mut bad = tcp;
    bad.management_relay.as_mut().unwrap().configuration_path = "/tmp/relay.json".into();
    assert!(bad.validate().is_err());
}
#[test]
fn management_public_config_pins_paths_credentials_and_bounds_without_key_material() {
    let r = relay();
    let bytes = relay_config().encode().unwrap();
    let shared = include_bytes!("../tests/fixtures/gcp-management-relay/public-config-shape.json");
    assert_eq!(bytes, shared.trim_ascii());
    let mut selected = r.clone();
    selected.configuration_sha384 = sha384(shared);
    selected.check_config_bytes(shared).unwrap();
    r.check_config_bytes(&bytes).unwrap();
    let mut changed = relay_config();
    changed.client_leaf_der_sha384 = "94".repeat(48);
    assert!(r.check_config_bytes(&changed.encode().unwrap()).is_err());
    for mutate in [0, 1, 2, 3, 4] {
        let mut bad = relay_config();
        match mutate {
            0 => bad.max_connections = 9,
            1 => bad.listen_ip = "host-name".into(),
            2 => bad.server_name = "https://podvm-server".into(),
            3 => bad.handshake_milliseconds = 10001,
            _ => bad.max_bytes = (64 << 20) + 1,
        };
        assert!(bad.validate().is_err());
    }
    let mut bad = relay();
    bad.uid = 0;
    assert!(bad.validate().is_err());
    let mut bad = relay();
    bad.gid = 0;
    assert!(bad.validate().is_err());
    for field in ["private_key", "server_key_sha384", "credentials"] {
        let mut value = serde_json::to_value(relay()).unwrap();
        value[field] = "forbidden-key-material".into();
        assert!(serde_json::from_value::<GcpManagementRelayV1>(value).is_err());
        let mut value = serde_json::to_value(relay_config()).unwrap();
        value[field] = "forbidden-key-material".into();
        assert!(r
            .check_config_bytes(&serde_json::to_vec(&value).unwrap())
            .is_err());
    }
    let text = String::from_utf8(bytes).unwrap();
    assert!(r
        .check_config_bytes(text.replacen("{", "{\"version\":1,", 1).as_bytes())
        .is_err());
}
#[test]
fn management_role_requires_exact_declared_leaf_closure() {
    let mut c = config();
    c.host_transport = "tcp_tls13_mtls".into();
    let r = relay();
    c.management_relay = Some(r.clone());
    let mut core = ProducerCoreV1::decode(&fixture().d).unwrap();
    core.config_sha384 = sha384(&c.encode().unwrap());
    assert!(core.check_config(&c).is_err());
    core.leaves.extend(
        [
            (
                ProducerLeafKind::ManagementRelayBinary,
                r.executable_path.clone(),
                "94".repeat(48),
            ),
            (
                ProducerLeafKind::RelayConfig,
                r.configuration_path.clone(),
                r.configuration_sha384.clone(),
            ),
            (
                ProducerLeafKind::TlsRoots,
                r.client_ca_path.clone(),
                r.client_ca_sha384.clone(),
            ),
            (
                ProducerLeafKind::TlsRoots,
                r.server_certificate_path.clone(),
                r.server_certificate_sha384.clone(),
            ),
        ]
        .into_iter()
        .map(|(kind, path, sha384)| ProducerLeafV1 {
            kind,
            path,
            sha384,
            size_bytes: 128,
        }),
    );
    core.leaves.sort_by(|a, b| a.path.cmp(&b.path));
    core.validate().unwrap();
    core.check_config(&c).unwrap();
    assert!(core.check_config(&config()).is_err());
    let mut missing = core.clone();
    missing
        .leaves
        .retain(|l| l.kind != ProducerLeafKind::RelayConfig);
    assert!(missing.check_config(&c).is_err());
    let mut wrong = core.clone();
    wrong
        .leaves
        .iter_mut()
        .find(|l| l.kind == ProducerLeafKind::RelayConfig)
        .unwrap()
        .sha384 = "95".repeat(48);
    assert!(wrong.check_config(&c).is_err());
    let mut wrong = core;
    wrong
        .leaves
        .iter_mut()
        .find(|l| l.path == r.client_ca_path)
        .unwrap()
        .size_bytes = (64 << 10) + 1;
    assert!(wrong.check_config(&c).is_err());
}

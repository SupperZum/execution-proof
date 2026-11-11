//! Public authentication of the noncircular C -> D -> A -> V artifact graph.
//! Hashes cover exact bounded wire bytes. Signature verification establishes
//! selected authorities' statements, not physical boot provenance, enforcement,
//! qualification, key custody, or execution. No runtime capability is returned.

use crate::{
    frame, gcp_boot_binding::GcpBootBindingV1, hex_bytes, identifier, sha384, transcript,
    verify_signature, Error, Signed,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const ARTIFACT_VERSION: u16 = 1;
pub const CLOSED_BOOT_CONFIG_PURPOSE: &str = "qlad.execution-proof.gcp-closed-boot-config.v1";
pub const PRODUCER_CORE_PURPOSE: &str = "qlad.execution-proof.gcp-producer-core.v1";
pub const BOOT_ARTIFACT_MANIFEST_PURPOSE: &str =
    "qlad.execution-proof.gcp-boot-artifact-manifest.v1";
pub const REFERENCE_POLICY_SET_PURPOSE: &str = "qlad.execution-proof.gcp-reference-policy-set.v1";
pub const GCP_PLATFORM_PROFILE: &str = "gcp-c3-intel-tdx-x86_64.v1";
pub const GCP_MEASUREMENT_RECIPE: &str = "gcp-ccel-direct-pe.v1";
pub const GCP_REQUIRED_EVENTS_PROFILE: &str = "gcp-nvme-gpt-single-pe-exit-boot-services.v1";
pub const MAX_CONFIG_BYTES: usize = 64 << 10;
pub const MAX_CORE_BYTES: usize = 64 << 10;
pub const MAX_MANIFEST_BYTES: usize = 32 << 10;
pub const MAX_REFERENCE_BYTES: usize = 16 << 10;
pub const MAX_PRODUCER_LEAVES: usize = 64;
pub const MAX_PRODUCER_LEAF_BYTES: u64 = 256 << 20;
pub const MAX_PRODUCER_TOTAL_BYTES: u64 = 512 << 20;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedBootRootsV1 {
    pub authority_public_key: [u8; 32],
    pub build_public_key: [u8; 32],
    pub reference_public_key: [u8; 32],
    pub kbs_proof_public_key: [u8; 32],
    pub qualification_public_key: [u8; 32],
    pub authority_tls_roots_sha384: String,
    pub kbs_tls_roots_sha384: String,
}
impl ClosedBootRootsV1 {
    fn validate(&self) -> Result<(), Error> {
        let keys = [
            self.authority_public_key,
            self.build_public_key,
            self.reference_public_key,
            self.kbs_proof_public_key,
            self.qualification_public_key,
        ];
        for (i, key) in keys.iter().enumerate() {
            if *key == [0; 32] || keys[..i].contains(key) {
                return Err(Error::ConfusedKeys);
            }
        }
        nonzero_hash(&self.authority_tls_roots_sha384)?;
        nonzero_hash(&self.kbs_tls_roots_sha384)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpBootRole {
    Bootstrap,
    Cdh,
    KataAgent,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedBootLimitsV1 {
    pub pending_records: u16,
    pub pending_bytes: u64,
    pub quote_attempts: u16,
    pub quote_timeout_seconds: u16,
    pub pending_timeout_seconds: u16,
    pub evidence_bytes: u64,
    pub envelope_bytes: u64,
    pub pack_bytes: u64,
}
impl ClosedBootLimitsV1 {
    /// This version describes the existing fixed exporter/pack profile. Other
    /// limits require a new reviewed version rather than an unenforced knob.
    fn validate(&self) -> Result<(), Error> {
        if self.pending_records != 4
            || self.pending_bytes != 32 << 20
            || self.quote_attempts != 3
            || self.quote_timeout_seconds != 30
            || self.pending_timeout_seconds != 300
            || self.evidence_bytes != 1 << 20
            || self.envelope_bytes != 4 << 20
            || self.pack_bytes != 16 << 20
        {
            return Err(Error::InvalidField);
        }
        Ok(())
    }
}
/// C includes stable prebuild launch/image and RPC/device/writer policy refs.
/// It deliberately excludes the dynamic issuer admission-policy digest,
/// qualification decision, D, PE, A, V, and B. TLS roots refer to immutable leaf
/// bytes. These declarations do not prove the producer enforced those bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedBootConfigV1 {
    pub version: u16,
    pub purpose: String,
    pub roots: ClosedBootRootsV1,
    pub authority: String,
    pub tenant: String,
    pub grant_audience: String,
    pub aggregate_audience: String,
    pub admission_receipt_audience: String,
    pub authority_https_origin: String,
    pub kbs_https_origin: String,
    pub resource_path: [String; 3],
    pub workflow_id: String,
    pub launch_policy_sha384: String,
    pub image_policy_sha384: String,
    pub rpc_policy_sha384: String,
    pub device_policy_sha384: String,
    pub writer_policy_sha384: String,
    pub rpc_policy_path: String,
    pub device_policy_path: String,
    pub writer_policy_path: String,
    pub launch_policy_path: String,
    pub image_policy_path: String,
    pub authority_tls_roots_path: String,
    pub kbs_tls_roots_path: String,
    pub bootstrap_path: String,
    pub cdh_path: String,
    pub kata_agent_path: String,
    pub allowed_roles: [GcpBootRole; 3],
    pub custody_transport: String,
    pub host_transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_relay: Option<GcpManagementRelayV1>,
    pub generic_attestation_rpc_enabled: bool,
    pub limits: ClosedBootLimitsV1,
}
impl ClosedBootConfigV1 {
    pub fn validate(&self) -> Result<(), Error> {
        domain(self.version, &self.purpose, CLOSED_BOOT_CONFIG_PURPOSE)?;
        self.roots.validate()?;
        self.limits.validate()?;
        for id in [
            &self.authority,
            &self.tenant,
            &self.grant_audience,
            &self.aggregate_audience,
            &self.admission_receipt_audience,
            &self.workflow_id,
        ] {
            identifier(id)?;
        }
        for part in &self.resource_path {
            identifier(part)?;
            if part == "." || part == ".." {
                return Err(Error::InvalidField);
            }
        }
        for origin in [&self.authority_https_origin, &self.kbs_https_origin] {
            https_origin(origin)?;
        }
        for hash in [
            &self.launch_policy_sha384,
            &self.image_policy_sha384,
            &self.rpc_policy_sha384,
            &self.device_policy_sha384,
            &self.writer_policy_sha384,
        ] {
            nonzero_hash(hash)?;
        }
        let paths = [
            &self.bootstrap_path,
            &self.cdh_path,
            &self.kata_agent_path,
            &self.rpc_policy_path,
            &self.device_policy_path,
            &self.writer_policy_path,
            &self.launch_policy_path,
            &self.image_policy_path,
            &self.authority_tls_roots_path,
            &self.kbs_tls_roots_path,
        ];
        for (index, path) in paths.iter().enumerate() {
            immutable_path(path)?;
            if paths[..index].contains(path) {
                return Err(Error::InvalidField);
            }
        }
        if self.bootstrap_path == self.cdh_path
            || self.bootstrap_path == self.kata_agent_path
            || self.cdh_path == self.kata_agent_path
            || self.allowed_roles
                != [
                    GcpBootRole::Bootstrap,
                    GcpBootRole::Cdh,
                    GcpBootRole::KataAgent,
                ]
            || self.custody_transport != "private-unix-seqpacket"
            || self.generic_attestation_rpc_enabled
        {
            return Err(Error::InvalidField);
        }
        match (self.host_transport.as_str(), &self.management_relay) {
            ("vsock", None) => {}
            ("tcp_tls13_mtls", Some(relay)) => {
                relay.validate()?;
                for path in relay.paths() {
                    if paths.contains(&path) {
                        return Err(Error::InvalidField);
                    }
                }
            }
            _ => return Err(Error::InvalidField),
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(self, MAX_CONFIG_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let v: Self = decode(bytes, MAX_CONFIG_BYTES)?;
        v.validate()?;
        Ok(v)
    }
}

/// Optional management role, separate from the three proof/preparation roles.
/// Only public credentials appear here; private key bytes/hashes are excluded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpManagementRelayV1 {
    pub executable_path: String,
    pub configuration_path: String,
    pub configuration_sha384: String,
    pub client_ca_path: String,
    pub client_ca_sha384: String,
    pub server_certificate_path: String,
    pub server_certificate_sha384: String,
    pub client_leaf_der_sha384: String,
    pub uid: u32,
    pub gid: u32,
}
impl GcpManagementRelayV1 {
    fn paths(&self) -> [&String; 4] {
        [
            &self.executable_path,
            &self.configuration_path,
            &self.client_ca_path,
            &self.server_certificate_path,
        ]
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.uid != 1001
            || self.gid != 1001
            || self.configuration_path != "/onb17/management/relay.json"
        {
            return Err(Error::InvalidField);
        }
        let paths = self.paths();
        for (index, path) in paths.iter().enumerate() {
            immutable_path(path)?;
            if paths[..index].contains(path) {
                return Err(Error::InvalidField);
            }
        }
        for hash in [
            &self.configuration_sha384,
            &self.client_ca_sha384,
            &self.server_certificate_sha384,
            &self.client_leaf_der_sha384,
        ] {
            nonzero_hash(hash)?;
        }
        if self.client_ca_sha384 == self.server_certificate_sha384 {
            return Err(Error::ConfusedKeys);
        }
        Ok(())
    }
    /// Check exact authenticated config bytes before the startup owner launches
    /// the role. This authenticates public configuration, never key custody.
    pub fn check_config_bytes(&self, bytes: &[u8]) -> Result<(), Error> {
        self.validate()?;
        let config: GcpManagementRelayConfigV1 = decode(bytes, 16 << 10)?;
        config.validate()?;
        if sha384(bytes) != self.configuration_sha384
            || config.client_ca_pem_sha384 != self.client_ca_sha384
            || config.server_cert_pem_sha384 != self.server_certificate_sha384
            || config.client_leaf_der_sha384 != self.client_leaf_der_sha384
        {
            return Err(Error::BindingMismatch);
        }
        Ok(())
    }
}
/// Exact public JSON shared with the dedicated Go relay. Backend path, port,
/// TLS floor, inherited FD numbers, and copy-buffer size are fixed in its code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpManagementRelayConfigV1 {
    pub version: u16,
    pub purpose: String,
    pub listen_ip: String,
    pub server_name: String,
    pub client_ca_pem_sha384: String,
    pub server_cert_pem_sha384: String,
    pub client_leaf_der_sha384: String,
    pub max_connections: u16,
    pub handshake_milliseconds: u32,
    pub dial_milliseconds: u32,
    pub idle_milliseconds: u32,
    pub session_milliseconds: u32,
    pub max_bytes: u64,
}
impl GcpManagementRelayConfigV1 {
    pub fn validate(&self) -> Result<(), Error> {
        let ip: std::net::Ipv4Addr = self.listen_ip.parse().map_err(|_| Error::InvalidField)?;
        if self.version != 1
            || self.purpose != "onb17.gcp-management-tls-relay.v1"
            || ip.is_multicast()
            || ip.to_string() != self.listen_ip
            || !dns_name(&self.server_name)
        {
            return Err(Error::InvalidField);
        }
        for hash in [
            &self.client_ca_pem_sha384,
            &self.server_cert_pem_sha384,
            &self.client_leaf_der_sha384,
        ] {
            nonzero_hash(hash)?;
        }
        if !(1..=8).contains(&self.max_connections)
            || !(1..=10000).contains(&self.handshake_milliseconds)
            || !(1..=5000).contains(&self.dial_milliseconds)
            || !(1..=30000).contains(&self.idle_milliseconds)
            || !(1..=300000).contains(&self.session_milliseconds)
            || !(1..=64 << 20).contains(&self.max_bytes)
            || self.handshake_milliseconds > self.session_milliseconds
            || self.dial_milliseconds > self.session_milliseconds
            || self.idle_milliseconds > self.session_milliseconds
        {
            return Err(Error::InvalidField);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(self, 16 << 10)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerLeafKind {
    BootstrapBinary,
    CdhBinary,
    KataAgentBinary,
    ManagementRelayBinary,
    RelayConfig,
    HelperBinary,
    Loader,
    SharedLibrary,
    RpcPolicy,
    DevicePolicy,
    WriterPolicy,
    TlsRoots,
    LaunchPolicy,
    ImagePolicy,
    Data,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerLeafV1 {
    pub kind: ProducerLeafKind,
    pub path: String,
    pub sha384: String,
    pub size_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerCoreV1 {
    pub version: u16,
    pub purpose: String,
    pub config_sha384: String,
    pub leaves: Vec<ProducerLeafV1>,
}
impl ProducerCoreV1 {
    pub fn validate(&self) -> Result<(), Error> {
        domain(self.version, &self.purpose, PRODUCER_CORE_PURPOSE)?;
        nonzero_hash(&self.config_sha384)?;
        if self.leaves.is_empty() || self.leaves.len() > MAX_PRODUCER_LEAVES {
            return Err(Error::TooLarge);
        }
        let mut total = 0u64;
        for (index, leaf) in self.leaves.iter().enumerate() {
            immutable_path(&leaf.path)?;
            nonzero_hash(&leaf.sha384)?;
            if leaf.size_bytes == 0 || leaf.size_bytes > MAX_PRODUCER_LEAF_BYTES {
                return Err(Error::TooLarge);
            }
            total = total.checked_add(leaf.size_bytes).ok_or(Error::TooLarge)?;
            if total > MAX_PRODUCER_TOTAL_BYTES {
                return Err(Error::TooLarge);
            }
            if index > 0 && self.leaves[index - 1].path >= leaf.path {
                return Err(Error::InvalidField);
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(self, MAX_CORE_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let v: Self = decode(bytes, MAX_CORE_BYTES)?;
        v.validate()?;
        Ok(v)
    }
    fn check_config(&self, c: &ClosedBootConfigV1) -> Result<(), Error> {
        for (kind, path) in [
            (ProducerLeafKind::BootstrapBinary, &c.bootstrap_path),
            (ProducerLeafKind::CdhBinary, &c.cdh_path),
            (ProducerLeafKind::KataAgentBinary, &c.kata_agent_path),
        ] {
            let mut found = self.leaves.iter().filter(|l| l.kind == kind);
            if found.next().map(|l| &l.path) != Some(path) || found.next().is_some() {
                return Err(Error::BindingMismatch);
            }
        }
        for (kind, path, hash) in [
            (
                ProducerLeafKind::RpcPolicy,
                &c.rpc_policy_path,
                &c.rpc_policy_sha384,
            ),
            (
                ProducerLeafKind::DevicePolicy,
                &c.device_policy_path,
                &c.device_policy_sha384,
            ),
            (
                ProducerLeafKind::WriterPolicy,
                &c.writer_policy_path,
                &c.writer_policy_sha384,
            ),
            (
                ProducerLeafKind::TlsRoots,
                &c.authority_tls_roots_path,
                &c.roots.authority_tls_roots_sha384,
            ),
            (
                ProducerLeafKind::TlsRoots,
                &c.kbs_tls_roots_path,
                &c.roots.kbs_tls_roots_sha384,
            ),
            (
                ProducerLeafKind::LaunchPolicy,
                &c.launch_policy_path,
                &c.launch_policy_sha384,
            ),
            (
                ProducerLeafKind::ImagePolicy,
                &c.image_policy_path,
                &c.image_policy_sha384,
            ),
        ] {
            if !self
                .leaves
                .iter()
                .any(|l| l.kind == kind && &l.path == path && &l.sha384 == hash)
            {
                return Err(Error::BindingMismatch);
            }
        }
        let mut relay_binaries = self
            .leaves
            .iter()
            .filter(|leaf| leaf.kind == ProducerLeafKind::ManagementRelayBinary);
        match &c.management_relay {
            None => {
                if relay_binaries.next().is_some()
                    || self
                        .leaves
                        .iter()
                        .any(|leaf| leaf.kind == ProducerLeafKind::RelayConfig)
                {
                    return Err(Error::BindingMismatch);
                }
            }
            Some(relay) => {
                if relay_binaries.next().map(|leaf| &leaf.path) != Some(&relay.executable_path)
                    || relay_binaries.next().is_some()
                {
                    return Err(Error::BindingMismatch);
                }
                if self
                    .leaves
                    .iter()
                    .filter(|leaf| leaf.kind == ProducerLeafKind::RelayConfig)
                    .count()
                    != 1
                {
                    return Err(Error::BindingMismatch);
                }
                for (kind, path, hash) in [
                    (
                        ProducerLeafKind::RelayConfig,
                        &relay.configuration_path,
                        &relay.configuration_sha384,
                    ),
                    (
                        ProducerLeafKind::TlsRoots,
                        &relay.client_ca_path,
                        &relay.client_ca_sha384,
                    ),
                    (
                        ProducerLeafKind::TlsRoots,
                        &relay.server_certificate_path,
                        &relay.server_certificate_sha384,
                    ),
                ] {
                    let max = if kind == ProducerLeafKind::RelayConfig {
                        16 << 10
                    } else {
                        64 << 10
                    };
                    if !self.leaves.iter().any(|leaf| {
                        leaf.kind == kind
                            && &leaf.path == path
                            && &leaf.sha384 == hash
                            && leaf.size_bytes <= max
                    }) {
                        return Err(Error::BindingMismatch);
                    }
                }
            }
        }
        Ok(())
    }
}

/// A is external to the PE. No V, B, qualification decision, or self digest can
/// be carried by this schema; extra fields are rejected during deserialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootArtifactManifestV1 {
    pub version: u16,
    pub purpose: String,
    pub build_id: String,
    pub issuer: String,
    pub config_sha384: String,
    pub producer_core_sha384: String,
    pub pe_file_sha384: String,
    pub pe_authenticode_sha384: String,
    pub source_tree_sha384: String,
    pub toolchain_sha384: String,
    pub kernel_config_sha384: String,
    pub component_closure_sha384: String,
    pub build_recipe_sha384: String,
    pub measurement_recipe: String,
}
impl BootArtifactManifestV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        domain(self.version, &self.purpose, BOOT_ARTIFACT_MANIFEST_PURPOSE)?;
        identifier(&self.build_id)?;
        identifier(&self.issuer)?;
        if self.measurement_recipe != GCP_MEASUREMENT_RECIPE {
            return Err(Error::InvalidField);
        }
        let mut out = transcript(b"gcp-boot-artifact-manifest", self.version);
        for id in [
            &self.purpose,
            &self.build_id,
            &self.issuer,
            &self.measurement_recipe,
        ] {
            frame(&mut out, id.as_bytes());
        }
        hashes(
            &mut out,
            [
                &self.config_sha384,
                &self.producer_core_sha384,
                &self.pe_file_sha384,
                &self.pe_authenticode_sha384,
                &self.source_tree_sha384,
                &self.toolchain_sha384,
                &self.kernel_config_sha384,
                &self.component_closure_sha384,
                &self.build_recipe_sha384,
            ],
        )?;
        Ok(out)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpQuoteFraming {
    ExactFrame,
    GcpTsmZeroPadded8000,
}
/// V refers to exact signed A bytes and independently selected firmware and
/// module policy. A does not refer to V; neither refers back to B.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferencePolicySetV1 {
    pub version: u16,
    pub purpose: String,
    pub reference_id: String,
    pub issuer: String,
    pub artifact_manifest_sha384: String,
    pub firmware_mrtd: String,
    pub pe_authenticode_sha384: String,
    pub module_policy_sha384: String,
    pub firmware_endorsement_sha384: String,
    pub platform_profile: String,
    pub measurement_recipe: String,
    pub required_events_profile: String,
    pub quote_framing: GcpQuoteFraming,
    pub required_rtmrs: [u8; 4],
}
impl ReferencePolicySetV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        domain(self.version, &self.purpose, REFERENCE_POLICY_SET_PURPOSE)?;
        identifier(&self.reference_id)?;
        identifier(&self.issuer)?;
        if self.platform_profile != GCP_PLATFORM_PROFILE
            || self.measurement_recipe != GCP_MEASUREMENT_RECIPE
            || self.required_events_profile != GCP_REQUIRED_EVENTS_PROFILE
            || self.required_rtmrs != [0, 1, 2, 3]
        {
            return Err(Error::InvalidField);
        }
        let mut out = transcript(b"gcp-reference-policy-set", self.version);
        for id in [
            &self.purpose,
            &self.reference_id,
            &self.issuer,
            &self.platform_profile,
            &self.measurement_recipe,
            &self.required_events_profile,
        ] {
            frame(&mut out, id.as_bytes());
        }
        frame(
            &mut out,
            match self.quote_framing {
                GcpQuoteFraming::ExactFrame => b"exact_frame",
                GcpQuoteFraming::GcpTsmZeroPadded8000 => b"gcp_tsm_zero_padded8000",
            },
        );
        frame(&mut out, &self.required_rtmrs);
        hashes(
            &mut out,
            [
                &self.artifact_manifest_sha384,
                &self.firmware_mrtd,
                &self.pe_authenticode_sha384,
                &self.module_policy_sha384,
                &self.firmware_endorsement_sha384,
            ],
        )?;
        Ok(out)
    }
}

/// Relying-party inputs selected outside the submitted object set. Independently
/// selected build/reference issuers prevent a bundle from naming its own roots.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactVerificationExpectations {
    pub build_public_key: [u8; 32],
    pub reference_public_key: [u8; 32],
    pub build_issuer: String,
    pub reference_issuer: String,
    pub boot_binding: GcpBootBindingV1,
    pub pe_authenticode_sha384: String,
    pub firmware_mrtd: String,
    pub module_policy_sha384: String,
    pub firmware_endorsement_sha384: String,
    pub quote_framing: GcpQuoteFraming,
}
/// Authenticated public data only, without Deserialize or a public constructor.
/// This is not TrustedGcpBootContext, hardware evidence, or a qualified producer.
pub struct AuthenticatedArtifacts {
    config: ClosedBootConfigV1,
    core: ProducerCoreV1,
    manifest: BootArtifactManifestV1,
    reference: ReferencePolicySetV1,
}
impl AuthenticatedArtifacts {
    pub fn config(&self) -> &ClosedBootConfigV1 {
        &self.config
    }
    pub fn producer_core(&self) -> &ProducerCoreV1 {
        &self.core
    }
    pub fn manifest(&self) -> &BootArtifactManifestV1 {
        &self.manifest
    }
    pub fn reference(&self) -> &ReferencePolicySetV1 {
        &self.reference
    }
}
/// Validate the prebuild C/D relationship without inventing an external A/V
/// signature or a boot capability. Builders must separately read back each leaf.
pub fn validate_config_core(
    c_json: &[u8],
    d_json: &[u8],
) -> Result<(ClosedBootConfigV1, ProducerCoreV1), Error> {
    let config = ClosedBootConfigV1::decode(c_json)?;
    let core = ProducerCoreV1::decode(d_json)?;
    if core.config_sha384 != sha384(c_json) {
        return Err(Error::BindingMismatch);
    }
    core.check_config(&config)?;
    Ok((config, core))
}
pub fn verify_artifacts(
    c_json: &[u8],
    d_json: &[u8],
    signed_a_json: &[u8],
    signed_v_json: &[u8],
    expected: &ArtifactVerificationExpectations,
) -> Result<AuthenticatedArtifacts, Error> {
    expected.boot_binding.validate()?;
    identifier(&expected.build_issuer)?;
    identifier(&expected.reference_issuer)?;
    for value in [
        &expected.pe_authenticode_sha384,
        &expected.firmware_mrtd,
        &expected.module_policy_sha384,
        &expected.firmware_endorsement_sha384,
    ] {
        nonzero_hash(value)?;
    }
    if expected.build_public_key == [0; 32]
        || expected.reference_public_key == [0; 32]
        || expected.build_public_key == expected.reference_public_key
    {
        return Err(Error::ConfusedKeys);
    }
    let config = ClosedBootConfigV1::decode(c_json)?;
    let core = ProducerCoreV1::decode(d_json)?;
    let a: Signed<BootArtifactManifestV1> = decode(signed_a_json, MAX_MANIFEST_BYTES)?;
    let v: Signed<ReferencePolicySetV1> = decode(signed_v_json, MAX_REFERENCE_BYTES)?;
    let a_sign = a.statement.signing_bytes()?;
    let v_sign = v.statement.signing_bytes()?;
    let (c_hash, d_hash, a_hash, v_hash) = (
        sha384(c_json),
        sha384(d_json),
        sha384(signed_a_json),
        sha384(signed_v_json),
    );
    let b = &expected.boot_binding;
    if b.config_sha384 != c_hash
        || b.producer_core_sha384 != d_hash
        || b.artifact_manifest_sha384 != a_hash
        || b.reference_policy_sha384 != v_hash
        || core.config_sha384 != c_hash
        || a.statement.config_sha384 != c_hash
        || a.statement.producer_core_sha384 != d_hash
        || v.statement.artifact_manifest_sha384 != a_hash
        || config.roots.build_public_key != expected.build_public_key
        || config.roots.reference_public_key != expected.reference_public_key
        || a.statement.issuer != expected.build_issuer
        || v.statement.issuer != expected.reference_issuer
        || a.statement.pe_authenticode_sha384 != expected.pe_authenticode_sha384
        || v.statement.pe_authenticode_sha384 != expected.pe_authenticode_sha384
        || v.statement.firmware_mrtd != expected.firmware_mrtd
        || v.statement.module_policy_sha384 != expected.module_policy_sha384
        || v.statement.firmware_endorsement_sha384 != expected.firmware_endorsement_sha384
        || v.statement.quote_framing != expected.quote_framing
    {
        return Err(Error::BindingMismatch);
    }
    core.check_config(&config)?;
    verify_signature(&expected.build_public_key, &a_sign, &a.signature)?;
    verify_signature(&expected.reference_public_key, &v_sign, &v.signature)?;
    Ok(AuthenticatedArtifacts {
        config,
        core,
        manifest: a.statement,
        reference: v.statement,
    })
}

fn domain(version: u16, purpose: &str, expected: &str) -> Result<(), Error> {
    if version != ARTIFACT_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if purpose != expected {
        return Err(Error::WrongPurpose);
    }
    Ok(())
}
fn nonzero_hash(value: &str) -> Result<(), Error> {
    if hex_bytes(value, 48)? == [0; 48] {
        return Err(Error::InvalidField);
    }
    Ok(())
}
fn hashes<'a>(
    out: &mut Vec<u8>,
    values: impl IntoIterator<Item = &'a String>,
) -> Result<(), Error> {
    for value in values {
        nonzero_hash(value)?;
        frame(out, &hex_bytes(value, 48)?);
    }
    Ok(())
}
fn decode<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T, Error> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Malformed)
}
fn encode(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Malformed)?;
    if bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}
fn immutable_path(value: &str) -> Result<(), Error> {
    if value.len() > 256
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        || value
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || ["/proc/", "/sys/", "/dev/", "/run/", "/tmp/"]
            .iter()
            .any(|p| value == p.trim_end_matches('/') || value.starts_with(p))
    {
        return Err(Error::InvalidField);
    }
    Ok(())
}
fn https_origin(value: &str) -> Result<(), Error> {
    if value.len() > 256 {
        return Err(Error::InvalidField);
    }
    let authority = value.strip_prefix("https://").ok_or(Error::InvalidField)?;
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if !dns_name(host) {
        return Err(Error::InvalidField);
    }
    if let Some(port) = port {
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.starts_with('0')
            || port.parse::<u16>().ok().filter(|v| *v > 0).is_none()
        {
            return Err(Error::InvalidField);
        }
    }
    Ok(())
}
fn dns_name(host: &str) -> bool {
    !(host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }))
}

#[cfg(test)]
#[path = "gcp_artifact_tests.rs"]
mod tests;

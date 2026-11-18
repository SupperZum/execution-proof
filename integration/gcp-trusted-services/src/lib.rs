//! Dedicated production composition of selected Trustee GCP source. This crate
//! has no software evidence verifier, mock authority, sample attester or generic
//! KBS routes. Leaf manifests compile the actual Regorus and JWE source while
//! excluding unrelated provider/database feature graphs.
#![cfg(feature = "server")]
extern crate self as attestation_service;
pub mod config {
    pub use verifier::VerifierConfig;
}
#[path = "../../../../trustee-launch-dev/attestation-service/src/launch_policy.rs"]
mod as_policy;
#[path = "../../../../trustee-launch-dev/kbs/src/launch_policy.rs"]
mod kbs_policy;
pub mod launch_policy {
    pub use super::as_policy::*;
    pub use super::kbs_policy::{evaluate_kbs_policy, KbsPolicyError, KbsPolicyFacts};
}
#[path = "../../../../trustee-launch-dev/kbs/src/gcp_launch_credential.rs"]
pub mod gcp_launch_credential;
#[path = "../../../../trustee-launch-dev/attestation-service/src/gcp_launch_evidence.rs"]
pub mod gcp_launch_evidence;
#[path = "../../../../trustee-launch-dev/kbs/src/gcp_launch_http.rs"]
pub mod gcp_launch_http;
#[path = "../../../../trustee-launch-dev/kbs/src/gcp_launch_resource.rs"]
pub mod gcp_launch_resource;
#[path = "../../../../trustee-launch-dev/kbs/src/gcp_launch_session.rs"]
pub mod gcp_launch_session;
pub mod jwe {
    pub use credential_jwe::jwe;
}
#[path = "../../../../trustee-launch-dev/kbs/src/plugins/implementations/resource/backend.rs"]
#[allow(dead_code)] // Generic admin-plugin mutation callers are not registered here.
#[allow(clippy::double_must_use)] // Existing imported async_trait expansion.
pub mod credential_resource_backend;
pub use credential_resource_backend::{ResourceDesc, StorageBackend};
#[path = "../../../../trustee-launch-dev/kbs/src/plugins/implementations/resource/kv_storage.rs"]
pub mod credential_resource_kv;
pub mod plugins {
    pub mod resource {
        pub use crate::credential_resource_backend::*;
        pub mod kv_storage {
            pub use crate::credential_resource_kv::*;
        }
    }
}
pub mod prometheus {
    use std::sync::LazyLock;
    fn counter(name: &str) -> ::prometheus::IntCounterVec {
        ::prometheus::IntCounterVec::new(
            ::prometheus::Opts::new(name, "Scoped credential operations"),
            &["resource"],
        )
        .expect("constant metric definition")
    }
    pub static RESOURCE_READS_TOTAL: LazyLock<::prometheus::IntCounterVec> =
        LazyLock::new(|| counter("onb17_resource_reads"));
    pub static RESOURCE_WRITES_TOTAL: LazyLock<::prometheus::IntCounterVec> =
        LazyLock::new(|| counter("onb17_resource_writes"));
    pub static RESOURCE_DELETES_TOTAL: LazyLock<::prometheus::IntCounterVec> =
        LazyLock::new(|| counter("onb17_resource_deletes"));
}
pub mod archive;
#[cfg(test)]
mod policy_tests;
pub mod server;

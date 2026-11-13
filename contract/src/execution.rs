//! Bounded public data for one captured initial application exec.
//!
//! Decoding or hashing this record does not establish that an exec happened or
//! authenticate its producer. The runtime must capture it from its owned task
//! at the kernel exec stop, before resuming that task. Quote construction and
//! independent execution verification are separate operations.
//! This fixed profile supports only the authenticated application-init role;
//! the runtime and verifier must obtain that role from the referenced grant.

use crate::{frame, hex_bytes, identifier, transcript, Error, MAX_WIRE_BYTES};
use ring::digest;
use serde::{Deserialize, Serialize};

pub const EXECUTION_RECORD_VERSION: u16 = 1;
pub const EXECUTION_RECORD_PURPOSE: &str = "qlad.execution-proof.exec-record.v1";
pub const EXECUTION_RECORD_PROFILE: &str = "onb17.static-elf-exec-committed.v1";
pub const EXECUTION_RECORD_CLAIM: &str = "exec_committed";
pub const EXECUTION_APPLICATION_ROLE: &str = "application-init";

/// Runtime-local identity. A container ID is a local alias, not an authenticated
/// Kubernetes Pod identity; a PID alone is insufficient to identify a lifecycle.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTask {
    pub container_id: String,
    pub generation: u64,
    pub pid: u32,
    /// Kernel process identity in boot-local ticks, never an exec timestamp.
    pub process_start_time_ticks: u64,
}

/// Non-authorizing public observations and references, never a start capability.
/// Every field is covered by the ordered binary transcript and its SHA-384 hash.
/// Raw environment/spec bytes and credentials do not belong in this record.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    pub version: u16,
    pub purpose: String,
    pub profile: String,
    pub claim: String,
    /// Fresh 32-byte event identifier selected by the protected runtime owner.
    pub event_id: String,
    pub grant_sha384: String,
    pub admission_context_sha384: String,
    pub preparation_record_sha384: String,
    pub startup_binding_sha384: String,
    pub candidate_spec_sha384: String,
    pub final_spec_sha384: String,
    pub image_sha384: String,
    pub executable_sha384: String,
    pub mount_id: u64,
    pub task: ExecutionTask,
}

impl ExecutionRecord {
    /// Validate syntax and the fixed record profile, not producer authenticity
    /// or agreement with a particular admitted task and prepared view.
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != EXECUTION_RECORD_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.purpose != EXECUTION_RECORD_PURPOSE {
            return Err(Error::WrongPurpose);
        }
        if self.profile != EXECUTION_RECORD_PROFILE || self.claim != EXECUTION_RECORD_CLAIM {
            return Err(Error::InvalidField);
        }
        if hex_bytes(&self.event_id, 32)? == [0; 32] {
            return Err(Error::InvalidField);
        }
        for value in self.digests() {
            hex_bytes(value, 48)?;
        }
        identifier(&self.task.container_id)?;
        if self.mount_id == 0
            || self.mount_id > i64::MAX as u64
            || self.task.generation == 0
            || self.task.pid == 0
            || self.task.pid > i32::MAX as u32
            || self.task.process_start_time_ticks == 0
        {
            return Err(Error::InvalidField);
        }
        Ok(())
    }

    /// Purpose/version-separated ordered length framing. Fixed digests are
    /// framed as decoded bytes and integers as fixed-width big-endian bytes.
    /// JSON whitespace, escapes and object field order cannot alter this hash.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = transcript(b"exec-committed-record", self.version);
        for value in [&self.purpose, &self.profile, &self.claim] {
            frame(&mut out, value.as_bytes());
        }
        frame(&mut out, &hex_bytes(&self.event_id, 32)?);
        for value in self.digests() {
            frame(&mut out, &hex_bytes(value, 48)?);
        }
        frame(&mut out, &self.mount_id.to_be_bytes());
        frame(&mut out, self.task.container_id.as_bytes());
        frame(&mut out, &self.task.generation.to_be_bytes());
        frame(&mut out, &self.task.pid.to_be_bytes());
        frame(&mut out, &self.task.process_start_time_ticks.to_be_bytes());
        Ok(out)
    }

    pub fn sha384(&self) -> Result<[u8; 48], Error> {
        Ok(digest::digest(&digest::SHA384, &self.canonical_bytes()?)
            .as_ref()
            .try_into()
            .expect("SHA-384 output has 48 bytes"))
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Malformed)?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }

    /// Public data only. A decoded record cannot recreate the runtime's
    /// non-deserializable captured-record owner, lease or observed task.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(Error::TooLarge);
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        record.validate()?;
        Ok(record)
    }

    fn digests(&self) -> [&str; 8] {
        [
            &self.grant_sha384,
            &self.admission_context_sha384,
            &self.preparation_record_sha384,
            &self.startup_binding_sha384,
            &self.candidate_spec_sha384,
            &self.final_spec_sha384,
            &self.image_sha384,
            &self.executable_sha384,
        ]
    }
}

#[cfg(test)]
mod tests;

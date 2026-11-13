//! Private control messages for the measured early sandbox process.
use crate::{
    gcp_startup::EmbeddedRole,
    startup::{
        launch_kata_role, LaunchedRole, PinnedRoleExecutable, RoleCommand, StartupBoundChannel,
        StartupError,
    },
};
use serde::{Deserialize, Serialize};
use std::{fs::File, time::Duration};

pub const SOCKET: &str = "/run/onb17/kata-sandbox.sock";
pub const ARGUMENT: &str = "--gcp-sandbox-gateway";

/// Bind carries exactly one sealed public FD containing the signed plan's
/// effective spec. The other commands carry no descriptors.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ParentCommand {
    Bind {
        container_id: String,
        image_ref: String,
    },
    Attach,
    /// Release the application exit after the host acknowledges publication.
    ReleaseExit {},
    Shutdown,
}

/// Candidate is an observation of host input. Only the authenticated parent's
/// subsequent Bind and the protected app endpoint can authorize forwarding.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChildEvent {
    Ready,
    Candidate {
        container_id: String,
        wire_sha384: String,
    },
    Bound,
    Attached,
}

pub fn launch(
    embedded: &EmbeddedRole,
) -> Result<(StartupBoundChannel, LaunchedRole), StartupError> {
    if !embedded.sandbox_gateway_enabled() {
        return Err(StartupError::InvalidArguments);
    }
    let startup = embedded.expected_startup();
    if startup.role != crate::startup::Role::Preparation {
        return Err(StartupError::InvalidArguments);
    }
    let executable = PinnedRoleExecutable::new(
        File::open(&embedded.config().kata_agent_path)
            .map_err(|_| StartupError::InvalidExecutable)?,
        startup.peer_executable_sha384,
        256 << 20,
    )?;
    let command = RoleCommand::new(executable, vec![ARGUMENT.into()])?;
    launch_kata_role(
        command,
        startup.own_executable_sha384,
        256 << 20,
        startup.boot_config_sha384,
        Duration::from_secs(30),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_exit_control_has_only_its_kind() {
        let wire = serde_json::to_vec(&ParentCommand::ReleaseExit {}).unwrap();
        assert_eq!(wire, br#"{"kind":"release_exit"}"#);
        assert!(matches!(
            serde_json::from_slice(&wire).unwrap(),
            ParentCommand::ReleaseExit {}
        ));
        assert!(serde_json::from_slice::<ParentCommand>(
            br#"{"kind":"release_exit","container_id":"other"}"#
        )
        .is_err());
    }
}

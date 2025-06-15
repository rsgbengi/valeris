pub mod user;
pub mod mounts;
pub mod ports;
pub mod privileged;
pub mod capabilities;
pub mod network;
pub mod pid_mode;
pub mod readonly;
pub mod securityopt;
pub mod resource_limits;
pub mod ipc_mode;
pub mod uts_mode;
pub mod userns;
pub mod pids_limit;




use super::ValerisPlugin;

pub fn get_docker_plugins() -> Vec<Box<dyn ValerisPlugin>> {
    vec![
        Box::new(user::UserPlugin),
        Box::new(network::NetworkPlugin),
        Box::new(mounts::MountPlugin),
        Box::new(ports::PortPlugin),
        Box::new(capabilities::CapabilitiesPlugin),
        Box::new(pid_mode::PidModePlugin),
        Box::new(ipc_mode::IpcModePlugin),
        Box::new(uts_mode::UtsModePlugin),
        Box::new(privileged::PrivilegedPlugin),
        Box::new(readonly::ReadOnlyRootFSPlugin),
        Box::new(securityopt::SecurityOptPlugin),
        Box::new(resource_limits::ResourceLimitsPlugin),
        Box::new(userns::UserNamespacePlugin),
        Box::new(pids_limit::PidsLimitPlugin),
    ]
}


use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct IpcModePlugin;

impl ValerisPlugin for IpcModePlugin {
    fn id(&self) -> &str {
        "ipc_mode"
    }

    fn name(&self) -> &str {
        "Host IPC Mode Checker"
    }

    fn description(&self) -> &str {
        "Checks if the Docker container is sharing the host IPC namespace."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let is_host_ipc = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.ipc_mode.as_deref()) == Some("host");

        if is_host_ipc {
            vec![Finding {
                kind: "IPC Mode".to_string(),
                description: "Container is using host IPC mode".to_string(),
                risk: RiskLevel::Medium,
            }]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::RiskLevel;
    use bollard::models::{ContainerInspectResponse, HostConfig};

    #[test]
    fn detects_host_ipc_mode() {
        let host_config = HostConfig {
            ipc_mode: Some("host".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = IpcModePlugin;
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Medium);
        assert!(findings[0].description.contains("host IPC mode"));
    }

    #[test]
    fn ignores_non_host_ipc_mode() {
        let host_config = HostConfig {
            ipc_mode: Some("private".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = IpcModePlugin;
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }
}

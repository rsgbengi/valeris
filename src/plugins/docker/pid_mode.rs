use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct PidModePlugin;
impl ValerisPlugin for PidModePlugin {
    fn id(&self) -> &str {
        "pid_mode"
    }

    fn name(&self) -> &str {
        "Host PID Mode Checker"
    }

    fn description(&self) -> &str {
        "Checks if the Docker container is using the host PID namespace, which may expose process information and allow process-level attacks."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let pid_mode = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.pid_mode.as_deref())
            == Some("host");

        if pid_mode {
            vec![Finding {
                kind: "PID Mode".to_string(),
                description: "Container is using host PID mode".to_string(),
                risk: RiskLevel::Informative,
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
    fn detects_host_pid_mode() {
        // Simula un contenedor con pid_mode = "host"
        let host_config = HostConfig {
            pid_mode: Some("host".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = PidModePlugin;
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Informative);
        assert!(findings[0].description.contains("host PID mode"));
    }

    #[test]
    fn ignores_non_host_pid_mode() {
        // Simula un contenedor con pid_mode distinto
        let host_config = HostConfig {
            pid_mode: Some("private".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = PidModePlugin;
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }
}

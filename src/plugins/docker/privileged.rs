use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct PrivilegedPlugin;
impl ValerisPlugin for PrivilegedPlugin {
    fn id(&self) -> &str {
        "privileged_mode"
    }

    fn name(&self) -> &str {
        "Privileged Mode Checker"
    }

    fn description(&self) -> &str {
        "Detects if a Docker container is running in privileged mode, which grants extended host access and poses a significant security risk."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let privileged = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.privileged)
            .unwrap_or(false);

        if privileged {
            vec![Finding {
                kind: "Privileged".to_string(),
                description: "Container is running in privileged mode".to_string(),
                risk: RiskLevel::High,
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
    fn detects_privileged_mode() {
        let host_config = HostConfig {
            privileged: Some(true),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = PrivilegedPlugin;
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::High);
        assert!(findings[0].description.contains("privileged mode"));
    }

    #[test]
    fn ignores_non_privileged_mode() {
        let host_config = HostConfig {
            privileged: Some(false),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = PrivilegedPlugin;
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_missing_privileged_field() {
        let host_config = HostConfig {
            privileged: None,
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = PrivilegedPlugin;
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }
}

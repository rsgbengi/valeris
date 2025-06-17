use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct UserNamespacePlugin;

impl ValerisPlugin for UserNamespacePlugin {
    fn id(&self) -> &str {
        "user_namespace"
    }

    fn name(&self) -> &str {
        "User Namespace Mode Checker"
    }

    fn description(&self) -> &str {
        "Detects if a Docker container is running without user namespaces or with host user namespace mode, which increases the impact of a container compromise."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let userns_mode = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.userns_mode.as_deref());

        if userns_mode.is_none() || userns_mode == Some("host") {
            return vec![Finding {
                kind: "User Namespace".to_string(),
                description: "Container is running without user namespaces".to_string(),
                risk: RiskLevel::High,
            }];
        }

        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::RiskLevel;
    use bollard::models::{ContainerInspectResponse, HostConfig};

    #[test]
    fn detects_absent_userns_mode() {
        let host_config = HostConfig {
            userns_mode: None,
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let plugin = UserNamespacePlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::High);
    }

    #[test]
    fn detects_host_userns_mode() {
        let host_config = HostConfig {
            userns_mode: Some("host".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let plugin = UserNamespacePlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::High);
    }

    #[test]
    fn ignores_non_host_userns_mode() {
        let host_config = HostConfig {
            userns_mode: Some("private".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let plugin = UserNamespacePlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }
}

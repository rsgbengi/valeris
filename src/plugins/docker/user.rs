use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct UserPlugin;
impl ValerisPlugin for UserPlugin {
    fn id(&self) -> &str {
        "root_user"
    }

    fn name(&self) -> &str {
        "Root User Checker"
    }

    fn description(&self) -> &str {
        "Detects if the Docker container is running as the root user, which increases the impact of a container compromise."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let user = container
            .config
            .as_ref()
            .and_then(|c| c.user.as_deref()).filter(|u| !u.trim().is_empty())
            .unwrap_or("root");

        if user == "root" || user == "0" {
            vec![Finding {
                kind: "User".to_string(),
                description: "Container is running as root".to_string(),
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
    use crate::docker::model::{RiskLevel};
    use bollard::models::{ContainerInspectResponse, ContainerConfig};

    #[test]
    fn detects_root_user_by_default() {
        let config = ContainerConfig {
            user: None,
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            config: Some(config),
            ..Default::default()
        };

        let plugin = UserPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::High);
        assert!(findings[0].description.contains("running as root"));
    }

    #[test]
    fn detects_explicit_root_user() {
        // Campo user = "root"
        let config = ContainerConfig {
            user: Some("root".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            config: Some(config),
            ..Default::default()
        };

        let plugin = UserPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detects_root_by_uid_zero() {
        let config = ContainerConfig {
            user: Some("0".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            config: Some(config),
            ..Default::default()
        };

        let plugin = UserPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_non_root_user() {
        let config = ContainerConfig {
            user: Some("appuser".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            config: Some(config),
            ..Default::default()
        };

        let plugin = UserPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_empty_user_string() {
        let config = ContainerConfig {
            user: Some("   ".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            config: Some(config),
            ..Default::default()
        };

        let plugin = UserPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
    }
}


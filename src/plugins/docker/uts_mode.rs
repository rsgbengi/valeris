use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct UtsModePlugin;

impl ValerisPlugin for UtsModePlugin {
    fn id(&self) -> &str {
        "uts_mode"
    }

    fn name(&self) -> &str {
        "Host UTS Mode Checker"
    }

    fn description(&self) -> &str {
        "Checks if the Docker container shares the host UTS namespace."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let is_host_uts = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.uts_mode.as_deref()) == Some("host");

        if is_host_uts {
            vec![Finding {
                kind: "UTS Mode".to_string(),
                description: "Container is using host UTS mode".to_string(),
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
    fn detects_host_uts_mode() {
        let host_config = HostConfig {
            uts_mode: Some("host".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = UtsModePlugin;
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Medium);
        assert!(findings[0].description.contains("host UTS mode"));
    }

    #[test]
    fn ignores_non_host_uts_mode() {
        let host_config = HostConfig {
            uts_mode: Some("private".to_string()),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = UtsModePlugin;
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }
}
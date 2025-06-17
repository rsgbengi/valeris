use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct PidsLimitPlugin;

impl ValerisPlugin for PidsLimitPlugin {
    fn id(&self) -> &str {
        "pids_limit"
    }

    fn name(&self) -> &str {
        "PIDs Limit Checker"
    }

    fn description(&self) -> &str {
        "Ensures a maximum number of processes is configured for Docker containers to mitigate resource exhaustion attacks."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let host_config = match container.host_config.as_ref() {
            Some(cfg) => cfg,
            None => {
                return vec![Finding {
                    kind: "PIDs Limit".to_string(),
                    description: "PIDs limit not set".to_string(),
                    risk: RiskLevel::Medium,
                }];
            }
        };

        let has_limit = host_config.pids_limit.filter(|&l| l > 0).is_some()
            || host_config
                .ulimits
                .as_ref()
                .map(|ul| {
                    ul.iter().any(|u| {
                        let name = u.name.as_deref().unwrap_or("");
                        (name == "nproc" || name == "pids")
                            && (u.soft.unwrap_or(0) > 0 || u.hard.unwrap_or(0) > 0)
                    })
                })
                .unwrap_or(false);

        if has_limit {
            vec![]
        } else {
            vec![Finding {
                kind: "PIDs Limit".to_string(),
                description: "PIDs limit not set".to_string(),
                risk: RiskLevel::Medium,
            }]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::RiskLevel;
    use bollard::models::{ContainerInspectResponse, HostConfig, ResourcesUlimits};

    #[test]
    fn detects_missing_limits() {
        let container = ContainerInspectResponse {
            host_config: Some(HostConfig::default()),
            ..Default::default()
        };
        let plugin = PidsLimitPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Medium);
    }

    #[test]
    fn ignores_configured_limits() {
        let ulimits = vec![ResourcesUlimits {
            name: Some("nproc".to_string()),
            soft: Some(100),
            hard: Some(200),
        }];
        let host_config = HostConfig {
            pids_limit: Some(100),
            ulimits: Some(ulimits),
            ..Default::default()
        };
        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };
        let plugin = PidsLimitPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }
}

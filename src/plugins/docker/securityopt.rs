use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct SecurityOptPlugin;
impl ValerisPlugin for SecurityOptPlugin {
    fn id(&self) -> &str {
        "security_options"
    }

    fn name(&self) -> &str {
        "Security Options Analyzer"
    }

    fn description(&self) -> &str {
        "Analyzes Docker container security options, highlighting dangerous configurations like 'unconfined' AppArmor or seccomp profiles."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let mut findings = Vec::new();
        let security_opts = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.security_opt.as_ref());

        if let Some(options) = security_opts {
            for opt in options {
                findings.push(Finding {
                    kind: "Security Option".to_string(),
                    description: format!("Security option: {}", opt),
                    risk: if opt.contains("unconfined") {
                        RiskLevel::High
                    } else {
                        RiskLevel::Informative
                    },
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::RiskLevel;
    use bollard::models::{ContainerInspectResponse, HostConfig};

    #[test]
    fn detects_unconfined_security_options() {
        let host_config = HostConfig {
            security_opt: Some(vec![
                "apparmor=unconfined".to_string(),
                "seccomp=default".to_string(),
            ]),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let plugin = SecurityOptPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 2);

        assert!(findings
            .iter()
            .any(|f| f.risk == RiskLevel::High && f.description.contains("unconfined")));
        assert!(findings
            .iter()
            .any(|f| f.risk == RiskLevel::Informative && f.description.contains("seccomp")));
    }

    #[test]
    fn ignores_missing_security_options() {
        let host_config = HostConfig {
            security_opt: None,
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let plugin = SecurityOptPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }

    #[test]
    fn handles_empty_security_opt_vector() {
        let host_config = HostConfig {
            security_opt: Some(vec![]),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let plugin = SecurityOptPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }
}

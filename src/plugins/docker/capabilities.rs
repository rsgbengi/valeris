use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct CapabilitiesPlugin;

impl ValerisPlugin for CapabilitiesPlugin {
    fn id(&self) -> &str {
        "capabilities"
    }

    fn description(&self) -> &str {
        "Checks for added Linux capabilities in Docker containers, highlighting potentially dangerous ones like SYS_ADMIN or NET_ADMIN."
    }

    fn name(&self) -> &str {
        "Linux Capabilities Checker"
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;
        let mut findings = Vec::new();

        let cap_add = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.cap_add.as_ref());

        if let Some(capabilities) = cap_add {
            let high_risk = ["SYS_ADMIN", "ALL", "NET_ADMIN", "SYS_MODULE", "SYS_PTRACE"];

            let medium_risk = [
                "SYS_TIME",
                "MKNOD",
                "CHOWN",
                "FOWNER",
                "DAC_OVERRIDE",
                "AUDIT_WRITE",
                "KILL",
            ];

            for cap in capabilities {
                let cap_upper = cap.to_uppercase();

                let risk = if high_risk.contains(&cap_upper.as_str()) {
                    RiskLevel::High
                } else if medium_risk.contains(&cap_upper.as_str()) {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                };

                findings.push(Finding {
                    kind: "Capabilities".into(),
                    description: format!("Capability '{}' added", cap),
                    risk,
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::{RiskLevel};
    use bollard::models::{ContainerInspectResponse, HostConfig};

    #[test]
    fn detects_dangerous_capabilities() {
        let host_config = HostConfig {
            cap_add: Some(vec![
                "SYS_ADMIN".to_string(),
                "CHOWN".to_string(),
                "FOO".to_string(),
            ]),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = CapabilitiesPlugin;
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 3);
        assert!(findings.iter().any(|f| f.risk == RiskLevel::High && f.description.contains("SYS_ADMIN")));
        assert!(findings.iter().any(|f| f.risk == RiskLevel::Medium && f.description.contains("CHOWN")));
        assert!(findings.iter().any(|f| f.risk == RiskLevel::Low && f.description.contains("FOO")));
    }
}

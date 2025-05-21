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

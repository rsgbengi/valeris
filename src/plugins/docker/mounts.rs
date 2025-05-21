use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

const DANGEROUS_PATHS: [&str; 5] = ["/var/run/docker.sock", "/proc", "/sys", "/etc", "/root"];

pub struct MountPlugin;
impl ValerisPlugin for MountPlugin {
    fn id(&self) -> &str {
        "mounts"
    }

    fn name(&self) -> &str {
        "Sensitive Mounts Checker"
    }

    fn description(&self) -> &str {
        "Detects mounted host paths in Docker containers, flagging high-risk directories like /proc or /var/run/docker.sock that may expose the host."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let mut findings = Vec::new();

        if let Some(mounts) = &container.mounts {
            for mount in mounts {
                let source = mount.source.as_deref().unwrap_or("");
                let destination = mount.destination.as_deref().unwrap_or("");

                let is_dangerous = DANGEROUS_PATHS.iter().any(|p| source.starts_with(p));

                findings.push(Finding {
                    kind: "Mount".into(),
                    description: format!("{} → {}", source, destination),
                    risk: if is_dangerous {
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

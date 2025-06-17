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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::RiskLevel;
    use bollard::models::{ContainerInspectResponse, MountPoint};

    #[test]
    fn detects_sensitive_mounts() {
        let mounts = vec![
            MountPoint {
                source: Some("/var/run/docker.sock".to_string()),
                destination: Some("/sock".to_string()),
                ..Default::default()
            },
            MountPoint {
                source: Some("/data".to_string()),
                destination: Some("/app/data".to_string()),
                ..Default::default()
            },
        ];

        let container = ContainerInspectResponse {
            mounts: Some(mounts),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = MountPlugin;
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 2);

        assert!(findings
            .iter()
            .any(|f| f.risk == RiskLevel::High && f.description.contains("/var/run/docker.sock")));
        assert!(findings
            .iter()
            .any(|f| f.risk == RiskLevel::Informative && f.description.contains("/data")));
    }
}

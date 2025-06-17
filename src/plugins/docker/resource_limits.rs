use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct ResourceLimitsPlugin;

impl ValerisPlugin for ResourceLimitsPlugin {
    fn id(&self) -> &str {
        "resource_limits"
    }

    fn name(&self) -> &str {
        "Resource Limits Checker"
    }

    fn description(&self) -> &str {
        "Detects containers running without configured memory or CPU limits."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;
        let mut findings = Vec::new();

        let (mut memory_set, mut cpu_set) = (false, false);

        if let Some(hc) = container.host_config.as_ref() {
            if hc.memory.unwrap_or(0) > 0 {
                memory_set = true;
            }

            let nano_cpus = hc.nano_cpus.unwrap_or(0);
            let cpu_shares = hc.cpu_shares.unwrap_or(0);
            if nano_cpus > 0 || cpu_shares > 0 {
                cpu_set = true;
            }
        }

        if !memory_set {
            findings.push(Finding {
                kind: "ResourceLimits".to_string(),
                description: "Memory limit not set".to_string(),
                risk: RiskLevel::Medium,
            });
        }

        if !cpu_set {
            findings.push(Finding {
                kind: "ResourceLimits".to_string(),
                description: "CPU limit not set".to_string(),
                risk: RiskLevel::Medium,
            });
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
    fn detects_missing_limits() {
        let host_config = HostConfig {
            memory: None,
            nano_cpus: None,
            cpu_shares: None,
            ..Default::default()
        };
        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };
        let plugin = ResourceLimitsPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.risk == RiskLevel::Medium));
    }

    #[test]
    fn ignores_when_limits_set() {
        let host_config = HostConfig {
            memory: Some(64 * 1024 * 1024),
            nano_cpus: Some(1_000_000_000),
            cpu_shares: Some(1024),
            ..Default::default()
        };
        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };
        let plugin = ResourceLimitsPlugin;
        let input = ScanInput::DockerContainer(container);
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }
}

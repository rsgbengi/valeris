use bollard::secret::RestartPolicyNameEnum;

use crate::plugins::{PluginTarget, ScanInput, ValerisPlugin};


use crate::docker::model::{Finding, RiskLevel};

pub struct RestartPolicyPlugin;

impl ValerisPlugin for RestartPolicyPlugin {
    fn id(&self) -> &str {
        "restart_policy"
    }

    fn name(&self) -> &str {
        "Restart Policy Checker"
    }

    fn description(&self) -> &str {
        "Checks the Docker container's restart policy configuration to assess resilience and identify missing or unusual settings."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Both
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let policy_name = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.restart_policy.as_ref())
            .and_then(|rp| rp.name.as_ref());

        let (risk, description): (RiskLevel, String) = match policy_name {
            Some(RestartPolicyNameEnum::ALWAYS) => (
                RiskLevel::Low,
                "Restart policy is set to 'always' (recommended for production)".to_string(),
            ),
            Some(RestartPolicyNameEnum::ON_FAILURE) => (
                RiskLevel::Informative,
                "Restart policy is set to 'on-failure'".to_string(),
            ),
            Some(RestartPolicyNameEnum::UNLESS_STOPPED) => (
                RiskLevel::Informative,
                "Restart policy is set to 'unless-stopped'".to_string(),
            ),
            Some(RestartPolicyNameEnum::NO) => (
                RiskLevel::Informative,
                "Restart policy is set to 'no' — container won't auto-restart".to_string(),
            ),

            Some(other) => {
                let description = format!("Unusual restart policy: '{:?}'", other);
                (RiskLevel::Medium, description)
            }
            None => (
                RiskLevel::Medium,
                "No restart policy defined — container won't auto-recover".to_string(),
            ),
        };

        vec![Finding {
            kind: "RestartPolicy".into(),
            description: description.to_string(),
            risk,
        }]
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::{RiskLevel};
    use bollard::models::{ContainerInspectResponse, HostConfig, RestartPolicy};
    use bollard::secret::RestartPolicyNameEnum;

    fn make_container_with_policy(policy: Option<RestartPolicyNameEnum>) -> ContainerInspectResponse {
        let restart_policy = RestartPolicy {
            name: policy,
            ..Default::default()
        };

        let host_config = HostConfig {
            restart_policy: Some(restart_policy),
            ..Default::default()
        };

        ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        }
    }

    #[test]
    fn detects_always_restart_policy() {
        let container = make_container_with_policy(Some(RestartPolicyNameEnum::ALWAYS));
        let plugin = RestartPolicyPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Low);
        assert!(findings[0].description.contains("always"));
    }

    #[test]
    fn detects_on_failure_restart_policy() {
        let container = make_container_with_policy(Some(RestartPolicyNameEnum::ON_FAILURE));
        let plugin = RestartPolicyPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Informative);
        assert!(findings[0].description.contains("on-failure"));
    }

    #[test]
    fn detects_unless_stopped_restart_policy() {
        let container = make_container_with_policy(Some(RestartPolicyNameEnum::UNLESS_STOPPED));
        let plugin = RestartPolicyPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Informative);
        assert!(findings[0].description.contains("unless-stopped"));
    }

    #[test]
    fn detects_no_restart_policy() {
        let container = make_container_with_policy(Some(RestartPolicyNameEnum::NO));
        let plugin = RestartPolicyPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Informative);
        assert!(findings[0].description.contains("no"));
    }

    #[test]
    fn detects_missing_restart_policy() {
        let container = make_container_with_policy(None);
        let plugin = RestartPolicyPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Medium);
        assert!(findings[0].description.contains("No restart policy defined"));
    }
}


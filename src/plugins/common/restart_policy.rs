use bollard::secret::RestartPolicyNameEnum;

use super::super::{PluginTarget, ScanInput, ValerisPlugin};
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

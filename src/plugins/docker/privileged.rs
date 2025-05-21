use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct PrivilegedPlugin;
impl ValerisPlugin for PrivilegedPlugin {
    fn id(&self) -> &str {
        "privileged_mode"
    }

    fn name(&self) -> &str {
        "Privileged Mode Checker"
    }

    fn description(&self) -> &str {
        "Detects if a Docker container is running in privileged mode, which grants extended host access and poses a significant security risk."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let privileged = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.privileged)
            .unwrap_or(false);

        if privileged {
            vec![Finding {
                kind: "Privileged".to_string(),
                description: "Container is running in privileged mode".to_string(),
                risk: RiskLevel::High,
            }]
        } else {
            vec![]
        }
    }
}

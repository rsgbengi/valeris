use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct NetworkPlugin;

impl ValerisPlugin for NetworkPlugin {
    fn id(&self) -> &str {
        "network"
    }

    fn name(&self) -> &str {
        "Host Network Mode Checker"
    }

    fn description(&self) -> &str {
        "Detects if a Docker container is using the host network mode, which can lead to network isolation bypass and security risks."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;
        let is_host_network = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.network_mode.as_deref())
            .map_or(false, |nm| nm == "host");

        if is_host_network {
            vec![Finding {
                kind: "Network".to_string(),
                description: "Container is using host network mode".to_string(),
                risk: RiskLevel::High,
            }]
        } else {
            vec![]
        }
    }
}

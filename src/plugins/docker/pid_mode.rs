use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct PidModePlugin;
impl ValerisPlugin for PidModePlugin {
    fn id(&self) -> &str {
        "pid_mode"
    }

    fn name(&self) -> &str {
        "Host PID Mode Checker"
    }

    fn description(&self) -> &str {
        "Checks if the Docker container is using the host PID namespace, which may expose process information and allow process-level attacks."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let pid_mode = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.pid_mode.as_deref())
            .map_or(false, |pm| pm == "host");

        if pid_mode {
            vec![Finding {
                kind: "PID Mode".to_string(),
                description: "Container is using host PID mode".to_string(),
                risk: RiskLevel::Informative,
            }]
        } else {
            vec![]
        }
    }
}

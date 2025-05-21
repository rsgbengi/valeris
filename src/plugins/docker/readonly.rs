use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct ReadOnlyRootFSPlugin;
impl ValerisPlugin for ReadOnlyRootFSPlugin {
    fn id(&self) -> &str {
        "readonly_rootfs"
    }

    fn name(&self) -> &str {
        "Read-Only Root Filesystem Checker"
    }

    fn description(&self) -> &str {
        "Checks if the Docker container is using a read-only root filesystem, which helps reduce the impact of container compromise by preventing writes."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let read_only = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.readonly_rootfs)
            .unwrap_or(false);
        if read_only {
            vec![Finding {
                kind: "Read-Only".to_string(),
                description: "Container is running in read-only mode".to_string(),
                risk: RiskLevel::Informative,
            }]
        } else {
            vec![]
        }
    }
}

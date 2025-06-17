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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::RiskLevel;
    use bollard::models::{ContainerInspectResponse, HostConfig};

    #[test]
    fn detects_readonly_rootfs_enabled() {
        let host_config = HostConfig {
            readonly_rootfs: Some(true),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = ReadOnlyRootFSPlugin;
        let findings = plugin.run(&input);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::Informative);
        assert!(findings[0].description.contains("read-only mode"));
    }

    #[test]
    fn ignores_readonly_rootfs_disabled() {
        let host_config = HostConfig {
            readonly_rootfs: Some(false),
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = ReadOnlyRootFSPlugin;
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_missing_readonly_rootfs_field() {
        let host_config = HostConfig {
            readonly_rootfs: None,
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            host_config: Some(host_config),
            ..Default::default()
        };

        let input = ScanInput::DockerContainer(container);
        let plugin = ReadOnlyRootFSPlugin;
        let findings = plugin.run(&input);

        assert!(findings.is_empty());
    }
}

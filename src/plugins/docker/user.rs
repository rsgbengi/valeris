use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct UserPlugin;
impl ValerisPlugin for UserPlugin {
    fn id(&self) -> &str {
        "root_user"
    }

    fn name(&self) -> &str {
        "Root User Checker"
    }

    fn description(&self) -> &str {
        "Detects if the Docker container is running as the root user, which increases the impact of a container compromise."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let user = container
            .config
            .as_ref()
            .and_then(|c| c.user.as_deref()).filter(|u| !u.trim().is_empty())
            .unwrap_or("root");

        if user == "root" || user == "0" {
            vec![Finding {
                kind: "User".to_string(),
                description: "Container is running as root".to_string(),
                risk: RiskLevel::High,
            }]
        } else {
            vec![]
        }
    }
}

use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct SecurityOptPlugin;
impl ValerisPlugin for SecurityOptPlugin {
    fn id(&self) -> &str {
        "security_options"
    }

    fn name(&self) -> &str {
        "Security Options Analyzer"
    }

    fn description(&self) -> &str {
        "Analyzes Docker container security options, highlighting dangerous configurations like 'unconfined' AppArmor or seccomp profiles."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let mut findings = Vec::new();
        let security_opts = container
            .host_config
            .as_ref()
            .and_then(|hc| hc.security_opt.as_ref());

        if let Some(options) = security_opts {
            for opt in options {
                findings.push(Finding {
                    kind: "Security Option".to_string(),
                    description: format!("Security option: {}", opt),
                    risk: if opt.contains("unconfined") {
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

use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};
use std::collections::HashSet;

pub struct PortPlugin;

impl ValerisPlugin for PortPlugin {
    fn id(&self) -> &str {
        "exposed_ports"
    }

    fn name(&self) -> &str {
        "Exposed Ports Analyzer"
    }

    fn description(&self) -> &str {
        "Identifies exposed ports in Docker containers and highlights those bound to all interfaces (0.0.0.0 or ::), which can pose external attack risks."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Docker
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;

        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        if let Some(ports) = container
            .network_settings
            .as_ref()
            .and_then(|ns| ns.ports.as_ref())
        {
            for (port_proto, bindings) in ports {
                if let Some(bindings_vec) = bindings {
                    for binding in bindings_vec {
                        let host_port = binding.host_port.as_deref().unwrap_or("");
                        let key = format!("{}:{}", port_proto, host_port);

                        if seen.contains(&key) {
                            continue;
                        }
                        seen.insert(key);

                        let host_ip = binding.host_ip.as_deref().unwrap_or("");
                        let risk = if host_ip == "0.0.0.0" || host_ip == "::" {
                            RiskLevel::High
                        } else {
                            RiskLevel::Medium
                        };

                        findings.push(Finding {
                            kind: "Port".into(),
                            description: format!(
                                "Exposed port: {} → {}:{}",
                                port_proto, host_ip, host_port
                            ),
                            risk,
                        });
                    }
                } else {
                    findings.push(Finding {
                        kind: "Port".into(),
                        description: format!("Port {} exposed internally", port_proto),
                        risk: RiskLevel::Informative,
                    });
                }
            }
        }

        findings
    }
}

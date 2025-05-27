use super::super::{PluginTarget, ScanInput, ValerisPlugin};
use crate::docker::model::{Finding, RiskLevel};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::ScanInput;
    use bollard::models::{ContainerInspectResponse, NetworkSettings, PortBinding};
    use std::collections::HashMap;

    fn mock_container_with_exposed_port() -> ContainerInspectResponse {
        let mut bindings = HashMap::new();
        bindings.insert(
            "80/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some("8080".to_string()),
            }]),
        );

        let network_settings = NetworkSettings {
            ports: Some(bindings),
            ..Default::default()
        };

        ContainerInspectResponse {
            network_settings: Some(network_settings),
            ..Default::default()
        }
    }

    #[test]
    fn detects_exposed_ports() {
        let plugin = PortPlugin;
        let input = ScanInput::DockerContainer(mock_container_with_exposed_port());
        let findings = plugin.run(&input);

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.risk == RiskLevel::High));
    }
}

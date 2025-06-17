use super::ValerisPlugin;
use crate::docker::model::{Finding, RiskLevel};
use crate::plugins::{PluginTarget, ScanInput};

pub struct SecretsPlugin;

fn is_sensitive_key(key: &str) -> bool {
    [
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "DB_PASSWORD",
        "DB_PASS",
        "DB_USER",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GCP_KEY",
        "JWT_SECRET",
    ]
    .iter()
    .any(|sensitive| key.contains(sensitive))
}

impl ValerisPlugin for SecretsPlugin {
    fn id(&self) -> &str {
        "secrets_in_env"
    }

    fn name(&self) -> &str {
        "Sensitive Environment Variables Checker"
    }

    fn description(&self) -> &str {
        "Scans container environment variables for hardcoded secrets such as passwords, tokens, or API keys, which pose a serious security risk."
    }

    fn target(&self) -> PluginTarget {
        PluginTarget::Both
    }

    fn run(&self, input: &ScanInput) -> Vec<Finding> {
        let ScanInput::DockerContainer(container) = input;
        let mut findings = Vec::new();

        let env_vars = container.config.as_ref().and_then(|cfg| cfg.env.as_ref());

        if let Some(envs) = env_vars {
            for var in envs {
                if let Some((key, value)) = var.split_once('=') {
                    let key_upper = key.to_uppercase();

                    if is_sensitive_key(&key_upper) {
                        findings.push(Finding {
                            kind: "Environment".into(),
                            description: format!(
                                "Sensitive variable detected: {} = {}",
                                key, value
                            ),
                            risk: RiskLevel::High,
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::RiskLevel;
    use bollard::models::{ContainerConfig, ContainerInspectResponse};

    fn make_container_with_env(envs: Vec<&str>) -> ContainerInspectResponse {
        let config = ContainerConfig {
            env: Some(envs.into_iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };

        ContainerInspectResponse {
            config: Some(config),
            ..Default::default()
        }
    }

    #[test]
    fn detects_sensitive_env_vars() {
        let container =
            make_container_with_env(vec!["PASSWORD=supersecret", "DB_PASS=123456", "USER=admin"]);

        let plugin = SecretsPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|f| f.description.contains("PASSWORD = supersecret")));
        assert!(findings
            .iter()
            .any(|f| f.description.contains("DB_PASS = 123456")));
        assert!(findings.iter().all(|f| f.risk == RiskLevel::High));
    }

    #[test]
    fn ignores_non_sensitive_env_vars() {
        let container =
            make_container_with_env(vec!["NODE_ENV=production", "USER=admin", "VERSION=1.0.0"]);

        let plugin = SecretsPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert!(findings.is_empty());
    }

    #[test]
    fn handles_missing_env_list() {
        let config = ContainerConfig {
            env: None,
            ..Default::default()
        };

        let container = ContainerInspectResponse {
            config: Some(config),
            ..Default::default()
        };

        let plugin = SecretsPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_malformed_env_vars() {
        let container = make_container_with_env(vec!["INVALID_ENV_FORMAT", "ALSO_BAD"]);

        let plugin = SecretsPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert!(findings.is_empty());
    }

    #[test]
    fn detects_sensitive_env_vars_lowercase_key() {
        let container = make_container_with_env(vec!["password=abc"]);

        let plugin = SecretsPlugin;
        let findings = plugin.run(&ScanInput::DockerContainer(container));

        assert_eq!(findings.len(), 1);
        assert!(findings
            .iter()
            .any(|f| f.description.contains("password = abc")));
        assert!(findings.iter().all(|f| f.risk == RiskLevel::High));
    }
}

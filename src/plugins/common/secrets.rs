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

use std::collections::HashSet;

use anyhow::{bail, Result};
use bollard::models::ContainerInspectResponse;

use crate::docker::model::{ContainerResult, Finding};
use crate::plugins::{load_plugins_for_target, PluginTarget, ScanInput};

pub async fn scan_with_plugins_on_containers(
    containers: Vec<ContainerInspectResponse>,
    target: PluginTarget,
    only: Option<String>,
    exclude: Option<String>,
) -> Result<Vec<ContainerResult>> {
    let plugins = load_plugins_for_target(target);
    let available_ids = collect_plugin_ids(&plugins);
    let only_set = parse_id_set(&only);
    let exclude_set = parse_id_set(&exclude);

    validate_plugin_ids(&available_ids, &only_set, "--only")?;
    validate_plugin_ids(&available_ids, &exclude_set, "--exclude")?;

    let results = containers
        .into_iter()
        .map(|container| {
            let findings = run_plugins_on_container(&container, &plugins, &only_set, &exclude_set);
            ContainerResult { container, findings }
        })
        .collect();

    Ok(results)
}

pub async fn scan_docker_with_plugins(
    target: PluginTarget,
    only: Option<String>,
    exclude: Option<String>,
) -> Result<Vec<ContainerResult>> {
    let containers = get_running_containers().await?;
    scan_with_plugins_on_containers(containers, target, only, exclude).await
}

fn collect_plugin_ids(plugins: &[Box<dyn crate::plugins::ValerisPlugin>]) -> HashSet<String> {
    plugins.iter().map(|p| p.id().to_lowercase()).collect()
}

fn parse_id_set(input: &Option<String>) -> Option<HashSet<String>> {
    input.as_ref().map(|s| {
        s.split(',')
            .map(|id| id.trim().to_lowercase())
            .collect::<HashSet<_>>()
    })
}

fn validate_plugin_ids(
    available: &HashSet<String>,
    provided: &Option<HashSet<String>>,
    flag: &str,
) -> Result<()> {
    if let Some(ids) = provided {
        let unknown: Vec<_> = ids.difference(available).cloned().collect();
        if !unknown.is_empty() {
            let list = unknown.join(", ");
            let plural = if unknown.len() > 1 { "plugins" } else { "plugin" };
            bail!("Unknown {} in {}: {}", plural, flag, list);
        }
    }
    Ok(())
}

fn run_plugins_on_container(
    container: &ContainerInspectResponse,
    plugins: &[Box<dyn crate::plugins::ValerisPlugin>],
    only: &Option<HashSet<String>>,
    exclude: &Option<HashSet<String>>,
) -> Vec<Finding> {
    let input = ScanInput::DockerContainer(container.clone());

    plugins
        .iter()
        .filter(|p| matches!(p.target(), PluginTarget::Docker | PluginTarget::Both))
        .filter(|p| {
            let id = p.id().to_lowercase();
            only.as_ref().is_none_or(|s| s.contains(&id))
                && exclude.as_ref().is_none_or(|s| !s.contains(&id))
        })
        .flat_map(|p| p.run(&input))
        .collect()
}

pub async fn get_running_containers() -> Result<Vec<ContainerInspectResponse>> {
    use bollard::container::{InspectContainerOptions, ListContainersOptions};
    use bollard::Docker;

    let docker = Docker::connect_with_socket_defaults()?;

    let containers = docker
        .list_containers(Some(ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        }))
        .await?;

    let mut result = Vec::new();

    for container in containers {
        if let Some(id) = container.id.as_deref() {
            let inspect = docker
                .inspect_container(id, None::<InspectContainerOptions>)
                .await?;
            result.push(inspect);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_id_set() {
        let input = Some("  foo,Bar ,baz".to_string());
        let set = parse_id_set(&input).unwrap();
        assert!(set.contains("foo"));
        assert!(set.contains("bar"));
        assert!(set.contains("baz"));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn test_parse_id_set_none() {
        let input: Option<String> = None;
        let set = parse_id_set(&input);
        assert!(set.is_none());
    }

    #[test]
    fn test_validate_plugin_ids_all_valid() {
        let available = ["a", "b", "c"].into_iter().map(String::from).collect();
        let provided = Some(["b", "a"].into_iter().map(String::from).collect());
        let result = validate_plugin_ids(&available, &provided, "--only");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_plugin_ids_with_invalid() {
        let available = ["a", "b", "c"].into_iter().map(String::from).collect();
        let provided = Some(["x", "b"].into_iter().map(String::from).collect());
        let result = validate_plugin_ids(&available, &provided, "--only");
        assert!(result.is_err());
    }

    #[test]
    fn test_collect_plugin_ids_extracts_lowercase_ids() {
        struct DummyPlugin(&'static str);
        impl crate::plugins::ValerisPlugin for DummyPlugin {
            fn id(&self) -> &str {
                self.0
            }
            fn name(&self) -> &str {
                self.0
            }
            fn target(&self) -> PluginTarget {
                PluginTarget::Docker
            }
            fn description(&self) -> &str {
                "test"
            }
            fn run(&self, _: &ScanInput) -> Vec<Finding> {
                vec![]
            }
        }

        let plugins: Vec<Box<dyn crate::plugins::ValerisPlugin>> = vec![
            Box::new(DummyPlugin("PortS")),
            Box::new(DummyPlugin("CAPABILITIES")),
        ];

        let ids = collect_plugin_ids(&plugins);
        assert!(ids.contains("ports"));
        assert!(ids.contains("capabilities"));
    }
}

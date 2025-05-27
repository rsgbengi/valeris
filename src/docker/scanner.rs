use std::collections::HashSet;

use anyhow::{bail, Result};
use bollard::{
    container::{InspectContainerOptions, ListContainersOptions},
    models::ContainerInspectResponse,
    Docker,
};

use super::printer::print_container_report;
use crate::plugins::{load_plugins_for_target, PluginTarget, ScanInput};

pub async fn get_running_containers() -> Result<Vec<ContainerInspectResponse>> {
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

pub async fn scan_with_plugins_on_containers(
    containers: Vec<ContainerInspectResponse>,
    target: PluginTarget,
    only: Option<String>,
    exclude: Option<String>,
) -> Result<()> {
    let plugins = load_plugins_for_target(target);

    let available_ids: HashSet<String> = plugins.iter().map(|p| p.id().to_lowercase()).collect();

    let only_set: Option<HashSet<String>> =
        only.map(|s| s.split(',').map(|s| s.trim().to_lowercase()).collect());

    let exclude_set: Option<HashSet<String>> =
        exclude.map(|s| s.split(',').map(|s| s.trim().to_lowercase()).collect());

    if let Some(ref only_ids) = only_set {
        let unknown: Vec<_> = only_ids.difference(&available_ids).cloned().collect();
        if !unknown.is_empty() {
            let list = unknown.join(", ");
            let plural = if unknown.len() > 1 { "plugins" } else { "plugin" };
            bail!("Unknown {} in --only: {}", plural, list);
        }
    }

    if let Some(ref exclude_ids) = exclude_set {
        let unknown: Vec<_> = exclude_ids.difference(&available_ids).cloned().collect();
        if !unknown.is_empty() {
            let list = unknown.join(", ");
            let plural = if unknown.len() > 1 { "plugins" } else { "plugin" };
            bail!("Unknown {} in --exclude: {}", plural, list);
        }
    }

    for container in containers {
        let input = ScanInput::DockerContainer(container.clone());
        let findings: Vec<_> = plugins
            .iter()
            .filter(|p| matches!(p.target(), PluginTarget::Docker | PluginTarget::Both))
            .filter(|p| {
                let id = p.id().to_lowercase();
                only_set.as_ref().map_or(true, |s| s.contains(&id))
                    && exclude_set.as_ref().map_or(true, |s| !s.contains(&id))
            })
            .flat_map(|p| p.run(&input))
            .collect();

        print_container_report(&container, &findings);
    }

    Ok(())
}


pub async fn scan_docker_with_plugins(
    target: PluginTarget,
    only: Option<String>,
    exclude: Option<String>,
) -> Result<()> {
    let containers = get_running_containers().await?;
    scan_with_plugins_on_containers(containers, target, only, exclude).await
}


#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::ContainerInspectResponse;

    #[tokio::test]
    async fn test_scan_with_mock_container_and_valid_plugin() {
        let mock_container = ContainerInspectResponse::default(); // mínimo necesario
        let containers = vec![mock_container];

        let result = scan_with_plugins_on_containers(
            containers,
            PluginTarget::Docker,
            Some("exposed_ports".to_string()),
            None,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_scan_with_invalid_plugin_should_fail() {
        let mock_container = ContainerInspectResponse::default();
        let containers = vec![mock_container];

        let result = scan_with_plugins_on_containers(
            containers,
            PluginTarget::Docker,
            Some("nonexistent_plugin".to_string()),
            None,
        )
        .await;

        assert!(result.is_err());
    }
}





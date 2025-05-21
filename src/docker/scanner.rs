use std::collections::HashSet;

use anyhow::Result;
use bollard::container::{InspectContainerOptions, ListContainersOptions};
use bollard::models::ContainerInspectResponse;
use bollard::Docker;
use crate::plugins::{load_plugins_for_target, ScanInput, PluginTarget};

use super::printer::print_container_report;



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
        let id = container.id.as_deref().unwrap_or_default();
        let inspect = docker
            .inspect_container(id, None::<InspectContainerOptions>)
            .await?;

        result.push(inspect);
    }

    Ok(result)
}


pub async fn scan_docker_with_plugins(
    target: PluginTarget,
    only: Option<String>,
    exclude: Option<String>,
) -> Result<()> {
    let containers = get_running_containers().await?;
    let plugins = load_plugins_for_target(target);

    let only_set: Option<HashSet<String>> = only.map(|s| {
        s.split(',')
            .map(|s| s.trim().to_lowercase())
            .collect()
    });

    let exclude_set: Option<HashSet<String>> = exclude.map(|s| {
        s.split(',')
            .map(|s| s.trim().to_lowercase())
            .collect()
    });

    for container in containers {
        let input = ScanInput::DockerContainer(container.clone());
        let mut findings = Vec::new();

        for plugin in &plugins {
            let plugin_id = plugin.id().to_lowercase();

            if !(plugin.target() == PluginTarget::Docker || plugin.target() == PluginTarget::Both) {
                continue;
            }

            if let Some(ref only_ids) = only_set {
                if !only_ids.contains(&plugin_id) {
                    continue;
                }
            }

            if let Some(ref excluded_ids) = exclude_set {
                if excluded_ids.contains(&plugin_id) {
                    continue;
                }
            }

            findings.extend(plugin.run(&input));
        }

        print_container_report(&container, &findings);
    }

    Ok(())
}






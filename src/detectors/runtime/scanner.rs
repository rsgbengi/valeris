use std::{collections::HashSet, path::PathBuf};

use anyhow::{bail, Context, Result};
use bollard::{
    container::{InspectContainerOptions, ListContainersOptions},
    models::ContainerInspectResponse,
    Docker,
};
use serde_json::to_value;

use crate::{
    docker::model::{ContainerResult, Finding},
};

use crate::YamlRuleEngine;



pub async fn scan_docker_with_yaml_detectors(
    rules_dir: PathBuf,       
    only: Option<String>,
    exclude: Option<String>,
    state: Option<String>,
) -> Result<Vec<ContainerResult>> {
    let engine = YamlRuleEngine::from_dir(&rules_dir)
        .with_context(|| format!("loading YAML detectors from {}", rules_dir.display()))?;

    let state_set = parse_state_set(&state);
    let containers = get_containers(state_set.as_ref())
        .await
        .context("Failed to connect to Docker daemon or list containers")?;

    let rule_ids = collect_rule_ids(&engine);
    let only_set = parse_id_set(&only);
    let exclude_set = parse_id_set(&exclude);

    validate_ids(&rule_ids, &only_set, "--only")?;
    validate_ids(&rule_ids, &exclude_set, "--exclude")?;

    Ok(containers
        .into_iter()
        .map(|container| {
            let findings = run_detectors_on_container(
                &container,
                &engine,
                &only_set,
                &exclude_set,
            );
            ContainerResult { container, findings }
        })
        .collect())
}



fn collect_rule_ids(engine: &YamlRuleEngine) -> HashSet<String> {
    engine
        .rules()                         
        .iter()
        .map(|r| r.id.to_lowercase())
        .collect()
}

fn run_detectors_on_container(
    container: &ContainerInspectResponse,
    engine: &YamlRuleEngine,
    only: &Option<HashSet<String>>,
    exclude: &Option<HashSet<String>>,
) -> Vec<Finding> {
    let json = to_value(container).expect("container to json");

    let mut findings = engine.scan_value(&json);

    findings.retain(|f| {
        let id = f.kind.to_lowercase();
        only.as_ref().is_none()
            || only.as_ref().unwrap().contains(&id)
    });
    findings.retain(|f| {
        exclude.as_ref().is_none()
            || !exclude.as_ref().unwrap().contains(&f.kind.to_lowercase())
    });

    findings
}


fn parse_id_set(input: &Option<String>) -> Option<HashSet<String>> {
    input.as_ref().map(|s| {
        s.split(',')
            .map(|id| id.trim().to_lowercase())
            .collect::<HashSet<_>>()
    })
}

fn parse_state_set(input: &Option<String>) -> Option<HashSet<String>> {
    input.as_ref().map(|s| {
        s.split(',')
            .map(|id| id.trim().to_lowercase())
            .collect::<HashSet<_>>()
    })
}

fn validate_ids(available: &HashSet<String>, provided: &Option<HashSet<String>>, flag: &str) -> Result<()> {
    if let Some(ids) = provided {
        let unknown: Vec<_> = ids.difference(available).cloned().collect();
        if !unknown.is_empty() {
            let noun = if unknown.len() == 1 { "detector" } else { "detectors" };
            bail!("Unknown {noun} in {flag}: {}", unknown.join(", "));
        }
    }
    Ok(())
}


async fn get_containers(state_filter: Option<&HashSet<String>>) -> Result<Vec<ContainerInspectResponse>> {
    let docker = Docker::connect_with_socket_defaults()
        .context("Failed to connect to Docker socket")?;

    let containers = docker
        .list_containers(Some(ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        }))
        .await
        .context("Failed to list Docker containers")?;

    let mut result = Vec::new();

    for container in containers {
        if let Some(filter) = state_filter {
            if let Some(state) = container.state.as_deref() {
                if !filter.contains(&state.to_lowercase()) {
                    continue;
                }
            }
        }
        if let Some(id) = container.id.as_deref() {
            let inspect = docker
                .inspect_container(id, None::<InspectContainerOptions>)
                .await
                .with_context(|| format!("Failed to inspect container {}", id))?;
            result.push(inspect);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_id_set_normalizes_and_deduplicates() {
        let input = Some("FOO, bar , foo".to_string());
        let set = parse_id_set(&input).expect("some set");
        assert_eq!(set.len(), 2);
        assert!(set.contains("foo"));
        assert!(set.contains("bar"));
    }

    #[test]
    fn parse_state_set_handles_spaces() {
        let input = Some("Running , Exited".to_string());
        let set = parse_state_set(&input).expect("some set");
        assert!(set.contains("running"));
        assert!(set.contains("exited"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn validate_ids_errors_on_unknown() {
        let available: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let provided: Option<HashSet<String>> = Some(["b", "c"].iter().map(|s| s.to_string()).collect());
        let result = validate_ids(&available, &provided, "--only");
        assert!(result.is_err());
    }
}

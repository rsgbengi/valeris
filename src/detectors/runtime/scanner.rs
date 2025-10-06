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



/// Scans running Docker containers using YAML-based detection rules.
///
/// This function connects to the Docker daemon, lists containers (filtered by state
/// if specified), and applies YAML rules to detect security misconfigurations.
///
/// # Arguments
///
/// * `rules_dir` - Path to directory containing YAML rule files
/// * `only` - Optional comma-separated list of rule IDs to exclusively run
/// * `exclude` - Optional comma-separated list of rule IDs to skip
/// * `state` - Optional comma-separated list of container states to scan (e.g., "running,paused")
///
/// # Returns
///
/// `Result<Vec<ContainerResult>>` containing findings for each scanned container
///
/// # Errors
///
/// Returns an error if:
/// * Rules cannot be loaded from the specified directory
/// * Docker daemon is unreachable or returns an error
/// * Invalid rule IDs are specified in `only` or `exclude`
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



/// Extracts all rule IDs from the engine and normalizes them to lowercase.
///
/// # Arguments
///
/// * `engine` - The YAML rule engine containing loaded rules
///
/// # Returns
///
/// HashSet of lowercase rule IDs
fn collect_rule_ids(engine: &YamlRuleEngine) -> HashSet<String> {
    engine
        .rules()
        .iter()
        .map(|r| r.id.to_lowercase())
        .collect()
}

/// Runs YAML-based detectors on a container and filters results.
///
/// # Arguments
///
/// * `container` - Container inspection response from Docker API
/// * `engine` - YAML rule engine with loaded detection rules
/// * `only` - Optional set of rule IDs to exclusively run (whitelist)
/// * `exclude` - Optional set of rule IDs to skip (blacklist)
///
/// # Returns
///
/// Vector of findings matching the filter criteria
fn run_detectors_on_container(
    container: &ContainerInspectResponse,
    engine: &YamlRuleEngine,
    only: &Option<HashSet<String>>,
    exclude: &Option<HashSet<String>>,
) -> Vec<Finding> {
    let json = match to_value(container) {
        Ok(val) => val,
        Err(e) => {
            tracing::warn!("Failed to serialize container to JSON: {}", e);
            return Vec::new();
        }
    };

    let findings = engine.scan_value(&json);

    // Apply filters in one pass for efficiency
    findings
        .into_iter()
        .filter(|f| {
            let id = f.kind.to_lowercase();

            // Check whitelist (only) filter
            let passes_only = only.as_ref().is_none_or(|set| set.contains(&id));

            // Check blacklist (exclude) filter
            let passes_exclude = exclude.as_ref().is_none_or(|set| !set.contains(&id));

            passes_only && passes_exclude
        })
        .collect()
}


/// Parses a comma-separated string into a normalized HashSet of lowercase strings.
///
/// # Arguments
///
/// * `input` - Optional comma-separated string (e.g., "FOO, bar, BAZ")
///
/// # Returns
///
/// `Some(HashSet)` containing trimmed, lowercased values, or `None` if input is `None`
fn parse_comma_separated_set(input: &Option<String>) -> Option<HashSet<String>> {
    input.as_ref().map(|s| {
        s.split(',')
            .map(|item| item.trim().to_lowercase())
            .collect::<HashSet<_>>()
    })
}

// Convenience aliases for clarity
fn parse_id_set(input: &Option<String>) -> Option<HashSet<String>> {
    parse_comma_separated_set(input)
}

fn parse_state_set(input: &Option<String>) -> Option<HashSet<String>> {
    parse_comma_separated_set(input)
}

/// Validates that provided rule IDs exist in the available set.
///
/// # Arguments
///
/// * `available` - Set of valid rule IDs from loaded rules
/// * `provided` - Set of rule IDs provided by user via CLI
/// * `flag` - Name of the CLI flag (for error messages)
///
/// # Returns
///
/// `Ok(())` if all IDs are valid, or an error listing unknown IDs
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


/// Fetches and inspects Docker containers, optionally filtered by state.
///
/// # Arguments
///
/// * `state_filter` - Optional set of container states to include (e.g., "running", "exited")
///
/// # Returns
///
/// Vector of detailed container inspection responses
///
/// # Errors
///
/// Returns an error if:
/// * Unable to connect to Docker socket
/// * Container listing fails
/// * Container inspection fails for any container
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

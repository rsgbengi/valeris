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
/// * `only` - Optional vector of rule IDs to exclusively run
/// * `exclude` - Optional vector of rule IDs to skip
/// * `state` - Optional vector of container states to scan (e.g., ["running", "paused"])
/// * `container` - Optional vector of container name/ID patterns to filter
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
    only: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    state: Option<Vec<String>>,
    container: Option<Vec<String>>,
) -> Result<Vec<ContainerResult>> {
    let engine = YamlRuleEngine::from_dir(&rules_dir)
        .with_context(|| format!("loading YAML detectors from {}", rules_dir.display()))?;

    let state_set = parse_state_set(&state);
    let container_patterns = parse_container_patterns(&container);
    let containers = get_containers(state_set.as_ref(), container_patterns.as_ref())
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


/// Converts a vector of strings into a normalized HashSet (lowercase, trimmed).
///
/// # Arguments
///
/// * `input` - Optional vector of strings to convert
///
/// # Returns
///
/// `Option<HashSet<String>>` with normalized values, or `None` if input is `None`
fn parse_vec_to_set(input: &Option<Vec<String>>) -> Option<HashSet<String>> {
    input.as_ref().map(|vec| {
        vec.iter()
            .map(|item| item.trim().to_lowercase())
            .collect::<HashSet<_>>()
    })
}

// Convenience aliases for clarity
fn parse_id_set(input: &Option<Vec<String>>) -> Option<HashSet<String>> {
    parse_vec_to_set(input)
}

fn parse_state_set(input: &Option<Vec<String>>) -> Option<HashSet<String>> {
    parse_vec_to_set(input)
}

/// Converts container name/ID patterns into a lowercase vector for matching.
///
/// # Arguments
///
/// * `input` - Optional vector of container name or ID patterns
///
/// # Returns
///
/// `Option<Vec<String>>` with lowercase patterns, or `None` if input is `None`
fn parse_container_patterns(input: &Option<Vec<String>>) -> Option<Vec<String>> {
    input.as_ref().map(|vec| {
        vec.iter()
            .map(|item| item.trim().to_lowercase())
            .collect::<Vec<_>>()
    })
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


/// Fetches and inspects Docker containers, optionally filtered by state and name/ID patterns.
///
/// # Arguments
///
/// * `state_filter` - Optional set of container states to include (e.g., "running", "exited")
/// * `container_patterns` - Optional vector of name/ID patterns to match
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
async fn get_containers(
    state_filter: Option<&HashSet<String>>,
    container_patterns: Option<&Vec<String>>,
) -> Result<Vec<ContainerInspectResponse>> {
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
        // Filter by state
        if let Some(filter) = state_filter {
            if let Some(state) = container.state.as_deref() {
                if !filter.contains(&state.to_lowercase()) {
                    continue;
                }
            }
        }

        // Filter by container name/ID pattern
        if let Some(patterns) = container_patterns {
            let mut matched = false;

            // Check container ID
            if let Some(id) = container.id.as_deref() {
                let id_lower = id.to_lowercase();
                for pattern in patterns {
                    if id_lower.starts_with(pattern) || id_lower.contains(pattern) {
                        matched = true;
                        break;
                    }
                }
            }

            // Check container names
            if !matched {
                if let Some(names) = &container.names {
                    for name in names {
                        let name_lower = name.trim_start_matches('/').to_lowercase();
                        for pattern in patterns {
                            if name_lower.contains(pattern) {
                                matched = true;
                                break;
                            }
                        }
                        if matched {
                            break;
                        }
                    }
                }
            }

            if !matched {
                continue;
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
        let input = Some(vec!["FOO".to_string(), "bar".to_string(), "foo".to_string()]);
        let set = parse_id_set(&input).expect("some set");
        assert_eq!(set.len(), 2);
        assert!(set.contains("foo"));
        assert!(set.contains("bar"));
    }

    #[test]
    fn parse_state_set_handles_spaces() {
        let input = Some(vec!["Running ".to_string(), " Exited".to_string()]);
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

    #[test]
    fn parse_container_patterns_normalizes() {
        let input = Some(vec!["Nginx ".to_string(), " REDIS".to_string(), "web-app".to_string()]);
        let patterns = parse_container_patterns(&input).expect("some patterns");
        assert_eq!(patterns.len(), 3);
        assert_eq!(patterns[0], "nginx");
        assert_eq!(patterns[1], "redis");
        assert_eq!(patterns[2], "web-app");
    }

    #[test]
    fn parse_container_patterns_none() {
        let input: Option<Vec<String>> = None;
        let patterns = parse_container_patterns(&input);
        assert!(patterns.is_none());
    }
}

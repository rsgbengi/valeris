pub mod docker;
pub mod common;

use crate::docker::model::Finding;
use bollard::models::ContainerInspectResponse;


#[derive(Debug, PartialEq, Eq)]
pub enum PluginTarget {
    Docker,
    Kubernetes,
    Both,
}

pub enum ScanInput {
    DockerContainer(ContainerInspectResponse),
}

#[allow(dead_code)]
pub trait ValerisPlugin {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn target(&self) -> PluginTarget;
    fn description(&self) -> &str;
    fn run(&self, input: &ScanInput) -> Vec<Finding>;
}



pub fn load_plugins_for_target(target: PluginTarget) -> Vec<Box<dyn ValerisPlugin>> {
    let mut plugins = Vec::new();

    plugins.extend(docker::get_docker_plugins());
    plugins.extend(common::get_common_plugins());

    if target != PluginTarget::Both {
        plugins.retain(|p| p.target() == target || p.target() == PluginTarget::Both);
    }

    plugins
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_docker_plugins() {
        let plugins = load_plugins_for_target(PluginTarget::Docker);
        assert!(!plugins.is_empty());
        assert!(plugins
            .iter()
            .all(|p| matches!(p.target(), PluginTarget::Docker | PluginTarget::Both)));
    }

    #[test]
    fn loads_kubernetes_plugins() {
        let plugins = load_plugins_for_target(PluginTarget::Kubernetes);
        assert!(!plugins.is_empty());
        assert!(plugins
            .iter()
            .all(|p| matches!(p.target(), PluginTarget::Kubernetes | PluginTarget::Both)));
    }

    #[test]
    fn loads_all_plugins_for_both() {
        let plugins = load_plugins_for_target(PluginTarget::Both);
        assert!(!plugins.is_empty());
        // Expect at least one Docker-specific and one cross-target plugin
        assert!(plugins.iter().any(|p| p.target() == PluginTarget::Docker));
        assert!(plugins.iter().any(|p| p.target() == PluginTarget::Both));
    }
}
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



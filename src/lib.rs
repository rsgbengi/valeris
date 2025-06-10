pub mod cli;

mod docker;
mod plugins;

use crate::plugins::PluginTarget;
use clap::Parser;
use cli::{Cli, Commands, ScanTarget};
use docker::exporters::export_findings_grouped;
use docker::scanner::scan_docker_with_plugins;
use plugins::load_plugins_for_target;
use docker::printer::print_container_report;

pub fn list_plugins(filter_target: PluginTarget) {
    let plugins = load_plugins_for_target(filter_target);

    println!("Available Plugins:");

    for plugin in plugins {
        let target_str = match plugin.target() {
            PluginTarget::Docker => "Docker",
            PluginTarget::Kubernetes => "Kubernetes",
            PluginTarget::Both => "Both",
        };

        println!("- [{}] {} - {}", target_str, plugin.id(), plugin.name());
    }
}

pub async fn run_with_args<I, T>(args: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);

    match cli.command {
        Commands::Scan {
            target,
            only,
            exclude,
            format,
            output,
        } => {
            let target = match target {
                ScanTarget::Docker => PluginTarget::Docker,
                ScanTarget::K8s => PluginTarget::Kubernetes,
                ScanTarget::Both => PluginTarget::Both,
            };

            let results = scan_docker_with_plugins(target, only, exclude).await?;

            if output.is_some() {
                export_findings_grouped(&results, &format, &output);
            } else {
                for result in results {
                    print_container_report(&result.container, &result.findings);
                }
            }
        }

        Commands::ListPlugins { target } => {
            let plugin_target = match target {
                Some(ScanTarget::Docker) => PluginTarget::Docker,
                Some(ScanTarget::K8s) => PluginTarget::Kubernetes,
                Some(ScanTarget::Both) | None => PluginTarget::Both,
            };

            crate::list_plugins(plugin_target);
        }
    }

    Ok(())
}

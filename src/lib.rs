pub mod cli;

pub mod docker;          
mod detectors;       
pub mod yaml_rules;

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, ScanTarget};
use docker::exporters::export_findings_grouped;
use docker::printer::print_container_report;
use detectors::docker::{
    scan_docker_with_yaml_detectors,
}; 
use yaml_rules::YamlRuleEngine;        

// ────────────────────────────────────────────────────────────────────
// LIST YAML DETECTORS
// ────────────────────────────────────────────────────────────────────
fn list_detectors(rules_dir: &Path) -> Result<()> {
    let engine = YamlRuleEngine::from_dir(rules_dir)?;
    println!("Available YAML detectors ({}):", rules_dir.display());
    for r in engine.rules() {
        let name = r.name.as_deref().unwrap_or("");
        println!("- [{}] {} {}", r.id, name, r.target.as_deref().unwrap_or(""));
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// CLI entry-point
// ────────────────────────────────────────────────────────────────────
pub async fn run_with_args<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);

    match cli.command {
        // -----------------------------------------------------------
        //     scan
        // -----------------------------------------------------------
        Commands::Scan {
            target,
            only,
            exclude,
            state,
            format,
            output,
        } => {
            let rules_dir = match target {
                ScanTarget::Docker => PathBuf::from("rules/runtime/docker"),
                ScanTarget::K8s    => PathBuf::from("detectors/k8s"),
                ScanTarget::Both   => PathBuf::from("detectors"), 
            };

            let results = scan_docker_with_yaml_detectors(
                rules_dir,
                only,
                exclude,
                state,
            )
            .await?;

            if output.is_some() {
                export_findings_grouped(&results, &format, &output);
            } else {
                for result in results {
                    print_container_report(&result.container, &result.findings);
                }
            }
        }

        // -----------------------------------------------------------
        //     list-detectors
        // -----------------------------------------------------------
        Commands::ListPlugins { target } => {
            let rules_dir = match target {
                Some(ScanTarget::Docker) => PathBuf::from("rules/runtime/docker"),
                Some(ScanTarget::K8s)    => PathBuf::from("detectors/k8s"),
                Some(ScanTarget::Both) | None => PathBuf::from("rules/runtime/docker"),
            };
            println!("Rules directory: {}", rules_dir.display());
            list_detectors(&rules_dir)?;
        }
    }

    Ok(())
}

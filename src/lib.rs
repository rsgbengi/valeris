pub mod cli;
pub mod config;
pub mod detectors;
pub mod docker;
pub mod output;
mod rules;
use detectors::runtime::yaml_rules::YamlRuleEngine;

use std::path::Path;

use rules::ensure_rules;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use detectors::runtime::scanner::scan_docker_with_yaml_detectors;
use detectors::dockerfile::scanner::scan_dockerfile;
use output::printer::{print_scan_report, ScanContext};
use output::exporters::{export_scan_results, ScanSource};

// ────────────────────────────────────────────────────────────────────
// LIST YAML DETECTORS
// ────────────────────────────────────────────────────────────────────
fn list_detectors(rules_dir: &Path) -> Result<()> {
    let engine = YamlRuleEngine::from_dir(rules_dir)?;
    println!("Available YAML detectors ({}):", rules_dir.display());
    for r in engine.rules() {
        let name = r.name.as_deref().unwrap_or("");
        println!(
            "- [{}] {} {}",
            r.id,
            name,
            r.target.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

pub async fn run_with_args<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);

    match cli.command {
        Commands::Scan {
            target: _target,
            only,
            exclude,
            state,
            format,
            output,
        } => {
            let rules_dir = tokio::task::spawn_blocking(ensure_rules)
                .await
                .context("Failed to spawn rules download task")?
                .context("Failed to download or locate rules")?;
            let results = scan_docker_with_yaml_detectors(rules_dir, only, exclude, state)
                .await
                .context("Docker scan failed")?;

            if output.is_some() {
                export_scan_results(
                    ScanSource::Containers(&results),
                    &format,
                    &output
                )?;
            } else {
                for result in results {
                    print_scan_report(
                        ScanContext::Container(&result.container),
                        &result.findings
                    );
                }
            }
        }

        Commands::DockerFile {
            path,
            rules,
            format,
            output,
        } => {
            let is_table = matches!(format, cli::OutputFormat::Table);
            match scan_dockerfile(path, rules, format, output) {
                Ok(_) => {
                    if is_table {
                        println!("Dockerfile processed successfully");
                    }
                }
                Err(e) => eprintln!("Error: {e:?}"),
            }
        }

        Commands::ListPlugins { .. } => {
            let rules_dir = ensure_rules()?;
            list_detectors(&rules_dir)?;
        }
    }
    Ok(())
}

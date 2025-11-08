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
use cli::{Cli, Commands, SeverityLevel};
use detectors::runtime::scanner::scan_docker_with_yaml_detectors;
use detectors::dockerfile::scanner::scan_dockerfile;
use output::printer::{print_scan_report, ScanContext};
use output::exporters::{export_scan_results, ScanSource};
use docker::model::RiskLevel;
use config::ConfigFile;

// ────────────────────────────────────────────────────────────────────
// HELPER FUNCTIONS
// ────────────────────────────────────────────────────────────────────

/// Applies configuration file defaults to CLI arguments
/// CLI arguments always take precedence
fn apply_config_defaults(
    cli_value: &Option<Vec<String>>,
    config_value: &Option<Vec<String>>,
) -> Option<Vec<String>> {
    if cli_value.is_some() {
        cli_value.clone()
    } else {
        config_value.clone()
    }
}

/// Converts CLI SeverityLevel to RiskLevel
fn severity_to_risk(severity: &SeverityLevel) -> RiskLevel {
    match severity {
        SeverityLevel::Informative => RiskLevel::Informative,
        SeverityLevel::Low => RiskLevel::Low,
        SeverityLevel::Medium => RiskLevel::Medium,
        SeverityLevel::High => RiskLevel::High,
    }
}

/// Filters findings by severity
fn filter_by_severity(
    results: &mut [docker::model::ContainerResult],
    severity: Option<&Vec<SeverityLevel>>,
    min_severity: Option<&SeverityLevel>,
) {
    if let Some(severities) = severity {
        // Filter to exact severity levels
        let risk_levels: Vec<RiskLevel> = severities.iter().map(severity_to_risk).collect();
        for result in results.iter_mut() {
            result.findings.retain(|f| risk_levels.contains(&f.risk));
        }
    } else if let Some(min_sev) = min_severity {
        // Filter to minimum severity and above
        let min_risk = severity_to_risk(min_sev);
        for result in results.iter_mut() {
            result.findings.retain(|f| f.risk >= min_risk);
        }
    }
}

/// Checks if any findings meet the fail-on threshold
fn should_fail(
    results: &[docker::model::ContainerResult],
    fail_on: Option<&SeverityLevel>,
) -> bool {
    if let Some(threshold) = fail_on {
        let threshold_risk = severity_to_risk(threshold);
        results.iter().any(|result| {
            result.findings.iter().any(|f| f.risk >= threshold_risk)
        })
    } else {
        false
    }
}

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

    // Load configuration file if it exists
    let config_file = ConfigFile::load_default().ok().flatten();

    if config_file.is_some() {
        tracing::debug!("Loaded configuration from file");
    }

    match cli.command {
        Commands::Scan {
            target: _target,
            only,
            exclude,
            state,
            container,
            severity,
            min_severity,
            fail_on,
            quiet,
            format,
            output,
        } => {
            // Apply configuration file defaults (CLI args override)
            let scan_config = config_file.as_ref().and_then(|c| c.scan.as_ref());

            let effective_only = apply_config_defaults(&only, &scan_config.and_then(|s| s.only.clone()));
            let effective_exclude = apply_config_defaults(&exclude, &scan_config.and_then(|s| s.exclude.clone()));
            let effective_state = apply_config_defaults(&state, &scan_config.and_then(|s| s.default_state.clone()));

            let rules_dir = tokio::task::spawn_blocking(ensure_rules)
                .await
                .context("Failed to spawn rules download task")?
                .context("Failed to download or locate rules")?;

            let mut results = scan_docker_with_yaml_detectors(
                rules_dir,
                effective_only,
                effective_exclude,
                effective_state,
                container
            )
                .await
                .context("Docker scan failed")?;

            // Apply severity filtering
            filter_by_severity(&mut results, severity.as_ref(), min_severity.as_ref());

            // Check fail-on condition
            let should_exit_with_error = should_fail(&results, fail_on.as_ref());

            // Output results (unless in quiet mode)
            if !quiet {
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

            // Exit with error if fail-on threshold was met
            if should_exit_with_error {
                std::process::exit(1);
            }
        }

        Commands::DockerFile {
            path,
            rules,
            only,
            exclude,
            severity,
            min_severity,
            fail_on,
            quiet,
            format,
            output,
        } => {
            let is_table = matches!(format, cli::OutputFormat::Table);
            match scan_dockerfile(
                path,
                rules,
                only,
                exclude,
                severity,
                min_severity,
                fail_on,
                quiet,
                format,
                output
            ) {
                Ok(should_fail) => {
                    if is_table && !quiet {
                        println!("Dockerfile processed successfully");
                    }
                    if should_fail {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e:?}");
                    std::process::exit(1);
                }
            }
        }

        Commands::ListPlugins { .. } => {
            let rules_dir = ensure_rules()?;
            list_detectors(&rules_dir)?;
        }

        Commands::Config {} => {
            println!("Valeris Configuration");
            println!("{}", "━".repeat(60));

            // Check environment variable
            if let Ok(path) = std::env::var(config::CONFIG_FILE_ENV) {
                println!("\n📝 Environment variable set:");
                println!("   {}={}", config::CONFIG_FILE_ENV, path);
                let path_buf = std::path::PathBuf::from(&path);
                if path_buf.exists() {
                    println!("   Status: ✅ File exists");
                } else {
                    println!("   Status: ❌ File not found");
                }
            }

            // Check XDG config directory
            if let Some(config_dir) = dirs::config_dir() {
                let path = config_dir.join("valeris").join("config.toml");
                println!("\n📁 XDG config location:");
                println!("   {}", path.display());
                if path.exists() {
                    println!("   Status: ✅ File exists");
                    if let Ok(cfg) = ConfigFile::load(&path) {
                        println!("   Parse: ✅ Valid TOML");
                        if cfg.scan.is_some() {
                            println!("   - Contains [scan] configuration");
                        }
                        if cfg.output.is_some() {
                            println!("   - Contains [output] configuration");
                        }
                        if cfg.rules.is_some() {
                            println!("   - Contains [rules] configuration");
                        }
                        if cfg.docker.is_some() {
                            println!("   - Contains [docker] configuration");
                        }
                    } else {
                        println!("   Parse: ❌ Invalid TOML");
                    }
                } else {
                    println!("   Status: ⚠️  File not found (create to use)");
                }
            }

            // Check home directory
            if let Some(home_dir) = dirs::home_dir() {
                let path = home_dir.join(".valeris.toml");
                println!("\n🏠 Home directory location:");
                println!("   {}", path.display());
                if path.exists() {
                    println!("   Status: ✅ File exists");
                } else {
                    println!("   Status: ⚠️  File not found");
                }
            }

            println!("\n💡 To create a config file:");
            println!("   mkdir -p ~/.config/valeris");
            println!("   cp valeris.toml.example ~/.config/valeris/config.toml");
            println!("   vi ~/.config/valeris/config.toml");
            println!("\n📖 See example file: valeris.toml.example");
        }
    }
    Ok(())
}

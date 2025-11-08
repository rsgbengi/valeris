//! Unified export functionality for all scan types.
//!
//! This module provides a consistent interface for exporting scan results
//! to various formats (JSON, CSV) across different scanner types.

use crate::docker::model::{ContainerResult, Finding, RiskLevel};
use crate::cli::OutputFormat;
use anyhow::{Context, Result};
use bollard::models::ContainerInspectResponse;
use serde::Serialize;
use std::path::Path;

/// Source of a scan - what was scanned.
pub enum ScanSource<'a> {
    /// Runtime container scans
    Containers(&'a [ContainerResult]),
    /// Dockerfile static analysis
    Dockerfile {
        path: &'a Path,
        findings: &'a [Finding],
    },
}

// ─────────────────────────────────────────────────────────────────
// Container Export Structures
// ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ExportableContainerFinding {
    pub kind: String,
    pub description: String,
    pub risk: RiskLevel,
}

#[derive(Serialize)]
pub struct ExportableContainerResult {
    pub container_id: String,
    pub container_name: String,
    pub findings: Vec<ExportableContainerFinding>,
}

// ─────────────────────────────────────────────────────────────────
// Dockerfile Export Structures
// ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DockerfileScanResult {
    pub dockerfile_path: String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub findings: Vec<DockerfileFinding>,
}

#[derive(Serialize)]
pub struct DockerfileFinding {
    pub id: String,
    pub severity: String,
    pub line: Option<usize>,
    pub description: String,
}

// ─────────────────────────────────────────────────────────────────
// Unified Export API
// ─────────────────────────────────────────────────────────────────

/// Exports scan results in the specified format.
///
/// # Arguments
///
/// * `source` - The scan source (containers or Dockerfile)
/// * `format` - Output format (JSON or CSV)
/// * `output` - Optional output file path
///
/// # Returns
///
/// `Ok(())` on success, or an error if export failed
pub fn export_scan_results(
    source: ScanSource,
    format: &OutputFormat,
    output: &Option<String>,
) -> Result<()> {
    match format {
        OutputFormat::Table => {
            // Table format is handled by the printer module
            Ok(())
        }
        OutputFormat::Json => export_json(source, output),
        OutputFormat::Csv => export_csv(source, output),
    }
}

fn export_json(source: ScanSource, output: &Option<String>) -> Result<()> {
    let json = match source {
        ScanSource::Containers(results) => {
            let data = containers_to_json(results);
            serde_json::to_string_pretty(&data)
                .context("Failed to serialize containers to JSON")?
        }
        ScanSource::Dockerfile { path, findings } => {
            let data = dockerfile_to_json(path, findings);
            serde_json::to_string_pretty(&data)
                .context("Failed to serialize Dockerfile to JSON")?
        }
    };

    write_or_print(&json, output)?;

    if let Some(path) = output {
        tracing::info!("JSON exported to {}", path);
    }

    Ok(())
}

fn export_csv(source: ScanSource, output: &Option<String>) -> Result<()> {
    match source {
        ScanSource::Containers(results) => {
            export_containers_csv(results, output)?;
        }
        ScanSource::Dockerfile { path, findings } => {
            export_dockerfile_csv(path, findings, output)?;
        }
    }

    if let Some(path) = output {
        tracing::info!("CSV exported to {}", path);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Container-specific Export Logic
// ─────────────────────────────────────────────────────────────────

fn containers_to_json(results: &[ContainerResult]) -> Vec<ExportableContainerResult> {
    results
        .iter()
        .map(|r| {
            let id = get_container_id(&r.container);
            let name = get_container_name(&r.container);

            let findings = r
                .findings
                .iter()
                .map(|f| ExportableContainerFinding {
                    kind: f.kind.clone(),
                    description: f.description.clone(),
                    risk: f.risk.clone(),
                })
                .collect();

            ExportableContainerResult {
                container_id: id,
                container_name: name,
                findings,
            }
        })
        .collect()
}

fn export_containers_csv(results: &[ContainerResult], output: &Option<String>) -> Result<()> {
    let writer: Box<dyn std::io::Write> = match output {
        Some(path) => Box::new(
            std::fs::File::create(path)
                .with_context(|| format!("Failed to create CSV file {}", path))?,
        ),
        None => Box::new(std::io::stdout()),
    };

    let mut wtr = csv::Writer::from_writer(writer);

    // Flatten findings for CSV
    for result in results {
        for finding in &result.findings {
            wtr.serialize(&ExportableContainerFinding {
                kind: finding.kind.clone(),
                description: finding.description.clone(),
                risk: finding.risk.clone(),
            })
            .context("Failed to write CSV row")?;
        }
    }

    wtr.flush().context("Failed to flush CSV writer")?;
    Ok(())
}

fn get_container_id(container: &ContainerInspectResponse) -> String {
    container.id.clone().unwrap_or_default()
}

fn get_container_name(container: &ContainerInspectResponse) -> String {
    container
        .name
        .clone()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string()
}

// ─────────────────────────────────────────────────────────────────
// Dockerfile-specific Export Logic
// ─────────────────────────────────────────────────────────────────

fn dockerfile_to_json(path: &Path, findings: &[Finding]) -> DockerfileScanResult {
    let (critical, medium, low, info) = count_by_severity(findings);

    let exportable_findings = findings
        .iter()
        .map(|f| DockerfileFinding {
            id: f.kind.clone(),
            severity: severity_to_string(&f.risk),
            line: f.line,
            description: f.description.clone(),
        })
        .collect();

    DockerfileScanResult {
        dockerfile_path: path.display().to_string(),
        total_findings: findings.len(),
        critical_count: critical,
        medium_count: medium,
        low_count: low,
        info_count: info,
        findings: exportable_findings,
    }
}

fn export_dockerfile_csv(path: &Path, findings: &[Finding], output: &Option<String>) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(vec![]);

    let dockerfile_path = path.display().to_string();

    // Write header
    wtr.write_record(["dockerfile", "severity", "id", "line", "description"])
        .context("Failed to write CSV header")?;

    // Write findings
    for finding in findings {
        wtr.write_record([
            &dockerfile_path,
            &severity_to_string(&finding.risk),
            &finding.kind,
            &finding.line.map(|n| n.to_string()).unwrap_or_else(|| "".to_string()),
            &finding.description,
        ])
        .context("Failed to write CSV row")?;
    }

    let data = String::from_utf8(wtr.into_inner().context("Failed to get CSV buffer")?)
        .context("Failed to convert CSV to UTF-8")?;

    write_or_print(&data, output)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────

fn count_by_severity(findings: &[Finding]) -> (usize, usize, usize, usize) {
    let mut critical = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    for finding in findings {
        match finding.risk {
            RiskLevel::High => critical += 1,
            RiskLevel::Medium => medium += 1,
            RiskLevel::Low => low += 1,
            RiskLevel::Informative => info += 1,
        }
    }

    (critical, medium, low, info)
}

fn severity_to_string(risk: &RiskLevel) -> String {
    match risk {
        RiskLevel::High => "CRITICAL".to_string(),
        RiskLevel::Medium => "MEDIUM".to_string(),
        RiskLevel::Low => "LOW".to_string(),
        RiskLevel::Informative => "INFO".to_string(),
    }
}

fn write_or_print(content: &str, output: &Option<String>) -> Result<()> {
    match output {
        Some(path) => {
            std::fs::write(path, content)
                .with_context(|| format!("Failed to write output to {}", path))?;
        }
        None => {
            println!("{}", content);
        }
    }
    Ok(())
}

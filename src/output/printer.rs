//! Unified output formatting for scan results.
//!
//! This module provides a consistent, modular approach to displaying
//! security findings across different scan types (containers, Dockerfiles, etc.).

use crate::docker::model::{Finding, RiskLevel};
use bollard::models::ContainerInspectResponse;
use console::{style, Emoji};
use comfy_table::{Table, presets::UTF8_FULL, ContentArrangement, Cell, Color, Attribute};
use std::collections::BTreeMap;
use std::path::PathBuf;

static DOCKER: Emoji<'_, '_> = Emoji("🐳 ", "[D] ");
static MAGNIFIER: Emoji<'_, '_> = Emoji("🔍 ", "");
static CHECK: Emoji<'_, '_> = Emoji("✅ ", "[OK] ");
static WARN: Emoji<'_, '_> = Emoji("⚠️  ", "[!] ");

/// Context for a scan operation - what was scanned and metadata.
pub enum ScanContext<'a> {
    /// A running Docker container
    Container(&'a ContainerInspectResponse),
    /// A Dockerfile on disk
    Dockerfile(&'a PathBuf),
}

/// Prints a comprehensive report for any scan type.
///
/// # Arguments
///
/// * `context` - The scan context (container or file)
/// * `findings` - List of security/quality findings
pub fn print_scan_report(context: ScanContext, findings: &[Finding]) {
    print_header(&context);

    if findings.is_empty() {
        print_success_message();
        return;
    }

    print_summary(findings);
    print_findings_table(&context, findings);
    print_footer();
}

/// Prints the report header based on scan context.
fn print_header(context: &ScanContext) {
    println!("\n{}", style("━".repeat(80)).dim());

    match context {
        ScanContext::Container(container) => {
            let name = container
                .name
                .as_deref()
                .unwrap_or("<none>")
                .trim_start_matches('/');
            let image = container
                .config
                .as_ref()
                .and_then(|cfg| cfg.image.as_deref())
                .or(container.image.as_deref())
                .unwrap_or("<unknown>");
            let image_with_tag = if image.contains(':') {
                image.to_string()
            } else {
                format!("{image}:latest")
            };

            let state_str = if let Some(state_obj) = &container.state {
                match state_obj.status {
                    Some(ref s) => format!("{:?}", s),
                    None => "unknown".to_string(),
                }
            } else {
                "unknown".to_string()
            };

            let status_style = match state_str.as_str() {
                "RUNNING" => style("Running").green().bold().to_string(),
                "EXITED" => style("Exited").red().bold().to_string(),
                "PAUSED" => style("Paused").yellow().bold().to_string(),
                "CREATED" => style("Created").blue().bold().to_string(),
                _ => style(&state_str).dim().to_string(),
            };

            println!(
                "{}{} {}",
                DOCKER,
                style("Container:").bold().cyan(),
                style(name).bold().white()
            );
            println!("  {} {}", style("Image:").dim(), style(image_with_tag).white());
            println!("  {} {}", style("Status:").dim(), status_style);
        }

        ScanContext::Dockerfile(path) => {
            let file_name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Dockerfile");
            let path_str = path.display().to_string();

            println!(
                "{}{} {}",
                MAGNIFIER,
                style("Scanning Dockerfile:").bold().cyan(),
                style(file_name).bold().white()
            );
            println!("  {} {}", style("Path:").dim(), style(path_str).dim());
        }
    }

    println!("{}", style("━".repeat(80)).dim());
}

/// Prints a success message when no issues are found.
fn print_success_message() {
    println!(
        "\n  {}{}\n",
        CHECK,
        style("No security issues found!").green().bold()
    );
    println!("{}\n", style("━".repeat(80)).dim());
}

/// Prints a summary banner with issue counts by severity.
fn print_summary(findings: &[Finding]) {
    let counts = count_findings_by_severity(findings);
    let total = findings.len();

    print!("\n  {}", WARN);
    print!("{} ", style(format!("{} issues found:", total)).bold().yellow());

    let summary_parts = build_summary_parts(&counts);
    println!("{}\n", summary_parts.join(", "));
}

/// Counts findings grouped by severity level.
fn count_findings_by_severity(findings: &[Finding]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();

    for finding in findings {
        let severity = match finding.risk {
            RiskLevel::High => "Critical",
            RiskLevel::Medium => "Medium",
            RiskLevel::Low => "Low",
            RiskLevel::Informative => "Info",
        };
        *counts.entry(severity).or_insert(0) += 1;
    }

    counts
}

/// Builds colored summary text parts for each severity level.
fn build_summary_parts(counts: &BTreeMap<&'static str, usize>) -> Vec<String> {
    let mut parts = Vec::new();

    if let Some(&n) = counts.get("Critical") {
        parts.push(style(format!("{} critical", n)).red().bold().to_string());
    }
    if let Some(&n) = counts.get("Medium") {
        parts.push(style(format!("{} medium", n)).yellow().to_string());
    }
    if let Some(&n) = counts.get("Low") {
        parts.push(style(format!("{} low", n)).blue().to_string());
    }
    if let Some(&n) = counts.get("Info") {
        parts.push(style(format!("{} info", n)).dim().to_string());
    }

    parts
}

/// Prints a formatted table of all findings.
fn print_findings_table(context: &ScanContext, findings: &[Finding]) {
    let mut table = Table::new();

    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    // Build header based on context
    let mut header = vec![
        Cell::new("Severity").add_attribute(Attribute::Bold),
        Cell::new("ID").add_attribute(Attribute::Bold),
    ];

    // Add line column only for Dockerfile scans
    if matches!(context, ScanContext::Dockerfile(_)) {
        header.push(Cell::new("Line").add_attribute(Attribute::Bold));
    }

    header.push(Cell::new("Description").add_attribute(Attribute::Bold));
    table.set_header(header);

    // Add rows
    for finding in findings {
        add_finding_row(&mut table, context, finding);
    }

    println!("{}\n", table);
}

/// Adds a single finding as a table row.
fn add_finding_row(table: &mut Table, context: &ScanContext, finding: &Finding) {
    let (severity_text, severity_color) = get_severity_display(&finding.risk);

    let mut cells = vec![
        Cell::new(severity_text).fg(severity_color).add_attribute(Attribute::Bold),
        Cell::new(&finding.kind).fg(Color::Cyan),
    ];

    // Add line number only for Dockerfile scans
    if matches!(context, ScanContext::Dockerfile(_)) {
        let line_str = format_line_number(finding.line);
        cells.push(Cell::new(line_str));
    }

    cells.push(Cell::new(&finding.description));
    table.add_row(cells);
}

/// Returns display text and color for a risk level.
fn get_severity_display(risk: &RiskLevel) -> (&'static str, Color) {
    match risk {
        RiskLevel::High => ("CRITICAL", Color::Red),
        RiskLevel::Medium => ("MEDIUM", Color::Yellow),
        RiskLevel::Low => ("LOW", Color::Blue),
        RiskLevel::Informative => ("INFO", Color::White),
    }
}

/// Formats a line number for display (or "—" if None).
fn format_line_number(line: Option<usize>) -> String {
    match line {
        Some(n) => n.to_string(),
        None => "—".to_string(),
    }
}

/// Prints the report footer.
fn print_footer() {
    println!("{}\n", style("━".repeat(80)).dim());
}

//! Output formatting for Dockerfile scan results.
//!
//! This module handles the visual presentation of scan findings,
//! including colored tables, summaries, and formatted reports.

use crate::docker::model::{Finding, RiskLevel};
use console::{style, Emoji};
use comfy_table::{Table, presets::UTF8_FULL, ContentArrangement, Cell, Color, Attribute};
use std::collections::BTreeMap;
use std::path::PathBuf;

static MAGNIFIER: Emoji<'_, '_> = Emoji("🔍 ", "");
static CHECK: Emoji<'_, '_> = Emoji("✅ ", "[OK] ");
static WARN: Emoji<'_, '_> = Emoji("⚠️  ", "[!] ");

/// Prints a comprehensive report of Dockerfile scan results.
///
/// Displays a header with file information, a summary of findings by severity,
/// and a detailed table of all issues found.
///
/// # Arguments
///
/// * `path` - Path to the scanned Dockerfile
/// * `findings` - List of security/quality findings
pub fn print_dockerfile_report(path: &PathBuf, findings: &[Finding]) {
    print_header(path);

    if findings.is_empty() {
        print_success_message();
        return;
    }

    print_summary(findings);
    print_findings_table(findings);
    print_footer();
}

/// Prints the report header with file information.
fn print_header(path: &PathBuf) {
    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Dockerfile");

    let path_str = path.display().to_string();

    println!("\n{}", style("━".repeat(80)).dim());
    println!(
        "{}{} {}",
        MAGNIFIER,
        style("Scanning Dockerfile:").bold().cyan(),
        style(file_name).bold().white()
    );
    println!("  {} {}", style("Path:").dim(), style(path_str).dim());
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
fn print_findings_table(findings: &[Finding]) {
    let mut table = Table::new();

    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Severity").add_attribute(Attribute::Bold),
            Cell::new("ID").add_attribute(Attribute::Bold),
            Cell::new("Line").add_attribute(Attribute::Bold),
            Cell::new("Issue").add_attribute(Attribute::Bold),
        ]);

    for finding in findings {
        add_finding_row(&mut table, finding);
    }

    println!("{}\n", table);
}

/// Adds a single finding as a table row.
fn add_finding_row(table: &mut Table, finding: &Finding) {
    let (severity_text, severity_color) = get_severity_display(&finding.risk);
    let line_str = format_line_number(finding.line);

    table.add_row(vec![
        Cell::new(severity_text).fg(severity_color).add_attribute(Attribute::Bold),
        Cell::new(&finding.kind).fg(Color::Cyan),
        Cell::new(line_str),
        Cell::new(&finding.description),
    ]);
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

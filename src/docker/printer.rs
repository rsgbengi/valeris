use crate::docker::model::{Finding, RiskLevel};
use bollard::models::ContainerInspectResponse;
use console::{style, Emoji};
use comfy_table::{Table, presets::UTF8_FULL, ContentArrangement, Cell, Color, Attribute};
use std::collections::BTreeMap;

pub fn print_container_report(container: &ContainerInspectResponse, findings: &[Finding]) {
    static DOCKER: Emoji<'_, '_> = Emoji("🐳 ", "[D] ");
    static CHECK: Emoji<'_, '_> = Emoji("✅ ", "[OK] ");
    static WARN: Emoji<'_, '_> = Emoji("⚠️  ", "[!] ");

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

    // Header
    println!("\n{}", style("━".repeat(80)).dim());
    println!(
        "{}{} {}",
        DOCKER,
        style("Container:").bold().cyan(),
        style(name).bold().white()
    );
    println!("  {} {}", style("Image:").dim(), style(image_with_tag).white());
    println!("  {} {}", style("Status:").dim(), status_style);
    println!("{}", style("━".repeat(80)).dim());

    if findings.is_empty() {
        println!(
            "\n  {}{}\n",
            CHECK,
            style("No security issues found!").green().bold()
        );
        println!("{}\n", style("━".repeat(80)).dim());
        return;
    }

    // Count findings by severity
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in findings {
        let severity = match finding.risk {
            RiskLevel::High => "Critical",
            RiskLevel::Medium => "Medium",
            RiskLevel::Low => "Low",
            RiskLevel::Informative => "Info",
        };
        *counts.entry(severity).or_insert(0) += 1;
    }

    // Summary banner
    let total = findings.len();
    print!("\n  {}", WARN);
    print!("{} ", style(format!("{} issues found:", total)).bold().yellow());

    let mut parts = vec![];
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

    println!("{}\n", parts.join(", "));

    // Create findings table
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Severity").add_attribute(Attribute::Bold),
            Cell::new("Rule ID").add_attribute(Attribute::Bold),
            Cell::new("Description").add_attribute(Attribute::Bold),
        ]);

    for finding in findings {
        let (severity_text, severity_color) = match finding.risk {
            RiskLevel::High => ("CRITICAL", Color::Red),
            RiskLevel::Medium => ("MEDIUM", Color::Yellow),
            RiskLevel::Low => ("LOW", Color::Blue),
            RiskLevel::Informative => ("INFO", Color::White),
        };

        table.add_row(vec![
            Cell::new(severity_text).fg(severity_color).add_attribute(Attribute::Bold),
            Cell::new(&finding.kind).fg(Color::Cyan),
            Cell::new(&finding.description),
        ]);
    }

    println!("{}\n", table);
    println!("{}\n", style("━".repeat(80)).dim());
}

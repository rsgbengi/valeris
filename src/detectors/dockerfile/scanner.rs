//! Dockerfile security scanner.
//!
//! This module orchestrates the scanning of Dockerfiles for security issues
//! and misconfigurations using YAML-defined rules.

use anyhow::{Context, anyhow};
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use dockerfile_parser::{Dockerfile, Instruction};

use crate::detectors::dockerfile::yaml_rules::{self, Rule, Severity};
use crate::docker::model::{Finding, RiskLevel};
use crate::output::printer::{print_scan_report, ScanContext};
use crate::output::exporters::{export_scan_results, ScanSource};
use crate::detectors::dockerfile::matcher::matches_matcher;
use crate::detectors::dockerfile::instruction_utils::{
    get_instruction_kind,
    instruction_to_map,
    get_line_number,
    find_last_user_instruction,
};
use crate::cli::OutputFormat;

/// Scans a Dockerfile for security issues and misconfigurations.
///
/// This function performs a three-level analysis:
/// 1. Instruction-level checks (individual FROM, RUN, ENV, etc.)
/// 2. Stage-level checks (entire build stage properties)
/// 3. File-level checks (global properties like .dockerignore)
///
/// # Arguments
///
/// * `path` - Path to the Dockerfile to scan
/// * `rules_dir` - Directory containing YAML rule definitions
/// * `only` - Optional list of rule IDs to run exclusively
/// * `exclude` - Optional list of rule IDs to exclude
/// * `severity` - Optional exact severity levels to filter
/// * `min_severity` - Optional minimum severity threshold
/// * `fail_on` - Optional severity level to trigger exit code 1
/// * `quiet` - Suppress all output
/// * `format` - Output format (Table, JSON, or CSV)
/// * `output_file` - Optional file path to write output to
///
/// # Returns
///
/// Returns `Ok(bool)` where the boolean indicates whether the scan should fail
/// (true if fail_on threshold was met), or an error if the file couldn't be
/// read or parsed
///
/// # Example
///
/// ```no_run
/// use std::path::PathBuf;
/// use valeris::detectors::dockerfile::scanner::scan_dockerfile;
/// use valeris::cli::OutputFormat;
///
/// let result = scan_dockerfile(
///     PathBuf::from("./Dockerfile"),
///     PathBuf::from("./rules/dockerfile"),
///     None,
///     None,
///     None,
///     None,
///     None,
///     false,
///     OutputFormat::Table,
///     None
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn scan_dockerfile(
    path: PathBuf,
    rules_dir: PathBuf,
    only: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    severity: Option<Vec<crate::cli::SeverityLevel>>,
    min_severity: Option<crate::cli::SeverityLevel>,
    fail_on: Option<crate::cli::SeverityLevel>,
    quiet: bool,
    format: OutputFormat,
    output_file: Option<PathBuf>,
) -> anyhow::Result<bool> {
    let content = read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;

    let dockerfile = Dockerfile::parse(&content)
        .map_err(|e| anyhow!("Error parsing Dockerfile: {:?}", e))?;

    let mut ruleset = yaml_rules::load_rules_from_dir(rules_dir.as_path())?;

    // Apply rule filtering (only/exclude)
    filter_rules(&mut ruleset.rules, only.as_ref(), exclude.as_ref());

    let mut all_findings = Vec::new();

    // Scan at instruction level
    all_findings.extend(scan_instructions(&dockerfile, &ruleset.rules, &content));

    // Scan at stage level
    all_findings.extend(scan_stages(&dockerfile, &ruleset.rules, &content));

    // Scan at file level
    all_findings.extend(scan_file(&dockerfile, &ruleset.rules, &path));

    // Apply severity filtering
    filter_findings_by_severity(&mut all_findings, severity.as_ref(), min_severity.as_ref());

    // Check if we should fail based on fail_on threshold
    let should_fail = should_fail_scan(&all_findings, fail_on.as_ref());

    // Output results based on format (unless quiet mode)
    if !quiet {
        output_results(&path, &all_findings, format, output_file)?;
    }

    Ok(should_fail)
}

/// Outputs scan results in the specified format.
fn output_results(
    path: &PathBuf,
    findings: &[Finding],
    format: OutputFormat,
    output_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Table => {
            // Table format goes to stdout
            print_scan_report(ScanContext::Dockerfile(path), findings);
        }
        _ => {
            // Use unified exporter for JSON and CSV
            export_scan_results(
                ScanSource::Dockerfile {
                    path,
                    findings,
                },
                &format,
                &output_file.as_ref().map(|p| p.display().to_string()),
            )?;
        }
    }

    Ok(())
}

/// Scans all instructions in all stages for rule violations.
///
/// # Arguments
///
/// * `dockerfile` - Parsed Dockerfile
/// * `rules` - List of rule definitions
/// * `content` - Raw Dockerfile content (for line number calculation)
///
/// # Returns
///
/// Vector of findings from instruction-level rules
fn scan_instructions(
    dockerfile: &Dockerfile,
    rules: &[Rule],
    content: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for stage in dockerfile.iter_stages() {
        for instruction in &stage.instructions {
            findings.extend(check_instruction_rules(
                rules,
                instruction,
                stage.index,
                content,
            ));
        }
    }

    findings
}

/// Scans all build stages for stage-level rule violations.
///
/// # Arguments
///
/// * `dockerfile` - Parsed Dockerfile
/// * `rules` - List of rule definitions
/// * `content` - Raw Dockerfile content
///
/// # Returns
///
/// Vector of findings from stage-level rules
fn scan_stages(
    dockerfile: &Dockerfile,
    rules: &[Rule],
    content: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for stage in dockerfile.iter_stages() {
        findings.extend(check_stage_rules(rules, &stage, content));
    }

    findings
}

/// Scans the entire Dockerfile for file-level rule violations.
///
/// # Arguments
///
/// * `dockerfile` - Parsed Dockerfile
/// * `rules` - List of rule definitions
/// * `path` - Path to the Dockerfile
///
/// # Returns
///
/// Vector of findings from file-level rules
fn scan_file(
    dockerfile: &Dockerfile,
    rules: &[Rule],
    path: &Path,
) -> Vec<Finding> {
    check_file_rules(rules, dockerfile, path)
}

/// Checks a single instruction against all instruction-scoped rules.
fn check_instruction_rules(
    rules: &[Rule],
    ins: &Instruction,
    stage_index: usize,
    content: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        if let Rule::Instruction { id, kind, matcher, severity, message, .. } = rule {
            let ins_kind = get_instruction_kind(ins);

            if &ins_kind != kind {
                continue;
            }

            let context = instruction_to_map(ins);

            if matches_matcher(matcher, &context) {
                let line = get_line_number(ins, content);

                findings.push(Finding {
                    kind: id.clone(),
                    description: format!("Stage {}: {}", stage_index, message),
                    risk: severity_to_risk(severity),
                    line,
                });
            }
        }
    }

    findings
}

/// Checks a build stage against all stage-scoped rules.
fn check_stage_rules(
    rules: &[Rule],
    stage: &dockerfile_parser::Stage,
    content: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        if let Rule::Stage { id, when, severity, message, .. } = rule {
            if when.must_end_non_root {
                let last_user = find_last_user_instruction(stage);

                if last_user.is_none() || last_user == Some("root".to_string()) {
                    let line = stage.instructions.first()
                        .and_then(|ins| get_line_number(ins, content));

                    findings.push(Finding {
                        kind: id.clone(),
                        description: format!("Stage {}: {}", stage.index, message),
                        risk: severity_to_risk(severity),
                        line,
                    });
                }
            }
        }
    }

    findings
}

/// Checks the entire Dockerfile against file-scoped rules.
fn check_file_rules(
    rules: &[Rule],
    df: &Dockerfile,
    path: &Path,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in rules {
        if let Rule::File { id, when, severity, message, .. } = rule {
            if when.requires_dockerignore_if_copy_dot {
                let has_copy_dot = df.iter_stages().any(|stage| {
                    stage.instructions.iter().any(|ins| {
                        matches!(ins, Instruction::Copy(c) if c.sources.iter().any(|s| s.content == "."))
                    })
                });

                if has_copy_dot {
                    let dockerignore = path.parent()
                        .map(|p| p.join(".dockerignore"))
                        .filter(|p| p.exists());

                    if dockerignore.is_none() {
                        findings.push(Finding {
                            kind: id.clone(),
                            description: message.clone(),
                            risk: severity_to_risk(severity),
                            line: None,
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Converts a rule severity to a risk level.
fn severity_to_risk(severity: &Severity) -> RiskLevel {
    match severity {
        Severity::Info => RiskLevel::Informative,
        Severity::Low => RiskLevel::Low,
        Severity::Medium => RiskLevel::Medium,
        Severity::High | Severity::Critical => RiskLevel::High,
    }
}

/// Filters rules based on only/exclude sets.
///
/// # Arguments
///
/// * `rules` - Mutable reference to rules vector
/// * `only` - Optional set of rule IDs to include exclusively
/// * `exclude` - Optional set of rule IDs to exclude
fn filter_rules(
    rules: &mut Vec<Rule>,
    only: Option<&Vec<String>>,
    exclude: Option<&Vec<String>>,
) {
    use std::collections::HashSet;

    if let Some(only_set) = only {
        let only_ids: HashSet<&str> = only_set.iter().map(|s| s.as_str()).collect();
        rules.retain(|rule| {
            let rule_id = get_rule_id(rule);
            only_ids.contains(rule_id)
        });
    } else if let Some(exclude_set) = exclude {
        let exclude_ids: HashSet<&str> = exclude_set.iter().map(|s| s.as_str()).collect();
        rules.retain(|rule| {
            let rule_id = get_rule_id(rule);
            !exclude_ids.contains(rule_id)
        });
    }
}

/// Gets the rule ID from a Rule enum.
fn get_rule_id(rule: &Rule) -> &str {
    match rule {
        Rule::Instruction { id, .. } => id,
        Rule::Stage { id, .. } => id,
        Rule::File { id, .. } => id,
    }
}

/// Filters findings by severity level(s).
///
/// # Arguments
///
/// * `findings` - Mutable reference to findings vector
/// * `severity` - Optional exact severity levels to match
/// * `min_severity` - Optional minimum severity threshold
fn filter_findings_by_severity(
    findings: &mut Vec<Finding>,
    severity: Option<&Vec<crate::cli::SeverityLevel>>,
    min_severity: Option<&crate::cli::SeverityLevel>,
) {
    if let Some(severity_levels) = severity {
        // Filter by exact severity match
        let target_risks: Vec<RiskLevel> = severity_levels
            .iter()
            .map(severity_level_to_risk)
            .collect();

        findings.retain(|f| target_risks.contains(&f.risk));
    } else if let Some(min_sev) = min_severity {
        // Filter by minimum severity
        let min_risk = severity_level_to_risk(min_sev);
        findings.retain(|f| f.risk >= min_risk);
    }
}

/// Converts CLI SeverityLevel to RiskLevel.
fn severity_level_to_risk(level: &crate::cli::SeverityLevel) -> RiskLevel {
    use crate::cli::SeverityLevel;

    match level {
        SeverityLevel::Informative => RiskLevel::Informative,
        SeverityLevel::Low => RiskLevel::Low,
        SeverityLevel::Medium => RiskLevel::Medium,
        SeverityLevel::High => RiskLevel::High,
    }
}

/// Determines if the scan should fail based on fail_on threshold.
///
/// # Arguments
///
/// * `findings` - Findings from the scan
/// * `fail_on` - Optional minimum severity level to trigger failure
///
/// # Returns
///
/// `true` if any finding meets or exceeds the fail_on threshold
fn should_fail_scan(
    findings: &[Finding],
    fail_on: Option<&crate::cli::SeverityLevel>,
) -> bool {
    if let Some(threshold) = fail_on {
        let threshold_risk = severity_level_to_risk(threshold);
        findings.iter().any(|f| f.risk >= threshold_risk)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::dockerfile::yaml_rules::{Matcher, Rule, Severity, StageWhen};
    use dockerfile_parser::Dockerfile;

    #[test]
    fn test_severity_to_risk_info() {
        assert_eq!(severity_to_risk(&Severity::Info), RiskLevel::Informative);
    }

    #[test]
    fn test_severity_to_risk_low() {
        assert_eq!(severity_to_risk(&Severity::Low), RiskLevel::Low);
    }

    #[test]
    fn test_severity_to_risk_medium() {
        assert_eq!(severity_to_risk(&Severity::Medium), RiskLevel::Medium);
    }

    #[test]
    fn test_severity_to_risk_high() {
        assert_eq!(severity_to_risk(&Severity::High), RiskLevel::High);
    }

    #[test]
    fn test_severity_to_risk_critical() {
        assert_eq!(severity_to_risk(&Severity::Critical), RiskLevel::High);
    }

    #[test]
    fn test_check_instruction_rules_from_latest() {
        let dockerfile = "FROM nginx:latest";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[0];

        let rules = vec![
            Rule::Instruction {
                id: "DF001".to_string(),
                name: Some("No latest tag".to_string()),
                kind: "FROM".to_string(),
                matcher: Matcher {
                    all: None,
                    any: None,
                    field: Some("from.tag".to_string()),
                    equals: Some("latest".to_string()),
                    regex: None,
                    glob: None,
                    missing: None,
                },
                severity: Severity::Medium,
                message: "Base image uses latest tag".to_string(),
                remediation: "Pin to specific version".to_string(),
                tags: vec![],
            }
        ];

        let findings = check_instruction_rules(&rules, instruction, 0, dockerfile);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "DF001");
        assert_eq!(findings[0].risk, RiskLevel::Medium);
        assert_eq!(findings[0].line, Some(1));
    }

    #[test]
    fn test_check_instruction_rules_from_pinned() {
        let dockerfile = "FROM nginx:1.20";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[0];

        let rules = vec![
            Rule::Instruction {
                id: "DF001".to_string(),
                name: Some("No latest tag".to_string()),
                kind: "FROM".to_string(),
                matcher: Matcher {
                    all: None,
                    any: None,
                    field: Some("from.tag".to_string()),
                    equals: Some("latest".to_string()),
                    regex: None,
                    glob: None,
                    missing: None,
                },
                severity: Severity::Medium,
                message: "Base image uses latest tag".to_string(),
                remediation: "Pin to specific version".to_string(),
                tags: vec![],
            }
        ];

        let findings = check_instruction_rules(&rules, instruction, 0, dockerfile);

        // Should not match because tag is "1.20", not "latest"
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_check_instruction_rules_user_root() {
        let dockerfile = "FROM nginx\nUSER root";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[1];

        let rules = vec![
            Rule::Instruction {
                id: "DF002".to_string(),
                name: Some("No root user".to_string()),
                kind: "USER".to_string(),
                matcher: Matcher {
                    all: None,
                    any: None,
                    field: Some("user".to_string()),
                    equals: Some("root".to_string()),
                    regex: None,
                    glob: None,
                    missing: None,
                },
                severity: Severity::High,
                message: "Container runs as root".to_string(),
                remediation: "Use a non-root user".to_string(),
                tags: vec![],
            }
        ];

        let findings = check_instruction_rules(&rules, instruction, 0, dockerfile);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "DF002");
        assert_eq!(findings[0].risk, RiskLevel::High);
        assert_eq!(findings[0].line, Some(2));
    }

    #[test]
    fn test_check_instruction_rules_wrong_kind() {
        let dockerfile = "FROM nginx\nRUN apt-get update";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();
        let instruction = &stage.instructions[1]; // RUN instruction

        let rules = vec![
            Rule::Instruction {
                id: "DF001".to_string(),
                name: Some("Test".to_string()),
                kind: "FROM".to_string(), // Rule targets FROM, not RUN
                matcher: Matcher {
                    all: None,
                    any: None,
                    field: None,
                    equals: None,
                    regex: None,
                    glob: None,
                    missing: None,
                },
                severity: Severity::Low,
                message: "Test".to_string(),
                remediation: "Test".to_string(),
                tags: vec![],
            }
        ];

        let findings = check_instruction_rules(&rules, instruction, 0, dockerfile);

        // Should not match because instruction kind doesn't match
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_check_stage_rules_must_end_non_root_no_user() {
        let dockerfile = "FROM nginx\nRUN apt-get update";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();

        let rules = vec![
            Rule::Stage {
                id: "DF100".to_string(),
                name: Some("Must end as non-root".to_string()),
                when: StageWhen {
                    must_end_non_root: true,
                },
                severity: Severity::High,
                message: "Stage does not end with non-root user".to_string(),
                remediation: "Add USER directive".to_string(),
                tags: vec![],
            }
        ];

        let findings = check_stage_rules(&rules, &stage, dockerfile);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "DF100");
        assert_eq!(findings[0].risk, RiskLevel::High);
    }

    #[test]
    fn test_check_stage_rules_must_end_non_root_with_root() {
        let dockerfile = "FROM nginx\nUSER root";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();

        let rules = vec![
            Rule::Stage {
                id: "DF100".to_string(),
                name: Some("Must end as non-root".to_string()),
                when: StageWhen {
                    must_end_non_root: true,
                },
                severity: Severity::High,
                message: "Stage ends with root user".to_string(),
                remediation: "Use non-root user".to_string(),
                tags: vec![],
            }
        ];

        let findings = check_stage_rules(&rules, &stage, dockerfile);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "DF100");
    }

    #[test]
    fn test_check_stage_rules_must_end_non_root_with_nobody() {
        let dockerfile = "FROM nginx\nUSER nobody";
        let parsed = Dockerfile::parse(dockerfile).unwrap();
        let stage = parsed.iter_stages().next().unwrap();

        let rules = vec![
            Rule::Stage {
                id: "DF100".to_string(),
                name: Some("Must end as non-root".to_string()),
                when: StageWhen {
                    must_end_non_root: true,
                },
                severity: Severity::High,
                message: "Stage does not end with non-root user".to_string(),
                remediation: "Add USER directive".to_string(),
                tags: vec![],
            }
        ];

        let findings = check_stage_rules(&rules, &stage, dockerfile);

        // Should not match because stage ends with "nobody"
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_scan_instructions_multiple_findings() {
        let dockerfile = "FROM nginx:latest\nUSER root\nFROM alpine:latest";
        let parsed = Dockerfile::parse(dockerfile).unwrap();

        let rules = vec![
            Rule::Instruction {
                id: "DF001".to_string(),
                name: Some("No latest tag".to_string()),
                kind: "FROM".to_string(),
                matcher: Matcher {
                    all: None,
                    any: None,
                    field: Some("from.tag".to_string()),
                    equals: Some("latest".to_string()),
                    regex: None,
                    glob: None,
                    missing: None,
                },
                severity: Severity::Medium,
                message: "Base image uses latest tag".to_string(),
                remediation: "Pin to specific version".to_string(),
                tags: vec![],
            },
            Rule::Instruction {
                id: "DF002".to_string(),
                name: Some("No root user".to_string()),
                kind: "USER".to_string(),
                matcher: Matcher {
                    all: None,
                    any: None,
                    field: Some("user".to_string()),
                    equals: Some("root".to_string()),
                    regex: None,
                    glob: None,
                    missing: None,
                },
                severity: Severity::High,
                message: "Container runs as root".to_string(),
                remediation: "Use a non-root user".to_string(),
                tags: vec![],
            }
        ];

        let findings = scan_instructions(&parsed, &rules, dockerfile);

        // Should find 2 FROM:latest + 1 USER root = 3 findings
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn test_scan_stages_multiple_stages() {
        let dockerfile = "FROM nginx\nRUN test\n\nFROM alpine\nUSER nobody";
        let parsed = Dockerfile::parse(dockerfile).unwrap();

        let rules = vec![
            Rule::Stage {
                id: "DF100".to_string(),
                name: Some("Must end as non-root".to_string()),
                when: StageWhen {
                    must_end_non_root: true,
                },
                severity: Severity::High,
                message: "Stage does not end with non-root user".to_string(),
                remediation: "Add USER directive".to_string(),
                tags: vec![],
            }
        ];

        let findings = scan_stages(&parsed, &rules, dockerfile);

        // First stage has no USER, second has USER nobody
        // Only first stage should trigger
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("Stage 0"));
    }
}

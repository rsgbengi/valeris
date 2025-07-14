use std::{collections::HashSet, fs, path::Path};

use anyhow::{Context, Result};
use itertools::Itertools;
use jsonpath_lib as jsonpath;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::docker::model::{Finding, RiskLevel};

type Bucket     = Vec<String>;          // Value for just one part
type Buckets    = Vec<Bucket>;          // All parts
#[allow(dead_code)]
type Combos<'a> = Vec<&'a String>;      // One combination -> Future phase

// ──────────────────────────────── Rules ────────────────────────────────
#[derive(Debug, Deserialize)]
pub struct YamlRule {
    pub id: String,
    pub name: Option<String>,
    pub target: Option<String>,
    pub severity: Option<String>,
    #[allow(dead_code)]
    pub description: Option<String>,
    #[allow(dead_code)]
    #[serde(default)] pub references: Vec<String>,
    #[serde(rename = "match")] pub matcher: RuleMatcher,
    pub message: String,
    #[allow(dead_code)]
    pub fix: Option<String>,
    #[serde(default)] pub include_match_in_description: bool,
}

#[derive(Debug, Deserialize)]
pub struct RuleMatcher {
    #[serde(default)] pub parts:     Option<Vec<MatchPart>>,
    #[serde(default)] pub separator: Option<String>,
    #[serde(default)] pub equals:    Option<String>,
    #[serde(default)] pub regex:     Option<String>,
    #[serde(default)] pub jsonpath:  Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MatchPart {
    pub jsonpath: String,
}

// ───────────────────────────── Engine ───────────────────────────────────
pub struct YamlRuleEngine {
    rules: Vec<YamlRule>,
}

impl YamlRuleEngine {
    pub fn rules(&self) -> &Vec<YamlRule> {
        &self.rules
    }
    // ------------ Rule Loader --------------------------------------
    pub fn from_dir(base: &Path) -> Result<Self> {
    let dir = base.join("docker");

    let mut rules = Vec::new();
    if dir.exists() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                let contents = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let rule: YamlRule = serde_yaml::from_str(&contents)
                    .with_context(|| format!("parsing {}", path.display()))?;
                rules.push(rule);
            }
        }
    }
    println!("Loaded {} YAML rules from {}", rules.len(), dir.display());
    Ok(Self { rules })
}



    // ------------ Public API ------------------------------------------
    pub fn scan_value(&self, value: &Value) -> Vec<Finding> {
        self.rules
            .iter()
            .flat_map(|rule| self.scan_with_rule(rule, value))
            .collect()
    }

    // ------------ Apply a rule ---------------------------
    fn scan_with_rule(&self, rule: &YamlRule, value: &Value) -> Vec<Finding> {
        let sep = rule.matcher.separator.as_deref().unwrap_or(":");

        // 1️Collect possible matches
        let matches = if let Some(ref parts) = rule.matcher.parts {
            self.matches_from_parts(parts, sep, &rule.matcher, value)
        } else if let Some(ref expr) = rule.matcher.jsonpath {
            self.matches_from_jsonpath(expr, &rule.matcher, value)
        } else {
            Vec::new()
        };

        // 2️No matches found
        if matches.is_empty() {
            return Vec::new();
        }

        // 3️Remove duplicates
        let mut seen = HashSet::new();
        let unique = matches
            .into_iter()
            .filter(|m| seen.insert(m.clone()))
            .collect::<Vec<_>>();

        // Convert to findings
        let risk = risk_from_severity(rule.severity.as_deref());
        unique
            .into_iter()
            .map(|mv| to_finding(rule, &mv, risk.clone()))
            .collect()
    }

    // ------------ Matching Helpers ----------------------------------
    fn matches_from_parts(
        &self,
        parts: &[MatchPart],
        sep: &str,
        matcher: &RuleMatcher,
        value: &Value,
    ) -> Vec<String> {
        let buckets: Buckets = parts
            .iter()
            .filter_map(|part| jsonpath::select(value, &part.jsonpath).ok())
            .map(|nodes| {
                nodes
                    .iter()
                    .map(|n| n.to_string().trim_matches('"').to_string())
                    .collect::<Bucket>()
            })
            .filter(|bucket| !bucket.is_empty())
            .collect();

        if buckets.is_empty() || buckets.iter().any(|b| b.is_empty()) {
            return Vec::new();
        }

        buckets
            .iter()
            .map(|b| b.as_slice())
            .multi_cartesian_product()
            .filter_map(|combo| {
                let combined = combo.iter().join(sep);
                matcher_matches(&combined, matcher).then_some(combined)
            })
            .collect()
    }

    fn matches_from_jsonpath(
        &self,
        expr: &str,
        matcher: &RuleMatcher,
        value: &Value,
    ) -> Vec<String> {
        jsonpath::select(value, expr)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|n| {
                let s = n.to_string().trim_matches('"').to_string();
                matcher_matches(&s, matcher).then_some(s)
            })
            .collect()
    }
}

// ─────────────────────────── Helpers ──────────────────────────────
fn matcher_matches(value: &str, matcher: &RuleMatcher) -> bool {
    match (&matcher.equals, &matcher.regex) {
        (Some(expected), _) => value == expected,
        (None, Some(pattern)) => Regex::new(pattern)
            .map(|re| re.is_match(value))
            .unwrap_or(false),
        _ => true,
    }
}

fn risk_from_severity(s: Option<&str>) -> RiskLevel {
    match s.unwrap_or("MEDIUM").to_ascii_uppercase().as_str() {
        "INFORMATIVE" | "INFO" => RiskLevel::Informative,
        "LOW"       => RiskLevel::Low,
        "HIGH" | "CRITICAL" => RiskLevel::High,
        _           => RiskLevel::Medium,
    }
}

fn to_finding(rule: &YamlRule, mv: &str, risk: RiskLevel) -> Finding {
    let mut desc = rule.message.replace("{{match}}", mv);
    if rule.include_match_in_description {
        desc = format!("{}: {}", desc, mv);
    }
    Finding {
        kind: rule.id.clone(),
        description: desc,
        risk,
    }
}

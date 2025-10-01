//! YAML rule definitions for Dockerfile scanning.
//!
//! This module defines the structure of YAML rules used to detect
//! security issues and misconfigurations in Dockerfiles.
//!
//! # Rule Types
//!
//! Rules can operate at three different scopes:
//!
//! * **Instruction** - Checks individual Dockerfile instructions (FROM, RUN, USER, etc.)
//! * **Stage** - Checks entire build stages (multi-stage builds)
//! * **File** - Checks file-level properties (e.g., .dockerignore existence)
//!
//! # Example Rule
//!
//! ```yaml
//! version: 1
//! rules:
//!   - id: DF001
//!     name: Disallow latest tag
//!     scope: instruction
//!     kind: FROM
//!     match:
//!       field: from.tag
//!       equals: latest
//!     severity: medium
//!     message: "Base image uses mutable latest tag"
//!     remediation: "Pin to specific version"
//!     tags: [reproducibility]
//! ```

use regex::Regex;
use serde::Deserialize;
use anyhow::Context;
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub version: u32,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all="lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
}

#[derive(Debug, Deserialize)]
#[serde(tag = "scope", rename_all="lowercase", deny_unknown_fields)]
pub enum Rule {
    Instruction {
        id: String,
        name: Option<String>,
        kind: String,
        #[serde(rename = "match")]
        matcher: Matcher,
        severity: Severity,
        message: String,
        remediation: String,
        #[serde(default)]
        tags:Vec<String>,
    },

    Stage {
        id: String,
        name: Option<String>,
        when: StageWhen,
        severity: Severity,
        message: String,
        remediation: String,
        tags: Vec<String>,
    },
    File {
        id: String,
        name: Option<String>,
        when: FileWhen,
        severity: Severity,
        message:String,
        remediation: String,
        tags: Vec<String>,
    }
}

mod optional_regex {
    use regex::Regex;
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize <'de, D>(deserializer: D) -> Result<Option<Regex>,D::Error> where D: Deserializer<'de>,{
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(regex_str) => {
                Regex::new(&regex_str).map(Some).map_err(serde::de::Error::custom)
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    #[serde(default)]
    pub all: Option<Vec<Predicate>>,
    #[serde(default)]
    pub any: Option<Vec<Predicate>>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub equals: Option<String>,
    #[serde(default, deserialize_with = "optional_regex::deserialize")]
    pub regex: Option<Regex>,
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub missing: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predicate {
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub equals: Option<serde_yaml::Value>,
    #[serde(default, deserialize_with = "optional_regex::deserialize")]
    pub regex: Option<Regex>,
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub missing: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StageWhen {
    #[serde(default)]
    pub must_end_non_root: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileWhen {
    #[serde(default)]
    pub requires_dockerignore_if_copy_dot: bool,
}


pub fn load_rules_from_dir(dir: &Path) -> anyhow::Result<RuleSet> {
    let mut out = RuleSet {
        version: 1,
        rules: Vec::new(),
    };
    for entry in std::fs::read_dir(dir)?{
        let path = entry?.path();
        if path.extension().map(|e| e == "yml" || e == "yaml").unwrap_or(false){
            let content = std::fs::read_to_string(&path).with_context(|| format!("Reading {}", path.display()))?;
            let parsed: RuleSet = serde_yaml::from_str(&content).with_context(|| format!("Parsing yaml in {}", path.display()))?;
            out.rules.extend(parsed.rules);
        }
    }
    Ok(out)

}

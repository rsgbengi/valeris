use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use valeris::docker::model::Finding;
use valeris::yaml_rules::YamlRuleEngine;

const DETECTOR_DIR: &str = "rules/runtime";
const TEST_DATA_DIR: &str = "tests/data";

fn engine() -> YamlRuleEngine {
    YamlRuleEngine::from_dir(Path::new(DETECTOR_DIR)).expect("cannot load detectors")
}

fn read_json<P: AsRef<Path>>(p: P) -> Result<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(&p)?)?)
}

fn test_cases() -> Vec<(String, PathBuf, PathBuf)> {
    WalkDir::new(TEST_DATA_DIR)
        .min_depth(1)                 
        .max_depth(1)
        .into_iter()
        .filter_map(|e| {
            let dir = e.ok()?;
            if !dir.file_type().is_dir() {
                return None;           
            }
            let name = dir.file_name().to_string_lossy().into_owned();
            let input     = dir.path().join("input.json");
            let expected  = dir.path().join("expected.json");
            if input.exists() {
                Some((name, input, expected))
            } else {
                None                   
            }
        })
        .collect()
}


#[test]
fn yaml_detector_cases_pass() -> Result<()> {
    let engine = engine();
    for (name, input_path, expected_path) in test_cases() {
        if let Some(rule) = engine.rules().iter().find(|r| r.id == name) {
            let title = rule.name.as_deref().unwrap_or("");
            println!("▶  Testing YAML '{}' – {}", rule.id, title);
        } else {
            println!("▶  Testing YAML '{}'", name);
        }

        if !expected_path.exists() {
            continue;
        }
        let input =
            read_json(&input_path).with_context(|| format!("reading input for case '{name}'"))?;
        let mut got = engine.scan_value(&input);
        println!("  - found {} findings", got.len());

        let expected: Vec<Finding> = serde_json::from_value(read_json(&expected_path)?)?;

        got.sort_by(|a, b| a.kind.cmp(&b.kind));
        let mut exp = expected;
        exp.sort_by(|a, b| a.kind.cmp(&b.kind));

        assert_eq!(got, exp, "case '{name}' mismatch");
    }
    Ok(())
}


#[test]
fn insta_snapshots() {
    let engine = engine();

    for (name, input_path, _) in test_cases() {
        let input = read_json(&input_path).expect("read json input");
        let findings = engine.scan_value(&input);

        insta::assert_json_snapshot!(name, findings);
    }
}

#[test]
fn yaml_catalog_is_consistent() -> Result<()> {
    let engine = engine();
    let mut ids = std::collections::HashSet::new();
    let allowed: std::collections::HashSet<_> = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    for r in engine.rules() {
        assert!(ids.insert(&r.id), "duplicated rule id '{}'", r.id);

        if let Some(sev) = &r.severity {
            let sev_up = sev.to_ascii_uppercase();
            assert!(
                allowed.contains(&sev_up),
                "invalid severity '{}' in rule {}",
                sev,
                r.id
            );
        }
    }

    Ok(())
}

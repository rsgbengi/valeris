//! Integration tests for YAML detectors using `insta` snapshots.
//!
//! Coloca este archivo en `tests/yaml_detectors.rs`.
//!
//! Cada archivo JSON dentro de `tests/data/` se tomará como caso de prueba.
//! Si existe un fichero `tests/data/<nombre>.expected.json`, se usará para
//! comparación tradicional.  Si no existe, el test dependerá únicamente del
//! snapshot generado/validado por `insta`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

use valeris::docker::model::Finding;
use valeris::yaml_rules::YamlRuleEngine;

/// Directorio donde residen las reglas YAML de Docker.
const DETECTOR_DIR: &str = "rules/runtime/docker";
/// Directorio con los ficheros JSON de entrada de pruebas.
const TEST_DATA_DIR: &str = "tests/data";

/// Instancia preparada del motor de reglas.
fn engine() -> YamlRuleEngine {
    YamlRuleEngine::from_dir(Path::new(DETECTOR_DIR)).expect("cannot load detectors")
}

/// Lee y deserializa un archivo JSON.
fn read_json<P: AsRef<Path>>(p: P) -> Result<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(&p)?)?)
}

/// Reúne cada caso de prueba (id, input.json, expected.json)
fn test_cases() -> Vec<(String, PathBuf, PathBuf)> {
    WalkDir::new(TEST_DATA_DIR)
        .min_depth(1)                 // solo subdirectorios directos
        .max_depth(1)
        .into_iter()
        .filter_map(|e| {
            let dir = e.ok()?;
            if !dir.file_type().is_dir() {
                return None;           // saltar ficheros sueltos
            }
            let name = dir.file_name().to_string_lossy().into_owned();
            let input     = dir.path().join("input.json");
            let expected  = dir.path().join("expected.json");
            if input.exists() {
                Some((name, input, expected))
            } else {
                None                   // carpeta sin input.json -> ignorar
            }
        })
        .collect()
}


// -----------------------------------------------------------------------------
// Test clásico contra un archivo expected.json (opcional)
// -----------------------------------------------------------------------------
#[test]
fn yaml_detector_cases_pass() -> Result<()> {
    let engine = engine();
    for (name, input_path, expected_path) in test_cases() {
        // imprime el ID y (si existe) el nombre de la regla
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

        let expected: Vec<Finding> = serde_json::from_value(read_json(&expected_path)?)?;

        got.sort_by(|a, b| a.kind.cmp(&b.kind));
        let mut exp = expected;
        exp.sort_by(|a, b| a.kind.cmp(&b.kind));

        assert_eq!(got, exp, "case '{name}' mismatch");
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Snapshot con `insta`
// -----------------------------------------------------------------------------
#[test]
fn insta_snapshots() {
    let engine = engine();

    for (name, input_path, _) in test_cases() {
        let input = read_json(&input_path).expect("read json input");
        let findings = engine.scan_value(&input);

        insta::assert_json_snapshot!(name, findings);
    }
}

// -----------------------------------------------------------------------------
// Sanidad del catálogo: ids únicos y severities válidas
// -----------------------------------------------------------------------------
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

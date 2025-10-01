use super::model::{ContainerResult, RiskLevel};
use crate::cli::OutputFormat;

use bollard::secret::ContainerInspectResponse;
use serde::Serialize;

#[derive(Serialize)]
pub struct ExportableFinding {
    pub kind: String,
    pub description: String,
    pub risk: RiskLevel,
}

#[derive(Serialize)]
pub struct ExportableContainerResult {
    pub container_id: String,
    pub container_name: String,
    pub findings: Vec<ExportableFinding>,
}

fn get_id(container: &ContainerInspectResponse) -> String {
    container.id.clone().unwrap_or_default()
}

fn get_name(container: &ContainerInspectResponse) -> String {
    container
        .name
        .clone()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string()
}

fn to_exportable_json(results: &[ContainerResult]) -> Vec<ExportableContainerResult> {
    results
        .iter()
        .map(|r| {
            let id = get_id(&r.container);
            let name = get_name(&r.container);

            let findings = r
                .findings
                .iter()
                .map(|f| ExportableFinding {
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

fn to_exportable_csv(results: &[ContainerResult]) -> Vec<ExportableFinding> {
    results
        .iter()
        .flat_map(|r| {
            r.findings.iter().map(move |f| ExportableFinding {
                kind: f.kind.clone(),
                description: f.description.clone(),
                risk: f.risk.clone(),
            })
        })
        .collect()
}

pub fn export_findings_grouped(
    results: &[ContainerResult],
    format: &OutputFormat,
    output: &Option<String>,
) {
    match format {
        OutputFormat::Table => {
            // Table format is handled separately in scan command
            // This shouldn't be called for Table format
        }
        OutputFormat::Json => {
            let data = to_exportable_json(results);
            let json = serde_json::to_string_pretty(&data).unwrap();
            match output {
                Some(path) => {
                    std::fs::write(path, json).expect("Failed to write JSON file");
                    println!("✅ JSON exported to {path}");
                }
                None => println!("{json}"),
            }
        }
        OutputFormat::Csv => {
            let data = to_exportable_csv(results);
            let writer: Box<dyn std::io::Write> = match output {
                Some(path) => Box::new(std::fs::File::create(path).expect("Failed to write CSV")),
                None => Box::new(std::io::stdout()),
            };

            let mut wtr = csv::Writer::from_writer(writer);
            for row in data {
                wtr.serialize(row).unwrap();
            }
            wtr.flush().unwrap();

            if let Some(path) = output {
                println!("✅ CSV exported to {path}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker::model::{ContainerResult, Finding, RiskLevel};
    use bollard::models::ContainerInspectResponse;

    fn mock_container(id: &str, name: &str) -> ContainerInspectResponse {
        ContainerInspectResponse {
            id: Some(id.to_string()),
            name: Some(name.to_string()),
            ..Default::default()
        }
    }

    fn mock_finding(kind: &str, description: &str, risk: RiskLevel) -> Finding {
        Finding {
            kind: kind.to_string(),
            description: description.to_string(),
            risk,
            line: None,
        }
    }

    #[test]
    fn test_to_exportable_json_single_result() {
        let container = mock_container("abc123", "/my-container");
        let finding = mock_finding("secrets", "API key found", RiskLevel::High);

        let result = ContainerResult {
            container,
            findings: vec![finding],
        };

        let json_result = to_exportable_json(&[result]);
        assert_eq!(json_result.len(), 1);
        assert_eq!(json_result[0].container_id, "abc123");
        assert_eq!(json_result[0].container_name, "my-container");
        assert_eq!(json_result[0].findings.len(), 1);
        assert_eq!(json_result[0].findings[0].risk, RiskLevel::High);
    }

    #[test]
    fn test_to_exportable_csv_flattening() {
        let container = mock_container("c1", "/csv-test");
        let f1 = mock_finding("mount", "mounted /proc", RiskLevel::Medium);
        let f2 = mock_finding("capabilities", "SYS_ADMIN present", RiskLevel::High);

        let result = ContainerResult {
            container,
            findings: vec![f1, f2],
        };

        let csv_rows = to_exportable_csv(&[result]);
        assert_eq!(csv_rows.len(), 2);
        assert_eq!(csv_rows[0].kind, "mount");
        assert_eq!(csv_rows[1].kind, "capabilities");
    }

    #[test]
    fn test_json_serialization_format() {
        let container = mock_container("j123", "/json-test");
        let finding = mock_finding("pid_mode", "host PID mode enabled", RiskLevel::Low);

        let results = vec![ContainerResult {
            container,
            findings: vec![finding],
        }];

        let export = to_exportable_json(&results);
        let json = serde_json::to_string(&export).unwrap();
        assert!(json.contains("pid_mode"));
        assert!(json.contains("host PID mode enabled"));
        assert!(json.contains("j123"));
        assert!(json.contains("json-test"));
    }

    #[test]
    fn test_csv_serialization_format() {
        let container = mock_container("csv-id", "/csv-write");
        let finding = mock_finding(
            "readonly_rootfs",
            "rootfs is writable",
            RiskLevel::Informative,
        );

        let export_rows = to_exportable_csv(&[ContainerResult {
            container,
            findings: vec![finding],
        }]);

        let mut wtr = csv::Writer::from_writer(vec![]);
        for row in &export_rows {
            wtr.serialize(row).unwrap();
        }
        let data = String::from_utf8(wtr.into_inner().unwrap()).unwrap();
        assert!(data.contains("readonly_rootfs"));
        assert!(data.contains("rootfs is writable"));
    }

    #[test]
    fn test_export_findings_grouped_json_to_file() {
        use crate::cli::OutputFormat;
        use std::fs;
        use tempfile::NamedTempFile;

        let container = mock_container("json123", "/json-container");
        let finding = mock_finding("network", "host network mode", RiskLevel::Medium);

        let results = vec![ContainerResult {
            container,
            findings: vec![finding],
        }];

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path().to_path_buf();
        export_findings_grouped(
            &results,
            &OutputFormat::Json,
            &Some(path.to_string_lossy().into()),
        );

        let content = fs::read_to_string(path).expect("Failed to read exported JSON");
        assert!(content.contains("network"));
        assert!(content.contains("host network mode"));
        assert!(content.contains("json123"));
    }

    #[test]
    fn test_export_findings_grouped_csv_to_file() {
        use crate::cli::OutputFormat;
        use std::fs;
        use tempfile::NamedTempFile;

        let container = mock_container("csv123", "/csv-container");
        let finding = mock_finding("capabilities", "SYS_ADMIN found", RiskLevel::High);

        let results = vec![ContainerResult {
            container,
            findings: vec![finding],
        }];

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path().to_path_buf();
        export_findings_grouped(
            &results,
            &OutputFormat::Csv,
            &Some(path.to_string_lossy().into()),
        );

        let content = fs::read_to_string(path).expect("Failed to read exported CSV");
        assert!(content.contains("capabilities"));
        assert!(content.contains("SYS_ADMIN found"));
        assert!(content.contains("High"));
    }
}

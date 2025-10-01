//! Export functionality for Dockerfile scan results.
//!
//! This module handles exporting scan findings to various formats
//! including JSON and CSV.

use crate::docker::model::{Finding, RiskLevel};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::path::PathBuf;

/// Exportable representation of a Dockerfile scan result.
///
/// This structure contains the complete scan results with metadata
/// that can be serialized to JSON or CSV formats.
///
/// # Fields
///
/// * `dockerfile_path` - Full path to the scanned Dockerfile
/// * `total_findings` - Total number of issues found
/// * `critical_count` - Number of critical severity findings
/// * `medium_count` - Number of medium severity findings
/// * `low_count` - Number of low severity findings
/// * `info_count` - Number of informational findings
/// * `findings` - Detailed list of all findings
///
/// # Example JSON Output
///
/// ```json
/// {
///   "dockerfile_path": "./Dockerfile",
///   "total_findings": 5,
///   "critical_count": 2,
///   "medium_count": 2,
///   "low_count": 1,
///   "info_count": 0,
///   "findings": [...]
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct DockerfileScanResult {
    pub dockerfile_path: String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub findings: Vec<ExportableFinding>,
}

/// Exportable representation of a single finding.
///
/// Represents a single security issue or misconfiguration detected
/// in the Dockerfile.
///
/// # Fields
///
/// * `id` - Rule identifier (e.g., "DF001", "DF002")
/// * `severity` - Human-readable severity: "CRITICAL", "MEDIUM", "LOW", "INFO"
/// * `line` - Line number where the issue was found (None for file-level issues)
/// * `description` - Detailed description of the finding
///
/// # Example
///
/// ```json
/// {
///   "id": "DF006",
///   "severity": "CRITICAL",
///   "line": 5,
///   "description": "Possible hardcoded secret in ENV variable"
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportableFinding {
    pub id: String,
    pub severity: String,
    pub line: Option<usize>,
    pub description: String,
}

impl DockerfileScanResult {
    /// Creates a new scan result from a path and findings.
    ///
    /// Aggregates findings and calculates severity counts for the report.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the Dockerfile that was scanned
    /// * `findings` - Slice of findings detected during the scan
    ///
    /// # Returns
    ///
    /// A new `DockerfileScanResult` with aggregated statistics
    ///
    /// # Example
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use valeris::docker::model::{Finding, RiskLevel};
    /// use valeris::detectors::dockerfile::exporters::DockerfileScanResult;
    ///
    /// let findings = vec![
    ///     Finding {
    ///         kind: "DF001".to_string(),
    ///         description: "Test finding".to_string(),
    ///         risk: RiskLevel::High,
    ///         line: Some(1),
    ///     }
    /// ];
    ///
    /// let result = DockerfileScanResult::new(&PathBuf::from("Dockerfile"), &findings);
    /// assert_eq!(result.total_findings, 1);
    /// assert_eq!(result.critical_count, 1);
    /// ```
    pub fn new(path: &PathBuf, findings: &[Finding]) -> Self {
        let (critical, medium, low, info) = count_by_severity(findings);

        Self {
            dockerfile_path: path.display().to_string(),
            total_findings: findings.len(),
            critical_count: critical,
            medium_count: medium,
            low_count: low,
            info_count: info,
            findings: findings.iter().map(ExportableFinding::from).collect(),
        }
    }
}

impl From<&Finding> for ExportableFinding {
    /// Converts a Finding to an ExportableFinding.
    ///
    /// Transforms internal finding representation to a format
    /// suitable for serialization (JSON/CSV).
    fn from(finding: &Finding) -> Self {
        Self {
            id: finding.kind.clone(),
            severity: severity_to_string(&finding.risk),
            line: finding.line,
            description: finding.description.clone(),
        }
    }
}

/// Exports scan results to JSON format.
///
/// Creates a structured JSON representation of scan results including
/// metadata and detailed findings. The output is pretty-printed for
/// readability.
///
/// # Arguments
///
/// * `path` - Path to the scanned Dockerfile
/// * `findings` - Slice of findings detected during the scan
///
/// # Returns
///
/// * `Ok(String)` - Pretty-printed JSON string
/// * `Err` - If JSON serialization fails
///
/// # Example Output
///
/// ```json
/// {
///   "dockerfile_path": "./Dockerfile",
///   "total_findings": 2,
///   "critical_count": 1,
///   "medium_count": 1,
///   "low_count": 0,
///   "info_count": 0,
///   "findings": [
///     {
///       "id": "DF006",
///       "severity": "CRITICAL",
///       "line": 5,
///       "description": "Possible hardcoded secret"
///     }
///   ]
/// }
/// ```
///
/// # Example
///
/// ```
/// use std::path::PathBuf;
/// use valeris::docker::model::{Finding, RiskLevel};
/// use valeris::detectors::dockerfile::exporters::to_json;
///
/// let findings = vec![
///     Finding {
///         kind: "DF001".to_string(),
///         description: "Test".to_string(),
///         risk: RiskLevel::High,
///         line: Some(1),
///     }
/// ];
///
/// let json = to_json(&PathBuf::from("test.Dockerfile"), &findings).unwrap();
/// assert!(json.contains("DF001"));
/// ```
pub fn to_json(path: &PathBuf, findings: &[Finding]) -> Result<String> {
    let result = DockerfileScanResult::new(path, findings);
    serde_json::to_string_pretty(&result)
        .map_err(|e| anyhow::anyhow!("Failed to serialize to JSON: {}", e))
}

/// Exports scan results to CSV format.
///
/// Creates a CSV representation with headers and one row per finding.
/// Suitable for importing into spreadsheets or data analysis tools.
///
/// # CSV Format
///
/// ```csv
/// dockerfile,severity,id,line,description
/// ./Dockerfile,CRITICAL,DF006,5,Hardcoded secret detected
/// ./Dockerfile,MEDIUM,DF001,1,Using latest tag
/// ```
///
/// # Arguments
///
/// * `path` - Path to the scanned Dockerfile
/// * `findings` - Slice of findings detected during the scan
///
/// # Returns
///
/// * `Ok(String)` - CSV formatted string with headers
/// * `Err` - If CSV serialization fails
///
/// # Example
///
/// ```
/// use std::path::PathBuf;
/// use valeris::docker::model::{Finding, RiskLevel};
/// use valeris::detectors::dockerfile::exporters::to_csv;
///
/// let findings = vec![
///     Finding {
///         kind: "DF001".to_string(),
///         description: "Test finding".to_string(),
///         risk: RiskLevel::Medium,
///         line: Some(3),
///     }
/// ];
///
/// let csv = to_csv(&PathBuf::from("test.Dockerfile"), &findings).unwrap();
/// assert!(csv.contains("dockerfile,severity,id,line,description"));
/// assert!(csv.contains("DF001"));
/// ```
pub fn to_csv(path: &PathBuf, findings: &[Finding]) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(vec![]);

    // Write header
    wtr.write_record(&["dockerfile", "severity", "id", "line", "description"])?;

    let dockerfile_path = path.display().to_string();

    // Write findings
    for finding in findings {
        wtr.write_record(&[
            &dockerfile_path,
            &severity_to_string(&finding.risk),
            &finding.kind,
            &finding.line.map(|n| n.to_string()).unwrap_or_else(|| "".to_string()),
            &finding.description,
        ])?;
    }

    let data = wtr.into_inner()
        .map_err(|e| anyhow::anyhow!("Failed to write CSV: {}", e))?;

    String::from_utf8(data)
        .map_err(|e| anyhow::anyhow!("Failed to convert CSV to string: {}", e))
}

/// Counts findings by severity level.
///
/// Iterates through findings and counts how many belong to each
/// severity category for summary statistics.
///
/// # Arguments
///
/// * `findings` - Slice of findings to count
///
/// # Returns
///
/// Tuple of `(critical, medium, low, info)` counts
///
/// # Example
///
/// ```
/// use valeris::docker::model::{Finding, RiskLevel};
///
/// let findings = vec![
///     Finding { kind: "1".into(), description: "".into(), risk: RiskLevel::High, line: None },
///     Finding { kind: "2".into(), description: "".into(), risk: RiskLevel::High, line: None },
///     Finding { kind: "3".into(), description: "".into(), risk: RiskLevel::Medium, line: None },
/// ];
///
/// // This is a private function, but shown for documentation
/// // let (critical, medium, low, info) = count_by_severity(&findings);
/// // assert_eq!(critical, 2);
/// // assert_eq!(medium, 1);
/// ```
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

/// Converts a risk level to a human-readable string.
///
/// Maps internal risk level enum to standardized severity strings
/// used in JSON and CSV exports.
///
/// # Arguments
///
/// * `risk` - The risk level to convert
///
/// # Returns
///
/// String representation: "CRITICAL", "MEDIUM", "LOW", or "INFO"
///
/// # Example
///
/// ```
/// use valeris::docker::model::RiskLevel;
///
/// // This is a private function, but shown for documentation
/// // let severity = severity_to_string(&RiskLevel::High);
/// // assert_eq!(severity, "CRITICAL");
/// ```
fn severity_to_string(risk: &RiskLevel) -> String {
    match risk {
        RiskLevel::High => "CRITICAL".to_string(),
        RiskLevel::Medium => "MEDIUM".to_string(),
        RiskLevel::Low => "LOW".to_string(),
        RiskLevel::Informative => "INFO".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_finding(id: &str, severity: RiskLevel, line: Option<usize>) -> Finding {
        Finding {
            kind: id.to_string(),
            description: format!("Test finding for {}", id),
            risk: severity,
            line,
        }
    }

    #[test]
    fn test_json_export() {
        let path = PathBuf::from("test.Dockerfile");
        let findings = vec![
            mock_finding("DF001", RiskLevel::Medium, Some(1)),
            mock_finding("DF002", RiskLevel::High, Some(5)),
        ];

        let json = to_json(&path, &findings).unwrap();
        assert!(json.contains("test.Dockerfile"));
        assert!(json.contains("DF001"));
        assert!(json.contains("CRITICAL"));
        assert!(json.contains("MEDIUM"));
    }

    #[test]
    fn test_csv_export() {
        let path = PathBuf::from("test.Dockerfile");
        let findings = vec![
            mock_finding("DF001", RiskLevel::Low, Some(3)),
        ];

        let csv = to_csv(&path, &findings).unwrap();
        assert!(csv.contains("dockerfile,severity,id,line,description"));
        assert!(csv.contains("test.Dockerfile"));
        assert!(csv.contains("DF001"));
        assert!(csv.contains("LOW"));
    }

    #[test]
    fn test_count_by_severity() {
        let findings = vec![
            mock_finding("DF001", RiskLevel::High, Some(1)),
            mock_finding("DF002", RiskLevel::High, Some(2)),
            mock_finding("DF003", RiskLevel::Medium, Some(3)),
            mock_finding("DF004", RiskLevel::Low, Some(4)),
        ];

        let (critical, medium, low, info) = count_by_severity(&findings);
        assert_eq!(critical, 2);
        assert_eq!(medium, 1);
        assert_eq!(low, 1);
        assert_eq!(info, 0);
    }
}

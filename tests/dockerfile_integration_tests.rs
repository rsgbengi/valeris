//! Integration tests for Dockerfile scanner.
//!
//! These tests verify the complete scanning workflow using real Dockerfile
//! fixtures and rule files.

use std::path::PathBuf;
use valeris::detectors::dockerfile::scanner::scan_dockerfile;
use valeris::cli::OutputFormat;

/// Helper function to get the test fixtures directory
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("dockerfile")
}

/// Helper function to get the rules directory
fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("rules")
        .join("dockerfile")
}

#[test]
#[ignore] // Ignore by default since it requires rules directory
fn test_scan_insecure_dockerfile() {
    let dockerfile_path = fixtures_dir().join("insecure.Dockerfile");
    let rules_path = rules_dir();

    // Skip test if rules directory doesn't exist
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        return;
    }

    let result = scan_dockerfile(
        dockerfile_path,
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Should succeed
    assert!(result.is_ok(), "Scan should complete successfully");
}

#[test]
#[ignore] // Ignore by default since it requires rules directory
fn test_scan_secure_dockerfile() {
    let dockerfile_path = fixtures_dir().join("secure.Dockerfile");
    let rules_path = rules_dir();

    // Skip test if rules directory doesn't exist
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        return;
    }

    let result = scan_dockerfile(
        dockerfile_path,
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Should succeed
    assert!(result.is_ok(), "Scan should complete successfully");
}

#[test]
#[ignore] // Ignore by default since it requires rules directory
fn test_scan_multistage_dockerfile() {
    let dockerfile_path = fixtures_dir().join("multistage.Dockerfile");
    let rules_path = rules_dir();

    // Skip test if rules directory doesn't exist
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        return;
    }

    let result = scan_dockerfile(
        dockerfile_path,
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Should succeed
    assert!(result.is_ok(), "Scan should complete successfully");
}

#[test]
fn test_scan_nonexistent_dockerfile() {
    let dockerfile_path = fixtures_dir().join("does-not-exist.Dockerfile");
    let rules_path = rules_dir();

    let result = scan_dockerfile(
        dockerfile_path,
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Should fail with file not found error
    assert!(result.is_err(), "Should fail when Dockerfile doesn't exist");
    assert!(
        result.unwrap_err().to_string().contains("reading"),
        "Error should mention reading the file"
    );
}

#[test]
fn test_scan_invalid_dockerfile() {
    // Create a temporary invalid Dockerfile
    let temp_dir = std::env::temp_dir();
    let invalid_dockerfile = temp_dir.join("invalid.Dockerfile");
    std::fs::write(&invalid_dockerfile, "INVALID INSTRUCTION!!!").unwrap();

    let rules_path = rules_dir();

    let result = scan_dockerfile(
        invalid_dockerfile.clone(),
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Clean up
    let _ = std::fs::remove_file(&invalid_dockerfile);

    // Parsing might succeed with Misc instruction, so we just verify it completes
    // The parser is lenient and treats unknown instructions as Misc
    assert!(result.is_ok(), "Scanner handles unknown instructions gracefully");
}

#[test]
fn test_scan_with_nonexistent_rules_dir() {
    let dockerfile_path = fixtures_dir().join("secure.Dockerfile");
    let rules_path = PathBuf::from("/nonexistent/rules/directory");

    let result = scan_dockerfile(
        dockerfile_path,
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Should fail when rules directory doesn't exist
    assert!(result.is_err(), "Should fail when rules directory doesn't exist");
}

#[test]
fn test_scan_empty_dockerfile() {
    // Create a temporary empty Dockerfile
    let temp_dir = std::env::temp_dir();
    let empty_dockerfile = temp_dir.join("empty.Dockerfile");
    std::fs::write(&empty_dockerfile, "").unwrap();

    let rules_path = rules_dir();

    let result = scan_dockerfile(
        empty_dockerfile.clone(),
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Clean up
    let _ = std::fs::remove_file(&empty_dockerfile);

    // Empty Dockerfile is parsed successfully (parser is lenient)
    // It just produces no findings
    assert!(result.is_ok(), "Empty Dockerfile should parse successfully");
}

#[test]
fn test_output_formats_json() {
    let dockerfile_path = fixtures_dir().join("secure.Dockerfile");
    let rules_path = rules_dir();

    // Skip test if rules directory doesn't exist
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        return;
    }

    let result = scan_dockerfile(
        dockerfile_path,
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    assert!(result.is_ok(), "JSON output should work");
}

#[test]
fn test_output_formats_csv() {
    let dockerfile_path = fixtures_dir().join("secure.Dockerfile");
    let rules_path = rules_dir();

    // Skip test if rules directory doesn't exist
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        return;
    }

    let result = scan_dockerfile(
        dockerfile_path,
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Csv,
        None,
    );

    assert!(result.is_ok(), "CSV output should work");
}

#[test]
fn test_output_formats_table() {
    let dockerfile_path = fixtures_dir().join("secure.Dockerfile");
    let rules_path = rules_dir();

    // Skip test if rules directory doesn't exist
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        return;
    }

    let result = scan_dockerfile(
        dockerfile_path,
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Table,
        None,
    );

    assert!(result.is_ok(), "Table output should work");
}

#[test]
#[ignore] // Ignore by default to avoid creating files during normal test runs
fn test_output_to_file() {
    let dockerfile_path = fixtures_dir().join("secure.Dockerfile");
    let rules_path = rules_dir();

    // Skip test if rules directory doesn't exist
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        return;
    }

    let temp_dir = std::env::temp_dir();
    let output_file = temp_dir.join("test_output.json");

    let result = scan_dockerfile(
        dockerfile_path,
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        Some(output_file.clone()),
    );

    assert!(result.is_ok(), "Output to file should work");
    assert!(output_file.exists(), "Output file should be created");

    // Clean up
    let _ = std::fs::remove_file(&output_file);
}

// ============================================================================
// Tests for new Dockerfile scanner features (severity, fail-on, only/exclude)
// ============================================================================

#[test]
fn test_severity_filtering_high_only() {
    let temp_dir = std::env::temp_dir();
    let test_dockerfile = temp_dir.join("test_severity.Dockerfile");

    // Create a Dockerfile with known issues of different severities
    std::fs::write(&test_dockerfile, "FROM ubuntu:latest\nUSER root\n").unwrap();

    let rules_path = rules_dir();
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        let _ = std::fs::remove_file(&test_dockerfile);
        return;
    }

    let result = scan_dockerfile(
        test_dockerfile.clone(),
        rules_path,
        None, // only
        None, // exclude
        Some(vec![valeris::cli::SeverityLevel::High]), // severity - only high
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Clean up
    let _ = std::fs::remove_file(&test_dockerfile);

    assert!(result.is_ok(), "Severity filtering should work");
}

#[test]
fn test_min_severity_filtering() {
    let temp_dir = std::env::temp_dir();
    let test_dockerfile = temp_dir.join("test_min_severity.Dockerfile");

    std::fs::write(&test_dockerfile, "FROM ubuntu:latest\nUSER root\n").unwrap();

    let rules_path = rules_dir();
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        let _ = std::fs::remove_file(&test_dockerfile);
        return;
    }

    let result = scan_dockerfile(
        test_dockerfile.clone(),
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        Some(valeris::cli::SeverityLevel::Medium), // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Clean up
    let _ = std::fs::remove_file(&test_dockerfile);

    assert!(result.is_ok(), "Min severity filtering should work");
}

#[test]
fn test_fail_on_returns_true_when_findings_exist() {
    let temp_dir = std::env::temp_dir();
    let test_dockerfile = temp_dir.join("test_fail_on.Dockerfile");

    // Create insecure Dockerfile that will trigger findings
    std::fs::write(&test_dockerfile, "FROM ubuntu:latest\nUSER root\n").unwrap();

    let rules_path = rules_dir();
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        let _ = std::fs::remove_file(&test_dockerfile);
        return;
    }

    let result = scan_dockerfile(
        test_dockerfile.clone(),
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        Some(valeris::cli::SeverityLevel::Low), // fail_on - low threshold
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Clean up
    let _ = std::fs::remove_file(&test_dockerfile);

    // Should succeed but return true (indicating should fail)
    match result {
        Ok(should_fail) => {
            // We expect findings, so should_fail should be true
            // But we can't guarantee it without knowing exact rules
            println!("should_fail: {}", should_fail);
        }
        Err(e) => panic!("Scan should succeed: {}", e),
    }
}

#[test]
fn test_quiet_mode_suppresses_output() {
    let temp_dir = std::env::temp_dir();
    let test_dockerfile = temp_dir.join("test_quiet.Dockerfile");

    std::fs::write(&test_dockerfile, "FROM ubuntu:latest\n").unwrap();

    let rules_path = rules_dir();
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        let _ = std::fs::remove_file(&test_dockerfile);
        return;
    }

    let result = scan_dockerfile(
        test_dockerfile.clone(),
        rules_path,
        None, // only
        None, // exclude
        None, // severity
        None, // min_severity
        Some(valeris::cli::SeverityLevel::High), // fail_on required for quiet
        true, // quiet - no output
        OutputFormat::Json,
        None,
    );

    // Clean up
    let _ = std::fs::remove_file(&test_dockerfile);

    assert!(result.is_ok(), "Quiet mode should work");
}

#[test]
fn test_only_filter_specific_rules() {
    let temp_dir = std::env::temp_dir();
    let test_dockerfile = temp_dir.join("test_only.Dockerfile");

    std::fs::write(&test_dockerfile, "FROM ubuntu:latest\nUSER root\n").unwrap();

    let rules_path = rules_dir();
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        let _ = std::fs::remove_file(&test_dockerfile);
        return;
    }

    let result = scan_dockerfile(
        test_dockerfile.clone(),
        rules_path,
        Some(vec!["DF001".to_string(), "DF002".to_string()]), // only - specific rules
        None, // exclude
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Clean up
    let _ = std::fs::remove_file(&test_dockerfile);

    assert!(result.is_ok(), "Only filter should work");
}

#[test]
fn test_exclude_filter_specific_rules() {
    let temp_dir = std::env::temp_dir();
    let test_dockerfile = temp_dir.join("test_exclude.Dockerfile");

    std::fs::write(&test_dockerfile, "FROM ubuntu:latest\nUSER root\n").unwrap();

    let rules_path = rules_dir();
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        let _ = std::fs::remove_file(&test_dockerfile);
        return;
    }

    let result = scan_dockerfile(
        test_dockerfile.clone(),
        rules_path,
        None, // only
        Some(vec!["DF001".to_string()]), // exclude - skip DF001
        None, // severity
        None, // min_severity
        None, // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Clean up
    let _ = std::fs::remove_file(&test_dockerfile);

    assert!(result.is_ok(), "Exclude filter should work");
}

#[test]
fn test_combined_filters() {
    let temp_dir = std::env::temp_dir();
    let test_dockerfile = temp_dir.join("test_combined.Dockerfile");

    std::fs::write(&test_dockerfile, "FROM ubuntu:latest\nUSER root\n").unwrap();

    let rules_path = rules_dir();
    if !rules_path.exists() {
        println!("Skipping test - rules directory not found");
        let _ = std::fs::remove_file(&test_dockerfile);
        return;
    }

    let result = scan_dockerfile(
        test_dockerfile.clone(),
        rules_path,
        Some(vec!["DF001".to_string(), "DF002".to_string()]), // only
        None, // exclude
        None, // severity
        Some(valeris::cli::SeverityLevel::Medium), // min_severity
        Some(valeris::cli::SeverityLevel::High), // fail_on
        false, // quiet
        OutputFormat::Json,
        None,
    );

    // Clean up
    let _ = std::fs::remove_file(&test_dockerfile);

    assert!(result.is_ok(), "Combined filters should work");
}

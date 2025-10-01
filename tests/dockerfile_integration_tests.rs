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
        OutputFormat::Json,
        Some(output_file.clone()),
    );

    assert!(result.is_ok(), "Output to file should work");
    assert!(output_file.exists(), "Output file should be created");

    // Clean up
    let _ = std::fs::remove_file(&output_file);
}

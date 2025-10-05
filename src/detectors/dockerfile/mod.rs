//! Dockerfile security scanner module.
//!
//! This module provides functionality to scan Dockerfiles for security
//! issues and misconfigurations using YAML-defined rules.
//!
//! # Architecture
//!
//! The scanner is organized into several sub-modules:
//!
//! * [`scanner`] - Main orchestration and scanning logic
//! * [`yaml_rules`] - YAML rule definitions and loading
//! * [`matcher`] - Rule matching logic (regex, glob, predicates)
//! * [`instruction_utils`] - Utilities for working with Dockerfile instructions
//!
//! For output formatting, see the unified [`crate::output`] module:
//! - [`crate::output::printer`] - Visual console output
//! - [`crate::output::exporters`] - JSON/CSV export functionality
//!
//! # Example Usage
//!
//! ```no_run
//! use std::path::PathBuf;
//! use valeris::detectors::dockerfile::scanner::scan_dockerfile;
//! use valeris::cli::OutputFormat;
//!
//! // Scan a Dockerfile with table output
//! scan_dockerfile(
//!     PathBuf::from("./Dockerfile"),
//!     PathBuf::from("./rules/dockerfile"),
//!     OutputFormat::Table,
//!     None
//! ).expect("Scan failed");
//! ```

pub mod scanner;
pub mod yaml_rules;
pub mod matcher;
pub mod instruction_utils;

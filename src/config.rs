//! Centralized configuration for Valeris.
//!
//! This module provides configuration settings and constants used throughout
//! the application, including rules management, Docker settings, and output preferences.

use std::path::PathBuf;
use std::io::IsTerminal;

/// Default URL for downloading rule releases from GitHub
pub const DEFAULT_RULES_RELEASE_URL: &str =
    "https://github.com/rsgbengi/valeris-rules/releases/download/v0.1.0/detectors.tar.gz";

/// Default environment variable for rules directory override
pub const RULES_DIR_ENV: &str = "VALERIS_RULES_DIR";

/// Rules directory configuration
pub struct RulesConfig {
    /// Base directory for rules
    pub base_dir: PathBuf,
    /// Whether to download rules if missing
    pub auto_download: bool,
}

impl Default for RulesConfig {
    fn default() -> Self {
        let base_dir = std::env::var(RULES_DIR_ENV)
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("valeris")
                    .join("detectors")
            });

        Self {
            base_dir,
            auto_download: true,
        }
    }
}

impl RulesConfig {
    /// Returns the runtime rules directory for Docker containers
    pub fn runtime_docker_dir(&self) -> PathBuf {
        self.base_dir.join("runtime").join("docker")
    }

    /// Returns the dockerfile rules directory
    pub fn dockerfile_dir(&self) -> PathBuf {
        self.base_dir.join("dockerfile")
    }
}

/// Docker client configuration
pub struct DockerConfig {
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Maximum number of containers to scan in parallel
    pub max_parallel_scans: usize,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            connection_timeout_secs: 30,
            max_parallel_scans: 10,
        }
    }
}

/// Output formatting preferences
pub struct OutputConfig {
    /// Use colored output in terminal
    pub use_colors: bool,
    /// Table width for formatted output
    pub table_width: usize,
    /// Show verbose error messages
    pub verbose_errors: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            use_colors: std::io::stdout().is_terminal(),
            table_width: 80,
            verbose_errors: false,
        }
    }
}

/// Application-wide configuration
#[derive(Default)]
pub struct AppConfig {
    pub rules: RulesConfig,
    pub docker: DockerConfig,
    pub output: OutputConfig,
}


impl AppConfig {
    /// Creates a new application configuration with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables verbose output
    pub fn with_verbose(mut self) -> Self {
        self.output.verbose_errors = true;
        self
    }

    /// Disables automatic rules download
    pub fn without_auto_download(mut self) -> Self {
        self.rules.auto_download = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_config_default() {
        let config = RulesConfig::default();
        assert!(config.auto_download);
        assert!(config.base_dir.to_string_lossy().contains("valeris"));
    }

    #[test]
    fn test_docker_config_defaults() {
        let config = DockerConfig::default();
        assert_eq!(config.connection_timeout_secs, 30);
        assert_eq!(config.max_parallel_scans, 10);
    }

    #[test]
    fn test_app_config_builder() {
        let config = AppConfig::new()
            .with_verbose()
            .without_auto_download();

        assert!(config.output.verbose_errors);
        assert!(!config.rules.auto_download);
    }

    #[test]
    fn test_rules_subdirectories() {
        let config = RulesConfig::default();
        let runtime_dir = config.runtime_docker_dir();
        let dockerfile_dir = config.dockerfile_dir();

        assert!(runtime_dir.to_string_lossy().contains("runtime"));
        assert!(dockerfile_dir.to_string_lossy().contains("dockerfile"));
    }
}

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Valeris - Security Scanner for Container Runtime and Build-time Misconfigurations
///
/// A declarative YAML-based security scanner that detects misconfigurations in:
/// - Running Docker containers (privileged mode, exposed ports, dangerous capabilities, etc.)
/// - Dockerfiles (build-time security issues)
/// - Kubernetes workloads (coming soon)
///
/// Examples:
///   # Scan all running Docker containers
///   valeris scan
///
///   # Scan with specific detectors only
///   valeris scan --only exposed_ports,capabilities
///
///   # Export findings to JSON
///   valeris scan --format json --output report.json
///
///   # Scan a Dockerfile
///   valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
///
///   # List all available detection rules
///   valeris list-plugins
#[derive(Parser)]
#[command(
    name = "valeris",
    version = "0.1.0",
    author = "rsgbengi",
    about = "Security scanner for container runtime and build-time misconfigurations",
    long_about = None,
    after_help = "For more information and documentation, visit: https://github.com/rsgbengi/valeris"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Target platform for security scanning
#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum ScanTarget {
    /// Scan Docker containers
    Docker,
    /// Scan Kubernetes workloads (coming soon)
    K8s,
    /// Scan both Docker and Kubernetes
    Both,
}

/// Severity levels for filtering findings
#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLevel {
    /// Informational findings
    Informative,
    /// Low severity issues
    Low,
    /// Medium severity issues
    Medium,
    /// High severity issues
    High,
}
/// Output format for scan results
#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable table with colors (default for terminal)
    Table,
    /// JSON format for CI/CD and programmatic parsing
    Json,
    /// CSV format for spreadsheets and data analysis
    Csv,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan running containers for security misconfigurations
    ///
    /// Analyzes running Docker containers against YAML-defined security rules.
    /// Detects issues like privileged mode, exposed ports, dangerous capabilities,
    /// secrets in environment variables, and more.
    ///
    /// Examples:
    ///   # Scan all running Docker containers
    ///   valeris scan
    ///
    ///   # Scan only specific detectors
    ///   valeris scan --only exposed_ports,capabilities,secrets_in_env
    ///
    ///   # Exclude certain detectors
    ///   valeris scan --exclude readonly_rootfs
    ///
    ///   # Filter by container state
    ///   valeris scan --state running
    ///
    ///   # Scan specific containers by name or ID
    ///   valeris scan --container nginx,redis
    ///   valeris scan -c web-app
    ///
    ///   # Filter by severity
    ///   valeris scan --severity high
    ///   valeris scan --min-severity medium
    ///
    ///   # CI/CD integration - fail on critical findings
    ///   valeris scan --fail-on high
    ///   valeris scan --quiet --fail-on medium
    ///
    ///   # Combine filters
    ///   valeris scan --state running --container nginx --min-severity high
    ///
    ///   # Export results to JSON for CI/CD
    ///   valeris scan --format json --output findings.json
    ///
    ///   # Export to CSV for analysis
    ///   valeris scan --format csv --output report.csv
    #[command(visible_alias = "s")]
    Scan {
        // Target Selection
        #[arg(
            long,
            short = 't',
            default_value = "docker",
            value_enum,
            help = "Target platform to scan"
        )]
        target: ScanTarget,

        // Detector Filtering
        #[arg(
            long,
            value_name = "DETECTORS",
            value_delimiter = ',',
            help = "Run only specified detectors (comma-separated)",
            long_help = "Run only the specified detector(s). Multiple detectors can be specified \
                        as a comma-separated list.\n\n\
                        Example: --only exposed_ports,capabilities,secrets_in_env\n\n\
                        Use 'valeris list-plugins' to see all available detectors."
        )]
        only: Option<Vec<String>>,

        #[arg(
            long,
            value_name = "DETECTORS",
            value_delimiter = ',',
            help = "Exclude specified detectors (comma-separated)",
            long_help = "Exclude the specified detector(s) from the scan. Multiple detectors \
                        can be specified as a comma-separated list.\n\n\
                        Example: --exclude privileged_mode,readonly_rootfs\n\n\
                        Use 'valeris list-plugins' to see all available detectors.",
            conflicts_with = "only"
        )]
        exclude: Option<Vec<String>>,

        // Container Filtering
        #[arg(
            long,
            value_name = "STATES",
            value_delimiter = ',',
            help = "Filter containers by state (comma-separated)",
            long_help = "Filter containers by their current state. Common states include:\n\
                        - running: Currently executing containers\n\
                        - exited: Stopped containers\n\
                        - paused: Paused containers\n\
                        - restarting: Containers in restart process\n\n\
                        Example: --state running,paused"
        )]
        state: Option<Vec<String>>,

        #[arg(
            long,
            short = 'c',
            value_name = "PATTERN",
            value_delimiter = ',',
            help = "Filter containers by name or ID (comma-separated patterns)",
            long_help = "Filter containers by name or ID. Supports multiple patterns as comma-separated list.\n\
                        Patterns can match:\n\
                        - Full container ID (64 characters)\n\
                        - Short container ID (12 characters)\n\
                        - Container name (exact or partial match)\n\n\
                        Examples:\n  \
                        --container nginx               # Match containers with 'nginx' in name\n  \
                        --container web-1,web-2         # Match specific containers\n  \
                        --container abc123              # Match by container ID prefix"
        )]
        container: Option<Vec<String>>,

        // Severity Filtering
        #[arg(
            long,
            value_name = "SEVERITIES",
            value_delimiter = ',',
            help = "Filter findings by severity (comma-separated)",
            long_help = "Show only findings with specified severity levels. Multiple levels \
                        can be specified as a comma-separated list.\n\n\
                        Available levels (in order): informative, low, medium, high\n\n\
                        Examples:\n  \
                        --severity high                    # Only high severity\n  \
                        --severity medium,high             # Medium and high\n  \
                        --severity critical,high,medium    # All except low and info"
        )]
        severity: Option<Vec<SeverityLevel>>,

        #[arg(
            long,
            value_name = "LEVEL",
            help = "Show only findings at or above this severity",
            long_help = "Filter findings to show only those at or above the specified minimum \
                        severity level. This is a shorthand for specifying multiple severities.\n\n\
                        Available levels: informative, low, medium, high\n\n\
                        Examples:\n  \
                        --min-severity medium    # Show medium and high\n  \
                        --min-severity high      # Show only high",
            conflicts_with = "severity"
        )]
        min_severity: Option<SeverityLevel>,

        // CI/CD Integration
        #[arg(
            long,
            value_name = "LEVEL",
            help = "Exit with error code 1 if findings at or above this level exist",
            long_help = "Causes valeris to exit with code 1 if any findings at or above the \
                        specified severity level are found. Useful for CI/CD pipelines.\n\n\
                        Available levels: informative, low, medium, high\n\n\
                        Examples:\n  \
                        --fail-on high       # Fail on high severity findings\n  \
                        --fail-on medium     # Fail on medium or high findings\n  \
                        --fail-on low        # Fail on any findings except informative"
        )]
        fail_on: Option<SeverityLevel>,

        #[arg(
            long,
            help = "Suppress all output, only set exit code (implies --fail-on)",
            long_help = "Run in quiet mode with no output. Useful for CI/CD where you only \
                        care about the exit code. This flag requires --fail-on to be set.\n\n\
                        Example: valeris scan --quiet --fail-on high",
            requires = "fail_on"
        )]
        quiet: bool,

        // Output Options
        #[arg(
            long,
            short = 'f',
            value_enum,
            default_value = "json",
            requires = "output",
            help = "Output format (requires --output)"
        )]
        format: OutputFormat,

        #[arg(
            long,
            short = 'o',
            value_name = "FILE",
            help = "Write results to file instead of stdout",
            long_help = "Write scan results to the specified file instead of stdout.\n\
                        The format is determined by the --format flag.\n\n\
                        Examples:\n  \
                        --output findings.json\n  \
                        --output report.csv"
        )]
        output: Option<String>,
    },

    /// Scan Dockerfiles for build-time security issues (experimental)
    ///
    /// Analyzes Dockerfile instructions for security misconfigurations during
    /// the build process. Detects issues like running as root, using latest tags,
    /// hardcoded secrets, insecure base images, and more.
    ///
    /// Note: This feature is currently in development (WIP).
    ///
    /// Examples:
    ///   # Scan a Dockerfile with default rules
    ///   valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile
    ///
    ///   # Export findings as JSON
    ///   valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile \
    ///     --format json --output dockerfile-findings.json
    ///
    ///   # Human-readable table output
    ///   valeris docker-file --path ./Dockerfile --rules ./rules/dockerfile --format table
    #[command(visible_alias = "df")]
    DockerFile {
        #[arg(
            long,
            short = 'p',
            value_name = "PATH",
            help = "Path to the Dockerfile to scan",
            long_help = "Path to the Dockerfile that will be analyzed for security issues.\n\n\
                        Example: --path ./Dockerfile"
        )]
        path: PathBuf,

        #[arg(
            long,
            short = 'r',
            value_name = "PATH",
            help = "Path to directory containing YAML rule definitions",
            long_help = "Path to the directory containing YAML rule files for Dockerfile scanning.\n\
                        Rules define what security issues to detect.\n\n\
                        Example: --rules ./rules/dockerfile"
        )]
        rules: PathBuf,

        #[arg(
            long,
            short = 'f',
            value_enum,
            default_value = "table",
            help = "Output format"
        )]
        format: OutputFormat,

        #[arg(
            long,
            short = 'o',
            value_name = "FILE",
            help = "Write results to file instead of stdout",
            long_help = "Write scan results to the specified file.\n\n\
                        Examples:\n  \
                        --output dockerfile-report.json\n  \
                        --output findings.csv"
        )]
        output: Option<PathBuf>,
    },

    /// List all available security detection rules
    ///
    /// Displays all loaded YAML rules that can be used for scanning.
    /// Shows rule IDs, descriptions, severity levels, and target platforms.
    ///
    /// Examples:
    ///   # List all available detectors
    ///   valeris list-plugins
    ///
    ///   # List only Docker-specific detectors
    ///   valeris list-plugins --target docker
    ///
    ///   # List Kubernetes detectors
    ///   valeris list-plugins --target k8s
    #[command(visible_alias = "ls")]
    ListPlugins {
        #[arg(
            long,
            short = 't',
            value_enum,
            help = "Filter detectors by target platform"
        )]
        target: Option<ScanTarget>,
    },

    /// Show configuration file location and status
    ///
    /// Displays information about the configuration file, including its location
    /// and whether it was successfully loaded.
    ///
    /// Examples:
    ///   # Show config file status
    ///   valeris config
    #[command(visible_alias = "cfg")]
    Config {},
}

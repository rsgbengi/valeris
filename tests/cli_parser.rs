#[cfg(test)]
mod tests {
    use clap::Parser;
    use valeris::cli::{Cli, Commands, OutputFormat, ScanTarget};

    const VALID_PLUGINS: &[&str] = &[
        "capabilities",
        "mounts",
        "network",
        "exposed_ports",
        "secrets_in_env",
        "privileged_mode",
        "readonly_rootfs",
        "security_options",
        "root_user",
        "pid_mode",
    ];

    #[test]
    fn parses_scan_with_only_and_target() {
        let cli = Cli::parse_from([
            "valeris",
            "scan",
            "--target",
            "docker",
            "--only",
            "ports,secrets",
            "--output",
            "report.json",
            "--format",
            "json",
        ]);

        match cli.command {
            Commands::Scan {
                target,
                only,
                exclude,
                format,
                output,
            } => {
                assert_eq!(target, ScanTarget::Docker);
                assert_eq!(only.unwrap(), "ports,secrets");
                assert!(exclude.is_none());
                assert_eq!(format, OutputFormat::Json);
                assert_eq!(output.unwrap(), "report.json");
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_scan_with_defaults() {
        let cli = Cli::parse_from(["valeris", "scan"]);
        match cli.command {
            Commands::Scan {
                target,
                only,
                exclude,
                format,
                output,
            } => {
                assert_eq!(target, ScanTarget::Docker);
                assert!(only.is_none());
                assert!(exclude.is_none());
                assert_eq!(format, OutputFormat::Json);
                assert!(output.is_none());
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_list_plugins_with_target() {
        let cli = Cli::parse_from(["valeris", "list-plugins", "--target", "k8s"]);
        match cli.command {
            Commands::ListPlugins { target } => {
                assert_eq!(target.unwrap(), ScanTarget::K8s);
            }
            _ => panic!("Expected ListPlugins command"),
        }
    }

    #[test]
    fn parses_list_plugins_without_target() {
        let cli = Cli::parse_from(["valeris", "list-plugins"]);
        match cli.command {
            Commands::ListPlugins { target } => {
                assert!(target.is_none());
            }
            _ => panic!("Expected ListPlugins command"),
        }
    }

    #[test]
    fn fails_with_invalid_target() {
        let result = Cli::try_parse_from(["valeris", "scan", "--target", "invalidvalue"]);
        assert!(result.is_err());
    }

    #[test]
    fn all_plugins_are_cli_valid() {
        for &name in VALID_PLUGINS {
            let cli = Cli::parse_from(["valeris", "scan", "--only", name]);
            match cli.command {
                Commands::Scan { only: Some(s), .. } => assert_eq!(s, name),
                _ => panic!("Should parse plugin name"),
            }
        }
    }

    #[test]
    fn all_plugins_are_valid_in_exclude() {
        for &name in VALID_PLUGINS {
            let cli = Cli::parse_from(["valeris", "scan", "--exclude", name]);
            match cli.command {
                Commands::Scan {
                    exclude: Some(s), ..
                } => assert_eq!(s, name),
                _ => panic!("Should parse plugin name in exclude"),
            }
        }
    }
    #[test]
    fn fails_if_format_without_output() {
        let result = Cli::try_parse_from(["valeris", "scan", "--format", "json"]);
        assert!(
            result.is_err(),
            "Expected failure when using --format without --output"
        );
    }

    #[test]
    fn parses_output_without_format() {
        let cli = Cli::parse_from(["valeris", "scan", "--output", "out.json"]);
        match cli.command {
            Commands::Scan { output, format, .. } => {
                assert_eq!(output.unwrap(), "out.json");
                assert_eq!(format, OutputFormat::Json); // default
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_format_csv_with_output() {
        let cli = Cli::parse_from([
            "valeris",
            "scan",
            "--output",
            "report.csv",
            "--format",
            "csv",
        ]);
        match cli.command {
            Commands::Scan { output, format, .. } => {
                assert_eq!(output.unwrap(), "report.csv");
                assert_eq!(format, OutputFormat::Csv);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_complex_scan_command() {
        let cli = Cli::parse_from([
            "valeris",
            "scan",
            "--target",
            "docker",
            "--only",
            "capabilities,network",
            "--exclude",
            "root_user",
            "--output",
            "output.csv",
            "--format",
            "csv",
        ]);
        match cli.command {
            Commands::Scan {
                target,
                only,
                exclude,
                output,
                format,
            } => {
                assert_eq!(target, ScanTarget::Docker);
                assert_eq!(only.unwrap(), "capabilities,network");
                assert_eq!(exclude.unwrap(), "root_user");
                assert_eq!(output.unwrap(), "output.csv");
                assert_eq!(format, OutputFormat::Csv);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn shows_help_flag_does_not_panic() {
        let result = Cli::try_parse_from(["valeris", "--help"]);
        assert!(result.is_err()); // clap returns an error that triggers help display
    }
}

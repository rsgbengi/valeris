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
        "ipc_mode",
        "uts_mode",
        "resource_limits",
        "user_namespace",
        "pids_limit",
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
                ..
            } => {
                assert_eq!(target, ScanTarget::Docker);
                let only_vec = only.unwrap();
                assert_eq!(only_vec.len(), 2);
                assert!(only_vec.contains(&"ports".to_string()));
                assert!(only_vec.contains(&"secrets".to_string()));
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
                ..
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
                Commands::Scan { only: Some(s), .. } => {
                    assert_eq!(s.len(), 1);
                    assert_eq!(s[0], name);
                }
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
                } => {
                    assert_eq!(s.len(), 1);
                    assert_eq!(s[0], name);
                }
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
    fn parses_state_option() {
        let cli = Cli::parse_from(["valeris", "scan", "--state", "running,exited"]);
        match cli.command {
            Commands::Scan { state: Some(s), .. } => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"running".to_string()));
                assert!(s.contains(&"exited".to_string()));
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
                ..
            } => {
                assert_eq!(target, ScanTarget::Docker);
                let only_vec = only.unwrap();
                assert_eq!(only_vec.len(), 2);
                assert!(only_vec.contains(&"capabilities".to_string()));
                assert!(only_vec.contains(&"network".to_string()));
                assert!(exclude.is_none());
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

    #[test]
    fn parses_container_filter() {
        let cli = Cli::parse_from(["valeris", "scan", "--container", "nginx,redis"]);
        match cli.command {
            Commands::Scan { container, .. } => {
                let containers = container.unwrap();
                assert_eq!(containers.len(), 2);
                assert!(containers.contains(&"nginx".to_string()));
                assert!(containers.contains(&"redis".to_string()));
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_container_filter_short_flag() {
        let cli = Cli::parse_from(["valeris", "scan", "-c", "web-app"]);
        match cli.command {
            Commands::Scan { container, .. } => {
                let containers = container.unwrap();
                assert_eq!(containers.len(), 1);
                assert_eq!(containers[0], "web-app");
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_combined_filters() {
        let cli = Cli::parse_from([
            "valeris",
            "scan",
            "--state",
            "running",
            "--container",
            "nginx",
            "--only",
            "exposed_ports",
        ]);
        match cli.command {
            Commands::Scan {
                state,
                container,
                only,
                ..
            } => {
                assert!(state.is_some());
                assert!(container.is_some());
                assert!(only.is_some());

                let states = state.unwrap();
                assert_eq!(states.len(), 1);
                assert_eq!(states[0], "running");

                let containers = container.unwrap();
                assert_eq!(containers.len(), 1);
                assert_eq!(containers[0], "nginx");

                let only_detectors = only.unwrap();
                assert_eq!(only_detectors.len(), 1);
                assert_eq!(only_detectors[0], "exposed_ports");
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_severity_filter() {
        let cli = Cli::parse_from(["valeris", "scan", "--severity", "high,medium"]);
        match cli.command {
            Commands::Scan { severity, .. } => {
                let severities = severity.unwrap();
                assert_eq!(severities.len(), 2);
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_min_severity() {
        let cli = Cli::parse_from(["valeris", "scan", "--min-severity", "medium"]);
        match cli.command {
            Commands::Scan { min_severity, .. } => {
                assert!(min_severity.is_some());
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_fail_on() {
        let cli = Cli::parse_from(["valeris", "scan", "--fail-on", "high"]);
        match cli.command {
            Commands::Scan { fail_on, .. } => {
                assert!(fail_on.is_some());
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn parses_quiet_with_fail_on() {
        let cli = Cli::parse_from(["valeris", "scan", "--quiet", "--fail-on", "medium"]);
        match cli.command {
            Commands::Scan { quiet, fail_on, .. } => {
                assert!(quiet);
                assert!(fail_on.is_some());
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn fails_quiet_without_fail_on() {
        let result = Cli::try_parse_from(["valeris", "scan", "--quiet"]);
        assert!(result.is_err());
    }

    #[test]
    fn fails_severity_and_min_severity_together() {
        let result = Cli::try_parse_from([
            "valeris",
            "scan",
            "--severity",
            "high",
            "--min-severity",
            "medium",
        ]);
        assert!(result.is_err());
    }
}

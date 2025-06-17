use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "valeris", version = "0.1", author = "rsgbengi")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum ScanTarget {
    Docker,
    K8s,
    Both,
}
#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Csv,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Scan containers for misconfigurations and secrets")]
    Scan {
        #[arg(
            long,
            default_value = "docker",
            value_enum,
            help = "Choose what to scan: docker, k8s or both"
        )]
        target: ScanTarget,

        #[arg(
            long,
            help = "Run only the specified plugin(s), comma-separated (e.g. --only exposed_ports,secrets_in_env)"
        )]
        only: Option<String>,

        #[arg(
            long,
            help = "Exclude the specified plugin(s), comma-separated (e.g. --exclude privileged_mode,readonly_rootfs)"
        )]
        exclude: Option<String>,
         #[arg(long, help = "Filter containers by state, comma separated (e.g. running,exited)"
        )]
        state: Option<String>,#[arg(
            long,
            value_enum,
            default_value = "json",
            requires = "output",
            help = "Format of the output: json or csv"
        )]
        format: OutputFormat,

        #[arg(
            long,
            help = "Write output to a file instead of stdout (e.g. --output findings.json)"
        )]
        output: Option<String>,
    },

    #[command(about = "List all available plugins")]
    ListPlugins {
        #[arg(long, value_enum, help = "Filter plugins by target: docker, k8s, both")]
        target: Option<ScanTarget>,
    },
}

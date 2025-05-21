use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "valeris", version = "0.1", author = "rsgbengi")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ScanTarget {
    Docker,
    K8s,
    Both,
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
            help = "Run only the specified plugin(s), comma-separated (e.g. --only ports,secrets)"
        )]
        only: Option<String>,

        #[arg(
            long,
            help = "Exclude the specified plugin(s), comma-separated (e.g. --exclude privileged_mode,readonly_rootfs)"
        )]
        exclude: Option<String>,
    },

    #[command(about = "List all available plugins")]
    ListPlugins {
        #[arg(long, value_enum, help = "Filter plugins by target: docker, k8s, both")]
        target: Option<ScanTarget>,
    },
}

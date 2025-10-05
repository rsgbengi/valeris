#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing subscriber
    // Only log to stderr if RUST_LOG is set, otherwise stay quiet
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    if let Err(err) = valeris::run_with_args(std::env::args()).await {
        eprintln!("Error: {:#}", err);
        std::process::exit(1);
    }

    Ok(())
}

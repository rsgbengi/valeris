


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if let Err(err) = valeris::run_with_args(std::env::args()).await {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }

    Ok(())
}

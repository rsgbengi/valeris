use anyhow::{Context, anyhow};
use std::fs::read_to_string;
use std::path::PathBuf;
use dockerfile_parser::{Dockerfile, Instruction};

pub fn scan_dockerfile(path: PathBuf) -> anyhow::Result<()> {
    let content = read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    println!("{}", content);

    let df = Dockerfile::parse(&content).map_err(|e| anyhow!("Error parsing Dockerfile: {:?}", e))?;

    for stage in df.iter_stages() {
        println!("Stage #{}:", stage.index);
        for ins in &stage.instructions {
            match ins {
                Instruction::From(f) => {
                    println!(" From image: {}", f.image.content);
                }
                _ => {
                    println!(" Other instruction: {:?}", ins);
                }
            }
        }
    }
    Ok(())
}

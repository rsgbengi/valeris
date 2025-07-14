use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use flate2::read::GzDecoder;
use reqwest::blocking::get;
use tar::Archive;
use walkdir::WalkDir;

const RELEASE_URL: &str =
    "https://github.com/rsgbengi/valeris/releases/latest/download/valeris-rules.tar.gz";

pub fn rules_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("VALERIS_RULES_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(data_home) = dirs::data_dir() {
        return Ok(data_home.join("valeris").join("detectors"));
    }
    Err(anyhow!("cannot locate $XDG_DATA_HOME and VALERIS_RULES_DIR not set"))
}

pub fn ensure_rules() -> Result<PathBuf> {
    let dir = rules_dir()?;
    let version_file = dir.join(".valeris_version");

    let have_rules = version_file.exists()
        || WalkDir::new(&dir)
            .into_iter()
            .filter_map(Result::ok)
            .any(|e| e.path().extension() == Some("yaml".as_ref()));

    if have_rules {
        println!("▷ Returning without downloading");
        return Ok(dir);
    }

    fs::create_dir_all(&dir)?;
    println!("▷ Detectors not found – downloading default rule-pack…");

    download_and_extract(&dir)?;
    fs::write(&version_file, "installed")?;
    println!("✅ Rules installed in {}", dir.display());

    Ok(dir)
}

fn download_and_extract(target_dir: &Path) -> Result<()> {
    let resp = get(RELEASE_URL)
        .with_context(|| format!("downloading {}", RELEASE_URL))?
        .error_for_status()?;

    let bytes = resp.bytes()?;
    let gz = GzDecoder::new(bytes.as_ref());
    Archive::new(gz).unpack(target_dir)?;
    Ok(())
}

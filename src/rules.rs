use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use reqwest::blocking::get;
use tar::Archive;
use walkdir::WalkDir;

use crate::config::{RulesConfig, DEFAULT_RULES_RELEASE_URL};

/// Returns the rules directory, using configuration defaults
pub fn rules_dir() -> Result<PathBuf> {
    let config = RulesConfig::default();
    Ok(config.base_dir)
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
        tracing::debug!("Rules already present in {}", dir.display());
        return Ok(dir);
    }

    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create rules directory {}", dir.display()))?;
    tracing::info!("Detectors not found – downloading default rule-pack…");

    download_and_extract(&dir)
        .context("Failed to download and extract rules")?;
    fs::write(&version_file, "installed")
        .with_context(|| format!("Failed to write version file {}", version_file.display()))?;
    tracing::info!("Rules installed in {}", dir.display());

    Ok(dir)
}

fn download_and_extract(target_dir: &Path) -> Result<()> {
    let resp = get(DEFAULT_RULES_RELEASE_URL)
        .with_context(|| format!("downloading {}", DEFAULT_RULES_RELEASE_URL))?
        .error_for_status()?;

    let bytes = resp.bytes()?;
    let gz = GzDecoder::new(bytes.as_ref());
    Archive::new(gz).unpack(target_dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use serial_test::serial;

    #[test]
    #[serial]
    fn rules_dir_uses_env_var() {
        std::env::set_var("VALERIS_RULES_DIR", "/tmp/valeris_test");
        let dir = rules_dir().unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/valeris_test"));
        std::env::remove_var("VALERIS_RULES_DIR");
    }

    #[test]
    #[serial]
    fn ensure_rules_skips_download_if_present() {
        let td = tempdir().unwrap();
        let dir = td.path();
        std::env::set_var("VALERIS_RULES_DIR", dir);
        fs::create_dir_all(dir.join("docker")).unwrap();
        fs::write(dir.join(".valeris_version"), "installed").unwrap();

        let res = ensure_rules().unwrap();
        assert_eq!(res, dir);
        std::env::remove_var("VALERIS_RULES_DIR");
    }
}

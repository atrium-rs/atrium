use super::{Config, Loader, Saver};
use anyhow::anyhow;
use async_trait::async_trait;
use std::path::{Path, PathBuf};

pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl Loader for FileStore {
    async fn load(
        &self,
    ) -> core::result::Result<Config, Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self.path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => Ok(serde_json::from_str(&std::fs::read_to_string(&self.path)?)?),
            #[cfg(feature = "config-toml")]
            Some("toml") => Ok(toml::from_str(&std::fs::read_to_string(&self.path)?)?),
            _ => Err(anyhow!("Unsupported file format").into()),
        }
    }
}

#[async_trait]
impl Saver for FileStore {
    async fn save(
        &self,
        config: &Config,
    ) -> core::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        match self.path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => Ok(std::fs::write(
                &self.path,
                serde_json::to_string_pretty(config)?,
            )?),
            #[cfg(feature = "config-toml")]
            Some("toml") => Ok(std::fs::write(&self.path, toml::to_string_pretty(config)?)?),
            _ => Err(anyhow!("Unsupported file format").into()),
        }
    }
}

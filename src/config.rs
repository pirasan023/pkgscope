use std::{fs, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::output::{SortField, SortOrder};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub scan: ScanConfig,
    pub ui: UiConfig,
    pub privacy: PrivacyConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub default_environment_mode: EnvironmentModeConfig,
    pub default_timeout: String,
    pub history: bool,
    pub project_roots: Vec<PathBuf>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            default_environment_mode: EnvironmentModeConfig::Active,
            default_timeout: "10s".into(),
            history: false,
            project_roots: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EnvironmentModeConfig {
    #[default]
    Active,
    Deep,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    pub default_sort: SortConfig,
    pub default_order: OrderConfig,
    pub color: ColorConfig,
    pub language: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            default_sort: SortConfig::Name,
            default_order: OrderConfig::Asc,
            color: ColorConfig::Auto,
            language: "auto".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SortConfig {
    #[default]
    Name,
    Manager,
    Environment,
    Version,
    Size,
    KnownSince,
    Findings,
}

impl From<SortConfig> for SortField {
    fn from(value: SortConfig) -> Self {
        match value {
            SortConfig::Name => Self::Name,
            SortConfig::Manager => Self::Manager,
            SortConfig::Environment => Self::Environment,
            SortConfig::Version => Self::Version,
            SortConfig::Size => Self::Size,
            SortConfig::KnownSince => Self::KnownSince,
            SortConfig::Findings => Self::Findings,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OrderConfig {
    #[default]
    Asc,
    Desc,
}

impl From<OrderConfig> for SortOrder {
    fn from(value: OrderConfig) -> Self {
        match value {
            OrderConfig::Asc => Self::Asc,
            OrderConfig::Desc => Self::Desc,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ColorConfig {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct PrivacyConfig {
    pub telemetry: bool,
    pub store_raw_history: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub max_snapshots: u32,
    pub max_age_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_snapshots: 20,
            max_age_days: 30,
        }
    }
}

impl Config {
    pub fn load_default() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = read_config(&path)
            .with_context(|| format!("could not read config {}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .with_context(|| format!("invalid config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn timeout(&self) -> Result<Duration> {
        parse_duration(&self.scan.default_timeout).map_err(anyhow::Error::msg)
    }

    fn validate(&self) -> Result<()> {
        if self.privacy.telemetry {
            anyhow::bail!("privacy.telemetry=true is unsupported; pkgscope has no telemetry");
        }
        if self.privacy.store_raw_history {
            anyhow::bail!(
                "privacy.store_raw_history=true is prohibited; pkgscope never stores raw history"
            );
        }
        if !(1..=1_000).contains(&self.storage.max_snapshots) {
            anyhow::bail!("storage.max_snapshots must be between 1 and 1000");
        }
        if !(1..=3_650).contains(&self.storage.max_age_days) {
            anyhow::bail!("storage.max_age_days must be between 1 and 3650");
        }
        // Validate now so a bad setting cannot fail halfway through a scan.
        self.timeout()?;
        Ok(())
    }
}

fn read_config(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    const LIMIT: u64 = 1024 * 1024;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "configuration exceeds the 1 MiB safety limit",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

pub fn config_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .context("could not determine the user config directory")?;
    Ok(base.join("pkgscope/config.toml"))
}

pub fn parse_duration(value: &str) -> std::result::Result<Duration, String> {
    let value = value.trim();
    let (number, factor) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1_u64)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000)
    } else {
        (value, 1_000)
    };
    let amount: u64 = number
        .parse()
        .map_err(|_| format!("invalid duration {value:?}; use forms such as 10s, 500ms, or 1m"))?;
    let millis = amount
        .checked_mul(factor)
        .ok_or_else(|| "duration is too large".to_string())?;
    if millis == 0 {
        return Err("duration must be greater than zero".into());
    }
    Ok(Duration::from_millis(millis))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults_and_rejects_raw_history_storage() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.timeout().unwrap(), Duration::from_secs(10));
        let unsafe_config: Config = toml::from_str("[privacy]\nstore_raw_history=true").unwrap();
        assert!(unsafe_config.validate().is_err());
        let unbounded: Config = toml::from_str("[storage]\nmax_snapshots=0").unwrap();
        assert!(unbounded.validate().is_err());
    }
}

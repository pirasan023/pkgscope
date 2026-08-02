use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub scan_id: String,
    pub host: HostInfo,
    pub scope: ScanScope,
    pub partial: bool,
    pub manager_instances: Vec<ManagerInstance>,
    pub installations: Vec<InstallationRecord>,
    pub commands: Vec<CommandExposure>,
    pub findings: Vec<Finding>,
    pub errors: Vec<ScanError>,
}

impl Snapshot {
    pub fn empty(scope: ScanScope) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            generated_at: Utc::now(),
            scan_id: uuid::Uuid::new_v4().to_string(),
            host: HostInfo::current(),
            scope,
            partial: false,
            manager_instances: Vec::new(),
            installations: Vec::new(),
            commands: Vec::new(),
            findings: Vec::new(),
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostInfo {
    pub os: String,
    pub os_version: Option<String>,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linux_distribution: Option<LinuxDistribution>,
}

impl HostInfo {
    fn current() -> Self {
        let linux_distribution = linux_distribution();
        Self {
            os: std::env::consts::OS.to_string(),
            os_version: macos_version().or_else(|| {
                linux_distribution
                    .as_ref()
                    .and_then(|distribution| distribution.version_id.clone())
            }),
            architecture: platform_architecture().to_string(),
            linux_distribution,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinuxDistribution {
    pub id: Option<String>,
    pub name: Option<String>,
    pub pretty_name: Option<String>,
    pub version_id: Option<String>,
    pub version_codename: Option<String>,
    pub id_like: Vec<String>,
}

pub fn platform_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        architecture => architecture,
    }
}

fn macos_version() -> Option<String> {
    if std::env::consts::OS != "macos" {
        return None;
    }
    std::process::Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn linux_distribution() -> Option<LinuxDistribution> {
    if std::env::consts::OS != "linux" {
        return None;
    }
    let contents = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .ok()?;
    parse_os_release(&contents)
}

fn parse_os_release(contents: &str) -> Option<LinuxDistribution> {
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        if !key.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        }) {
            continue;
        }
        let value = unquote_os_release(raw_value.trim());
        values.insert(key.to_string(), crate::sanitize::terminal_text(&value));
    }
    let get = |key: &str| values.get(key).filter(|value| !value.is_empty()).cloned();
    let distribution = LinuxDistribution {
        id: get("ID"),
        name: get("NAME"),
        pretty_name: get("PRETTY_NAME"),
        version_id: get("VERSION_ID"),
        version_codename: get("VERSION_CODENAME"),
        id_like: get("ID_LIKE")
            .map(|value| value.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
    };
    (distribution.id.is_some() || distribution.name.is_some() || distribution.pretty_name.is_some())
        .then_some(distribution)
}

fn unquote_os_release(value: &str) -> String {
    let quoted = (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''));
    let value = if quoted && value.len() >= 2 {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let mut result = String::with_capacity(value.len());
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            result.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            result.push(character);
        }
    }
    if escaped {
        result.push('\\');
    }
    result
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanScope {
    pub user_scope: String,
    pub environment_mode: EnvironmentMode,
    pub history_enabled: bool,
    pub project_roots: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub requested_managers: Vec<ManagerKind>,
}

impl Default for ScanScope {
    fn default() -> Self {
        Self {
            user_scope: "current".into(),
            environment_mode: EnvironmentMode::Active,
            history_enabled: false,
            project_roots: Vec::new(),
            requested_managers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentMode {
    Active,
    Deep,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ManagerKind {
    Brew,
    Npm,
    Pnpm,
    Pipx,
    Uv,
    Cargo,
    Apt,
    Dnf,
    Pacman,
    Snap,
    Flatpak,
}

impl ManagerKind {
    pub const ALL: [Self; 11] = [
        Self::Brew,
        Self::Npm,
        Self::Pnpm,
        Self::Pipx,
        Self::Uv,
        Self::Cargo,
        Self::Apt,
        Self::Dnf,
        Self::Pacman,
        Self::Snap,
        Self::Flatpak,
    ];

    pub fn executable(self) -> &'static str {
        match self {
            Self::Brew => "brew",
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Pipx => "pipx",
            Self::Uv => "uv",
            Self::Cargo => "cargo",
            Self::Apt => "apt-get",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
            Self::Snap => "snap",
            Self::Flatpak => "flatpak",
        }
    }

    pub fn executable_names(self) -> &'static [&'static str] {
        match self {
            Self::Dnf => &["dnf5", "dnf", "dnf4", "dnf-3"],
            _ => match self {
                Self::Brew => &["brew"],
                Self::Npm => &["npm"],
                Self::Pnpm => &["pnpm"],
                Self::Pipx => &["pipx"],
                Self::Uv => &["uv"],
                Self::Cargo => &["cargo"],
                Self::Apt => &["apt-get"],
                Self::Pacman => &["pacman"],
                Self::Snap => &["snap"],
                Self::Flatpak => &["flatpak"],
                Self::Dnf => unreachable!(),
            },
        }
    }
}

impl std::fmt::Display for ManagerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.executable())
    }
}

impl std::str::FromStr for ManagerKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "brew" | "homebrew" => Ok(Self::Brew),
            "npm" => Ok(Self::Npm),
            "pnpm" => Ok(Self::Pnpm),
            "pipx" => Ok(Self::Pipx),
            "uv" => Ok(Self::Uv),
            "cargo" | "rust" => Ok(Self::Cargo),
            "apt" | "apt-get" | "dpkg" => Ok(Self::Apt),
            "dnf" | "dnf4" | "dnf5" => Ok(Self::Dnf),
            "pacman" => Ok(Self::Pacman),
            "snap" | "snapd" => Ok(Self::Snap),
            "flatpak" => Ok(Self::Flatpak),
            _ => Err(format!("unsupported manager: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagerInstance {
    pub id: String,
    pub manager: ManagerKind,
    pub executable_path: String,
    pub root: Option<String>,
    pub runtime: Option<RuntimeInfo>,
    pub runtime_manager: Option<String>,
    pub architecture: String,
    pub scope_owner: String,
    pub discovered_by: Vec<String>,
    pub scan_status: ScanStatus,
    pub scanned_at: DateTime<Utc>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub name: String,
    pub version: Option<String>,
    pub executable_path: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Success,
    Partial,
    Unavailable,
    TimedOut,
    PermissionDenied,
    ParseError,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallationRecord {
    pub id: String,
    pub identity: PackageIdentity,
    pub manager_instance_id: String,
    pub category: Category,
    pub version: FieldValue<String>,
    pub architecture: FieldValue<String>,
    pub install_type: InstallType,
    pub intent: InstallIntent,
    pub environment: String,
    pub paths: InstallationPaths,
    pub dates: InstallationDates,
    pub sizes: InstallationSizes,
    pub command_ids: Vec<String>,
    pub finding_ids: Vec<String>,
    pub removal_plan_available: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageIdentity {
    pub ecosystem: String,
    pub name: String,
    pub source_kind: SourceKind,
    pub source_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Registry,
    Git,
    Path,
    Tarball,
    Formula,
    Cask,
    Linked,
    Deb,
    Rpm,
    Pacman,
    Snap,
    Flatpak,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Cli,
    App,
    Font,
    Library,
    Other,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallType {
    Normal,
    Linked,
    Editable,
    Dependency,
    Injected,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallIntent {
    Explicit,
    Dependency,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InstallationPaths {
    pub install_root: Option<String>,
    pub bins: Vec<String>,
    pub artifacts: Vec<String>,
    pub configs: Vec<String>,
    pub dedicated_caches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InstallationDates {
    pub first_seen_at: Option<FieldValue<DateTime<Utc>>>,
    pub last_seen_at: Option<FieldValue<DateTime<Utc>>>,
    pub manager_install_event_at: Option<FieldValue<DateTime<Utc>>>,
    pub current_version_installed_at: Option<FieldValue<DateTime<Utc>>>,
    pub filesystem_created_at: Option<FieldValue<DateTime<Utc>>>,
    pub updated_at: Option<FieldValue<DateTime<Utc>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallationSizes {
    pub owned_apparent_bytes: Option<u64>,
    pub owned_allocated_bytes: Option<u64>,
    pub shared_store_bytes: Option<u64>,
    pub dedicated_cache_bytes: Option<u64>,
    pub estimated_reclaimable_bytes: Option<u64>,
    pub confidence: Confidence,
    pub method: String,
}

impl Default for InstallationSizes {
    fn default() -> Self {
        Self {
            owned_apparent_bytes: None,
            owned_allocated_bytes: None,
            shared_store_bytes: None,
            dedicated_cache_bytes: None,
            estimated_reclaimable_bytes: None,
            confidence: Confidence::Unknown,
            method: "not_calculated".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldValue<T> {
    pub value: Option<T>,
    pub source: String,
    pub confidence: Confidence,
    pub observed_at: DateTime<Utc>,
}

impl<T> FieldValue<T> {
    pub fn exact(value: T, source: impl Into<String>) -> Self {
        Self {
            value: Some(value),
            source: source.into(),
            confidence: Confidence::Exact,
            observed_at: Utc::now(),
        }
    }

    pub fn unknown(source: impl Into<String>) -> Self {
        Self {
            value: None,
            source: source.into(),
            confidence: Confidence::Unknown,
            observed_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Unknown,
    Ambiguous,
    Estimated,
    High,
    Exact,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandExposure {
    pub id: String,
    pub name: String,
    pub path: String,
    pub real_path: Option<String>,
    pub owner_installation_id: String,
    pub path_rank: Option<usize>,
    pub on_current_path: bool,
    pub exposure_state: ExposureState,
    pub shell_resolution: Option<ShellResolution>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExposureState {
    Active,
    Shadowed,
    Hidden,
    Broken,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellResolution {
    pub kind: String,
    pub value: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub code: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub installation_ids: Vec<String>,
    pub command_ids: Vec<String>,
    pub title: String,
    pub explanation: String,
    pub evidence_refs: Vec<String>,
    pub suggested_action: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Review,
    Warning,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}").map(|_| ())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanError {
    pub manager: ManagerKind,
    pub manager_instance_id: Option<String>,
    pub code: String,
    pub message: String,
    pub recoverable: bool,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemovalPlan {
    pub installation_id: String,
    pub manager_instance_id: String,
    pub target_name: String,
    pub target_version: Option<String>,
    pub preconditions: Vec<String>,
    pub managed_dependents: Vec<String>,
    pub warnings: Vec<String>,
    pub action: RemovalAction,
    pub related_data_excluded: Vec<String>,
    pub rollback_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemovalAction {
    pub executable: String,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env_overrides: BTreeMap<String, String>,
}

pub fn stable_id(parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(&hasher.finalize()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_os_release_without_accepting_control_sequences() {
        let release = parse_os_release(
            "NAME=\"Example Linux\"\nID=example\nID_LIKE=\"debian ubuntu\"\nVERSION_ID='24.04'\nPRETTY_NAME=\"Example\\ Linux\u{1b}[31m\"\ninvalid-key=value\n",
        )
        .unwrap();
        assert_eq!(release.id.as_deref(), Some("example"));
        assert_eq!(release.version_id.as_deref(), Some("24.04"));
        assert_eq!(release.id_like, ["debian", "ubuntu"]);
        assert_eq!(release.pretty_name.as_deref(), Some("Example Linux"));
    }

    #[test]
    fn schema_v1_host_without_linux_fields_still_deserializes() {
        let host: HostInfo = serde_json::from_value(serde_json::json!({
            "os": "macos",
            "os_version": "14.0",
            "architecture": "arm64"
        }))
        .unwrap();
        assert!(host.linux_distribution.is_none());
    }

    #[test]
    fn complete_schema_v1_snapshot_remains_readable() {
        let mut value = serde_json::to_value(Snapshot::empty(ScanScope::default())).unwrap();
        value["schema_version"] = 1.into();
        value["host"]
            .as_object_mut()
            .unwrap()
            .remove("linux_distribution");
        let snapshot: Snapshot = serde_json::from_value(value).unwrap();
        assert_eq!(snapshot.schema_version, 1);
        assert!(snapshot.host.linux_distribution.is_none());
    }
}

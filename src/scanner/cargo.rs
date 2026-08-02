use std::{collections::BTreeMap, fs, path::PathBuf};

use serde_json::Value;

use crate::model::{Category, InstallIntent, InstallType, ManagerInstance, ScanStatus, SourceKind};

use super::{PartialScan, ScanOptions, make_record, read_file_bounded, read_text_bounded};

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let root = cargo_root();
    instance.root = Some(root.display().to_string());
    let installs = match read_installs(&root) {
        Ok(installs) => installs,
        Err(error) => return PartialScan::failed(instance, "parse_error", error),
    };
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    for install in installs {
        let bins = install
            .bins
            .iter()
            .map(|name| root.join("bin").join(name))
            .collect();
        let (mut record, record_commands) = make_record(
            &instance,
            &install.name,
            install.version.as_deref(),
            "cargo",
            install.source_kind,
            install.source_ref,
            None,
            bins,
            Category::Cli,
            InstallType::Normal,
            InstallIntent::Explicit,
            options,
        );
        let mut apparent = 0_u64;
        let mut allocated = 0_u64;
        let mut measured = 0_usize;
        for command in &record_commands {
            let Ok(metadata) = fs::metadata(&command.path) else {
                continue;
            };
            apparent = apparent.saturating_add(metadata.len());
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                allocated = allocated.saturating_add(metadata.blocks().saturating_mul(512));
            }
            #[cfg(not(unix))]
            {
                allocated = allocated.saturating_add(metadata.len());
            }
            measured += 1;
        }
        if measured > 0 {
            record.sizes.owned_apparent_bytes = Some(apparent);
            record.sizes.owned_allocated_bytes = Some(allocated);
            record.sizes.estimated_reclaimable_bytes = Some(allocated);
            record.sizes.confidence = crate::model::Confidence::High;
        }
        record.paths.install_root = Some(root.display().to_string());
        record.sizes.method = "installed_binary_files_only_shared_cargo_data_excluded".into();
        record.metadata.extend(install.metadata);
        commands.extend(record_commands);
        installations.push(record);
    }
    instance.scan_status = ScanStatus::Success;
    PartialScan {
        instance,
        installations,
        commands,
        errors: Vec::new(),
    }
}

fn cargo_root() -> PathBuf {
    if let Some(root) = std::env::var_os("CARGO_INSTALL_ROOT") {
        return PathBuf::from(root);
    }
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".cargo")))
        .unwrap_or_else(|| PathBuf::from(".cargo"));
    for config_name in ["config.toml", "config"] {
        let config_path = cargo_home.join(config_name);
        let Ok(content) = read_text_bounded(&config_path, 1024 * 1024) else {
            continue;
        };
        let Ok(config) = toml::from_str::<toml::Value>(&content) else {
            continue;
        };
        if let Some(root) = config
            .get("install")
            .and_then(|install| install.get("root"))
            .and_then(toml::Value::as_str)
        {
            if let Some(home) = dirs::home_dir()
                && let Some(relative) = root.strip_prefix("~/")
            {
                return home.join(relative);
            }
            let root = PathBuf::from(root);
            return if root.is_absolute() {
                root
            } else {
                cargo_home.join(root)
            };
        }
    }
    cargo_home
}

struct CargoInstall {
    name: String,
    version: Option<String>,
    source_kind: SourceKind,
    source_ref: Option<String>,
    bins: Vec<String>,
    metadata: BTreeMap<String, Value>,
}

fn read_installs(root: &std::path::Path) -> anyhow::Result<Vec<CargoInstall>> {
    let crates2 = root.join(".crates2.json");
    if crates2.exists() && crates2.metadata()?.len() > 0 {
        let value: Value = serde_json::from_slice(&read_file_bounded(&crates2, 16 * 1024 * 1024)?)?;
        if let Some(installs) = value.get("installs").and_then(Value::as_object) {
            return Ok(installs
                .iter()
                .map(|(package_id, value)| cargo_install(package_id, value))
                .collect());
        }
    }
    let crates = root.join(".crates.toml");
    if !crates.exists() || crates.metadata()?.len() == 0 {
        return Ok(Vec::new());
    }
    let value: toml::Value = toml::from_str(&read_text_bounded(&crates, 16 * 1024 * 1024)?)?;
    let Some(installs) = value.get("v1").and_then(toml::Value::as_table) else {
        return Ok(Vec::new());
    };
    Ok(installs
        .iter()
        .map(|(package_id, value)| CargoInstall {
            name: parse_package_id(package_id).0,
            version: parse_package_id(package_id).1,
            source_kind: cargo_source(package_id).0,
            source_ref: cargo_source(package_id).1,
            bins: value
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect(),
            metadata: BTreeMap::new(),
        })
        .collect())
}

fn cargo_install(package_id: &str, value: &Value) -> CargoInstall {
    let (name, version) = parse_package_id(package_id);
    let (source_kind, source_ref) = cargo_source(package_id);
    let bins = value
        .get("bins")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    let mut metadata = BTreeMap::new();
    for key in ["features", "profile", "target", "rustc"] {
        if let Some(value) = value.get(key) {
            metadata.insert(key.into(), value.clone());
        }
    }
    CargoInstall {
        name,
        version,
        source_kind,
        source_ref,
        bins,
        metadata,
    }
}

fn parse_package_id(value: &str) -> (String, Option<String>) {
    let before_source = value.split(" (").next().unwrap_or(value);
    let mut parts = before_source.rsplitn(2, ' ');
    let version = parts
        .next()
        .filter(|part| part.chars().next().is_some_and(|ch| ch.is_ascii_digit()));
    match (parts.next(), version) {
        (Some(name), Some(version)) => (name.to_string(), Some(version.to_string())),
        _ => (before_source.to_string(), None),
    }
}

fn cargo_source(value: &str) -> (SourceKind, Option<String>) {
    let source = value
        .split_once(" (")
        .map(|(_, rest)| rest.trim_end_matches(')'));
    let Some(source) = source else {
        return (SourceKind::Unknown, None);
    };
    if source.starts_with("registry+") || source.starts_with("sparse+") {
        (SourceKind::Registry, Some(source.into()))
    } else if source.starts_with("git+") {
        (SourceKind::Git, Some(source.into()))
    } else if source.starts_with("path+") {
        (SourceKind::Path, Some(source.into()))
    } else {
        (SourceKind::Unknown, Some(source.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_package_ids_without_putting_version_in_identity() {
        assert_eq!(
            parse_package_id(
                "ripgrep 14.1.1 (registry+https://github.com/rust-lang/crates.io-index)"
            ),
            ("ripgrep".into(), Some("14.1.1".into()))
        );
    }
}

use std::{fs, path::PathBuf};

use chrono::{DateTime, Utc};
use serde_yaml_ng::Value;

use crate::model::{
    Category, Confidence, FieldValue, InstallIntent, InstallType, InstallationDates,
    ManagerInstance, ScanError, ScanStatus, SourceKind,
};
use crate::sanitize::terminal_text;

use super::{
    PartialScan, ScanOptions, command, command_error_code, insert_metadata_text, make_record,
    read_text_bounded,
};

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let output = match command(&instance, &["list", "--unicode=never"], options) {
        Ok(output) => output,
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    instance.root = Some(snap_state_dir().display().to_string());
    let listed = parse_list(&output.stdout_text());
    let packages = listed
        .into_iter()
        .map(|listed| {
            let root = snap_mount_dir().join(&listed.name).join("current");
            let metadata = read_text_bounded(&root.join("meta/snap.yaml"), 4 * 1024 * 1024)
                .ok()
                .and_then(|contents| serde_yaml_ng::from_str::<Value>(&contents).ok());
            SnapPackage {
                listed,
                root,
                metadata,
            }
        })
        .collect::<Vec<_>>();
    let dependency_snaps = packages
        .iter()
        .filter(|package| snap_role(package.metadata.as_ref()) == SnapRole::Dependency)
        .map(|package| package.listed.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    let errors = packages
        .iter()
        .filter(|package| snap_role(package.metadata.as_ref()) == SnapRole::Unknown)
        .map(|package| ScanError {
            manager: instance.manager,
            manager_instance_id: Some(instance.id.clone()),
            code: "parse_error".into(),
            message: format!(
                "Could not classify installed Snap {} from its local snap.yaml; it was omitted.",
                package.listed.name
            ),
            recoverable: true,
            occurred_at: Utc::now(),
        })
        .collect::<Vec<_>>();
    for package in packages
        .into_iter()
        .filter(|package| snap_role(package.metadata.as_ref()) == SnapRole::Application)
    {
        let metadata = package.metadata.as_ref();
        let app_names = yaml_mapping_keys(metadata.and_then(|value| value.get("apps")));
        let bins = snap_bins(&package.listed.name, &app_names);
        let architecture = yaml_architecture(metadata).unwrap_or_else(|| "unknown".into());
        let mut scan_options = options.clone();
        scan_options.calculate_sizes = false;
        let (mut record, record_commands) = make_record(
            &instance,
            &package.listed.name,
            Some(&package.listed.version),
            "snap",
            SourceKind::Snap,
            None,
            Some(package.root.clone()),
            bins,
            Category::App,
            InstallType::Normal,
            InstallIntent::Explicit,
            &scan_options,
        );
        record.version = FieldValue::exact(package.listed.version, "snap_list");
        record.architecture = if architecture == "unknown" {
            FieldValue::unknown("installed_snap_yaml")
        } else {
            FieldValue::exact(architecture, "installed_snap_yaml")
        };
        insert_metadata_text(
            &mut record,
            "description",
            yaml_text(metadata, "description")
                .or_else(|| yaml_text(metadata, "summary"))
                .as_deref(),
        );
        if record.metadata.contains_key("description") {
            record
                .metadata
                .insert("description_source".into(), "installed_snap_yaml".into());
        }
        insert_metadata_text(
            &mut record,
            "homepage",
            yaml_text(metadata, "website").as_deref(),
        );
        record
            .metadata
            .insert("revision".into(), package.listed.revision.clone().into());
        record
            .metadata
            .insert("tracking".into(), package.listed.tracking.into());
        record
            .metadata
            .insert("publisher".into(), package.listed.publisher.into());
        record
            .metadata
            .insert("notes".into(), package.listed.notes.into());
        let mut dependencies = Vec::new();
        if let Some(base) = yaml_text(metadata, "base")
            && dependency_snaps.contains(&base)
        {
            dependencies.push(base);
        }
        dependencies.extend(content_providers(metadata));
        dependencies.sort();
        dependencies.dedup();
        if !dependencies.is_empty() {
            record
                .metadata
                .insert("dependencies".into(), dependencies.into());
        }
        let snap_file = snap_state_dir().join("snaps").join(format!(
            "{}_{}.snap",
            package.listed.name, package.listed.revision
        ));
        if let Ok(file_metadata) = fs::metadata(&snap_file) {
            record.sizes.owned_apparent_bytes = Some(file_metadata.len());
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                record.sizes.owned_allocated_bytes =
                    Some(file_metadata.blocks().saturating_mul(512));
            }
            #[cfg(not(unix))]
            {
                record.sizes.owned_allocated_bytes = Some(file_metadata.len());
            }
            record.sizes.estimated_reclaimable_bytes = record.sizes.owned_allocated_bytes;
            record.sizes.confidence = Confidence::High;
            record.sizes.method = "installed_snap_revision_file".into();
            if let Ok(modified) = file_metadata.modified() {
                let timestamp = DateTime::<Utc>::from(modified);
                record.dates = InstallationDates {
                    current_version_installed_at: Some(FieldValue {
                        value: Some(timestamp),
                        source: "snap_revision_file_mtime".into(),
                        confidence: Confidence::Estimated,
                        observed_at: Utc::now(),
                    }),
                    ..record.dates
                };
            }
        }
        record.metadata.insert("data_purge".into(), false.into());
        commands.extend(record_commands);
        installations.push(record);
    }
    instance.scan_status = if errors.is_empty() {
        ScanStatus::Success
    } else {
        ScanStatus::Partial
    };
    PartialScan {
        instance,
        installations,
        commands,
        errors,
    }
}

struct ListedSnap {
    name: String,
    version: String,
    revision: String,
    tracking: String,
    publisher: String,
    notes: String,
}

struct SnapPackage {
    listed: ListedSnap,
    root: PathBuf,
    metadata: Option<Value>,
}

fn parse_list(output: &str) -> Vec<ListedSnap> {
    output
        .lines()
        .skip_while(|line| line.trim().is_empty())
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() >= 5).then(|| ListedSnap {
                name: terminal_text(fields[0]),
                version: terminal_text(fields[1]),
                revision: terminal_text(fields[2]),
                tracking: terminal_text(fields[3]),
                publisher: terminal_text(fields[4]),
                notes: terminal_text(&fields.get(5..).unwrap_or_default().join(" ")),
            })
        })
        .collect()
}

fn snap_mount_dir() -> PathBuf {
    std::env::var_os("SNAP_MOUNT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let standard = PathBuf::from("/snap");
            if standard.exists() {
                standard
            } else {
                PathBuf::from("/var/lib/snapd/snap")
            }
        })
}

fn snap_state_dir() -> PathBuf {
    std::env::var_os("SNAPD_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/snapd"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapRole {
    Application,
    Dependency,
    Unknown,
}

fn snap_role(metadata: Option<&Value>) -> SnapRole {
    let has_apps = metadata
        .and_then(|value| value.get("apps"))
        .and_then(Value::as_mapping)
        .is_some_and(|apps| !apps.is_empty());
    if has_apps {
        return SnapRole::Application;
    }
    match yaml_text(metadata, "type").as_deref() {
        Some("base" | "kernel" | "gadget" | "snapd" | "os") => SnapRole::Dependency,
        Some("app") => SnapRole::Dependency,
        Some(_) => SnapRole::Unknown,
        None => SnapRole::Unknown,
    }
}

fn yaml_text(metadata: Option<&Value>, key: &str) -> Option<String> {
    metadata?
        .get(key)?
        .as_str()
        .map(terminal_text)
        .filter(|value| !value.is_empty())
}

fn yaml_mapping_keys(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_mapping)
        .into_iter()
        .flat_map(|mapping| mapping.keys())
        .filter_map(Value::as_str)
        .map(terminal_text)
        .collect()
}

fn yaml_architecture(metadata: Option<&Value>) -> Option<String> {
    let values = metadata?
        .get("architectures")?
        .as_sequence()?
        .iter()
        .filter_map(Value::as_str)
        .map(|architecture| match architecture {
            "amd64" => "x86_64",
            "arm64" => "arm64",
            value => value,
        })
        .map(str::to_string)
        .collect::<std::collections::BTreeSet<_>>();
    match values.len() {
        0 => None,
        1 => values.into_iter().next(),
        _ => Some("universal".into()),
    }
}

fn snap_bins(snap: &str, apps: &[String]) -> Vec<PathBuf> {
    let bin_dir = snap_mount_dir().join("bin");
    let mut names = if apps.is_empty() {
        vec![snap.to_string()]
    } else {
        apps.iter()
            .map(|app| {
                if app == snap {
                    snap.to_string()
                } else {
                    format!("{snap}.{app}")
                }
            })
            .collect()
    };
    names.sort();
    names.dedup();
    names
        .into_iter()
        .map(|name| bin_dir.join(name))
        .filter(|path| fs::symlink_metadata(path).is_ok())
        .collect()
}

fn content_providers(metadata: Option<&Value>) -> Vec<String> {
    let Some(plugs) = metadata
        .and_then(|value| value.get("plugs"))
        .and_then(Value::as_mapping)
    else {
        return Vec::new();
    };
    plugs
        .values()
        .filter_map(Value::as_mapping)
        .filter(|plug| {
            plug.get(Value::String("interface".into()))
                .and_then(Value::as_str)
                == Some("content")
        })
        .filter_map(|plug| {
            plug.get(Value::String("default-provider".into()))
                .and_then(Value::as_str)
        })
        .map(|provider| terminal_text(provider.split(':').next().unwrap_or(provider)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_apps_from_snap_platform_dependencies() {
        let app: Value = serde_yaml_ng::from_str(
            "type: app\nbase: core24\narchitectures: [amd64]\napps: {demo: {command: bin/demo}}\n",
        )
        .unwrap();
        let base: Value = serde_yaml_ng::from_str("type: base\n").unwrap();
        let content_only: Value = serde_yaml_ng::from_str("type: app\n").unwrap();
        assert_eq!(snap_role(Some(&app)), SnapRole::Application);
        assert_eq!(snap_role(Some(&base)), SnapRole::Dependency);
        assert_eq!(snap_role(Some(&content_only)), SnapRole::Dependency);
        assert_eq!(snap_role(None), SnapRole::Unknown);
        assert_eq!(yaml_architecture(Some(&app)), Some("x86_64".into()));
    }

    #[test]
    fn corrupt_or_future_list_rows_are_ignored_safely() {
        let list = parse_list(
            "Name Version Rev Tracking Publisher Notes\ndemo 1 2 stable pub - future\nbroken\n",
        );
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "demo");
    }
}

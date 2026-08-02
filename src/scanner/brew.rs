use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::model::{Category, InstallIntent, InstallType, ManagerInstance, ScanStatus, SourceKind};

use super::{
    PartialScan, ScanOptions, bins_in_directory, command, command_error_code, insert_metadata_text,
    make_record,
};

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let prefix = match command(&instance, &["--prefix"], options) {
        Ok(output) => PathBuf::from(output.stdout_text().trim()),
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    instance.root = Some(prefix.display().to_string());
    let output = match command(&instance, &["info", "--json=v2", "--installed"], options) {
        Ok(output) => output,
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    let value: Value = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(error) => return PartialScan::failed(instance, "parse_error", error),
    };
    let mut installations = Vec::new();
    let mut commands = Vec::new();

    for formula in value
        .get("formulae")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = formula.get("name").and_then(Value::as_str) else {
            continue;
        };
        let installed = formula
            .get("installed")
            .and_then(Value::as_array)
            .and_then(|versions| versions.last());
        let version = installed
            .and_then(|item| item.get("version"))
            .and_then(Value::as_str)
            .or_else(|| formula.get("versions")?.get("stable")?.as_str());
        let package_root = prefix.join("Cellar").join(name);
        let current_keg = version.map(|version| package_root.join(version));
        let linked = formula
            .get("linked_keg")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .is_some();
        let mut bins = current_keg
            .as_deref()
            .map(|root| brew_bins(root, &prefix, linked))
            .unwrap_or_default();
        bins.sort();
        bins.dedup();
        let requested = installed
            .and_then(|item| item.get("installed_on_request"))
            .and_then(Value::as_bool);
        let category = if bins.is_empty() {
            Category::Library
        } else {
            Category::Cli
        };
        let (mut record, record_commands) = make_record(
            &instance,
            name,
            version,
            "homebrew",
            SourceKind::Formula,
            formula
                .get("tap")
                .and_then(Value::as_str)
                .map(str::to_string),
            Some(package_root),
            bins,
            category,
            if requested == Some(false) {
                InstallType::Dependency
            } else {
                InstallType::Normal
            },
            match requested {
                Some(true) => InstallIntent::Explicit,
                Some(false) => InstallIntent::Dependency,
                None => InstallIntent::Unknown,
            },
            options,
        );
        record.metadata.insert("linked".into(), linked.into());
        if let Some(installed_versions) = formula.get("installed").and_then(Value::as_array) {
            record.metadata.insert(
                "installed_versions".into(),
                Value::Array(installed_versions.clone()),
            );
        }
        record.metadata.insert(
            "keg_only".into(),
            formula
                .get("keg_only")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                .into(),
        );
        insert_metadata_text(
            &mut record,
            "description",
            formula.get("desc").and_then(Value::as_str),
        );
        if record.metadata.contains_key("description") {
            record
                .metadata
                .insert("description_source".into(), "homebrew_info_json".into());
        }
        insert_metadata_text(
            &mut record,
            "homepage",
            formula.get("homepage").and_then(Value::as_str),
        );
        insert_metadata_text(
            &mut record,
            "license",
            formula.get("license").and_then(Value::as_str),
        );
        if let Some(timestamp) = installed
            .and_then(|item| item.get("time"))
            .and_then(Value::as_i64)
            .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_secs)
        {
            record.dates.manager_install_event_at = Some(crate::model::FieldValue::exact(
                timestamp,
                "homebrew_installed_time",
            ));
            record.dates.current_version_installed_at =
                record.dates.manager_install_event_at.clone();
        }
        if let Some(dependencies) = formula.get("dependencies").and_then(Value::as_array) {
            record
                .metadata
                .insert("dependencies".into(), Value::Array(dependencies.clone()));
        }
        commands.extend(record_commands);
        installations.push(record);
    }

    for cask in value
        .get("casks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(token) = cask.get("token").and_then(Value::as_str) else {
            continue;
        };
        let version = cask_version(cask);
        let root = prefix.join("Caskroom").join(token);
        let (artifact_paths, bin_paths, category) = cask_artifacts(cask, &prefix);
        let (mut record, record_commands) = make_record(
            &instance,
            token,
            version,
            "homebrew",
            SourceKind::Cask,
            cask.get("tap").and_then(Value::as_str).map(str::to_string),
            Some(root),
            bin_paths,
            category,
            InstallType::Normal,
            InstallIntent::Explicit,
            options,
        );
        record.paths.artifacts = artifact_paths;
        insert_metadata_text(
            &mut record,
            "description",
            cask.get("desc").and_then(Value::as_str),
        );
        if record.metadata.contains_key("description") {
            record
                .metadata
                .insert("description_source".into(), "homebrew_info_json".into());
        }
        insert_metadata_text(
            &mut record,
            "homepage",
            cask.get("homepage").and_then(Value::as_str),
        );
        record.metadata.insert("zap_excluded".into(), true.into());
        record.sizes.estimated_reclaimable_bytes = None;
        record.sizes.confidence = crate::model::Confidence::Ambiguous;
        record.sizes.method = "caskroom_only_external_artifacts_not_attributed".into();
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

fn brew_bins(root: &Path, prefix: &Path, linked: bool) -> Vec<PathBuf> {
    ["bin", "sbin"]
        .into_iter()
        .flat_map(|kind| {
            bins_in_directory(&root.join(kind))
                .into_iter()
                .map(move |path| {
                    if linked {
                        let candidate =
                            prefix.join(kind).join(path.file_name().unwrap_or_default());
                        if candidate.exists() || std::fs::symlink_metadata(&candidate).is_ok() {
                            return candidate;
                        }
                    }
                    path
                })
        })
        .collect()
}

fn cask_version(cask: &Value) -> Option<&str> {
    match cask.get("installed") {
        Some(Value::String(value)) => Some(value),
        Some(Value::Array(values)) => values.last().and_then(Value::as_str),
        _ => cask.get("version").and_then(Value::as_str),
    }
}

fn cask_artifacts(cask: &Value, prefix: &Path) -> (Vec<String>, Vec<PathBuf>, Category) {
    let mut artifacts = Vec::new();
    let mut bins = Vec::new();
    let mut category = Category::Other;
    for artifact in cask
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(object) = artifact.as_object() else {
            continue;
        };
        for (kind, value) in object {
            match kind.as_str() {
                "app" => {
                    category = Category::App;
                    collect_strings(value, &mut artifacts);
                }
                "font" => {
                    if category != Category::App {
                        category = Category::Font;
                    }
                    collect_strings(value, &mut artifacts);
                }
                "binary" => {
                    let mut values = Vec::new();
                    collect_strings(value, &mut values);
                    if let Some(target) = object.get("target").and_then(Value::as_str) {
                        bins.push(PathBuf::from(target));
                    } else {
                        for value in &values {
                            let name = Path::new(value).file_name().unwrap_or_default();
                            bins.push(prefix.join("bin").join(name));
                        }
                    }
                    artifacts.extend(values);
                    if category == Category::Other {
                        category = Category::Cli;
                    }
                }
                _ => collect_strings(value, &mut artifacts),
            }
        }
    }
    (artifacts, bins, category)
}

fn collect_strings(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(value) => output.push(crate::sanitize::terminal_text(value)),
        Value::Array(values) => {
            for value in values {
                collect_strings(value, output);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cask_binary_uses_explicit_target_and_installed_version() {
        let value = serde_json::json!({
            "version": "2.0",
            "installed": "1.5",
            "artifacts": [{
                "binary": ["/Caskroom/tool/1.5/source-name"],
                "target": "/custom/bin/public-name"
            }]
        });
        assert_eq!(cask_version(&value), Some("1.5"));
        let (artifacts, bins, category) = cask_artifacts(&value, Path::new("/prefix"));
        assert_eq!(
            artifacts,
            vec!["/Caskroom/tool/1.5/source-name", "/custom/bin/public-name"]
        );
        assert_eq!(bins, vec![PathBuf::from("/custom/bin/public-name")]);
        assert_eq!(category, Category::Cli);
    }
}

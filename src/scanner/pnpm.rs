use std::{fs, path::PathBuf};

use serde_json::{Map, Value};

use crate::model::{Category, InstallIntent, InstallType, ManagerInstance, ScanStatus, SourceKind};

use super::{
    PartialScan, ScanOptions, command, command_error_code, enrich_from_package_json, make_record,
    package_json_bin_names,
};

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let root = match command(&instance, &["root", "-g"], options) {
        Ok(output) => PathBuf::from(output.stdout_text().trim()),
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    let bin_dir = command(&instance, &["bin", "-g"], options)
        .ok()
        .map(|output| PathBuf::from(output.stdout_text().trim()))
        .unwrap_or_else(|| root.parent().unwrap_or(&root).join("bin"));
    let store_path = command(&instance, &["store", "path"], options)
        .ok()
        .map(|output| output.stdout_text().trim().to_string());
    instance.root = Some(root.display().to_string());
    instance.runtime = super::npm::node_runtime(&instance, options);
    let output = match command(&instance, &["list", "-g", "--depth=0", "--json"], options) {
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
    let dependencies = pnpm_dependencies(&value);
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    for (name, package) in dependencies {
        let package_root = package
            .get("path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join(name));
        let declared_commands = package_json_bin_names(&package_root);
        let bins = declared_commands
            .iter()
            .map(|name| bin_dir.join(name))
            .filter(|path| fs::symlink_metadata(path).is_ok())
            .collect();
        let resolved = package
            .get("resolved")
            .or_else(|| package.get("resolution"))
            .and_then(Value::as_str);
        let (source_kind, source_ref) = pnpm_source(resolved);
        let (mut record, record_commands) = make_record(
            &instance,
            name,
            package.get("version").and_then(Value::as_str),
            "npm",
            source_kind,
            source_ref,
            Some(package_root.clone()),
            bins,
            Category::Cli,
            InstallType::Normal,
            InstallIntent::Explicit,
            options,
        );
        // pnpm's content-addressed store is shared. It is deliberately not
        // attributed to any one installation or reclaimable byte estimate.
        record.sizes.estimated_reclaimable_bytes = None;
        record.sizes.confidence = crate::model::Confidence::Ambiguous;
        record.sizes.method = "package_links_only_shared_store_excluded".into();
        if let Some(store_path) = &store_path {
            record
                .metadata
                .insert("shared_store_path".into(), store_path.clone().into());
        }
        record
            .metadata
            .insert("declared_commands".into(), declared_commands.into());
        enrich_from_package_json(&mut record, &package_root);
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

fn pnpm_dependencies(value: &Value) -> Vec<(&str, &Map<String, Value>)> {
    let project = match value {
        Value::Array(values) => values.first(),
        Value::Object(_) => Some(value),
        _ => None,
    };
    let Some(project) = project else {
        return Vec::new();
    };
    ["dependencies", "devDependencies", "optionalDependencies"]
        .into_iter()
        .filter_map(|key| project.get(key).and_then(Value::as_object))
        .flat_map(|dependencies| {
            dependencies
                .iter()
                .filter_map(|(name, value)| value.as_object().map(|value| (name.as_str(), value)))
        })
        .collect()
}

fn pnpm_source(resolved: Option<&str>) -> (SourceKind, Option<String>) {
    let Some(resolved) = resolved else {
        return (SourceKind::Registry, None);
    };
    let lower = resolved.to_ascii_lowercase();
    if lower.starts_with("link:") || lower.starts_with("file:") {
        (SourceKind::Linked, Some(resolved.into()))
    } else if lower.starts_with("git+") || lower.contains("github.com") {
        (SourceKind::Git, Some(resolved.into()))
    } else {
        (SourceKind::Registry, Some(resolved.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_array_and_unknown_fields_in_list_output() {
        let value = serde_json::json!([{
            "future_field": true,
            "dependencies": {"tool": {"version": "1.0.0", "path": "/tmp/tool"}}
        }]);
        let dependencies = pnpm_dependencies(&value);
        assert_eq!(dependencies.len(), 1);
        assert_eq!(dependencies[0].0, "tool");
    }
}

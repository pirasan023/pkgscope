use std::{fs, path::PathBuf};

use serde_json::Value;

use crate::model::{
    Category, InstallIntent, InstallType, ManagerInstance, RuntimeInfo, ScanStatus, SourceKind,
};

use super::{
    PartialScan, ScanOptions, command, command_error_code, enrich_from_package_json, make_record,
    package_json_bin_names,
};

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let prefix = match command(&instance, &["prefix", "-g"], options) {
        Ok(output) => PathBuf::from(output.stdout_text().trim()),
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    let root = match command(&instance, &["root", "-g"], options) {
        Ok(output) => PathBuf::from(output.stdout_text().trim()),
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    instance.root = Some(root.display().to_string());
    instance.runtime = node_runtime(&instance, options);
    let output = match command(
        &instance,
        &["ls", "-g", "--depth=0", "--json", "--long"],
        options,
    ) {
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
    let Some(dependencies) = value.get("dependencies").and_then(Value::as_object) else {
        instance.scan_status = ScanStatus::Success;
        return PartialScan {
            instance,
            installations: Vec::new(),
            commands: Vec::new(),
            errors: Vec::new(),
        };
    };
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    let bin_dir = prefix.join("bin");
    for (name, package) in dependencies {
        let package_root = package
            .get("path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join(name));
        let linked = fs::symlink_metadata(&package_root)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
            || package
                .get("link")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let declared_commands = package_json_bin_names(&package_root);
        let bins = declared_commands
            .iter()
            .map(|name| bin_dir.join(name))
            .filter(|path| fs::symlink_metadata(path).is_ok())
            .collect();
        let resolved = package.get("resolved").and_then(Value::as_str);
        let (source_kind, source_ref) = npm_source(resolved, linked, &package_root);
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
            if linked {
                InstallType::Linked
            } else {
                InstallType::Normal
            },
            InstallIntent::Explicit,
            options,
        );
        if let Some(problems) = package.get("problems") {
            record
                .metadata
                .insert("manager_problems".into(), problems.clone());
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

pub(super) fn node_runtime(
    instance: &ManagerInstance,
    options: &ScanOptions,
) -> Option<RuntimeInfo> {
    let npm_dir = PathBuf::from(&instance.executable_path)
        .parent()?
        .to_path_buf();
    let node = npm_dir.join("node");
    let executable = if node.exists() {
        node
    } else {
        crate::process::find_executables("node")
            .into_iter()
            .next()?
    };
    let mut spec = crate::process::CommandSpec::new(&executable, &["--version"], options.timeout);
    spec.output_limit = 1024 * 1024;
    let version = crate::process::run(&spec)
        .ok()
        .map(|output| output.stdout_text().trim().to_string());
    Some(RuntimeInfo {
        name: "node".into(),
        version,
        executable_path: Some(executable.display().to_string()),
    })
}

fn npm_source(
    resolved: Option<&str>,
    linked: bool,
    root: &std::path::Path,
) -> (SourceKind, Option<String>) {
    if linked {
        return (
            SourceKind::Linked,
            root.canonicalize()
                .ok()
                .map(|path| path.display().to_string()),
        );
    }
    let Some(resolved) = resolved else {
        return (SourceKind::Registry, None);
    };
    let lower = resolved.to_ascii_lowercase();
    if lower.starts_with("git+") || lower.ends_with(".git") {
        (SourceKind::Git, Some(resolved.into()))
    } else if lower.starts_with("file:") {
        (SourceKind::Path, Some(resolved.into()))
    } else if lower.ends_with(".tgz") || lower.ends_with(".tar.gz") {
        (SourceKind::Tarball, Some(resolved.into()))
    } else {
        (SourceKind::Registry, Some(resolved.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_non_registry_sources_without_guessing() {
        assert_eq!(
            npm_source(
                Some("git+https://example.test/tool.git"),
                false,
                std::path::Path::new("/x")
            )
            .0,
            SourceKind::Git
        );
        assert_eq!(
            npm_source(Some("file:../tool"), false, std::path::Path::new("/x")).0,
            SourceKind::Path
        );
        assert_eq!(
            npm_source(None, false, std::path::Path::new("/x")).0,
            SourceKind::Registry
        );
    }
}

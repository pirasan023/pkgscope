use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::model::{
    Category, InstallIntent, InstallType, ManagerInstance, RuntimeInfo, ScanStatus, SourceKind,
};

use super::{
    PartialScan, ScanOptions, command, command_error_code, enrich_from_python_metadata, make_record,
};

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let output = match command(&instance, &["list", "--json"], options) {
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
    let home = pipx_path(&instance, options, "PIPX_HOME").unwrap_or_else(default_pipx_home);
    let bin_dir = pipx_path(&instance, options, "PIPX_BIN_DIR")
        .or_else(|| dirs::home_dir().map(|home| home.join(".local/bin")))
        .unwrap_or_else(|| PathBuf::from(".local/bin"));
    instance.root = Some(home.display().to_string());
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    for (venv_key, venv) in value
        .get("venvs")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let metadata = venv.get("metadata").unwrap_or(venv);
        let main = metadata.get("main_package").unwrap_or(metadata);
        let name = main
            .get("package")
            .or_else(|| main.get("package_name"))
            .and_then(Value::as_str)
            .unwrap_or(venv_key);
        let root = venv
            .get("venv_dir")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("venvs").join(venv_key));
        let direct_apps = string_array(main.get("apps").or_else(|| main.get("app_names")));
        let dependency_apps = string_array(main.get("apps_of_dependencies"));
        let mut app_names = direct_apps.clone();
        app_names.extend(dependency_apps.clone());
        app_names.sort();
        app_names.dedup();
        let bins = app_names
            .iter()
            .map(|name| bin_dir.join(name))
            .filter(|path| std::fs::symlink_metadata(path).is_ok())
            .collect();
        let (mut record, record_commands) = make_record(
            &instance,
            name,
            main.get("package_version").and_then(Value::as_str),
            "pypi",
            python_source(main),
            main.get("package_or_url")
                .and_then(Value::as_str)
                .map(str::to_string),
            Some(root.clone()),
            bins,
            Category::Cli,
            InstallType::Normal,
            InstallIntent::Explicit,
            options,
        );
        record.environment = crate::sanitize::terminal_text(venv_key);
        enrich_from_python_metadata(&mut record, &root, name);
        let interpreter = python_interpreter(&root);
        record.metadata.insert(
            "python_interpreter".into(),
            interpreter.display().to_string().into(),
        );
        if let Some(version) = metadata.get("python_version") {
            record
                .metadata
                .insert("python_version".into(), version.clone());
        }
        if let Some(source) = metadata.get("source_interpreter").and_then(path_value) {
            record
                .metadata
                .insert("source_interpreter".into(), source.into());
        }
        if let Some(backend) = metadata
            .get("backend")
            .or_else(|| metadata.get("venv_backend"))
        {
            record.metadata.insert("backend".into(), backend.clone());
        }
        let exposed: Vec<_> = record_commands
            .iter()
            .map(|command| command.name.clone())
            .collect();
        let unexposed: Vec<_> = app_names
            .iter()
            .filter(|name| !exposed.contains(name))
            .cloned()
            .collect();
        record
            .metadata
            .insert("declared_commands".into(), app_names.into());
        record
            .metadata
            .insert("main_package_commands".into(), direct_apps.into());
        record
            .metadata
            .insert("dependency_commands".into(), dependency_apps.into());
        record
            .metadata
            .insert("exposed_commands".into(), exposed.into());
        record
            .metadata
            .insert("unexposed_commands".into(), unexposed.into());
        commands.extend(record_commands);
        installations.push(record);

        for (injected_name, injected) in metadata
            .get("injected_packages")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let injected_apps = string_array(injected.get("apps"));
            let injected_bins = injected_apps
                .iter()
                .map(|name| bin_dir.join(name))
                .filter(|path| std::fs::symlink_metadata(path).is_ok())
                .collect();
            let (mut record, record_commands) = make_record(
                &instance,
                injected_name,
                injected.get("package_version").and_then(Value::as_str),
                "pypi",
                python_source(injected),
                injected
                    .get("package_or_url")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                None,
                injected_bins,
                Category::Library,
                InstallType::Injected,
                InstallIntent::Dependency,
                options,
            );
            record.environment = crate::sanitize::terminal_text(venv_key);
            enrich_from_python_metadata(&mut record, &root, injected_name);
            record.removal_plan_available = false;
            record
                .metadata
                .insert("injected_into".into(), name.to_string().into());
            record
                .metadata
                .insert("declared_commands".into(), injected_apps.into());
            commands.extend(record_commands);
            installations.push(record);
        }
    }
    instance.scan_status = ScanStatus::Success;
    PartialScan {
        instance,
        installations,
        commands,
        errors: Vec::new(),
    }
}

fn pipx_path(instance: &ManagerInstance, options: &ScanOptions, variable: &str) -> Option<PathBuf> {
    std::env::var_os(variable).map(PathBuf::from).or_else(|| {
        command(instance, &["environment", "--value", variable], options)
            .ok()
            .map(|output| PathBuf::from(output.stdout_text().trim()))
            .filter(|path| !path.as_os_str().is_empty())
    })
}

fn default_pipx_home() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let modern = home.join(".local/share/pipx");
    if modern.exists() {
        modern
    } else {
        home.join(".local/pipx")
    }
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn python_source(value: &Value) -> SourceKind {
    let value = value
        .get("package_or_url")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if value.starts_with("git+") {
        SourceKind::Git
    } else if value.starts_with("file:") || value.starts_with('/') {
        SourceKind::Path
    } else {
        SourceKind::Registry
    }
}

fn python_interpreter(root: &Path) -> PathBuf {
    [root.join("bin/python"), root.join("bin/python3")]
        .into_iter()
        .find(|path| path.exists())
        .unwrap_or_else(|| root.join("bin/python"))
}

fn path_value(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("__Path__").and_then(Value::as_str))
}

#[allow(dead_code)]
fn runtime(path: &Path) -> RuntimeInfo {
    RuntimeInfo {
        name: "python".into(),
        version: None,
        executable_path: Some(path.display().to_string()),
    }
}

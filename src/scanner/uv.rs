use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::model::{
    Category, Confidence, InstallIntent, InstallType, ManagerInstance, ScanStatus, SourceKind,
};

use super::{
    PartialScan, ScanOptions, command, command_error_code, enrich_from_python_metadata,
    make_record, read_text_bounded,
};

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let tool_dir = match command(&instance, &["tool", "dir"], options) {
        Ok(output) => PathBuf::from(output.stdout_text().trim()),
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    let bin_dir = command(&instance, &["tool", "dir", "--bin"], options)
        .ok()
        .map(|output| PathBuf::from(output.stdout_text().trim()))
        .or_else(|| dirs::home_dir().map(|home| home.join(".local/bin")))
        .unwrap_or_else(|| PathBuf::from(".local/bin"));
    instance.root = Some(tool_dir.display().to_string());
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    let entries = match fs::read_dir(&tool_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            instance.scan_status = ScanStatus::Success;
            return PartialScan {
                instance,
                installations,
                commands,
                errors: Vec::new(),
            };
        }
        Err(error) => return PartialScan::failed(instance, "permission_denied", error),
    };
    for entry in entries.flatten() {
        let root = entry.path();
        if !root.is_dir() {
            continue;
        }
        let environment_name = entry.file_name().to_string_lossy().into_owned();
        let receipt = uv_receipt(&root);
        let packages = dist_info_packages(&root);
        let requested_name = receipt
            .as_ref()
            .and_then(|receipt| receipt.name.as_deref())
            .unwrap_or(&environment_name);
        let main = packages
            .iter()
            .find(|package| normalize_name(&package.0) == normalize_name(requested_name))
            .or_else(|| packages.first());
        let (name, version) = main
            .map(|(name, version)| (name.as_str(), version.as_deref()))
            .unwrap_or((requested_name, None));
        let mut bins: Vec<PathBuf> = receipt
            .as_ref()
            .map(|receipt| {
                receipt
                    .entrypoints
                    .iter()
                    .map(|entry| entry.path.clone())
                    .collect()
            })
            .unwrap_or_default();
        bins.extend(exposed_bins(&root, &bin_dir));
        bins.sort();
        bins.dedup();
        let (source_kind, source_ref) = receipt
            .as_ref()
            .map(|receipt| (receipt.source_kind, receipt.source_ref.clone()))
            .unwrap_or((SourceKind::Unknown, None));
        let (mut record, record_commands) = make_record(
            &instance,
            name,
            version,
            "pypi",
            source_kind,
            source_ref,
            Some(root.clone()),
            bins,
            Category::Cli,
            InstallType::Normal,
            InstallIntent::Explicit,
            options,
        );
        record.environment = crate::sanitize::terminal_text(&environment_name);
        enrich_from_python_metadata(&mut record, &root, name);
        // uv's cache is shared and deliberately excluded from record sizes.
        record.sizes.estimated_reclaimable_bytes = None;
        record.sizes.confidence = if record.sizes.owned_allocated_bytes.is_some() {
            Confidence::Estimated
        } else {
            Confidence::Unknown
        };
        record.sizes.method = "tool_environment_only_shared_uv_cache_excluded".into();
        if packages.len() > 1 {
            record.metadata.insert(
                "environment_packages".into(),
                packages
                    .iter()
                    .map(|(name, version)| {
                        format!("{}@{}", name, version.as_deref().unwrap_or("unknown"))
                    })
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        let mut providers = entry_point_providers(&root);
        if let Some(receipt) = &receipt {
            for entrypoint in &receipt.entrypoints {
                providers.insert(entrypoint.name.clone(), entrypoint.provider.clone());
            }
        }
        if !providers.is_empty() {
            record.metadata.insert(
                "command_providers".into(),
                serde_json::to_value(providers).unwrap_or_default(),
            );
        }
        if let Some(interpreter) = python_interpreter_from_cfg(&root) {
            record
                .metadata
                .insert("source_interpreter".into(), interpreter.into());
        }
        record.metadata.insert(
            "python_interpreter".into(),
            root.join("bin/python").display().to_string().into(),
        );
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

struct UvReceipt {
    name: Option<String>,
    source_kind: SourceKind,
    source_ref: Option<String>,
    entrypoints: Vec<UvEntrypoint>,
}

struct UvEntrypoint {
    name: String,
    path: PathBuf,
    provider: String,
}

fn uv_receipt(root: &Path) -> Option<UvReceipt> {
    let value: toml::Value =
        toml::from_str(&read_text_bounded(&root.join("uv-receipt.toml"), 1024 * 1024).ok()?)
            .ok()?;
    let tool = value.get("tool")?;
    let requirement = tool
        .get("requirements")
        .and_then(toml::Value::as_array)
        .and_then(|requirements| requirements.first());
    let name = requirement
        .and_then(|requirement| requirement.get("name"))
        .and_then(toml::Value::as_str)
        .map(crate::sanitize::terminal_text);
    let editable = requirement
        .and_then(|requirement| requirement.get("editable"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    let source_ref = requirement.and_then(|requirement| {
        ["git", "path", "url", "source"]
            .into_iter()
            .find_map(|key| requirement.get(key).and_then(toml::Value::as_str))
            .map(crate::sanitize::terminal_text)
    });
    let source_kind = if editable {
        SourceKind::Linked
    } else if source_ref
        .as_deref()
        .is_some_and(|source| source.starts_with("git+") || source.ends_with(".git"))
    {
        SourceKind::Git
    } else if source_ref
        .as_deref()
        .is_some_and(|source| source.starts_with("file:") || source.starts_with('/'))
    {
        SourceKind::Path
    } else if source_ref.as_deref().is_some_and(|source| {
        source.ends_with(".whl") || source.ends_with(".tar.gz") || source.ends_with(".zip")
    }) {
        SourceKind::Tarball
    } else {
        SourceKind::Registry
    };
    let entrypoints = tool
        .get("entrypoints")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entrypoint| {
            let name = entrypoint.get("name")?.as_str()?;
            let path = entrypoint.get("install-path")?.as_str()?;
            let provider = entrypoint
                .get("from")
                .and_then(toml::Value::as_str)
                .unwrap_or(name);
            Some(UvEntrypoint {
                name: crate::sanitize::terminal_text(name),
                path: PathBuf::from(path),
                provider: crate::sanitize::terminal_text(provider),
            })
        })
        .collect();
    Some(UvReceipt {
        name,
        source_kind,
        source_ref,
        entrypoints,
    })
}

fn exposed_bins(root: &Path, bin_dir: &Path) -> Vec<PathBuf> {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let Ok(entries) = fs::read_dir(bin_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.canonicalize()
                .map(|target| target.starts_with(&canonical_root))
                .unwrap_or(false)
        })
        .collect()
}

fn dist_info_packages(root: &Path) -> Vec<(String, Option<String>)> {
    let mut packages = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .max_depth(6)
        .follow_links(false)
        .into_iter()
        .flatten()
        .take(250_000)
    {
        if entry.file_name() != "METADATA" {
            continue;
        }
        if !entry
            .path()
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .map(|name| name.ends_with(".dist-info"))
            .unwrap_or(false)
        {
            continue;
        }
        let Ok(content) = read_text_bounded(entry.path(), 2 * 1024 * 1024) else {
            continue;
        };
        let name = header(&content, "Name");
        if let Some(name) = name {
            packages.push((name, header(&content, "Version")));
        }
    }
    packages
}

fn entry_point_providers(root: &Path) -> std::collections::BTreeMap<String, String> {
    let mut providers = std::collections::BTreeMap::new();
    for entry in walkdir::WalkDir::new(root)
        .max_depth(6)
        .follow_links(false)
        .into_iter()
        .flatten()
        .take(250_000)
    {
        if entry.file_name() != "entry_points.txt" {
            continue;
        }
        let Some(directory) = entry.path().parent() else {
            continue;
        };
        let Some(provider) = directory
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".dist-info"))
            .and_then(|name| name.rsplit_once('-').map(|(name, _)| name))
        else {
            continue;
        };
        let Ok(content) = read_text_bounded(entry.path(), 2 * 1024 * 1024) else {
            continue;
        };
        let mut console_scripts = false;
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                console_scripts = line == "[console_scripts]";
            } else if console_scripts && let Some((name, _target)) = line.split_once('=') {
                providers.insert(
                    crate::sanitize::terminal_text(name.trim()),
                    crate::sanitize::terminal_text(provider),
                );
            }
        }
    }
    providers
}

fn header(content: &str, name: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .map(crate::sanitize::terminal_text)
}

fn normalize_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if matches!(ch, '-' | '_' | '.') {
                '-'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect()
}

fn python_interpreter_from_cfg(root: &Path) -> Option<String> {
    let cfg = read_text_bounded(&root.join("pyvenv.cfg"), 64 * 1024).ok()?;
    cfg.lines()
        .find_map(|line| line.strip_prefix("home = "))
        .map(|home| Path::new(home).join("python").display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_identifies_main_package_and_command_provider() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("uv-receipt.toml"),
            r#"
[tool]
requirements = [{ name = "main-tool" }]
entrypoints = [{ name = "helper", install-path = "/tmp/helper", from = "extra-package" }]
"#,
        )
        .unwrap();

        let receipt = uv_receipt(temp.path()).unwrap();

        assert_eq!(receipt.name.as_deref(), Some("main-tool"));
        assert_eq!(receipt.source_kind, SourceKind::Registry);
        assert_eq!(receipt.entrypoints[0].provider, "extra-package");
    }
}

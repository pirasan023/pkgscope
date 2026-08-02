use std::{collections::BTreeMap, path::PathBuf};

use chrono::DateTime;

use crate::model::{
    Category, Confidence, FieldValue, InstallIntent, InstallType, InstallationDates,
    ManagerInstance, ScanStatus, SourceKind,
};
use crate::{process, sanitize::terminal_text};

use super::{
    PartialScan, ScanOptions, command, command_error_code, companion_command, insert_metadata_text,
    make_record, read_text_bounded,
};

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let output = match command(&instance, &["-Qqe"], options) {
        Ok(output) => output,
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    let explicit = output
        .stdout_text()
        .lines()
        .map(terminal_text)
        .filter(|name| !name.is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    let root =
        pacman_config_path(&instance, options, "RootDir").unwrap_or_else(|| PathBuf::from("/"));
    let database = pacman_config_path(&instance, options, "DBPath")
        .unwrap_or_else(|| root.join("var/lib/pacman"));
    instance.root = Some(database.display().to_string());
    if explicit.is_empty() {
        instance.scan_status = ScanStatus::Success;
        return PartialScan {
            instance,
            installations: Vec::new(),
            commands: Vec::new(),
            errors: Vec::new(),
        };
    }
    let local = database.join("local");
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    let entries = match std::fs::read_dir(&local) {
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
    for entry in entries.flatten().take(100_000) {
        let package_dir = entry.path();
        let Ok(description) = read_text_bounded(&package_dir.join("desc"), 4 * 1024 * 1024) else {
            continue;
        };
        let fields = parse_sections(&description);
        let Some(name) = first(&fields, "NAME") else {
            continue;
        };
        if !explicit.contains(name) {
            continue;
        }
        let files = read_text_bounded(&package_dir.join("files"), 16 * 1024 * 1024)
            .ok()
            .map(|contents| parse_sections(&contents))
            .and_then(|sections| sections.get("FILES").cloned())
            .unwrap_or_default();
        let bins = files
            .into_iter()
            .filter(|path| is_command_path(path))
            .map(|path| root.join(path.trim_start_matches('/')))
            .filter(|path| process::is_executable(path))
            .collect();
        let version = first(&fields, "VERSION");
        let (mut record, record_commands) = make_record(
            &instance,
            name,
            version,
            "pacman",
            SourceKind::Pacman,
            None,
            None,
            bins,
            Category::Other,
            InstallType::Normal,
            InstallIntent::Explicit,
            options,
        );
        record.category = if record_commands.is_empty() {
            Category::Other
        } else {
            Category::Cli
        };
        record.version = version.map_or_else(
            || FieldValue::unknown("pacman_local_database"),
            |version| FieldValue::exact(version.to_string(), "pacman_local_database"),
        );
        record.architecture = first(&fields, "ARCH").map_or_else(
            || FieldValue::unknown("pacman_local_database"),
            |architecture| FieldValue::exact(architecture.to_string(), "pacman_local_database"),
        );
        if let Some(size) = first(&fields, "SIZE")
            .or_else(|| first(&fields, "ISIZE"))
            .and_then(|size| size.parse().ok())
        {
            record.sizes.owned_apparent_bytes = Some(size);
            record.sizes.owned_allocated_bytes = Some(size);
            record.sizes.estimated_reclaimable_bytes = Some(size);
            record.sizes.confidence = Confidence::Estimated;
            record.sizes.method = "pacman_installed_size".into();
        }
        if let Some(timestamp) = first(&fields, "INSTALLDATE")
            .and_then(|timestamp| timestamp.parse().ok())
            .and_then(|timestamp| DateTime::from_timestamp(timestamp, 0))
        {
            record.dates = InstallationDates {
                manager_install_event_at: Some(FieldValue::exact(
                    timestamp,
                    "pacman_local_database",
                )),
                current_version_installed_at: Some(FieldValue::exact(
                    timestamp,
                    "pacman_local_database",
                )),
                ..record.dates
            };
        }
        insert_metadata_text(&mut record, "description", first(&fields, "DESC"));
        if record.metadata.contains_key("description") {
            record
                .metadata
                .insert("description_source".into(), "pacman_local_database".into());
        }
        insert_metadata_text(&mut record, "homepage", first(&fields, "URL"));
        if let Some(dependencies) = fields.get("DEPENDS") {
            let dependencies = dependencies
                .iter()
                .filter_map(|dependency| dependency_name(dependency))
                .collect::<Vec<_>>();
            if !dependencies.is_empty() {
                record
                    .metadata
                    .insert("dependencies".into(), dependencies.into());
            }
        }
        if let Some(required_by) = fields.get("REQUIREDBY") {
            record
                .metadata
                .insert("required_by".into(), required_by.clone().into());
        }
        record.metadata.insert("requires_root".into(), true.into());
        record.metadata.insert(
            "privilege_reason".into(),
            "pacman modifies the system package database".into(),
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

fn pacman_config_path(
    instance: &ManagerInstance,
    options: &ScanOptions,
    key: &str,
) -> Option<PathBuf> {
    companion_command(instance, &["pacman-conf"], &[key], options)
        .ok()
        .map(|output| PathBuf::from(output.stdout_text().trim()))
        .filter(|path| !path.as_os_str().is_empty())
}

fn parse_sections(contents: &str) -> BTreeMap<String, Vec<String>> {
    let mut result = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in contents.lines() {
        if line.starts_with('%') && line.ends_with('%') && line.len() > 2 {
            current = Some(line.trim_matches('%').to_string());
        } else if !line.is_empty()
            && let Some(section) = &current
        {
            result
                .entry(section.clone())
                .or_insert_with(Vec::new)
                .push(terminal_text(line));
        }
    }
    result
}

fn first<'a>(fields: &'a BTreeMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    fields.get(key)?.first().map(String::as_str)
}

fn is_command_path(path: &str) -> bool {
    ["bin/", "sbin/", "usr/bin/", "usr/sbin/", "usr/local/bin/"]
        .iter()
        .any(|prefix| path.trim_start_matches('/').starts_with(prefix))
}

fn dependency_name(value: &str) -> Option<String> {
    let name = value
        .split(['<', '>', '='])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())?;
    Some(terminal_text(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unknown_sections_without_losing_known_fields() {
        let fields = parse_sections(
            "%NAME%\ndemo\n\n%UNKNOWN%\nfuture\n\n%ISIZE%\n1234\n\n%DEPENDS%\nlibc>=1\n",
        );
        assert_eq!(first(&fields, "NAME"), Some("demo"));
        assert_eq!(dependency_name("libc>=1"), Some("libc".into()));
    }
}

use std::path::{Path, PathBuf};

use chrono::{Local, NaiveDateTime, TimeZone, Utc};

use crate::model::{
    Category, Confidence, FieldValue, InstallIntent, InstallType, InstallationDates,
    ManagerInstance, ScanStatus, SourceKind,
};
use crate::{process, sanitize::terminal_text};

use super::{
    PartialScan, ScanOptions, command_error_code, companion_command, insert_metadata_text,
    make_record,
};

const QUERY_FORMAT: &str = "${binary:Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${Homepage}\t${binary:Summary}\t${db:Status-Abbrev}\t${Pre-Depends}\t${Depends}\n";

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let manual = match companion_command(&instance, &["apt-mark"], &["showmanual"], options) {
        Ok(output) => output
            .stdout_text()
            .lines()
            .map(terminal_text)
            .filter(|name| !name.is_empty())
            .collect::<std::collections::BTreeSet<_>>(),
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    instance.root = Some("/var/lib/dpkg".into());
    if manual.is_empty() {
        instance.scan_status = ScanStatus::Success;
        return PartialScan {
            instance,
            installations: Vec::new(),
            commands: Vec::new(),
            errors: Vec::new(),
        };
    }
    let output = match companion_command(
        &instance,
        &["dpkg-query"],
        &["--show", &format!("--showformat={QUERY_FORMAT}")],
        options,
    ) {
        Ok(output) => output,
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    let install_times = dpkg_install_times();
    for package in parse_packages(&output.stdout_text()) {
        if package.status != "ii"
            || (!manual.contains(&package.binary_name) && !manual.contains(&package.name))
        {
            continue;
        }
        let bins = package_files(&instance, &package.binary_name, options)
            .into_iter()
            .filter(|path| is_command_path(path) && process::is_executable(path))
            .collect();
        let (mut record, record_commands) = make_record(
            &instance,
            &package.binary_name,
            Some(&package.version),
            "deb",
            SourceKind::Deb,
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
        record.version = FieldValue::exact(package.version.clone(), "dpkg_status");
        record.architecture = FieldValue::exact(package.architecture, "dpkg_status");
        if let Some(kib) = package.installed_size_kib {
            let bytes = kib.saturating_mul(1024);
            record.sizes.owned_apparent_bytes = Some(bytes);
            record.sizes.owned_allocated_bytes = Some(bytes);
            record.sizes.estimated_reclaimable_bytes = Some(bytes);
            record.sizes.confidence = Confidence::Estimated;
            record.sizes.method = "dpkg_installed_size_kib".into();
        }
        if let Some(installed_at) = install_times
            .get(&(package.binary_name.clone(), package.version.clone()))
            .or_else(|| install_times.get(&(package.name.clone(), package.version.clone())))
        {
            record.dates = InstallationDates {
                manager_install_event_at: Some(FieldValue::exact(*installed_at, "local_dpkg_log")),
                current_version_installed_at: Some(FieldValue::exact(
                    *installed_at,
                    "local_dpkg_log",
                )),
                ..record.dates
            };
        }
        insert_metadata_text(&mut record, "description", Some(&package.summary));
        if record.metadata.contains_key("description") {
            record
                .metadata
                .insert("description_source".into(), "dpkg_status".into());
        }
        insert_metadata_text(&mut record, "homepage", Some(&package.homepage));
        let dependencies = package
            .dependencies
            .split(',')
            .filter_map(dependency_name)
            .collect::<Vec<_>>();
        if !dependencies.is_empty() {
            record
                .metadata
                .insert("dependencies".into(), dependencies.into());
        }
        record.metadata.insert("requires_root".into(), true.into());
        record.metadata.insert(
            "privilege_reason".into(),
            "APT modifies the system dpkg database".into(),
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

fn dpkg_install_times() -> std::collections::BTreeMap<(String, String), chrono::DateTime<Utc>> {
    let Ok(contents) = super::read_text_bounded(Path::new("/var/log/dpkg.log"), 16 * 1024 * 1024)
    else {
        return std::collections::BTreeMap::new();
    };
    let mut result = std::collections::BTreeMap::new();
    for line in contents.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 || !matches!(fields[2], "install" | "upgrade") {
            continue;
        }
        let Ok(naive) = NaiveDateTime::parse_from_str(
            &format!("{} {}", fields[0], fields[1]),
            "%Y-%m-%d %H:%M:%S",
        ) else {
            continue;
        };
        let Some(local) = Local.from_local_datetime(&naive).single() else {
            continue;
        };
        let package = terminal_text(fields[3]);
        let version = terminal_text(fields[5]);
        result.insert((package, version), local.with_timezone(&Utc));
    }
    result
}

struct AptPackage {
    binary_name: String,
    name: String,
    version: String,
    architecture: String,
    installed_size_kib: Option<u64>,
    homepage: String,
    summary: String,
    status: String,
    dependencies: String,
}

fn parse_packages(output: &str) -> Vec<AptPackage> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(9, '\t').map(terminal_text);
            let binary_name = fields.next()?;
            let version = fields.next()?;
            let architecture = fields.next()?;
            let installed_size_kib = fields.next()?.parse().ok();
            let homepage = fields.next()?;
            let summary = fields.next()?;
            let status = fields.next()?;
            let pre_depends = fields.next()?;
            let depends = fields.next().unwrap_or_default();
            if binary_name.is_empty() || version.is_empty() || architecture.is_empty() {
                return None;
            }
            Some(AptPackage {
                name: binary_name
                    .split_once(':')
                    .map_or_else(|| binary_name.clone(), |(name, _)| name.to_string()),
                binary_name,
                version,
                architecture,
                installed_size_kib,
                homepage,
                summary,
                status,
                dependencies: [pre_depends, depends]
                    .into_iter()
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>()
                    .join(","),
            })
        })
        .collect()
}

fn dependency_name(value: &str) -> Option<String> {
    let name = value
        .trim()
        .split('|')
        .next()?
        .split_whitespace()
        .next()?
        .split(':')
        .next()?
        .trim();
    (!name.is_empty()).then(|| terminal_text(name))
}

fn package_files(instance: &ManagerInstance, name: &str, options: &ScanOptions) -> Vec<PathBuf> {
    companion_command(instance, &["dpkg-query"], &["--listfiles", name], options)
        .ok()
        .map(|output| {
            output
                .stdout_text()
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with('/'))
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

fn is_command_path(path: &Path) -> bool {
    [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/local/bin/",
    ]
    .iter()
    .any(|prefix| path.to_string_lossy().starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_complete_records_and_sanitizes_metadata() {
        let parsed = parse_packages(
            "demo:amd64\t1.2\tamd64\t42\thttps://example.test\tDemo\u{1b}[31m tool\tii \tlibc6 (>= 2)\tca-certificates\nunknown\n",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].binary_name, "demo:amd64");
        assert_eq!(parsed[0].summary, "Demo tool");
        assert_eq!(parsed[0].installed_size_kib, Some(42));
    }
}
